package main

import (
	"errors"
	"strings"
	"testing"
	"time"

	libvirt "github.com/digitalocean/go-libvirt"
	"github.com/prometheus/client_golang/prometheus"
)

func dataIntegrityRunHeavyCollection(t *testing.T, mc *MetricsCollector) []prometheus.Metric {
	t.Helper()
	ch := make(chan prometheus.Metric, 4096)
	mc.collectHeavy(ch)
	close(ch)
	metrics := make([]prometheus.Metric, 0, len(ch))
	for metric := range ch {
		metrics = append(metrics, metric)
	}
	return metrics
}

func dataIntegrityMetricFamilyValue(t *testing.T, metrics []prometheus.Metric, name string) (float64, bool) {
	t.Helper()
	registry := prometheus.NewRegistry()
	registry.MustRegister(staticMetricCollector{metrics: metrics})
	families, err := registry.Gather()
	if err != nil {
		t.Fatalf("gather metric family %s: %v", name, err)
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		if len(family.Metric) != 1 {
			t.Fatalf("metric family %s samples=%d, want 1", name, len(family.Metric))
		}
		sample := family.Metric[0]
		switch {
		case sample.Gauge != nil:
			return sample.GetGauge().GetValue(), true
		case sample.Counter != nil:
			return sample.GetCounter().GetValue(), true
		default:
			t.Fatalf("metric family %s has no scalar value", name)
		}
	}
	return 0, false
}

func dataIntegrityHasMetricFamily(metrics []prometheus.Metric, name string) bool {
	needle := `fqName: "` + name + `"`
	for _, metric := range metrics {
		if strings.Contains(metric.Desc().String(), needle) {
			return true
		}
	}
	return false
}

func TestDataIntegrityLibvirtCycleRetainsAtomicallyAndRecoversToFreshEmpty(t *testing.T) {
	mc := newCollectorOrchestrationTestCollector(t)
	firstDomain, firstUUID := dataIntegrityDomain(0x61, "instance-data-integrity-cycle-first")
	secondDomain, secondUUID := dataIntegrityDomain(0x62, "instance-data-integrity-cycle-second")
	now := time.Now()
	mc.im.domainMeta[firstUUID] = &DomainStatic{
		Name:         "server-first",
		InstanceUUID: firstUUID,
		ProjectUUID:  "project",
		ProjectName:  "project-name",
		UserUUID:     "user",
		LastUpdated:  now,
	}
	mc.im.domainMeta[secondUUID] = &DomainStatic{
		Name:         "server-second",
		InstanceUUID: secondUUID,
		LastUpdated:  now.Add(-10 * time.Minute),
	}
	firstRecord := libvirt.DomainStatsRecord{
		Dom: firstDomain,
		Params: []libvirt.TypedParam{
			typedParam("state.state", int32(libvirt.DomainRunning)),
		},
	}
	secondRecord := libvirt.DomainStatsRecord{Dom: secondDomain}

	phase := 0
	mc.fetchDomainStatsOverride = func() ([]libvirt.DomainStatsRecord, float64, error) {
		switch phase {
		case 0:
			return []libvirt.DomainStatsRecord{firstRecord}, 0.01, nil
		case 1:
			return []libvirt.DomainStatsRecord{firstRecord, secondRecord}, 0.02, nil
		case 2:
			return []libvirt.DomainStatsRecord{firstRecord}, 0.03, errors.New("temporary complete-cycle failure after a partial response")
		default:
			return nil, 0.01, nil
		}
	}

	fresh := dataIntegrityRunHeavyCollection(t, mc)
	if got, ok := dataIntegrityMetricFamilyValue(t, fresh, "oie_host_libvirt_ok"); !ok || got != 1 {
		t.Fatalf("fresh Libvirt ok=(%v,%v), want (1,true)", got, ok)
	}
	if got, ok := dataIntegrityMetricFamilyValue(t, fresh, "oie_host_libvirt_active_vms"); !ok || got != 1 {
		t.Fatalf("fresh active VMs=(%v,%v), want (1,true)", got, ok)
	}
	if !mc.im.isInstanceActive(firstUUID) || mc.im.isInstanceActive(secondUUID) {
		t.Fatalf("fresh active set=%v, want only first instance", mc.im.snapshotActiveInstances())
	}
	mc.cacheMu.Lock()
	mc.cachedMetrics = append([]prometheus.Metric(nil), fresh...)
	mc.cacheInitialized = true
	mc.cacheMu.Unlock()
	retainedResource := mc.getResourceV2State(firstUUID)
	retainedResource.OverallHi95Streak = 7
	lastSuccess := mc.libvirtLastSuccessUnix

	phase = 1
	individualFailure := dataIntegrityRunHeavyCollection(t, mc)
	if got, ok := dataIntegrityMetricFamilyValue(t, individualFailure, "oie_host_libvirt_ok"); !ok || got != 0 {
		t.Fatalf("individual-domain failure Libvirt ok=(%v,%v), want (0,true)", got, ok)
	}
	if got, ok := dataIntegrityMetricFamilyValue(t, individualFailure, "oie_host_libvirt_active_vms"); !ok || got != 1 {
		t.Fatalf("individual-domain failure retained active VMs=(%v,%v), want (1,true)", got, ok)
	}
	if !mc.im.isInstanceActive(firstUUID) || mc.im.isInstanceActive(secondUUID) {
		t.Fatalf("individual-domain failure partially committed active set: %v", mc.im.snapshotActiveInstances())
	}
	if mc.resourceV2[firstUUID] != retainedResource || retainedResource.OverallHi95Streak != 7 {
		t.Fatal("individual-domain failure mutated retained resource state")
	}
	if mc.libvirtLastSuccessUnix != lastSuccess {
		t.Fatalf("individual-domain failure moved last success from %d to %d", lastSuccess, mc.libvirtLastSuccessUnix)
	}

	phase = 2
	completeFailure := dataIntegrityRunHeavyCollection(t, mc)
	if got, ok := dataIntegrityMetricFamilyValue(t, completeFailure, "oie_host_libvirt_ok"); !ok || got != 0 {
		t.Fatalf("complete-cycle failure Libvirt ok=(%v,%v), want (0,true)", got, ok)
	}
	if !mc.im.isInstanceActive(firstUUID) || mc.im.isInstanceActive(secondUUID) || retainedResource.OverallHi95Streak != 7 {
		t.Fatal("complete-cycle failure changed retained inventory or resource state")
	}
	if mc.libvirtLastSuccessUnix != lastSuccess {
		t.Fatalf("complete-cycle failure moved last success from %d to %d", lastSuccess, mc.libvirtLastSuccessUnix)
	}

	phase = 3
	emptyRecovery := dataIntegrityRunHeavyCollection(t, mc)
	if got, ok := dataIntegrityMetricFamilyValue(t, emptyRecovery, "oie_host_libvirt_ok"); !ok || got != 1 {
		t.Fatalf("empty recovery Libvirt ok=(%v,%v), want (1,true)", got, ok)
	}
	if got, ok := dataIntegrityMetricFamilyValue(t, emptyRecovery, "oie_host_libvirt_active_vms"); !ok || got != 0 {
		t.Fatalf("empty recovery active VMs=(%v,%v), want (0,true)", got, ok)
	}
	if len(mc.im.snapshotActiveInstances()) != 0 {
		t.Fatalf("empty recovery retained active instances: %v", mc.im.snapshotActiveInstances())
	}
	if _, exists := mc.resourceV2[firstUUID]; exists {
		t.Fatal("empty recovery retained deleted-instance resource state")
	}
	if dataIntegrityHasMetricFamily(emptyRecovery, "oie_instance_info") {
		t.Fatal("empty recovery retained a deleted instance metric")
	}
}

func TestDataIntegrityInitialLibvirtFailureRejectsGenericCache(t *testing.T) {
	mc := newCollectorOrchestrationTestCollector(t)
	genericDesc := prometheus.NewDesc("test_generic_failed_cycle_cache", "not a complete Libvirt cycle", nil, nil)
	mc.cachedMetrics = []prometheus.Metric{prometheus.MustNewConstMetric(genericDesc, prometheus.GaugeValue, 9)}
	mc.cacheInitialized = true
	mc.fetchDomainStatsOverride = func() ([]libvirt.DomainStatsRecord, float64, error) {
		return nil, 0.02, errors.New("initial Libvirt failure")
	}

	for attempt := 0; attempt < 2; attempt++ {
		metrics := dataIntegrityRunHeavyCollection(t, mc)
		if dataIntegrityHasMetricFamily(metrics, "test_generic_failed_cycle_cache") {
			t.Fatal("generic failed-cycle cache was presented as a Libvirt last-good cycle")
		}
		for name, want := range map[string]float64{
			"oie_host_libvirt_ok":                             0,
			"oie_host_libvirt_last_success_timestamp_seconds": 0,
			"oie_host_libvirt_stale_seconds":                  -1,
		} {
			if got, ok := dataIntegrityMetricFamilyValue(t, metrics, name); !ok || got != want {
				t.Fatalf("attempt %d %s=(%v,%v), want (%v,true)", attempt+1, name, got, ok, want)
			}
		}
		if dataIntegrityHasMetricFamily(metrics, "oie_host_libvirt_active_vms") {
			t.Fatal("initial failure emitted unavailable inventory as a healthy zero")
		}
	}
}
