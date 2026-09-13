package main

import (
	"math"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

type resourceTelemetryCachedResourceFixture struct {
	mc           *MetricsCollector
	instanceUUID string
	lastSuccess  time.Time
}

func newResourceTelemetryCachedResourceFixture(t *testing.T, lastSuccess time.Time) resourceTelemetryCachedResourceFixture {
	t.Helper()

	const instanceUUID = "00112233-4455-6677-8899-aabbccddeeff"
	mc, err := NewMetricsCollector(CollectorConfig{
		LibvirtURI:         "qemu:///system",
		CollectionInterval: 10 * time.Second,
		Severity:           SeverityConfig{ResourceWeight: 1},
	})
	if err != nil {
		t.Fatalf("NewMetricsCollector: %v", err)
	}
	t.Cleanup(func() { close(mc.shutdownChan) })

	labels := []string{
		"instance-resource-telemetry-cached",
		"server-resource-telemetry-cached",
		instanceUUID,
		"project-resource-telemetry-cached",
		"project-name-resource-telemetry-cached",
		"user-resource-telemetry-cached",
	}
	out, _ := mc.computeResourceV2(instanceUUID, resourceV2Input{
		Now:          lastSuccess,
		CpuAvailable: true,
		CpuPRaw:      1,
		CpuConf:      1,
		CpuImpact:    1,
		CpuSources:   []string{"cpu.time"},
		CpuIdentity:  "vcpu-count=2",
	})

	cached := make([]prometheus.Metric, 0, 24)
	appendInstanceResourceAxisHealthMetrics(
		mc,
		&cached,
		out,
		labels[0], labels[1], labels[2], labels[3], labels[4], labels[5],
	)
	cached = append(cached,
		prometheus.MustNewConstMetric(mc.instanceResourceCpuSeverityDesc, prometheus.GaugeValue, out.CPU.Sev, labels...),
		prometheus.MustNewConstMetric(mc.instanceResourceSeverityDesc, prometheus.GaugeValue, out.OverallFinal, labels...),
		prometheus.MustNewConstMetric(mc.instanceAttentionSeverityDesc, prometheus.GaugeValue, out.OverallFinal, labels...),
	)

	mc.cacheMu.Lock()
	mc.cachedMetrics = cached
	mc.cacheMu.Unlock()
	mc.recordLibvirtCollectionResult(true, lastSuccess)

	return resourceTelemetryCachedResourceFixture{
		mc:           mc,
		instanceUUID: instanceUUID,
		lastSuccess:  lastSuccess,
	}
}

func resourceTelemetryCollectCachedResourceFallback(t *testing.T, mc *MetricsCollector) []*dto.MetricFamily {
	t.Helper()

	metricCh := make(chan prometheus.Metric, 256)
	if !mc.emitCachedMetricsWithLiveHealth(metricCh, 0.5, 0.25, 0.1) {
		t.Fatal("cached resource fallback was unavailable")
	}
	close(metricCh)

	metrics := make([]prometheus.Metric, 0, len(metricCh))
	for metric := range metricCh {
		metrics = append(metrics, metric)
	}
	registry := prometheus.NewRegistry()
	registry.MustRegister(staticMetricCollector{metrics: metrics})
	families, err := registry.Gather()
	if err != nil {
		t.Fatalf("cached resource fallback contains duplicate or invalid series: %v", err)
	}
	return families
}

func resourceTelemetryCachedResourceSample(
	t *testing.T,
	families []*dto.MetricFamily,
	familyName string,
	labels map[string]string,
) (float64, bool) {
	t.Helper()

	for _, family := range families {
		if family.GetName() != familyName {
			continue
		}
		for _, sample := range family.Metric {
			matches := true
			for labelName, labelValue := range labels {
				found := false
				for _, pair := range sample.Label {
					if pair.GetName() == labelName && pair.GetValue() == labelValue {
						found = true
						break
					}
				}
				if !found {
					matches = false
					break
				}
			}
			if !matches {
				continue
			}
			switch {
			case sample.Gauge != nil:
				return sample.GetGauge().GetValue(), true
			case sample.Counter != nil:
				return sample.GetCounter().GetValue(), true
			default:
				t.Fatalf("metric family %s has no scalar value", familyName)
			}
		}
	}
	return 0, false
}

func resourceTelemetryCachedResourceFamilySampleCount(families []*dto.MetricFamily, familyName string) int {
	for _, family := range families {
		if family.GetName() == familyName {
			return len(family.Metric)
		}
	}
	return 0
}

func TestResourceTelemetryCachedLibvirtFallbackOverlaysLiveResourceAxisLifecycle(t *testing.T) {
	now := time.Now()
	fixture := newResourceTelemetryCachedResourceFixture(t, now.Add(-30*time.Second))
	families := resourceTelemetryCollectCachedResourceFallback(t, fixture.mc)
	cpuLabels := map[string]string{
		"instance_uuid": fixture.instanceUUID,
		"axis":          "cpu",
	}

	if fresh, ok := resourceTelemetryCachedResourceSample(t, families, "oie_instance_resource_axis_fresh", cpuLabels); !ok || fresh != 0 {
		t.Fatalf("cached CPU freshness=(%v,%v), want (0,true)", fresh, ok)
	}
	if available, ok := resourceTelemetryCachedResourceSample(t, families, "oie_instance_resource_axis_available", cpuLabels); !ok || available != 1 {
		t.Fatalf("retained cached CPU availability=(%v,%v), want (1,true)", available, ok)
	}
	lastSuccess, ok := resourceTelemetryCachedResourceSample(t, families, "oie_instance_resource_axis_last_success_timestamp_seconds", cpuLabels)
	if !ok || math.Abs(lastSuccess-resourceAxisLastSuccessTimestamp(fixture.lastSuccess)) > 0.001 {
		t.Fatalf("cached CPU last success=(%v,%v), want %v", lastSuccess, ok, resourceAxisLastSuccessTimestamp(fixture.lastSuccess))
	}
	staleSeconds, ok := resourceTelemetryCachedResourceSample(t, families, "oie_instance_resource_axis_stale_seconds", cpuLabels)
	if !ok || staleSeconds < 30 || staleSeconds > 35 {
		t.Fatalf("cached CPU stale seconds=(%v,%v), want [30,35]", staleSeconds, ok)
	}

	for _, familyName := range []string{
		"oie_instance_resource_axis_fresh",
		"oie_instance_resource_axis_available",
		"oie_instance_resource_axis_last_success_timestamp_seconds",
		"oie_instance_resource_axis_stale_seconds",
	} {
		if count := resourceTelemetryCachedResourceFamilySampleCount(families, familyName); count != len(resourceAxisNames) {
			t.Fatalf("cached lifecycle family %s samples=%d, want exactly %d", familyName, count, len(resourceAxisNames))
		}
	}

	instanceLabels := map[string]string{"instance_uuid": fixture.instanceUUID}
	for _, familyName := range []string{
		"oie_instance_resource_cpu_severity",
		"oie_instance_resource_severity",
		"oie_instance_attention_severity",
	} {
		if _, ok := resourceTelemetryCachedResourceSample(t, families, familyName, instanceLabels); !ok {
			t.Fatalf("trustworthy retained cached family %s was omitted before expiry", familyName)
		}
	}
}

func TestResourceTelemetryCachedLibvirtFallbackCannotReplayExpiredResourceOrAttentionSeverity(t *testing.T) {
	interval := 10 * time.Second
	lastSuccess := time.Now().Add(-resourceAxisMaxRetainedAge(interval) - 5*time.Second)
	fixture := newResourceTelemetryCachedResourceFixture(t, lastSuccess)
	families := resourceTelemetryCollectCachedResourceFallback(t, fixture.mc)
	cpuLabels := map[string]string{
		"instance_uuid": fixture.instanceUUID,
		"axis":          "cpu",
	}

	if fresh, ok := resourceTelemetryCachedResourceSample(t, families, "oie_instance_resource_axis_fresh", cpuLabels); !ok || fresh != 0 {
		t.Fatalf("expired cached CPU freshness=(%v,%v), want (0,true)", fresh, ok)
	}
	if available, ok := resourceTelemetryCachedResourceSample(t, families, "oie_instance_resource_axis_available", cpuLabels); !ok || available != 0 {
		t.Fatalf("expired cached CPU availability=(%v,%v), want (0,true)", available, ok)
	}
	staleSeconds, ok := resourceTelemetryCachedResourceSample(t, families, "oie_instance_resource_axis_stale_seconds", cpuLabels)
	if !ok || staleSeconds <= resourceAxisMaxRetainedAge(interval).Seconds() {
		t.Fatalf("expired cached CPU stale seconds=(%v,%v), want greater than %v", staleSeconds, ok, resourceAxisMaxRetainedAge(interval).Seconds())
	}

	instanceLabels := map[string]string{"instance_uuid": fixture.instanceUUID}
	for _, familyName := range []string{
		"oie_instance_resource_cpu_severity",
		"oie_instance_resource_severity",
		"oie_instance_attention_severity",
	} {
		if value, ok := resourceTelemetryCachedResourceSample(t, families, familyName, instanceLabels); ok {
			t.Fatalf("expired cached family %s replayed value %v", familyName, value)
		}
	}
}

func TestResourceTelemetryCachedFailureMarksAxisMissingBeforeWithinGraceRecovery(t *testing.T) {
	interval := 10 * time.Second
	base := time.Unix(1_700_617_000, 0)
	fixture := newResourceTelemetryCachedResourceFixture(t, base)

	fixture.mc.cacheMu.RLock()
	cached := append([]prometheus.Metric(nil), fixture.mc.cachedMetrics...)
	fixture.mc.cacheMu.RUnlock()
	fixture.mc.overlayCachedResourceMetrics(cached, base.Add(interval))
	state, ok := fixture.mc.lookupResourceV2State(fixture.instanceUUID)
	if !ok || state == nil || !state.Cpu.Missing {
		t.Fatalf("cached full-source failure did not mark CPU history missing: %+v", state)
	}

	recovered, _ := fixture.mc.computeResourceV2(fixture.instanceUUID, resourceV2Input{
		Now:          base.Add(2 * interval),
		CpuAvailable: true,
		CpuPRaw:      0,
		CpuConf:      1,
		CpuImpact:    1,
		CpuSources:   []string{"cpu.time"},
		CpuIdentity:  "vcpu-count=2",
	})
	wantAlpha := 1 - math.Exp(-interval.Seconds()/120.0)
	wantEWMA := 1 - wantAlpha
	if recovered.CPU.Recovery {
		t.Fatalf("exact grace-boundary recovery was classified as post-grace: %+v", recovered.CPU)
	}
	if math.Abs(recovered.CPU.Alpha-wantAlpha) > 1e-12 || math.Abs(recovered.CPU.EWMA-wantEWMA) > 1e-12 {
		t.Fatalf("cached outage advanced EWMA time: alpha=%v want=%v ewma=%v want=%v", recovered.CPU.Alpha, wantAlpha, recovered.CPU.EWMA, wantEWMA)
	}
}
