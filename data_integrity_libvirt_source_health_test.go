package main

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func newDataIntegrityLibvirtHealthTestCollector(t *testing.T) *MetricsCollector {
	t.Helper()
	mc, err := NewMetricsCollector(CollectorConfig{
		LibvirtURI:          "qemu:///system",
		CollectionInterval:  time.Hour,
		ConntrackIPv4Enable: false,
		ConntrackIPv6Enable: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { close(mc.shutdownChan) })
	return mc
}

func dataIntegrityLibvirtMetricValues(t *testing.T, metrics []prometheus.Metric) map[string]float64 {
	t.Helper()
	registry := prometheus.NewRegistry()
	registry.MustRegister(staticMetricCollector{metrics: metrics})
	families, err := registry.Gather()
	if err != nil {
		t.Fatalf("gather Libvirt source-health metrics: %v", err)
	}

	values := make(map[string]float64, len(families))
	for _, family := range families {
		if family.GetName() == "oie_host_threat_feed_fresh" {
			dataIntegrityAssertDisabledThreatFeedFamily(t, family)
			continue
		}
		if family.GetName() == "oie_host_volume_retype_results_total" {
			if len(family.Metric) != 3 {
				t.Fatalf("metric family %s samples=%d, want fixed result set 3", family.GetName(), len(family.Metric))
			}
			continue
		}
		if len(family.Metric) != 1 {
			t.Fatalf("metric family %s samples=%d, want 1", family.GetName(), len(family.Metric))
		}
		metric := family.Metric[0]
		switch {
		case metric.Gauge != nil:
			values[family.GetName()] = metric.GetGauge().GetValue()
		case metric.Counter != nil:
			values[family.GetName()] = metric.GetCounter().GetValue()
		default:
			t.Fatalf("metric family %s has no scalar value", family.GetName())
		}
	}
	return values
}

func dataIntegrityAssertDisabledThreatFeedFamily(t *testing.T, family *dto.MetricFamily) {
	t.Helper()
	want := map[string]float64{
		"TOREXIT":    -1,
		"TORRELAY":   -1,
		"EMERGING":   -1,
		"CUSTOMLIST": -1,
		"spamhaus":   -1,
	}
	if len(family.Metric) != len(want) {
		t.Fatalf("metric family %s samples=%d, want fixed tri-state set %d", family.GetName(), len(family.Metric), len(want))
	}
	for _, metric := range family.Metric {
		list := ""
		for _, label := range metric.Label {
			if label.GetName() == "list" {
				list = label.GetValue()
			}
		}
		expected, exists := want[list]
		if !exists {
			t.Fatalf("metric family %s has unexpected or duplicate list label %q", family.GetName(), list)
		}
		if metric.Gauge == nil || metric.GetGauge().GetValue() != expected {
			t.Fatalf("metric family %s list %q value=%v, want disabled tri-state %v", family.GetName(), list, metric.GetGauge().GetValue(), expected)
		}
		delete(want, list)
	}
	if len(want) != 0 {
		t.Fatalf("metric family %s missing fixed feed states: %v", family.GetName(), want)
	}
}

func TestDataIntegrityLibvirtSourceHealthStateTransitions(t *testing.T) {
	mc := newDataIntegrityLibvirtHealthTestCollector(t)
	firstSuccess := time.Unix(1_700_000_000, 0)

	ok, lastSuccess, staleSeconds := mc.libvirtSourceHealthSnapshot(firstSuccess)
	if ok != 0 || lastSuccess != 0 || staleSeconds != -1 {
		t.Fatalf("initial health=(%v,%v,%v), want (0,0,-1)", ok, lastSuccess, staleSeconds)
	}

	mc.recordLibvirtCollectionResult(true, firstSuccess)
	ok, lastSuccess, staleSeconds = mc.libvirtSourceHealthSnapshot(firstSuccess.Add(10 * time.Second))
	if ok != 1 || lastSuccess != float64(firstSuccess.Unix()) || staleSeconds != 10 {
		t.Fatalf("successful health=(%v,%v,%v), want (1,%d,10)", ok, lastSuccess, staleSeconds, firstSuccess.Unix())
	}

	mc.recordLibvirtCollectionResult(false, firstSuccess.Add(10*time.Second))
	ok, lastSuccess, staleSeconds = mc.libvirtSourceHealthSnapshot(firstSuccess.Add(25 * time.Second))
	if ok != 0 || lastSuccess != float64(firstSuccess.Unix()) || staleSeconds != 25 {
		t.Fatalf("retained health=(%v,%v,%v), want (0,%d,25)", ok, lastSuccess, staleSeconds, firstSuccess.Unix())
	}

	_, _, staleSeconds = mc.libvirtSourceHealthSnapshot(firstSuccess.Add(-time.Second))
	if staleSeconds != 0 {
		t.Fatalf("backward-clock stale seconds=%v, want 0", staleSeconds)
	}

	recovery := firstSuccess.Add(time.Minute)
	mc.recordLibvirtCollectionResult(true, recovery)
	ok, lastSuccess, staleSeconds = mc.libvirtSourceHealthSnapshot(recovery)
	if ok != 1 || lastSuccess != float64(recovery.Unix()) || staleSeconds != 0 {
		t.Fatalf("recovered health=(%v,%v,%v), want (1,%d,0)", ok, lastSuccess, staleSeconds, recovery.Unix())
	}
}

func TestDataIntegrityLibvirtSourceHealthMetricContract(t *testing.T) {
	mc := newDataIntegrityLibvirtHealthTestCollector(t)
	now := time.Unix(1_700_000_000, 0)
	values := dataIntegrityLibvirtMetricValues(t, mc.libvirtSourceHealthMetrics(now))
	want := map[string]float64{
		"oie_host_libvirt_ok":                             0,
		"oie_host_libvirt_last_success_timestamp_seconds": 0,
		"oie_host_libvirt_stale_seconds":                  -1,
	}
	if len(values) != len(want) {
		t.Fatalf("Libvirt health families=%v, want exactly %v", values, want)
	}
	for name, expected := range want {
		if got, exists := values[name]; !exists || got != expected {
			t.Errorf("%s=(%v,%v), want (%v,true)", name, got, exists, expected)
		}
	}

	for _, metric := range mc.libvirtSourceHealthMetrics(now) {
		if len(metric.Desc().String()) == 0 {
			t.Fatal("Libvirt health metric has an empty descriptor")
		}
	}
}

func TestDataIntegrityLibvirtSourceHealthNormalEmissionDistinguishesUnavailableAndEmpty(t *testing.T) {
	mc := newDataIntegrityLibvirtHealthTestCollector(t)
	emit := func(available bool) map[string]float64 {
		ch := make(chan prometheus.Metric, 128)
		mc.emitHostAndAggMetrics(
			ch,
			nil,
			&hostAgg{projects: make(map[string]struct{})},
			0, 0, 0, 0, 0, 0, 0, 0,
			available, false, false,
		)
		close(ch)
		metrics := make([]prometheus.Metric, 0, len(ch))
		for metric := range ch {
			metrics = append(metrics, metric)
		}
		return dataIntegrityLibvirtMetricValues(t, metrics)
	}

	unavailable := emit(false)
	if unavailable["oie_host_libvirt_ok"] != 0 ||
		unavailable["oie_host_libvirt_last_success_timestamp_seconds"] != 0 ||
		unavailable["oie_host_libvirt_stale_seconds"] != -1 {
		t.Fatalf("unavailable Libvirt health=%v", unavailable)
	}
	if _, exists := unavailable["oie_host_libvirt_active_vms"]; exists {
		t.Fatal("unavailable Libvirt inventory emitted a healthy active-VM zero")
	}

	empty := emit(true)
	if empty["oie_host_libvirt_ok"] != 1 || empty["oie_host_libvirt_last_success_timestamp_seconds"] <= 0 {
		t.Fatalf("successful empty Libvirt health=%v", empty)
	}
	if empty["oie_host_libvirt_stale_seconds"] < 0 || empty["oie_host_libvirt_stale_seconds"] >= 1 {
		t.Fatalf("successful empty Libvirt stale seconds=%v, want [0,1)", empty["oie_host_libvirt_stale_seconds"])
	}
	if activeVMs, exists := empty["oie_host_libvirt_active_vms"]; !exists || activeVMs != 0 {
		t.Fatalf("successful empty active VMs=(%v,%v), want (0,true)", activeVMs, exists)
	}
}

func TestDataIntegrityLibvirtSourceHealthCachedFallbackOverlaysWithoutDuplicates(t *testing.T) {
	mc := newDataIntegrityLibvirtHealthTestCollector(t)
	lastSuccess := time.Now().Add(-30 * time.Second).Truncate(time.Second)
	mc.recordLibvirtCollectionResult(true, lastSuccess)

	customDesc := prometheus.NewDesc("test_libvirt_retained_metric", "test", nil, nil)
	mc.cachedMetrics = append(
		[]prometheus.Metric{prometheus.MustNewConstMetric(customDesc, prometheus.GaugeValue, 7)},
		mc.libvirtSourceHealthMetrics(lastSuccess)...,
	)

	ch := make(chan prometheus.Metric, 128)
	if !mc.emitCachedMetricsWithLiveHealth(ch, 1, 2, 3) {
		t.Fatal("cached Libvirt fallback was unavailable")
	}
	close(ch)
	metrics := make([]prometheus.Metric, 0, len(ch))
	for metric := range ch {
		metrics = append(metrics, metric)
	}
	values := dataIntegrityLibvirtMetricValues(t, metrics)

	if values["test_libvirt_retained_metric"] != 7 {
		t.Fatalf("retained metric=%v, want 7", values["test_libvirt_retained_metric"])
	}
	if values["oie_host_libvirt_ok"] != 0 {
		t.Fatalf("cached fallback Libvirt ok=%v, want 0", values["oie_host_libvirt_ok"])
	}
	if values["oie_host_libvirt_last_success_timestamp_seconds"] != float64(lastSuccess.Unix()) {
		t.Fatalf("cached fallback last success=%v, want %d", values["oie_host_libvirt_last_success_timestamp_seconds"], lastSuccess.Unix())
	}
	if values["oie_host_libvirt_stale_seconds"] < 30 {
		t.Fatalf("cached fallback stale seconds=%v, want at least 30", values["oie_host_libvirt_stale_seconds"])
	}
	if values["oie_host_collection_interval_seconds"] != mc.collectionInterval.Seconds() {
		t.Fatalf("cached fallback collection interval=%v, want %v", values["oie_host_collection_interval_seconds"], mc.collectionInterval.Seconds())
	}
}
