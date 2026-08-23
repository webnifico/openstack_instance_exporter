package main

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestLibvirtFailureCanEmitLastGoodMetricCycle(t *testing.T) {
	desc := prometheus.NewDesc("test_last_good_cycle", "test", nil, nil)
	want := prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, 7)
	mc := &MetricsCollector{cachedMetrics: []prometheus.Metric{want}}
	ch := make(chan prometheus.Metric, 1)
	if !mc.emitCachedMetrics(ch) {
		t.Fatal("last-good cycle was unavailable")
	}
	close(ch)
	got := <-ch
	if got != want {
		t.Fatal("last-good cycle changed while being preserved")
	}
}

func TestLibvirtFailureWithoutPriorCycleReportsUnavailable(t *testing.T) {
	mc := &MetricsCollector{}
	if mc.emitCachedMetrics(make(chan prometheus.Metric, 1)) {
		t.Fatal("empty cache was treated as valid last-good data")
	}
}
