package main

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func TestStaleThreatFeedAndMissingConntrackAreUnavailable(t *testing.T) {
	now := time.Now()
	provider := &IPThreatProvider{Enabled: true, RefreshInterval: time.Hour, LastSuccess: float64(now.Add(-3 * time.Hour).Unix()), EntryCount: 1}
	tm := &ThreatManager{Providers: []*IPThreatProvider{provider}}
	mc := &MetricsCollector{tm: tm, threatSourceState: make(map[string]*ThreatSourceState)}
	metrics := make([]prometheus.Metric, 0)
	mc.collectDomainThreatSignals(nil, nil, "domain", "server", "vm", "project", "name", "user", false, false, true, &metrics)
	if len(metrics) != 0 {
		t.Fatal("unexpected measurement/lifecycle state: len(metrics) != 0")

	}
}
