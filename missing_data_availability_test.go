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
	mc := &MetricsCollector{tm: tm, intelHistory: make(map[string]*IntelHistory)}
	metrics := make([]prometheus.Metric, 0)
	score, available := mc.collectDomainThreatSignals(nil, nil, "domain", "server", "vm", "project", "name", "user", false, &metrics)
	if available || score != 0 || len(metrics) != 0 {
		t.Fatalf("stale/missing intelligence reported healthy: score=%v available=%v metrics=%d", score, available, len(metrics))
	}
}

func TestThreatSeverityPreservesInitializedHistoryDuringInitialReadOutage(t *testing.T) {
	now := time.Now()
	provider := &IPThreatProvider{Enabled: true, RefreshInterval: time.Hour, LastSuccess: float64(now.Unix()), EntryCount: 1}
	tm := &ThreatManager{Providers: []*IPThreatProvider{provider}}
	mc := &MetricsCollector{
		tm: tm,
		intelHistory: map[string]*IntelHistory{
			"vm": {EWMA: 0.8, Initialized: true},
		},
	}
	metrics := make([]prometheus.Metric, 0)
	score, available := mc.collectDomainThreatSignals(nil, nil, "domain", "server", "vm", "project", "name", "user", false, &metrics)
	if !available || score <= 0 || len(metrics) != 0 {
		t.Fatalf("last-known threat history was not preserved: score=%v available=%v metrics=%d", score, available, len(metrics))
	}
}

func TestAttentionAvailabilityRequiresAnAvailableWeightedInput(t *testing.T) {
	cfg := SeverityConfig{ResourceWeight: 0.45, BehaviorWeight: 0.45, ThreatWeight: 0.10}
	if attentionInputsAvailable(cfg, false, false, false) {
		t.Fatal("attention score reported available with no evidence")
	}
	if !attentionInputsAvailable(cfg, true, false, false) {
		t.Fatal("available resource evidence was ignored")
	}
	zeroWeight := SeverityConfig{ResourceWeight: 0, BehaviorWeight: 1, ThreatWeight: 0}
	if attentionInputsAvailable(zeroWeight, true, false, true) {
		t.Fatal("zero-weight evidence incorrectly made attention available")
	}
}
