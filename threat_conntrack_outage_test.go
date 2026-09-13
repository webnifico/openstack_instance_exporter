package main

import (
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func TestConntrackOutageDoesNotAdvanceThreatContactState(t *testing.T) {
	tm := &ThreatManager{threatLastHit: make(map[string]time.Time)}
	activeDesc := prometheus.NewDesc("test_threat_active", "test", labelsInstance("direction"), nil)
	totalDesc := prometheus.NewDesc("test_threat_total", "test", labelsInstance("direction"), nil)
	countMap := map[string]float64{"vm-1": 5}
	prevHits := map[string]map[string]struct{}{"vm-1": {"old": {}}}
	var countMu sync.Mutex
	var prevMu sync.Mutex
	hits := map[PairKey]ConntrackEntry{
		MakePairKey(IPStrToKey("10.0.0.10"), 1000, IPStrToKey("198.51.100.20"), 443, 6): {
			Src: "10.0.0.10", Dst: "198.51.100.20", SrcPort: 1000, DstPort: 443, Proto: 6,
		},
	}
	metrics := make([]prometheus.Metric, 0)
	signal := 0.0
	tm.exportThreatHitsCommon(
		"test", ContactOut, hits, 0, map[string]struct{}{"10.0.0.10": {}},
		"domain", "server", "vm-1", "project", "project-name", "user",
		&metrics, &signal, activeDesc, totalDesc,
		countMap, &countMu, prevHits, &prevMu, false,
	)
	if countMap["vm-1"] != 5 {
		t.Fatalf("stale contacts incremented total: got %v", countMap["vm-1"])
	}
	if _, ok := prevHits["vm-1"]["old"]; !ok || len(prevHits["vm-1"]) != 1 {
		t.Fatalf("stale contacts replaced previous hit set: %#v", prevHits["vm-1"])
	}
	if signal <= 0 || len(metrics) != 2 {
		t.Fatalf("stale last-good metrics were not preserved: signal=%v metrics=%d", signal, len(metrics))
	}
}
