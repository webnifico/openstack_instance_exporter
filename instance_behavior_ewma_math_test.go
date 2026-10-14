package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"testing"
	"time"
)

func TestBehaviorEWMAOnlyReadsNetworkCounts(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "instance_behavior_ewma_math.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	ast.Inspect(file, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		input, ok := selector.X.(*ast.Ident)
		if !ok || input.Name != "feature" {
			return true
		}
		seen[selector.Sel.Name] = true
		if selector.Sel.Name != "Flows" && selector.Sel.Name != "UniqueRemotes" {
			t.Errorf("EWMA reads input outside its network-count contract: %s", selector.Sel.Name)
		}
		return true
	})
	if !seen["Flows"] || !seen["UniqueRemotes"] {
		t.Fatal("network baseline input disappeared")
	}
}

func TestBehaviorEWMATimestampAndOwnershipBoundaries(t *testing.T) {
	cm := &ConntrackManager{behaviorSensitivity: 1}
	first := behaviorIdentityKey{InstanceUUID: "vm-first", IP: IPStrToKey("10.0.0.1"), Direction: "outbound"}
	low := BehaviorFeature{Flows: 12, UniqueRemotes: 4}
	high := BehaviorFeature{Flows: 120, UniqueRemotes: 40}
	if got := cm.updateBehaviorEWMA(first, low, 0); got != (behaviorAnomalies{}) {
		t.Fatal("initial observation manufactured an anomaly")
	}
	cm.updateBehaviorEWMA(first, high, 15)
	state := cm.behaviorObservations[shardIndexBehavior(first)][first]
	if state.Flows.Fast <= 12 || state.Flows.Fast >= 120 {
		t.Fatalf("Unix epoch boundary lost elapsed-time weighting: %+v", state.Flows)
	}
	before := *state
	cm.updateBehaviorEWMA(first, low, 15)
	if *state != before {
		t.Fatal("duplicate timestamp trained the baseline")
	}
	for _, other := range []behaviorIdentityKey{
		{InstanceUUID: "vm-second", IP: first.IP, Direction: first.Direction},
		{InstanceUUID: first.InstanceUUID, IP: IPStrToKey("10.0.0.2"), Direction: first.Direction},
		{InstanceUUID: first.InstanceUUID, IP: first.IP, Direction: "inbound"},
	} {
		if got := cm.updateBehaviorEWMA(other, high, 30); got != (behaviorAnomalies{}) {
			t.Fatalf("new identity borrowed another baseline: %+v", other)
		}
	}
	if got := cm.updateBehaviorEWMA(first, high, 10); got != (behaviorAnomalies{}) {
		t.Fatal("backward clock step manufactured an anomaly")
	}
	if state.Flows.Fast != 120 || state.Flows.Slow != 120 || state.UniqueRemotes.Fast != 40 || state.UniqueRemotes.Slow != 40 {
		t.Fatalf("backward clock step did not rebaseline: %+v", state)
	}
}

func TestEwmaAlpha(t *testing.T) {
	a := ewmaAlpha(1, 10)
	if a <= 0 || a >= 1 {
		t.Fatalf("alpha out of range: %v", a)
	}
	exp := 1 - math.Exp(-0.1)
	if math.Abs(a-exp) > 1e-6 {
		t.Fatalf("alpha mismatch: got %v want %v", a, exp)
	}
}

func TestUpdateAxisEWMAInitAndMove(t *testing.T) {
	var s axisEWMA
	updateAxisEWMA(&s, 10, 0.2, 0.05)
	if !s.Initialized {
		t.Fatalf("expected initialized")
	}
	if s.Fast != 10 || s.Slow != 10 {
		t.Fatalf("expected fast/slow set to 10, got %v/%v", s.Fast, s.Slow)
	}
	updateAxisEWMA(&s, 20, 0.5, 0.1)
	if s.Fast <= 10 {
		t.Fatalf("expected fast to increase, got %v", s.Fast)
	}
	if s.Slow <= 10 {
		t.Fatalf("expected slow to increase, got %v", s.Slow)
	}
}

func TestBehaviorEWMAFallbackConstants(t *testing.T) {
	if behaviorEWMATauFastDefaultSeconds != 180 {
		t.Fatalf("fast tau default=%v want 180", behaviorEWMATauFastDefaultSeconds)
	}
	if behaviorEWMATauSlowDefaultSeconds != 7200 {
		t.Fatalf("slow tau default=%v want 7200", behaviorEWMATauSlowDefaultSeconds)
	}
}

func TestUpdateBehaviorEWMAUsesDefaultTauFallbacks(t *testing.T) {
	cm := &ConntrackManager{
		behaviorSensitivity: 1.0,
	}
	ident := behaviorIdentityKey{InstanceUUID: "inst-1", Direction: "outbound"}
	idx := shardIndexBehavior(ident)
	cm.behaviorObservations[idx] = make(map[behaviorIdentityKey]*behaviorObservationState)

	feature := BehaviorFeature{
		Flows:          10,
		UniqueRemotes:  4,
		UniqueDstPorts: 3,
		UnrepliedRatio: 0.25,
	}

	_ = cm.updateBehaviorEWMA(ident, feature, 100)
	ew := cm.behaviorObservations[idx][ident]
	if ew == nil {
		t.Fatalf("expected ewma state to be created")
	}
	if !ew.Flows.Initialized || !ew.UniqueRemotes.Initialized {
		t.Fatalf("expected axes initialized after first update")
	}
	if ew.Flows.Fast != float64(feature.Flows) || ew.Flows.Slow != float64(feature.Flows) {
		t.Fatalf("expected initial flows state=%v/%v want %v/%v", ew.Flows.Fast, ew.Flows.Slow, float64(feature.Flows), float64(feature.Flows))
	}
	if ew.UniqueRemotes.Fast != float64(feature.UniqueRemotes) {
		t.Fatalf("expected remote count initialized from feature")
	}

	cm.behaviorEWMATauFast = 0
	cm.behaviorEWMATauSlow = 0
	prevSeen := int64(100)
	ew.LastSeenUnix = prevSeen
	_ = cm.updateBehaviorEWMA(ident, BehaviorFeature{
		Flows:          40,
		UniqueRemotes:  10,
		UniqueDstPorts: 8,
		UnrepliedRatio: 0.5,
	}, 160)
	if ew.LastSeenUnix != 160 {
		t.Fatalf("second update last-seen=%d, want supplied timestamp 160", ew.LastSeenUnix)
	}
	if ew.Flows.Fast <= ew.Flows.Slow {
		t.Fatalf("expected fast EWMA to react faster than slow under fallback taus, got fast=%v slow=%v", ew.Flows.Fast, ew.Flows.Slow)
	}
}

func TestLongGapBehaviorEWMARebaselinesMeasuredFlowAndRemoteCounts(t *testing.T) {
	cm := newBehaviorStateTestManager()
	ident := behaviorIdentityKey{InstanceUUID: "vm-partial-accounting", IP: IPStrToKey("10.0.0.11"), Direction: "outbound"}
	idx := shardIndexBehavior(ident)
	cm.behaviorObservations[idx][ident] = &behaviorObservationState{
		LastSeenUnix: time.Now().Unix() - behaviorIdentityTTLSeconds - 1,
		Flows:        axisEWMA{Fast: 10, Slow: 10, Initialized: true},
	}

	stats := newBehaviorStats(false)
	stats.updateDetailedWithCoverage(
		IPStrToKey("198.51.100.11"),
		443,
		6,
		IPS_SEEN_REPLY,
		1,
		128,
		0,
		true,
		false,
	)
	cm.analyzeBehavior(
		stats,
		ident.IP,
		"10.0.0.11", "ipv4", "domain", "server", ident.InstanceUUID, "project", "project-name", "user",
		nil,
		metricDescGroup{thresholdConfigKey: "outbound"},
		BehaviorContext{},
	)

	ew := cm.behaviorObservations[idx][ident]
	if !ew.Flows.Initialized || ew.Flows.Fast != 1 || ew.Flows.Slow != 1 || !ew.UniqueRemotes.Initialized || ew.UniqueRemotes.Fast != 1 {
		t.Fatalf("long gap did not establish fresh flow and remote baselines: %+v", ew)
	}
}
