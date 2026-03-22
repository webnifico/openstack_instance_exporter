package main

import (
	"math"
	"testing"
	"time"
)

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
	cm.behaviorEWMA[idx] = make(map[behaviorIdentityKey]*behaviorEWMAState)

	feature := BehaviorFeature{
		Flows:          10,
		UniqueRemotes:  4,
		UniqueDstPorts: 3,
		UnrepliedRatio: 0.25,
	}

	_, _ = cm.updateBehaviorEWMA(ident, feature)
	ew := cm.behaviorEWMA[idx][ident]
	if ew == nil {
		t.Fatalf("expected ewma state to be created")
	}
	if !ew.Flows.Initialized || !ew.UniqueRemotes.Initialized || !ew.UniquePorts.Initialized || !ew.Unreplied.Initialized {
		t.Fatalf("expected axes initialized after first update")
	}
	if ew.Flows.Fast != float64(feature.Flows) || ew.Flows.Slow != float64(feature.Flows) {
		t.Fatalf("expected initial flows state=%v/%v want %v/%v", ew.Flows.Fast, ew.Flows.Slow, float64(feature.Flows), float64(feature.Flows))
	}
	if ew.UniqueRemotes.Fast != float64(feature.UniqueRemotes) || ew.UniquePorts.Fast != float64(feature.UniqueDstPorts) {
		t.Fatalf("expected remotes/ports initialized from feature")
	}

	cm.behaviorEWMATauFast = 0
	cm.behaviorEWMATauSlow = 0
	prevSeen := time.Now().Unix() - 60
	ew.LastSeenUnix = prevSeen
	_, _ = cm.updateBehaviorEWMA(ident, BehaviorFeature{
		Flows:          40,
		UniqueRemotes:  10,
		UniqueDstPorts: 8,
		UnrepliedRatio: 0.5,
	})
	if ew.LastSeenUnix <= prevSeen {
		t.Fatalf("expected second update to advance last-seen timestamp")
	}
	if ew.Flows.Fast <= ew.Flows.Slow {
		t.Fatalf("expected fast EWMA to react faster than slow under fallback taus, got fast=%v slow=%v", ew.Flows.Fast, ew.Flows.Slow)
	}
}
