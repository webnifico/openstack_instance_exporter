package main

import "testing"

func TestBehaviorAlertTransitionPersistenceGapBoundary(t *testing.T) {
	base := behaviorAlertTransitionInput{
		Kind:     "outbound_horizontal_scan_suspected",
		Feature:  BehaviorFeature{Direction: "outbound", Flows: 10},
		Evidence: behaviorAlertEvidence{EvidenceMode: "distributed"},
		Persistence: behaviorPersistState{
			Hits:          2,
			FirstSeenUnix: 10,
			LastSeenUnix:  100,
		},
	}

	atBoundary := base
	atBoundary.NowUnix = 100 + behaviorAlertPersistenceGapSeconds
	continued := evaluateBehaviorAlertTransition(atBoundary)
	if continued.PersistenceReset || continued.Persistence.Hits != 3 || continued.Persistence.FirstSeenUnix != 10 {
		t.Fatalf("exact persistence-gap boundary reset state: %+v", continued)
	}
	if !continued.PersistenceSatisfied || !continued.ShouldEmit || continued.EmitReason != "new_kind" {
		t.Fatalf("continued transition=%+v, want persisted new-kind emission", continued)
	}

	afterBoundary := base
	afterBoundary.NowUnix = 100 + behaviorAlertPersistenceGapSeconds + 1
	reset := evaluateBehaviorAlertTransition(afterBoundary)
	if !reset.PersistenceReset || reset.Persistence.Hits != 1 || reset.Persistence.FirstSeenUnix != afterBoundary.NowUnix {
		t.Fatalf("long-gap persistence did not reset: %+v", reset)
	}
	if reset.PersistenceSatisfied || reset.ShouldEmit || reset.SuppressReason != "persistence_gate" {
		t.Fatalf("post-reset transition=%+v, want a fresh persistence gate", reset)
	}
}

func TestBehaviorAlertTransitionDecisionBoundaries(t *testing.T) {
	feature := BehaviorFeature{
		Direction:         "outbound",
		Flows:             1_000_000,
		UniqueRemotes:     1,
		NewRemotes:        1,
		UniqueDstPorts:    1,
		NewDstPorts:       1,
		MaxSingleRemote:   1_000_000,
		MaxSingleDstPort:  1_000_000,
		UnrepliedRatio:    0.90,
		HostImpactPercent: 100,
	}
	evidence := behaviorAlertEvidence{
		TopRemoteIP:    "198.51.100.2",
		TopDstPort:     443,
		TopRemoteShare: 1,
		TopPortShare:   1,
		EvidenceMode:   "dominant_remote",
	}
	base := behaviorAlertTransitionInput{
		Kind:     "outbound_horizontal_scan_suspected",
		Feature:  feature,
		Evidence: evidence,
		Persistence: behaviorPersistState{
			Hits:          3,
			FirstSeenUnix: 1,
		},
		Emission: behaviorEmitState{
			LastKind:             "outbound_horizontal_scan_suspected",
			LastPriority:         "P1",
			LastSeverityBand:     "high",
			LastTopRemote:        "198.51.100.1",
			LastTopDstPort:       443,
			LastEpisodeStartUnix: 10,
			LastEmitUnix:         100,
		},
	}

	beforeCooldown := base
	beforeCooldown.NowUnix = 100 + behaviorAlertCooldownSeconds - 1
	beforeCooldown.Persistence.LastSeenUnix = beforeCooldown.NowUnix - 1
	suppressed := evaluateBehaviorAlertTransition(beforeCooldown)
	if suppressed.Priority != "P1" || suppressed.SeverityBand != "high" {
		t.Fatalf("fixture priority/band=%s/%s, want P1/high", suppressed.Priority, suppressed.SeverityBand)
	}
	if suppressed.ShouldEmit || suppressed.EmitReason != "changed" || suppressed.SuppressReason != "cooldown" {
		t.Fatalf("endpoint change before cooldown boundary=%+v", suppressed)
	}
	if suppressed.Emission.LastTopRemote != base.Emission.LastTopRemote ||
		suppressed.Emission.LastEpisodeStartUnix != base.Emission.LastEpisodeStartUnix ||
		suppressed.Emission.LastEmitUnix != base.Emission.LastEmitUnix {
		t.Fatalf("suppressed transition mutated last-emitted evidence: %+v", suppressed.Emission)
	}

	atCooldown := base
	atCooldown.NowUnix = 100 + behaviorAlertCooldownSeconds
	atCooldown.Persistence.LastSeenUnix = atCooldown.NowUnix - 1
	changed := evaluateBehaviorAlertTransition(atCooldown)
	if !changed.ShouldEmit || changed.EmitReason != "changed" || changed.SuppressReason != "" {
		t.Fatalf("endpoint change at cooldown boundary=%+v", changed)
	}
	if changed.Emission.LastTopRemote != evidence.TopRemoteIP || changed.Emission.LastEmitUnix != atCooldown.NowUnix {
		t.Fatalf("emitted endpoint state=%+v", changed.Emission)
	}

	escalation := base
	escalation.NowUnix = 101
	escalation.Persistence.LastSeenUnix = 100
	escalation.Emission.LastPriority = "P2"
	escalation.Emission.LastTopRemote = evidence.TopRemoteIP
	escalated := evaluateBehaviorAlertTransition(escalation)
	if !escalated.ShouldEmit || escalated.EmitReason != "escalated" {
		t.Fatalf("priority escalation was incorrectly cooled down: %+v", escalated)
	}

	bandInput := base
	bandInput.NowUnix = 100 + behaviorAlertCooldownSeconds
	bandInput.Persistence.LastSeenUnix = bandInput.NowUnix - 1
	bandInput.Emission.LastSeverityBand = "critical"
	bandInput.Emission.LastTopRemote = evidence.TopRemoteIP
	bandChanged := evaluateBehaviorAlertTransition(bandInput)
	if !bandChanged.ShouldEmit || bandChanged.EmitReason != "band_cross" {
		t.Fatalf("severity-band crossing at cooldown boundary=%+v", bandChanged)
	}

	beforeHeartbeat := base
	beforeHeartbeat.NowUnix = 100 + behaviorAlertHeartbeatSeconds - 1
	beforeHeartbeat.Persistence.LastSeenUnix = beforeHeartbeat.NowUnix - 1
	beforeHeartbeat.Emission.LastTopRemote = evidence.TopRemoteIP
	if got := evaluateBehaviorAlertTransition(beforeHeartbeat); got.ShouldEmit {
		t.Fatalf("heartbeat emitted early: %+v", got)
	}

	atHeartbeat := beforeHeartbeat
	atHeartbeat.NowUnix++
	atHeartbeat.Persistence.LastSeenUnix = atHeartbeat.NowUnix - 1
	heartbeat := evaluateBehaviorAlertTransition(atHeartbeat)
	if !heartbeat.ShouldEmit || heartbeat.EmitReason != "heartbeat" || heartbeat.SuppressReason != "" {
		t.Fatalf("heartbeat boundary=%+v", heartbeat)
	}
}

func TestBehaviorAlertTransitionReemitsReconfirmedIncidentAfterPersistenceGap(t *testing.T) {
	firstRecurrentHit := behaviorAlertTransitionInput{
		NowUnix: 281,
		Kind:    "outbound_horizontal_scan_suspected",
		Feature: BehaviorFeature{
			Direction:      "outbound",
			Flows:          30,
			UniqueRemotes:  30,
			UniqueDstPorts: 1,
		},
		Evidence: behaviorAlertEvidence{EvidenceMode: "distributed"},
		Persistence: behaviorPersistState{
			Hits:          3,
			FirstSeenUnix: 10,
			LastSeenUnix:  100,
		},
		Emission: behaviorEmitState{
			LastKind:             "outbound_horizontal_scan_suspected",
			LastPriority:         "P4",
			LastSeverityBand:     "low",
			LastEpisodeStartUnix: 10,
			LastEmitUnix:         100,
		},
	}
	first := evaluateBehaviorAlertTransition(firstRecurrentHit)
	if !first.PersistenceReset || first.Persistence.Hits != 1 || first.ShouldEmit {
		t.Fatalf("first recurrent hit=%+v, want reset persistence without emission", first)
	}
	if first.Emission.LastEpisodeStartUnix != firstRecurrentHit.Emission.LastEpisodeStartUnix {
		t.Fatalf("pre-persistence recurrence mutated last-emitted episode: %+v", first.Emission)
	}

	input := behaviorAlertTransitionInput{
		NowUnix: 402,
		Kind:    "outbound_horizontal_scan_suspected",
		Feature: BehaviorFeature{
			Direction:      "outbound",
			Flows:          30,
			UniqueRemotes:  30,
			UniqueDstPorts: 1,
		},
		Evidence: behaviorAlertEvidence{EvidenceMode: "distributed"},
		Persistence: behaviorPersistState{
			Hits:          2,
			FirstSeenUnix: 400,
			LastSeenUnix:  401,
		},
		Emission: behaviorEmitState{
			LastKind:             "outbound_horizontal_scan_suspected",
			LastPriority:         "P4",
			LastSeverityBand:     "low",
			LastEpisodeStartUnix: 10,
			LastEmitUnix:         100,
		},
	}

	result := evaluateBehaviorAlertTransition(input)
	if !result.PersistenceSatisfied || !result.ShouldEmit || result.EmitReason != "changed" {
		t.Fatalf("reconfirmed incident transition=%+v, want a changed emission after the cleared persistence gap", result)
	}
}
