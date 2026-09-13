package main

import "testing"

func TestBehaviorAlertTransitionRequiresHitsAndMinimumElapsedTime(t *testing.T) {
	tests := []struct {
		name         string
		kind         string
		feature      BehaviorFeature
		evidence     behaviorAlertEvidence
		requiredHits int
		minimum      int64
	}{
		{
			name: "two hits",
			kind: "outbound_horizontal_scan_suspected",
			feature: BehaviorFeature{
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
			},
			evidence: behaviorAlertEvidence{
				TopRemoteShare: 1,
				TopPortShare:   1,
				EvidenceMode:   "dominant_remote",
			},
			requiredHits: 2,
			minimum:      15,
		},
		{
			name:         "three hits",
			kind:         "outbound_horizontal_scan_suspected",
			feature:      BehaviorFeature{Direction: "outbound", Flows: 10},
			evidence:     behaviorAlertEvidence{EvidenceMode: "distributed"},
			requiredHits: 3,
			minimum:      30,
		},
		{
			name: "six hits",
			kind: miningBehaviorKind,
			feature: BehaviorFeature{
				Direction: "outbound",
				Flows:     1,
				Mining: miningDetectionEvidence{
					Valid:      true,
					Confidence: miningPortConfidenceSharedPersistent,
				},
			},
			evidence:     behaviorAlertEvidence{EvidenceMode: "dominant_remote"},
			requiredHits: 6,
			minimum:      75,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const firstSeen int64 = 100
			before := evaluateBehaviorAlertTransition(behaviorAlertTransitionInput{
				NowUnix:  firstSeen + tt.minimum - 1,
				Kind:     tt.kind,
				Feature:  tt.feature,
				Evidence: tt.evidence,
				Persistence: behaviorPersistState{
					Hits:          tt.requiredHits - 1,
					FirstSeenUnix: firstSeen,
					LastSeenUnix:  firstSeen + tt.minimum - 2,
				},
			})
			if before.PersistenceRequired != tt.requiredHits ||
				before.PersistenceMinimumElapsedSeconds != tt.minimum ||
				before.PersistenceElapsedSeconds != tt.minimum-1 {
				t.Fatalf("pre-boundary contract=%+v, want hits=%d elapsed=%d/%d", before, tt.requiredHits, tt.minimum-1, tt.minimum)
			}
			if before.PersistenceSatisfied || before.ShouldEmit || before.SuppressReason != "persistence_gate" {
				t.Fatalf("pre-boundary transition matured: %+v", before)
			}

			exact := evaluateBehaviorAlertTransition(behaviorAlertTransitionInput{
				NowUnix:  firstSeen + tt.minimum,
				Kind:     tt.kind,
				Feature:  tt.feature,
				Evidence: tt.evidence,
				Persistence: behaviorPersistState{
					Hits:          tt.requiredHits - 1,
					FirstSeenUnix: firstSeen,
					LastSeenUnix:  firstSeen + tt.minimum - 1,
				},
			})
			if !exact.PersistenceSatisfied || !exact.ShouldEmit || exact.PersistenceElapsedSeconds != tt.minimum {
				t.Fatalf("exact-boundary transition=%+v, want satisfied at %ds", exact, tt.minimum)
			}
		})
	}
}

func TestBehaviorAlertTransitionTreatsUnixEpochAsARealFirstObservation(t *testing.T) {
	input := behaviorAlertTransitionInput{
		NowUnix: 0,
		Kind:    "outbound_horizontal_scan_suspected",
		Feature: BehaviorFeature{Direction: "outbound", Flows: 10},
		Evidence: behaviorAlertEvidence{
			EvidenceMode: "distributed",
		},
	}
	first := evaluateBehaviorAlertTransition(input)
	if first.Persistence.Hits != 1 || first.Persistence.FirstSeenUnix != 0 || first.Persistence.LastSeenUnix != 0 {
		t.Fatalf("epoch first observation=%+v, want one hit rooted at zero", first)
	}

	input.Persistence = first.Persistence
	duplicate := evaluateBehaviorAlertTransition(input)
	if duplicate.Persistence.Hits != 1 || duplicate.PersistenceSatisfied || duplicate.ShouldEmit {
		t.Fatalf("duplicate epoch observation advanced state: %+v", duplicate)
	}

	input.NowUnix = 15
	input.Persistence = duplicate.Persistence
	second := evaluateBehaviorAlertTransition(input)
	if second.Persistence.Hits != 2 || second.Persistence.FirstSeenUnix != 0 || second.PersistenceSatisfied {
		t.Fatalf("second distinct observation=%+v, want two hits retaining epoch boundary", second)
	}

	input.NowUnix = 30
	input.Persistence = second.Persistence
	third := evaluateBehaviorAlertTransition(input)
	if third.Persistence.Hits != 3 || third.Persistence.FirstSeenUnix != 0 ||
		!third.PersistenceSatisfied || !third.ShouldEmit {
		t.Fatalf("third distinct observation=%+v, want maturity at 30 seconds", third)
	}
}

func TestBehaviorAlertTransitionBackwardClockResetsPersistence(t *testing.T) {
	result := evaluateBehaviorAlertTransition(behaviorAlertTransitionInput{
		NowUnix: 119,
		Kind:    "outbound_horizontal_scan_suspected",
		Feature: BehaviorFeature{
			Direction: "outbound",
			Flows:     10,
		},
		Evidence: behaviorAlertEvidence{EvidenceMode: "distributed"},
		Persistence: behaviorPersistState{
			Hits:          2,
			FirstSeenUnix: 100,
			LastSeenUnix:  120,
		},
	})

	if !result.PersistenceReset || result.Persistence.Hits != 1 ||
		result.Persistence.FirstSeenUnix != 119 || result.Persistence.LastSeenUnix != 119 {
		t.Fatalf("backward clock did not reset persistence: %+v", result)
	}
	if result.PersistenceElapsedSeconds != 0 || result.PersistenceSatisfied || result.ShouldEmit {
		t.Fatalf("backward clock matured persistence: %+v", result)
	}
}

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
		NowUnix: 430,
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
			LastSeenUnix:  429,
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
