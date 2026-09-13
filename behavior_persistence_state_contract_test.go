package main

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func behaviorMiningGenericPersistKey(instanceUUID, kind string) behaviorAlertKey {
	return behaviorAlertKey{
		InstanceUUID: instanceUUID,
		IP:           IPStrToKey("10.0.0.91"),
		Direction:    "outbound",
		Kind:         kind,
	}
}

func TestBehaviorMiningGenericPersistenceRequiresConsecutiveCompleteCollections(t *testing.T) {
	_ = captureDataIntegrityStructuredLogs(t)
	resetDataIntegrityBehaviorRuleLogState(t)
	cm := dataIntegrityBehaviorManager()
	events := captureBehaviorAlerts(cm)
	const instanceUUID = "vm-behavior-mining-consecutive"
	scan := dataIntegrityGenericScanStats()

	dataIntegrityAnalyzeBehaviorWithContext(cm, scan, instanceUUID, "server-behavior-mining", BehaviorContext{ObservationUnix: 100})
	dataIntegrityAnalyzeBehaviorWithContext(cm, newBehaviorStats(false), instanceUUID, "server-behavior-mining", BehaviorContext{ObservationUnix: 115})
	if len(cm.behaviorPersist) != 0 {
		t.Fatalf("complete clean collection retained generic candidate: %+v", cm.behaviorPersist)
	}

	for index, nowUnix := range []int64{130, 145, 160} {
		dataIntegrityAnalyzeBehaviorWithContext(cm, scan, instanceUUID, "server-behavior-mining", BehaviorContext{ObservationUnix: nowUnix})
		if index < 2 && len(*events) != 0 {
			t.Fatalf("generic candidate matured before three post-clean consecutive observations: %#v", *events)
		}
	}
	if len(*events) != 1 || (*events)[0]["kind"] != "outbound_horizontal_scan_suspected" {
		t.Fatalf("three post-clean observations did not confirm one generic candidate: %#v", *events)
	}
}

func TestBehaviorMiningGenericPersistenceCountsOneHitPerCompleteSnapshot(t *testing.T) {
	_ = captureDataIntegrityStructuredLogs(t)
	resetDataIntegrityBehaviorRuleLogState(t)
	cm := dataIntegrityBehaviorManager()
	events := captureBehaviorAlerts(cm)
	const instanceUUID = "vm-behavior-mining-snapshot-idempotence"
	scan := dataIntegrityGenericScanStats()

	for duplicate := 0; duplicate < 3; duplicate++ {
		dataIntegrityAnalyzeBehaviorWithContext(cm, scan, instanceUUID, "server-behavior-mining", BehaviorContext{ObservationUnix: 100})
	}
	key := behaviorMiningGenericPersistKey(instanceUUID, "outbound_horizontal_scan_suspected")
	state := cm.behaviorPersist[key]
	if state == nil || state.Hits != 1 || state.FirstSeenUnix != 100 || state.LastSeenUnix != 100 {
		t.Fatalf("duplicate complete snapshot state=%+v, want one hit at timestamp 100", state)
	}
	if len(*events) != 0 {
		t.Fatalf("duplicate complete snapshot matured generic state: %#v", *events)
	}

	dataIntegrityAnalyzeBehaviorWithContext(cm, scan, instanceUUID, "server-behavior-mining", BehaviorContext{ObservationUnix: 115})
	if state := cm.behaviorPersist[key]; state == nil || state.Hits != 2 {
		t.Fatalf("second distinct complete snapshot state=%+v, want two hits", state)
	}
	if len(*events) != 0 {
		t.Fatalf("generic state matured after only two distinct snapshots: %#v", *events)
	}

	dataIntegrityAnalyzeBehaviorWithContext(cm, scan, instanceUUID, "server-behavior-mining", BehaviorContext{ObservationUnix: 130})
	if len(*events) != 1 || (*events)[0]["kind"] != "outbound_horizontal_scan_suspected" {
		t.Fatalf("third distinct complete snapshot did not mature generic state: %#v", *events)
	}
}

func TestBehaviorMiningDifferentGenericKindBreaksConsecutiveness(t *testing.T) {
	_ = captureDataIntegrityStructuredLogs(t)
	resetDataIntegrityBehaviorRuleLogState(t)
	cm := dataIntegrityBehaviorManager()
	cm.behaviorOutboundPortNames = map[uint16]string{}
	events := captureBehaviorAlerts(cm)
	const instanceUUID = "vm-behavior-mining-kind-switch"
	horizontal := dataIntegrityGenericScanStats()
	vertical := dataIntegrityVerticalScanStats()

	dataIntegrityAnalyzeBehaviorWithContext(cm, horizontal, instanceUUID, "server-behavior-mining", BehaviorContext{ObservationUnix: 100})
	dataIntegrityAnalyzeBehaviorWithContext(cm, vertical, instanceUUID, "server-behavior-mining", BehaviorContext{ObservationUnix: 115})
	dataIntegrityAnalyzeBehaviorWithContext(cm, horizontal, instanceUUID, "server-behavior-mining", BehaviorContext{ObservationUnix: 130})
	if len(*events) != 0 {
		t.Fatalf("A/B/A generic observations matured a candidate: %#v", *events)
	}
	state := cm.behaviorPersist[behaviorMiningGenericPersistKey(instanceUUID, "outbound_horizontal_scan_suspected")]
	if state == nil || state.Hits != 1 || len(cm.behaviorPersist) != 1 {
		t.Fatalf("A/B/A state=%+v map=%+v, want one fresh A hit", state, cm.behaviorPersist)
	}

	dataIntegrityAnalyzeBehaviorWithContext(cm, horizontal, instanceUUID, "server-behavior-mining", BehaviorContext{ObservationUnix: 145})
	dataIntegrityAnalyzeBehaviorWithContext(cm, horizontal, instanceUUID, "server-behavior-mining", BehaviorContext{ObservationUnix: 160})
	if len(*events) != 1 {
		t.Fatalf("three consecutive A observations after kind switch emitted %d events, want 1: %#v", len(*events), *events)
	}
}

func TestBehaviorMiningGenericCandidateFingerprintIncludesRuleIdentity(t *testing.T) {
	cm := newBehaviorStateTestManager()
	key := behaviorMiningGenericPersistKey("vm-behavior-mining-rule-fingerprint", "external_same_kind")

	cm.behaviorAlertMu.Lock()
	state := cm.genericBehaviorCandidateLocked(key, "rule-a", "external", 100)
	state.Hits = 2
	state.LastSeenUnix = 115
	replacement := cm.genericBehaviorCandidateLocked(key, "rule-b", "external", 130)
	cm.behaviorAlertMu.Unlock()

	if replacement == state || replacement.Hits != 0 || replacement.FirstSeenUnix != 130 ||
		replacement.CandidateRuleID != "rule-b" || replacement.CandidateRuleSource != "external" {
		t.Fatalf("different same-kind rule reused persistence: old=%+v replacement=%+v", state, replacement)
	}
}

func TestBehaviorMiningRecoveryReconcilesGenericEvidenceWithoutAdvancing(t *testing.T) {
	tests := []struct {
		name         string
		recovery     *behaviorStats
		wantPreserve bool
	}{
		{name: "same candidate preserved", recovery: dataIntegrityGenericScanStats(), wantPreserve: true},
		{name: "clean clears", recovery: newBehaviorStats(false)},
		{name: "changed kind clears", recovery: dataIntegrityVerticalScanStats()},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_ = captureDataIntegrityStructuredLogs(t)
			resetDataIntegrityBehaviorRuleLogState(t)
			cm := dataIntegrityBehaviorManager()
			cm.behaviorOutboundPortNames = map[uint16]string{}
			events := captureBehaviorAlerts(cm)
			const instanceUUID = "vm-behavior-mining-recovery"
			scan := dataIntegrityGenericScanStats()

			dataIntegrityAnalyzeBehaviorWithContext(cm, scan, instanceUUID, "server-behavior-mining", BehaviorContext{ObservationUnix: 100})
			dataIntegrityAnalyzeBehaviorWithContext(cm, scan, instanceUUID, "server-behavior-mining", BehaviorContext{ObservationUnix: 115})
			key := behaviorMiningGenericPersistKey(instanceUUID, "outbound_horizontal_scan_suspected")
			before := cm.behaviorPersist[key]
			if before == nil || before.Hits != 2 {
				t.Fatalf("pre-recovery candidate=%+v, want two hits", before)
			}

			dataIntegrityAnalyzeBehaviorWithContext(cm, test.recovery, instanceUUID, "server-behavior-mining", BehaviorContext{ObservationUnix: 130, Rebaseline: true})
			if len(*events) != 0 {
				t.Fatalf("recovery rebaseline emitted behavior event: %#v", *events)
			}
			if test.wantPreserve {
				after := cm.behaviorPersist[key]
				if after == nil || after.Hits != 2 || after.FirstSeenUnix != before.FirstSeenUnix || after.LastSeenUnix != before.LastSeenUnix {
					t.Fatalf("matching recovery advanced or cleared candidate: before=%+v after=%+v", before, after)
				}
				dataIntegrityAnalyzeBehaviorWithContext(cm, scan, instanceUUID, "server-behavior-mining", BehaviorContext{ObservationUnix: 145})
				if len(*events) != 1 {
					t.Fatalf("first post-recovery interval did not complete preserved candidate: %#v", *events)
				}
				return
			}
			if len(cm.behaviorPersist) != 0 {
				t.Fatalf("clean/changed recovery retained or seeded generic persistence: %+v", cm.behaviorPersist)
			}
		})
	}
}

func TestBehaviorMiningConntrackSnapshotSuppliesOneObservationTimeToAllWorkers(t *testing.T) {
	cm := newBehaviorStateTestManager()
	cm.conntrackNowOverride = func() time.Time {
		t.Fatal("complete aggregate unexpectedly consulted a per-worker wall clock")
		return time.Time{}
	}
	firstIP := IPStrToKey("10.0.0.91")
	secondIP := IPStrToKey("10.0.0.92")
	agg := &ConntrackAgg{
		VMIndex: map[VMIPIdentity]uint32{
			{InstanceUUID: "vm-behavior-mining-common-clock", IP: firstIP}:  0,
			{InstanceUUID: "vm-behavior-mining-common-clock", IP: secondIP}: 1,
		},
		InstanceFlowTotals: map[string]int{"vm-behavior-mining-common-clock": 60},
		ObservationUnix:    777,
		FlowsOut:           []int{30, 30},
		OutboundStats:      []*behaviorStats{dataIntegrityGenericScanStats(), dataIntegrityGenericScanStats()},
		FlowsIn:            []int{0, 0},
		InboundStats:       []*behaviorStats{nil, nil},
	}
	metrics := make([]prometheus.Metric, 0)
	cm.calculateConntrackMetrics(
		[]IP{{Address: "10.0.0.91", Family: "ipv4"}, {Address: "10.0.0.92", Family: "ipv4"}},
		agg,
		nil,
		nil,
		1000,
		true,
		"domain", "server", "vm-behavior-mining-common-clock", "project", "project-name", "user",
		&metrics,
	)

	for _, ip := range []IPKey{firstIP, secondIP} {
		key := behaviorAlertKey{
			InstanceUUID: "vm-behavior-mining-common-clock",
			IP:           ip,
			Direction:    "outbound",
			Kind:         "outbound_horizontal_scan_suspected",
		}
		state := cm.behaviorPersist[key]
		if state == nil || state.FirstSeenUnix != 777 || state.LastSeenUnix != 777 {
			t.Fatalf("identity %s persistence clock=%+v, want shared timestamp 777", IPKeyToString(ip), state)
		}
	}
}
