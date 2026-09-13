package main

import (
	"testing"
	"time"
)

func TestDataIntegrityGenericAlertLifecycleContract(t *testing.T) {
	_ = captureDataIntegrityStructuredLogs(t)
	resetDataIntegrityBehaviorRuleLogState(t)
	cm := dataIntegrityBehaviorManager()
	stats := dataIntegrityGenericScanStats()
	events := make([]map[string]interface{}, 0, 1)
	cm.LogThreat = func(tag, event, domain, instanceUUID, projectUUID, projectName, userUUID string, kvpairs ...interface{}) {
		fields := dataIntegrityKVMap(kvpairs)
		fields["tag"] = tag
		fields["event"] = event
		events = append(events, fields)
	}

	for cycle := 1; cycle <= 4; cycle++ {
		dataIntegrityAnalyzeBehavior(cm, stats, "vm-data-integrity-lifecycle", "server-data-integrity")
		switch {
		case cycle < 3 && len(events) != 0:
			t.Fatalf("generic behavior alert emitted before its persistence gate on cycle %d: %#v", cycle, events)
		case cycle == 3 && len(events) != 1:
			t.Fatalf("generic behavior alert count after persistence=%d, want 1: %#v", len(events), events)
		case cycle == 4 && len(events) != 1:
			t.Fatalf("unchanged generic behavior alert emitted again without a transition: %#v", events)
		}
	}

	event := events[0]
	for key, want := range map[string]interface{}{
		"tag":                  "BEHAVIOR",
		"event":                "behavior_alert",
		"kind":                 "outbound_horizontal_scan_suspected",
		"persistence_hits":     3,
		"persistence_required": 3,
		"emit_reason":          "new_kind",
	} {
		if got := event[key]; got != want {
			t.Fatalf("generic lifecycle field %s=%v (%T), want %v (%T); event=%#v", key, got, got, want, want, event)
		}
	}
}

func TestDataIntegrityGenericAlertLifecycleTransitionContract(t *testing.T) {
	_ = captureDataIntegrityStructuredLogs(t)
	resetDataIntegrityBehaviorRuleLogState(t)
	cm := dataIntegrityBehaviorManager()
	cm.behaviorOutboundPortNames = map[uint16]string{}
	events := make([]map[string]interface{}, 0, 5)
	cm.LogThreat = func(tag, event, domain, instanceUUID, projectUUID, projectName, userUUID string, kvpairs ...interface{}) {
		fields := dataIntegrityKVMap(kvpairs)
		fields["tag"] = tag
		fields["event"] = event
		events = append(events, fields)
	}

	const instanceUUID = "vm-data-integrity-lifecycle-transitions"
	initial := dataIntegrityGenericScanStatsForPort(22)
	for cycle := 0; cycle < 3; cycle++ {
		dataIntegrityAnalyzeBehavior(cm, initial, instanceUUID, "server-data-integrity")
	}
	if len(events) != 1 || events[0]["emit_reason"] != "new_kind" {
		t.Fatalf("initial lifecycle transition=%#v, want one new_kind event", events)
	}

	ident := behaviorEmitKey{InstanceUUID: instanceUUID, IP: IPStrToKey("10.0.0.91"), Direction: "outbound"}
	emitState := cm.behaviorEmit[ident]
	if emitState == nil || emitState.LastTopDstPort != 22 || emitState.LastPriority != "P3" {
		t.Fatalf("initial generic emit state=%+v, want port 22/P3", emitState)
	}

	changed := dataIntegrityGenericScanStatsForPort(23)
	dataIntegrityAnalyzeBehavior(cm, changed, instanceUUID, "server-data-integrity")
	if len(events) != 1 {
		t.Fatalf("changed endpoint bypassed cooldown: %#v", events)
	}
	if emitState.LastTopDstPort != 22 {
		t.Fatalf("cooldown-suppressed evidence replaced last emitted endpoint: %+v", emitState)
	}

	emitState.LastEmitUnix = time.Now().Unix() - behaviorAlertCooldownSeconds
	dataIntegrityAnalyzeBehavior(cm, changed, instanceUUID, "server-data-integrity")
	if len(events) != 2 || events[1]["emit_reason"] != "changed" || events[1]["top_dst_port"] != 23 {
		t.Fatalf("endpoint change did not emit at cooldown boundary: %#v", events)
	}

	highImpact := BehaviorContext{HostConntrackMax: 100, InstanceFlowTotal: 30}
	dataIntegrityAnalyzeBehaviorWithContext(cm, changed, instanceUUID, "server-data-integrity", highImpact)
	if len(events) != 3 || events[2]["emit_reason"] != "escalated" || events[2]["priority"] != "P2" {
		t.Fatalf("priority escalation transition=%#v, want immediate P2 escalation", events)
	}

	emitState.LastEmitUnix = time.Now().Unix() - behaviorAlertHeartbeatSeconds
	dataIntegrityAnalyzeBehaviorWithContext(cm, changed, instanceUUID, "server-data-integrity", highImpact)
	if len(events) != 4 || events[3]["emit_reason"] != "heartbeat" || events[3]["priority"] != "P2" {
		t.Fatalf("high-priority heartbeat transition=%#v, want P2 heartbeat", events)
	}

	vertical := dataIntegrityVerticalScanStats()
	for cycle := 1; cycle <= 3; cycle++ {
		dataIntegrityAnalyzeBehavior(cm, vertical, instanceUUID, "server-data-integrity")
		if cycle < 3 && len(events) != 4 {
			t.Fatalf("new generic kind bypassed persistence on cycle %d: %#v", cycle, events)
		}
	}
	if len(events) != 5 || events[4]["emit_reason"] != "new_kind" || events[4]["kind"] != "outbound_vertical_scan_suspected" {
		t.Fatalf("generic kind transition=%#v, want persisted vertical-scan new_kind", events)
	}

	persistKey := behaviorAlertKey{
		InstanceUUID: instanceUUID,
		IP:           IPStrToKey("10.0.0.91"),
		Direction:    "outbound",
		Kind:         "outbound_vertical_scan_suspected",
	}
	persistState := cm.behaviorPersist[persistKey]
	if persistState == nil {
		t.Fatal("vertical-scan persistence state is missing")
	}
	persistState.LastSeenUnix = time.Now().Unix() - 181
	dataIntegrityAnalyzeBehavior(cm, vertical, instanceUUID, "server-data-integrity")
	if persistState.Hits != 1 || len(events) != 5 {
		t.Fatalf("long-gap persistence reset hits=%d events=%#v, want one fresh hit and no event", persistState.Hits, events)
	}
}
