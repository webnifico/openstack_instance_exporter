package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func passOneBehaviorManager() *ConntrackManager {
	cm := newBehaviorStateTestManager()
	cm.behaviorOutboundPortNames = builtinBehaviorOutboundMonitoredPorts()
	return cm
}

func passOneGenericScanStats() *behaviorStats {
	return passOneGenericScanStatsForPort(22)
}

func passOneGenericScanStatsForPort(port uint16) *behaviorStats {
	stats := newBehaviorStats(false)
	for i := 1; i <= 30; i++ {
		remote := IPKey{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 198, 51, 100, byte(i)}
		stats.updateDetailedWithCoverage(remote, port, 6, 0, 1, 0, 0, false, false)
	}
	return stats
}

func passOneVerticalScanStats() *behaviorStats {
	stats := newBehaviorStats(false)
	remote := IPStrToKey("198.51.100.200")
	for port := uint16(20000); port < 20030; port++ {
		stats.updateDetailedWithCoverage(remote, port, 6, 0, 1, 0, 0, false, false)
	}
	return stats
}

func passOneAnalyzeBehavior(cm *ConntrackManager, stats *behaviorStats, instanceUUID, serverName string) float64 {
	return passOneAnalyzeBehaviorWithContext(cm, stats, instanceUUID, serverName, BehaviorContext{})
}

func passOneAnalyzeBehaviorWithContext(cm *ConntrackManager, stats *behaviorStats, instanceUUID, serverName string, ctx BehaviorContext) float64 {
	return cm.analyzeBehavior(
		stats,
		IPStrToKey("10.0.0.91"),
		"10.0.0.91",
		"ipv4",
		"domain-pass1",
		serverName,
		instanceUUID,
		"project-pass1",
		"project-name-pass1",
		"user-pass1",
		nil,
		metricDescGroup{thresholdConfigKey: "outbound"},
		ctx,
	)
}

func passOneThreatManager() *ThreatManager {
	return &ThreatManager{
		threatLogMinInterval: 0,
		threatLastHit:        make(map[string]time.Time),
	}
}

func resetPassOneBehaviorRuleLogState(t *testing.T) {
	t.Helper()
	behaviorRuleLogMu.Lock()
	oldMap := behaviorRuleLogStateMap
	oldSeed := behaviorRuleLogEvictSeed
	behaviorRuleLogStateMap = make(map[behaviorEmitKey]*behaviorRuleLogState)
	behaviorRuleLogEvictSeed = 1
	behaviorRuleLogMu.Unlock()
	t.Cleanup(func() {
		behaviorRuleLogMu.Lock()
		behaviorRuleLogStateMap = oldMap
		behaviorRuleLogEvictSeed = oldSeed
		behaviorRuleLogMu.Unlock()
	})
}

func passOneKVMap(kvpairs []interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(kvpairs)/2)
	for i := 0; i+1 < len(kvpairs); i += 2 {
		key, ok := kvpairs[i].(string)
		if ok {
			out[key] = kvpairs[i+1]
		}
	}
	return out
}

func capturePassOneStructuredLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	oldRoot := getRootLogger()
	oldDefault := slog.Default()
	buf := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	rootLoggerVal.Store(logger)
	slog.SetDefault(logger)
	t.Cleanup(func() {
		rootLoggerVal.Store(oldRoot)
		slog.SetDefault(oldDefault)
	})
	return buf
}

func decodePassOneStructuredLogs(t *testing.T, raw string) []map[string]interface{} {
	t.Helper()
	events := make([]map[string]interface{}, 0, 4)
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		decoder := json.NewDecoder(strings.NewReader(scanner.Text()))
		decoder.UseNumber()
		opening, err := decoder.Token()
		if err != nil || opening != json.Delim('{') {
			t.Fatalf("decode structured log object %q: opening=%v err=%v", scanner.Text(), opening, err)
		}
		event := make(map[string]interface{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				t.Fatalf("decode structured log key %q: %v", scanner.Text(), err)
			}
			key, ok := keyToken.(string)
			if !ok {
				t.Fatalf("structured log key is %T, want string: %q", keyToken, scanner.Text())
			}
			if _, duplicate := event[key]; duplicate {
				t.Fatalf("structured log contains duplicate field %q: %s", key, scanner.Text())
			}
			var value interface{}
			if err := decoder.Decode(&value); err != nil {
				t.Fatalf("decode structured log field %q: %v", key, err)
			}
			event[key] = value
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			t.Fatalf("decode structured log object %q: closing=%v err=%v", scanner.Text(), closing, err)
		}
		var trailing interface{}
		if err := decoder.Decode(&trailing); err != io.EOF {
			t.Fatalf("structured log has trailing JSON value %v: %q (err=%v)", trailing, scanner.Text(), err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return events
}

func findPassOneStructuredEvent(t *testing.T, events []map[string]interface{}, msg, kind string) map[string]interface{} {
	t.Helper()
	for _, event := range events {
		if event["msg"] != msg {
			continue
		}
		if event["kind"] == kind || event["new_kind"] == kind {
			return event
		}
	}
	t.Fatalf("structured event msg=%q kind=%q not found: %#v", msg, kind, events)
	return nil
}

func assertPassOneStructuredValues(t *testing.T, event map[string]interface{}, want map[string]interface{}) {
	t.Helper()
	for key, wantValue := range want {
		if got := event[key]; got != wantValue {
			t.Fatalf("structured field %s=%v (%T), want %v (%T); event=%#v", key, got, got, wantValue, wantValue, event)
		}
	}
}

func assertPassOneStructuredTypes(t *testing.T, event map[string]interface{}, want map[string]string) {
	t.Helper()
	if gotType := passOneJSONType(event["time"]); gotType != "string" {
		t.Fatalf("structured field %q type=%s value=%v, want string; event=%#v", "time", gotType, event["time"], event)
	}
	for key := range event {
		if key == "time" {
			continue
		}
		if _, expected := want[key]; !expected {
			t.Fatalf("unexpected structured field %q; exact schema=%v event=%#v", key, want, event)
		}
	}
	for key, wantType := range want {
		value, ok := event[key]
		if !ok {
			t.Fatalf("required structured field %q is missing; event=%#v", key, event)
		}
		if gotType := passOneJSONType(value); gotType != wantType {
			t.Fatalf("structured field %q type=%s value=%v, want %s; event=%#v", key, gotType, value, wantType, event)
		}
	}
}

func passOneJSONType(value interface{}) string {
	switch value.(type) {
	case string:
		return "string"
	case json.Number:
		return "number"
	case bool:
		return "boolean"
	case nil:
		return "null"
	default:
		return "other"
	}
}

func passOneBehaviorAlertRequiredTypes(mining bool) map[string]string {
	types := map[string]string{
		"level": "string", "msg": "string", "category": "string", "component": "string", "severity_class": "string",
		"tag": "string", "domain": "string", "server_name": "string", "instance_uuid": "string", "project_uuid": "string",
		"project_name": "string", "user_uuid": "string", "kind": "string", "reason": "string", "detail": "string", "direction": "string",
		"synergy_darkspace_scan": "boolean", "synergy_darkspace_physics": "boolean", "threshold_flows": "number",
		"local_scan_hits": "number", "infra_hits": "number", "infra_max_flows": "number", "tenant_private_hits": "number",
		"tenant_private_max_flows": "number", "flows_current": "number", "unique_remotes": "number", "unique_remotes_saturated": "boolean",
		"new_remotes": "number", "new_remotes_saturated": "boolean", "unique_ports": "number", "new_ports": "number",
		"top_dst_port": "number", "top_dst_port_name": "string", "top_remote_ip": "string", "top_remote_share": "number",
		"top_port_share": "number", "evidence_mode": "string", "persistence_hits": "number", "persistence_required": "number",
		"emit_reason": "string", "severity_score": "number", "confidence_score": "number", "severity_band": "string",
		"priority_basis": "string", "unreplied_ratio": "number", "multicast_count": "number", "icmp_count": "number",
		"udp_count": "number", "host_impact_percent": "number", "behavior_signal": "number", "conntrack_acct": "boolean",
		"bytes_per_flow": "number", "packets_per_flow": "number", "remote_map_capped": "boolean", "src_ip": "string",
		"dst_ip": "string", "priority": "string", "max_flows_single_remote": "number", "max_flows_single_port": "number",
	}
	if mining {
		types["mining_port_confidence"] = "string"
		types["mining_flows"] = "number"
		types["mining_replied_flows"] = "number"
		types["mining_unique_remotes"] = "number"
		types["mining_unique_ports"] = "number"
	}
	return types
}

func passOneBehaviorSummaryRequiredTypes() map[string]string {
	return map[string]string{
		"level": "string", "msg": "string", "category": "string", "component": "string", "severity_class": "string",
		"project_uuid": "string", "instance_uuid": "string", "direction": "string", "previous_kind": "string", "new_kind": "string",
		"previous_priority": "string", "new_priority": "string", "previous_severity_band": "string", "new_severity_band": "string",
		"rule_id": "string", "rule_source": "string", "emit_reason": "string", "severity_score": "number", "confidence_score": "number",
		"top_remote_share": "number", "top_port_share": "number", "evidence_mode": "string",
	}
}
