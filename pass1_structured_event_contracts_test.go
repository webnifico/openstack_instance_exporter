package main

import "testing"

func TestPassOneBehaviorStructuredEventContract(t *testing.T) {
	resetPassOneBehaviorRuleLogState(t)
	buf := capturePassOneStructuredLogs(t)
	tm := passOneThreatManager()
	cm := passOneBehaviorManager()
	cm.LogThreat = tm.logThreatEvent
	stats := passOneGenericScanStats()
	for cycle := 0; cycle < 3; cycle++ {
		passOneAnalyzeBehavior(cm, stats, "vm-pass1-behavior-event", "server-pass1-behavior")
	}

	events := decodePassOneStructuredLogs(t, buf.String())
	event := findPassOneStructuredEvent(t, events, "behavior_alert", "outbound_horizontal_scan_suspected")
	assertPassOneStructuredValues(t, event, map[string]interface{}{
		"level":          "WARN",
		"msg":            "behavior_alert",
		"category":       "behavior",
		"component":      "behavior",
		"severity_class": "notice",
		"tag":            "BEHAVIOR",
		"domain":         "domain-pass1",
		"server_name":    "server-pass1-behavior",
		"instance_uuid":  "vm-pass1-behavior-event",
		"project_uuid":   "project-pass1",
		"project_name":   "project-name-pass1",
		"user_uuid":      "user-pass1",
		"kind":           "outbound_horizontal_scan_suspected",
		"direction":      "outbound",
		"emit_reason":    "new_kind",
	})
	assertPassOneStructuredTypes(t, event, passOneBehaviorAlertRequiredTypes(false))

	summary := findPassOneStructuredEvent(t, events, "behavior_rule_summary", "outbound_horizontal_scan_suspected")
	assertPassOneStructuredValues(t, summary, map[string]interface{}{
		"level":          "WARN",
		"msg":            "behavior_rule_summary",
		"category":       "behavior",
		"component":      "behavior",
		"severity_class": "notice",
		"new_kind":       "outbound_horizontal_scan_suspected",
		"rule_id":        "legacy_scan",
		"rule_source":    "internal",
		"emit_reason":    "new_kind",
	})
	assertPassOneStructuredTypes(t, summary, passOneBehaviorSummaryRequiredTypes())
}

func TestPassOneMiningStructuredEventContract(t *testing.T) {
	resetPassOneBehaviorRuleLogState(t)
	buf := capturePassOneStructuredLogs(t)
	tm := passOneThreatManager()
	cm := passOneBehaviorManager()
	cm.LogThreat = tm.logThreatEvent
	stats := newBehaviorStats(false)
	remote := IPStrToKey("203.0.113.77")
	stats.updateDetailedWithCoverage(remote, 10128, 6, IPS_SEEN_REPLY, 1, 0, 0, false, false)
	stats.updateOutboundMining(remote, 10128, 6, IPS_SEEN_REPLY, true)
	stats.updateDetailedWithCoverage(remote, 10128, 6, IPS_SEEN_REPLY, 1, 0, 0, false, false)
	stats.updateOutboundMining(remote, 10128, 6, IPS_SEEN_REPLY, true)
	for cycle := 0; cycle < 3; cycle++ {
		passOneAnalyzeBehavior(cm, stats, "vm-pass1-mining-event", "server-pass1-mining")
	}

	events := decodePassOneStructuredLogs(t, buf.String())
	event := findPassOneStructuredEvent(t, events, "behavior_alert", miningBehaviorKind)
	assertPassOneStructuredValues(t, event, map[string]interface{}{
		"level":                  "WARN",
		"msg":                    "behavior_alert",
		"category":               "behavior",
		"component":              "behavior",
		"severity_class":         "notice",
		"tag":                    "BEHAVIOR",
		"domain":                 "domain-pass1",
		"server_name":            "server-pass1-mining",
		"instance_uuid":          "vm-pass1-mining-event",
		"project_uuid":           "project-pass1",
		"project_name":           "project-name-pass1",
		"user_uuid":              "user-pass1",
		"kind":                   miningBehaviorKind,
		"direction":              "outbound",
		"top_dst_port_name":      "moneroocean_randomx_stratum",
		"mining_port_confidence": "high",
		"emit_reason":            "new_kind",
	})
	assertPassOneStructuredTypes(t, event, passOneBehaviorAlertRequiredTypes(true))

	summary := findPassOneStructuredEvent(t, events, "behavior_rule_summary", miningBehaviorKind)
	assertPassOneStructuredValues(t, summary, map[string]interface{}{
		"level":          "WARN",
		"msg":            "behavior_rule_summary",
		"category":       "behavior",
		"component":      "behavior",
		"severity_class": "notice",
		"new_kind":       miningBehaviorKind,
		"rule_id":        miningBehaviorRuleID,
		"rule_source":    "internal",
		"emit_reason":    "new_kind",
	})
	assertPassOneStructuredTypes(t, summary, passOneBehaviorSummaryRequiredTypes())
}

func TestPassOneThreatStructuredEventContracts(t *testing.T) {
	buf := capturePassOneStructuredLogs(t)
	tm := passOneThreatManager()
	tm.logThreatHit(
		"TOREXIT",
		"domain-threat",
		"server-threat",
		"vm-threat",
		"project-threat",
		"project-name-threat",
		"user-threat",
		ConntrackEntry{Src: "10.0.0.8", Dst: "198.51.100.88", SrcPort: 40123, DstPort: 443, Proto: 6, Status: IPS_SEEN_REPLY},
		"out",
		ContactAny,
	)
	tm.logHostThreatHit("spamhaus", "192.0.2.44", "ipv4")

	events := decodePassOneStructuredLogs(t, buf.String())
	instanceEvent := findPassOneStructuredEvent(t, events, "threat_list_hit", "TOREXIT")
	assertPassOneStructuredValues(t, instanceEvent, map[string]interface{}{
		"level":          "WARN",
		"msg":            "threat_list_hit",
		"category":       "threat",
		"component":      "threat",
		"severity_class": "notice",
		"tag":            "TOREXIT",
		"kind":           "TOREXIT",
		"list":           "TOREXIT",
		"domain":         "domain-threat",
		"server_name":    "server-threat",
		"instance_uuid":  "vm-threat",
		"project_uuid":   "project-threat",
		"project_name":   "project-name-threat",
		"user_uuid":      "user-threat",
		"src":            "10.0.0.8",
		"dst":            "198.51.100.88",
		"direction":      "outbound",
	})
	assertPassOneStructuredTypes(t, instanceEvent, map[string]string{
		"level": "string", "msg": "string", "category": "string", "component": "string", "severity_class": "string",
		"tag": "string", "kind": "string", "list": "string", "domain": "string", "server_name": "string",
		"instance_uuid": "string", "project_uuid": "string", "project_name": "string", "user_uuid": "string",
		"src": "string", "dst": "string", "direction": "string",
	})

	hostEvent := findPassOneStructuredEvent(t, events, "provider_ip_listed", "spamhaus")
	assertPassOneStructuredValues(t, hostEvent, map[string]interface{}{
		"level":          "WARN",
		"msg":            "provider_ip_listed",
		"category":       "threat",
		"component":      "threat",
		"severity_class": "notice",
		"tag":            "PROVIDER_IP_THREAT",
		"kind":           "spamhaus",
		"list":           "spamhaus",
		"ip":             "192.0.2.44",
		"family":         "ipv4",
	})
	assertPassOneStructuredTypes(t, hostEvent, map[string]string{
		"level": "string", "msg": "string", "category": "string", "component": "string", "severity_class": "string",
		"tag": "string", "kind": "string", "list": "string", "ip": "string", "family": "string",
	})
}
