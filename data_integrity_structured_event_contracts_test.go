package main

import "testing"

func TestDataIntegrityBehaviorStructuredEventContract(t *testing.T) {
	resetDataIntegrityBehaviorRuleLogState(t)
	buf := captureDataIntegrityStructuredLogs(t)
	tm := dataIntegrityThreatManager()
	cm := dataIntegrityBehaviorManager()
	cm.LogThreat = tm.logThreatEvent
	stats := dataIntegrityGenericScanStats()
	for cycle := 0; cycle < 3; cycle++ {
		dataIntegrityAnalyzeBehavior(cm, stats, "vm-data-integrity-behavior-event", "server-data-integrity-behavior")
	}

	events := decodeDataIntegrityStructuredLogs(t, buf.String())
	event := findDataIntegrityStructuredEvent(t, events, "behavior_alert", "outbound_horizontal_scan_suspected")
	assertDataIntegrityStructuredValues(t, event, map[string]interface{}{
		"level":          "WARN",
		"msg":            "behavior_alert",
		"category":       "behavior",
		"component":      "behavior",
		"severity_class": "notice",
		"tag":            "BEHAVIOR",
		"domain":         "domain-data-integrity",
		"server_name":    "server-data-integrity-behavior",
		"instance_uuid":  "vm-data-integrity-behavior-event",
		"project_uuid":   "project-data-integrity",
		"project_name":   "project-name-data-integrity",
		"user_uuid":      "user-data-integrity",
		"kind":           "outbound_horizontal_scan_suspected",
		"direction":      "outbound",
		"emit_reason":    "new_kind",
	})
	assertDataIntegrityStructuredTypes(t, event, dataIntegrityBehaviorAlertRequiredTypes(false))

	summary := findDataIntegrityStructuredEvent(t, events, "behavior_rule_summary", "outbound_horizontal_scan_suspected")
	assertDataIntegrityStructuredValues(t, summary, map[string]interface{}{
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
	assertDataIntegrityStructuredTypes(t, summary, dataIntegrityBehaviorSummaryRequiredTypes())
}

func TestDataIntegrityMiningStructuredEventContract(t *testing.T) {
	resetDataIntegrityBehaviorRuleLogState(t)
	buf := captureDataIntegrityStructuredLogs(t)
	tm := dataIntegrityThreatManager()
	cm := dataIntegrityBehaviorManager()
	cm.LogThreat = tm.logThreatEvent
	stats := newBehaviorStats(false)
	remote := IPStrToKey("203.0.113.77")
	stats.updateDetailedWithCoverage(remote, 10128, 6, IPS_SEEN_REPLY, 1, 0, 0, false, false)
	stats.updateOutboundMining(remote, 10128, 6, IPS_SEEN_REPLY, true)
	stats.updateDetailedWithCoverage(remote, 10128, 6, IPS_SEEN_REPLY, 1, 0, 0, false, false)
	stats.updateOutboundMining(remote, 10128, 6, IPS_SEEN_REPLY, true)
	for cycle := 0; cycle < 3; cycle++ {
		dataIntegrityAnalyzeBehavior(cm, stats, "vm-data-integrity-mining-event", "server-data-integrity-mining")
	}

	events := decodeDataIntegrityStructuredLogs(t, buf.String())
	event := findDataIntegrityStructuredEvent(t, events, "behavior_alert", miningBehaviorKind)
	assertDataIntegrityStructuredValues(t, event, map[string]interface{}{
		"level":                  "WARN",
		"msg":                    "behavior_alert",
		"category":               "behavior",
		"component":              "behavior",
		"severity_class":         "notice",
		"tag":                    "BEHAVIOR",
		"domain":                 "domain-data-integrity",
		"server_name":            "server-data-integrity-mining",
		"instance_uuid":          "vm-data-integrity-mining-event",
		"project_uuid":           "project-data-integrity",
		"project_name":           "project-name-data-integrity",
		"user_uuid":              "user-data-integrity",
		"kind":                   miningBehaviorKind,
		"direction":              "outbound",
		"top_dst_port_name":      "moneroocean_randomx_stratum",
		"mining_port_confidence": "high",
		"emit_reason":            "new_kind",
	})
	assertDataIntegrityStructuredTypes(t, event, dataIntegrityBehaviorAlertRequiredTypes(true))

	summary := findDataIntegrityStructuredEvent(t, events, "behavior_rule_summary", miningBehaviorKind)
	assertDataIntegrityStructuredValues(t, summary, map[string]interface{}{
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
	assertDataIntegrityStructuredTypes(t, summary, dataIntegrityBehaviorSummaryRequiredTypes())
}

func TestDataIntegrityThreatStructuredEventContracts(t *testing.T) {
	buf := captureDataIntegrityStructuredLogs(t)
	tm := dataIntegrityThreatManager()
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

	events := decodeDataIntegrityStructuredLogs(t, buf.String())
	instanceEvent := findDataIntegrityStructuredEvent(t, events, "threat_list_hit", "TOREXIT")
	assertDataIntegrityStructuredValues(t, instanceEvent, map[string]interface{}{
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
	assertDataIntegrityStructuredTypes(t, instanceEvent, map[string]string{
		"level": "string", "msg": "string", "category": "string", "component": "string", "severity_class": "string",
		"tag": "string", "kind": "string", "list": "string", "domain": "string", "server_name": "string",
		"instance_uuid": "string", "project_uuid": "string", "project_name": "string", "user_uuid": "string",
		"src": "string", "dst": "string", "direction": "string",
	})

	hostEvent := findDataIntegrityStructuredEvent(t, events, "provider_ip_listed", "spamhaus")
	assertDataIntegrityStructuredValues(t, hostEvent, map[string]interface{}{
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
	assertDataIntegrityStructuredTypes(t, hostEvent, map[string]string{
		"level": "string", "msg": "string", "category": "string", "component": "string", "severity_class": "string",
		"tag": "string", "kind": "string", "list": "string", "ip": "string", "family": "string",
	})
}
