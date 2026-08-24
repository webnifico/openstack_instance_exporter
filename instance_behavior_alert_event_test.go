package main

import "testing"

func TestRouteBehaviorAlertFallbackPreservesStructuredIdentity(t *testing.T) {
	buf := capturePassOneStructuredLogs(t)
	cm := &ConntrackManager{}
	target := behaviorAlertTarget{
		Domain:       "domain-fallback",
		ServerName:   "server-fallback",
		InstanceUUID: "instance-fallback",
		ProjectUUID:  "project-fallback",
		ProjectName:  "project-name-fallback",
		UserUUID:     "user-fallback",
	}

	cm.routeBehaviorAlert(target, []interface{}{"kind", "fallback_kind", "direction", "outbound"})

	event := findPassOneStructuredEvent(t, decodePassOneStructuredLogs(t, buf.String()), "behavior_alert", "fallback_kind")
	assertPassOneStructuredValues(t, event, map[string]interface{}{
		"level":          "WARN",
		"msg":            "behavior_alert",
		"category":       "behavior",
		"component":      "behavior",
		"severity_class": "notice",
		"domain":         target.Domain,
		"server_name":    target.ServerName,
		"instance_uuid":  target.InstanceUUID,
		"kind":           "fallback_kind",
		"direction":      "outbound",
	})
}
