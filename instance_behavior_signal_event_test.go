package main

import "testing"

func TestRouteBehaviorSignalFallbackPreservesStructuredIdentity(t *testing.T) {
	buf := captureDataIntegrityStructuredLogs(t)
	cm := &ConntrackManager{}
	target := behaviorSignalTarget{
		Domain:       "domain-fallback",
		ServerName:   "server-fallback",
		InstanceUUID: "instance-fallback",
		ProjectUUID:  "project-fallback",
		ProjectName:  "project-name-fallback",
		UserUUID:     "user-fallback",
	}

	cm.routeBehaviorSignal(target, []interface{}{"signal", "fallback_signal", "direction", "outbound"})

	event := findDataIntegrityStructuredEvent(t, decodeDataIntegrityStructuredLogs(t, buf.String()), "behavior_signal", "fallback_signal")
	assertDataIntegrityStructuredValues(t, event, map[string]interface{}{
		"level":          "WARN",
		"msg":            "behavior_signal",
		"category":       "behavior",
		"component":      "behavior",
		"severity_class": "notice",
		"domain":         target.Domain,
		"server_name":    target.ServerName,
		"instance_uuid":  target.InstanceUUID,
		"signal":         "fallback_signal",
		"direction":      "outbound",
	})
}
