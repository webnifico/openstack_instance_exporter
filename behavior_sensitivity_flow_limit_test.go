package main

import "testing"

func TestStartupFlowLimitSensitivityScalesOnce(t *testing.T) {
	for _, test := range []struct {
		name        string
		sensitivity float64
		limit       int
	}{{"less sensitive", 0.5, 8000}, {"default", 1, 4000}, {"more sensitive", 2, 2000}, {"maximum", 10, 400}} {
		t.Run(test.name, func(t *testing.T) {
			cm := newConntrackManager(CollectorConfig{BehaviorSensitivity: test.sensitivity, BehaviorThresholds: defaultBehaviorThresholds()})
			for _, threshold := range []int{cm.behaviorThresholds.OutboundFlowsTotal, cm.behaviorThresholds.InboundFlowsTotal} {
				feature := BehaviorFeature{Direction: "outbound", ThresholdFlows: threshold, Flows: test.limit}
				if hit, _, _ := cm.classifyCapacityAndFlood(feature, 0, newBehaviorScaler(test.sensitivity)); hit {
					t.Fatalf("flow limit fired at the boundary %d", test.limit)
				}
				feature.Flows++
				if hit, signal, _ := cm.classifyCapacityAndFlood(feature, 0, newBehaviorScaler(test.sensitivity)); !hit || signal != "conntrack_flow_limit_exceeded" {
					t.Fatalf("flow limit did not fire above %d: hit=%v signal=%q", test.limit, hit, signal)
				}
			}
		})
	}
}
