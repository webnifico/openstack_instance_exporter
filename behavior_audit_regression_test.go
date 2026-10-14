package main

import (
	"fmt"
	"strings"
	"testing"
)

func TestExternalRuleRejectsReservedMiningSignal(t *testing.T) {
	path := writeConfigTestFile(t, "reserved-mining.yml", `rules:
  - id: custom_mining
    ports: [443]
    signal: outbound_stratum_mining_suspected
`)
	rules, status := LoadBehaviorExternalRules(path)
	if len(rules) != 0 || status.Status != "error" || !strings.Contains(status.Err, "reserved") {
		t.Fatalf("reserved mining event was accepted as an external rule: rules=%d status=%+v", len(rules), status)
	}
}

func TestExternalRuleCappedEvidenceDoesNotBorrowRemoteAddress(t *testing.T) {
	path := writeConfigTestFile(t, "scoped.yml", `rules:
  - id: scoped_service
    ports: [4443]
    flows_min: 3
    signal: custom_service
`)
	rules, status := LoadBehaviorExternalRules(path)
	if status.Status != "loaded" {
		t.Fatal(status)
	}
	for _, direction := range []string{"inbound", "outbound"} {
		t.Run(direction, func(t *testing.T) {
			cm := newBehaviorStateTestManager()
			cm.behaviorSensitivity = 0.1 // Keep this below the built-in volume rule.
			cm.externalBehaviorRules = rules
			cm.behaviorOutboundPortNames = map[uint16]string{80: "http", 4443: "custom"}
			cm.behaviorInboundPortNames = cm.behaviorOutboundPortNames
			events := captureBehaviorSignals(cm)
			stats := newBehaviorStats(false)
			for i := 0; i <= maxRemoteMapSize; i++ {
				remote := IPStrToKey(fmt.Sprintf("198.18.%d.%d", i/256, i%256))
				stats.updateDetailedWithCoverage(remote, 80, 6, IPS_SEEN_REPLY, 1, 0, 0, false, false)
			}
			for i := 0; i < 3; i++ {
				stats.updateDetailedWithCoverage(IPStrToKey("203.0.113.9"), 4443, 6, IPS_SEEN_REPLY, 1, 0, 0, false, false)
			}
			for i := 0; i < 12; i++ {
				stats.updateDetailedWithCoverage(IPStrToKey("198.18.0.1"), 80, 6, IPS_SEEN_REPLY, 1, 0, 0, false, false)
			}
			if !stats.remotePortMapCapped {
				t.Fatal("fixture did not reach the production evidence limit")
			}
			for _, at := range []int64{100, 115, 130} {
				cm.analyzeBehavior(stats, IPStrToKey("10.0.0.10"), "10.0.0.10", "ipv4", "domain", "server", "scoped-vm",
					"project", "project-name", "user", nil, metricDescGroup{thresholdConfigKey: direction}, BehaviorContext{ObservationUnix: at})
			}
			if len(*events) != 1 || (*events)[0]["signal"] != "custom_service" {
				t.Fatalf("qualified flow-only rule did not emit once: %#v", *events)
			}
			event := (*events)[0]
			remoteKey, localKey := "dst_ip", "src_ip"
			if direction == "inbound" {
				remoteKey, localKey = "src_ip", "dst_ip"
			}
			if event[remoteKey] != "" || event["top_remote_ip"] != "" || event[localKey] != "10.0.0.10" {
				t.Fatalf("external rule borrowed an unproven remote: %s=%v top=%v local=%v", remoteKey, event[remoteKey], event["top_remote_ip"], event[localKey])
			}
		})
	}
}

func TestMetadataClassificationUsesExactEvidenceAfterRemoteSaturation(t *testing.T) {
	tests := []struct {
		name       string
		flows      int
		unreplied  int
		wantSignal string
	}{
		{name: "one benign metadata connection", flows: 1},
		{name: "real metadata hammering", flows: 100, wantSignal: "metadata_service_hammering"},
		{name: "real failed metadata probe", flows: 30, unreplied: 30, wantSignal: "metadata_probe_suspected"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm := newBehaviorStateTestManager()
			cm.behaviorOutboundPortNames = builtinBehaviorOutboundMonitoredPorts()
			events := captureBehaviorSignals(cm)
			stats := newBehaviorStats(false)
			// A real high-cardinality snapshot whose remote counters all exceed
			// the metadata hammering threshold before metadata first appears.
			// This forces the bounded heavy-hitter map to estimate that new
			// endpoint at 101 flows even when it has just one actual connection.
			for i := 0; i < maxRemoteMapSize; i++ {
				remote := IPKey{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 11, byte(i >> 16), byte(i >> 8), byte(i)}
				for flow := 0; flow < 100; flow++ {
					stats.updateDetailedWithCoverage(remote, 443, 6, IPS_SEEN_REPLY, 1, 0, 0, false, false)
				}
			}
			for flow := 0; flow < tt.flows; flow++ {
				status := uint32(IPS_SEEN_REPLY)
				if flow < tt.unreplied {
					status = 0
				}
				stats.updateDetailedWithCoverage(metadataServiceIPKey(), 80, 6, status, 1, 0, 0, false, false)
			}
			if !stats.remoteMapCapped || stats.perRemote[metadataServiceIPKey()] != 100+tt.flows {
				t.Fatalf("fixture did not force approximate metadata counter: capped=%v count=%d", stats.remoteMapCapped, stats.perRemote[metadataServiceIPKey()])
			}
			if stats.metadataFlows != tt.flows || stats.metadataUnreplied != tt.unreplied {
				t.Fatalf("exact metadata observation=(%d,%d), want (%d,%d)", stats.metadataFlows, stats.metadataUnreplied, tt.flows, tt.unreplied)
			}
			for _, at := range []int64{100, 115, 130} {
				cm.analyzeBehavior(stats, IPStrToKey("10.0.0.10"), "10.0.0.10", "ipv4", "domain", "server", "metadata-cap-vm",
					"project", "project-name", "user", nil, metricDescGroup{thresholdConfigKey: "outbound"}, BehaviorContext{ObservationUnix: at})
			}
			if tt.wantSignal == "" {
				if len(*events) != 0 {
					t.Fatalf("benign metadata connection borrowed evicted remote evidence: %#v", *events)
				}
				return
			}
			if len(*events) != 1 || (*events)[0]["signal"] != tt.wantSignal {
				t.Fatalf("events=%#v, want one %s signal from exact metadata evidence", *events, tt.wantSignal)
			}
			event := (*events)[0]
			if event["dst_ip"] != "169.254.169.254" || event["top_remote_ip"] != "169.254.169.254" || event["top_dst_port"] != 80 || event["top_dst_port_name"] != "http" {
				t.Fatalf("metadata signal borrowed unrelated web endpoint or port: %#v", event)
			}
			if !strings.HasPrefix(event["reason"].(string), fmt.Sprintf("flows_%d_unreplied_", tt.flows)) {
				t.Fatalf("metadata reason reported approximate flow count: %v", event["reason"])
			}
		})
	}
}

func TestMetadataSignalsSelectTheirActualEndpointWhenWebTrafficDominates(t *testing.T) {
	for _, signal := range []string{"metadata_service_hammering", "metadata_probe_suspected"} {
		t.Run(signal, func(t *testing.T) {
			cm := newBehaviorStateTestManager()
			cm.behaviorOutboundPortNames = builtinBehaviorOutboundMonitoredPorts()
			events := captureBehaviorSignals(cm)
			stats := newBehaviorStats(false)
			webRemote := IPStrToKey("203.0.113.9")
			for flow := 0; flow < 1000; flow++ {
				stats.updateDetailedWithCoverage(webRemote, 443, 6, IPS_SEEN_REPLY, 1, 0, 0, false, false)
			}
			metadataFlows, status := 100, uint32(IPS_SEEN_REPLY)
			if signal == "metadata_probe_suspected" {
				metadataFlows, status = 30, 0
			}
			for flow := 0; flow < metadataFlows; flow++ {
				stats.updateDetailedWithCoverage(metadataServiceIPKey(), 80, 6, status, 1, 0, 0, false, false)
			}
			for _, at := range []int64{100, 115, 130} {
				cm.analyzeBehavior(stats, IPStrToKey("10.0.0.10"), "10.0.0.10", "ipv4", "domain", "server", "metadata-web-vm",
					"project", "project-name", "user", nil, metricDescGroup{thresholdConfigKey: "outbound"}, BehaviorContext{ObservationUnix: at})
			}
			if len(*events) != 1 || (*events)[0]["signal"] != signal {
				t.Fatalf("events=%#v, want one %s signal", *events, signal)
			}
			event := (*events)[0]
			if event["src_ip"] != "10.0.0.10" || event["dst_ip"] != "169.254.169.254" || event["top_remote_ip"] != "169.254.169.254" || event["top_dst_port"] != 80 || event["top_dst_port_name"] != "http" {
				t.Fatalf("metadata signal borrowed dominant unrelated web endpoint: %#v", event)
			}
			wantShare := roundToFiveDecimals(float64(metadataFlows) / float64(1000+metadataFlows))
			if event["top_remote_share"] != wantShare || event["top_port_share"] != wantShare {
				t.Fatalf("metadata evidence shares=(%v,%v), want %v", event["top_remote_share"], event["top_port_share"], wantShare)
			}
		})
	}
}
