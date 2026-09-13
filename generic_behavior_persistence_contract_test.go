package main

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestBehaviorMiningGenericFirstMatchBehaviorMatrix(t *testing.T) {
	cm := &ConntrackManager{behaviorSensitivity: 1}
	tests := []struct {
		name            string
		feature         BehaviorFeature
		anomalies       behaviorAnomalies
		hostImpact      float64
		wantKind        string
		wantDarkScan    bool
		wantDarkPhysics bool
	}{
		{
			name: "dark-space plus protocol",
			feature: BehaviorFeature{
				Direction: "outbound", Flows: 100,
				UnmonitoredPortFlows: 50, UnmonitoredUnrepliedRatio: .9,
				SMTPFlows: 60, SMTPUniqueRemotes: 30, SMTPUnrepliedRatio: .9,
				SMTPTopDstPort: 25, SMTPTopDstPortFlows: 60, SMTPTopRemoteFlows: 3,
			},
			wantKind: "darkspace_plus_physics", wantDarkPhysics: true,
		},
		{
			name: "dark-space plus scan",
			feature: BehaviorFeature{
				Direction: "outbound", Flows: 100, UnrepliedRatio: .9,
				UnmonitoredPortFlows: 50, UnmonitoredUnrepliedRatio: .9,
				UniqueRemotes: 30, TopDstPort: 1234, MaxSingleDstPort: 90, MaxSingleRemote: 2,
			},
			wantKind: "darkspace_plus_scan", wantDarkScan: true,
		},
		{
			name: "outbound horizontal",
			feature: BehaviorFeature{
				Direction: "outbound", Flows: 100, UnrepliedRatio: .9,
				UniqueRemotes: 30, TopDstPort: 22, MaxSingleDstPort: 90, MaxSingleRemote: 2,
			},
			wantKind: "outbound_horizontal_scan_suspected",
		},
		{
			name: "outbound vertical",
			feature: BehaviorFeature{
				Direction: "outbound", Flows: 100, UnrepliedRatio: .9,
				UniqueDstPorts: 30, MaxSingleDstPort: 2, MaxSingleRemote: 90,
			},
			wantKind: "outbound_vertical_scan_suspected",
		},
		{
			name: "outbound distributed",
			feature: BehaviorFeature{
				Direction: "outbound", Flows: 100, UnrepliedRatio: .9,
				UniqueRemotes: 50, UniqueDstPorts: 10, MaxSingleDstPort: 10, MaxSingleRemote: 10,
			},
			anomalies: behaviorAnomalies{Signal: .85},
			wantKind:  "outbound_distributed_fanout_unreplied",
		},
		{
			name: "inbound service spray",
			feature: BehaviorFeature{
				Direction: "inbound", Flows: 100, UnrepliedRatio: .9,
				NewRemotes: 30, UniqueDstPorts: 2, MaxSingleDstPort: 90, MaxSingleRemote: 2,
			},
			wantKind: "inbound_service_spray_suspected",
		},
		{
			name: "inbound distributed probe",
			feature: BehaviorFeature{
				Direction: "inbound", Flows: 100, UnrepliedRatio: .9,
				NewRemotes: 30, UniqueDstPorts: 3, MaxSingleDstPort: 20, MaxSingleRemote: 20,
			},
			wantKind: "inbound_distributed_probe_suspected",
		},
		{
			name: "inbound single remote multi-port",
			feature: BehaviorFeature{
				Direction: "inbound", Flows: 100, UnrepliedRatio: .9,
				UniqueDstPorts: 20, MaxSingleDstPort: 2, MaxSingleRemote: 90,
			},
			wantKind: "inbound_single_remote_multiport_probe_suspected",
		},
		{
			name: "outbound TCP flood",
			feature: BehaviorFeature{
				Direction: "outbound", Flows: 1000, UnrepliedRatio: .1,
				TCPCount: 200, TCPUnrepliedRatio: .9, TCPTopRemoteFlows: 190, TCPTopDstPortFlows: 10,
			},
			wantKind: "outbound_single_remote_flood",
		},
		{
			name: "inbound TCP flood",
			feature: BehaviorFeature{
				Direction: "inbound", Flows: 1000, UnrepliedRatio: .1,
				TCPCount: 200, TCPUnrepliedRatio: .9, TCPTopRemoteFlows: 190, TCPTopDstPortFlows: 10,
			},
			wantKind: "inbound_single_remote_flood",
		},
		{
			name: "outbound UDP fan-out beats generic horizontal",
			feature: BehaviorFeature{
				Direction: "outbound", Flows: 101, UnrepliedRatio: .95,
				UniqueRemotes: 51, TopDstPort: 53, MaxSingleDstPort: 101, MaxSingleRemote: 2,
				UDPCount: 101, UDPUnrepliedRatio: .95, UDPUniqueRemotes: 51,
				UDPTopDstPort: 53, UDPTopDstPortFlows: 101, UDPTopRemoteFlows: 2,
			},
			wantKind: "outbound_udp_fanout_suspected",
		},
		{
			name: "protocol table order survives UDP elevation",
			feature: BehaviorFeature{
				Direction: "outbound", Flows: 341, UnrepliedRatio: .95,
				UniqueRemotes: 51, TopDstPort: 25, MaxSingleDstPort: 240, MaxSingleRemote: 6,
				SMTPFlows: 240, SMTPUniqueRemotes: 30, SMTPUnrepliedRatio: .9,
				SMTPTopDstPort: 25, SMTPTopDstPortFlows: 240, SMTPTopRemoteFlows: 5,
				UDPCount: 101, UDPUnrepliedRatio: .95, UDPUniqueRemotes: 51,
				UDPTopDstPort: 53, UDPTopDstPortFlows: 101, UDPTopRemoteFlows: 2,
			},
			wantKind: "smtp_spam_behavior_suspected",
		},
		{
			name: "inbound UDP flood beats generic service spray",
			feature: BehaviorFeature{
				Direction: "inbound", Flows: 100, UnrepliedRatio: .95,
				NewRemotes: 100, UniqueDstPorts: 1, MaxSingleDstPort: 100, MaxSingleRemote: 1,
				UDPCount: 100, UDPUnrepliedRatio: .95, UDPUniqueRemotes: 100,
				UDPTopDstPort: 53, UDPTopDstPortFlows: 100, UDPTopRemoteFlows: 1,
			},
			wantKind: "inbound_udp_targeted_flood_suspected",
		},
		{
			name: "instance-total host pressure owner",
			feature: BehaviorFeature{
				Direction: "outbound", Flows: 160, InstanceFlowTotal: 400, HostPressureOwner: true,
			},
			hostImpact: .11,
			wantKind:   "host_conntrack_pressure",
		},
		{
			name:      "EWMA after specific classes",
			feature:   BehaviorFeature{Direction: "outbound", Flows: 10},
			anomalies: behaviorAnomalies{Signal: .5},
			wantKind:  "outbound_behavior_spike_low_suspected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cm.classifyBehavior(tt.feature, tt.hostImpact, tt.anomalies, nil)
			if !got.Hit || got.Kind != tt.wantKind {
				t.Fatalf("classification=%+v, want kind %q", got, tt.wantKind)
			}
			if got.SynergyDarkScan != tt.wantDarkScan || got.SynergyDarkPhysics != tt.wantDarkPhysics {
				t.Fatalf("synergy=%v/%v, want %v/%v", got.SynergyDarkScan, got.SynergyDarkPhysics, tt.wantDarkScan, tt.wantDarkPhysics)
			}
		})
	}
}

func TestBehaviorMiningTCPFloodEvidenceIsTransportScoped(t *testing.T) {
	cm := &ConntrackManager{behaviorSensitivity: 1}
	tests := []struct {
		name     string
		feature  BehaviorFeature
		wantHit  bool
		wantKind string
	}{
		{
			name: "UDP concentration cannot qualify the TCP flood",
			feature: BehaviorFeature{
				Direction: "outbound", Flows: 400, UnrepliedRatio: .95, MaxSingleRemote: 390,
				UDPCount: 400, UDPUnrepliedRatio: .95, UDPTopRemoteFlows: 390,
			},
		},
		{
			name: "whole-direction dominance cannot lend TCP concentration",
			feature: BehaviorFeature{
				Direction: "outbound", Flows: 1000, UnrepliedRatio: .95, MaxSingleRemote: 950,
				TCPCount: 200, TCPUnrepliedRatio: .95, TCPTopRemoteFlows: 100,
			},
		},
		{
			name: "whole-direction failures cannot lend TCP reply evidence",
			feature: BehaviorFeature{
				Direction: "outbound", Flows: 1000, UnrepliedRatio: .95, MaxSingleRemote: 950,
				TCPCount: 200, TCPUnrepliedRatio: .1, TCPTopRemoteFlows: 190,
			},
		},
		{
			name: "unrelated replied traffic cannot hide a TCP flood",
			feature: BehaviorFeature{
				Direction: "outbound", Flows: 1000, UnrepliedRatio: .1,
				TCPCount: 200, TCPUnrepliedRatio: .95, TCPTopRemoteFlows: 190,
			},
			wantHit: true,
		},
		{
			name: "capped TCP remotes fail closed",
			feature: BehaviorFeature{
				Direction: "outbound", Flows: 200, TCPCount: 200, TCPUnrepliedRatio: .95,
				TCPTopRemoteFlows: 190, TCPRemoteEvidenceApproximate: true,
			},
		},
		{
			name: "inbound UDP concentration cannot lend TCP concentration",
			feature: BehaviorFeature{
				Direction: "inbound", Flows: 1000, UnrepliedRatio: .95, MaxSingleRemote: 950,
				UDPCount: 800, UDPUnrepliedRatio: 0, UDPTopRemoteFlows: 760,
				TCPCount: 200, TCPUnrepliedRatio: .95, TCPTopRemoteFlows: 100,
			},
		},
		{
			name: "inbound UDP failures cannot lend TCP reply evidence",
			feature: BehaviorFeature{
				Direction: "inbound", Flows: 1000, UnrepliedRatio: .95, MaxSingleRemote: 950,
				UDPCount: 99, UDPUnrepliedRatio: 1, UDPTopRemoteFlows: 99,
				TCPCount: 200, TCPUnrepliedRatio: .1, TCPTopRemoteFlows: 190,
			},
		},
		{
			name: "inbound unrelated replies cannot hide a TCP flood",
			feature: BehaviorFeature{
				Direction: "inbound", Flows: 1000, UnrepliedRatio: .1,
				UDPCount: 800, UDPUnrepliedRatio: 0, UDPTopRemoteFlows: 760,
				TCPCount: 200, TCPUnrepliedRatio: .95, TCPTopRemoteFlows: 190,
			},
			wantHit: true, wantKind: "inbound_single_remote_flood",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var hit bool
			var kind string
			if tt.feature.Direction == "inbound" {
				hit, kind, _ = cm.classifyInboundAttackPatterns(tt.feature, newBehaviorScaler(1))
			} else {
				hit, kind, _ = cm.classifyOutboundScanning(tt.feature, behaviorAnomalies{}, newBehaviorScaler(1))
			}
			if hit != tt.wantHit {
				t.Fatalf("hit=%v kind=%q, want hit=%v", hit, kind, tt.wantHit)
			}
			wantKind := tt.wantKind
			if wantKind == "" && tt.wantHit {
				wantKind = "outbound_single_remote_flood"
			}
			if hit && kind != wantKind {
				t.Fatalf("kind=%q, want %q", kind, wantKind)
			}
		})
	}
}

func TestBehaviorMiningTCPStatsAndEvidenceStayProtocolScoped(t *testing.T) {
	tcpRemote := IPStrToKey("198.51.100.10")
	otherTCPRemote := IPStrToKey("198.51.100.11")
	udpRemote := IPStrToKey("203.0.113.99")
	stats := newBehaviorStats(false)
	for i := 0; i < 3; i++ {
		stats.updateDetailedWithCoverage(tcpRemote, 443, 6, 0, 1, 0, 0, false, false)
	}
	stats.updateDetailedWithCoverage(otherTCPRemote, 80, 6, IPS_SEEN_REPLY, 1, 0, 0, false, false)
	for i := 0; i < 20; i++ {
		stats.updateDetailedWithCoverage(udpRemote, 53, 17, 0, 1, 0, 0, false, false)
	}

	if stats.tcpCount != 4 || stats.tcpUnreplied != 3 || len(stats.tcpRemotes) != 2 || stats.tcpPerRemote[tcpRemote] != 3 || stats.tcpPerDstPort[443] != 3 {
		t.Fatalf("TCP stats borrowed other transport data: %+v", stats)
	}
	feature := BehaviorFeature{
		Direction: "outbound", Flows: stats.flows,
		TCPCount: stats.tcpCount, TCPUnrepliedRatio: float64(stats.tcpUnreplied) / float64(stats.tcpCount),
		TCPTopRemote: tcpRemote, TCPTopRemoteFlows: 3, TCPTopDstPort: 443, TCPTopDstPortFlows: 3,
		TopDstPort: 53, MaxSingleRemote: 20, MaxSingleDstPort: 20,
	}
	ev := (&ConntrackManager{behaviorOutboundPortNames: map[uint16]string{443: "https"}}).buildBehaviorAlertEvidence(feature, udpRemote, true, "outbound_single_remote_flood")
	if ev.TopRemoteIP != "198.51.100.10" || ev.TopDstPort != 443 || ev.TopDstPortName != "https" || ev.TopRemoteShare != .75 || ev.TopPortShare != .75 {
		t.Fatalf("TCP alert evidence=%+v", ev)
	}
}

func TestBehaviorMiningCappedUDPRemoteEvidenceFailsClosed(t *testing.T) {
	stats := newBehaviorStats(false)
	for i := 0; i < maxRemoteMapSize; i++ {
		var remote IPKey
		remote[14] = byte(i >> 8)
		remote[15] = byte(i)
		stats.udpRemotes[remote] = struct{}{}
	}
	newRemote := IPKey{14: 0xff, 15: 0xff}
	stats.updateDetailedWithCoverage(newRemote, 53, 17, 0, 1, 0, 0, false, false)
	if !stats.udpRemoteMapCapped {
		t.Fatal("UDP remote-map saturation was not surfaced")
	}
	if _, retained := stats.udpPerRemote[newRemote]; retained {
		t.Fatal("dropped UDP remote was reported as exact")
	}

	feature := BehaviorFeature{
		Direction: "inbound", Flows: 100, UnrepliedRatio: 1,
		UDPCount: 100, UDPUnrepliedRatio: 1,
		UDPTopRemote: IPStrToKey("198.51.100.99"), UDPTopRemoteFlows: 100,
		UDPTopDstPort: 53, UDPTopDstPortFlows: 100,
		UDPRemoteEvidenceApproximate: true,
	}
	hit, kind, _ := (&ConntrackManager{}).classifyInboundAttackPatterns(feature, newBehaviorScaler(1))
	if !hit || kind != "inbound_udp_flood_suspected" {
		t.Fatalf("approximate UDP classification=%v/%q, want non-targeted fail-closed subtype", hit, kind)
	}
	ev := (&ConntrackManager{}).buildBehaviorAlertEvidence(feature, IPStrToKey("203.0.113.1"), true, kind)
	if ev.TopRemoteIP != "" || ev.TopRemoteShare != 0 || ev.EvidenceMode != "" || ev.TopDstPort != 53 || ev.TopPortShare != 1 {
		t.Fatalf("approximate UDP evidence was overstated: %+v", ev)
	}
}

func TestBehaviorMiningTCPFloodEventsUseTCPOnlyEndpointAndShares(t *testing.T) {
	tests := []struct {
		name       string
		direction  string
		wantKind   string
		endpointKV string
	}{
		{"outbound", "outbound", "outbound_single_remote_flood", "dst_ip"},
		{"inbound", "inbound", "inbound_single_remote_flood", "src_ip"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm := newBehaviorStateTestManager()
			cm.behaviorOutboundPortNames = builtinBehaviorOutboundMonitoredPorts()
			cm.behaviorInboundPortNames = builtinBehaviorInboundMonitoredPorts()
			events := captureBehaviorAlerts(cm)
			stats := newBehaviorStats(false)
			tcpRemote := IPStrToKey("198.51.100.44")
			for i := 0; i < 200; i++ {
				stats.updateDetailedWithCoverage(tcpRemote, 443, 6, 0, 1, 0, 0, false, false)
			}
			udpRemote := IPStrToKey("203.0.113.200")
			for i := 0; i < 500; i++ {
				stats.updateDetailedWithCoverage(udpRemote, 53, 17, IPS_SEEN_REPLY, 1, 0, 0, false, false)
			}

			for cycle := 0; cycle < 3; cycle++ {
				cm.analyzeBehavior(
					stats,
					IPStrToKey("10.0.0.80"),
					"10.0.0.80", "ipv4", "domain", "server", "vm-behavior-mining-tcp-"+tt.direction,
					"project", "project-name", "user",
					nil,
					metricDescGroup{thresholdConfigKey: tt.direction},
					BehaviorContext{},
				)
			}
			if len(*events) != 1 {
				t.Fatalf("events=%#v, want one TCP flood alert", *events)
			}
			event := (*events)[0]
			if event["kind"] != tt.wantKind || event["top_dst_port"] != 443 || event[tt.endpointKV] != "198.51.100.44" || event["top_remote_share"] != 1.0 || event["top_port_share"] != 1.0 {
				t.Fatalf("TCP flood inherited UDP endpoint or shares: %#v", event)
			}
		})
	}
}

func TestBehaviorMiningHostPressureHasOneDeterministicOwner(t *testing.T) {
	vm := "vm-pressure"
	ipLow := IPStrToKey("10.0.0.1")
	ipHigh := IPStrToKey("10.0.0.2")
	agg := &ConntrackAgg{
		VMIndex: map[VMIPIdentity]uint32{
			{InstanceUUID: vm, IP: ipHigh}: 0,
			{InstanceUUID: vm, IP: ipLow}:  1,
		},
		FlowsOut: []int{160, 160},
		FlowsIn:  []int{100, 160},
	}
	want := behaviorIdentityKey{InstanceUUID: vm, IP: ipLow, Direction: "inbound"}
	orders := [][]IP{
		{{Address: "10.0.0.2"}, {Address: "10.0.0.1"}},
		{{Address: "10.0.0.1"}, {Address: "10.0.0.2"}},
	}
	for _, fixedIPs := range orders {
		if got := behaviorPressureOwner(fixedIPs, agg, vm, true, true); got != want {
			t.Fatalf("owner=%+v, want %+v", got, want)
		}
	}

	cm := &ConntrackManager{behaviorSensitivity: 1}
	owner := BehaviorFeature{Direction: "inbound", Flows: 160, InstanceFlowTotal: 400, HostPressureOwner: true}
	if hit, kind, _ := cm.classifyCapacityAndFlood(owner, .11, newBehaviorScaler(1)); !hit || kind != "inbound_conntrack_pressure" {
		t.Fatalf("owner classification=%v/%q", hit, kind)
	}
	nonOwner := owner
	nonOwner.HostPressureOwner = false
	if hit, kind, _ := cm.classifyCapacityAndFlood(nonOwner, .11, newBehaviorScaler(1)); hit || kind != "" {
		t.Fatalf("non-owner classification=%v/%q", hit, kind)
	}
}

func TestBehaviorMiningHostPressureEmitsOneLifecycleAcrossFixedIPsAndDirections(t *testing.T) {
	cm := newBehaviorStateTestManager()
	cm.inboundBehaviorEnabled = true
	events := captureBehaviorAlerts(cm)
	vm := "vm-pressure-integration"
	ip1 := IPStrToKey("10.0.0.1")
	ip2 := IPStrToKey("10.0.0.2")
	statsWithFlows := func(flows int) *behaviorStats {
		stats := newBehaviorStats(false)
		stats.flows = flows
		return stats
	}
	agg := &ConntrackAgg{
		VMIndex: map[VMIPIdentity]uint32{
			{InstanceUUID: vm, IP: ip1}: 0,
			{InstanceUUID: vm, IP: ip2}: 1,
		},
		InstanceFlowTotals: map[string]int{vm: 1000},
		FlowsOut:           []int{250, 300},
		FlowsIn:            []int{250, 200},
		OutboundStats:      []*behaviorStats{statsWithFlows(250), statsWithFlows(300)},
		InboundStats:       []*behaviorStats{statsWithFlows(250), statsWithFlows(200)},
	}
	fixedIPs := []IP{{Address: "10.0.0.2", Family: "ipv4"}, {Address: "10.0.0.1", Family: "ipv4"}}
	ipSet := map[string]struct{}{"10.0.0.1": {}, "10.0.0.2": {}}
	metrics := make([]prometheus.Metric, 0)
	for cycle := 0; cycle < 3; cycle++ {
		cm.calculateConntrackMetrics(
			fixedIPs,
			agg,
			ipSet,
			map[string]struct{}{},
			5000,
			true,
			"domain", "server", vm, "project", "project-name", "user",
			&metrics,
		)
	}
	if len(*events) != 1 {
		t.Fatalf("host pressure emitted %d lifecycles, want one: %#v", len(*events), *events)
	}
	event := (*events)[0]
	if event["kind"] != "host_conntrack_pressure" || event["direction"] != "outbound" || event["src_ip"] != "10.0.0.2" {
		t.Fatalf("host pressure owner event=%#v", event)
	}
}

func TestBehaviorMiningEWMABandsAtExactBoundaries(t *testing.T) {
	cm := &ConntrackManager{}
	tests := []struct {
		signal float64
		kind   string
	}{
		{.5, "outbound_behavior_spike_low_suspected"},
		{.65, "outbound_behavior_spike_medium_suspected"},
		{.8, "outbound_behavior_spike_high_suspected"},
		{.9, "outbound_behavior_spike_critical_suspected"},
	}
	for _, tt := range tests {
		hit, kind, _ := cm.classifyEWMABands(BehaviorFeature{Direction: "outbound", Flows: 10}, behaviorAnomalies{Signal: tt.signal}, newBehaviorScaler(1))
		if !hit || kind != tt.kind {
			t.Errorf("signal %.2f = %v/%q, want %q", tt.signal, hit, kind, tt.kind)
		}
	}
}

func TestBehaviorMiningExternalRulesAreAdditiveOrderedAndPortScoped(t *testing.T) {
	path := writeConfigTestFile(t, "behavior-mining-rules.yml", `rules:
  - id: first_scoped
    direction: outbound
    ports: [9999, 10000]
    flows_min: 10
    unique_remotes_min: 3
    ratios: {unreplied: 0.5}
    evidence_mode: dominant_port
    top_remote_share_min: 0.3
    top_port_share_min: 0.6
    kind: external_first
  - id: second_scoped
    direction: outbound
    ports: [9999, 10000]
    flows_min: 10
    kind: external_second
`)
	rules, status := LoadBehaviorExternalRules(path)
	if status.Status != "loaded" || len(rules) != 2 {
		t.Fatalf("rules status=%+v count=%d", status, len(rules))
	}
	cm := &ConntrackManager{behaviorSensitivity: 1, externalBehaviorRules: rules}
	r1 := IPStrToKey("198.51.100.1")
	r2 := IPStrToKey("198.51.100.2")
	r3 := IPStrToKey("198.51.100.3")
	unrelated := IPStrToKey("203.0.113.200")
	scopedCtx := &RuleCtx{
		DstPortCounts:        map[uint16]int{9999: 6, 10000: 4, 443: 1000},
		DstPortRepliedCounts: map[uint16]int{9999: 3, 10000: 2},
		RemoteDstPortCounts: map[behaviorRemotePortKey]int{
			{Remote: r1, Port: 9999}: 3, {Remote: r1, Port: 10000}: 1,
			{Remote: r2, Port: 9999}: 2, {Remote: r2, Port: 10000}: 2,
			{Remote: r3, Port: 9999}: 1, {Remote: r3, Port: 10000}: 1,
			{Remote: unrelated, Port: 443}: 1000,
		},
		PortEvidenceComplete:       true,
		RemotePortEvidenceComplete: true,
	}
	feature := BehaviorFeature{Direction: "outbound", Flows: 1010, TopDstPort: 443, MaxSingleDstPort: 1000, MaxSingleRemote: 1000}
	got := cm.classifyBehaviorWithRuleContext(feature, 0, behaviorAnomalies{}, scopedCtx)
	if !got.Hit || got.Kind != "external_first" || got.RuleID != "first_scoped" || got.RuleSource != "external" {
		t.Fatalf("external first-match classification=%+v", got)
	}
	if got.EvidenceOverride == nil || got.EvidenceOverride.TopDstPort != 9999 || got.EvidenceOverride.TopRemoteIP != "198.51.100.1" || got.EvidenceOverride.TopPortShare != .6 || got.EvidenceOverride.TopRemoteShare != .4 {
		t.Fatalf("external scoped evidence=%+v", got.EvidenceOverride)
	}

	builtin := BehaviorFeature{
		Direction: "outbound", Flows: 100, UnrepliedRatio: .9,
		UniqueRemotes: 30, TopDstPort: 9999, MaxSingleDstPort: 90, MaxSingleRemote: 2,
	}
	got = cm.classifyBehaviorWithRuleContext(builtin, 0, behaviorAnomalies{}, scopedCtx)
	if !got.Hit || got.Kind != "outbound_horizontal_scan_suspected" || got.RuleSource != "internal" {
		t.Fatalf("external rule displaced built-in classification: %+v", got)
	}

	unrelatedVolume := &RuleCtx{
		DstPortCounts:              map[uint16]int{9999: 1, 443: 1000},
		DstPortRepliedCounts:       map[uint16]int{443: 1},
		RemoteDstPortCounts:        map[behaviorRemotePortKey]int{{Remote: r1, Port: 9999}: 1, {Remote: unrelated, Port: 443}: 1000},
		PortEvidenceComplete:       true,
		RemotePortEvidenceComplete: true,
	}
	if rules[0].When(feature, newBehaviorScaler(1), buildBehaviorEvidence(feature), unrelatedVolume) {
		t.Fatal("external rule borrowed unrelated port volume or remote evidence")
	}

	repliedSelected := &RuleCtx{
		DstPortCounts:              scopedCtx.DstPortCounts,
		DstPortRepliedCounts:       map[uint16]int{9999: 6, 10000: 4},
		RemoteDstPortCounts:        scopedCtx.RemoteDstPortCounts,
		PortEvidenceComplete:       true,
		RemotePortEvidenceComplete: true,
	}
	if rules[0].When(feature, newBehaviorScaler(1), buildBehaviorEvidence(feature), repliedSelected) {
		t.Fatal("external rule borrowed unrelated unreplied traffic")
	}

	capped := *scopedCtx
	capped.RemotePortEvidenceComplete = false
	if rules[0].When(feature, newBehaviorScaler(1), buildBehaviorEvidence(feature), &capped) {
		t.Fatal("external rule accepted capped remote evidence")
	}
	if !rules[1].When(feature, newBehaviorScaler(1), buildBehaviorEvidence(feature), &capped) {
		t.Fatal("flow-only external rule should remain eligible with exact scoped port counts")
	}

	sharePath := writeConfigTestFile(t, "behavior-mining-share-rules.yml", `rules:
  - id: scoped_shares
    direction: outbound
    ports: [9999, 10000]
    flows_min: 10
    evidence_mode: dominant_port
    top_remote_share_min: 0.3
    top_port_share_min: 0.6
    kind: scoped_shares
`)
	shareRules, shareStatus := LoadBehaviorExternalRules(sharePath)
	if shareStatus.Status != "loaded" || len(shareRules) != 1 {
		t.Fatalf("share rule status=%+v count=%d", shareStatus, len(shareRules))
	}
	incompletePorts := *scopedCtx
	incompletePorts.PortEvidenceComplete = false
	if shareRules[0].When(feature, newBehaviorScaler(1), buildBehaviorEvidence(feature), &incompletePorts) {
		t.Fatal("external concentration rule accepted incomplete scoped port totals")
	}
	if evidence, ok := shareRules[0].Evidence(feature, newBehaviorScaler(1), buildBehaviorEvidence(feature), &incompletePorts); !ok || evidence.TopDstPort != 0 || evidence.TopRemoteIP != "" || evidence.TopRemoteShare != 0 || evidence.TopPortShare != 0 || evidence.EvidenceMode != "" {
		t.Fatalf("incomplete external evidence was published: %+v, available=%v", evidence, ok)
	}
	if !rules[1].When(feature, newBehaviorScaler(1), buildBehaviorEvidence(feature), &incompletePorts) {
		t.Fatal("flow-only rule should remain eligible when bounded counts already prove its minimum")
	}
}
