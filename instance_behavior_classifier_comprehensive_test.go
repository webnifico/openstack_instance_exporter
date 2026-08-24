package main

import (
	"fmt"
	"math"
	"strings"
	"testing"
)

func TestBehaviorScalerBoundaries(t *testing.T) {
	for _, sens := range []float64{0, -1} {
		if got := newBehaviorScaler(sens).sens; got != 1 {
			t.Fatalf("sensitivity %v normalized to %v, want 1", sens, got)
		}
	}
	sc := newBehaviorScaler(2)
	if got := sc.scaleIntHigh(0); got != 0 {
		t.Fatalf("scaleIntHigh(0) = %d", got)
	}
	if got := sc.scaleIntHigh(1); got != 1 {
		t.Fatalf("scaleIntHigh(1) = %d", got)
	}
	if got := sc.scaleIntHigh(5); got != 3 {
		t.Fatalf("scaleIntHigh(5) = %d, want 3", got)
	}
	if got := sc.scaleIntLow(0); got != 0 {
		t.Fatalf("scaleIntLow(0) = %d", got)
	}
	if got := sc.scaleIntLow(5); got != 10 {
		t.Fatalf("scaleIntLow(5) = %d, want 10", got)
	}
	if got := sc.threshLow(10); got != 20 {
		t.Fatalf("threshLow(10) = %v, want 20", got)
	}
	if got := newBehaviorScaler(0.1).ratioThresh(1); got != 1 {
		t.Fatalf("upper ratio clamp = %v", got)
	}
	if got := newBehaviorScaler(0.1).ratioThresh(0); got != 0 {
		t.Fatalf("lower ratio clamp = %v", got)
	}
	if got := newBehaviorScaler(100).anomThresh(0.5); got != 0.05 {
		t.Fatalf("lower anomaly clamp = %v", got)
	}
	if got := newBehaviorScaler(0.1).anomThresh(0.5); got != 0.99 {
		t.Fatalf("upper anomaly clamp = %v", got)
	}
}

func TestBehaviorSensitivityIsMonotonicForLowRatioRules(t *testing.T) {
	feature := BehaviorFeature{
		Direction:           "outbound",
		Flows:               100,
		SMTPFlows:           70,
		SMTPUniqueRemotes:   40,
		SMTPUnrepliedRatio:  0.30,
		SMTPTopRemoteFlows:  3,
		SMTPTopDstPort:      25,
		SMTPTopDstPortFlows: 70,
		UniqueRemotes:       40,
		UnrepliedRatio:      0.30,
		TopDstPort:          25,
		MaxSingleDstPort:    70,
	}
	ctx := &RuleCtx{Thresholds: defaultRuleThresholds}

	normalHit, _, _, _, _ := evalRules(feature, newBehaviorScaler(1), buildBehaviorEvidence(feature), ctx, rulesProtocol)
	highHit, _, _, _, _ := evalRules(feature, newBehaviorScaler(2), buildBehaviorEvidence(feature), ctx, rulesProtocol)
	if !normalHit || !highHit {
		t.Fatalf("SMTP threshold became harder at higher sensitivity: normal=%v high=%v", normalHit, highHit)
	}

	feature.UnrepliedRatio = 0.20
	feature.SMTPUnrepliedRatio = 0.20
	lowHit, _, _, _, _ := evalRules(feature, newBehaviorScaler(0.5), buildBehaviorEvidence(feature), ctx, rulesProtocol)
	if lowHit {
		t.Fatal("lower sensitivity made the SMTP unreplied-ratio threshold easier")
	}
}

func TestLateralRuleUsesTenantPrivateReplyEvidence(t *testing.T) {
	tests := []struct {
		name             string
		privateReplied   int
		privateUnreplied int
		publicReplied    int
		publicUnreplied  int
		wantLateralAlert bool
	}{
		{
			name:             "public failures cannot make replied private traffic lateral",
			privateReplied:   20,
			privateUnreplied: 10,
			publicUnreplied:  70,
			wantLateralAlert: false,
		},
		{
			name:             "public replies cannot hide failed private traffic",
			privateUnreplied: 30,
			publicReplied:    70,
			wantLateralAlert: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm := newBehaviorStateTestManager()
			cm.behaviorOutboundPortNames = builtinBehaviorOutboundMonitoredPorts()
			events := captureBehaviorAlerts(cm)
			stats := newBehaviorStats(false)
			privateRemote := IPStrToKey("10.20.30.40")
			publicRemote := IPStrToKey("198.51.100.40")

			appendFlows := func(remote IPKey, count int, status uint32) {
				for i := 0; i < count; i++ {
					stats.updateDetailedWithCoverage(remote, 443, 6, status, 1, 0, 0, false, false)
				}
			}
			appendFlows(privateRemote, tt.privateReplied, IPS_SEEN_REPLY)
			appendFlows(privateRemote, tt.privateUnreplied, 0)
			appendFlows(publicRemote, tt.publicReplied, IPS_SEEN_REPLY)
			appendFlows(publicRemote, tt.publicUnreplied, 0)

			for cycle := 0; cycle < 3; cycle++ {
				cm.analyzeBehavior(
					stats,
					IPStrToKey("10.0.0.40"),
					"10.0.0.40", "ipv4", "domain", "server", "vm-lateral-"+tt.name,
					"project", "project-name", "user",
					nil,
					metricDescGroup{thresholdConfigKey: "outbound"},
					BehaviorContext{},
				)
			}

			gotLateral := false
			for _, event := range *events {
				gotLateral = gotLateral || event["kind"] == "lateral_probe_suspected"
			}
			if gotLateral != tt.wantLateralAlert {
				t.Fatalf("lateral alert=%v, want %v; events=%#v", gotLateral, tt.wantLateralAlert, *events)
			}
		})
	}
}

func TestDarkspaceRuleUsesUnmonitoredPortReplyEvidence(t *testing.T) {
	tests := []struct {
		name                 string
		unmonitoredReplied   int
		unmonitoredUnreplied int
		monitoredReplied     int
		monitoredUnreplied   int
		wantDarkspaceAlert   bool
	}{
		{
			name:               "monitored failures cannot make replied darkspace traffic suspicious",
			unmonitoredReplied: 20,
			monitoredUnreplied: 80,
			wantDarkspaceAlert: false,
		},
		{
			name:                 "monitored replies cannot hide failed darkspace traffic",
			unmonitoredUnreplied: 20,
			monitoredReplied:     80,
			wantDarkspaceAlert:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm := newBehaviorStateTestManager()
			cm.behaviorOutboundPortNames = builtinBehaviorOutboundMonitoredPorts()
			events := captureBehaviorAlerts(cm)
			stats := newBehaviorStats(false)
			remote := IPStrToKey("198.51.100.41")

			appendFlows := func(port uint16, count int, status uint32) {
				for i := 0; i < count; i++ {
					stats.updateDetailedWithCoverage(remote, port, 6, status, 1, 0, 0, false, false)
				}
			}
			appendFlows(12345, tt.unmonitoredReplied, IPS_SEEN_REPLY)
			appendFlows(12345, tt.unmonitoredUnreplied, 0)
			appendFlows(443, tt.monitoredReplied, IPS_SEEN_REPLY)
			appendFlows(443, tt.monitoredUnreplied, 0)

			for cycle := 0; cycle < 3; cycle++ {
				cm.analyzeBehavior(
					stats,
					IPStrToKey("10.0.0.41"),
					"10.0.0.41", "ipv4", "domain", "server", "vm-darkspace-"+tt.name,
					"project", "project-name", "user",
					nil,
					metricDescGroup{thresholdConfigKey: "outbound"},
					BehaviorContext{},
				)
			}

			gotDarkspace := false
			for _, event := range *events {
				kind, _ := event["kind"].(string)
				gotDarkspace = gotDarkspace || strings.Contains(kind, "darkspace")
			}
			if gotDarkspace != tt.wantDarkspaceAlert {
				t.Fatalf("darkspace alert=%v, want %v; events=%#v", gotDarkspace, tt.wantDarkspaceAlert, *events)
			}
		})
	}
}

func TestDarkspaceAlertUsesUnmonitoredEndpointEvidence(t *testing.T) {
	cm := newBehaviorStateTestManager()
	cm.behaviorOutboundPortNames = builtinBehaviorOutboundMonitoredPorts()
	events := captureBehaviorAlerts(cm)
	stats := newBehaviorStats(false)
	darkRemote := IPStrToKey("198.51.100.45")
	webRemote := IPStrToKey("203.0.113.45")
	for i := 0; i < 20; i++ {
		stats.updateDetailedWithCoverage(darkRemote, 12345, 6, 0, 1, 0, 0, false, false)
	}
	for i := 0; i < 80; i++ {
		stats.updateDetailedWithCoverage(webRemote, 443, 6, IPS_SEEN_REPLY, 1, 0, 0, false, false)
	}

	for cycle := 0; cycle < 3; cycle++ {
		cm.analyzeBehavior(
			stats,
			IPStrToKey("10.0.0.45"),
			"10.0.0.45", "ipv4", "domain", "server", "vm-darkspace-endpoint",
			"project", "project-name", "user",
			nil,
			metricDescGroup{thresholdConfigKey: "outbound"},
			BehaviorContext{},
		)
	}

	if len(*events) != 1 {
		t.Fatalf("events=%#v, want one darkspace alert", *events)
	}
	event := (*events)[0]
	if event["kind"] != "darkspace_port_detected" || event["top_dst_port"] != 12345 || event["dst_ip"] != "198.51.100.45" {
		t.Fatalf("darkspace alert inherited monitored endpoint evidence: %#v", event)
	}
}

func TestProtocolRulesUseProtocolSpecificEvidence(t *testing.T) {
	ctx := &RuleCtx{Thresholds: defaultRuleThresholds}
	tests := []struct {
		name    string
		feature BehaviorFeature
	}{
		{
			name: "SMTP ignores unrelated remote fanout and failures",
			feature: BehaviorFeature{
				Direction: "outbound", Flows: 100, UniqueRemotes: 31, UnrepliedRatio: 0.30,
				SMTPFlows: 70, SMTPUniqueRemotes: 1, SMTPUnrepliedRatio: 0,
				SMTPTopRemoteFlows: 70, SMTPTopDstPort: 25, SMTPTopDstPortFlows: 70,
				TopDstPort: 25, MaxSingleDstPort: 70,
			},
		},
		{
			name: "SMTP ignores UDP dominance on an SMTP-numbered port",
			feature: BehaviorFeature{
				Direction: "outbound", Flows: 100, UniqueRemotes: 30, UnrepliedRatio: 0.30,
				SMTPFlows: 50, SMTPUniqueRemotes: 20, SMTPUnrepliedRatio: 0.30,
				SMTPTopRemoteFlows: 3, SMTPTopDstPort: 25, SMTPTopDstPortFlows: 25,
				TopDstPort: 25, MaxSingleDstPort: 80,
			},
		},
		{
			name: "DNS ignores unrelated bytes and failures",
			feature: BehaviorFeature{
				Direction: "outbound", Flows: 31, UniqueRemotes: 21, UnrepliedRatio: 0.70,
				ConntrackAcct: true, BytesPerFlow: 10000, UDPCount: 11,
				TopDstPort: 53, MaxSingleDstPort: 11,
				DNSUDPFlows: 11, DNSBytesPerFlow: 100, DNSBytesPerFlowAvailable: true, DNSUnrepliedRatio: 0,
			},
		},
		{
			name: "UDP fanout ignores unrelated remote fanout and failures",
			feature: BehaviorFeature{
				Direction: "outbound", Flows: 150, UniqueRemotes: 60, UnrepliedRatio: 0.90,
				UDPCount: 101, UDPUniqueRemotes: 1, UDPUnrepliedRatio: 0,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hit, ruleID, kind, _, _ := evalRules(tt.feature, newBehaviorScaler(1), buildBehaviorEvidence(tt.feature), ctx, rulesProtocol)
			if hit {
				t.Fatalf("unrelated aggregate evidence triggered protocol rule %q (%s)", ruleID, kind)
			}
		})
	}
}

func TestSMTPRuleUsesTCPSpecificPortDominanceAndEvidence(t *testing.T) {
	ctx := &RuleCtx{Thresholds: defaultRuleThresholds}
	topSMTPRemote := IPStrToKey("198.51.100.25")
	tests := []struct {
		name    string
		feature BehaviorFeature
		wantHit bool
	}{
		{
			name: "dominant UDP on port 25 cannot qualify split TCP SMTP",
			feature: BehaviorFeature{
				Direction: "outbound", Flows: 300, TopDstPort: 25, MaxSingleDstPort: 250,
				SMTPFlows: 50, SMTPUniqueRemotes: 20, SMTPUnrepliedRatio: 0.30,
				SMTPTopRemote: topSMTPRemote, SMTPTopRemoteFlows: 3,
				SMTPTopDstPort: 25, SMTPTopDstPortFlows: 25,
			},
		},
		{
			name: "overall-dominant TCP SMTP qualifies with mixed protocol traffic",
			feature: BehaviorFeature{
				Direction: "outbound", Flows: 100, TopDstPort: 25, MaxSingleDstPort: 100,
				SMTPFlows: 70, SMTPUniqueRemotes: 20, SMTPUnrepliedRatio: 0.30,
				SMTPTopRemote: topSMTPRemote, SMTPTopRemoteFlows: 3,
				SMTPTopDstPort: 25, SMTPTopDstPortFlows: 70,
			},
			wantHit: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hit, ruleID, kind, _, _ := evalRules(tt.feature, newBehaviorScaler(1), buildBehaviorEvidence(tt.feature), ctx, rulesProtocol)
			if hit != tt.wantHit {
				t.Fatalf("SMTP classification hit=%v rule=%q kind=%q, want hit=%v", hit, ruleID, kind, tt.wantHit)
			}
			if !hit {
				return
			}
			cm := &ConntrackManager{behaviorOutboundPortNames: map[uint16]string{25: "smtp"}}
			ev := cm.buildBehaviorAlertEvidence(tt.feature, IPStrToKey("203.0.113.9"), true, kind)
			if ev.TopDstPort != 25 || ev.TopDstPortName != "smtp" || ev.TopPortShare != 0.7 || ev.TopRemoteIP != "198.51.100.25" {
				t.Fatalf("SMTP alert evidence inherited generic traffic: %+v", ev)
			}
		})
	}
}

func TestBehaviorScalerSaturatesExtremeFiniteIntegerThresholds(t *testing.T) {
	maxInt := int(^uint(0) >> 1)
	if got := newBehaviorScaler(math.SmallestNonzeroFloat64).scaleIntHigh(2); got != maxInt {
		t.Fatalf("tiny sensitivity high threshold=%d, want saturated maximum", got)
	}
	if got := newBehaviorScaler(math.MaxFloat64).scaleIntLow(2); got != maxInt {
		t.Fatalf("huge sensitivity upper bound=%d, want saturated maximum", got)
	}
}

func TestBehaviorEvidenceModes(t *testing.T) {
	tests := []struct {
		remote float64
		port   float64
		want   string
	}{
		{0.7, 0.6, "dominant_remote"},
		{0.6, 0.7, "dominant_port"},
		{0.2, 0.3, "distributed"},
		{0.5, 0.5, "mixed"},
	}
	for _, tt := range tests {
		if got := behaviorEvidenceMode(tt.remote, tt.port); got != tt.want {
			t.Errorf("mode(%v,%v) = %q, want %q", tt.remote, tt.port, got, tt.want)
		}
	}
	feature := BehaviorFeature{Flows: 10, MaxSingleRemote: 9, MaxSingleDstPort: 8, RemoteEvidenceApproximate: true}
	remote, port, mode := behaviorEvidenceFromFeature(feature)
	if remote != 0 || port != 0.8 || mode != "dominant_port" {
		t.Fatalf("approximate evidence = %v %v %q", remote, port, mode)
	}
}

func TestBehaviorFlowFeatureHelpers(t *testing.T) {
	a := IPStrToKey("198.51.100.2")
	b := IPStrToKey("198.51.100.1")
	victim, count, ok := minRemoteCountEntry(map[IPKey]int{a: 2, b: 2})
	if !ok || victim != b || count != 2 {
		t.Fatalf("deterministic minimum = %v/%d/%v", victim, count, ok)
	}
	if _, _, ok := minRemoteCountEntry(nil); ok {
		t.Fatal("empty remote map returned a victim")
	}
	current := map[IPKey]struct{}{a: {}, b: {}}
	prev := map[IPKey]struct{}{a: {}}
	if got, saturated := countNewIPKeys(current, prev, 10); got != 1 || saturated {
		t.Fatalf("new IP count = %d saturated=%v", got, saturated)
	}
	if got, saturated := countNewIPKeys(current, nil, 1); got != 1 || !saturated {
		t.Fatalf("saturated new IP count = %d saturated=%v", got, saturated)
	}
	if got, saturated := saturatingCount(3, 0); got != 3 || saturated {
		t.Fatalf("unbounded count = %d saturated=%v", got, saturated)
	}
	if minInt(2, 1) != 1 || minInt(1, 2) != 1 {
		t.Fatal("minInt boundary failure")
	}
	if !isAdminExposurePort(22) || isAdminExposurePort(12345) {
		t.Fatal("admin exposure port classification failure")
	}
}

func TestBehaviorStatsDetailedCollection(t *testing.T) {
	s := newBehaviorStats(true)
	remote := IPStrToKey("198.51.100.10")
	s.updateDetailed(remote, 53, 17, IPS_SEEN_REPLY, 8, 100, 5)
	s.updateDetailed(remote, 0, 58, 0, 9, 50, 2)
	if s.flows != 2 || s.bytes != 150 || s.packets != 7 || s.unreplied != 1 {
		t.Fatalf("stats = flows %d bytes %d packets %d unreplied %d", s.flows, s.bytes, s.packets, s.unreplied)
	}
	if s.udpCount != 1 || s.icmpCount != 1 || s.perRemote[remote] != 2 || s.remoteZones[remote] != 9 {
		t.Fatalf("protocol/remote stats are wrong: %+v", s)
	}
	if s.perDstPort[53] != 1 || s.perDstPortReplied[53] != 1 {
		t.Fatalf("port stats = %v/%v", s.perDstPort, s.perDstPortReplied)
	}
}

func TestBehaviorStatsCollectProtocolSpecificEvidence(t *testing.T) {
	s := newBehaviorStats(true)
	smtpRemote := IPStrToKey("198.51.100.10")
	dnsRemote := IPStrToKey("198.51.100.11")
	unrelatedRemote := IPStrToKey("198.51.100.12")
	s.updateDetailed(smtpRemote, 25, 6, IPS_SEEN_REPLY, 1, 500, 5)
	s.updateDetailed(dnsRemote, 53, 17, IPS_SEEN_REPLY, 1, 100, 2)
	s.updateDetailed(unrelatedRemote, 9999, 17, 0, 1, 10_000, 3)
	s.updateDetailed(unrelatedRemote, 25, 17, 0, 1, 100, 1)

	if s.smtpFlows != 1 || s.smtpUnreplied != 0 || len(s.smtpRemotes) != 1 || s.smtpPerDstPort[25] != 1 || s.smtpPerRemote[smtpRemote] != 1 {
		t.Fatalf("SMTP evidence flows=%d unreplied=%d remotes=%d", s.smtpFlows, s.smtpUnreplied, len(s.smtpRemotes))
	}
	if s.udpCount != 3 || s.udpUnreplied != 2 || len(s.udpRemotes) != 2 {
		t.Fatalf("UDP evidence flows=%d unreplied=%d remotes=%d", s.udpCount, s.udpUnreplied, len(s.udpRemotes))
	}
	if s.dnsUDPFlows != 1 || s.dnsUDPUnreplied != 0 || s.dnsBytes != 100 || s.dnsByteCoveredFlows != 1 {
		t.Fatalf("DNS evidence flows=%d unreplied=%d bytes=%d covered=%d", s.dnsUDPFlows, s.dnsUDPUnreplied, s.dnsBytes, s.dnsByteCoveredFlows)
	}

	restricted := newBehaviorStats(false)
	restricted.updateDetailedWithCoverage(smtpRemote, 179, 6, IPS_SEEN_REPLY, 1, 0, 0, false, false)
	restricted.updateDetailedWithCoverage(smtpRemote, 179, 17, IPS_SEEN_REPLY, 1, 0, 0, false, false)
	restricted.updateDetailedWithCoverage(smtpRemote, 6081, 17, IPS_SEEN_REPLY, 1, 0, 0, false, false)
	restricted.updateDetailedWithCoverage(smtpRemote, 6081, 6, IPS_SEEN_REPLY, 1, 0, 0, false, false)
	if restricted.bgpFlows != 1 || restricted.geneveFlows != 1 {
		t.Fatalf("restricted protocol evidence BGP=%d Geneve=%d, want one correctly transported flow each", restricted.bgpFlows, restricted.geneveFlows)
	}
}

func TestRestrictedProtocolRulesIgnoreWrongTransport(t *testing.T) {
	tests := []struct {
		name       string
		port       uint16
		wrongProto uint8
		wantKind   string
	}{
		{name: "BGP ignores UDP port 179", port: 179, wrongProto: 17, wantKind: "bgp_peering_attempt"},
		{name: "Geneve ignores TCP port 6081", port: 6081, wrongProto: 6, wantKind: "geneve_underlay_attempt"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm := newBehaviorStateTestManager()
			cm.behaviorOutboundPortNames = builtinBehaviorOutboundMonitoredPorts()
			events := captureBehaviorAlerts(cm)
			stats := newBehaviorStats(false)
			stats.updateDetailedWithCoverage(
				IPStrToKey("198.51.100.17"),
				tt.port,
				tt.wrongProto,
				IPS_SEEN_REPLY,
				1,
				0,
				0,
				false,
				false,
			)

			for cycle := 0; cycle < 3; cycle++ {
				cm.analyzeBehavior(
					stats,
					IPStrToKey("10.0.0.17"),
					"10.0.0.17", "ipv4", "domain", "server", "vm-wrong-transport-"+tt.name,
					"project", "project-name", "user",
					nil,
					metricDescGroup{thresholdConfigKey: "outbound"},
					BehaviorContext{},
				)
			}

			for _, event := range *events {
				if event["kind"] == tt.wantKind {
					t.Fatalf("wrong transport produced %q alert: %#v", tt.wantKind, event)
				}
			}
		})
	}
}

func TestRestrictedProtocolAlertsUseProtocolSpecificEndpoint(t *testing.T) {
	tests := []struct {
		name       string
		port       uint16
		proto      uint8
		wantKind   string
		wantRemote string
	}{
		{name: "BGP", port: 179, proto: 6, wantKind: "bgp_peering_attempt", wantRemote: "198.51.100.71"},
		{name: "Geneve", port: 6081, proto: 17, wantKind: "geneve_underlay_attempt", wantRemote: "198.51.100.72"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm := newBehaviorStateTestManager()
			cm.behaviorOutboundPortNames = builtinBehaviorOutboundMonitoredPorts()
			events := captureBehaviorAlerts(cm)
			stats := newBehaviorStats(false)
			protocolRemote := IPStrToKey(tt.wantRemote)
			stats.updateDetailedWithCoverage(protocolRemote, tt.port, tt.proto, IPS_SEEN_REPLY, 1, 0, 0, false, false)
			webRemote := IPStrToKey("203.0.113.71")
			for i := 0; i < 100; i++ {
				stats.updateDetailedWithCoverage(webRemote, 443, 6, IPS_SEEN_REPLY, 1, 0, 0, false, false)
			}

			for cycle := 0; cycle < 3; cycle++ {
				cm.analyzeBehavior(
					stats,
					IPStrToKey("10.0.0.71"),
					"10.0.0.71", "ipv4", "domain", "server", "vm-restricted-endpoint-"+tt.name,
					"project", "project-name", "user",
					nil,
					metricDescGroup{thresholdConfigKey: "outbound"},
					BehaviorContext{},
				)
			}

			if len(*events) != 1 {
				t.Fatalf("events=%#v, want one %s alert", *events, tt.wantKind)
			}
			event := (*events)[0]
			if event["kind"] != tt.wantKind || event["top_dst_port"] != int(tt.port) || event["dst_ip"] != tt.wantRemote {
				t.Fatalf("%s alert inherited unrelated endpoint evidence: %#v", tt.name, event)
			}
		})
	}
}

func TestBehaviorStatsDNSBytesSaturateWithoutWrapping(t *testing.T) {
	s := newBehaviorStats(true)
	remote := IPStrToKey("198.51.100.53")
	s.updateDetailedWithCoverage(remote, 53, 17, IPS_SEEN_REPLY, 1, math.MaxUint64, 0, true, false)
	s.updateDetailedWithCoverage(remote, 53, 17, IPS_SEEN_REPLY, 1, 1, 0, true, false)

	if s.dnsBytes != math.MaxUint64 {
		t.Fatalf("DNS byte total wrapped: got %d, want %d", s.dnsBytes, uint64(math.MaxUint64))
	}
}

func TestBehaviorPortNamesAndAlertIPs(t *testing.T) {
	cm := &ConntrackManager{
		behaviorOutboundPortNames: map[uint16]string{443: "https"},
		behaviorInboundPortNames:  map[uint16]string{22: "ssh"},
	}
	if cm.behaviorPortName("outbound", 443) != "https" || cm.behaviorPortName("inbound", 22) != "ssh" {
		t.Fatal("known behavior port name missing")
	}
	for _, tc := range []struct {
		dir  string
		port uint16
	}{
		{"outbound", 0}, {"outbound", 25}, {"inbound", 25},
	} {
		if got := cm.behaviorPortName(tc.dir, tc.port); got != "" {
			t.Errorf("unexpected name %q for %s/%d", got, tc.dir, tc.port)
		}
	}

	private := IPStrToKey("10.0.0.9")
	host := IPStrToKey("192.0.2.10")
	public := IPStrToKey("198.51.100.20")
	s := newBehaviorStats(false)
	s.remotes[private] = struct{}{}
	s.remotes[host] = struct{}{}
	s.sampleRemote = public
	s.sampleRemoteSet = true
	hostIPs := map[string]struct{}{IPKeyToString(host): {}}

	src, dst := behaviorSelectAlertIPs("outbound", "10.0.0.5", s, "lateral_probe_suspected", hostIPs)
	if src != "10.0.0.5" || dst != "10.0.0.9" {
		t.Fatalf("lateral alert IPs = %q -> %q", src, dst)
	}
	_, dst = behaviorSelectAlertIPs("outbound", "10.0.0.5", s, "restricted_network_probe", hostIPs)
	if dst != "192.0.2.10" {
		t.Fatalf("restricted alert destination = %q", dst)
	}
	src, dst = behaviorSelectAlertIPs("inbound", "10.0.0.5", s, "", hostIPs)
	if src != "198.51.100.20" || dst != "10.0.0.5" {
		t.Fatalf("inbound alert IPs = %q -> %q", src, dst)
	}
}

func TestBehaviorAlertIPSelectionIsClassSpecificAndDeterministic(t *testing.T) {
	privateHigh := IPStrToKey("10.0.0.9")
	privateLow := IPStrToKey("10.0.0.8")
	metadata := metadataServiceIPKey()
	host := IPStrToKey("192.0.2.10")
	s := newBehaviorStats(false)
	for _, remote := range []IPKey{metadata, privateHigh, host, privateLow} {
		s.remotes[remote] = struct{}{}
	}
	s.perRemote[metadata] = 100
	s.perRemote[privateHigh] = 5
	s.perRemote[host] = 1
	s.perRemote[privateLow] = 2
	s.sampleRemote = metadata
	s.sampleRemoteSet = true
	hostIPs := map[string]struct{}{IPKeyToString(host): {}}

	_, lateralDst := behaviorSelectAlertIPs("outbound", "10.0.0.5", s, "lateral_probe_suspected", hostIPs)
	if lateralDst != "10.0.0.9" {
		t.Fatalf("lateral endpoint selection=%q, want highest-flow tenant-private destination", lateralDst)
	}

	s.perRemote[privateLow] = 5
	for i := 0; i < 256; i++ {
		_, lateralDst = behaviorSelectAlertIPs("outbound", "10.0.0.5", s, "lateral_probe_suspected", hostIPs)
		if lateralDst != "10.0.0.8" {
			t.Fatalf("lateral endpoint selection=%q, want deterministic lowest tenant-private destination", lateralDst)
		}
		_, restrictedDst := behaviorSelectAlertIPs("outbound", "10.0.0.5", s, "restricted_network_probe", hostIPs)
		if restrictedDst != "192.0.2.10" {
			t.Fatalf("restricted endpoint selection=%q, want host/control destination rather than metadata", restrictedDst)
		}
	}
}

func TestGenericBehaviorAlertIPSelectionUsesDeterministicTopRemote(t *testing.T) {
	lowRemote := IPStrToKey("198.51.100.8")
	highRemote := IPStrToKey("198.51.100.9")

	for _, tc := range []struct {
		name       string
		remotes    []IPKey
		wantRemote string
	}{
		{
			name:       "highest flow wins regardless of first observation",
			remotes:    []IPKey{lowRemote, highRemote, highRemote},
			wantRemote: "198.51.100.9",
		},
		{
			name:       "lowest IP breaks an equal-flow tie",
			remotes:    []IPKey{highRemote, lowRemote},
			wantRemote: "198.51.100.8",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stats := newBehaviorStats(false)
			for _, remote := range tc.remotes {
				stats.updateDetailedWithCoverage(remote, 443, 6, IPS_SEEN_REPLY, 1, 0, 0, false, false)
			}

			outboundSrc, outboundDst := behaviorSelectAlertIPs(
				"outbound", "10.0.0.5", stats, "outbound_horizontal_scan_suspected", nil,
			)
			if outboundSrc != "10.0.0.5" || outboundDst != tc.wantRemote {
				t.Fatalf("outbound alert IPs=%q -> %q, want 10.0.0.5 -> %s", outboundSrc, outboundDst, tc.wantRemote)
			}

			inboundSrc, inboundDst := behaviorSelectAlertIPs("inbound", "10.0.0.5", stats, "", nil)
			if inboundSrc != tc.wantRemote || inboundDst != "10.0.0.5" {
				t.Fatalf("inbound alert IPs=%q -> %q, want %s -> 10.0.0.5", inboundSrc, inboundDst, tc.wantRemote)
			}
		})
	}
}

func TestBehaviorTiedTopEvidenceIsDeterministic(t *testing.T) {
	lowRemote := IPStrToKey("198.51.100.8")
	highRemote := IPStrToKey("198.51.100.9")

	for iteration := 0; iteration < 128; iteration++ {
		cm := newBehaviorStateTestManager()
		cm.behaviorOutboundPortNames = map[uint16]string{179: "bgp", 6081: "geneve"}
		events := captureBehaviorAlerts(cm)
		stats := newBehaviorStats(false)
		stats.updateDetailedWithCoverage(lowRemote, 179, 6, IPS_SEEN_REPLY, 1, 0, 0, false, false)
		stats.updateDetailedWithCoverage(highRemote, 6081, 6, IPS_SEEN_REPLY, 1, 0, 0, false, false)

		instanceUUID := fmt.Sprintf("vm-tied-evidence-%d", iteration)
		for cycle := 0; cycle < 3; cycle++ {
			cm.analyzeBehavior(
				stats,
				IPStrToKey("10.0.0.20"),
				"10.0.0.20", "ipv4", "domain", "server", instanceUUID, "project", "project-name", "user",
				nil,
				metricDescGroup{thresholdConfigKey: "outbound"},
				BehaviorContext{},
			)
		}
		if len(*events) != 1 {
			t.Fatalf("iteration %d emitted %d alerts, want one: %#v", iteration, len(*events), *events)
		}
		event := (*events)[0]
		if event["top_dst_port"] != 179 || event["top_remote_ip"] != "198.51.100.8" {
			t.Fatalf("iteration %d tied evidence=%v/%v, want deterministic 179/198.51.100.8", iteration, event["top_dst_port"], event["top_remote_ip"])
		}
	}
}

func TestBehaviorScanningClassifierBranches(t *testing.T) {
	cm := &ConntrackManager{}
	sc := newBehaviorScaler(1)
	tests := []struct {
		name    string
		feature BehaviorFeature
		anoms   behaviorAnomalies
		want    string
	}{
		{"wrong direction", BehaviorFeature{Direction: "inbound", Flows: 100, UnrepliedRatio: 1}, behaviorAnomalies{}, ""},
		{"too few flows", BehaviorFeature{Direction: "outbound", Flows: 19, UnrepliedRatio: 1}, behaviorAnomalies{}, ""},
		{"low unreplied", BehaviorFeature{Direction: "outbound", Flows: 100, UnrepliedRatio: .2}, behaviorAnomalies{}, ""},
		{"horizontal", BehaviorFeature{Direction: "outbound", Flows: 100, UnrepliedRatio: .9, UniqueRemotes: 50, TopDstPort: 22, MaxSingleDstPort: 90, MaxSingleRemote: 2}, behaviorAnomalies{}, "outbound_horizontal_scan_suspected"},
		{"vertical", BehaviorFeature{Direction: "outbound", Flows: 100, UnrepliedRatio: .9, UniqueDstPorts: 30, MaxSingleDstPort: 2, MaxSingleRemote: 90}, behaviorAnomalies{}, "outbound_vertical_scan_suspected"},
		{"single remote flood", BehaviorFeature{Direction: "outbound", Flows: 200, UnrepliedRatio: .9, UniqueDstPorts: 2, MaxSingleDstPort: 10, MaxSingleRemote: 190}, behaviorAnomalies{}, "outbound_single_remote_flood"},
		{"distributed anomaly", BehaviorFeature{Direction: "outbound", Flows: 100, UnrepliedRatio: .9, UniqueRemotes: 50, UniqueDstPorts: 10, MaxSingleDstPort: 10, MaxSingleRemote: 10}, behaviorAnomalies{Signal: .85}, "outbound_distributed_fanout_unreplied"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hit, kind, _ := cm.classifyOutboundScanning(tt.feature, tt.anoms, sc)
			if hit != (tt.want != "") || kind != tt.want {
				t.Fatalf("hit=%v kind=%q, want %q", hit, kind, tt.want)
			}
		})
	}
}

func TestInboundExposureClassifierBranches(t *testing.T) {
	cm := &ConntrackManager{}
	sc := newBehaviorScaler(1)
	noHit := []BehaviorFeature{
		{Direction: "outbound", AdminPortFlows: 10, PublicRemotes: 10},
		{Direction: "inbound", PublicRemotes: 10},
		{Direction: "inbound", AdminPortFlows: 10},
		{Direction: "inbound", Flows: 100, AdminPortFlows: 80, AdminUniqueRemotes: 1, AdminNewRemotes: 1, AdminTopDstPort: 22, PublicRemotes: 10, TopDstPort: 80, NewRemotes: 1, UniqueRemotes: 1},
	}
	for i, feature := range noHit {
		if hit, kind, _ := cm.classifyInboundExposure(feature, sc); hit || kind != "" {
			t.Errorf("no-hit case %d matched %q", i, kind)
		}
	}
	for _, feature := range []BehaviorFeature{
		{Direction: "inbound", Flows: 100, AdminPortFlows: 10, AdminUniqueRemotes: 10, AdminNewRemotes: 10, AdminTopDstPort: 22, PublicRemotes: 10, TopDstPort: 80, NewRemotes: 20},
		{Direction: "inbound", Flows: 20, AdminPortFlows: 1, AdminUniqueRemotes: 10, AdminNewRemotes: 10, AdminTopDstPort: 22, PublicRemotes: 10, TopDstPort: 22, NewRemotes: 10},
		{Direction: "inbound", Flows: 20, AdminPortFlows: 15, AdminUniqueRemotes: 20, AdminTopDstPort: 22, PublicRemotes: 10, TopDstPort: 80, UniqueRemotes: 20},
	} {
		hit, kind, reason := cm.classifyInboundExposure(feature, sc)
		if !hit || kind != "inbound_admin_port_exposure_suspected" || reason == "" {
			t.Fatalf("exposure classification = %v/%q/%q", hit, kind, reason)
		}
	}
}

func TestInboundExposureRequiresAdminTrafficFromPublicRemote(t *testing.T) {
	cm := newBehaviorStateTestManager()
	cm.behaviorInboundPortNames = builtinBehaviorInboundMonitoredPorts()
	events := captureBehaviorAlerts(cm)
	stats := newBehaviorStats(false)
	privateRemote := IPStrToKey("10.20.30.50")

	for i := 0; i < 50; i++ {
		stats.updateDetailedWithCoverage(privateRemote, 22, 6, IPS_SEEN_REPLY, 1, 0, 0, false, false)
	}
	for i := 1; i <= 20; i++ {
		stats.updateDetailedWithCoverage(IPStrToKey(fmt.Sprintf("198.51.100.%d", i)), 443, 6, IPS_SEEN_REPLY, 1, 0, 0, false, false)
	}

	for cycle := 0; cycle < 3; cycle++ {
		cm.analyzeBehavior(
			stats,
			IPStrToKey("10.0.0.50"),
			"10.0.0.50", "ipv4", "domain", "server", "vm-private-admin-public-web",
			"project", "project-name", "user",
			nil,
			metricDescGroup{thresholdConfigKey: "inbound"},
			BehaviorContext{},
		)
	}

	for _, event := range *events {
		if event["kind"] == "inbound_admin_port_exposure_suspected" {
			t.Fatalf("private admin traffic was attributed to unrelated public remotes: %#v", event)
		}
	}
}

func TestInboundExposureGatesUsePublicAdminCategoryEvidence(t *testing.T) {
	tests := []struct {
		name  string
		build func(*behaviorStats)
	}{
		{
			name: "unrelated public fanout cannot amplify one public admin flow",
			build: func(stats *behaviorStats) {
				stats.updateDetailedWithCoverage(IPStrToKey("198.51.100.90"), 22, 6, IPS_SEEN_REPLY, 1, 0, 0, false, false)
				for i := 1; i <= 20; i++ {
					stats.updateDetailedWithCoverage(IPStrToKey(fmt.Sprintf("203.0.113.%d", i)), 443, 6, IPS_SEEN_REPLY, 1, 0, 0, false, false)
				}
				for i := 0; i < 50; i++ {
					stats.updateDetailedWithCoverage(IPStrToKey("10.20.30.90"), 22, 6, IPS_SEEN_REPLY, 1, 0, 0, false, false)
				}
			},
		},
		{
			name: "private failures cannot amplify one replied public admin flow",
			build: func(stats *behaviorStats) {
				stats.updateDetailedWithCoverage(IPStrToKey("198.51.100.91"), 22, 6, IPS_SEEN_REPLY, 1, 0, 0, false, false)
				for i := 0; i < 99; i++ {
					stats.updateDetailedWithCoverage(IPStrToKey("10.20.30.91"), 22, 6, 0, 1, 0, 0, false, false)
				}
			},
		},
		{
			name: "one unreplied public admin flow cannot borrow private admin volume",
			build: func(stats *behaviorStats) {
				stats.updateDetailedWithCoverage(IPStrToKey("198.51.100.92"), 22, 6, 0, 1, 0, 0, false, false)
				for i := 0; i < 99; i++ {
					stats.updateDetailedWithCoverage(IPStrToKey("10.20.30.92"), 22, 6, IPS_SEEN_REPLY, 1, 0, 0, false, false)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm := newBehaviorStateTestManager()
			cm.behaviorInboundPortNames = builtinBehaviorInboundMonitoredPorts()
			events := captureBehaviorAlerts(cm)
			stats := newBehaviorStats(false)
			tt.build(stats)

			for cycle := 0; cycle < 3; cycle++ {
				cm.analyzeBehavior(
					stats,
					IPStrToKey("10.0.0.90"),
					"10.0.0.90", "ipv4", "domain", "server", "vm-admin-category-"+tt.name,
					"project", "project-name", "user",
					nil,
					metricDescGroup{thresholdConfigKey: "inbound"},
					BehaviorContext{},
				)
			}

			for _, event := range *events {
				if event["kind"] == "inbound_admin_port_exposure_suspected" {
					t.Fatalf("unrelated evidence triggered public-admin exposure: %#v", event)
				}
			}
		})
	}
}

func TestInboundAdminAlertUsesPublicAdminEndpoint(t *testing.T) {
	cm := newBehaviorStateTestManager()
	cm.behaviorInboundPortNames = builtinBehaviorInboundMonitoredPorts()
	events := captureBehaviorAlerts(cm)
	stats := newBehaviorStats(false)
	privateAdminRemote := IPStrToKey("10.20.30.51")
	for i := 0; i < 100; i++ {
		stats.updateDetailedWithCoverage(privateAdminRemote, 22, 6, IPS_SEEN_REPLY, 1, 0, 0, false, false)
	}
	for i := 1; i <= 20; i++ {
		for flow := 0; flow < 5; flow++ {
			stats.updateDetailedWithCoverage(IPStrToKey(fmt.Sprintf("198.51.100.%d", i)), 3389, 6, IPS_SEEN_REPLY, 1, 0, 0, false, false)
		}
	}

	for cycle := 0; cycle < 3; cycle++ {
		cm.analyzeBehavior(
			stats,
			IPStrToKey("10.0.0.51"),
			"10.0.0.51", "ipv4", "domain", "server", "vm-public-admin-endpoint",
			"project", "project-name", "user",
			nil,
			metricDescGroup{thresholdConfigKey: "inbound"},
			BehaviorContext{},
		)
	}

	if len(*events) != 1 {
		t.Fatalf("events=%#v, want one public admin exposure alert", *events)
	}
	event := (*events)[0]
	if event["kind"] != "inbound_admin_port_exposure_suspected" || event["top_dst_port"] != 3389 || event["src_ip"] != "198.51.100.1" {
		t.Fatalf("public admin alert inherited private endpoint evidence: %#v", event)
	}
}

func TestInboundAdminCategoryCannotBeHiddenByDominantHTTPS(t *testing.T) {
	cm := newBehaviorStateTestManager()
	cm.behaviorInboundPortNames = builtinBehaviorInboundMonitoredPorts()
	events := captureBehaviorAlerts(cm)
	stats := newBehaviorStats(false)
	for i := 1; i <= 20; i++ {
		stats.updateDetailedWithCoverage(IPStrToKey(fmt.Sprintf("198.51.100.%d", i)), 3389, 6, IPS_SEEN_REPLY, 1, 0, 0, false, false)
	}
	httpsRemote := IPStrToKey("203.0.113.200")
	for i := 0; i < 500; i++ {
		stats.updateDetailedWithCoverage(httpsRemote, 443, 6, IPS_SEEN_REPLY, 1, 0, 0, false, false)
	}

	for cycle := 0; cycle < 3; cycle++ {
		cm.analyzeBehavior(
			stats,
			IPStrToKey("10.0.0.52"),
			"10.0.0.52", "ipv4", "domain", "server", "vm-public-admin-with-https",
			"project", "project-name", "user",
			nil,
			metricDescGroup{thresholdConfigKey: "inbound"},
			BehaviorContext{},
		)
	}

	if len(*events) != 1 {
		t.Fatalf("events=%#v, want one public admin exposure alert", *events)
	}
	event := (*events)[0]
	if event["kind"] != "inbound_admin_port_exposure_suspected" || event["top_dst_port"] != 3389 || event["src_ip"] != "198.51.100.1" {
		t.Fatalf("dominant HTTPS hid or replaced public-admin evidence: %#v", event)
	}
}

func TestInboundAdminExposureIgnoresUDPOnTCPOnlyPort(t *testing.T) {
	cm := newBehaviorStateTestManager()
	cm.behaviorInboundPortNames = builtinBehaviorInboundMonitoredPorts()
	events := captureBehaviorAlerts(cm)
	stats := newBehaviorStats(false)
	for i := 1; i <= 20; i++ {
		stats.updateDetailedWithCoverage(IPStrToKey(fmt.Sprintf("198.51.100.%d", i)), 22, 17, IPS_SEEN_REPLY, 1, 0, 0, false, false)
	}

	for cycle := 0; cycle < 3; cycle++ {
		cm.analyzeBehavior(
			stats,
			IPStrToKey("10.0.0.53"),
			"10.0.0.53", "ipv4", "domain", "server", "vm-udp-admin-port",
			"project", "project-name", "user",
			nil,
			metricDescGroup{thresholdConfigKey: "inbound"},
			BehaviorContext{},
		)
	}

	for _, event := range *events {
		if event["kind"] == "inbound_admin_port_exposure_suspected" {
			t.Fatalf("UDP/22 was classified as TCP admin exposure: %#v", event)
		}
	}
}

func TestInboundAttackClassifierBranches(t *testing.T) {
	cm := &ConntrackManager{}
	sc := newBehaviorScaler(1)
	tests := []struct {
		name    string
		feature BehaviorFeature
		want    string
	}{
		{"wrong direction", BehaviorFeature{Direction: "outbound", Flows: 100, UnrepliedRatio: 1}, ""},
		{"few flows", BehaviorFeature{Direction: "inbound", Flows: 10, UnrepliedRatio: 1}, ""},
		{"replied", BehaviorFeature{Direction: "inbound", Flows: 100, UnrepliedRatio: .2}, ""},
		{"service spray", BehaviorFeature{Direction: "inbound", Flows: 100, UnrepliedRatio: .9, NewRemotes: 30, UniqueDstPorts: 2, MaxSingleDstPort: 90, MaxSingleRemote: 2}, "inbound_service_spray_suspected"},
		{"distributed probe", BehaviorFeature{Direction: "inbound", Flows: 100, UnrepliedRatio: .9, NewRemotes: 30, UniqueDstPorts: 3, MaxSingleDstPort: 20, MaxSingleRemote: 20}, "inbound_distributed_probe_suspected"},
		{"multiport probe", BehaviorFeature{Direction: "inbound", Flows: 100, UnrepliedRatio: .9, UniqueDstPorts: 20, MaxSingleDstPort: 2, MaxSingleRemote: 90}, "inbound_single_remote_multiport_probe_suspected"},
		{"single remote flood", BehaviorFeature{Direction: "inbound", Flows: 200, UnrepliedRatio: .9, UniqueDstPorts: 5, MaxSingleDstPort: 10, MaxSingleRemote: 190}, "inbound_single_remote_flood"},
		{"udp distributed flood", BehaviorFeature{Direction: "inbound", Flows: 150, UnrepliedRatio: .95, UDPCount: 100, UDPUnrepliedRatio: .95, UniqueDstPorts: 10, MaxSingleDstPort: 20, MaxSingleRemote: 20}, "inbound_udp_flood_suspected"},
		{"udp targeted flood", BehaviorFeature{Direction: "inbound", Flows: 150, UnrepliedRatio: .95, UDPCount: 100, UDPUnrepliedRatio: .95, UDPTopDstPort: 53, UDPTopDstPortFlows: 100, UDPTopRemoteFlows: 10, UniqueDstPorts: 5, MaxSingleDstPort: 130, MaxSingleRemote: 10}, "inbound_udp_targeted_flood_suspected"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hit, kind, _ := cm.classifyInboundAttackPatterns(tt.feature, sc)
			if hit != (tt.want != "") || kind != tt.want {
				t.Fatalf("hit=%v kind=%q, want %q", hit, kind, tt.want)
			}
		})
	}
}

func TestInboundUDPAttackUsesUDPReplyEvidence(t *testing.T) {
	cm := &ConntrackManager{}
	sc := newBehaviorScaler(1)

	tests := []struct {
		name    string
		feature BehaviorFeature
		wantHit bool
	}{
		{
			name: "unrelated TCP failures cannot turn replied UDP into a flood",
			feature: BehaviorFeature{
				Direction: "inbound", Flows: 1000, UnrepliedRatio: .90,
				UDPCount: 100, UDPUnrepliedRatio: 0,
				UniqueDstPorts: 10, MaxSingleDstPort: 20, MaxSingleRemote: 20,
			},
		},
		{
			name: "unrelated replied TCP cannot hide an unreplied UDP flood",
			feature: BehaviorFeature{
				Direction: "inbound", Flows: 1000, UnrepliedRatio: .10,
				UDPCount: 100, UDPUnrepliedRatio: 1,
				UniqueDstPorts: 10, MaxSingleDstPort: 20, MaxSingleRemote: 20,
			},
			wantHit: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hit, kind, _ := cm.classifyInboundAttackPatterns(tt.feature, sc)
			if hit != tt.wantHit {
				t.Fatalf("hit=%v kind=%q, want hit=%v", hit, kind, tt.wantHit)
			}
		})
	}
}

func TestUDPAlertsUseUDPOnlyEndpointAndDominanceEvidence(t *testing.T) {
	t.Run("outbound fanout ignores dominant TCP endpoint", func(t *testing.T) {
		cm := newBehaviorStateTestManager()
		cm.behaviorOutboundPortNames = builtinBehaviorOutboundMonitoredPorts()
		events := captureBehaviorAlerts(cm)
		stats := newBehaviorStats(false)

		for i := 0; i < 120; i++ {
			remote := IPStrToKey(fmt.Sprintf("198.51.100.%d", (i%60)+1))
			stats.updateDetailedWithCoverage(remote, 123, 17, 0, 1, 0, 0, false, false)
		}
		tcpRemote := IPStrToKey("203.0.113.200")
		for i := 0; i < 500; i++ {
			stats.updateDetailedWithCoverage(tcpRemote, 443, 6, IPS_SEEN_REPLY, 1, 0, 0, false, false)
		}

		for cycle := 0; cycle < 3; cycle++ {
			cm.analyzeBehavior(
				stats,
				IPStrToKey("10.0.0.60"),
				"10.0.0.60", "ipv4", "domain", "server", "vm-udp-outbound-endpoint",
				"project", "project-name", "user",
				nil,
				metricDescGroup{thresholdConfigKey: "outbound"},
				BehaviorContext{},
			)
		}

		if len(*events) != 1 {
			t.Fatalf("events=%#v, want one UDP fanout alert", *events)
		}
		event := (*events)[0]
		if event["kind"] != "outbound_udp_fanout_suspected" || event["top_dst_port"] != 123 || event["dst_ip"] != "198.51.100.1" {
			t.Fatalf("UDP fanout inherited TCP endpoint evidence: %#v", event)
		}
	})

	t.Run("inbound flood ignores dominant TCP port", func(t *testing.T) {
		cm := newBehaviorStateTestManager()
		cm.behaviorInboundPortNames = builtinBehaviorInboundMonitoredPorts()
		events := captureBehaviorAlerts(cm)
		stats := newBehaviorStats(false)

		for i := 0; i < 100; i++ {
			remote := IPStrToKey(fmt.Sprintf("198.51.100.%d", (i%100)+1))
			stats.updateDetailedWithCoverage(remote, 53, 17, 0, 1, 0, 0, false, false)
		}
		for i := 0; i < 900; i++ {
			remote := IPStrToKey(fmt.Sprintf("203.0.113.%d", (i%100)+1))
			stats.updateDetailedWithCoverage(remote, 443, 6, IPS_SEEN_REPLY, 1, 0, 0, false, false)
		}

		for cycle := 0; cycle < 3; cycle++ {
			cm.analyzeBehavior(
				stats,
				IPStrToKey("10.0.0.61"),
				"10.0.0.61", "ipv4", "domain", "server", "vm-udp-inbound-endpoint",
				"project", "project-name", "user",
				nil,
				metricDescGroup{thresholdConfigKey: "inbound"},
				BehaviorContext{},
			)
		}

		if len(*events) != 1 {
			t.Fatalf("events=%#v, want one inbound UDP flood alert", *events)
		}
		event := (*events)[0]
		if event["kind"] != "inbound_udp_targeted_flood_suspected" || event["top_dst_port"] != 53 || event["src_ip"] != "198.51.100.1" {
			t.Fatalf("inbound UDP flood inherited TCP endpoint or dominance evidence: %#v", event)
		}
	})
}

func TestCapacityAndFloodClassifierBranches(t *testing.T) {
	cm := &ConntrackManager{}
	sc := newBehaviorScaler(1)
	tests := []struct {
		name       string
		feature    BehaviorFeature
		hostImpact float64
		want       string
	}{
		{"configured limit", BehaviorFeature{ThresholdFlows: 100, Flows: 201}, 0, "conntrack_flow_limit_exceeded"},
		{"no pressure", BehaviorFeature{Flows: 300}, .05, ""},
		{"generic pressure", BehaviorFeature{Direction: "outbound", Flows: 300}, .11, "host_conntrack_pressure"},
		{"icmp", BehaviorFeature{Direction: "outbound", Flows: 300, ICMPCount: 51}, .11, "host_icmp_flood_suspected"},
		{"multicast", BehaviorFeature{Direction: "outbound", Flows: 300, MulticastCount: 51}, .11, "host_multicast_storm_suspected"},
		{"inbound", BehaviorFeature{Direction: "inbound", Flows: 300}, .11, "inbound_conntrack_pressure"},
		{"stale", BehaviorFeature{Direction: "outbound", Flows: 300, ConntrackAcct: true, UnrepliedRatio: .1, BytesPerFlow: 500, BytesPerFlowAvailable: true}, .11, "host_accumulating_stale_flows"},
		{"known zero is stale rather than missing", BehaviorFeature{Direction: "outbound", Flows: 300, ConntrackAcct: true, UnrepliedRatio: .1, BytesPerFlow: 0, BytesPerFlowAvailable: true}, .11, "host_accumulating_stale_flows"},
		{"missing accounting is not stale", BehaviorFeature{Direction: "outbound", Flows: 300, ConntrackAcct: true, UnrepliedRatio: .1, BytesPerFlow: 0}, .11, "host_conntrack_pressure"},
		{"high throughput", BehaviorFeature{Direction: "outbound", Flows: 300, ConntrackAcct: true, UnrepliedRatio: .1, BytesPerFlow: 200000, BytesPerFlowAvailable: true}, .11, "host_high_throughput_anomaly"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hit, kind, reason := cm.classifyCapacityAndFlood(tt.feature, tt.hostImpact, sc)
			if hit != (tt.want != "") || kind != tt.want {
				t.Fatalf("hit=%v kind=%q reason=%q, want %q", hit, kind, reason, tt.want)
			}
		})
	}
}

func TestEWMABandClassifierBoundaries(t *testing.T) {
	cm := &ConntrackManager{}
	sc := newBehaviorScaler(1)
	if hit, _, _ := cm.classifyEWMABands(BehaviorFeature{Flows: 9}, behaviorAnomalies{Signal: 1}, sc); hit {
		t.Fatal("low-flow EWMA alert")
	}
	tests := []struct {
		dir    string
		signal float64
		want   string
	}{
		{"outbound", .91, "outbound_behavior_spike_critical_suspected"},
		{"inbound", .81, "inbound_behavior_spike_high_suspected"},
		{"", .66, "behavior_spike_medium_suspected"},
		{"outbound", .51, "outbound_behavior_spike_low_suspected"},
		{"outbound", .49, ""},
	}
	for _, tt := range tests {
		hit, kind, _ := cm.classifyEWMABands(BehaviorFeature{Direction: tt.dir, Flows: 10}, behaviorAnomalies{Signal: tt.signal}, sc)
		if hit != (tt.want != "") || kind != tt.want {
			t.Errorf("dir=%q signal=%v got %v/%q want %q", tt.dir, tt.signal, hit, kind, tt.want)
		}
	}
}

func TestBehaviorSeverityConfidencePriorityBoundaries(t *testing.T) {
	if got := behaviorSeverityScore(BehaviorFeature{}); got != 0 {
		t.Fatalf("empty severity = %d", got)
	}
	feature := BehaviorFeature{
		Direction: "inbound", Flows: 1000, HostImpactPercent: 10, UnrepliedRatio: 1,
		InfraHits: 1, InfraMaxFlows: 1000, LocalScanHits: 1, BGPFlows: 1,
		GeneveFlows: 1, MetadataHits: 1, MetadataMaxFlows: 1000, AdminPortFlows: 1000,
	}
	if got := behaviorSeverityScore(feature); got < 95 || got > 100 {
		t.Fatalf("maximum evidence severity = %d", got)
	}
	if got := behaviorConfidenceScore(BehaviorFeature{InfraHits: 1}, "restricted_network_probe", 0, 0, "distributed", 0); got != 70 {
		t.Fatalf("restricted confidence floor = %d", got)
	}
	if got := behaviorConfidenceScore(BehaviorFeature{TenantPrivateHits: 1}, "lateral_probe_suspected", 0, 0, "distributed", 0); got != 70 {
		t.Fatalf("lateral confidence floor = %d", got)
	}
	if got := behaviorConfidenceScore(BehaviorFeature{BGPFlows: 1}, "bgp_peering_attempt", 1, 1, "dominant_port", 3); got != 49 {
		t.Fatalf("single BGP confidence cap = %d", got)
	}
	if got := behaviorConfidenceScore(BehaviorFeature{GeneveFlows: 3}, "geneve_underlay_attempt", 0, 0, "distributed", 2); got != 80 {
		t.Fatalf("persistent Geneve confidence floor = %d", got)
	}
	if got := behaviorConfidenceScore(BehaviorFeature{}, "metadata_probe_suspected", 0, 0, "distributed", 0); got != 75 {
		t.Fatalf("metadata confidence floor = %d", got)
	}
	if got := behaviorConfidenceScore(BehaviorFeature{SynergyDarkScan: true, SynergyDarkPhysics: true}, "x", 1, 1, "dominant_port", 3); got != 100 {
		t.Fatalf("synergy confidence clamp = %d", got)
	}

	bands := map[int]string{0: "low", 35: "medium", 65: "high", 85: "critical"}
	for score, want := range bands {
		if got := behaviorSeverityBand(score); got != want {
			t.Errorf("severity band %d = %q", score, got)
		}
	}
	priorities := []struct {
		sev, conf int
		p, basis  string
	}{
		{80, 80, "P1", "mixed"},
		{80, 60, "P2", "mixed"},
		{60, 80, "P2", "mixed"},
		{80, 30, "P3", "severity"},
		{30, 80, "P3", "confidence"},
		{10, 10, "P4", "mixed"},
	}
	for _, tt := range priorities {
		p, basis := behaviorPriorityFromScores(tt.sev, tt.conf)
		if p != tt.p || basis != tt.basis {
			t.Errorf("priority(%d,%d) = %s/%s, want %s/%s", tt.sev, tt.conf, p, basis, tt.p, tt.basis)
		}
	}
	for p, want := range map[string]int{"P4": 1, "P3": 2, "P2": 3, "P1": 4, "junk": 1} {
		if got := priorityRank(p); got != want {
			t.Errorf("priorityRank(%q) = %d", p, got)
		}
	}
}

func TestBehaviorSeverityIncludesLateralPolicyEvidence(t *testing.T) {
	base := BehaviorFeature{Direction: "outbound", Flows: 100}
	withLateral := base
	withLateral.TenantPrivateHits = 1
	withLateral.TenantPrivateMaxFlows = 100
	if got, without := behaviorSeverityScore(withLateral), behaviorSeverityScore(base); got <= without {
		t.Fatalf("lateral policy evidence did not increase severity: with=%d without=%d", got, without)
	}
}

func TestClassifyBehaviorOrderingAndSynergy(t *testing.T) {
	cm := &ConntrackManager{behaviorSensitivity: 1}
	tests := []struct {
		name            string
		feature         BehaviorFeature
		anoms           behaviorAnomalies
		wantKind        string
		wantRuleID      string
		wantDarkScan    bool
		wantDarkPhysics bool
	}{
		{"restricted first", BehaviorFeature{Direction: "outbound", BGPFlows: 1, UnmonitoredPortFlows: 100, UnmonitoredUnrepliedRatio: 1, Flows: 100, UnrepliedRatio: 1}, behaviorAnomalies{}, "bgp_peering_attempt", "restricted_bgp", false, false},
		{"dark physics", BehaviorFeature{Direction: "outbound", Flows: 100, UnmonitoredPortFlows: 50, UnmonitoredUnrepliedRatio: .9, UnrepliedRatio: .9, SMTPFlows: 60, SMTPUniqueRemotes: 30, SMTPUnrepliedRatio: .9, SMTPTopRemoteFlows: 3, SMTPTopDstPort: 25, SMTPTopDstPortFlows: 60, UniqueRemotes: 30, TopDstPort: 25, MaxSingleDstPort: 90}, behaviorAnomalies{}, "darkspace_plus_physics", "synergy_darkspace_plus_physics", true, true},
		{"dark scan", BehaviorFeature{Direction: "outbound", Flows: 100, UnmonitoredPortFlows: 50, UnmonitoredUnrepliedRatio: .9, UnrepliedRatio: .9, UniqueRemotes: 30, TopDstPort: 1234, MaxSingleDstPort: 90}, behaviorAnomalies{}, "darkspace_plus_scan", "synergy_darkspace_plus_scan", true, false},
		{"capacity", BehaviorFeature{Direction: "outbound", Flows: 201, ThresholdFlows: 100}, behaviorAnomalies{}, "conntrack_flow_limit_exceeded", "legacy_capacity_and_flood", false, false},
		{"ewma", BehaviorFeature{Direction: "outbound", Flows: 10}, behaviorAnomalies{Signal: .9}, "outbound_behavior_spike_critical_suspected", "legacy_ewma_bands", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			classification := cm.classifyBehavior(tt.feature, 0, tt.anoms, map[uint16]int{tt.feature.TopDstPort: tt.feature.Flows})
			if !classification.Hit || classification.Kind != tt.wantKind || classification.Reason == "" || classification.RuleID != tt.wantRuleID || classification.RuleSource != "internal" || classification.SynergyDarkScan != tt.wantDarkScan || classification.SynergyDarkPhysics != tt.wantDarkPhysics {
				t.Fatalf("classification = %+v", classification)
			}
		})
	}
}

func TestTopPortIsAndRuleDirection(t *testing.T) {
	feature := BehaviorFeature{TopDstPort: 443}
	if !topPortIs(feature, 80, 443) || topPortIs(feature, 80, 8080) {
		t.Fatal("topPortIs result is wrong")
	}
	for _, dir := range []string{"", "any", "outbound"} {
		if !ruleDirMatch(dir, "outbound") {
			t.Errorf("direction %q should match outbound", dir)
		}
	}
	if ruleDirMatch("inbound", "outbound") {
		t.Fatal("opposite directions matched")
	}
}

func TestBehaviorAlertEvidenceGeneralPath(t *testing.T) {
	remote := IPStrToKey("198.51.100.7")
	cm := &ConntrackManager{behaviorOutboundPortNames: map[uint16]string{443: "https"}}
	feature := BehaviorFeature{Direction: "outbound", Flows: 10, TopDstPort: 443, MaxSingleDstPort: 8, MaxSingleRemote: 6}
	ev := cm.buildBehaviorAlertEvidence(feature, remote, true, "outbound_horizontal_scan_suspected")
	if ev.TopDstPort != 443 || ev.TopDstPortName != "https" || ev.TopRemoteIP != "198.51.100.7" || ev.TopPortShare != .8 || ev.TopRemoteShare != .6 {
		t.Fatalf("alert evidence = %+v", ev)
	}
	feature.RemoteEvidenceApproximate = true
	ev = cm.buildBehaviorAlertEvidence(feature, remote, true, "outbound_horizontal_scan_suspected")
	if ev.TopRemoteIP != "" || ev.TopRemoteShare != 0 || !strings.Contains(ev.EvidenceMode, "port") {
		t.Fatalf("approximate alert evidence = %+v", ev)
	}
}
