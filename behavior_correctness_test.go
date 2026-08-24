package main

import "testing"

func TestCombineBehaviorSignalsUsesMostSevereEnabledDirection(t *testing.T) {
	got, available := combineBehaviorSignals(0.92, 0.08, true, true)
	if !available {
		t.Fatal("expected behavior scoring to be available")
	}
	if got != 0.92 {
		t.Fatalf("combined signal = %v, want worst enabled direction 0.92", got)
	}

	got, available = combineBehaviorSignals(0.92, 0.08, false, true)
	if !available || got != 0.08 {
		t.Fatalf("inbound-only signal = %v, available=%v; want 0.08, true", got, available)
	}
}

func TestBehaviorDestinationClassesAreDisjoint(t *testing.T) {
	hostPrivate := IPStrToKey("10.20.30.40")
	hosts := map[IPKey]struct{}{hostPrivate: {}}
	tests := []struct {
		name string
		ip   string
		want behaviorDestinationClass
	}{
		{name: "metadata", ip: "169.254.169.254", want: behaviorDestinationMetadata},
		{name: "private host", ip: "10.20.30.40", want: behaviorDestinationHostControl},
		{name: "rfc1918", ip: "192.168.8.9", want: behaviorDestinationTenantPrivate},
		{name: "ula", ip: "fd12:3456::9", want: behaviorDestinationTenantPrivate},
		{name: "link local", ip: "fe80::1", want: behaviorDestinationLocalLink},
		{name: "loopback", ip: "127.0.0.1", want: behaviorDestinationLocalLink},
		{name: "limited broadcast", ip: "255.255.255.255", want: behaviorDestinationLocalLink},
		{name: "public", ip: "203.0.113.10", want: behaviorDestinationPublic},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyBehaviorDestination(IPStrToKey(tt.ip), hosts); got != tt.want {
				t.Fatalf("classifyBehaviorDestination(%s) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestRestrictedAlertSelectsNonGlobalLocalEvidence(t *testing.T) {
	publicRemote := IPStrToKey("203.0.113.10")
	limitedBroadcast := IPStrToKey("255.255.255.255")
	stats := newBehaviorStats(false)
	stats.remotes[publicRemote] = struct{}{}
	stats.perRemote[publicRemote] = 8
	stats.remotes[limitedBroadcast] = struct{}{}
	stats.perRemote[limitedBroadcast] = 3

	src, dst := behaviorSelectAlertIPs(
		"outbound",
		"10.0.0.10",
		stats,
		"restricted_network_probe",
		nil,
	)
	if src != "10.0.0.10" || dst != "255.255.255.255" {
		t.Fatalf("restricted alert endpoints=(%q,%q), want local evidence destination", src, dst)
	}
}

func TestMetadataTrafficDoesNotMatchGenericInfrastructureRule(t *testing.T) {
	feature := BehaviorFeature{
		Direction:              "outbound",
		Flows:                  30,
		MetadataHits:           30,
		MetadataMaxFlows:       30,
		MetadataUnrepliedRatio: 1,
	}
	hit, ruleID, kind, _, _ := evalRules(feature, newBehaviorScaler(1), buildBehaviorEvidence(feature), &RuleCtx{Thresholds: defaultRuleThresholds}, rulesRestrictedLocal)
	if !hit || ruleID != "restricted_metadata_probe" || kind != "metadata_probe_suspected" {
		t.Fatalf("metadata classification = hit %v rule %q kind %q", hit, ruleID, kind)
	}
}

func TestHigherSensitivityDoesNotTightenUpperBounds(t *testing.T) {
	feature := BehaviorFeature{
		Direction: "outbound",
		MiningHigh: miningTierSummary{
			Flows:          15,
			RepliedFlows:   15,
			UniqueRemotes:  15,
			UniquePorts:    1,
			TopPort:        10128,
			TopPortFlows:   15,
			TopPortReplied: 15,
		},
	}
	ctx := &RuleCtx{Thresholds: defaultRuleThresholds}

	normal := feature
	normal.Mining = selectMiningDetectionEvidence(normal, newBehaviorScaler(1))
	sensitive := feature
	sensitive.Mining = selectMiningDetectionEvidence(sensitive, newBehaviorScaler(2))
	hitNormal, _, _, _, _ := evalRules(normal, newBehaviorScaler(1), buildBehaviorEvidence(normal), ctx, rulesProtocol)
	hitSensitive, _, _, _, _ := evalRules(sensitive, newBehaviorScaler(2), buildBehaviorEvidence(sensitive), ctx, rulesProtocol)
	if hitNormal {
		t.Fatal("normal sensitivity unexpectedly accepted more than the configured remote maximum")
	}
	if !hitSensitive {
		t.Fatal("increased sensitivity tightened the Stratum maximum-remotes bound")
	}

	inbound := BehaviorFeature{
		Direction:        "inbound",
		Flows:            20,
		NewRemotes:       20,
		UniqueRemotes:    20,
		UniqueDstPorts:   6,
		MaxSingleDstPort: 20,
		UnrepliedRatio:   1,
	}
	cm := &ConntrackManager{}
	if hit, _, _ := cm.classifyInboundAttackPatterns(inbound, newBehaviorScaler(1)); hit {
		t.Fatal("normal sensitivity unexpectedly accepted six destination ports as a narrow spray")
	}
	if hit, _, _ := cm.classifyInboundAttackPatterns(inbound, newBehaviorScaler(2)); !hit {
		t.Fatal("increased sensitivity tightened the inbound maximum-port bound")
	}
}

func TestMiningEvidenceExcludesBitcoinP2PAndRequiresReplies(t *testing.T) {
	ctx := &RuleCtx{Thresholds: defaultRuleThresholds}
	tests := []struct {
		name    string
		feature BehaviorFeature
		sens    float64
		wantHit bool
	}{
		{
			name: "bitcoin p2p",
			feature: BehaviorFeature{Direction: "outbound", Flows: 20, UniqueRemotes: 1, TopDstPort: 8333,
				StratumFlows: 20, StratumRepliedFlows: 20, MaxSingleDstPort: 20},
			wantHit: false,
		},
		{
			name: "unreplied stratum",
			feature: BehaviorFeature{Direction: "outbound", Flows: 2, UniqueRemotes: 1, TopDstPort: 3333,
				MiningShared: miningTierSummary{Flows: 3, RepliedFlows: 0, UniqueRemotes: 1, UniquePorts: 1, TopPort: 3333, TopPortFlows: 3}},
			wantHit: false,
		},
		{
			name: "one shared-port connection at high sensitivity",
			feature: BehaviorFeature{Direction: "outbound", Flows: 1, UniqueRemotes: 1, TopDstPort: 3333,
				MiningShared: miningTierSummary{Flows: 1, RepliedFlows: 1, UniqueRemotes: 1, UniquePorts: 1, TopPort: 3333, TopPortFlows: 1, TopPortReplied: 1}},
			sens:    2,
			wantHit: false,
		},
		{
			name: "shared-port candidate stays out of generic classifier",
			feature: BehaviorFeature{Direction: "outbound", Flows: 3, UniqueRemotes: 1, TopDstPort: 4444,
				MiningShared: miningTierSummary{Flows: 3, RepliedFlows: 2, UniqueRemotes: 1, UniquePorts: 1, TopPort: 4444, TopPortFlows: 3, TopPortReplied: 2}},
			wantHit: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sens := tt.sens
			if sens == 0 {
				sens = 1
			}
			tt.feature.Mining = selectMiningDetectionEvidence(tt.feature, newBehaviorScaler(sens))
			hit, _, _, _, _ := evalRules(tt.feature, newBehaviorScaler(sens), buildBehaviorEvidence(tt.feature), ctx, rulesProtocol)
			if hit != tt.wantHit {
				t.Fatalf("mining rule hit = %v, want %v", hit, tt.wantHit)
			}
		})
	}
}

func TestSingleBGPOrGeneveFlowIsNotHighConfidence(t *testing.T) {
	for _, tc := range []struct {
		name string
		kind string
		port uint16
		set  func(*BehaviorFeature)
	}{
		{name: "bgp", kind: "bgp_peering_attempt", port: 179, set: func(f *BehaviorFeature) { f.BGPFlows = 1 }},
		{name: "geneve", kind: "geneve_underlay_attempt", port: 6081, set: func(f *BehaviorFeature) { f.GeneveFlows = 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			feature := BehaviorFeature{Direction: "outbound", Flows: 1, UniqueRemotes: 1, NewRemotes: 1,
				UniqueDstPorts: 1, NewDstPorts: 1, MaxSingleRemote: 1, MaxSingleDstPort: 1, TopDstPort: tc.port}
			tc.set(&feature)
			confidence := behaviorConfidenceScore(feature, tc.kind, 1, 1, "dominant_remote", 3)
			if confidence >= 75 {
				t.Fatalf("single-flow confidence = %d, want below high-confidence threshold", confidence)
			}
		})
	}
}
