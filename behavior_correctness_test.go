package main

import "testing"

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

func TestRestrictedSignalSelectsNonGlobalLocalEvidence(t *testing.T) {
	publicRemote := IPStrToKey("203.0.113.10")
	limitedBroadcast := IPStrToKey("255.255.255.255")
	stats := newBehaviorStats(false)
	stats.remotes[publicRemote] = struct{}{}
	stats.perRemote[publicRemote] = 8
	stats.remotes[limitedBroadcast] = struct{}{}
	stats.perRemote[limitedBroadcast] = 3

	src, dst := behaviorSelectSignalIPs(
		"outbound",
		"10.0.0.10",
		stats,
		"restricted_network_probe",
		nil,
	)
	if src != "10.0.0.10" || dst != "255.255.255.255" {
		t.Fatalf("restricted signal endpoints=(%q,%q), want local evidence destination", src, dst)
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
	hit, ruleID, signal, _, _ := evalRules(feature, newBehaviorScaler(1), buildBehaviorEvidence(feature), &RuleCtx{Thresholds: defaultRuleThresholds}, rulesRestrictedLocal)
	if !hit || ruleID != "restricted_metadata_probe" || signal != "metadata_probe_suspected" {
		t.Fatalf("metadata classification = hit %v rule %q signal %q", hit, ruleID, signal)
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
			TopPairFlows:   15,
			TopPairReplied: 15,
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
				MiningShared: miningTierSummary{Flows: 1, RepliedFlows: 1, UniqueRemotes: 1, UniquePorts: 1, TopPort: 3333, TopPairFlows: 1, TopPairReplied: 1, TopPortFlows: 1, TopPortReplied: 1}},
			sens:    2,
			wantHit: false,
		},
		{
			name: "shared-port candidate stays out of generic classifier",
			feature: BehaviorFeature{Direction: "outbound", Flows: 3, UniqueRemotes: 1, TopDstPort: 4444,
				MiningShared: miningTierSummary{Flows: 3, RepliedFlows: 2, UniqueRemotes: 1, UniquePorts: 1, TopPort: 4444, TopPairFlows: 3, TopPairReplied: 2, TopPortFlows: 3, TopPortReplied: 2}},
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
