package main

import "testing"

func TestBuiltinMiningPortCoverageIncludesMoneroAndMajorPools(t *testing.T) {
	tests := []struct {
		port       uint16
		confidence miningPortConfidence
	}{
		// Common Monero/RandomX pool ports.
		{3333, miningPortConfidenceShared},
		{4444, miningPortConfidenceShared},
		{5555, miningPortConfidenceShared},
		{7777, miningPortConfidenceShared},
		{9000, miningPortConfidenceShared},
		{14444, miningPortConfidenceHigh},

		// MoneroOcean difficulty and TLS endpoints.
		{10001, miningPortConfidenceHigh},
		{10128, miningPortConfidenceHigh},
		{18192, miningPortConfidenceHigh},
		{20001, miningPortConfidenceHigh},
		{20128, miningPortConfidenceHigh},

		// Dedicated endpoints used by other active mining pools.
		{11010, miningPortConfidenceHigh},
		{12020, miningPortConfidenceHigh},
		{14141, miningPortConfidenceHigh},
		{16060, miningPortConfidenceHigh},
		{18888, miningPortConfidenceHigh},
		{34141, miningPortConfidenceHigh},
		{5252, miningPortConfidenceShared},
		{6464, miningPortConfidenceShared},
		{11818, miningPortConfidenceHigh},
	}

	for _, tt := range tests {
		info, ok := builtinMiningPortInfo(tt.port)
		if !ok {
			t.Errorf("port %d is missing from built-in mining coverage", tt.port)
			continue
		}
		if info.Confidence != tt.confidence {
			t.Errorf("port %d confidence = %v, want %v", tt.port, info.Confidence, tt.confidence)
		}
		if info.Name == "" {
			t.Errorf("port %d has no evidence label", tt.port)
		}
	}
}

func TestBuiltinMiningPortCoverageExcludesGenericAndPeerPorts(t *testing.T) {
	for _, port := range []uint16{
		80, 443, 8080, 8333, 9200,
		18080, // Monero peer-to-peer.
		18081, // Monero daemon RPC.
	} {
		if info, ok := builtinMiningPortInfo(port); ok {
			t.Errorf("port %d must not be classified as mining by port alone: %+v", port, info)
		}
	}
}

func TestMiningFlowCollectionRequiresTCPExternalDestination(t *testing.T) {
	publicRemote := IPStrToKey("198.51.100.10")
	privateRemote := IPStrToKey("10.0.0.10")
	s := newBehaviorStats(false)

	s.updateOutboundMining(publicRemote, 10128, 6, IPS_SEEN_REPLY, true)
	s.updateOutboundMining(publicRemote, 10128, 17, IPS_SEEN_REPLY, true)
	s.updateOutboundMining(publicRemote, 10128, 6, IPS_SEEN_REPLY, false)
	s.updateOutboundMining(privateRemote, 10128, 6, IPS_SEEN_REPLY, true)
	s.updateOutboundMining(publicRemote, 8333, 6, IPS_SEEN_REPLY, true)

	high, shared := s.summarizeMining(nil)
	if high.Flows != 1 || high.RepliedFlows != 1 || high.UniqueRemotes != 1 {
		t.Fatalf("high-confidence summary = %+v, want one replied public TCP flow", high)
	}
	if shared.Flows != 0 {
		t.Fatalf("shared summary = %+v, want no flows", shared)
	}
}

func TestMiningFlowCollectionExcludesHostControlPlaneAddresses(t *testing.T) {
	remote := IPStrToKey("203.0.113.20")
	s := newBehaviorStats(false)
	s.updateOutboundMining(remote, 10128, 6, IPS_SEEN_REPLY, true)

	hostIPs := map[IPKey]struct{}{remote: {}}
	high, _ := s.summarizeMining(hostIPs)
	if high.Flows != 0 {
		t.Fatalf("host/control-plane destination was counted as mining: %+v", high)
	}
}

func TestHighConfidenceMiningUsesMiningSpecificEvidence(t *testing.T) {
	feature := BehaviorFeature{
		Direction:     "outbound",
		Flows:         500,
		UniqueRemotes: 200,
		TopDstPort:    443,
		MiningHigh: miningTierSummary{
			Flows:          1,
			RepliedFlows:   1,
			UniqueRemotes:  1,
			UniquePorts:    1,
			TopPort:        10128,
			TopPortFlows:   1,
			TopPortReplied: 1,
		},
	}

	evidence := selectMiningDetectionEvidence(feature, newBehaviorScaler(1))
	if !evidence.Valid || evidence.Confidence != miningPortConfidenceHighPersistent {
		t.Fatalf("single dedicated-port evidence = %+v, want a persistent dedicated-port candidate", evidence)
	}
	if evidence.TopPort != 10128 || evidence.UniqueRemotes != 1 {
		t.Fatalf("candidate used global rather than mining-specific evidence: %+v", evidence)
	}

	feature.Mining = evidence
	if got := behaviorPersistenceRequired(feature, "outbound_stratum_mining_suspected", "P2"); got != 3 {
		t.Fatalf("single-flow high-confidence persistence = %d, want 3", got)
	}

	feature.Mining.Flows = 2
	feature.Mining.RepliedFlows = 2
	if got := behaviorPersistenceRequired(feature, "outbound_stratum_mining_suspected", "P2"); got != 2 {
		t.Fatalf("multi-reply high-confidence persistence = %d, want 2", got)
	}
	feature.MiningHigh.Flows = 2
	feature.MiningHigh.RepliedFlows = 2
	feature.MiningHigh.TopPortFlows = 2
	feature.MiningHigh.TopPortReplied = 2
	if got := selectMiningDetectionEvidence(feature, newBehaviorScaler(1)); !got.Valid || got.Confidence != miningPortConfidenceHigh {
		t.Fatalf("multiple replied dedicated-port flows = %+v, want high confidence", got)
	}
}

func TestBehaviorClassifierFindsMiningWhenNormalWebTrafficDominates(t *testing.T) {
	feature := BehaviorFeature{
		Direction:        "outbound",
		Flows:            500,
		UniqueRemotes:    200,
		UniqueDstPorts:   2,
		TopDstPort:       443,
		MaxSingleDstPort: 499,
		MiningHigh: miningTierSummary{
			Flows:          2,
			RepliedFlows:   2,
			UniqueRemotes:  1,
			UniquePorts:    1,
			TopPort:        10128,
			TopPortFlows:   2,
			TopPortReplied: 2,
		},
	}
	cm := &ConntrackManager{behaviorSensitivity: 1}
	feature.Mining = selectMiningDetectionEvidence(feature, newBehaviorScaler(cm.behaviorSensitivity))
	classification := cm.classifyBehavior(feature, 0, behaviorAnomalies{}, map[uint16]int{443: 499, 10128: 1})
	if !classification.Hit || classification.Kind != "outbound_stratum_mining_suspected" || classification.RuleID != "proto_stratum_mining" {
		t.Fatalf("classification = %+v", classification)
	}
	if feature.Mining.TopPort != 10128 {
		t.Fatalf("mining evidence top port = %d, want 10128", feature.Mining.TopPort)
	}
}

func TestMiningAlertEvidenceReportsMiningEndpoint(t *testing.T) {
	remote := IPStrToKey("198.51.100.44")
	feature := BehaviorFeature{
		Direction:        "outbound",
		Flows:            100,
		TopDstPort:       443,
		MaxSingleDstPort: 99,
		Mining: miningDetectionEvidence{
			Valid:      true,
			Confidence: miningPortConfidenceHigh,
			miningTierSummary: miningTierSummary{
				Flows:            1,
				RepliedFlows:     1,
				UniqueRemotes:    1,
				UniquePorts:      1,
				TopPort:          10128,
				TopPortFlows:     1,
				TopPortReplied:   1,
				TopRemote:        remote,
				TopRemoteFlows:   1,
				TopRemoteReplied: 1,
			},
		},
	}
	cm := &ConntrackManager{}
	ev := cm.buildBehaviorAlertEvidence(feature, IPStrToKey("203.0.113.99"), true, "outbound_stratum_mining_suspected")
	if ev.TopDstPort != 10128 || ev.TopDstPortName != "moneroocean_randomx_stratum" {
		t.Fatalf("mining alert port evidence = %d/%q", ev.TopDstPort, ev.TopDstPortName)
	}
	if ev.TopRemoteIP != "198.51.100.44" || ev.TopPortShare != 1 || ev.TopRemoteShare != 1 {
		t.Fatalf("mining alert remote/share evidence = %+v", ev)
	}
}

func TestSharedMiningPortsRequireStrongerEvidence(t *testing.T) {
	feature := BehaviorFeature{
		Direction: "outbound",
		MiningShared: miningTierSummary{
			Flows:          2,
			RepliedFlows:   2,
			UniqueRemotes:  1,
			UniquePorts:    1,
			TopPort:        5555,
			TopPortFlows:   2,
			TopPortReplied: 2,
		},
	}
	if got := selectMiningDetectionEvidence(feature, newBehaviorScaler(1)); !got.Valid || got.Confidence != miningPortConfidenceSharedPersistent {
		t.Fatalf("two shared-port flows = %+v, want a persistent shared-port candidate", got)
	}

	feature.MiningShared.Flows = 3
	feature.MiningShared.TopPortFlows = 3
	evidence := selectMiningDetectionEvidence(feature, newBehaviorScaler(1))
	if !evidence.Valid || evidence.Confidence != miningPortConfidenceShared {
		t.Fatalf("shared-port evidence = %+v, want a valid shared candidate", evidence)
	}

	feature.Mining = evidence
	if got := behaviorPersistenceRequired(feature, "outbound_stratum_mining_suspected", "P1"); got != 3 {
		t.Fatalf("shared-port persistence = %d, want 3", got)
	}
}

func TestSingleSharedPortFlowBecomesPersistentCandidate(t *testing.T) {
	feature := BehaviorFeature{
		Direction: "outbound",
		MiningShared: miningTierSummary{
			Flows:          1,
			RepliedFlows:   1,
			UniqueRemotes:  1,
			UniquePorts:    1,
			TopPort:        7777,
			TopPortFlows:   1,
			TopPortReplied: 1,
			TopRemote:      IPStrToKey("198.51.100.77"),
		},
	}

	evidence := selectMiningDetectionEvidence(feature, newBehaviorScaler(1))
	if !evidence.Valid || evidence.Confidence != miningPortConfidenceSharedPersistent {
		t.Fatalf("single replied shared-port flow = %+v, want a persistent candidate", evidence)
	}
	feature.Mining = evidence
	if got := behaviorPersistenceRequired(feature, miningBehaviorKind, "P1"); got != 6 {
		t.Fatalf("single shared-port persistence = %d, want 6 cycles", got)
	}
}

func TestSharedMiningPortsRequireReplyEvidenceAndConcentration(t *testing.T) {
	base := BehaviorFeature{
		Direction: "outbound",
		MiningShared: miningTierSummary{
			Flows:          4,
			RepliedFlows:   1,
			UniqueRemotes:  1,
			UniquePorts:    1,
			TopPort:        7777,
			TopPortFlows:   4,
			TopPortReplied: 1,
		},
	}
	if got := selectMiningDetectionEvidence(base, newBehaviorScaler(1)); !got.Valid || got.Confidence != miningPortConfidenceSharedPersistent {
		t.Fatalf("one replied shared-port flow = %+v, want a persistent candidate", got)
	}

	base.MiningShared.RepliedFlows = 2
	base.MiningShared.UniquePorts = 3
	base.MiningShared.TopPortFlows = 1
	base.MiningShared.TopPortReplied = 1
	if got := selectMiningDetectionEvidence(base, newBehaviorScaler(1)); got.Valid {
		t.Fatalf("unconcentrated shared-port traffic unexpectedly classified: %+v", got)
	}
}

func TestMiningRemoteMapSaturationCannotPassRemoteLimit(t *testing.T) {
	remote := IPStrToKey("198.51.100.50")
	s := newBehaviorStats(false)
	s.updateOutboundMining(remote, 10128, 6, IPS_ASSURED, true)
	s.miningRemoteMapCapped = true
	high, _ := s.summarizeMining(nil)
	feature := BehaviorFeature{Direction: "outbound", MiningHigh: high}
	if got := selectMiningDetectionEvidence(feature, newBehaviorScaler(1)); got.Valid {
		t.Fatalf("saturated mining remote evidence unexpectedly classified: %+v", got)
	}
}

func TestMiningSummarySelectsOneRealRemotePortPair(t *testing.T) {
	remoteA := IPStrToKey("198.51.100.60")
	remoteB := IPStrToKey("198.51.100.61")
	stats := newBehaviorStats(false)
	for i := 0; i < 4; i++ {
		stats.updateOutboundMining(remoteA, 7777, 6, IPS_SEEN_REPLY, true)
	}
	for _, port := range []uint16{5555, 6666} {
		for i := 0; i < 3; i++ {
			stats.updateOutboundMining(remoteB, port, 6, IPS_SEEN_REPLY, true)
		}
	}

	_, shared := stats.summarizeMining(nil)
	if shared.TopRemote != remoteA || shared.TopPort != 7777 {
		t.Fatalf("selected mining endpoint=%s:%d, want %s:7777; summary=%+v",
			IPKeyToString(shared.TopRemote), shared.TopPort, IPKeyToString(remoteA), shared)
	}
}

func TestMiningCatalogIsNamedWithoutOverwritingExistingServiceNames(t *testing.T) {
	ports := builtinBehaviorOutboundMonitoredPorts()
	if ports[10128] == "" {
		t.Fatal("dedicated mining port was not added to the monitored-port map")
	}
	if got := ports[5900]; got != "vnc" {
		t.Fatalf("existing service name for shared port 5900 = %q, want vnc", got)
	}
	if got := ports[8333]; got != "bitcoin_p2p" {
		t.Fatalf("Bitcoin P2P label = %q, want bitcoin_p2p", got)
	}
}

func TestConntrackAggregationExcludesVMToVMMiningPortTraffic(t *testing.T) {
	src := IPStrToKey("10.0.0.10")
	dstVM := IPStrToKey("10.0.0.20")
	dstPublic := IPStrToKey("198.51.100.30")
	cm := &ConntrackManager{outboundBehaviorEnabled: true}
	agg, consume := cm.newConntrackAggregator([]VMIPIdentity{
		{InstanceUUID: "vm-src", IP: src},
		{InstanceUUID: "vm-dst", IP: dstVM},
	}, nil)

	consume(ConntrackFlowLite{
		SrcIP: src, DstIP: dstVM, SrcPort: 40000, DstPort: 10128,
		Proto: 6, Status: IPS_SEEN_REPLY,
	})
	consume(ConntrackFlowLite{
		SrcIP: src, DstIP: dstPublic, SrcPort: 40001, DstPort: 10128,
		Proto: 6, Status: IPS_SEEN_REPLY,
	})

	idx := agg.VMIndex[VMIPIdentity{InstanceUUID: "vm-src", IP: src}]
	high, _ := agg.OutboundStats[idx].summarizeMining(nil)
	if high.Flows != 1 || high.RepliedFlows != 1 {
		t.Fatalf("external mining summary = %+v, want only the public non-VM flow", high)
	}
}

func TestMiningCatalogHasSubstantialCoverage(t *testing.T) {
	if got := len(builtinMiningPortCatalog); got < 100 {
		t.Fatalf("built-in mining catalog contains %d ports, want at least 100", got)
	}
}
