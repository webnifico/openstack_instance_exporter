package main

type miningPortConfidence uint8

const (
	miningPortConfidenceNone miningPortConfidence = iota
	miningPortConfidenceHigh
	// HighPersistent is one stable replied connection on a dedicated mining
	// endpoint. It is strong port evidence, but not enough by itself for a
	// warning-level alert.
	miningPortConfidenceHighPersistent
	miningPortConfidenceShared
	// SharedPersistent is a low-confidence candidate produced by one or two
	// stable replied connections on an ambiguous/shared port. It is exported
	// only after a longer persistence gate and must be corroborated by the
	// Prometheus alert before it pages.
	miningPortConfidenceSharedPersistent
)

func (c miningPortConfidence) String() string {
	switch c {
	case miningPortConfidenceHigh:
		return "high"
	case miningPortConfidenceHighPersistent:
		return "high_persistent"
	case miningPortConfidenceShared:
		return "shared"
	case miningPortConfidenceSharedPersistent:
		return "shared_persistent"
	default:
		return "none"
	}
}

type miningPortDetails struct {
	Port       uint16
	Name       string
	Confidence miningPortConfidence
}

// These ports are current public Stratum/pool endpoints or long-established
// mining endpoints. High-confidence ports are uncommon outside mining.
// Shared ports overlap other software and therefore use stronger flow and
// persistence gates. Generic web/service ports (80, 443, 8080, 9200), coin
// peer ports (8333, 18080), and Monero daemon RPC (18081) are deliberately not
// classified by port alone.
var builtinMiningPortCatalog = buildBuiltinMiningPortCatalog()

func buildBuiltinMiningPortCatalog() map[uint16]miningPortDetails {
	high := []miningPortDetails{
		{1010, "etc_or_zcash_stratum", miningPortConfidenceHigh},
		{1228, "bitcoin_cash_stratum", miningPortConfidenceHigh},
		{1300, "bitcoin_stratum_tls", miningPortConfidenceHigh},
		{1301, "bitcoin_stratum_tls_backup", miningPortConfidenceHigh},
		{1314, "bitcoin_stratum", miningPortConfidenceHigh},
		{1315, "bitcoin_stratum_backup", miningPortConfidenceHigh},
		{1430, "kaspa_stratum", miningPortConfidenceHigh},
		{3335, "litecoin_stratum", miningPortConfidenceHigh},
		{3357, "zcash_stratum", miningPortConfidenceHigh},
		{3400, "nexa_stratum", miningPortConfidenceHigh},
		{4141, "bitcoin_gold_nicehash", miningPortConfidenceHigh},
		{4300, "nervos_stratum", miningPortConfidenceHigh},
		{4420, "aleo_stratum_tls", miningPortConfidenceHigh},
		{4430, "aleo_stratum", miningPortConfidenceHigh},
		{5151, "etc_or_nexa_solo_nicehash", miningPortConfidenceHigh},
		{5200, "litecoin_stratum_backup", miningPortConfidenceHigh},
		{5201, "litecoin_stratum_tls", miningPortConfidenceHigh},
		{5202, "litecoin_stratum_tls_backup", miningPortConfidenceHigh},
		{5400, "kadena_stratum", miningPortConfidenceHigh},
		{5588, "dash_stratum", miningPortConfidenceHigh},
		{5630, "alephium_stratum", miningPortConfidenceHigh},
		{6161, "kawpow_or_ethw_nicehash", miningPortConfidenceHigh},
		{6688, "ethw_stratum", miningPortConfidenceHigh},
		{6689, "ethw_stratum_backup", miningPortConfidenceHigh},
		{6698, "ethw_stratum_tls", miningPortConfidenceHigh},
		{6699, "ethw_stratum_tls_backup", miningPortConfidenceHigh},
		{6800, "conflux_stratum", miningPortConfidenceHigh},
		{6820, "conflux_stratum_tls", miningPortConfidenceHigh},
		{7171, "nexa_or_kawpow_solo_nicehash", miningPortConfidenceHigh},
		{7788, "siacoin_stratum", miningPortConfidenceHigh},
		{9898, "ergo_solo_stratum", miningPortConfidenceHigh},

		// MoneroOcean difficulty endpoints and explicitly documented TLS endpoints.
		{10001, "moneroocean_randomx_stratum", miningPortConfidenceHigh},
		{10002, "moneroocean_randomx_stratum", miningPortConfidenceHigh},
		{10004, "moneroocean_randomx_stratum", miningPortConfidenceHigh},
		{10008, "moneroocean_randomx_stratum", miningPortConfidenceHigh},
		{10016, "moneroocean_randomx_stratum", miningPortConfidenceHigh},
		{10032, "moneroocean_randomx_stratum", miningPortConfidenceHigh},
		{10064, "moneroocean_randomx_stratum", miningPortConfidenceHigh},
		{10128, "moneroocean_randomx_stratum", miningPortConfidenceHigh},
		{10512, "moneroocean_randomx_stratum", miningPortConfidenceHigh},
		{11010, "etc_or_zcash_stratum_tls", miningPortConfidenceHigh},
		{11024, "moneroocean_randomx_stratum", miningPortConfidenceHigh},
		{11111, "zcash_stratum_tls", miningPortConfidenceHigh},
		{11818, "pearl_stratum_tls", miningPortConfidenceHigh},
		{11919, "pearl_solo_stratum_tls", miningPortConfidenceHigh},
		{12020, "ethw_stratum_tls", miningPortConfidenceHigh},
		{12048, "moneroocean_randomx_stratum", miningPortConfidenceHigh},
		{12222, "zephyr_stratum_tls", miningPortConfidenceHigh},
		{13030, "grin_stratum_tls", miningPortConfidenceHigh},
		{13333, "zephyr_stratum_tls", miningPortConfidenceHigh},
		{14040, "bitcoin_gold_or_grin_stratum_tls", miningPortConfidenceHigh},
		{14096, "moneroocean_randomx_stratum", miningPortConfidenceHigh},
		{14141, "bitcoin_gold_nicehash_tls", miningPortConfidenceHigh},
		{14242, "aeternity_stratum_tls", miningPortConfidenceHigh},
		{14343, "aeternity_solo_stratum_tls", miningPortConfidenceHigh},
		{14433, "monero_stratum", miningPortConfidenceHigh},
		{14444, "randomx_or_zephyr_stratum_tls", miningPortConfidenceHigh},
		{14455, "monero_stratum", miningPortConfidenceHigh},
		{14545, "quai_kawpow_stratum_tls", miningPortConfidenceHigh},
		{14646, "quai_kawpow_stratum_tls_high_diff", miningPortConfidenceHigh},
		{14848, "quai_kawpow_solo_stratum_tls", miningPortConfidenceHigh},
		{14949, "quai_kawpow_solo_stratum_tls_high_diff", miningPortConfidenceHigh},
		{15050, "etc_or_nexa_solo_stratum_tls", miningPortConfidenceHigh},
		{15151, "etc_or_nexa_solo_nicehash_tls", miningPortConfidenceHigh},
		{15555, "zephyr_solo_stratum_tls", miningPortConfidenceHigh},
		{16060, "kawpow_or_ethw_solo_stratum_tls", miningPortConfidenceHigh},
		{16161, "kawpow_or_ethw_solo_nicehash_tls", miningPortConfidenceHigh},
		{16464, "nervos_stratum_tls", miningPortConfidenceHigh},
		{16565, "nervos_stratum_tls_high_diff", miningPortConfidenceHigh},
		{16767, "nervos_solo_stratum_tls", miningPortConfidenceHigh},
		{16868, "nervos_solo_stratum_tls_high_diff", miningPortConfidenceHigh},
		{17070, "nexa_or_kawpow_solo_stratum_tls", miningPortConfidenceHigh},
		{17171, "nexa_or_kawpow_solo_nicehash_tls", miningPortConfidenceHigh},
		{17575, "mimblewimblecoin_stratum_tls", miningPortConfidenceHigh},
		{18192, "moneroocean_randomx_stratum", miningPortConfidenceHigh},
		{18585, "mimblewimblecoin_solo_stratum_tls", miningPortConfidenceHigh},
		{18888, "ergo_stratum_tls", miningPortConfidenceHigh},
		{19898, "ergo_solo_stratum_tls", miningPortConfidenceHigh},
		{19999, "ergo_solo_nicehash_tls", miningPortConfidenceHigh},
		{20001, "moneroocean_randomx_stratum_tls", miningPortConfidenceHigh},
		{20128, "moneroocean_randomx_stratum_tls", miningPortConfidenceHigh},
		{24040, "bitcoin_gold_solo_stratum", miningPortConfidenceHigh},
		{24141, "bitcoin_gold_solo_nicehash", miningPortConfidenceHigh},
		{34040, "bitcoin_gold_solo_stratum_tls", miningPortConfidenceHigh},
		{34141, "bitcoin_gold_solo_nicehash_tls", miningPortConfidenceHigh},
	}

	shared := []miningPortDetails{
		{1111, "shared_stratum", miningPortConfidenceShared},
		{1818, "shared_pearl_stratum", miningPortConfidenceShared},
		{1919, "shared_pearl_solo_stratum", miningPortConfidenceShared},
		{2020, "shared_ethash_or_kaspa_stratum", miningPortConfidenceShared},
		{2121, "shared_kaspa_stratum", miningPortConfidenceShared},
		{2222, "shared_randomx_or_kaspa_stratum", miningPortConfidenceShared},
		{2323, "shared_bitcoin_or_kaspa_stratum", miningPortConfidenceShared},
		{3030, "shared_solo_stratum", miningPortConfidenceShared},
		{3333, "common_stratum", miningPortConfidenceShared},
		{3434, "shared_solo_stratum", miningPortConfidenceShared},
		{3535, "shared_solo_stratum", miningPortConfidenceShared},
		{4040, "shared_mining_pool_or_service", miningPortConfidenceShared},
		{4242, "shared_aeternity_or_timeseries_service", miningPortConfidenceShared},
		{4343, "shared_aeternity_solo_or_service", miningPortConfidenceShared},
		{4444, "common_randomx_stratum", miningPortConfidenceShared},
		{4545, "shared_quai_kawpow_or_service", miningPortConfidenceShared},
		{4646, "shared_quai_kawpow_or_nomad", miningPortConfidenceShared},
		{4848, "shared_quai_kawpow_solo_or_service", miningPortConfidenceShared},
		{4949, "shared_quai_kawpow_solo_or_service", miningPortConfidenceShared},
		{5050, "shared_etc_or_nexa_solo_stratum", miningPortConfidenceShared},
		{5252, "shared_beam_or_service", miningPortConfidenceShared},
		{5353, "shared_beam_or_mdns_port", miningPortConfidenceShared},
		{5454, "shared_beam_solo_or_service", miningPortConfidenceShared},
		{5555, "common_randomx_or_solo_stratum", miningPortConfidenceShared},
		{5600, "shared_alephium_or_service", miningPortConfidenceShared},
		{5656, "shared_beam_solo_or_service", miningPortConfidenceShared},
		{5900, "shared_mining_pool_or_vnc", miningPortConfidenceShared},
		{6060, "shared_kawpow_or_debug_service", miningPortConfidenceShared},
		{6464, "shared_nervos_or_service", miningPortConfidenceShared},
		{6565, "shared_nervos_or_service", miningPortConfidenceShared},
		{6666, "common_stratum_alt", miningPortConfidenceShared},
		{6767, "shared_nervos_solo_or_service", miningPortConfidenceShared},
		{6868, "shared_nervos_solo_or_service", miningPortConfidenceShared},
		{7070, "shared_nexa_or_web_service", miningPortConfidenceShared},
		{7373, "shared_bitcoin_cash_or_service", miningPortConfidenceShared},
		{7575, "shared_mimblewimblecoin_or_service", miningPortConfidenceShared},
		{7777, "common_randomx_stratum", miningPortConfidenceShared},
		{8008, "shared_mining_pool_or_http_alt", miningPortConfidenceShared},
		{8118, "shared_mining_pool_or_proxy", miningPortConfidenceShared},
		{8180, "shared_mining_pool_or_http_alt", miningPortConfidenceShared},
		{8181, "shared_mining_pool_or_http_alt", miningPortConfidenceShared},
		{8282, "shared_quai_sha256_or_service", miningPortConfidenceShared},
		{8383, "shared_quai_sha256_solo_or_service", miningPortConfidenceShared},
		{8484, "shared_quai_sha256_solo_or_service", miningPortConfidenceShared},
		{8585, "shared_mimblewimblecoin_solo_or_service", miningPortConfidenceShared},
		{8686, "shared_quai_sha256_solo_or_service", miningPortConfidenceShared},
		{8888, "shared_randomx_or_web_service", miningPortConfidenceShared},
		{9000, "shared_randomx_tls_or_service", miningPortConfidenceShared},
		{9393, "shared_bitcoin_cash_solo_or_service", miningPortConfidenceShared},
		{9999, "shared_randomx_or_ergo_stratum", miningPortConfidenceShared},
		{10256, "shared_moneroocean_or_kubernetes_health", miningPortConfidenceShared},
	}

	out := make(map[uint16]miningPortDetails, len(high)+len(shared))
	for _, info := range append(high, shared...) {
		if _, exists := out[info.Port]; exists {
			panic("duplicate built-in mining port")
		}
		out[info.Port] = info
	}
	return out
}

func builtinMiningPortInfo(port uint16) (miningPortDetails, bool) {
	info, ok := builtinMiningPortCatalog[port]
	return info, ok
}

func builtinMiningPortName(port uint16) string {
	info, ok := builtinMiningPortInfo(port)
	if !ok {
		return ""
	}
	return info.Name
}

type miningPortFlowCount struct {
	Flows   int
	Replied int
}

type miningRemoteFlowStats struct {
	ByPort map[uint16]miningPortFlowCount
}

type miningTierSummary struct {
	Flows                     int
	RepliedFlows              int
	UniqueRemotes             int
	UniquePorts               int
	TopPort                   uint16
	TopPortFlows              int
	TopPortReplied            int
	TopRemote                 IPKey
	TopRemoteFlows            int
	TopRemoteReplied          int
	RemoteEvidenceApproximate bool
}

type miningDetectionEvidence struct {
	Valid      bool
	Confidence miningPortConfidence
	miningTierSummary
}

type miningTierAccumulator struct {
	byPort   map[uint16]miningPortFlowCount
	byRemote map[IPKey]miningPortFlowCount
	byPair   map[behaviorRemotePortKey]miningPortFlowCount
}

const maxMiningRemoteMapSize = 4096

func (b *behaviorStats) updateOutboundMining(remote IPKey, port uint16, proto uint8, status uint32, externalDestination bool) {
	if b == nil || !externalDestination || proto != 6 || port == 0 {
		return
	}
	if _, ok := builtinMiningPortInfo(port); !ok {
		return
	}
	if classifyBehaviorDestination(remote, nil) != behaviorDestinationPublic {
		return
	}
	remoteStats, ok := b.miningRemotes[remote]
	if !ok {
		if len(b.miningRemotes) >= maxMiningRemoteMapSize {
			b.miningRemoteMapCapped = true
			return
		}
		remoteStats = &miningRemoteFlowStats{ByPort: make(map[uint16]miningPortFlowCount)}
		b.miningRemotes[remote] = remoteStats
	}
	count := remoteStats.ByPort[port]
	count.Flows++
	if (status&IPS_SEEN_REPLY) != 0 || (status&IPS_ASSURED) != 0 {
		count.Replied++
	}
	remoteStats.ByPort[port] = count
}

func (b *behaviorStats) summarizeMining(hostIPKeys map[IPKey]struct{}) (miningTierSummary, miningTierSummary) {
	high := newMiningTierAccumulator()
	shared := newMiningTierAccumulator()
	if b == nil {
		return high.finalize(false), shared.finalize(false)
	}

	for remote, remoteStats := range b.miningRemotes {
		if classifyBehaviorDestination(remote, hostIPKeys) != behaviorDestinationPublic || remoteStats == nil {
			continue
		}
		for port, count := range remoteStats.ByPort {
			info, ok := builtinMiningPortInfo(port)
			if !ok || count.Flows <= 0 {
				continue
			}
			switch info.Confidence {
			case miningPortConfidenceHigh:
				high.add(remote, port, count)
			case miningPortConfidenceShared:
				shared.add(remote, port, count)
			}
		}
	}

	return high.finalize(b.miningRemoteMapCapped), shared.finalize(b.miningRemoteMapCapped)
}

func newMiningTierAccumulator() miningTierAccumulator {
	return miningTierAccumulator{
		byPort:   make(map[uint16]miningPortFlowCount),
		byRemote: make(map[IPKey]miningPortFlowCount),
		byPair:   make(map[behaviorRemotePortKey]miningPortFlowCount),
	}
}

func (a *miningTierAccumulator) add(remote IPKey, port uint16, count miningPortFlowCount) {
	portCount := a.byPort[port]
	portCount.Flows += count.Flows
	portCount.Replied += count.Replied
	a.byPort[port] = portCount

	remoteCount := a.byRemote[remote]
	remoteCount.Flows += count.Flows
	remoteCount.Replied += count.Replied
	a.byRemote[remote] = remoteCount

	pair := behaviorRemotePortKey{Remote: remote, Port: port}
	pairCount := a.byPair[pair]
	pairCount.Flows += count.Flows
	pairCount.Replied += count.Replied
	a.byPair[pair] = pairCount
}

func (a miningTierAccumulator) finalize(approximate bool) miningTierSummary {
	out := miningTierSummary{
		UniquePorts:               len(a.byPort),
		UniqueRemotes:             len(a.byRemote),
		RemoteEvidenceApproximate: approximate,
	}
	for _, count := range a.byPort {
		out.Flows += count.Flows
		out.RepliedFlows += count.Replied
	}
	var topPair behaviorRemotePortKey
	topPairCount := miningPortFlowCount{}
	for pair, count := range a.byPair {
		if count.Replied <= 0 {
			continue
		}
		if topPair == (behaviorRemotePortKey{}) || count.Flows > topPairCount.Flows ||
			(count.Flows == topPairCount.Flows && count.Replied > topPairCount.Replied) ||
			(count.Flows == topPairCount.Flows && count.Replied == topPairCount.Replied && pair.Port < topPair.Port) ||
			(count.Flows == topPairCount.Flows && count.Replied == topPairCount.Replied && pair.Port == topPair.Port && compareIPKey(pair.Remote, topPair.Remote) < 0) {
			topPair = pair
			topPairCount = count
		}
	}
	if topPair != (behaviorRemotePortKey{}) {
		out.TopPort = topPair.Port
		out.TopRemote = topPair.Remote
		out.TopPortFlows = a.byPort[topPair.Port].Flows
		out.TopPortReplied = a.byPort[topPair.Port].Replied
		out.TopRemoteFlows = a.byRemote[topPair.Remote].Flows
		out.TopRemoteReplied = a.byRemote[topPair.Remote].Replied
	}
	return out
}

func selectMiningDetectionEvidence(feature BehaviorFeature, sc behaviorScaler) miningDetectionEvidence {
	if feature.Direction != "outbound" {
		return miningDetectionEvidence{}
	}
	maxRemotes := sc.scaleIntLow(defaultRuleThresholds.StratumMaxRemotes)
	if maxRemotes < 1 {
		maxRemotes = 1
	}

	high := feature.MiningHigh
	if !high.RemoteEvidenceApproximate && high.RepliedFlows >= 1 && high.UniqueRemotes >= 1 &&
		high.UniqueRemotes <= maxRemotes && high.TopPort != 0 && high.TopPortReplied >= 1 {
		confidence := miningPortConfidenceHighPersistent
		if high.Flows >= 2 && high.RepliedFlows >= 2 && high.TopPortFlows >= 2 && high.TopPortReplied >= 2 {
			confidence = miningPortConfidenceHigh
		}
		return miningDetectionEvidence{Valid: true, Confidence: confidence, miningTierSummary: high}
	}

	shared := feature.MiningShared
	minSharedFlows := maxInt(3, sc.scaleIntHigh(3))
	minSharedReplied := 2
	portShare := 0.0
	if shared.Flows > 0 {
		portShare = float64(shared.TopPortFlows) / float64(shared.Flows)
	}
	if !shared.RemoteEvidenceApproximate && shared.Flows >= minSharedFlows && shared.RepliedFlows >= minSharedReplied &&
		shared.UniqueRemotes >= 1 && shared.UniqueRemotes <= maxRemotes && shared.TopPort != 0 &&
		shared.TopPortFlows >= 2 && shared.TopPortReplied >= 1 && portShare >= sc.threshHigh(0.50) {
		return miningDetectionEvidence{Valid: true, Confidence: miningPortConfidenceShared, miningTierSummary: shared}
	}
	// Stratum normally uses one long-lived TCP connection. Keep such a flow
	// observable without treating an ambiguous port match as a confirmed alert.
	// Requiring reply evidence, port concentration, a bounded destination set,
	// and a longer state-machine gate avoids returning to port-only paging.
	if !shared.RemoteEvidenceApproximate && shared.RepliedFlows >= 1 &&
		shared.UniqueRemotes >= 1 && shared.UniqueRemotes <= maxRemotes && shared.TopPort != 0 &&
		shared.TopPortReplied >= 1 && portShare >= sc.threshHigh(0.50) {
		return miningDetectionEvidence{Valid: true, Confidence: miningPortConfidenceSharedPersistent, miningTierSummary: shared}
	}

	return miningDetectionEvidence{}
}

func behaviorPersistenceRequired(feature BehaviorFeature, kind, priority string) int {
	required := 3
	if priorityRank(priority) >= priorityRank("P2") {
		required = 2
	}
	if kind != "outbound_stratum_mining_suspected" || !feature.Mining.Valid {
		return required
	}
	if feature.Mining.Confidence == miningPortConfidenceSharedPersistent {
		return 6
	}
	if feature.Mining.Confidence == miningPortConfidenceShared || feature.Mining.Flows < 2 || feature.Mining.RepliedFlows < 2 {
		return 3
	}
	return required
}
