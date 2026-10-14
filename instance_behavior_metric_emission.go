package main

import (
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"math"
	"sort"
	"sync"
)

const maxBehaviorRuleLogStateEntries = 50000

var behaviorRuleLogMu sync.Mutex
var behaviorRuleLogStateMap = map[behaviorEmitKey]*behaviorRuleLogState{}

type behaviorRuleLogEvictionCandidate struct {
	key          behaviorEmitKey
	lastActivity int64
}

func behaviorRuleLogLastActivity(state *behaviorRuleLogState) int64 {
	if state == nil {
		return 0
	}
	return state.LastSuppressedUnix
}

func behaviorEmitKeyLess(left, right behaviorEmitKey) bool {
	if left.InstanceUUID != right.InstanceUUID {
		return left.InstanceUUID < right.InstanceUUID
	}
	if compared := compareIPKey(left.IP, right.IP); compared != 0 {
		return compared < 0
	}
	return left.Direction < right.Direction
}

func evictBehaviorRuleLogStateLocked(maxEntries int) int {
	if maxEntries < 0 {
		maxEntries = 0
	}
	if len(behaviorRuleLogStateMap) <= maxEntries {
		return 0
	}

	candidates := make([]behaviorRuleLogEvictionCandidate, 0, len(behaviorRuleLogStateMap))
	for key, state := range behaviorRuleLogStateMap {
		candidates = append(candidates, behaviorRuleLogEvictionCandidate{
			key:          key,
			lastActivity: behaviorRuleLogLastActivity(state),
		})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].lastActivity != candidates[j].lastActivity {
			return candidates[i].lastActivity < candidates[j].lastActivity
		}
		return behaviorEmitKeyLess(candidates[i].key, candidates[j].key)
	})

	removeCount := len(behaviorRuleLogStateMap) - maxEntries
	for index := 0; index < removeCount; index++ {
		delete(behaviorRuleLogStateMap, candidates[index].key)
	}
	return removeCount
}

func ensureRuleLogStateLocked(k behaviorEmitKey) *behaviorRuleLogState {
	s, ok := behaviorRuleLogStateMap[k]
	if ok {
		return s
	}
	if len(behaviorRuleLogStateMap) >= maxBehaviorRuleLogStateEntries {
		lowWatermark := maxBehaviorRuleLogStateEntries - maxBehaviorRuleLogStateEntries/10
		removed := evictBehaviorRuleLogStateLocked(lowWatermark)
		logKV(LogLevelNotice, "behavior", "behavior", "behavior_rule_log_state_evict",
			"max", maxBehaviorRuleLogStateEntries,
			"removed", removed,
			"size", len(behaviorRuleLogStateMap),
		)
	}
	s = &behaviorRuleLogState{}
	behaviorRuleLogStateMap[k] = s
	return s
}

func clearBehaviorRuleLogStateForInstance(instanceUUID string) int {
	if instanceUUID == "" {
		return 0
	}
	behaviorRuleLogMu.Lock()
	defer behaviorRuleLogMu.Unlock()
	removed := 0
	for key := range behaviorRuleLogStateMap {
		if key.InstanceUUID == instanceUUID {
			delete(behaviorRuleLogStateMap, key)
			removed++
		}
	}
	return removed
}

func pruneBehaviorRuleLogStateToVMIPIdentities(allowed map[VMIPIdentity]struct{}, activeSet map[string]struct{}) int {
	behaviorRuleLogMu.Lock()
	defer behaviorRuleLogMu.Unlock()
	removed := 0
	for key := range behaviorRuleLogStateMap {
		if _, active := activeSet[key.InstanceUUID]; !active {
			delete(behaviorRuleLogStateMap, key)
			removed++
			continue
		}
		identity := VMIPIdentity{InstanceUUID: key.InstanceUUID, IP: key.IP}
		if _, retained := allowed[identity]; !retained {
			delete(behaviorRuleLogStateMap, key)
			removed++
		}
	}
	return removed
}

func shiftBehaviorRuleLogTimestamp(timestamp *int64, delta int64) {
	if timestamp != nil && *timestamp > 0 {
		*timestamp += delta
	}
}

func shiftBehaviorRuleLogStateLocked(matches func(behaviorEmitKey) bool, delta int64) int {
	if delta <= 0 {
		return 0
	}
	shifted := 0
	for key, state := range behaviorRuleLogStateMap {
		if state == nil || !matches(key) {
			continue
		}
		shiftBehaviorRuleLogTimestamp(&state.LastSuppressedUnix, delta)
		shifted++
	}
	return shifted
}

func shiftBehaviorRuleLogStateForInstance(instanceUUID string, delta int64) int {
	if instanceUUID == "" || delta <= 0 {
		return 0
	}
	behaviorRuleLogMu.Lock()
	defer behaviorRuleLogMu.Unlock()
	return shiftBehaviorRuleLogStateLocked(func(key behaviorEmitKey) bool {
		return key.InstanceUUID == instanceUUID
	}, delta)
}

func shiftAllBehaviorRuleLogState(delta int64) int {
	if delta <= 0 {
		return 0
	}
	behaviorRuleLogMu.Lock()
	defer behaviorRuleLogMu.Unlock()
	return shiftBehaviorRuleLogStateLocked(func(behaviorEmitKey) bool { return true }, delta)
}

func ruleLogStateMarkSuppressed(k behaviorEmitKey, nowUnix int64) bool {
	behaviorRuleLogMu.Lock()
	defer behaviorRuleLogMu.Unlock()
	st := ensureRuleLogStateLocked(k)
	if st.LastSuppressedUnix != 0 && nowUnix >= st.LastSuppressedUnix && (nowUnix-st.LastSuppressedUnix) < 60 {
		return false
	}
	st.LastSuppressedUnix = nowUnix
	return true
}

func behaviorHostImpactFlowTotal(ctx BehaviorContext, fallback int) int {
	if ctx.InstanceFlowTotal > 0 {
		return ctx.InstanceFlowTotal
	}
	return fallback
}

func (cm *ConntrackManager) behaviorIntervalSnapshot(ident behaviorIdentityKey) (behaviorIntervalSnapshot, bool) {
	idx := shardIndexBehavior(ident)
	cm.behaviorObservationMu[idx].Lock()
	state := cm.behaviorObservations[idx][ident]
	var snapshot behaviorIntervalSnapshot
	if state != nil {
		snapshot = state.LastInterval
	}
	cm.behaviorObservationMu[idx].Unlock()
	if !snapshot.Initialized {
		return behaviorIntervalSnapshot{}, false
	}
	return snapshot, true
}

func (cm *ConntrackManager) storeBehaviorIntervalSnapshot(ident behaviorIdentityKey, snapshot behaviorIntervalSnapshot) {
	idx := shardIndexBehavior(ident)
	cm.behaviorObservationMu[idx].Lock()
	if cm.behaviorObservations[idx] == nil {
		cm.behaviorObservations[idx] = make(map[behaviorIdentityKey]*behaviorObservationState)
	}
	state := cm.behaviorObservations[idx][ident]
	if state == nil {
		state = &behaviorObservationState{}
		cm.behaviorObservations[idx][ident] = state
	}
	snapshot.Initialized = true
	state.LastInterval = snapshot
	cm.behaviorObservationMu[idx].Unlock()
}

func (cm *ConntrackManager) analyzeBehavior(
	s *behaviorStats,
	addrKey IPKey,
	addr, family, domain, serverName, instanceUUID, projectUUID, projectName, userUUID string,
	dynamicMetrics *[]prometheus.Metric,
	descs metricDescGroup,
	ctx BehaviorContext,
) {
	analysisNowUnix := ctx.ObservationUnix
	if analysisNowUnix <= 0 {
		analysisNowUnix = cm.conntrackNow().Unix()
	}

	hostMax := ctx.HostConntrackMax
	hostImpactFlowTotal := behaviorHostImpactFlowTotal(ctx, s.flows)
	hostImpact := 0.0
	if hostMax > 0 {
		hostImpact = float64(hostImpactFlowTotal) / float64(hostMax)
	}

	var tFlows int
	if descs.thresholdConfigKey == "outbound" {
		tFlows = cm.behaviorThresholds.OutboundFlowsTotal
	} else {
		tFlows = cm.behaviorThresholds.InboundFlowsTotal
	}

	unrepliedRatio := 0.0
	if s.flows > 0 {
		unrepliedRatio = float64(s.unreplied) / float64(s.flows)
	}

	bytesPerFlow, packetsPerFlow, bytesAvailable, packetsAvailable := s.accountingAverages()
	acctEnabled := bytesAvailable || packetsAvailable

	rawUniqueRemotes := len(s.remotes)
	uniqueRemotes, uniqueRemotesSaturated := saturatingCount(rawUniqueRemotes, behaviorRemoteCountCeiling)
	newRemotes := 0
	newRemotesSaturated := false
	key := BehaviorKey{InstanceUUID: instanceUUID, IP: addrKey}
	dir := descs.thresholdConfigKey
	ident := behaviorIdentityKey{InstanceUUID: instanceUUID, IP: addrKey, Direction: dir}
	idx := shardIndexBehavior(ident)
	if !ctx.FreezeState && !ctx.Rebaseline {
		cm.behaviorObservationMu[idx].Lock()
		previous := cm.behaviorObservations[idx][ident]
		if previous != nil && previous.LastInterval.Initialized && previous.LastSeenUnix == analysisNowUnix {
			ctx.FreezeState = true
		}
		cm.behaviorObservationMu[idx].Unlock()
	}

	mu := &cm.inboundMu[idx]
	prevRemotesMap := cm.inboundPrev[idx]
	prevPortsMap := cm.inboundPrevDstPorts[idx]
	prevSeenMap := cm.inboundPrevLastSeen[idx]

	if dir == "outbound" {
		mu = &cm.outboundMu[idx]
		prevRemotesMap = cm.outboundPrev[idx]
		prevPortsMap = cm.outboundPrevDstPorts[idx]
		prevSeenMap = cm.outboundPrevLastSeen[idx]
	}

	localScanHits := 0
	infraHits := 0
	infraMaxFlows := 0
	tenantPrivateHits := 0
	tenantPrivateMaxFlows := 0
	tenantPrivateFlows := 0
	tenantPrivateUnreplied := 0
	publicRemotes := 0
	adminPortFlows := 0
	adminUnrepliedFlows := 0
	publicAdminPerRemote := make(map[IPKey]int)
	publicAdminRemotes := make(map[IPKey]struct{})
	for rk := range s.remotes {
		switch classifyBehaviorDestination(rk, ctx.HostIPKeys) {
		case behaviorDestinationPublic:
			publicRemotes++
			if descs.thresholdConfigKey == "inbound" {
				adminFlows := s.adminPerRemote[rk]
				adminPortFlows += adminFlows
				if adminFlows > 0 {
					publicAdminPerRemote[rk] = adminFlows
					publicAdminRemotes[rk] = struct{}{}
					adminUnrepliedFlows += s.adminPerRemoteUnreplied[rk]
				}
			}
		}
	}
	publicAdminPerPort := make(map[uint16]int)
	if descs.thresholdConfigKey == "inbound" && !s.remotePortMapCapped {
		for key, count := range s.perRemoteDstPort {
			if !isAdminExposurePort(key.Port) || classifyBehaviorDestination(key.Remote, ctx.HostIPKeys) != behaviorDestinationPublic {
				continue
			}
			publicAdminPerPort[key.Port] += count
		}
	}

	metadataFlows := 0
	metadataUnrepliedRatio := 0.0
	metadataTopDstPortFlows, metadataTopDstPort := topBehaviorPort(s.metadataPerDstPort)
	if descs.thresholdConfigKey == "outbound" {
		metadataFlows = s.metadataFlows
		if metadataFlows > 0 {
			metadataUnrepliedRatio = float64(s.metadataUnreplied) / float64(metadataFlows)
		}

		if s.flows > 10 {
			for rk := range s.remotes {
				switch classifyBehaviorDestination(rk, ctx.HostIPKeys) {
				case behaviorDestinationMetadata:
					// Metadata has dedicated rules and must not also become a
					// generic infrastructure probe.
					continue
				case behaviorDestinationHostControl:
					infraHits++
					if c := s.perRemote[rk]; c > infraMaxFlows {
						infraMaxFlows = c
					}
				case behaviorDestinationTenantPrivate:
					tenantPrivateHits++
					c := s.perRemote[rk]
					tenantPrivateFlows += c
					tenantPrivateUnreplied += s.perRemoteUnreplied[rk]
					if c > tenantPrivateMaxFlows {
						tenantPrivateMaxFlows = c
					}
				case behaviorDestinationLocalLink:
					localScanHits++
				}
			}
		}
	}
	tenantPrivateUnrepliedRatio := 0.0
	if tenantPrivateFlows > 0 {
		tenantPrivateUnrepliedRatio = float64(tenantPrivateUnreplied) / float64(tenantPrivateFlows)
	}

	uniqueDstPorts := len(s.dstPorts)
	newDstPorts := 0
	adminNewRemotes := 0

	mu.Lock()
	if !ctx.FreezeState {
		prevSeenMap[key] = analysisNowUnix
	}

	if prev, ok := prevRemotesMap[key]; ok {
		newRemotes, newRemotesSaturated = countNewIPKeys(s.remotes, prev.remotes, behaviorRemoteCountCeiling)
		adminNewRemotes, _ = countNewIPKeys(publicAdminRemotes, prev.remotes, behaviorRemoteCountCeiling)
	} else {
		newRemotes = uniqueRemotes
		newRemotesSaturated = uniqueRemotesSaturated
		adminNewRemotes = len(publicAdminRemotes)
	}
	if !ctx.FreezeState {
		prevRemotesMap[key] = outboundPrev{remotes: cloneIPKeySet(s.remotes)}
	}

	curPortSet := cloneUint16Set(s.dstPorts)
	if prev, ok := prevPortsMap[key]; ok {
		if len(curPortSet) > 0 {
			overlap := 0
			for p := range curPortSet {
				if _, exists := prev.ports[p]; exists {
					overlap++
				}
			}
			fracNew := 1.0 - (float64(overlap) / float64(len(curPortSet)))
			newDstPorts = int(math.Round(float64(uniqueDstPorts) * fracNew))
		}
	} else {
		newDstPorts = uniqueDstPorts
	}
	if !ctx.FreezeState {
		prevPortsMap[key] = outboundPrevDstPorts{ports: curPortSet}
	}
	mu.Unlock()
	if ctx.FreezeState {
		if retained, ok := cm.behaviorIntervalSnapshot(ident); ok {
			newRemotes = retained.NewRemotes
			newDstPorts = retained.NewDstPorts
			newRemotesSaturated = retained.NewRemotesSaturated
		}
	}
	if ctx.Rebaseline {
		newRemotes = 0
		newDstPorts = 0
		adminNewRemotes = 0
		newRemotesSaturated = false
	}

	maxSingleRemote, topRemoteKey, topRemoteSet := topBehaviorRemote(s.perRemote)
	maxSingleDstPort, topDstPort := topBehaviorPort(s.perDstPort)

	bgpFlows := s.bgpFlows
	bgpTopRemoteFlows, bgpTopRemote, _ := topBehaviorRemote(s.bgpPerRemote)
	geneveFlows := s.geneveFlows
	geneveTopRemoteFlows, geneveTopRemote, _ := topBehaviorRemote(s.genevePerRemote)
	smtpFlows := s.smtpFlows
	smtpTopRemoteFlows, smtpTopRemote, _ := topBehaviorRemote(s.smtpPerRemote)
	smtpTopDstPortFlows, smtpTopDstPort := topBehaviorPort(s.smtpPerDstPort)
	smtpUnrepliedRatio := 0.0
	if smtpFlows > 0 {
		smtpUnrepliedRatio = float64(s.smtpUnreplied) / float64(smtpFlows)
	}
	udpUnrepliedRatio := 0.0
	if s.udpCount > 0 {
		udpUnrepliedRatio = float64(s.udpUnreplied) / float64(s.udpCount)
	}
	udpTopRemoteFlows, udpTopRemote, _ := topBehaviorRemote(s.udpPerRemote)
	udpTopDstPortFlows, udpTopDstPort := topBehaviorPort(s.udpPerDstPort)
	tcpUnrepliedRatio := 0.0
	if s.tcpCount > 0 {
		tcpUnrepliedRatio = float64(s.tcpUnreplied) / float64(s.tcpCount)
	}
	tcpTopRemoteFlows, tcpTopRemote, _ := topBehaviorRemote(s.tcpPerRemote)
	tcpTopDstPortFlows, tcpTopDstPort := topBehaviorPort(s.tcpPerDstPort)
	dnsUnrepliedRatio := 0.0
	if s.dnsUDPFlows > 0 {
		dnsUnrepliedRatio = float64(s.dnsUDPUnreplied) / float64(s.dnsUDPFlows)
	}
	dnsBytesPerFlow := 0.0
	dnsBytesPerFlowAvailable := s.dnsByteCoveredFlows > 0
	if dnsBytesPerFlowAvailable {
		dnsBytesPerFlow = float64(s.dnsBytes) / float64(s.dnsByteCoveredFlows)
	}
	miningHigh, miningShared := s.summarizeMining(ctx.HostIPKeys)
	stratumFlows := miningHigh.Flows + miningShared.Flows
	stratumRepliedFlows := miningHigh.RepliedFlows + miningShared.RepliedFlows
	adminTopRemoteFlows, adminTopRemote, _ := topBehaviorRemote(publicAdminPerRemote)
	adminTopDstPortFlows, adminTopDstPort := topBehaviorPort(publicAdminPerPort)
	adminUnrepliedRatio := 0.0
	if adminPortFlows > 0 {
		adminUnrepliedRatio = float64(adminUnrepliedFlows) / float64(adminPortFlows)
	}
	// -------------------------------------------------------------------------
	// Feature 1: Dark-Space Port Detection (Unmonitored Ports)
	// -------------------------------------------------------------------------
	unmonitoredPortFlows := 0
	unmonitoredUnrepliedFlows := 0
	unmonitoredUniqueDstPorts := 0
	maxSingleUnmonitoredDstPort := 0
	topUnmonitoredDstPort := uint16(0)

	// Select the correct monitored port map based on traffic direction
	var monitoredPorts map[uint16]string
	if descs.thresholdConfigKey == "outbound" {
		monitoredPorts = cm.behaviorOutboundPortNames
	} else {
		monitoredPorts = cm.behaviorInboundPortNames
	}

	// Iterate over all destination ports seen in this traffic snapshot
	for port := range s.dstPorts {
		// If map is nil, all ports are technically "unmonitored" unless we assume default open.
		// However, typical config implies if map exists, only those are monitored.
		// If map is empty/nil, we skip this check to avoid noise.
		if len(monitoredPorts) > 0 {
			if _, ok := monitoredPorts[port]; !ok {
				unmonitoredUniqueDstPorts++
				count := s.perDstPort[port]
				unmonitoredPortFlows += count
				unmonitoredUnrepliedFlows += count - s.perDstPortReplied[port]
				if count > maxSingleUnmonitoredDstPort ||
					(count == maxSingleUnmonitoredDstPort && (topUnmonitoredDstPort == 0 || port < topUnmonitoredDstPort)) {
					maxSingleUnmonitoredDstPort = count
					topUnmonitoredDstPort = port
				}
			}
		}
	}
	unmonitoredUnrepliedRatio := 0.0
	if unmonitoredPortFlows > 0 {
		unmonitoredUnrepliedRatio = float64(unmonitoredUnrepliedFlows) / float64(unmonitoredPortFlows)
	}
	topUnmonitoredRemoteFlows, topUnmonitoredRemote, _ := topBehaviorRemoteForPort(s, topUnmonitoredDstPort)
	// -------------------------------------------------------------------------

	if dynamicMetrics != nil {
		if descs.uniqueRemotes != nil {
			*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(descs.uniqueRemotes, prometheus.GaugeValue, float64(uniqueRemotes), domain, serverName, instanceUUID, projectUUID, projectName, userUUID, addr, family))
		}
		if descs.newRemotes != nil {
			*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(descs.newRemotes, prometheus.GaugeValue, float64(newRemotes), domain, serverName, instanceUUID, projectUUID, projectName, userUUID, addr, family))
		}
		if descs.maxSingleRemote != nil && !s.remoteMapCapped {
			*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(descs.maxSingleRemote, prometheus.GaugeValue, float64(maxSingleRemote), domain, serverName, instanceUUID, projectUUID, projectName, userUUID, addr, family))
		}
		if descs.uniqueDstPorts != nil {
			*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(descs.uniqueDstPorts, prometheus.GaugeValue, float64(uniqueDstPorts), domain, serverName, instanceUUID, projectUUID, projectName, userUUID, addr, family))
		}
		if descs.newDstPorts != nil {
			*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(descs.newDstPorts, prometheus.GaugeValue, float64(newDstPorts), domain, serverName, instanceUUID, projectUUID, projectName, userUUID, addr, family))
		}
		if descs.maxSingleDstPort != nil {
			*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(descs.maxSingleDstPort, prometheus.GaugeValue, float64(maxSingleDstPort), domain, serverName, instanceUUID, projectUUID, projectName, userUUID, addr, family))
		}
		if descs.flows != nil {
			*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(descs.flows, prometheus.GaugeValue, float64(s.flows), domain, serverName, instanceUUID, projectUUID, projectName, userUUID, addr, family))
		}
		if bytesAvailable && descs.bytesPerFlow != nil {
			*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(descs.bytesPerFlow, prometheus.GaugeValue, bytesPerFlow, domain, serverName, instanceUUID, projectUUID, projectName, userUUID, addr, family))
		}
		if packetsAvailable && descs.packetsPerFlow != nil {
			*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(descs.packetsPerFlow, prometheus.GaugeValue, packetsPerFlow, domain, serverName, instanceUUID, projectUUID, projectName, userUUID, addr, family))
		}
	}

	feature := BehaviorFeature{
		Direction:                    descs.thresholdConfigKey,
		ThresholdFlows:               tFlows,
		LocalScanHits:                localScanHits,
		InfraHits:                    infraHits,
		InfraMaxFlows:                infraMaxFlows,
		TenantPrivateHits:            tenantPrivateHits,
		TenantPrivateMaxFlows:        tenantPrivateMaxFlows,
		TenantPrivateUnrepliedRatio:  tenantPrivateUnrepliedRatio,
		PublicRemotes:                publicRemotes,
		MetadataHits:                 metadataFlows,
		MetadataMaxFlows:             metadataFlows,
		MetadataUnrepliedRatio:       metadataUnrepliedRatio,
		MetadataTopDstPort:           metadataTopDstPort,
		MetadataTopDstPortFlows:      metadataTopDstPortFlows,
		BGPFlows:                     bgpFlows,
		BGPTopRemote:                 bgpTopRemote,
		BGPTopRemoteFlows:            bgpTopRemoteFlows,
		GeneveFlows:                  geneveFlows,
		GeneveTopRemote:              geneveTopRemote,
		GeneveTopRemoteFlows:         geneveTopRemoteFlows,
		SMTPFlows:                    smtpFlows,
		SMTPUniqueRemotes:            len(s.smtpRemotes),
		SMTPUnrepliedRatio:           smtpUnrepliedRatio,
		SMTPTopRemote:                smtpTopRemote,
		SMTPTopRemoteFlows:           smtpTopRemoteFlows,
		SMTPTopDstPort:               smtpTopDstPort,
		SMTPTopDstPortFlows:          smtpTopDstPortFlows,
		StratumFlows:                 stratumFlows,
		StratumRepliedFlows:          stratumRepliedFlows,
		MiningHigh:                   miningHigh,
		MiningShared:                 miningShared,
		AdminPortFlows:               adminPortFlows,
		AdminUniqueRemotes:           len(publicAdminRemotes),
		AdminNewRemotes:              adminNewRemotes,
		AdminUnrepliedRatio:          adminUnrepliedRatio,
		AdminTopRemote:               adminTopRemote,
		AdminTopRemoteFlows:          adminTopRemoteFlows,
		AdminTopDstPort:              adminTopDstPort,
		AdminTopDstPortFlows:         adminTopDstPortFlows,
		Flows:                        s.flows,
		UniqueRemotes:                uniqueRemotes,
		NewRemotes:                   newRemotes,
		UniqueDstPorts:               uniqueDstPorts,
		NewDstPorts:                  newDstPorts,
		MaxSingleRemote:              maxSingleRemote,
		MaxSingleDstPort:             maxSingleDstPort,
		TopDstPort:                   topDstPort,
		UnmonitoredPortFlows:         unmonitoredPortFlows,
		UnmonitoredUnrepliedRatio:    unmonitoredUnrepliedRatio,
		UnmonitoredUniqueDstPorts:    unmonitoredUniqueDstPorts,
		MaxSingleUnmonitoredDstPort:  maxSingleUnmonitoredDstPort,
		TopUnmonitoredDstPort:        topUnmonitoredDstPort,
		TopUnmonitoredRemote:         topUnmonitoredRemote,
		TopUnmonitoredRemoteFlows:    topUnmonitoredRemoteFlows,
		UnrepliedRatio:               unrepliedRatio,
		MulticastCount:               s.multicastCount,
		ICMPCount:                    s.icmpCount,
		UDPCount:                     s.udpCount,
		UDPUniqueRemotes:             len(s.udpRemotes),
		UDPUnrepliedRatio:            udpUnrepliedRatio,
		UDPTopRemote:                 udpTopRemote,
		UDPTopRemoteFlows:            udpTopRemoteFlows,
		UDPTopDstPort:                udpTopDstPort,
		UDPTopDstPortFlows:           udpTopDstPortFlows,
		UDPRemoteEvidenceApproximate: s.udpRemoteMapCapped,
		TCPCount:                     s.tcpCount,
		TCPUnrepliedRatio:            tcpUnrepliedRatio,
		TCPTopRemote:                 tcpTopRemote,
		TCPTopRemoteFlows:            tcpTopRemoteFlows,
		TCPTopDstPort:                tcpTopDstPort,
		TCPTopDstPortFlows:           tcpTopDstPortFlows,
		TCPRemoteEvidenceApproximate: s.tcpRemoteMapCapped,
		DNSUDPFlows:                  s.dnsUDPFlows,
		DNSBytesPerFlow:              dnsBytesPerFlow,
		DNSBytesPerFlowAvailable:     dnsBytesPerFlowAvailable,
		DNSUnrepliedRatio:            dnsUnrepliedRatio,
		BytesPerFlow:                 bytesPerFlow,
		PacketsPerFlow:               packetsPerFlow,
		BytesPerFlowAvailable:        bytesAvailable,
		PacketsPerFlowAvailable:      packetsAvailable,
		HostImpactPercent:            roundToFiveDecimals(hostImpact * 100),
		RemoteMapCapped:              s.remoteMapCapped,
		RemoteEvidenceApproximate:    s.remoteMapCapped,
		UniqueRemotesSaturated:       uniqueRemotesSaturated,
		NewRemotesSaturated:          newRemotesSaturated,
		ConntrackAcct:                acctEnabled,
		InstanceFlowTotal:            ctx.InstanceFlowTotal,
		HostPressureOwner:            ctx.HostPressureOwner == ident,
	}
	feature.Mining = selectMiningDetectionEvidence(feature, newBehaviorScaler(cm.behaviorSensitivity))
	ruleContext := &RuleCtx{
		DstPortCounts:              s.perDstPort,
		DstPortRepliedCounts:       s.perDstPortReplied,
		RemoteDstPortCounts:        s.perRemoteDstPort,
		PortEvidenceComplete:       true,
		RemotePortEvidenceComplete: !s.remotePortMapCapped,
	}

	if ctx.FreezeState {
		cm.appendMiningMetric(
			dynamicMetrics,
			cm.miningSignalSnapshot(ident),
			domain, serverName, instanceUUID, projectUUID, projectName, userUUID, addr, family,
		)
		return
	}
	if ctx.Rebaseline {
		classification := cm.classifyBehaviorWithRuleContext(feature, hostImpact, behaviorAnomalies{}, ruleContext)
		cm.reconcileGenericBehaviorRecovery(ident, classification)
		if feature.Direction == "outbound" {
			cm.appendMiningMetric(
				dynamicMetrics,
				cm.reconcileMiningRecovery(feature, ident, analysisNowUnix),
				domain, serverName, instanceUUID, projectUUID, projectName, userUUID, addr, family,
			)
		}
		cm.rebaselineBehaviorObservation(ident, feature, analysisNowUnix)
		return
	}
	anoms := cm.updateBehaviorEWMA(ident, feature, analysisNowUnix)
	cm.storeBehaviorIntervalSnapshot(ident, behaviorIntervalSnapshot{
		NewRemotes:          newRemotes,
		NewDstPorts:         newDstPorts,
		NewRemotesSaturated: newRemotesSaturated,
	})

	classification := cm.classifyBehaviorWithRuleContext(feature, hostImpact, anoms, ruleContext)
	feature.SynergyDarkScan = classification.SynergyDarkScan
	feature.SynergyDarkPhysics = classification.SynergyDarkPhysics
	hitSignal := classification.Hit
	signal := classification.Signal
	reason := classification.Reason
	ruleID := classification.RuleID
	ruleSource := classification.RuleSource
	miningOutcome := miningSignalOutcome{}
	if feature.Direction == "outbound" {
		miningOutcome = cm.updateMiningSignalState(feature, ident, analysisNowUnix)
		cm.appendMiningMetric(
			dynamicMetrics,
			miningOutcome,
			domain, serverName, instanceUUID, projectUUID, projectName, userUUID, addr, family,
		)
		cm.emitMiningBehaviorSignal(
			feature,
			s,
			miningOutcome,
			addr, domain, serverName, instanceUUID, projectUUID, projectName, userUUID,
			ctx,
			hostImpact,
			acctEnabled,
			analysisNowUnix,
		)
	}
	if hitSignal && signal == miningBehaviorSignal {
		cm.resetGenericBehaviorCandidate(ident)
		return
	}
	if !hitSignal {
		cm.resetGenericBehaviorCandidate(ident)
	}

	if hitSignal {
		msg := fmt.Sprintf("Behavior signal: %s detected (Flows: %d, Unreplied: %.0f%%, Impact: %.2f%%)", signal, s.flows, unrepliedRatio*100, hostImpact*100)
		srcIP, dstIP := behaviorSelectSignalIPs(feature.Direction, addr, s, signal, ctx.HostIPs)
		if signal == "outbound_stratum_mining_suspected" && feature.Mining.Valid && feature.Mining.TopRemote != (IPKey{}) {
			dstIP = IPKeyToString(feature.Mining.TopRemote)
		} else if signal == "smtp_spam_behavior_suspected" && feature.SMTPTopRemote != (IPKey{}) {
			dstIP = IPKeyToString(feature.SMTPTopRemote)
		} else if isUDPBehaviorSignal(signal) {
			if !feature.UDPRemoteEvidenceApproximate && feature.UDPTopRemote != (IPKey{}) {
				if feature.Direction == "outbound" {
					dstIP = IPKeyToString(feature.UDPTopRemote)
				} else {
					srcIP = IPKeyToString(feature.UDPTopRemote)
				}
			} else if feature.Direction == "outbound" {
				dstIP = ""
			} else {
				srcIP = ""
			}
		} else if isTCPBehaviorSignal(signal) && feature.TCPTopRemote != (IPKey{}) && !feature.TCPRemoteEvidenceApproximate {
			if feature.Direction == "outbound" {
				dstIP = IPKeyToString(feature.TCPTopRemote)
			} else {
				srcIP = IPKeyToString(feature.TCPTopRemote)
			}
		} else if remote, _, _, _ := restrictedProtocolBehaviorEvidenceFromFeature(feature, signal); remote != (IPKey{}) {
			dstIP = IPKeyToString(remote)
		} else if signal == "inbound_admin_port_exposure_suspected" && feature.AdminTopRemote != (IPKey{}) {
			srcIP = IPKeyToString(feature.AdminTopRemote)
		} else if isDarkspaceBehaviorSignal(signal) && feature.TopUnmonitoredRemote != (IPKey{}) {
			if feature.Direction == "outbound" {
				dstIP = IPKeyToString(feature.TopUnmonitoredRemote)
			} else {
				srcIP = IPKeyToString(feature.TopUnmonitoredRemote)
			}
		}

		ev := cm.buildBehaviorSignalEvidence(feature, topRemoteKey, topRemoteSet, signal)
		if classification.EvidenceOverride != nil {
			ev = *classification.EvidenceOverride
			ev.TopDstPortName = cm.behaviorPortName(feature.Direction, ev.TopDstPort)
			// A scoped rule must not inherit a whole-direction remote when
			// bounded collection cannot prove the rule's own endpoint.
			if feature.Direction == "outbound" {
				dstIP = ev.TopRemoteIP
			} else {
				srcIP = ev.TopRemoteIP
			}
		}
		topRemoteShare := ev.TopRemoteShare
		topPortShare := ev.TopPortShare
		evidenceMode := ev.EvidenceMode

		nowUnix := analysisNowUnix
		cm.behaviorSignalMu.Lock()
		signalKey := behaviorSignalKey{InstanceUUID: instanceUUID, IP: addrKey, Direction: feature.Direction, Signal: signal}
		ps := cm.genericBehaviorCandidateLocked(signalKey, ruleID, ruleSource, nowUnix)

		emitKey := behaviorEmitKey{InstanceUUID: instanceUUID, IP: addrKey, Direction: feature.Direction}
		es, ok := cm.behaviorEmit[emitKey]
		if !ok {
			es = &behaviorEmitState{}
			cm.behaviorEmit[emitKey] = es
		}
		transition := evaluateBehaviorSignalTransition(behaviorSignalTransitionInput{
			NowUnix:     nowUnix,
			Signal:      signal,
			Feature:     feature,
			Evidence:    ev,
			Persistence: *ps,
			Emission:    *es,
		})
		*ps = transition.Persistence

		persistenceHits := transition.Persistence.Hits
		persistenceRequired := transition.PersistenceRequired
		emitReason := transition.EmitReason
		shouldEmit := transition.ShouldEmit
		suppressReason := transition.SuppressReason
		if shouldEmit {
			*es = transition.Emission
		}
		cm.behaviorSignalMu.Unlock()

		if suppressReason != "" {
			if ruleLogStateMarkSuppressed(emitKey, nowUnix) {
				logKV(LogLevelDebug, "behavior", "behavior", "behavior_rule_suppressed",
					"project_uuid", projectUUID,
					"instance_uuid", instanceUUID,
					"direction", feature.Direction,
					"signal_candidate", signal,
					"rule_id", ruleID,
					"rule_source", ruleSource,
					"suppress_reason", suppressReason,
					"persistence_hits", persistenceHits,
					"persistence_required", persistenceRequired,
					"top_remote_share", topRemoteShare,
					"top_port_share", topPortShare,
					"evidence_mode", evidenceMode,
				)
			}
		}

		if !shouldEmit {
			return
		}

		signalKVs := buildBehaviorSignalKVs(behaviorSignalEvent{
			Feature:             feature,
			Evidence:            ev,
			Signal:              signal,
			Reason:              reason,
			Detail:              msg,
			PersistenceHits:     persistenceHits,
			PersistenceRequired: persistenceRequired,
			EmitReason:          emitReason,
			HostImpact:          hostImpact,
			ConntrackAcct:       acctEnabled,
			SrcIP:               srcIP,
			DstIP:               dstIP,
			Mining:              feature.Mining,
		})
		cm.routeBehaviorSignal(behaviorSignalTarget{
			Domain:       domain,
			ServerName:   serverName,
			InstanceUUID: instanceUUID,
			ProjectUUID:  projectUUID,
			ProjectName:  projectName,
			UserUUID:     userUUID,
		}, signalKVs)

		return
	}
}
