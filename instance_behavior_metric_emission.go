package main

import (
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

var behaviorRuleLogMu sync.Mutex
var behaviorRuleLogEvictSeed uint64 = 1
var behaviorRuleLogStateMap = map[behaviorEmitKey]*behaviorRuleLogState{}

func evictBehaviorRuleLogStateLocked(maxEntries int) int {
	if len(behaviorRuleLogStateMap) <= maxEntries {
		return 0
	}

	removeTarget := len(behaviorRuleLogStateMap) / 10
	if removeTarget < 1000 {
		removeTarget = 1000
	}
	if removeTarget > 10000 {
		removeTarget = 10000
	}

	removed := 0
	seed := atomic.AddUint64(&behaviorRuleLogEvictSeed, 0x9e3779b97f4a7c15)

	next := func() uint64 {
		seed ^= seed >> 12
		seed ^= seed << 25
		seed ^= seed >> 27
		return seed * 2685821657736338717
	}

	for k := range behaviorRuleLogStateMap {
		if (next() & 0xF) == 0 {
			delete(behaviorRuleLogStateMap, k)
			removed++
			if removed >= removeTarget {
				return removed
			}
		}
	}

	for k := range behaviorRuleLogStateMap {
		delete(behaviorRuleLogStateMap, k)
		removed++
		if removed >= removeTarget {
			break
		}
	}

	return removed
}
func ensureRuleLogStateLocked(k behaviorEmitKey) *behaviorRuleLogState {
	if len(behaviorRuleLogStateMap) > 50000 {
		removed := evictBehaviorRuleLogStateLocked(50000)
		logKV(LogLevelNotice, "behavior", "behavior", "behavior_rule_log_state_evict", "max", 50000, "removed", removed, "size", len(behaviorRuleLogStateMap))
	}
	s, ok := behaviorRuleLogStateMap[k]
	if !ok {
		s = &behaviorRuleLogState{}
		behaviorRuleLogStateMap[k] = s
	}
	return s
}

func ruleLogStateMarkSuppressed(k behaviorEmitKey, nowUnix int64) bool {
	behaviorRuleLogMu.Lock()
	defer behaviorRuleLogMu.Unlock()
	st := ensureRuleLogStateLocked(k)
	if (nowUnix - st.LastSuppressedUnix) < 60 {
		return false
	}
	st.LastSuppressedUnix = nowUnix
	return true
}

func ruleLogStateMarkSummary(k behaviorEmitKey, nowUnix int64) bool {
	behaviorRuleLogMu.Lock()
	defer behaviorRuleLogMu.Unlock()
	st := ensureRuleLogStateLocked(k)
	if (nowUnix - st.LastSummaryUnix) < 60 {
		return false
	}
	st.LastSummaryUnix = nowUnix
	return true
}

func behaviorHostImpactFlowTotal(ctx BehaviorContext, fallback int) int {
	if ctx.InstanceFlowTotal > 0 {
		return ctx.InstanceFlowTotal
	}
	return fallback
}

func (cm *ConntrackManager) analyzeBehavior(
	s *behaviorStats,
	addrKey IPKey,
	addr, family, domain, serverName, instanceUUID, projectUUID, projectName, userUUID string,
	dynamicMetrics *[]prometheus.Metric,
	descs metricDescGroup,
	ctx BehaviorContext,
) (result float64) {
	analysisNowUnix := time.Now().Unix()

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
	idx := shardIndexBehavior(behaviorIdentityKey{InstanceUUID: instanceUUID, IP: addrKey, Direction: dir})

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
	metadataKey := metadataServiceIPKey()
	if descs.thresholdConfigKey == "outbound" {
		metadataFlows = s.perRemote[metadataKey]
		if metadataFlows > 0 {
			metadataUnrepliedRatio = float64(s.perRemoteUnreplied[metadataKey]) / float64(metadataFlows)
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
		Direction:                   descs.thresholdConfigKey,
		ThresholdFlows:              tFlows,
		LocalScanHits:               localScanHits,
		InfraHits:                   infraHits,
		InfraMaxFlows:               infraMaxFlows,
		TenantPrivateHits:           tenantPrivateHits,
		TenantPrivateMaxFlows:       tenantPrivateMaxFlows,
		TenantPrivateUnrepliedRatio: tenantPrivateUnrepliedRatio,
		PublicRemotes:               publicRemotes,
		MetadataHits:                metadataFlows,
		MetadataMaxFlows:            metadataFlows,
		MetadataUnrepliedRatio:      metadataUnrepliedRatio,
		BGPFlows:                    bgpFlows,
		BGPTopRemote:                bgpTopRemote,
		BGPTopRemoteFlows:           bgpTopRemoteFlows,
		GeneveFlows:                 geneveFlows,
		GeneveTopRemote:             geneveTopRemote,
		GeneveTopRemoteFlows:        geneveTopRemoteFlows,
		SMTPFlows:                   smtpFlows,
		SMTPUniqueRemotes:           len(s.smtpRemotes),
		SMTPUnrepliedRatio:          smtpUnrepliedRatio,
		SMTPTopRemote:               smtpTopRemote,
		SMTPTopRemoteFlows:          smtpTopRemoteFlows,
		SMTPTopDstPort:              smtpTopDstPort,
		SMTPTopDstPortFlows:         smtpTopDstPortFlows,
		StratumFlows:                stratumFlows,
		StratumRepliedFlows:         stratumRepliedFlows,
		MiningHigh:                  miningHigh,
		MiningShared:                miningShared,
		AdminPortFlows:              adminPortFlows,
		AdminUniqueRemotes:          len(publicAdminRemotes),
		AdminNewRemotes:             adminNewRemotes,
		AdminUnrepliedRatio:         adminUnrepliedRatio,
		AdminTopRemote:              adminTopRemote,
		AdminTopRemoteFlows:         adminTopRemoteFlows,
		AdminTopDstPort:             adminTopDstPort,
		AdminTopDstPortFlows:        adminTopDstPortFlows,
		Flows:                       s.flows,
		UniqueRemotes:               uniqueRemotes,
		NewRemotes:                  newRemotes,
		UniqueDstPorts:              uniqueDstPorts,
		NewDstPorts:                 newDstPorts,
		MaxSingleRemote:             maxSingleRemote,
		MaxSingleDstPort:            maxSingleDstPort,
		TopDstPort:                  topDstPort,
		UnmonitoredPortFlows:        unmonitoredPortFlows,
		UnmonitoredUnrepliedRatio:   unmonitoredUnrepliedRatio,
		UnmonitoredUniqueDstPorts:   unmonitoredUniqueDstPorts,
		MaxSingleUnmonitoredDstPort: maxSingleUnmonitoredDstPort,
		TopUnmonitoredDstPort:       topUnmonitoredDstPort,
		TopUnmonitoredRemote:        topUnmonitoredRemote,
		TopUnmonitoredRemoteFlows:   topUnmonitoredRemoteFlows,
		UnrepliedRatio:              unrepliedRatio,
		MulticastCount:              s.multicastCount,
		ICMPCount:                   s.icmpCount,
		UDPCount:                    s.udpCount,
		UDPUniqueRemotes:            len(s.udpRemotes),
		UDPUnrepliedRatio:           udpUnrepliedRatio,
		UDPTopRemote:                udpTopRemote,
		UDPTopRemoteFlows:           udpTopRemoteFlows,
		UDPTopDstPort:               udpTopDstPort,
		UDPTopDstPortFlows:          udpTopDstPortFlows,
		DNSUDPFlows:                 s.dnsUDPFlows,
		DNSBytesPerFlow:             dnsBytesPerFlow,
		DNSBytesPerFlowAvailable:    dnsBytesPerFlowAvailable,
		DNSUnrepliedRatio:           dnsUnrepliedRatio,
		BytesPerFlow:                bytesPerFlow,
		PacketsPerFlow:              packetsPerFlow,
		BytesPerFlowAvailable:       bytesAvailable,
		PacketsPerFlowAvailable:     packetsAvailable,
		HostImpactPercent:           roundToFiveDecimals(hostImpact * 100),
		RemoteMapCapped:             s.remoteMapCapped,
		RemoteEvidenceApproximate:   s.remoteMapCapped,
		UniqueRemotesSaturated:      uniqueRemotesSaturated,
		NewRemotesSaturated:         newRemotesSaturated,
		ConntrackAcct:               acctEnabled,
	}
	feature.Mining = selectMiningDetectionEvidence(feature, newBehaviorScaler(cm.behaviorSensitivity))

	ident := behaviorIdentityKey{InstanceUUID: instanceUUID, IP: addrKey, Direction: descs.thresholdConfigKey}
	if ctx.FreezeState {
		cm.appendMiningMetric(
			dynamicMetrics,
			cm.miningAlertSnapshot(ident),
			domain, serverName, instanceUUID, projectUUID, projectName, userUUID, addr, family,
		)
		return cm.behaviorSeveritySnapshot(ident)
	}
	defer func() {
		cm.storeBehaviorSeverity(ident, result)
	}()
	behaviorSignal, anoms := cm.updateBehaviorEWMA(ident, feature, analysisNowUnix)

	classification := cm.classifyBehavior(feature, hostImpact, anoms, s.perDstPort)
	feature.SynergyDarkScan = classification.SynergyDarkScan
	feature.SynergyDarkPhysics = classification.SynergyDarkPhysics
	hitAlert := classification.Hit
	kind := classification.Kind
	reason := classification.Reason
	ruleID := classification.RuleID
	ruleSource := classification.RuleSource
	pressure := clamp01(math.Log10(1 + 9*hostImpact))
	severity := clamp01(pressure + behaviorSignal)
	miningOutcome := miningAlertOutcome{}
	if feature.Direction == "outbound" {
		miningOutcome = cm.updateMiningAlertState(feature, ident, analysisNowUnix)
		cm.appendMiningMetric(
			dynamicMetrics,
			miningOutcome,
			domain, serverName, instanceUUID, projectUUID, projectName, userUUID, addr, family,
		)
		cm.emitMiningBehaviorAlert(
			feature,
			s,
			miningOutcome,
			addr, domain, serverName, instanceUUID, projectUUID, projectName, userUUID,
			ctx,
			hostImpact, behaviorSignal,
			acctEnabled,
			analysisNowUnix,
		)
		severity = applyConfirmedBehaviorPriorityFloor(severity, miningOutcome)
	}
	if hitAlert && kind == miningBehaviorKind {
		return severity
	}

	if hitAlert {
		msg := fmt.Sprintf("Alert: %s detected (Flows: %d, Unreplied: %.0f%%, Impact: %.2f%%)", kind, s.flows, unrepliedRatio*100, hostImpact*100)
		srcIP, dstIP := behaviorSelectAlertIPs(feature.Direction, addr, s, kind, ctx.HostIPs)
		if kind == "outbound_stratum_mining_suspected" && feature.Mining.Valid && feature.Mining.TopRemote != (IPKey{}) {
			dstIP = IPKeyToString(feature.Mining.TopRemote)
		} else if kind == "smtp_spam_behavior_suspected" && feature.SMTPTopRemote != (IPKey{}) {
			dstIP = IPKeyToString(feature.SMTPTopRemote)
		} else if isUDPBehaviorKind(kind) && feature.UDPTopRemote != (IPKey{}) {
			if feature.Direction == "outbound" {
				dstIP = IPKeyToString(feature.UDPTopRemote)
			} else {
				srcIP = IPKeyToString(feature.UDPTopRemote)
			}
		} else if remote, _, _, _ := restrictedProtocolBehaviorEvidenceFromFeature(feature, kind); remote != (IPKey{}) {
			dstIP = IPKeyToString(remote)
		} else if kind == "inbound_admin_port_exposure_suspected" && feature.AdminTopRemote != (IPKey{}) {
			srcIP = IPKeyToString(feature.AdminTopRemote)
		} else if isDarkspaceBehaviorKind(kind) && feature.TopUnmonitoredRemote != (IPKey{}) {
			if feature.Direction == "outbound" {
				dstIP = IPKeyToString(feature.TopUnmonitoredRemote)
			} else {
				srcIP = IPKeyToString(feature.TopUnmonitoredRemote)
			}
		}

		ev := cm.buildBehaviorAlertEvidence(feature, topRemoteKey, topRemoteSet, kind)
		topRemoteShare := ev.TopRemoteShare
		topPortShare := ev.TopPortShare
		evidenceMode := ev.EvidenceMode

		nowUnix := analysisNowUnix
		cm.behaviorAlertMu.Lock()
		alertKey := behaviorAlertKey{InstanceUUID: instanceUUID, IP: addrKey, Direction: feature.Direction, Kind: kind}
		ps, ok := cm.behaviorPersist[alertKey]
		if !ok {
			ps = &behaviorPersistState{Hits: 0, FirstSeenUnix: nowUnix, LastSeenUnix: nowUnix}
			cm.behaviorPersist[alertKey] = ps
		}

		emitKey := behaviorEmitKey{InstanceUUID: instanceUUID, IP: addrKey, Direction: feature.Direction}
		es, ok := cm.behaviorEmit[emitKey]
		if !ok {
			es = &behaviorEmitState{}
			cm.behaviorEmit[emitKey] = es
		}
		transition := evaluateBehaviorAlertTransition(behaviorAlertTransitionInput{
			NowUnix:     nowUnix,
			Kind:        kind,
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
		severityScore := transition.SeverityScore
		confidenceScore := transition.ConfidenceScore
		priority := transition.Priority
		priorityBasis := transition.PriorityBasis
		severityBand := transition.SeverityBand

		if suppressReason != "" {
			if ruleLogStateMarkSuppressed(emitKey, nowUnix) {
				logKV(LogLevelDebug, "behavior", "behavior", "behavior_rule_suppressed",
					"project_uuid", projectUUID,
					"instance_uuid", instanceUUID,
					"direction", feature.Direction,
					"kind_candidate", kind,
					"rule_id", ruleID,
					"rule_source", ruleSource,
					"suppress_reason", suppressReason,
					"persistence_hits", persistenceHits,
					"persistence_required", persistenceRequired,
					"priority", priority,
					"severity_score", severityScore,
					"confidence_score", confidenceScore,
					"top_remote_share", topRemoteShare,
					"top_port_share", topPortShare,
					"evidence_mode", evidenceMode,
				)
			}
		}

		if shouldEmit {
			if emitReason == "new_kind" || emitReason == "escalated" || emitReason == "band_cross" {
				if ruleLogStateMarkSummary(emitKey, nowUnix) {
					logKV(LogLevelNotice, "behavior", "behavior", "behavior_rule_summary",
						"project_uuid", projectUUID,
						"instance_uuid", instanceUUID,
						"direction", feature.Direction,
						"previous_kind", transition.PreviousKind,
						"new_kind", kind,
						"previous_priority", transition.PreviousPriority,
						"new_priority", priority,
						"previous_severity_band", transition.PreviousSeverityBand,
						"new_severity_band", severityBand,
						"rule_id", ruleID,
						"rule_source", ruleSource,
						"emit_reason", emitReason,
						"severity_score", severityScore,
						"confidence_score", confidenceScore,
						"top_remote_share", topRemoteShare,
						"top_port_share", topPortShare,
						"evidence_mode", evidenceMode,
					)
				}
			}
			*es = transition.Emission
		}
		cm.behaviorAlertMu.Unlock()

		if persistenceHits >= persistenceRequired {
			switch priority {
			case "P1":
				severity = 1.0
			case "P2":
				if severity < 0.7 {
					severity = 0.7
				}
			case "P3":
				if severity < 0.5 {
					severity = 0.5
				}
			case "P4":
			}
		}

		if !shouldEmit {
			return severity
		}

		alertKVs := buildBehaviorAlertKVs(behaviorAlertEvent{
			Feature:             feature,
			Evidence:            ev,
			Kind:                kind,
			Reason:              reason,
			Detail:              msg,
			PersistenceHits:     persistenceHits,
			PersistenceRequired: persistenceRequired,
			EmitReason:          emitReason,
			SeverityScore:       severityScore,
			ConfidenceScore:     confidenceScore,
			SeverityBand:        severityBand,
			PriorityBasis:       priorityBasis,
			Priority:            priority,
			HostImpact:          hostImpact,
			BehaviorSignal:      behaviorSignal,
			ConntrackAcct:       acctEnabled,
			SrcIP:               srcIP,
			DstIP:               dstIP,
			Mining:              feature.Mining,
		})
		cm.routeBehaviorAlert(behaviorAlertTarget{
			Domain:       domain,
			ServerName:   serverName,
			InstanceUUID: instanceUUID,
			ProjectUUID:  projectUUID,
			ProjectName:  projectName,
			UserUUID:     userUUID,
		}, alertKVs)

		return severity
	}

	return severity
}
