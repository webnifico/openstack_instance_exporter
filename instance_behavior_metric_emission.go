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
func ruleLogStateForKey(k behaviorEmitKey) *behaviorRuleLogState {
	behaviorRuleLogMu.Lock()
	defer behaviorRuleLogMu.Unlock()
	if len(behaviorRuleLogStateMap) > 50000 {
		removed := evictBehaviorRuleLogStateLocked(50000)
		logKV(LogLevelNotice, "behavior", "behavior_rule_log_state_evict", "max", 50000, "removed", removed, "size", len(behaviorRuleLogStateMap))
	}
	s, ok := behaviorRuleLogStateMap[k]
	if !ok {
		s = &behaviorRuleLogState{}
		behaviorRuleLogStateMap[k] = s
	}
	return s
}

func (cm *ConntrackManager) analyzeBehavior(
	s *behaviorStats,
	addrKey IPKey,
	addr, family, domain, serverName, instanceUUID, projectUUID, projectName, userUUID string,
	dynamicMetrics *[]prometheus.Metric,
	descs metricDescGroup,
	ctx BehaviorContext,
) float64 {

	hostMax := ctx.HostConntrackMax
	hostImpact := 0.0
	if hostMax > 0 {
		hostImpact = float64(s.flows) / float64(hostMax)
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

	bytesPerFlow := 0.0
	packetsPerFlow := 0.0
	acctEnabled := cm.conntrackAcctEnabled && s.trackAcct
	if acctEnabled && s.flows > 0 {
		bytesPerFlow = float64(s.bytes) / float64(s.flows)
		packetsPerFlow = float64(s.packets) / float64(s.flows)
	}

	uniqueRemotes := len(s.remotes)
	newRemotes := 0
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
	publicRemotes := 0
	for rk := range s.remotes {
		if s.remoteIsPrivate[rk] {
			continue
		}
		if isInfrastructureKey(rk, ctx.HostIPKeys) {
			continue
		}
		publicRemotes++
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
				if isInfrastructureKey(rk, ctx.HostIPKeys) {
					infraHits++
					if c := s.perRemote[rk]; c > infraMaxFlows {
						infraMaxFlows = c
					}
				} else if isLocalOnlyKey(rk) {
					localScanHits++
				}
			}
		}
	}

	remoteHistoryCap, portHistoryCap := behaviorHistoryCaps(cm.behaviorSensitivity)

	uniqueDstPorts := len(s.dstPorts)
	newDstPorts := 0

	mu.Lock()
	now := time.Now().Unix()
	prevSeenMap[key] = now

	curRemoteSample := sampleIPKeySetDeterministic(s.remotes, remoteHistoryCap)
	if prev, ok := prevRemotesMap[key]; ok {
		if len(curRemoteSample) > 0 {
			overlap := 0
			for r := range curRemoteSample {
				if _, exists := prev.remotes[r]; exists {
					overlap++
				}
			}
			fracNew := 1.0 - (float64(overlap) / float64(len(curRemoteSample)))
			newRemotes = int(math.Round(float64(uniqueRemotes) * fracNew))
		}
	} else {
		newRemotes = uniqueRemotes
	}
	prevRemotesMap[key] = outboundPrev{remotes: curRemoteSample}

	curPortSample := samplePortSetDeterministic(s.dstPorts, portHistoryCap)
	if prev, ok := prevPortsMap[key]; ok {
		if len(curPortSample) > 0 {
			overlap := 0
			for p := range curPortSample {
				if _, exists := prev.ports[p]; exists {
					overlap++
				}
			}
			fracNew := 1.0 - (float64(overlap) / float64(len(curPortSample)))
			newDstPorts = int(math.Round(float64(uniqueDstPorts) * fracNew))
		}
	} else {
		newDstPorts = uniqueDstPorts
	}
	prevPortsMap[key] = outboundPrevDstPorts{ports: curPortSample}
	mu.Unlock()

	maxSingleRemote := 0
	var topRemoteKey IPKey
	topRemoteSet := false
	for rk, count := range s.perRemote {
		if count > maxSingleRemote {
			maxSingleRemote = count
			topRemoteKey = rk
			topRemoteSet = true
		}
	}

	maxSingleDstPort := 0
	topDstPort := uint16(0)
	for port, count := range s.perDstPort {
		if count > maxSingleDstPort {
			maxSingleDstPort = count
			topDstPort = port
		}
	}

	bgpFlows := s.perDstPort[179]
	geneveFlows := s.perDstPort[6081]
	smtpFlows := sumPortCounts(s.perDstPort, 25, 465, 587)
	stratumFlows := sumPortCounts(s.perDstPort, 3333, 4444, 8333)
	adminPortFlows := 0
	if descs.thresholdConfigKey == "inbound" {
		adminPortFlows = sumPortCounts(s.perDstPort, 22, 3389, 5900, 2375, 6443, 10250, 2379, 9200, 27017, 6379, 445, 3306, 5432, 8888)
	}

	// -------------------------------------------------------------------------
	// Feature 1: Dark-Space Port Detection (Unmonitored Ports)
	// -------------------------------------------------------------------------
	unmonitoredPortFlows := 0
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
				if count > maxSingleUnmonitoredDstPort {
					maxSingleUnmonitoredDstPort = count
					topUnmonitoredDstPort = port
				}
			}
		}
	}
	// -------------------------------------------------------------------------

	if dynamicMetrics != nil {
		if descs.uniqueRemotes != nil {
			*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(descs.uniqueRemotes, prometheus.GaugeValue, float64(uniqueRemotes), domain, serverName, instanceUUID, projectUUID, projectName, userUUID, addr, family))
		}
		if descs.newRemotes != nil {
			*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(descs.newRemotes, prometheus.GaugeValue, float64(newRemotes), domain, serverName, instanceUUID, projectUUID, projectName, userUUID, addr, family))
		}
		if descs.maxSingleRemote != nil {
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
		if acctEnabled && descs.bytesPerFlow != nil {
			*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(descs.bytesPerFlow, prometheus.GaugeValue, bytesPerFlow, domain, serverName, instanceUUID, projectUUID, projectName, userUUID, addr, family))
		}
		if acctEnabled && descs.packetsPerFlow != nil {
			*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(descs.packetsPerFlow, prometheus.GaugeValue, packetsPerFlow, domain, serverName, instanceUUID, projectUUID, projectName, userUUID, addr, family))
		}
	}

	feature := BehaviorFeature{
		Direction:                   descs.thresholdConfigKey,
		ThresholdFlows:              tFlows,
		LocalScanHits:               localScanHits,
		InfraHits:                   infraHits,
		InfraMaxFlows:               infraMaxFlows,
		PublicRemotes:               publicRemotes,
		MetadataHits:                metadataFlows,
		MetadataMaxFlows:            metadataFlows,
		MetadataUnrepliedRatio:      metadataUnrepliedRatio,
		BGPFlows:                    bgpFlows,
		GeneveFlows:                 geneveFlows,
		SMTPFlows:                   smtpFlows,
		StratumFlows:                stratumFlows,
		AdminPortFlows:              adminPortFlows,
		Flows:                       s.flows,
		UniqueRemotes:               uniqueRemotes,
		NewRemotes:                  newRemotes,
		UniqueDstPorts:              uniqueDstPorts,
		NewDstPorts:                 newDstPorts,
		MaxSingleRemote:             maxSingleRemote,
		MaxSingleDstPort:            maxSingleDstPort,
		TopDstPort:                  topDstPort,
		UnmonitoredPortFlows:        unmonitoredPortFlows,
		UnmonitoredUniqueDstPorts:   unmonitoredUniqueDstPorts,
		MaxSingleUnmonitoredDstPort: maxSingleUnmonitoredDstPort,
		TopUnmonitoredDstPort:       topUnmonitoredDstPort,
		UnrepliedRatio:              unrepliedRatio,
		MulticastCount:              s.multicastCount,
		ICMPCount:                   s.icmpCount,
		UDPCount:                    s.udpCount,
		BytesPerFlow:                bytesPerFlow,
		PacketsPerFlow:              packetsPerFlow,
		HostImpactPercent:           roundToFiveDecimals(hostImpact * 100),
		RemoteMapCapped:             s.remoteMapCapped,
		PortMapCapped:               s.portMapCapped,
		ConntrackAcct:               acctEnabled,
	}

	ident := behaviorIdentityKey{InstanceUUID: instanceUUID, IP: addrKey, Direction: descs.thresholdConfigKey}
	behaviorSignal, anoms := cm.updateBehaviorEWMA(ident, feature)

	hitAlert, kind, reason, ruleID, ruleSource := cm.classifyBehavior(&feature, hostImpact, anoms)
	pressure := clamp01(math.Log10(1 + 9*hostImpact))
	severity := clamp01(pressure + behaviorSignal)

	if hitAlert {
		msg := fmt.Sprintf("Alert: %s detected (Flows: %d, Unreplied: %.0f%%, Impact: %.2f%%)", kind, s.flows, unrepliedRatio*100, hostImpact*100)
		srcIP, dstIP := behaviorSelectAlertIPs(feature.Direction, addr, s, kind, ctx.HostIPs)

		ev := cm.buildBehaviorAlertEvidence(feature, topRemoteKey, topRemoteSet)
		topDstPortName := ev.TopDstPortName
		topRemoteIP := ev.TopRemoteIP
		topRemoteShare := ev.TopRemoteShare
		topPortShare := ev.TopPortShare
		evidenceMode := ev.EvidenceMode

		nowUnix := time.Now().Unix()
		persistenceHits := 1
		emitReason := "new_kind"
		shouldEmit := false
		severityScore := 0
		confidenceScore := 0
		priority := "P4"
		priorityBasis := "mixed"
		severityBand := "low"
		persistenceRequired := 3

		cm.behaviorAlertMu.Lock()
		alertKey := behaviorAlertKey{InstanceUUID: instanceUUID, IP: addrKey, Direction: feature.Direction, Kind: kind}
		ps, ok := cm.behaviorPersist[alertKey]
		if !ok {
			ps = &behaviorPersistState{Hits: 0, FirstSeenUnix: nowUnix, LastSeenUnix: nowUnix}
			cm.behaviorPersist[alertKey] = ps
		}
		if (nowUnix - ps.LastSeenUnix) > 180 {
			ps.Hits = 0
			ps.FirstSeenUnix = nowUnix
		}
		ps.Hits++
		ps.LastSeenUnix = nowUnix
		persistenceHits = ps.Hits

		severityScore = behaviorSeverityScore(feature)
		confidenceScore = behaviorConfidenceScore(feature, kind, topRemoteShare, topPortShare, evidenceMode, persistenceHits)
		priority, priorityBasis = behaviorPriorityFromScores(severityScore, confidenceScore)
		severityBand = behaviorSeverityBand(severityScore)
		persistenceRequired = 3
		if priorityRank(priority) >= priorityRank("P2") {
			persistenceRequired = 2
		}

		emitKey := behaviorEmitKey{InstanceUUID: instanceUUID, IP: addrKey, Direction: feature.Direction}
		es, ok := cm.behaviorEmit[emitKey]
		if !ok {
			es = &behaviorEmitState{}
			cm.behaviorEmit[emitKey] = es
		}
		prevKind := es.LastKind
		prevPriority := es.LastPriority
		prevSeverityBand := es.LastSeverityBand

		if persistenceHits >= persistenceRequired {
			if es.LastKind == "" {
				shouldEmit = true
				emitReason = "new_kind"
			} else if es.LastKind != kind {
				shouldEmit = true
				emitReason = "new_kind"
			} else if es.LastPriority != priority {
				shouldEmit = true
				if priorityRank(priority) > priorityRank(es.LastPriority) {
					emitReason = "escalated"
				} else {
					emitReason = "band_cross"
				}
			} else if es.LastSeverityBand != "" && es.LastSeverityBand != severityBand {
				shouldEmit = true
				emitReason = "band_cross"
			} else if topRemoteShare >= 0.60 && topRemoteIP != "" && es.LastTopRemote != "" && es.LastTopRemote != topRemoteIP {
				shouldEmit = true
				emitReason = "changed"
			} else if topPortShare >= 0.60 && topDstPort != 0 && es.LastTopDstPort != 0 && es.LastTopDstPort != topDstPort {
				shouldEmit = true
				emitReason = "changed"
			}
			if shouldEmit && (emitReason == "changed" || emitReason == "band_cross") && (nowUnix-es.LastEmitUnix) < behaviorAlertCooldownSeconds {
				shouldEmit = false
			}
			if !shouldEmit && priorityRank(priority) >= priorityRank("P2") && (nowUnix-es.LastEmitUnix) >= behaviorAlertHeartbeatSeconds {
				shouldEmit = true
				emitReason = "heartbeat"
			}
		}

		suppressReason := ""
		if persistenceHits < persistenceRequired {
			suppressReason = "persistence_gate"
		} else if !shouldEmit && (emitReason == "changed" || emitReason == "band_cross") && (nowUnix-es.LastEmitUnix) < behaviorAlertCooldownSeconds {
			suppressReason = "cooldown"
		}
		if suppressReason != "" {
			st := ruleLogStateForKey(emitKey)
			if (nowUnix - st.LastSuppressedUnix) >= 60 {
				st.LastSuppressedUnix = nowUnix
				logKV(LogLevelDebug, "behavior", "behavior_rule_suppressed",
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
				st := ruleLogStateForKey(emitKey)
				if (nowUnix - st.LastSummaryUnix) >= 60 {
					st.LastSummaryUnix = nowUnix
					logKV(LogLevelNotice, "behavior", "behavior_rule_summary",
						"project_uuid", projectUUID,
						"instance_uuid", instanceUUID,
						"direction", feature.Direction,
						"previous_kind", prevKind,
						"new_kind", kind,
						"previous_priority", prevPriority,
						"new_priority", priority,
						"previous_severity_band", prevSeverityBand,
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
			es.LastKind = kind
			es.LastPriority = priority
			es.LastSeverityBand = severityBand
			es.LastTopRemote = topRemoteIP
			es.LastTopDstPort = topDstPort
			es.LastEmitUnix = nowUnix
		}
		cm.behaviorAlertMu.Unlock()

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

		if !shouldEmit {
			return severity
		}

		alertKVs := []interface{}{
			"kind", kind,
			"reason", reason,
			"msg", msg,
			"direction", feature.Direction,
			"synergy_darkspace_scan", feature.SynergyDarkScan,
			"synergy_darkspace_physics", feature.SynergyDarkPhysics,
			"threshold_flows", feature.ThresholdFlows,
			"local_scan_hits", feature.LocalScanHits,
			"infra_hits", feature.InfraHits,
			"infra_max_flows", feature.InfraMaxFlows,
			"flows_current", feature.Flows,
			"unique_remotes", feature.UniqueRemotes,
			"new_remotes", feature.NewRemotes,
			"unique_ports", feature.UniqueDstPorts,
			"new_ports", feature.NewDstPorts,
			"max_flows_single_remote", feature.MaxSingleRemote,
			"max_flows_single_port", feature.MaxSingleDstPort,
			"top_dst_port", int(topDstPort),
			"top_dst_port_name", topDstPortName,
			"top_remote_ip", topRemoteIP,
			"top_remote_share", topRemoteShare,
			"top_port_share", topPortShare,
			"evidence_mode", evidenceMode,
			"persistence_hits", persistenceHits,
			"persistence_required", persistenceRequired,
			"emit_reason", emitReason,
			"severity_score", severityScore,
			"confidence_score", confidenceScore,
			"severity_band", severityBand,
			"priority_basis", priorityBasis,
			"unreplied_ratio", roundToFiveDecimals(feature.UnrepliedRatio),
			"multicast_count", feature.MulticastCount,
			"icmp_count", feature.ICMPCount,
			"udp_count", feature.UDPCount,
			"host_impact_percent", roundToFiveDecimals(hostImpact * 100),
			"behavior_signal", roundToFiveDecimals(behaviorSignal),
			"conntrack_acct", acctEnabled,
			"bytes_per_flow", roundToFiveDecimals(feature.BytesPerFlow),
			"packets_per_flow", roundToFiveDecimals(feature.PacketsPerFlow),
			"remote_map_capped", feature.RemoteMapCapped,
			"port_map_capped", feature.PortMapCapped,
			"src_ip", srcIP,
			"dst_ip", dstIP,
			"priority", priority,
		}

		if cm.LogThreat != nil {
			cm.LogThreat("BEHAVIOR", "behavior_alert", domain, instanceUUID, projectUUID, projectName, userUUID, alertKVs...)
		} else {
			kvs := append([]interface{}{"domain", domain, "server_name", serverName}, alertKVs...)
			kvs = append(kvs, "instance_uuid", instanceUUID)
			logKV(LogLevelNotice, "behavior", "behavior_alert", kvs...)
		}

		return severity
	}

	return severity
}
