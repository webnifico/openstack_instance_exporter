package main

import (
	"fmt"
	"math"
)

func defaultBehaviorThresholds() BehaviorThresholds {
	// Classifiers apply sensitivity once when comparing observations. Scaling
	// these inputs at startup as well made the flow limit vary with its square.
	return BehaviorThresholds{OutboundFlowsTotal: 2000, InboundFlowsTotal: 2000}
}

type behaviorClassification struct {
	Hit                bool
	Signal             string
	Reason             string
	RuleID             string
	RuleSource         string
	SynergyDarkScan    bool
	SynergyDarkPhysics bool
	EvidenceOverride   *behaviorSignalEvidence
}

func behaviorClassificationHit(signal, reason, ruleID, ruleSource string) behaviorClassification {
	return behaviorClassification{
		Hit:        true,
		Signal:     signal,
		Reason:     reason,
		RuleID:     ruleID,
		RuleSource: ruleSource,
	}
}

func newBehaviorScaler(sens float64) behaviorScaler {
	if sens <= 0 || math.IsNaN(sens) || math.IsInf(sens, 0) {
		sens = 1.0
	}
	return behaviorScaler{sens: sens}
}

func saturatingScaledInt(value float64) int {
	maxInt := int(^uint(0) >> 1)
	if math.IsInf(value, 1) || value >= float64(maxInt) {
		return maxInt
	}
	value = math.Ceil(value)
	if value < 1 {
		return 1
	}
	return int(value)
}

func (s behaviorScaler) scaleIntHigh(v int) int {
	if v <= 0 {
		return v
	}
	return saturatingScaledInt(float64(v) / s.sens)
}
func (s behaviorScaler) scaleIntLow(v int) int {
	if v <= 0 {
		return v
	}
	return saturatingScaledInt(float64(v) * s.sens)
}
func (s behaviorScaler) threshHigh(v float64) float64 {
	return v / s.sens
}
func (s behaviorScaler) threshLow(v float64) float64 {
	return v * s.sens
}
func (s behaviorScaler) ratioThresh(base float64) float64 {
	t := base / s.sens
	if t < 0 {
		return 0
	}
	if t > 1 {
		return 1
	}
	return t
}
func (s behaviorScaler) ratioUpperBound(base float64) float64 {
	t := base * s.sens
	if t < 0 {
		return 0
	}
	if t > 1 {
		return 1
	}
	return t
}
func (s behaviorScaler) anomThresh(base float64) float64 {
	v := base / s.sens
	if v < 0.05 {
		v = 0.05
	}
	if v > 0.99 {
		v = 0.99
	}
	return v
}

func (cm *ConntrackManager) classifyBehaviorWithRuleContext(feature BehaviorFeature, hostImpact float64, anoms behaviorAnomalies, ruleCtx *RuleCtx) behaviorClassification {
	sc := newBehaviorScaler(cm.behaviorSensitivity)
	ev := buildBehaviorEvidence(feature)
	ctx := RuleCtx{Thresholds: defaultRuleThresholds}
	if ruleCtx != nil {
		ctx = *ruleCtx
		ctx.Thresholds = defaultRuleThresholds
	}

	restrictedHit, restrictedRuleID, restrictedSignal, restrictedReason, restrictedSource := evalRules(feature, sc, ev, &ctx, rulesRestrictedLocal)
	if restrictedHit {
		return behaviorClassificationHit(restrictedSignal, restrictedReason, restrictedRuleID, restrictedSource)
	}

	darkHit, darkRuleID, darkSignal, darkReason, darkSource := evalRules(feature, sc, ev, &ctx, rulesDarkspace)
	scanHit, scanSignal, scanReason := cm.classifyOutboundScanning(feature, anoms, sc)
	inboundExposureHit, inboundExposureSignal, inboundExposureReason := cm.classifyInboundExposure(feature, sc)
	inboundAttackHit, inboundAttackSignal, inboundAttackReason := cm.classifyInboundAttackPatterns(feature, sc)
	protoHit, protoRuleID, protoSignal, protoReason, protoSource := evalRules(feature, sc, ev, &ctx, rulesProtocol)
	udpHit, _, _, _, _ := evalRuleByID(feature, sc, ev, &ctx, rulesProtocol, "proto_udp_fanout")

	withSynergy := func(result behaviorClassification) behaviorClassification {
		result.SynergyDarkScan = darkHit && scanHit
		result.SynergyDarkPhysics = darkHit && protoHit
		return result
	}

	if darkHit && protoHit {
		return withSynergy(behaviorClassificationHit("darkspace_plus_physics", darkReason+" | "+protoReason, "synergy_darkspace_plus_physics", "internal"))
	}
	if darkHit && scanHit {
		return withSynergy(behaviorClassificationHit("darkspace_plus_scan", darkReason+" | "+scanReason, "synergy_darkspace_plus_scan", "internal"))
	}
	if darkHit {
		return withSynergy(behaviorClassificationHit(darkSignal, darkReason, darkRuleID, darkSource))
	}
	if udpHit {
		// A qualifying UDP rule must beat topology-only scanning, while the
		// protocol table's own first-match order remains authoritative.
		return withSynergy(behaviorClassificationHit(protoSignal, protoReason, protoRuleID, protoSource))
	}
	if scanHit {
		return withSynergy(behaviorClassificationHit(scanSignal, scanReason, "legacy_scan", "internal"))
	}
	if protoHit {
		return withSynergy(behaviorClassificationHit(protoSignal, protoReason, protoRuleID, protoSource))
	}
	if inboundAttackHit {
		return withSynergy(behaviorClassificationHit(inboundAttackSignal, inboundAttackReason, "legacy_inbound_attack_patterns", "internal"))
	}
	if inboundExposureHit {
		return withSynergy(behaviorClassificationHit(inboundExposureSignal, inboundExposureReason, "legacy_inbound_exposure", "internal"))
	}
	if hit, signal, reason := cm.classifyCapacityAndFlood(feature, hostImpact, sc); hit {
		return withSynergy(behaviorClassificationHit(signal, reason, "legacy_capacity_and_flood", "internal"))
	}

	externalRules := cm.externalBehaviorRules
	if len(externalRules) > 0 {
		extHit, extRuleID, extSignal, extReason, extSource := evalRules(feature, sc, ev, &ctx, externalRules)
		if extHit {
			result := behaviorClassificationHit(extSignal, extReason, extRuleID, extSource)
			for i := range externalRules {
				rule := &externalRules[i]
				if rule.ID != extRuleID || rule.Evidence == nil {
					continue
				}
				if evidence, available := rule.Evidence(feature, sc, ev, &ctx); available {
					result.EvidenceOverride = &evidence
				}
				break
			}
			return withSynergy(result)
		}
	}

	return withSynergy(behaviorClassification{})
}
func (cm *ConntrackManager) classifyOutboundScanning(feature BehaviorFeature, anoms behaviorAnomalies, sc behaviorScaler) (bool, string, string) {
	if feature.Direction != "outbound" {
		return false, "", ""
	}
	if feature.Flows < sc.scaleIntHigh(20) {
		return false, "", ""
	}
	_, _, evidenceMode := behaviorEvidenceFromFeature(feature)
	if feature.UnrepliedRatio >= sc.ratioThresh(0.60) {
		if evidenceMode == "dominant_port" && feature.UniqueRemotes >= sc.scaleIntHigh(20) && feature.TopDstPort != 0 {
			return true, "outbound_horizontal_scan_suspected", fmt.Sprintf("many_remotes_single_port_unreplied_ratio_%.2f", feature.UnrepliedRatio)
		}
		if evidenceMode == "dominant_remote" && feature.UniqueDstPorts >= sc.scaleIntHigh(20) {
			return true, "outbound_vertical_scan_suspected", fmt.Sprintf("many_ports_single_remote_ports_%d", feature.UniqueDstPorts)
		}
	}
	tcpTopRemoteShare, _, tcpEvidenceMode := tcpBehaviorEvidenceFromFeature(feature)
	if !feature.TCPRemoteEvidenceApproximate && tcpEvidenceMode == "dominant_remote" &&
		tcpTopRemoteShare >= sc.threshHigh(0.90) && feature.TCPCount >= sc.scaleIntHigh(200) &&
		feature.TCPUnrepliedRatio >= sc.ratioThresh(0.60) {
		return true, "outbound_single_remote_flood", fmt.Sprintf("dominant_remote_share_%.2f", tcpTopRemoteShare)
	}
	if feature.UnrepliedRatio >= sc.ratioThresh(0.60) &&
		anoms.Flows >= sc.anomThresh(0.80) && anoms.Remotes >= sc.anomThresh(0.80) && feature.UniqueRemotes >= sc.scaleIntHigh(30) {
		return true, "outbound_distributed_fanout_unreplied", "deviation_from_baseline"
	}
	return false, "", ""
}
func (cm *ConntrackManager) classifyInboundExposure(feature BehaviorFeature, sc behaviorScaler) (bool, string, string) {
	if feature.Direction != "inbound" {
		return false, "", ""
	}
	if feature.AdminPortFlows <= 0 {
		return false, "", ""
	}
	if feature.AdminUniqueRemotes <= 0 {
		return false, "", ""
	}
	adminTop := isAdminExposurePort(feature.AdminTopDstPort)
	adminRatio := float64(feature.AdminPortFlows) / float64(maxInt(1, feature.Flows))
	if !adminTop && adminRatio < sc.threshHigh(0.50) {
		return false, "", ""
	}
	failedAdminVolume := feature.AdminPortFlows >= sc.scaleIntHigh(10) && feature.AdminUnrepliedRatio >= sc.ratioThresh(0.60)
	if feature.AdminNewRemotes >= sc.scaleIntHigh(10) || feature.AdminUniqueRemotes >= sc.scaleIntHigh(20) || failedAdminVolume {
		port := feature.AdminTopDstPort
		if !adminTop {
			port = 0
		}
		return true, "inbound_admin_port_exposure_suspected", fmt.Sprintf("admin_flows_%d_admin_ratio_%.2f_port_%d_public_remotes_%d", feature.AdminPortFlows, adminRatio, port, feature.AdminUniqueRemotes)
	}
	return false, "", ""
}
func (cm *ConntrackManager) classifyInboundAttackPatterns(feature BehaviorFeature, sc behaviorScaler) (bool, string, string) {
	if feature.Direction != "inbound" {
		return false, "", ""
	}
	if feature.Flows < sc.scaleIntHigh(20) {
		return false, "", ""
	}
	if feature.UDPCount >= sc.scaleIntHigh(100) && feature.UDPUnrepliedRatio >= sc.ratioThresh(0.90) {
		signal := "inbound_udp_flood_suspected"
		_, _, udpEvidenceMode := udpBehaviorEvidenceFromFeature(feature)
		if !feature.UDPRemoteEvidenceApproximate && udpEvidenceMode == "dominant_port" {
			signal = "inbound_udp_targeted_flood_suspected"
		}
		return true, signal, fmt.Sprintf("udp_unreplied_spike_count_%d", feature.UDPCount)
	}

	_, _, evidenceMode := behaviorEvidenceFromFeature(feature)
	if feature.UnrepliedRatio >= sc.ratioThresh(0.60) {
		if feature.NewRemotes >= sc.scaleIntHigh(20) && feature.UniqueDstPorts <= sc.scaleIntLow(4) {
			if evidenceMode == "dominant_port" {
				return true, "inbound_service_spray_suspected", "rapid_new_remote_ips"
			}
			return true, "inbound_distributed_probe_suspected", "rapid_new_remote_ips"
		}
		if evidenceMode == "dominant_remote" && feature.UniqueDstPorts >= sc.scaleIntHigh(10) {
			return true, "inbound_single_remote_multiport_probe_suspected", fmt.Sprintf("many_ports_single_remote_ports_%d", feature.UniqueDstPorts)
		}
	}
	tcpTopRemoteShare, _, tcpEvidenceMode := tcpBehaviorEvidenceFromFeature(feature)
	if !feature.TCPRemoteEvidenceApproximate && tcpEvidenceMode == "dominant_remote" &&
		tcpTopRemoteShare >= sc.threshHigh(0.90) && feature.TCPCount >= sc.scaleIntHigh(200) &&
		feature.TCPUnrepliedRatio >= sc.ratioThresh(0.60) {
		return true, "inbound_single_remote_flood", fmt.Sprintf("dominant_remote_share_%.2f", tcpTopRemoteShare)
	}
	return false, "", ""
}
func (cm *ConntrackManager) classifyCapacityAndFlood(feature BehaviorFeature, hostImpact float64, sc behaviorScaler) (bool, string, string) {
	if feature.ThresholdFlows > 0 && feature.Flows > sc.scaleIntHigh(2*feature.ThresholdFlows) {
		return true, "conntrack_flow_limit_exceeded", fmt.Sprintf("2x_configured_threshold_%d", feature.ThresholdFlows)
	}

	pressureFlows := feature.Flows
	if feature.InstanceFlowTotal > 0 {
		if !feature.HostPressureOwner {
			return false, "", ""
		}
		pressureFlows = feature.InstanceFlowTotal
	}
	if hostImpact > sc.threshHigh(0.10) && pressureFlows > sc.scaleIntHigh(200) {
		signal := "host_conntrack_pressure"
		reason := fmt.Sprintf("host_table_impact_%.2f%%", hostImpact*100)

		if feature.ICMPCount > sc.scaleIntHigh(50) {
			signal = "host_icmp_flood_suspected"
		} else if feature.MulticastCount > sc.scaleIntHigh(50) {
			signal = "host_multicast_storm_suspected"
		} else if feature.Direction == "inbound" {
			signal = "inbound_conntrack_pressure"
		} else if feature.ConntrackAcct && feature.UnrepliedRatio < sc.ratioUpperBound(0.2) {
			lowBytes := feature.BytesPerFlowAvailable && feature.BytesPerFlow < sc.threshLow(float64(lowThroughputBytesPerFlow))
			lowPackets := feature.PacketsPerFlowAvailable && feature.PacketsPerFlow < sc.threshLow(float64(lowThroughputPacketsPerFlow))
			highBytes := feature.BytesPerFlowAvailable && feature.BytesPerFlow > sc.threshHigh(float64(heavyThroughputBytesPerFlow))
			highPackets := feature.PacketsPerFlowAvailable && feature.PacketsPerFlow > sc.threshHigh(float64(heavyThroughputPacketsPerFlow))
			if lowBytes || lowPackets {
				signal = "host_accumulating_stale_flows"
				reason = "low_throughput_high_count"
			} else if highBytes || highPackets {
				signal = "host_high_throughput_anomaly"
				reason = "high_bytes_per_flow"
			}
		}

		return true, signal, reason
	}

	return false, "", ""
}
