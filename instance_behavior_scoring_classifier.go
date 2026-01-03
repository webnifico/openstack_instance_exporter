package main

import (
	"fmt"
	"math"
)

func newBehaviorScaler(sens float64) behaviorScaler {
	if sens <= 0 {
		sens = 1.0
	}
	return behaviorScaler{sens: sens}
}
func (s behaviorScaler) scaleIntHigh(v int) int {
	if v <= 0 {
		return v
	}
	t := int(math.Ceil(float64(v) / s.sens))
	if t < 1 {
		t = 1
	}
	return t
}
func (s behaviorScaler) scaleIntLow(v int) int {
	if v <= 0 {
		return v
	}
	t := int(math.Ceil(float64(v) * s.sens))
	if t < 1 {
		t = 1
	}
	return t
}
func (s behaviorScaler) threshHigh(v float64) float64 {
	return v / s.sens
}
func (s behaviorScaler) threshLow(v float64) float64 {
	return v * s.sens
}
func (s behaviorScaler) ratioThresh(base float64) float64 {
	t := 0.5 + (base-0.5)/s.sens
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
func (cm *ConntrackManager) classifyBehavior(feature *BehaviorFeature, hostImpact float64, anoms behaviorAnomalies) (bool, string, string, string, string) {
	sc := newBehaviorScaler(cm.behaviorSensitivity)
	ev := buildBehaviorEvidence(*feature)
	ctx := &RuleCtx{Thresholds: defaultRuleThresholds}

	restrictedHit, restrictedRuleID, restrictedKind, restrictedReason, restrictedSource := evalRules(*feature, sc, ev, ctx, rulesRestrictedLocal)
	if restrictedHit {
		return true, restrictedKind, restrictedReason, restrictedRuleID, restrictedSource
	}

	darkHit, darkRuleID, darkKind, darkReason, darkSource := evalRules(*feature, sc, ev, ctx, rulesDarkspace)
	scanHit, scanKind, scanReason := cm.classifyOutboundScanning(*feature, anoms, sc)
	protoHit, protoRuleID, protoKind, protoReason, protoSource := evalRules(*feature, sc, ev, ctx, rulesProtocol)

	feature.SynergyDarkScan = darkHit && scanHit
	feature.SynergyDarkPhysics = darkHit && protoHit

	if darkHit && protoHit {
		return true, "darkspace_plus_physics", darkReason + " | " + protoReason, "synergy_darkspace_plus_physics", "internal"
	}
	if darkHit && scanHit {
		return true, "darkspace_plus_scan", darkReason + " | " + scanReason, "synergy_darkspace_plus_scan", "internal"
	}
	if darkHit {
		return true, darkKind, darkReason, darkRuleID, darkSource
	}
	if scanHit {
		return true, scanKind, scanReason, "legacy_scan", "internal"
	}
	if protoHit {
		return true, protoKind, protoReason, protoRuleID, protoSource
	}
	if hit, kind, reason := cm.classifyCapacityAndFlood(*feature, hostImpact, sc); hit {
		return true, kind, reason, "legacy_capacity_and_flood", "internal"
	}
	if hit, kind, reason := cm.classifyEWMABands(*feature, anoms, sc); hit {
		return true, kind, reason, "legacy_ewma_bands", "internal"
	}

	externalRules := cm.externalBehaviorRules
	if len(externalRules) > 0 {
		extHit, extRuleID, extKind, extReason, extSource := evalRules(*feature, sc, ev, ctx, externalRules)
		if extHit {
			return true, extKind, extReason, extRuleID, extSource
		}
	}

	return false, "", "", "", ""
}
func (cm *ConntrackManager) classifyOutboundScanning(feature BehaviorFeature, anoms behaviorAnomalies, sc behaviorScaler) (bool, string, string) {
	if feature.Direction != "outbound" {
		return false, "", ""
	}
	if feature.Flows < sc.scaleIntHigh(20) {
		return false, "", ""
	}
	if feature.UnrepliedRatio < sc.ratioThresh(0.60) {
		return false, "", ""
	}

	topRemoteShare, _, evidenceMode := behaviorEvidenceFromFeature(feature)
	if evidenceMode == "dominant_port" && feature.UniqueRemotes >= sc.scaleIntHigh(20) && feature.TopDstPort != 0 {
		return true, "outbound_horizontal_scan_suspected", fmt.Sprintf("many_remotes_single_port_unreplied_ratio_%.2f", feature.UnrepliedRatio)
	}
	if evidenceMode == "dominant_remote" && feature.UniqueDstPorts >= sc.scaleIntHigh(20) {
		return true, "outbound_vertical_scan_suspected", fmt.Sprintf("many_ports_single_remote_ports_%d", feature.UniqueDstPorts)
	}
	if evidenceMode == "dominant_remote" && topRemoteShare >= sc.threshHigh(0.90) && feature.Flows >= sc.scaleIntHigh(200) {
		return true, "outbound_single_remote_flood", fmt.Sprintf("dominant_remote_share_%.2f", topRemoteShare)
	}
	if anoms.Signal >= sc.anomThresh(0.80) && feature.UniqueRemotes >= sc.scaleIntHigh(30) {
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
	if feature.PublicRemotes <= 0 {
		return false, "", ""
	}
	adminTop := isAdminExposurePort(feature.TopDstPort)
	adminRatio := float64(feature.AdminPortFlows) / float64(maxInt(1, feature.Flows))
	if !adminTop && adminRatio < sc.threshHigh(0.50) {
		return false, "", ""
	}
	if feature.NewRemotes >= sc.scaleIntHigh(10) || feature.UniqueRemotes >= sc.scaleIntHigh(20) || feature.UnrepliedRatio >= sc.ratioThresh(0.60) {
		port := feature.TopDstPort
		if !adminTop {
			port = 0
		}
		return true, "inbound_admin_port_exposure_suspected", fmt.Sprintf("admin_flows_%d_admin_ratio_%.2f_port_%d_public_remotes_%d", feature.AdminPortFlows, adminRatio, port, feature.PublicRemotes)
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
	if feature.UnrepliedRatio < sc.ratioThresh(0.60) {
		return false, "", ""
	}

	topRemoteShare, _, evidenceMode := behaviorEvidenceFromFeature(feature)
	if feature.NewRemotes >= sc.scaleIntHigh(20) && feature.UniqueDstPorts <= sc.scaleIntHigh(4) {
		if evidenceMode == "dominant_port" {
			return true, "inbound_service_spray_suspected", "rapid_new_remote_ips"
		}
		return true, "inbound_distributed_probe_suspected", "rapid_new_remote_ips"
	}
	if evidenceMode == "dominant_remote" && feature.UniqueDstPorts >= sc.scaleIntHigh(10) {
		return true, "inbound_single_remote_multiport_probe_suspected", fmt.Sprintf("many_ports_single_remote_ports_%d", feature.UniqueDstPorts)
	}
	if evidenceMode == "dominant_remote" && topRemoteShare >= sc.threshHigh(0.90) && feature.Flows >= sc.scaleIntHigh(200) {
		return true, "inbound_single_remote_flood", fmt.Sprintf("dominant_remote_share_%.2f", topRemoteShare)
	}
	if feature.UDPCount >= sc.scaleIntHigh(100) && feature.UnrepliedRatio >= sc.ratioThresh(0.90) {
		kind := "inbound_udp_flood_suspected"
		if evidenceMode == "dominant_port" {
			kind = "inbound_udp_targeted_flood_suspected"
		}
		return true, kind, fmt.Sprintf("udp_unreplied_spike_count_%d", feature.UDPCount)
	}
	return false, "", ""
}
func (cm *ConntrackManager) classifyCapacityAndFlood(feature BehaviorFeature, hostImpact float64, sc behaviorScaler) (bool, string, string) {
	if feature.ThresholdFlows > 0 && feature.Flows > sc.scaleIntHigh(2*feature.ThresholdFlows) {
		return true, "conntrack_flow_limit_exceeded", fmt.Sprintf("2x_configured_threshold_%d", feature.ThresholdFlows)
	}

	if hostImpact > sc.threshHigh(0.10) && feature.Flows > sc.scaleIntHigh(200) {
		kind := "host_conntrack_pressure"
		reason := fmt.Sprintf("host_table_impact_%.2f%%", hostImpact*100)

		if feature.ICMPCount > sc.scaleIntHigh(50) {
			kind = "host_icmp_flood_suspected"
		} else if feature.MulticastCount > sc.scaleIntHigh(50) {
			kind = "host_multicast_storm_suspected"
		} else if feature.Direction == "inbound" {
			kind = "inbound_conntrack_pressure"
		} else if feature.ConntrackAcct && feature.UnrepliedRatio < sc.ratioThresh(0.2) {
			if (feature.BytesPerFlow > 0 && feature.BytesPerFlow < sc.threshLow(float64(lowThroughputBytesPerFlow))) || (feature.PacketsPerFlow > 0 && feature.PacketsPerFlow < sc.threshLow(float64(lowThroughputPacketsPerFlow))) {
				kind = "host_accumulating_stale_flows"
				reason = "low_throughput_high_count"
			} else if feature.BytesPerFlow > sc.threshHigh(float64(heavyThroughputBytesPerFlow)) || feature.PacketsPerFlow > sc.threshHigh(float64(heavyThroughputPacketsPerFlow)) {
				kind = "host_high_throughput_anomaly"
				reason = "high_bytes_per_flow"
			}
		}

		return true, kind, reason
	}

	return false, "", ""
}
func (cm *ConntrackManager) classifyEWMABands(feature BehaviorFeature, anoms behaviorAnomalies, sc behaviorScaler) (bool, string, string) {
	if feature.Flows < sc.scaleIntHigh(10) {
		return false, "", ""
	}

	prefix := "behavior_spike"
	switch feature.Direction {
	case "inbound":
		prefix = "inbound_behavior_spike"
	case "outbound":
		prefix = "outbound_behavior_spike"
	}

	if anoms.Signal >= sc.anomThresh(0.90) {
		return true, prefix + "_critical_suspected", fmt.Sprintf("signal_%.2f", anoms.Signal)
	}
	if anoms.Signal >= sc.anomThresh(0.80) {
		return true, prefix + "_high_suspected", fmt.Sprintf("signal_%.2f", anoms.Signal)
	}
	if anoms.Signal >= sc.anomThresh(0.65) {
		return true, prefix + "_medium_suspected", fmt.Sprintf("signal_%.2f", anoms.Signal)
	}
	if anoms.Signal >= sc.anomThresh(0.50) {
		return true, prefix + "_low_suspected", fmt.Sprintf("signal_%.2f", anoms.Signal)
	}

	return false, "", ""
}
