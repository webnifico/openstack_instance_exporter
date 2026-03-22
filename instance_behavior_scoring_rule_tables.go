package main

import (
	"fmt"
)

func ruleDirMatch(ruleDir, featureDir string) bool {
	if ruleDir == "" || ruleDir == "any" {
		return true
	}
	return ruleDir == featureDir
}
func evalRules(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx, tables ...[]BehaviorRule) (hit bool, ruleID, kind, reason, source string) {
	for _, t := range tables {
		for _, r := range t {
			if !ruleDirMatch(r.Dir, feature.Direction) {
				continue
			}
			if r.When != nil && !r.When(feature, sc, ev, ctx) {
				continue
			}
			k := ""
			if r.Kind != nil {
				k = r.Kind(feature, sc, ev, ctx)
			}
			rsn := ""
			if r.Reason != nil {
				rsn = r.Reason(feature, sc, ev, ctx)
			}
			return true, r.ID, k, rsn, r.Source
		}
	}
	return false, "", "", "", ""
}
func topPortIs(feature BehaviorFeature, ports ...uint16) bool {
	p := feature.TopDstPort
	for _, x := range ports {
		if p == x {
			return true
		}
	}
	return false
}

var rulesRestrictedLocal = []BehaviorRule{
	{
		ID:     "restricted_bgp",
		Dir:    "outbound",
		Source: "internal",
		When: func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) bool {
			return feature.BGPFlows > 0
		},
		Kind: func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) string {
			return "bgp_peering_attempt"
		},
		Reason: func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) string {
			return "dst_port_179_seen"
		},
	},
	{
		ID:     "restricted_geneve",
		Dir:    "outbound",
		Source: "internal",
		When: func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) bool {
			return feature.GeneveFlows > 0
		},
		Kind: func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) string {
			return "geneve_underlay_attempt"
		},
		Reason: func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) string {
			return "dst_port_6081_seen"
		},
	},
	{
		ID:     "restricted_metadata_hammer",
		Dir:    "outbound",
		Source: "internal",
		When: func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) bool {
			return feature.MetadataHits >= sc.scaleIntHigh(ctx.Thresholds.MetadataHammerHits)
		},
		Kind: func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) string {
			return "metadata_service_hammering"
		},
		Reason: func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) string {
			return fmt.Sprintf("flows_%d_unreplied_%.2f", feature.MetadataHits, feature.MetadataUnrepliedRatio)
		},
	},
	{
		ID:     "restricted_metadata_probe",
		Dir:    "outbound",
		Source: "internal",
		When: func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) bool {
			return feature.MetadataHits >= sc.scaleIntHigh(ctx.Thresholds.MetadataProbeHits) && feature.MetadataUnrepliedRatio >= sc.ratioThresh(ctx.Thresholds.MetadataProbeUnreplied)
		},
		Kind: func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) string {
			return "metadata_probe_suspected"
		},
		Reason: func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) string {
			return fmt.Sprintf("flows_%d_unreplied_%.2f", feature.MetadataHits, feature.MetadataUnrepliedRatio)
		},
	},
	{
		ID:     "restricted_local_scan",
		Dir:    "outbound",
		Source: "internal",
		When: func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) bool {
			return feature.LocalScanHits > 0
		},
		Kind: func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) string {
			return "restricted_network_probe"
		},
		Reason: func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) string {
			return "traffic_to_host_or_link_local"
		},
	},
	{
		ID:     "restricted_lateral_probe",
		Dir:    "outbound",
		Source: "internal",
		When: func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) bool {
			if feature.InfraHits <= 0 || feature.Flows <= 0 {
				return false
			}
			if feature.UnrepliedRatio < sc.ratioThresh(ctx.Thresholds.InfraLateralUnreplied) {
				return false
			}
			return float64(feature.InfraMaxFlows) >= sc.threshHigh(float64(feature.Flows)*ctx.Thresholds.InfraLateralShareOfTotal)
		},
		Kind: func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) string {
			return "lateral_probe_suspected"
		},
		Reason: func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) string {
			return "high_unreplied_local_flows"
		},
	},
	{
		ID:     "restricted_infra_probe",
		Dir:    "outbound",
		Source: "internal",
		When: func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) bool {
			return feature.InfraHits > 0
		},
		Kind: func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) string {
			return "restricted_network_probe"
		},
		Reason: func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) string {
			return "traffic_to_infrastructure"
		},
	},
}
var rulesDarkspace = []BehaviorRule{
	{
		ID:     "darkspace_unreplied",
		Dir:    "any",
		Source: "internal",
		When: func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) bool {
			return feature.UnmonitoredPortFlows > 0 &&
				feature.UnrepliedRatio >= sc.ratioThresh(ctx.Thresholds.DarkUnreplied) &&
				feature.UnmonitoredPortFlows >= sc.scaleIntHigh(ctx.Thresholds.DarkFlowsWithUnreplied)
		},
		Kind: func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) string {
			if feature.Direction == "inbound" {
				return "inbound_darkspace_port_detected"
			}
			return "darkspace_port_detected"
		},
		Reason: func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) string {
			return fmt.Sprintf("unmonitored_flows_%d_unreplied_%.2f", feature.UnmonitoredPortFlows, feature.UnrepliedRatio)
		},
	},
	{
		ID:     "darkspace_total",
		Dir:    "any",
		Source: "internal",
		When: func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) bool {
			return feature.UnmonitoredPortFlows > 0 && feature.UnmonitoredPortFlows >= sc.scaleIntHigh(ctx.Thresholds.DarkFlowsTotal)
		},
		Kind: func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) string {
			if feature.Direction == "inbound" {
				return "inbound_darkspace_port_detected"
			}
			return "darkspace_port_detected"
		},
		Reason: func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) string {
			return fmt.Sprintf("unmonitored_flows_%d", feature.UnmonitoredPortFlows)
		},
	},
}
var rulesProtocol = []BehaviorRule{
	{
		ID:     "proto_smtp_spam",
		Dir:    "outbound",
		Source: "internal",
		When: func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) bool {
			if feature.SMTPFlows < sc.scaleIntHigh(ctx.Thresholds.SMTPFlows) {
				return false
			}
			if !topPortIs(feature, 25, 465, 587) {
				return false
			}
			if feature.UniqueRemotes < sc.scaleIntHigh(ctx.Thresholds.SMTPRemotes) {
				return false
			}
			if feature.UnrepliedRatio < sc.ratioThresh(ctx.Thresholds.SMTPUnreplied) {
				return false
			}
			return ev.EvidenceMode == "dominant_port" || ev.TopPortShare >= sc.threshHigh(ctx.Thresholds.SMTPPortDominanceShare)
		},
		Kind: func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) string {
			return "smtp_spam_behavior_suspected"
		},
		Reason: func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) string {
			return fmt.Sprintf("smtp_flows_%d_remotes_%d_unreplied_%.2f", feature.SMTPFlows, feature.UniqueRemotes, feature.UnrepliedRatio)
		},
	},
	{
		ID:     "proto_stratum_mining",
		Dir:    "outbound",
		Source: "internal",
		When: func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) bool {
			if feature.StratumFlows < sc.scaleIntHigh(ctx.Thresholds.StratumFlows) {
				return false
			}
			if !topPortIs(feature, 3333, 4444, 8333) {
				return false
			}
			return feature.UniqueRemotes <= sc.scaleIntHigh(ctx.Thresholds.StratumMaxRemotes)
		},
		Kind: func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) string {
			return "outbound_stratum_mining_suspected"
		},
		Reason: func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) string {
			return fmt.Sprintf("stratum_flows_%d_port_%d_remotes_%d", feature.StratumFlows, feature.TopDstPort, feature.UniqueRemotes)
		},
	},
	{
		ID:     "proto_dns_tunnel",
		Dir:    "outbound",
		Source: "internal",
		When: func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) bool {
			if !feature.ConntrackAcct || feature.BytesPerFlow <= 0 {
				return false
			}
			if feature.TopDstPort != 53 {
				return false
			}
			if feature.UDPCount <= sc.scaleIntHigh(ctx.Thresholds.DNSMinUDP) {
				return false
			}
			if feature.BytesPerFlow <= sc.threshHigh(ctx.Thresholds.DNSMinBytesPerFlow) {
				return false
			}
			return feature.UnrepliedRatio >= sc.ratioThresh(ctx.Thresholds.DNSUnreplied)
		},
		Kind: func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) string {
			return "outbound_dns_tunneling_suspected"
		},
		Reason: func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) string {
			return fmt.Sprintf("port_53_avg_bytes_%.0f_udp_%d_unreplied_%.2f", feature.BytesPerFlow, feature.UDPCount, feature.UnrepliedRatio)
		},
	},
	{
		ID:     "proto_udp_fanout",
		Dir:    "outbound",
		Source: "internal",
		When: func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) bool {
			return feature.UDPCount > sc.scaleIntHigh(ctx.Thresholds.UDPFanoutUDP) &&
				feature.UnrepliedRatio >= sc.ratioThresh(ctx.Thresholds.UDPFanoutUnreplied) &&
				feature.UniqueRemotes >= sc.scaleIntHigh(ctx.Thresholds.UDPFanoutRemotes)
		},
		Kind: func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) string {
			return "outbound_udp_fanout_suspected"
		},
		Reason: func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) string {
			return fmt.Sprintf("remotes_%d_unreplied_%.2f", feature.UniqueRemotes, feature.UnrepliedRatio)
		},
	},
}

var defaultRuleThresholds = RuleThresholds{
	MetadataHammerHits:       100,
	MetadataProbeHits:        30,
	MetadataProbeUnreplied:   0.60,
	InfraLateralUnreplied:    0.80,
	InfraLateralShareOfTotal: 0.30,

	DarkUnreplied:          0.80,
	DarkFlowsWithUnreplied: 20,
	DarkFlowsTotal:         50,

	SMTPFlows:              50,
	SMTPRemotes:            20,
	SMTPUnreplied:          0.30,
	SMTPPortDominanceShare: 0.70,

	StratumFlows:      2,
	StratumMaxRemotes: 10,

	DNSMinUDP:          10,
	DNSMinBytesPerFlow: 3000,
	DNSUnreplied:       0.60,

	UDPFanoutUDP:       100,
	UDPFanoutUnreplied: 0.90,
	UDPFanoutRemotes:   50,
}
