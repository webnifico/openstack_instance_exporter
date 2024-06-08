package main

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/yaml.v3"
)

const (
	maxRemoteMapSize = 5000
	maxPortMapSize   = 2048
	remoteHistoryCap = 2048
	portHistoryCap   = 2048

	behaviorIdentityTTLSeconds int64 = 2 * 60 * 60

	behaviorPrevKeyTTLSeconds int64 = 24 * 60 * 60

	behaviorAlertCooldownSeconds  int64 = 180  //3m
	behaviorAlertHeartbeatSeconds int64 = 7200 //2h

	behaviorEWMATauFastDefaultSeconds float64 = 180
	behaviorEWMATauSlowDefaultSeconds float64 = 600

	lowThroughputBytesPerFlow     = 1000
	heavyThroughputBytesPerFlow   = 100000
	lowThroughputPacketsPerFlow   = 10
	heavyThroughputPacketsPerFlow = 100
)

type behaviorAnomalies struct {
	Flows          float64
	Remotes        float64
	Ports          float64
	Unreplied      float64
	BytesPerFlow   float64
	PacketsPerFlow float64
	Signal         float64
}

func behaviorHistoryCaps(sens float64) (int, int) {
	if sens <= 0 {
		sens = 1.0
	}
	remote := int(math.Round(float64(remoteHistoryCap) * sens))
	port := int(math.Round(float64(portHistoryCap) * sens))
	if remote < 256 {
		remote = 256
	}
	if port < 256 {
		port = 256
	}
	if remote > maxRemoteMapSize {
		remote = maxRemoteMapSize
	}
	if port > maxPortMapSize {
		port = maxPortMapSize
	}
	return remote, port
}

func newBehaviorStats(trackAcct bool) *behaviorStats {
	return &behaviorStats{
		trackAcct:          trackAcct,
		remotes:            make(map[IPKey]struct{}),
		remoteZones:        make(map[IPKey]uint16),
		remoteIsPrivate:    make(map[IPKey]bool),
		perRemote:          make(map[IPKey]int),
		perRemoteUnreplied: make(map[IPKey]int),
		dstPorts:           make(map[uint16]struct{}),
		perDstPort:         make(map[uint16]int),
	}
}

func (b *behaviorStats) updateDetailed(remote IPKey, port uint16, proto uint8, status uint32, zone uint16, bytes uint64, packets uint64) {
	b.flows++
	if b.trackAcct {
		b.bytes += bytes
		b.packets += packets
	}

	unreplied := (status&IPS_SEEN_REPLY) == 0 && (status&IPS_ASSURED) == 0
	if unreplied {
		b.unreplied++
	}

	if len(b.remotes) < maxRemoteMapSize {
		if _, exists := b.remotes[remote]; !exists {
			b.remotes[remote] = struct{}{}
			b.remoteIsPrivate[remote] = isPrivateOrLocalKey(remote)
		}
		b.remoteZones[remote] = zone
		b.perRemote[remote]++
		if unreplied {
			b.perRemoteUnreplied[remote]++
		}
	} else {
		b.remoteMapCapped = true
		if _, exists := b.remotes[remote]; exists {
			b.perRemote[remote]++
			if unreplied {
				b.perRemoteUnreplied[remote]++
			}
		}
	}

	if port != 0 {
		if len(b.dstPorts) < maxPortMapSize {
			b.dstPorts[port] = struct{}{}
			b.perDstPort[port]++
		} else {
			b.portMapCapped = true
			if _, exists := b.dstPorts[port]; exists {
				b.perDstPort[port]++
			}
		}
	}

	if isMulticastKey(remote) {
		b.multicastCount++
	}
	if proto == 1 || proto == 58 {
		b.icmpCount++
	}
	if proto == 17 {
		b.udpCount++
	}

	if !b.sampleRemoteSet {
		b.sampleRemote = remote
		b.sampleRemoteSet = true
		if port != 0 {
			b.sampleDstPort = port
		}
	}
}

func sampleIPKeySetDeterministic(in map[IPKey]struct{}, limit int) map[IPKey]struct{} {
	if limit <= 0 || len(in) == 0 {
		return map[IPKey]struct{}{}
	}
	keys := make([]IPKey, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return bytes.Compare(keys[i][:], keys[j][:]) < 0
	})
	n := len(keys)
	if n > limit {
		n = limit
	}
	out := make(map[IPKey]struct{}, n)
	for i := 0; i < n; i++ {
		out[keys[i]] = struct{}{}
	}
	return out
}

func samplePortSetDeterministic(in map[uint16]struct{}, limit int) map[uint16]struct{} {
	if limit <= 0 || len(in) == 0 {
		return map[uint16]struct{}{}
	}
	ports := make([]int, 0, len(in))
	for p := range in {
		ports = append(ports, int(p))
	}
	sort.Ints(ports)
	n := len(ports)
	if n > limit {
		n = limit
	}
	out := make(map[uint16]struct{}, n)
	for i := 0; i < n; i++ {
		out[uint16(ports[i])] = struct{}{}
	}
	return out
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func sumPortCounts(m map[uint16]int, ports ...uint16) int {
	s := 0
	for _, p := range ports {
		s += m[p]
	}
	return s
}

func isAdminExposurePort(p uint16) bool {
	switch p {
	case 22, 3389, 5900, 2375, 6443, 10250, 2379, 9200, 27017, 6379, 445, 3306, 5432, 8888:
		return true
	default:
		return false
	}
}

func behaviorEvidenceMode(topRemoteShare, topPortShare float64) string {
	if topRemoteShare >= 0.60 && topRemoteShare >= topPortShare {
		return "dominant_remote"
	}
	if topPortShare >= 0.60 && topPortShare > topRemoteShare {
		return "dominant_port"
	}
	if topRemoteShare < 0.40 && topPortShare < 0.40 {
		return "distributed"
	}
	return "mixed"
}

func behaviorEvidenceFromFeature(feature BehaviorFeature) (topRemoteShare, topPortShare float64, mode string) {
	flows := maxInt(1, feature.Flows)
	topRemoteShare = float64(feature.MaxSingleRemote) / float64(flows)
	topPortShare = float64(feature.MaxSingleDstPort) / float64(flows)
	mode = behaviorEvidenceMode(topRemoteShare, topPortShare)
	return
}

type BehaviorEvidence struct {
	TopRemoteShare float64
	TopPortShare   float64
	EvidenceMode   string
}

func buildBehaviorEvidence(feature BehaviorFeature) BehaviorEvidence {
	topRemoteShare, topPortShare, mode := behaviorEvidenceFromFeature(feature)
	return BehaviorEvidence{
		TopRemoteShare: topRemoteShare,
		TopPortShare:   topPortShare,
		EvidenceMode:   mode,
	}
}

type RuleThresholds struct {
	MetadataHammerHits       int
	MetadataProbeHits        int
	MetadataProbeUnreplied   float64
	InfraLateralUnreplied    float64
	InfraLateralShareOfTotal float64

	DarkUnreplied          float64
	DarkFlowsWithUnreplied int
	DarkFlowsTotal         int

	SMTPFlows              int
	SMTPRemotes            int
	SMTPUnreplied          float64
	SMTPPortDominanceShare float64

	StratumFlows      int
	StratumMaxRemotes int

	DNSMinUDP          int
	DNSMinBytesPerFlow float64
	DNSUnreplied       float64

	UDPFanoutUDP       int
	UDPFanoutUnreplied float64
	UDPFanoutRemotes   int
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

type RuleCtx struct {
	Thresholds RuleThresholds
}

type BehaviorRule struct {
	ID     string
	Dir    string
	When   func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) bool
	Kind   func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) string
	Reason func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) string
	Source string
}

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

const maxExternalBehaviorRules = 100

type externalBehaviorRulesFile struct {
	PortSets map[string][]int          `yaml:"port_sets"`
	Rules    []externalBehaviorRuleYML `yaml:"rules"`
}

type externalBehaviorRuleYML struct {
	ID        string `yaml:"id"`
	Direction string `yaml:"direction"`
	PortSet   string `yaml:"port_set"`
	Ports     []int  `yaml:"ports"`

	FlowsMin         int `yaml:"flows_min"`
	UniqueRemotesMin int `yaml:"unique_remotes_min"`

	Ratios struct {
		Unreplied float64 `yaml:"unreplied"`
	} `yaml:"ratios"`

	EvidenceMode      string  `yaml:"evidence_mode"`
	TopRemoteShareMin float64 `yaml:"top_remote_share_min"`
	TopPortShareMin   float64 `yaml:"top_port_share_min"`

	Kind   string `yaml:"kind"`
	Reason string `yaml:"reason"`
}

type BehaviorRulesConfigStatus struct {
	Status   string
	Path     string
	Rules    int
	PortSets int
	Err      string
}

func LoadBehaviorExternalRules(path string) ([]BehaviorRule, BehaviorRulesConfigStatus) {
	st := BehaviorRulesConfigStatus{Status: "not_configured", Path: path}
	if path == "" {
		return nil, st
	}

	b, err := os.ReadFile(path)
	if err != nil {
		st.Status = "error"
		st.Err = err.Error()
		return nil, st
	}

	var rf externalBehaviorRulesFile
	if err := yaml.Unmarshal(b, &rf); err != nil {
		st.Status = "error"
		st.Err = err.Error()
		return nil, st
	}

	portSets := make(map[string]map[uint16]struct{}, len(rf.PortSets))
	for name, ports := range rf.PortSets {
		set := make(map[uint16]struct{}, len(ports))
		for _, pi := range ports {
			if pi <= 0 || pi > 65535 {
				continue
			}
			set[uint16(pi)] = struct{}{}
		}
		if len(set) > 0 {
			portSets[name] = set
		}
	}
	var compiled []BehaviorRule
	for i, r := range rf.Rules {
		if len(compiled) >= maxExternalBehaviorRules {
			logKV(LogLevelNotice, "behavior", "behavior_rules_yaml_truncated", "path", path, "max_rules", maxExternalBehaviorRules)
			break
		}
		if r.ID == "" {
			logKV(LogLevelNotice, "behavior", "behavior_rules_yaml_bad_rule", "path", path, "index", i, "error", "missing id")
			continue
		}
		if r.Kind == "" {
			logKV(LogLevelNotice, "behavior", "behavior_rules_yaml_bad_rule", "path", path, "rule_id", r.ID, "error", "missing kind")
			continue
		}
		dir := r.Direction
		if dir == "" {
			dir = "any"
		}
		if dir != "any" && dir != "inbound" && dir != "outbound" {
			logKV(LogLevelNotice, "behavior", "behavior_rules_yaml_bad_rule", "path", path, "rule_id", r.ID, "error", "invalid direction")
			continue
		}

		portSet := map[uint16]struct{}{}
		if r.PortSet != "" {
			ps, ok := portSets[r.PortSet]
			if !ok {
				logKV(LogLevelNotice, "behavior", "behavior_rules_yaml_bad_rule", "path", path, "rule_id", r.ID, "error", "unknown port_set")
				continue
			}
			for p := range ps {
				portSet[p] = struct{}{}
			}
		}
		for _, pi := range r.Ports {
			if pi <= 0 || pi > 65535 {
				continue
			}
			portSet[uint16(pi)] = struct{}{}
		}
		if len(portSet) == 0 {
			logKV(LogLevelNotice, "behavior", "behavior_rules_yaml_bad_rule", "path", path, "rule_id", r.ID, "error", "no ports specified")
			continue
		}

		flowsMin := r.FlowsMin
		if flowsMin < 0 {
			flowsMin = 0
		}
		remotesMin := r.UniqueRemotesMin
		if remotesMin < 0 {
			remotesMin = 0
		}
		unrepliedMin := r.Ratios.Unreplied
		if unrepliedMin < 0 {
			unrepliedMin = 0
		}

		evMode := r.EvidenceMode
		if evMode != "" && evMode != "dominant_remote" && evMode != "dominant_port" && evMode != "distributed" && evMode != "mixed" {
			logKV(LogLevelNotice, "behavior", "behavior_rules_yaml_bad_rule", "path", path, "rule_id", r.ID, "error", "invalid evidence_mode")
			continue
		}

		topRemoteShareMin := r.TopRemoteShareMin
		topPortShareMin := r.TopPortShareMin

		kind := r.Kind
		reason := r.Reason
		if reason == "" {
			reason = "external_rule_match"
		}

		ruleID := r.ID
		compiled = append(compiled, BehaviorRule{
			ID:     ruleID,
			Dir:    dir,
			Source: "external",
			When: func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) bool {
				if !ruleDirMatch(dir, feature.Direction) {
					return false
				}
				if _, ok := portSet[feature.TopDstPort]; !ok {
					return false
				}
				if flowsMin > 0 && feature.MaxSingleDstPort < flowsMin {
					return false
				}
				if remotesMin > 0 && feature.UniqueRemotes < remotesMin {
					return false
				}
				if unrepliedMin > 0 && feature.UnrepliedRatio < unrepliedMin {
					return false
				}
				if evMode != "" && ev.EvidenceMode != evMode {
					return false
				}
				if topRemoteShareMin > 0 && ev.TopRemoteShare < topRemoteShareMin {
					return false
				}
				if topPortShareMin > 0 && ev.TopPortShare < topPortShareMin {
					return false
				}
				return true
			},
			Kind: func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) string {
				return kind
			},
			Reason: func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) string {
				return reason
			},
		})
	}

	st.Status = "loaded"
	st.Rules = len(compiled)
	st.PortSets = len(portSets)
	return compiled, st
}

type behaviorRuleLogState struct {
	LastSuppressedUnix int64
	LastSummaryUnix    int64
}

var behaviorRuleLogMu sync.Mutex
var behaviorRuleLogStateMap = map[behaviorEmitKey]*behaviorRuleLogState{}

var behaviorRuleLogEvictSeed uint64 = 1

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

type behaviorAlertEvidence struct {
	TopRemoteIP    string
	TopDstPort     uint16
	TopDstPortName string
	TopRemoteShare float64
	TopPortShare   float64
	EvidenceMode   string
}

func (cm *ConntrackManager) buildBehaviorAlertEvidence(feature BehaviorFeature, topRemoteKey IPKey, topRemoteSet bool) behaviorAlertEvidence {
	ev := behaviorAlertEvidence{
		TopDstPort:     feature.TopDstPort,
		TopDstPortName: cm.behaviorPortName(feature.Direction, feature.TopDstPort),
	}
	if topRemoteSet {
		ev.TopRemoteIP = IPKeyToString(topRemoteKey)
	}
	if feature.Flows > 0 {
		ev.TopRemoteShare = float64(feature.MaxSingleRemote) / float64(feature.Flows)
		ev.TopPortShare = float64(feature.MaxSingleDstPort) / float64(feature.Flows)
	}
	ev.TopRemoteShare = roundToFiveDecimals(ev.TopRemoteShare)
	ev.TopPortShare = roundToFiveDecimals(ev.TopPortShare)
	ev.EvidenceMode = behaviorEvidenceMode(ev.TopRemoteShare, ev.TopPortShare)
	return ev
}

func behaviorSelectAlertIPs(direction, addr string, stats *behaviorStats, kind string, hostIPs map[string]struct{}) (srcIP, dstIP string) {
	if direction == "outbound" {
		srcIP = addr
		if stats.sampleRemoteSet {
			dstIP = IPKeyToString(stats.sampleRemote)
		}

		if kind == "lateral_probe_suspected" {
			for rk := range stats.remotes {
				r := IPKeyToString(rk)
				if isPrivateOrLocalStr(r) && !isInfrastructureIP(r, hostIPs) {
					dstIP = r
					break
				}
			}
		} else if kind == "restricted_network_probe" {
			for rk := range stats.remotes {
				r := IPKeyToString(rk)
				if isInfrastructureIP(r, hostIPs) {
					dstIP = r
					break
				}
			}
		}
		return srcIP, dstIP
	}

	if stats.sampleRemoteSet {
		srcIP = IPKeyToString(stats.sampleRemote)
	}
	dstIP = addr
	return srcIP, dstIP
}

func updateAxisEWMA(a *axisEWMA, x float64, alphaFast, alphaSlow float64) {
	if !a.Initialized {
		a.Fast = x
		a.Slow = x
		a.Initialized = true
		return
	}
	a.Fast += alphaFast * (x - a.Fast)
	a.Slow += alphaSlow * (x - a.Slow)
}

func axisSpread(a *axisEWMA, minSpread float64) float64 {
	if !a.Initialized {
		return minSpread
	}
	s := math.Abs(a.Fast - a.Slow)
	if s < minSpread {
		return minSpread
	}
	return s
}

func featureAnomaly(x float64, a *axisEWMA, minSpread float64) float64 {
	if !a.Initialized {
		return 0
	}
	spread := axisSpread(a, minSpread)
	z := math.Abs(x-a.Slow) / spread
	return clamp01(z / 6.0)
}
func (cm *ConntrackManager) updateBehaviorEWMA(ident behaviorIdentityKey, feature BehaviorFeature) (float64, behaviorAnomalies) {
	idx := shardIndexBehavior(ident)
	cm.behaviorEWMAMu[idx].Lock()
	now := time.Now().Unix()

	ew, ok := cm.behaviorEWMA[idx][ident]
	if !ok {
		ew = &behaviorEWMAState{}
		cm.behaviorEWMA[idx][ident] = ew
	}
	prevSeen := ew.LastSeenUnix
	ew.LastSeenUnix = now

	dtSeconds := float64(0)
	if prevSeen > 0 {
		dtSeconds = float64(now - prevSeen)
		if dtSeconds < 1 {
			dtSeconds = 1
		}
	}
	tauFast := cm.behaviorEWMATauFast.Seconds()
	tauSlow := cm.behaviorEWMATauSlow.Seconds()
	if tauFast <= 0 {
		tauFast = behaviorEWMATauFastDefaultSeconds
	}
	if tauSlow <= 0 {
		tauSlow = behaviorEWMATauSlowDefaultSeconds
	}
	alphaFast := ewmaAlpha(dtSeconds, tauFast)
	alphaSlow := ewmaAlpha(dtSeconds, tauSlow)

	if feature.Flows == 0 {
		cm.behaviorEWMAMu[idx].Unlock()
		return 0, behaviorAnomalies{}
	}

	updateAxisEWMA(&ew.Flows, float64(feature.Flows), alphaFast, alphaSlow)
	updateAxisEWMA(&ew.UniqueRemotes, float64(feature.UniqueRemotes), alphaFast, alphaSlow)
	updateAxisEWMA(&ew.UniquePorts, float64(feature.UniqueDstPorts), alphaFast, alphaSlow)
	updateAxisEWMA(&ew.Unreplied, feature.UnrepliedRatio, alphaFast, alphaSlow)

	if feature.ConntrackAcct {
		if feature.BytesPerFlow > 0 {
			updateAxisEWMA(&ew.BytesPerFlow, feature.BytesPerFlow, alphaFast, alphaSlow)
		}
		if feature.PacketsPerFlow > 0 {
			updateAxisEWMA(&ew.PktsPerFlow, feature.PacketsPerFlow, alphaFast, alphaSlow)
		}
	}

	sens := cm.behaviorSensitivity
	if sens <= 0 {
		sens = 1.0
	}
	flowsMin := 10.0 / sens
	remotesMin := 5.0 / sens
	portsMin := 5.0 / sens
	unrepMin := 0.05 / sens
	bytesMin := 256.0 / sens
	pktsMin := 2.0 / sens
	if flowsMin < 0.001 {
		flowsMin = 0.001
	}
	if remotesMin < 0.001 {
		remotesMin = 0.001
	}
	if portsMin < 0.001 {
		portsMin = 0.001
	}
	if unrepMin < 0.0001 {
		unrepMin = 0.0001
	}
	if bytesMin < 0.001 {
		bytesMin = 0.001
	}
	if pktsMin < 0.001 {
		pktsMin = 0.001
	}

	flowsAnom := featureAnomaly(float64(feature.Flows), &ew.Flows, flowsMin)
	remotesAnom := featureAnomaly(float64(feature.UniqueRemotes), &ew.UniqueRemotes, remotesMin)
	portsAnom := featureAnomaly(float64(feature.UniqueDstPorts), &ew.UniquePorts, portsMin)
	unrepAnom := featureAnomaly(feature.UnrepliedRatio, &ew.Unreplied, unrepMin)

	bytesAnom := 0.0
	pktsAnom := 0.0
	if feature.ConntrackAcct {
		if feature.BytesPerFlow > 0 {
			bytesAnom = featureAnomaly(feature.BytesPerFlow, &ew.BytesPerFlow, bytesMin)
		}
		if feature.PacketsPerFlow > 0 {
			pktsAnom = featureAnomaly(feature.PacketsPerFlow, &ew.PktsPerFlow, pktsMin)
		}
	}

	behaviorSignal := clamp01(
		0.25*flowsAnom +
			0.20*remotesAnom +
			0.20*portsAnom +
			0.20*unrepAnom +
			0.10*bytesAnom +
			0.05*pktsAnom,
	)

	if sens != 1.0 {
		behaviorSignal = clamp01(math.Pow(behaviorSignal, 1.0/sens))
	}

	cm.behaviorEWMAMu[idx].Unlock()
	return behaviorSignal, behaviorAnomalies{Flows: flowsAnom, Remotes: remotesAnom, Ports: portsAnom, Unreplied: unrepAnom, BytesPerFlow: bytesAnom, PacketsPerFlow: pktsAnom, Signal: behaviorSignal}
}

func (cm *ConntrackManager) cleanupBehaviorState(activeSet map[string]struct{}) {
	now := time.Now().Unix()
	for i := 0; i < shardCount; i++ {
		cm.behaviorEWMAMu[i].Lock()
		for k, s := range cm.behaviorEWMA[i] {
			if _, ok := activeSet[k.InstanceUUID]; !ok || (now-s.LastSeenUnix) > behaviorIdentityTTLSeconds {
				delete(cm.behaviorEWMA[i], k)
			}
		}
		cm.behaviorEWMAMu[i].Unlock()

		cm.outboundMu[i].Lock()
		for k, last := range cm.outboundPrevLastSeen[i] {
			if _, ok := activeSet[k.InstanceUUID]; !ok || (now-last) > behaviorPrevKeyTTLSeconds {
				delete(cm.outboundPrevLastSeen[i], k)
				delete(cm.outboundPrev[i], k)
				delete(cm.outboundPrevDstPorts[i], k)
			}
		}
		cm.outboundMu[i].Unlock()

		cm.inboundMu[i].Lock()
		for k, last := range cm.inboundPrevLastSeen[i] {
			if _, ok := activeSet[k.InstanceUUID]; !ok || (now-last) > behaviorPrevKeyTTLSeconds {
				delete(cm.inboundPrevLastSeen[i], k)
				delete(cm.inboundPrev[i], k)
				delete(cm.inboundPrevDstPorts[i], k)
			}
		}
		cm.inboundMu[i].Unlock()
	}

	cm.behaviorAlertMu.Lock()
	for k, st := range cm.behaviorPersist {
		if _, ok := activeSet[k.InstanceUUID]; !ok || (now-st.LastSeenUnix) > 3600 {
			delete(cm.behaviorPersist, k)
		}
	}
	for k, st := range cm.behaviorEmit {
		if _, ok := activeSet[k.InstanceUUID]; !ok || (now-st.LastEmitUnix) > 3600 {
			delete(cm.behaviorEmit, k)
		}
	}
	cm.behaviorAlertMu.Unlock()
}

func (cm *ConntrackManager) analyzeBehavior(
	s *behaviorStats,
	addrKey IPKey,
	addr, family, name, instanceUUID, projectUUID, projectName, userUUID string,
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
			*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(descs.uniqueRemotes, prometheus.GaugeValue, float64(uniqueRemotes), name, instanceUUID, addr, family, projectUUID, projectName, userUUID))
		}
		if descs.newRemotes != nil {
			*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(descs.newRemotes, prometheus.GaugeValue, float64(newRemotes), name, instanceUUID, addr, family, projectUUID, projectName, userUUID))
		}
		if descs.maxSingleRemote != nil {
			*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(descs.maxSingleRemote, prometheus.GaugeValue, float64(maxSingleRemote), name, instanceUUID, addr, family, projectUUID, projectName, userUUID))
		}
		if descs.uniqueDstPorts != nil {
			*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(descs.uniqueDstPorts, prometheus.GaugeValue, float64(uniqueDstPorts), name, instanceUUID, addr, family, projectUUID, projectName, userUUID))
		}
		if descs.newDstPorts != nil {
			*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(descs.newDstPorts, prometheus.GaugeValue, float64(newDstPorts), name, instanceUUID, addr, family, projectUUID, projectName, userUUID))
		}
		if descs.maxSingleDstPort != nil {
			*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(descs.maxSingleDstPort, prometheus.GaugeValue, float64(maxSingleDstPort), name, instanceUUID, addr, family, projectUUID, projectName, userUUID))
		}
		if descs.flows != nil {
			*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(descs.flows, prometheus.GaugeValue, float64(s.flows), name, instanceUUID, addr, family, projectUUID, projectName, userUUID))
		}
		if acctEnabled && descs.bytesPerFlow != nil {
			*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(descs.bytesPerFlow, prometheus.GaugeValue, bytesPerFlow, name, instanceUUID, addr, family, projectUUID, projectName, userUUID))
		}
		if acctEnabled && descs.packetsPerFlow != nil {
			*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(descs.packetsPerFlow, prometheus.GaugeValue, packetsPerFlow, name, instanceUUID, addr, family, projectUUID, projectName, userUUID))
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
			cm.LogThreat("BEHAVIOR", "behavior_alert", name, instanceUUID, projectUUID, projectName, userUUID, alertKVs...)
		} else {
			kvs := append([]interface{}{"domain", name}, alertKVs...)
			kvs = append(kvs, "instance_uuid", instanceUUID)
			logKV(LogLevelNotice, "behavior", "behavior_alert", kvs...)
		}

		return severity
	}

	return severity
}

func (cm *ConntrackManager) behaviorPortName(direction string, port uint16) string {
	if port == 0 {
		return ""
	}
	if direction == "outbound" {
		if cm.behaviorOutboundPortNames == nil {
			return ""
		}
		if name, ok := cm.behaviorOutboundPortNames[port]; ok {
			return name
		}
		return ""
	}
	if cm.behaviorInboundPortNames == nil {
		return ""
	}
	if name, ok := cm.behaviorInboundPortNames[port]; ok {
		return name
	}
	return ""
}

func behaviorSeverityScore(feature BehaviorFeature) int {
	hostImpactPercent := feature.HostImpactPercent
	impactScore := clamp01(hostImpactPercent/10.0) * 100.0

	flowsScore := 0.0
	if feature.Flows > 0 {
		flowsScore = clamp01(math.Log10(1.0+float64(feature.Flows))/3.0) * 100.0
	}

	unrepliedScore := clamp01(feature.UnrepliedRatio) * 100.0

	policyScore := 0.0
	if feature.Flows > 0 {
		if feature.InfraHits > 0 {
			policyScore = math.Max(policyScore, clamp01(float64(feature.InfraMaxFlows)/float64(feature.Flows))*100.0)
		}
		if feature.LocalScanHits > 0 {
			policyScore = math.Max(policyScore, clamp01(float64(feature.LocalScanHits)/float64(feature.Flows))*100.0)
		}
		if feature.BGPFlows > 0 {
			policyScore = math.Max(policyScore, 100.0)
		}
		if feature.GeneveFlows > 0 {
			policyScore = math.Max(policyScore, 100.0)
		}
		if feature.MetadataHits > 0 {
			policyScore = math.Max(policyScore, clamp01(float64(feature.MetadataMaxFlows)/float64(feature.Flows))*100.0)
		}
		if feature.Direction == "inbound" && feature.AdminPortFlows > 0 {
			policyScore = math.Max(policyScore, clamp01(float64(feature.AdminPortFlows)/float64(feature.Flows))*100.0)
		}
	}

	sev := 0.35*impactScore + 0.30*flowsScore + 0.20*unrepliedScore + 0.15*policyScore
	if sev < 0 {
		sev = 0
	}
	if sev > 100 {
		sev = 100
	}
	return int(math.Round(sev))
}

func behaviorConfidenceScore(feature BehaviorFeature, kind string, topRemoteShare, topPortShare float64, evidenceMode string, persistenceHits int) int {
	dominanceScore := math.Max(topRemoteShare, topPortShare) * 100.0

	newnessScore := 0.0
	if feature.UniqueRemotes > 0 {
		newnessScore = math.Max(newnessScore, (float64(feature.NewRemotes)/float64(feature.UniqueRemotes))*100.0)
	}
	if feature.UniqueDstPorts > 0 {
		newnessScore = math.Max(newnessScore, (float64(feature.NewDstPorts)/float64(feature.UniqueDstPorts))*100.0)
	}

	hitsScore := clamp01(float64(persistenceHits)/3.0) * 100.0

	conf := 0.55*dominanceScore + 0.20*newnessScore + 0.25*hitsScore
	if evidenceMode == "distributed" && dominanceScore < 40.0 {
		conf *= 0.85
	}

	if (kind == "restricted_network_probe" || kind == "lateral_probe_suspected") && (feature.InfraHits > 0 || feature.LocalScanHits > 0) {
		if conf < 70.0 {
			conf = 70.0
		}
	}
	if kind == "bgp_peering_attempt" || kind == "geneve_underlay_attempt" {
		if conf < 80.0 {
			conf = 80.0
		}
	}
	if kind == "metadata_probe_suspected" || kind == "metadata_service_hammering" {
		if conf < 75.0 {
			conf = 75.0
		}
	}

	if feature.SynergyDarkScan {
		conf += 15.0
	}
	if feature.SynergyDarkPhysics {
		conf += 25.0
	}

	if conf < 0 {
		conf = 0
	}
	if conf > 100 {
		conf = 100
	}
	return int(math.Round(conf))
}

func behaviorSeverityBand(severityScore int) string {
	if severityScore >= 85 {
		return "critical"
	}
	if severityScore >= 65 {
		return "high"
	}
	if severityScore >= 35 {
		return "medium"
	}
	return "low"
}

func behaviorPriorityFromScores(severityScore, confidenceScore int) (string, string) {
	sev := severityScore
	conf := confidenceScore

	p := "P4"
	if sev >= 75 && conf >= 75 {
		p = "P1"
	} else if (sev >= 75 && conf >= 50) || (sev >= 50 && conf >= 75) {
		p = "P2"
	} else if (sev >= 50 && conf >= 50) || (sev >= 75 && conf >= 25) || (sev >= 25 && conf >= 75) {
		p = "P3"
	}

	basis := "mixed"
	if sev >= 75 && conf < 50 {
		basis = "severity"
	} else if conf >= 75 && sev < 50 {
		basis = "confidence"
	}

	return p, basis
}

func priorityRank(p string) int {
	switch p {
	case "P4":
		return 1
	case "P3":
		return 2
	case "P2":
		return 3
	case "P1":
		return 4
	default:
		return 1
	}
}

type behaviorScaler struct {
	sens float64
}

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
