package main

import (
	"bytes"
	"sort"
)

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

func buildBehaviorEvidence(feature BehaviorFeature) BehaviorEvidence {
	topRemoteShare, topPortShare, mode := behaviorEvidenceFromFeature(feature)
	return BehaviorEvidence{
		TopRemoteShare: topRemoteShare,
		TopPortShare:   topPortShare,
		EvidenceMode:   mode,
	}
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
