package main

import (
	"bytes"
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

	b.updateRemoteDetailed(remote, zone, unreplied)

	if port != 0 {
		b.updatePortDetailed(port)
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
	}
}

func (b *behaviorStats) updateRemoteDetailed(remote IPKey, zone uint16, unreplied bool) {
	if _, exists := b.remotes[remote]; exists {
		b.remoteZones[remote] = zone
		b.perRemote[remote]++
		if unreplied {
			b.perRemoteUnreplied[remote]++
		}
		return
	}

	if len(b.remotes) < maxRemoteMapSize {
		b.remotes[remote] = struct{}{}
		b.remoteZones[remote] = zone
		b.remoteIsPrivate[remote] = isPrivateOrLocalKey(remote)
		b.perRemote[remote] = 1
		if unreplied {
			b.perRemoteUnreplied[remote] = 1
		}
		return
	}

	b.remoteMapCapped = true
	victim, victimCount, ok := minRemoteCountEntry(b.perRemote)
	if !ok {
		return
	}
	delete(b.remotes, victim)
	delete(b.remoteZones, victim)
	delete(b.remoteIsPrivate, victim)
	delete(b.perRemote, victim)
	delete(b.perRemoteUnreplied, victim)

	b.remotes[remote] = struct{}{}
	b.remoteZones[remote] = zone
	b.remoteIsPrivate[remote] = isPrivateOrLocalKey(remote)
	b.perRemote[remote] = victimCount + 1
	if unreplied {
		b.perRemoteUnreplied[remote] = 1
	}
}

func (b *behaviorStats) updatePortDetailed(port uint16) {
	if _, exists := b.dstPorts[port]; !exists {
		b.dstPorts[port] = struct{}{}
	}
	b.perDstPort[port]++
}

func minRemoteCountEntry(in map[IPKey]int) (IPKey, int, bool) {
	var victim IPKey
	victimCount := 0
	set := false
	for k, count := range in {
		if !set || count < victimCount || (count == victimCount && bytes.Compare(k[:], victim[:]) < 0) {
			victim = k
			victimCount = count
			set = true
		}
	}
	return victim, victimCount, set
}

func cloneIPKeySet(in map[IPKey]struct{}) map[IPKey]struct{} {
	out := make(map[IPKey]struct{}, len(in))
	for k := range in {
		out[k] = struct{}{}
	}
	return out
}

func cloneUint16Set(in map[uint16]struct{}) map[uint16]struct{} {
	out := make(map[uint16]struct{}, len(in))
	for k := range in {
		out[k] = struct{}{}
	}
	return out
}

func saturatingCount(v, ceiling int) (int, bool) {
	if ceiling > 0 && v >= ceiling {
		return ceiling, true
	}
	return v, false
}

func countNewIPKeys(current, prev map[IPKey]struct{}, ceiling int) (int, bool) {
	count := 0
	for k := range current {
		if _, ok := prev[k]; ok {
			continue
		}
		count++
		if ceiling > 0 && count >= ceiling {
			return ceiling, true
		}
	}
	return count, false
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
	if !feature.RemoteEvidenceApproximate {
		topRemoteShare = float64(feature.MaxSingleRemote) / float64(flows)
	}
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
	ev := behaviorAlertEvidence{}
	ev.TopDstPort = feature.TopDstPort
	ev.TopDstPortName = cm.behaviorPortName(feature.Direction, feature.TopDstPort)
	if topRemoteSet && !feature.RemoteEvidenceApproximate {
		ev.TopRemoteIP = IPKeyToString(topRemoteKey)
	}
	if feature.Flows > 0 {
		if !feature.RemoteEvidenceApproximate {
			ev.TopRemoteShare = float64(feature.MaxSingleRemote) / float64(feature.Flows)
		}
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
