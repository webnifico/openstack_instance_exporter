package main

import (
	"bytes"
)

const maxBehaviorRemotePortPairs = 65536

func newBehaviorStats(trackAcct bool) *behaviorStats {
	return &behaviorStats{
		trackAcct:               trackAcct,
		remotes:                 make(map[IPKey]struct{}),
		remoteZones:             make(map[IPKey]uint16),
		remoteIsPrivate:         make(map[IPKey]bool),
		perRemote:               make(map[IPKey]int),
		perRemoteUnreplied:      make(map[IPKey]int),
		dstPorts:                make(map[uint16]struct{}),
		perDstPort:              make(map[uint16]int),
		perDstPortReplied:       make(map[uint16]int),
		perRemoteDstPort:        make(map[behaviorRemotePortKey]int),
		smtpRemotes:             make(map[IPKey]struct{}),
		smtpPerRemote:           make(map[IPKey]int),
		smtpPerDstPort:          make(map[uint16]int),
		adminPerRemote:          make(map[IPKey]int),
		adminPerRemoteUnreplied: make(map[IPKey]int),
		udpRemotes:              make(map[IPKey]struct{}),
		udpPerRemote:            make(map[IPKey]int),
		udpPerDstPort:           make(map[uint16]int),
		bgpPerRemote:            make(map[IPKey]int),
		genevePerRemote:         make(map[IPKey]int),
		miningRemotes:           make(map[IPKey]*miningRemoteFlowStats),
	}
}
func (b *behaviorStats) updateDetailed(remote IPKey, port uint16, proto uint8, status uint32, zone uint16, bytes uint64, packets uint64) {
	b.updateDetailedWithCoverage(remote, port, proto, status, zone, bytes, packets, b.trackAcct, b.trackAcct)
}
func (b *behaviorStats) updateDetailedWithCoverage(remote IPKey, port uint16, proto uint8, status uint32, zone uint16, bytes uint64, packets uint64, bytesPresent, packetsPresent bool) {
	b.flows++
	if bytesPresent {
		b.bytes = saturatingAddUint64(b.bytes, bytes)
		b.byteCoveredFlows++
	}
	if packetsPresent {
		b.packets = saturatingAddUint64(b.packets, packets)
		b.packetCoveredFlows++
	}

	unreplied := (status&IPS_SEEN_REPLY) == 0 && (status&IPS_ASSURED) == 0
	if unreplied {
		b.unreplied++
	}
	if proto == 6 && isSMTPPort(port) {
		b.smtpFlows++
		addBehaviorProtocolRemote(b.smtpRemotes, remote)
		addBehaviorProtocolRemoteCount(b.smtpPerRemote, remote)
		b.smtpPerDstPort[port]++
		if unreplied {
			b.smtpUnreplied++
		}
	}
	if proto == 6 && port == 179 {
		b.bgpFlows++
		addBehaviorProtocolRemoteCount(b.bgpPerRemote, remote)
	}
	if proto == 17 {
		if port == 6081 {
			b.geneveFlows++
			addBehaviorProtocolRemoteCount(b.genevePerRemote, remote)
		}
		addBehaviorProtocolRemote(b.udpRemotes, remote)
		addBehaviorProtocolRemoteCount(b.udpPerRemote, remote)
		if port != 0 {
			b.udpPerDstPort[port]++
		}
		if unreplied {
			b.udpUnreplied++
		}
		if port == 53 {
			b.dnsUDPFlows++
			if unreplied {
				b.dnsUDPUnreplied++
			}
			if bytesPresent {
				b.dnsBytes = saturatingAddUint64(b.dnsBytes, bytes)
				b.dnsByteCoveredFlows++
			}
		}
	}

	b.updateRemoteDetailed(remote, zone, unreplied)
	if proto == 6 && isAdminExposurePort(port) {
		if _, tracked := b.remotes[remote]; tracked {
			b.adminPerRemote[remote]++
			if unreplied {
				b.adminPerRemoteUnreplied[remote]++
			}
		}
	}

	if port != 0 {
		b.updatePortDetailed(port, !unreplied)
		b.updateRemotePortDetailed(remote, port)
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

func (b *behaviorStats) updateRemotePortDetailed(remote IPKey, port uint16) {
	if b.remoteMapCapped {
		b.remotePortMapCapped = true
		return
	}
	key := behaviorRemotePortKey{Remote: remote, Port: port}
	if count, exists := b.perRemoteDstPort[key]; exists {
		b.perRemoteDstPort[key] = count + 1
		return
	}
	if len(b.perRemoteDstPort) >= maxBehaviorRemotePortPairs {
		b.remotePortMapCapped = true
		return
	}
	b.perRemoteDstPort[key] = 1
}

func isSMTPPort(port uint16) bool {
	return port == 25 || port == 465 || port == 587
}

func addBehaviorProtocolRemote(remotes map[IPKey]struct{}, remote IPKey) {
	if len(remotes) < maxRemoteMapSize {
		remotes[remote] = struct{}{}
	}
}

func addBehaviorProtocolRemoteCount(remotes map[IPKey]int, remote IPKey) {
	if count, exists := remotes[remote]; exists {
		remotes[remote] = count + 1
		return
	}
	if len(remotes) < maxRemoteMapSize {
		remotes[remote] = 1
	}
}

func (b *behaviorStats) accountingAverages() (bytesPerFlow, packetsPerFlow float64, bytesOK, packetsOK bool) {
	if b.byteCoveredFlows > 0 {
		bytesPerFlow = float64(b.bytes) / float64(b.byteCoveredFlows)
		bytesOK = true
	}
	if b.packetCoveredFlows > 0 {
		packetsPerFlow = float64(b.packets) / float64(b.packetCoveredFlows)
		packetsOK = true
	}
	return
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
	delete(b.adminPerRemote, victim)
	delete(b.adminPerRemoteUnreplied, victim)

	b.remotes[remote] = struct{}{}
	b.remoteZones[remote] = zone
	b.remoteIsPrivate[remote] = isPrivateOrLocalKey(remote)
	b.perRemote[remote] = victimCount + 1
	if unreplied {
		b.perRemoteUnreplied[remote] = 1
	}
}

func (b *behaviorStats) updatePortDetailed(port uint16, replied bool) {
	if _, exists := b.dstPorts[port]; !exists {
		b.dstPorts[port] = struct{}{}
	}
	b.perDstPort[port]++
	if replied {
		b.perDstPortReplied[port]++
	}
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

func topBehaviorRemote(perRemote map[IPKey]int) (count int, remote IPKey, set bool) {
	for candidate, candidateCount := range perRemote {
		if !set || candidateCount > count || (candidateCount == count && compareIPKey(candidate, remote) < 0) {
			count = candidateCount
			remote = candidate
			set = true
		}
	}
	return count, remote, set
}

func topBehaviorPort(perPort map[uint16]int) (count int, port uint16) {
	for candidate, candidateCount := range perPort {
		if candidateCount > count || (candidateCount == count && candidateCount > 0 && (port == 0 || candidate < port)) {
			count = candidateCount
			port = candidate
		}
	}
	return count, port
}

func topBehaviorRemoteForPort(stats *behaviorStats, port uint16) (count int, remote IPKey, set bool) {
	if stats == nil || port == 0 || stats.remotePortMapCapped {
		return 0, IPKey{}, false
	}
	for key, candidateCount := range stats.perRemoteDstPort {
		if key.Port != port {
			continue
		}
		if !set || candidateCount > count || (candidateCount == count && compareIPKey(key.Remote, remote) < 0) {
			count = candidateCount
			remote = key.Remote
			set = true
		}
	}
	return
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

func smtpBehaviorEvidenceFromFeature(feature BehaviorFeature) (topRemoteShare, topPortShare float64, mode string) {
	flows := maxInt(1, feature.Flows)
	topRemoteShare = float64(feature.SMTPTopRemoteFlows) / float64(flows)
	topPortShare = float64(feature.SMTPTopDstPortFlows) / float64(flows)
	mode = behaviorEvidenceMode(topRemoteShare, topPortShare)
	return
}

func udpBehaviorEvidenceFromFeature(feature BehaviorFeature) (topRemoteShare, topPortShare float64, mode string) {
	flows := maxInt(1, feature.UDPCount)
	topRemoteShare = float64(feature.UDPTopRemoteFlows) / float64(flows)
	topPortShare = float64(feature.UDPTopDstPortFlows) / float64(flows)
	mode = behaviorEvidenceMode(topRemoteShare, topPortShare)
	return
}

func restrictedProtocolBehaviorEvidenceFromFeature(feature BehaviorFeature, kind string) (remote IPKey, remoteFlows int, port uint16, portFlows int) {
	switch kind {
	case "bgp_peering_attempt":
		return feature.BGPTopRemote, feature.BGPTopRemoteFlows, 179, feature.BGPFlows
	case "geneve_underlay_attempt":
		return feature.GeneveTopRemote, feature.GeneveTopRemoteFlows, 6081, feature.GeneveFlows
	default:
		return IPKey{}, 0, 0, 0
	}
}

func isDarkspaceBehaviorKind(kind string) bool {
	switch kind {
	case "darkspace_port_detected", "inbound_darkspace_port_detected", "darkspace_plus_scan", "darkspace_plus_physics":
		return true
	default:
		return false
	}
}

func populateCategoryBehaviorEvidence(ev *behaviorAlertEvidence, cm *ConntrackManager, feature BehaviorFeature, remote IPKey, remoteFlows int, port uint16, portFlows int) {
	ev.TopDstPort = port
	ev.TopDstPortName = cm.behaviorPortName(feature.Direction, port)
	if remote != (IPKey{}) {
		ev.TopRemoteIP = IPKeyToString(remote)
	}
	flows := maxInt(1, feature.Flows)
	ev.TopRemoteShare = roundToFiveDecimals(float64(remoteFlows) / float64(flows))
	ev.TopPortShare = roundToFiveDecimals(float64(portFlows) / float64(flows))
	ev.EvidenceMode = behaviorEvidenceMode(ev.TopRemoteShare, ev.TopPortShare)
}

func isUDPBehaviorKind(kind string) bool {
	switch kind {
	case "outbound_udp_fanout_suspected", "inbound_udp_flood_suspected", "inbound_udp_targeted_flood_suspected":
		return true
	default:
		return false
	}
}

func buildBehaviorEvidence(feature BehaviorFeature) BehaviorEvidence {
	topRemoteShare, topPortShare, mode := behaviorEvidenceFromFeature(feature)
	return BehaviorEvidence{
		TopRemoteShare: topRemoteShare,
		TopPortShare:   topPortShare,
		EvidenceMode:   mode,
	}
}

func (cm *ConntrackManager) buildBehaviorAlertEvidence(feature BehaviorFeature, topRemoteKey IPKey, topRemoteSet bool, kind string) behaviorAlertEvidence {
	ev := behaviorAlertEvidence{}
	if kind == "outbound_stratum_mining_suspected" && feature.Mining.Valid {
		ev.TopDstPort = feature.Mining.TopPort
		ev.TopDstPortName = builtinMiningPortName(feature.Mining.TopPort)
		if feature.Mining.TopRemote != (IPKey{}) {
			ev.TopRemoteIP = IPKeyToString(feature.Mining.TopRemote)
		}
		if feature.Mining.Flows > 0 {
			ev.TopRemoteShare = float64(feature.Mining.TopRemoteFlows) / float64(feature.Mining.Flows)
			ev.TopPortShare = float64(feature.Mining.TopPortFlows) / float64(feature.Mining.Flows)
		}
		ev.TopRemoteShare = roundToFiveDecimals(ev.TopRemoteShare)
		ev.TopPortShare = roundToFiveDecimals(ev.TopPortShare)
		ev.EvidenceMode = behaviorEvidenceMode(ev.TopRemoteShare, ev.TopPortShare)
		return ev
	}
	if kind == "smtp_spam_behavior_suspected" && feature.SMTPFlows > 0 {
		ev.TopDstPort = feature.SMTPTopDstPort
		ev.TopDstPortName = cm.behaviorPortName(feature.Direction, feature.SMTPTopDstPort)
		if feature.SMTPTopRemote != (IPKey{}) {
			ev.TopRemoteIP = IPKeyToString(feature.SMTPTopRemote)
		}
		ev.TopRemoteShare, ev.TopPortShare, ev.EvidenceMode = smtpBehaviorEvidenceFromFeature(feature)
		ev.TopRemoteShare = roundToFiveDecimals(ev.TopRemoteShare)
		ev.TopPortShare = roundToFiveDecimals(ev.TopPortShare)
		return ev
	}
	if isUDPBehaviorKind(kind) && feature.UDPCount > 0 {
		ev.TopDstPort = feature.UDPTopDstPort
		ev.TopDstPortName = cm.behaviorPortName(feature.Direction, feature.UDPTopDstPort)
		if feature.UDPTopRemote != (IPKey{}) {
			ev.TopRemoteIP = IPKeyToString(feature.UDPTopRemote)
		}
		ev.TopRemoteShare, ev.TopPortShare, ev.EvidenceMode = udpBehaviorEvidenceFromFeature(feature)
		ev.TopRemoteShare = roundToFiveDecimals(ev.TopRemoteShare)
		ev.TopPortShare = roundToFiveDecimals(ev.TopPortShare)
		return ev
	}
	if remote, remoteFlows, port, portFlows := restrictedProtocolBehaviorEvidenceFromFeature(feature, kind); port != 0 {
		populateCategoryBehaviorEvidence(&ev, cm, feature, remote, remoteFlows, port, portFlows)
		return ev
	}
	if kind == "inbound_admin_port_exposure_suspected" && feature.AdminPortFlows > 0 {
		populateCategoryBehaviorEvidence(&ev, cm, feature, feature.AdminTopRemote, feature.AdminTopRemoteFlows, feature.AdminTopDstPort, feature.AdminTopDstPortFlows)
		return ev
	}
	if isDarkspaceBehaviorKind(kind) && feature.UnmonitoredPortFlows > 0 {
		populateCategoryBehaviorEvidence(&ev, cm, feature, feature.TopUnmonitoredRemote, feature.TopUnmonitoredRemoteFlows, feature.TopUnmonitoredDstPort, feature.MaxSingleUnmonitoredDstPort)
		return ev
	}
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
	selectedRemote := ""
	if _, remote, ok := topBehaviorRemote(stats.perRemote); ok {
		selectedRemote = IPKeyToString(remote)
	} else if stats.sampleRemoteSet {
		// Keep the fallback for manually constructed or legacy state that does
		// not contain the per-remote counters used by normal collection.
		selectedRemote = IPKeyToString(stats.sampleRemote)
	}

	if direction == "outbound" {
		srcIP = addr
		dstIP = selectedRemote

		if kind == "lateral_probe_suspected" {
			if remote, ok := highestFlowBehaviorRemoteMatching(stats, func(rk IPKey) bool {
				r := IPKeyToString(rk)
				return IPKeyToAddr(rk).IsPrivate() && !isInfrastructureIP(r, hostIPs)
			}); ok {
				dstIP = IPKeyToString(remote)
			}
		} else if kind == "restricted_network_probe" {
			if remote, ok := highestFlowBehaviorRemoteMatching(stats, func(rk IPKey) bool {
				if rk == metadataServiceIPKey() {
					return false
				}
				return isInfrastructureIP(IPKeyToString(rk), hostIPs) || isLocalOnlyKey(rk)
			}); ok {
				dstIP = IPKeyToString(remote)
			}
		}
		return srcIP, dstIP
	}

	srcIP = selectedRemote
	dstIP = addr
	return srcIP, dstIP
}

func highestFlowBehaviorRemoteMatching(stats *behaviorStats, matches func(IPKey) bool) (IPKey, bool) {
	if stats == nil {
		return IPKey{}, false
	}
	var selected IPKey
	selectedCount := 0
	set := false
	for remote := range stats.remotes {
		if !matches(remote) {
			continue
		}
		count := stats.perRemote[remote]
		if !set || count > selectedCount || (count == selectedCount && compareIPKey(remote, selected) < 0) {
			selected = remote
			selectedCount = count
			set = true
		}
	}
	return selected, set
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
