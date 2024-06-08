package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const maxSpamhausHitsPerInstance = 5000
const maxProviderHitsPerInstance = 5000

// -----------------------------------------------------------------------------
// Host System Info & Conntrack Logic
// -----------------------------------------------------------------------------

func hostTotalMemBytes() uint64 {
	var si syscall.Sysinfo_t
	if err := syscall.Sysinfo(&si); err != nil {
		return 0
	}
	return si.Totalram * uint64(si.Unit)
}

func hostConntrackMax() uint64 {
	data, err := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_max")
	if err != nil {
		return 0
	}
	s := strings.TrimSpace(string(data))
	if s == "" {
		return 0
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0
	}
	return v
}

// -----------------------------------------------------------------------------
// Conntrack Manager Implementation
// -----------------------------------------------------------------------------

func (cm *ConntrackManager) readConntrack() ([]ConntrackFlowLite, []ConntrackFlowLite, error) {
	v4, v6, err := cm.readConntrackRawLite()
	if err != nil {
		atomic.StoreUint64(&cm.conntrackRawOK, 0)
		return v4, v6, err
	}
	atomic.StoreUint64(&cm.conntrackRawOK, 1)
	atomic.StoreInt64(&cm.conntrackLastSuccessUnix, time.Now().Unix())
	return v4, v6, nil
}

func (cm *ConntrackManager) newConntrackAggregator(
	vmIPs []VMIPIdentity,
	tm *ThreatManager,
) (*ConntrackAgg, func(flow ConntrackFlowLite)) {

	vmIndex := make(map[VMIPIdentity]uint32, len(vmIPs))
	ipToSingle := make(map[IPKey]string, len(vmIPs))

	nextIdx := uint32(0)
	for _, id := range vmIPs {
		if id.InstanceUUID == "" || id.IP == (IPKey{}) {
			continue
		}
		if _, ok := vmIndex[id]; ok {
			continue
		}
		vmIndex[id] = nextIdx
		nextIdx++

		if prev, ok := ipToSingle[id.IP]; !ok {
			ipToSingle[id.IP] = id.InstanceUUID
		} else if prev != id.InstanceUUID {
			ipToSingle[id.IP] = ""
		}
	}

	sz := int(nextIdx)

	agg := &ConntrackAgg{
		VMIndex:             vmIndex,
		FlowsIn:             make([]int, sz),
		FlowsOut:            make([]int, sz),
		OutboundStats:       make([]*behaviorStats, sz),
		InboundStats:        make([]*behaviorStats, sz),
		SpamhausHits:        make(map[string]map[PairKey]ConntrackEntry),
		SpamhausHitsDropped: make(map[string]uint64),
		ProviderHits:        make(map[string]map[string]map[PairKey]ConntrackEntry),
		ProviderHitsDropped: make(map[string]map[string]uint64),
	}

	threatsEnabled := tm != nil && tm.anyThreatsEnabled()
	var spamEnabled bool
	var spamDir ContactDirection
	var spamBucketsV4 map[uint16][]*net.IPNet
	var spamBucketsV6 map[uint32][]*net.IPNet
	var spamWideV4 []*net.IPNet
	var spamWideV6 []*net.IPNet

	type providerSnap struct {
		Name string
		Dir  ContactDirection
		Set  map[IPKey]struct{}
	}

	providers := make([]providerSnap, 0, 8)

	if threatsEnabled {
		tm.spamMu.RLock()
		spamEnabled = tm.spamEnabled
		spamDir = tm.spamDir
		spamBucketsV4 = tm.spamBucketsV4
		spamBucketsV6 = tm.spamBucketsV6
		spamWideV4 = tm.spamWideV4
		spamWideV6 = tm.spamWideV6
		tm.spamMu.RUnlock()

		for _, p := range tm.Providers {
			if p == nil || !p.Enabled {
				continue
			}
			snap, _ := p.SetAtomic.Load().(map[IPKey]struct{})
			if len(snap) == 0 {
				continue
			}
			providers = append(providers, providerSnap{Name: p.Name, Dir: p.Direction, Set: snap})
		}

		if !spamEnabled && len(providers) == 0 {
			threatsEnabled = false
		}
	}

	pairKey := func(a, b IPKey) PairKey {
		return MakePairKey(a, b)
	}

	isSpamhaus := func(k IPKey) bool {
		if !spamEnabled {
			return false
		}
		if isIPv4MappedKey(k) {
			ip4 := net.IP(k[12:16])
			for _, n := range spamWideV4 {
				if n.Contains(ip4) {
					return true
				}
			}
			key := uint16(k[12])<<8 | uint16(k[13])
			nets := spamBucketsV4[key]
			if len(nets) == 0 {
				return false
			}
			for _, n := range nets {
				if n.Contains(ip4) {
					return true
				}
			}
			return false
		}

		ip16 := net.IP(k[:])
		for _, n := range spamWideV6 {
			if n.Contains(ip16) {
				return true
			}
		}

		key := (uint32(k[0]) << 24) | (uint32(k[1]) << 16) | (uint32(k[2]) << 8) | uint32(k[3])
		nets := spamBucketsV6[key]
		if len(nets) == 0 {
			return false
		}
		for _, n := range nets {
			if n.Contains(ip16) {
				return true
			}
		}
		return false
	}

	addHit := func(dst map[string]map[PairKey]ConntrackEntry, inst string, k PairKey, ct ConntrackEntry) {
		h, ok := dst[inst]
		if !ok {
			h = make(map[PairKey]ConntrackEntry, 16)
			dst[inst] = h
		}
		if _, ok := h[k]; ok {
			return
		}
		if len(h) >= maxSpamhausHitsPerInstance {
			agg.SpamhausHitsDropped[inst]++
			return
		}
		h[k] = ct
	}

	addProviderHit := func(provider string, inst string, k PairKey, ct ConntrackEntry) {
		pm, ok := agg.ProviderHits[provider]
		if !ok {
			pm = make(map[string]map[PairKey]ConntrackEntry)
			agg.ProviderHits[provider] = pm
		}
		h, ok := pm[inst]
		if !ok {
			h = make(map[PairKey]ConntrackEntry, 16)
			pm[inst] = h
		}
		if _, ok := h[k]; ok {
			return
		}
		if len(h) >= maxProviderHitsPerInstance {
			dm, ok := agg.ProviderHitsDropped[provider]
			if !ok {
				dm = make(map[string]uint64)
				agg.ProviderHitsDropped[provider] = dm
			}
			dm[inst]++
			return
		}
		h[k] = ct
	}

	ipStrCache := make(map[IPKey]string, 1024)
	ipStrCacheCap := 8192
	ipStr := func(k IPKey) string {
		if s, ok := ipStrCache[k]; ok {
			return s
		}
		s := IPKeyToString(k)
		if len(ipStrCache) < ipStrCacheCap {
			ipStrCache[k] = s
		}
		return s
	}

	makeCT := func(srcK, dstK IPKey, flow ConntrackFlowLite, status uint32, bytes uint64, packets uint64) ConntrackEntry {
		return ConntrackEntry{
			Src: ipStr(srcK), Dst: ipStr(dstK),
			SrcPort: flow.SrcPort, DstPort: flow.DstPort,
			Proto: flow.Proto, Status: status, Zone: flow.Zone,
			Bytes: bytes, Packets: packets,
		}
	}

	routeThreatInstances := func(dir ContactDirection, instSrc, instDst string, srcMatch, dstMatch bool, visit func(inst string)) {
		switch dir {
		case ContactOut:
			if instSrc != "" && dstMatch {
				visit(instSrc)
			}
		case ContactIn:
			if instDst != "" && srcMatch {
				visit(instDst)
			}
		default:
			if srcMatch || dstMatch {
				if instSrc != "" {
					visit(instSrc)
				}
				if instDst != "" && instDst != instSrc {
					visit(instDst)
				}
			}
		}
	}

	zoneInfo := func(zone uint16) (string, map[IPKey]struct{}) {
		if zone == 0 || cm.ovnMapper == nil {
			return "", nil
		}
		return cm.ovnMapper.GetInstance(zone), cm.ovnMapper.GetIPs(zone)
	}

	consumeOne := func(flow ConntrackFlowLite) {
		srcKey := flow.SrcIP
		dstKey := flow.DstIP
		if srcKey == (IPKey{}) || dstKey == (IPKey{}) {
			return
		}

		var (
			idxSrc  uint32
			idxDst  uint32
			vmSrc   bool
			vmDst   bool
			instSrc string
			instDst string
		)

		inst, ips := zoneInfo(flow.Zone)
		if inst != "" {
			if _, ok := ips[srcKey]; ok {
				if idx, ok2 := vmIndex[VMIPIdentity{InstanceUUID: inst, IP: srcKey}]; ok2 {
					idxSrc = idx
					vmSrc = true
					instSrc = inst
				}
			}
			if _, ok := ips[dstKey]; ok {
				if idx, ok2 := vmIndex[VMIPIdentity{InstanceUUID: inst, IP: dstKey}]; ok2 {
					idxDst = idx
					vmDst = true
					instDst = inst
				}
			}

			if !vmSrc && !vmDst {
				if idx, ok := vmIndex[VMIPIdentity{InstanceUUID: inst, IP: srcKey}]; ok {
					idxSrc = idx
					vmSrc = true
					instSrc = inst
				}
				if idx, ok := vmIndex[VMIPIdentity{InstanceUUID: inst, IP: dstKey}]; ok {
					idxDst = idx
					vmDst = true
					instDst = inst
				}
			}

			if !vmSrc && !vmDst {
				inst = ""
			}
		}

		if inst == "" {
			if inst2 := ipToSingle[srcKey]; inst2 != "" {
				if idx, ok := vmIndex[VMIPIdentity{InstanceUUID: inst2, IP: srcKey}]; ok {
					idxSrc = idx
					vmSrc = true
					instSrc = inst2
				}
			}
			if inst2 := ipToSingle[dstKey]; inst2 != "" {
				if idx, ok := vmIndex[VMIPIdentity{InstanceUUID: inst2, IP: dstKey}]; ok {
					idxDst = idx
					vmDst = true
					instDst = inst2
				}
			}
			if !vmSrc && !vmDst {
				return
			}
		}

		status := uint32(0)
		if flow.ReversePackets > 0 {
			status |= IPS_SEEN_REPLY
		}
		if flow.ForwardPackets > 0 && flow.ReversePackets > 0 {
			status |= IPS_ASSURED
		}

		bytes := uint64(0)
		packets := uint64(0)
		if cm.conntrackAcctEnabled {
			bytes = flow.ForwardBytes
			packets = flow.ForwardPackets
		}

		if vmSrc {
			i := int(idxSrc)
			if i >= 0 && i < len(agg.FlowsOut) {
				agg.FlowsOut[i]++
			}
			if cm.outboundBehaviorEnabled && i >= 0 && i < len(agg.OutboundStats) {
				s := agg.OutboundStats[i]
				if s == nil {
					s = newBehaviorStats(cm.conntrackAcctEnabled)
					agg.OutboundStats[i] = s
				}
				s.updateDetailed(dstKey, flow.DstPort, flow.Proto, status, 0, bytes, packets)
			}
		}

		if vmDst && dstKey != srcKey {
			i := int(idxDst)
			if i >= 0 && i < len(agg.FlowsIn) {
				agg.FlowsIn[i]++
			}
			if cm.inboundBehaviorEnabled && i >= 0 && i < len(agg.InboundStats) {
				s := agg.InboundStats[i]
				if s == nil {
					s = newBehaviorStats(cm.conntrackAcctEnabled)
					agg.InboundStats[i] = s
				}
				s.updateDetailed(srcKey, flow.DstPort, flow.Proto, status, 0, bytes, packets)
			}
		}

		if !threatsEnabled {
			return
		}

		k := pairKey(srcKey, dstKey)

		if spamEnabled {
			spamSrc := isSpamhaus(srcKey)
			spamDst := isSpamhaus(dstKey)
			if spamSrc || spamDst {
				ctInit := false
				var ct ConntrackEntry
				getCT := func() ConntrackEntry {
					if !ctInit {
						ct = makeCT(srcKey, dstKey, flow, status, bytes, packets)
						ctInit = true
					}
					return ct
				}
				routeThreatInstances(spamDir, instSrc, instDst, spamSrc, spamDst, func(inst string) {
					addHit(agg.SpamhausHits, inst, k, getCT())
				})
			}
		}

		for _, p := range providers {
			_, inSrc := p.Set[srcKey]
			_, inDst := p.Set[dstKey]
			if !inSrc && !inDst {
				continue
			}

			ctInit := false
			var ct ConntrackEntry
			getCT := func() ConntrackEntry {
				if !ctInit {
					ct = makeCT(srcKey, dstKey, flow, status, bytes, packets)
					ctInit = true
				}
				return ct
			}

			routeThreatInstances(p.Dir, instSrc, instDst, inSrc, inDst, func(inst string) {
				addProviderHit(p.Name, inst, k, getCT())
			})
		}
	}

	return agg, consumeOne
}

func (cm *ConntrackManager) aggregateConntrackOnePassFamilies(
	flowsV4 []ConntrackFlowLite,
	flowsV6 []ConntrackFlowLite,
	vmIPs []VMIPIdentity,
	tm *ThreatManager,
) *ConntrackAgg {
	agg, consumeOne := cm.newConntrackAggregator(vmIPs, tm)
	for _, flow := range flowsV4 {
		consumeOne(flow)
	}
	for _, flow := range flowsV6 {
		consumeOne(flow)
	}
	return agg
}

func (cm *ConntrackManager) readAndAggregateConntrack(
	vmIPs []VMIPIdentity,
	tm *ThreatManager,
) (*ConntrackAgg, int, error) {
	agg, consumeOne := cm.newConntrackAggregator(vmIPs, tm)

	count := 0
	var parseErrs uint64
	var enobufs uint64
	var errV4 error
	var errV6 error

	dump := func(enabled bool, family int, errp *error) {
		if !enabled {
			return
		}
		c, p, e, err := conntrackDumpFamilyLiteConsume(family, cm.conntrackRawRcvBufBytes, consumeOne)
		count += int(c)
		parseErrs += p
		enobufs += e
		*errp = err
	}

	dump(cm.conntrackIPv4Enable, syscall.AF_INET, &errV4)
	dump(cm.conntrackIPv6Enable, syscall.AF_INET6, &errV6)

	if parseErrs > 0 {
		atomic.AddUint64(&cm.conntrackRawParseErrorsTotal, parseErrs)
	}
	if enobufs > 0 {
		atomic.AddUint64(&cm.conntrackRawENOBUFSTotal, enobufs)
	}

	if errV4 != nil || errV6 != nil {
		atomic.StoreUint64(&cm.conntrackRawOK, 0)
		return nil, count, fmt.Errorf("conntrack raw read errors: v4=%v v6=%v", errV4, errV6)
	}

	atomic.StoreUint64(&cm.conntrackRawOK, 1)
	atomic.StoreInt64(&cm.conntrackLastSuccessUnix, time.Now().Unix())
	return agg, count, nil
}

func (cm *ConntrackManager) cleanupBehaviorMaps(activeSet map[string]struct{}) {
	now := time.Now().Unix()

	cleanupShard := func(mu *sync.Mutex, prevR map[BehaviorKey]outboundPrev, prevP map[BehaviorKey]outboundPrevDstPorts, seen map[BehaviorKey]int64) {
		mu.Lock()
		defer mu.Unlock()

		for k := range prevR {
			last, okSeen := seen[k]
			if _, ok := activeSet[k.InstanceUUID]; !ok || !okSeen || (now-last) > behaviorPrevKeyTTLSeconds {
				delete(prevR, k)
				delete(prevP, k)
				delete(seen, k)
			}
		}

		for k := range prevP {
			if _, ok := prevR[k]; ok {
				continue
			}
			last, okSeen := seen[k]
			if _, ok := activeSet[k.InstanceUUID]; !ok || !okSeen || (now-last) > behaviorPrevKeyTTLSeconds {
				delete(prevP, k)
				delete(seen, k)
			}
		}
	}

	for i := 0; i < shardCount; i++ {
		cleanupShard(&cm.outboundMu[i], cm.outboundPrev[i], cm.outboundPrevDstPorts[i], cm.outboundPrevLastSeen[i])
		cleanupShard(&cm.inboundMu[i], cm.inboundPrev[i], cm.inboundPrevDstPorts[i], cm.inboundPrevLastSeen[i])
	}
}

func (cm *ConntrackManager) describeConntrackMetrics(ch chan<- *prometheus.Desc) {
	descs := []*prometheus.Desc{
		cm.instanceConntrackIPFlowsDesc, cm.instanceConntrackIPFlowsInboundDesc, cm.instanceConntrackIPFlowsOutboundDesc,
		cm.instanceOutboundUniqueRemotesDesc, cm.instanceOutboundNewRemotesDesc, cm.instanceOutboundFlowsDesc,
		cm.instanceOutboundMaxFlowsSingleRemoteDesc, cm.instanceOutboundUniqueDstPortsDesc, cm.instanceOutboundNewDstPortsDesc,
		cm.instanceOutboundMaxFlowsSingleDstPortDesc,
		cm.instanceInboundUniqueRemotesDesc, cm.instanceInboundNewRemotesDesc, cm.instanceInboundFlowsDesc,
		cm.instanceInboundMaxFlowsSingleRemoteDesc, cm.instanceInboundUniqueDstPortsDesc, cm.instanceInboundNewDstPortsDesc,
		cm.instanceInboundMaxFlowsSingleDstPortDesc,
	}
	for _, d := range descs {
		ch <- d
	}
}

func (cm *ConntrackManager) calculateConntrackMetrics(
	fixedIPs []IP,
	connAgg *ConntrackAgg,
	ipSet map[string]struct{},
	hostIPs map[string]struct{},
	hostConntrackMax uint64,
	name, instanceUUID, projectUUID, projectName, userUUID string,
	dynamicMetrics *[]prometheus.Metric,
) (float64, float64, int) {

	var outboundSignal, inboundSignal float64
	var maxIn, maxOut int

	hostIPKeys := make(map[IPKey]struct{}, len(hostIPs))
	for ipStr := range hostIPs {
		k := IPStrToKey(ipStr)
		if k == (IPKey{}) {
			continue
		}
		hostIPKeys[k] = struct{}{}
	}

	ctx := BehaviorContext{HostIPs: hostIPs, HostIPKeys: hostIPKeys, HostConntrackMax: hostConntrackMax}

	for _, ip := range fixedIPs {
		addr := ip.Address
		if addr == "" {
			continue
		}

		addrKey := IPStrToKey(addr)

		in := 0
		out := 0

		var outStats *behaviorStats
		var inStats *behaviorStats

		if connAgg != nil {
			if connAgg.VMIndex != nil {
				if idx, ok := connAgg.VMIndex[VMIPIdentity{InstanceUUID: instanceUUID, IP: addrKey}]; ok {
					i := int(idx)
					if i >= 0 && i < len(connAgg.FlowsIn) {
						in = connAgg.FlowsIn[i]
					}
					if i >= 0 && i < len(connAgg.FlowsOut) {
						out = connAgg.FlowsOut[i]
					}

					if cm.outboundBehaviorEnabled && i >= 0 && i < len(connAgg.OutboundStats) {
						outStats = connAgg.OutboundStats[i]
					}
					if cm.inboundBehaviorEnabled && i >= 0 && i < len(connAgg.InboundStats) {
						inStats = connAgg.InboundStats[i]
					}
				}
			}
		}

		if in > maxIn {
			maxIn = in
		}
		if out > maxOut {
			maxOut = out
		}

		total := in + out

		*dynamicMetrics = append(*dynamicMetrics,
			prometheus.MustNewConstMetric(cm.instanceConntrackIPFlowsDesc, prometheus.GaugeValue, float64(total), name, instanceUUID, addr, ip.Family, projectUUID, projectName, userUUID),
			prometheus.MustNewConstMetric(cm.instanceConntrackIPFlowsInboundDesc, prometheus.GaugeValue, float64(in), name, instanceUUID, addr, ip.Family, projectUUID, projectName, userUUID),
			prometheus.MustNewConstMetric(cm.instanceConntrackIPFlowsOutboundDesc, prometheus.GaugeValue, float64(out), name, instanceUUID, addr, ip.Family, projectUUID, projectName, userUUID),
		)

		if cm.outboundBehaviorEnabled && outStats != nil {
			val := cm.analyzeBehavior(
				outStats,
				addrKey,
				addr,
				ip.Family,
				name, instanceUUID, projectUUID, projectName, userUUID,
				dynamicMetrics,
				metricDescGroup{
					uniqueRemotes:      cm.instanceOutboundUniqueRemotesDesc,
					newRemotes:         cm.instanceOutboundNewRemotesDesc,
					flows:              cm.instanceOutboundFlowsDesc,
					maxSingleRemote:    cm.instanceOutboundMaxFlowsSingleRemoteDesc,
					uniqueDstPorts:     cm.instanceOutboundUniqueDstPortsDesc,
					newDstPorts:        cm.instanceOutboundNewDstPortsDesc,
					maxSingleDstPort:   cm.instanceOutboundMaxFlowsSingleDstPortDesc,
					bytesPerFlow:       cm.instanceOutboundBytesPerFlowDesc,
					packetsPerFlow:     cm.instanceOutboundPacketsPerFlowDesc,
					thresholdConfigKey: "outbound",
				},
				ctx,
			)
			if val > outboundSignal {
				outboundSignal = val
			}
		}

		if cm.inboundBehaviorEnabled && inStats != nil {
			val := cm.analyzeBehavior(
				inStats,
				addrKey,
				addr,
				ip.Family,
				name, instanceUUID, projectUUID, projectName, userUUID,
				dynamicMetrics,
				metricDescGroup{
					uniqueRemotes:      cm.instanceInboundUniqueRemotesDesc,
					newRemotes:         cm.instanceInboundNewRemotesDesc,
					flows:              cm.instanceInboundFlowsDesc,
					maxSingleRemote:    cm.instanceInboundMaxFlowsSingleRemoteDesc,
					uniqueDstPorts:     cm.instanceInboundUniqueDstPortsDesc,
					newDstPorts:        cm.instanceInboundNewDstPortsDesc,
					maxSingleDstPort:   cm.instanceInboundMaxFlowsSingleDstPortDesc,
					bytesPerFlow:       cm.instanceInboundBytesPerFlowDesc,
					packetsPerFlow:     cm.instanceInboundPacketsPerFlowDesc,
					thresholdConfigKey: "inbound",
				},
				ctx,
			)
			if val > inboundSignal {
				inboundSignal = val
			}
		}
	}

	maxConntrack := maxIn
	if maxOut > maxConntrack {
		maxConntrack = maxOut
	}

	_ = ipSet

	return outboundSignal, inboundSignal, maxConntrack
}
