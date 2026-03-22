package main

import (
	"fmt"
	"net"
	"sync/atomic"
	"syscall"
	"time"
)

const maxSpamhausHitsPerInstance = 5000
const maxProviderHitsPerInstance = 5000

type conntrackAggregateError struct {
	Partial bool
	ErrV4   error
	ErrV6   error
}

func (e *conntrackAggregateError) Error() string {
	if e == nil {
		return ""
	}
	prefix := "conntrack raw read errors"
	if e.Partial {
		prefix = "conntrack raw partial read errors"
	}
	return fmt.Sprintf("%s: v4=%v v6=%v", prefix, e.ErrV4, e.ErrV6)
}

func newConntrackAggregateError(enabledV4 bool, enabledV6 bool, errV4 error, errV6 error) *conntrackAggregateError {
	failV4 := enabledV4 && errV4 != nil
	failV6 := enabledV6 && errV6 != nil
	if !failV4 && !failV6 {
		return nil
	}

	successV4 := enabledV4 && errV4 == nil
	successV6 := enabledV6 && errV6 == nil

	return &conntrackAggregateError{
		Partial: (successV4 || successV6) && (failV4 || failV6),
		ErrV4:   errV4,
		ErrV6:   errV6,
	}
}

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
		InstanceFlowTotals:  make(map[string]int, len(vmIPs)),
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

	pairKey := func(srcIP IPKey, srcPort uint16, dstIP IPKey, dstPort uint16, proto uint8) PairKey {
		return MakePairKey(srcIP, srcPort, dstIP, dstPort, proto)
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

	var zoneToInstance map[uint16]string
	var zoneToIPs map[uint16]map[IPKey]struct{}
	if cm.ovnMapper != nil {
		zoneToInstance, zoneToIPs = cm.ovnMapper.SnapshotRefs()
	}

	zoneInfo := func(zone uint16) (string, map[IPKey]struct{}) {
		if zoneToInstance == nil {
			return "", nil
		}
		return zoneToInstance[zone], zoneToIPs[zone]
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

		idxSrc, idxDst, vmSrc, vmDst, instSrc, instDst = resolveFlowVMIndices(flow, vmIndex, ipToSingle, zoneInfo)
		if !vmSrc && !vmDst {
			return
		}

		switch {
		case instSrc != "" && instDst != "" && instSrc == instDst:
			agg.InstanceFlowTotals[instSrc]++
		case instSrc != "":
			agg.InstanceFlowTotals[instSrc]++
			if instDst != "" && instDst != instSrc {
				agg.InstanceFlowTotals[instDst]++
			}
		case instDst != "":
			agg.InstanceFlowTotals[instDst]++
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
			bytes = flow.ForwardBytes + flow.ReverseBytes
			packets = flow.ForwardPackets + flow.ReversePackets
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
				s.updateDetailed(dstKey, flow.DstPort, flow.Proto, status, flow.Zone, bytes, packets)
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
				s.updateDetailed(srcKey, flow.DstPort, flow.Proto, status, flow.Zone, bytes, packets)
			}
		}

		if !threatsEnabled {
			return
		}

		k := pairKey(srcKey, flow.SrcPort, dstKey, flow.DstPort, flow.Proto)

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
		c, p, e, err := conntrackDumpFamilyLiteConsume(family, cm.conntrackRawRcvBufBytes, cm.conntrackNetlinkRecvTimeout, consumeOne)
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

	enabledV4 := cm.conntrackIPv4Enable
	enabledV6 := cm.conntrackIPv6Enable
	readErr := newConntrackAggregateError(enabledV4, enabledV6, errV4, errV6)
	if readErr != nil {
		atomic.StoreUint64(&cm.conntrackRawOK, 0)
		if readErr.Partial {
			if enabledV4 && errV4 != nil {
				logConntrackMetric.Notice("conntrack_raw_partial_failure", "family", "v4", "err", errV4)
			}
			if enabledV6 && errV6 != nil {
				logConntrackMetric.Notice("conntrack_raw_partial_failure", "family", "v6", "err", errV6)
			}
			return agg, count, readErr
		}
		return nil, count, readErr
	}

	atomic.StoreUint64(&cm.conntrackRawOK, 1)
	atomic.StoreInt64(&cm.conntrackLastSuccessUnix, time.Now().Unix())
	return agg, count, nil
}
