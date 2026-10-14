package main

import (
	"fmt"
	"time"
)

func (cm *ConntrackManager) validateConntrackAttribution(identities []VMIPIdentity) error {
	owners := make(map[IPKey]string, len(identities))
	overlapping := make(map[IPKey]struct{})
	relevant := make(map[VMIPIdentity]struct{}, len(identities))
	for _, identity := range identities {
		if identity.InstanceUUID == "" || identity.IP == (IPKey{}) {
			continue
		}
		v4 := isIPv4MappedKey(identity.IP)
		if (v4 && !cm.conntrackIPv4Enable) || (!v4 && !cm.conntrackIPv6Enable) {
			continue
		}
		relevant[identity] = struct{}{}
		if owner, seen := owners[identity.IP]; seen && owner != identity.InstanceUUID {
			overlapping[identity.IP] = struct{}{}
		}
		owners[identity.IP] = identity.InstanceUUID
	}
	if len(overlapping) == 0 {
		return nil // Unique fixed addresses retain the existing IP fallback.
	}
	if cm.ovnMapper == nil {
		return fmt.Errorf("conntrack attribution unavailable: overlapping fixed IPs require OVN zone ownership")
	}
	maxAge := cm.ovnMappingMaxAge
	if maxAge <= 0 {
		maxAge = time.Minute
	}
	mapper := cm.ovnMapper
	mapper.RLock()
	defer mapper.RUnlock()
	if mapper.lastRefresh.IsZero() || cm.conntrackNow().Sub(mapper.lastRefresh) > maxAge {
		return fmt.Errorf("conntrack attribution unavailable: OVN zone ownership is stale for overlapping fixed IPs")
	}
	covered := make(map[VMIPIdentity]struct{})
	for zone, owner := range mapper.zoneToInstance {
		for ip := range mapper.zoneToIPs[zone] {
			covered[VMIPIdentity{InstanceUUID: owner, IP: ip}] = struct{}{}
		}
	}
	for identity := range relevant {
		if _, overlap := overlapping[identity.IP]; !overlap {
			continue
		}
		if _, ok := covered[identity]; !ok {
			return fmt.Errorf("conntrack attribution unavailable: OVN zone ownership is incomplete for overlapping fixed IPs")
		}
	}
	return nil
}

func resolveFlowVMIndices(flow ConntrackFlowLite, vmIndex map[VMIPIdentity]uint32, ipToSingle map[IPKey]string, zoneInfo func(uint16) (string, map[IPKey]struct{})) (uint32, uint32, bool, bool, string, string) {
	srcKey := flow.SrcIP
	dstKey := flow.DstIP
	if srcKey == (IPKey{}) || dstKey == (IPKey{}) {
		return 0, 0, false, false, "", ""
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

		if vmSrc || vmDst {
			// A matching OVN zone owns this entry's local endpoint(s). A
			// remote address may also be a unique local IP in another tenant;
			// global IP fallback must not assign that tenant's instance here.
			// Local VM-to-VM traffic is attributed through each endpoint's
			// own conntrack zone entry.
			return idxSrc, idxDst, vmSrc, vmDst, instSrc, instDst
		}
	}

	if !vmSrc {
		if inst2 := ipToSingle[srcKey]; inst2 != "" {
			if idx, ok := vmIndex[VMIPIdentity{InstanceUUID: inst2, IP: srcKey}]; ok {
				idxSrc = idx
				vmSrc = true
				instSrc = inst2
			}
		}
	}
	if !vmDst {
		if inst2 := ipToSingle[dstKey]; inst2 != "" {
			if idx, ok := vmIndex[VMIPIdentity{InstanceUUID: inst2, IP: dstKey}]; ok {
				idxDst = idx
				vmDst = true
				instDst = inst2
			}
		}
	}

	if !vmSrc && !vmDst {
		return 0, 0, false, false, "", ""
	}

	return idxSrc, idxDst, vmSrc, vmDst, instSrc, instDst
}
