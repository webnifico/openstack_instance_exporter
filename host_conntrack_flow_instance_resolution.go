package main

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
	}

	if !vmSrc && !vmDst {
		return 0, 0, false, false, "", ""
	}

	return idxSrc, idxDst, vmSrc, vmDst, instSrc, instDst
}
