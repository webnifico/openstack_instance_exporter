package main

import "testing"

func TestResolveFlowVMIndicesUsesZoneSnapshot(t *testing.T) {
	inst := "inst-1"
	src := IPStrToKey("10.0.0.5")
	dst := IPStrToKey("8.8.8.8")
	ips := map[IPKey]struct{}{src: {}}

	vmIndex := map[VMIPIdentity]uint32{
		{InstanceUUID: inst, IP: src}: 7,
	}
	ipToSingle := map[IPKey]string{}
	zoneInfo := func(zone uint16) (string, map[IPKey]struct{}) {
		if zone != 42 {
			return "", nil
		}
		return inst, ips
	}

	flow := ConntrackFlowLite{SrcIP: src, DstIP: dst, Zone: 42}
	idxSrc, idxDst, vmSrc, vmDst, instSrc, instDst := resolveFlowVMIndices(flow, vmIndex, ipToSingle, zoneInfo)

	if !vmSrc || vmDst {
		t.Fatalf("vmSrc=%v vmDst=%v want true,false", vmSrc, vmDst)
	}
	if idxSrc != 7 || idxDst != 0 {
		t.Fatalf("idxSrc=%d idxDst=%d want 7,0", idxSrc, idxDst)
	}
	if instSrc != inst || instDst != "" {
		t.Fatalf("instSrc=%q instDst=%q want %q,''", instSrc, instDst, inst)
	}
}

func TestResolveFlowVMIndicesFallsBackToIPToSingle(t *testing.T) {
	inst := "inst-2"
	src := IPStrToKey("10.0.0.9")
	dst := IPStrToKey("1.1.1.1")

	vmIndex := map[VMIPIdentity]uint32{
		{InstanceUUID: inst, IP: src}: 3,
	}
	ipToSingle := map[IPKey]string{src: inst}
	zoneInfo := func(zone uint16) (string, map[IPKey]struct{}) { return "", nil }

	flow := ConntrackFlowLite{SrcIP: src, DstIP: dst, Zone: 0}
	idxSrc, _, vmSrc, vmDst, instSrc, _ := resolveFlowVMIndices(flow, vmIndex, ipToSingle, zoneInfo)

	if !vmSrc || vmDst {
		t.Fatalf("vmSrc=%v vmDst=%v want true,false", vmSrc, vmDst)
	}
	if idxSrc != 3 {
		t.Fatalf("idxSrc=%d want 3", idxSrc)
	}
	if instSrc != inst {
		t.Fatalf("instSrc=%q want %q", instSrc, inst)
	}
}

func TestResolveFlowVMIndicesReturnsNoMatch(t *testing.T) {
	src := IPStrToKey("10.0.0.1")
	dst := IPStrToKey("10.0.0.2")
	vmIndex := map[VMIPIdentity]uint32{}
	ipToSingle := map[IPKey]string{}
	zoneInfo := func(zone uint16) (string, map[IPKey]struct{}) { return "", nil }

	flow := ConntrackFlowLite{SrcIP: src, DstIP: dst, Zone: 1}
	_, _, vmSrc, vmDst, _, _ := resolveFlowVMIndices(flow, vmIndex, ipToSingle, zoneInfo)
	if vmSrc || vmDst {
		t.Fatalf("vmSrc=%v vmDst=%v want false,false", vmSrc, vmDst)
	}
}
