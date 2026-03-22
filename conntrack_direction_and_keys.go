package main

import (
	"fmt"
	"strings"
)

const (
	IPS_SEEN_REPLY = (1 << 1)
	IPS_ASSURED    = (1 << 2)
)

type ContactDirection int

const (
	ContactAny ContactDirection = iota
	ContactOut
	ContactIn
)

func parseContactDirection(s string) (ContactDirection, error) {
	normalized := strings.ToLower(strings.TrimSpace(s))
	switch normalized {
	case "", "out", "outbound", "src":
		return ContactOut, nil
	case "any":
		return ContactAny, nil
	case "in", "inbound", "dst":
		return ContactIn, nil
	default:
		return ContactOut, fmt.Errorf("invalid contact direction %q", s)
	}
}
func (d ContactDirection) String() string {
	switch d {
	case ContactAny:
		return "any"
	case ContactIn:
		return "in"
	default:
		return "out"
	}
}
func flowDirection(ipSet map[IPKey]struct{}, ct ConntrackEntry) string {
	src := IPStrToKey(ct.Src)
	dst := IPStrToKey(ct.Dst)
	_, isVMsrc := ipSet[src]
	_, isVMdst := ipSet[dst]
	if isVMsrc && !isVMdst {
		return "out"
	}
	if isVMdst && !isVMsrc {
		return "in"
	}
	return "any"
}

// -----------------------------------------------------------------------------
// Conntrack Flow Types
// -----------------------------------------------------------------------------

type ConntrackEntry struct {
	Src     string
	Dst     string
	SrcPort uint16
	DstPort uint16
	Proto   uint8
	Status  uint32
	Zone    uint16
	Bytes   uint64
	Packets uint64
}

type ConntrackFlowLite struct {
	SrcIP          IPKey
	DstIP          IPKey
	SrcPort        uint16
	DstPort        uint16
	Proto          uint8
	Zone           uint16
	ForwardPackets uint64
	ForwardBytes   uint64
	ReversePackets uint64
	ReverseBytes   uint64
}

type VMIPIdentity struct {
	InstanceUUID string
	IP           IPKey
}

type ConntrackAgg struct {
	VMIndex            map[VMIPIdentity]uint32
	InstanceFlowTotals map[string]int

	FlowsIn  []int
	FlowsOut []int

	OutboundStats []*behaviorStats
	InboundStats  []*behaviorStats

	SpamhausHits        map[string]map[PairKey]ConntrackEntry
	SpamhausHitsDropped map[string]uint64
	ProviderHits        map[string]map[string]map[PairKey]ConntrackEntry
	ProviderHitsDropped map[string]map[string]uint64
}

// -----------------------------------------------------------------------------
// Configuration Structs
// -----------------------------------------------------------------------------

// Resource EWMA State
// -----------------------------------------------------------------------------
