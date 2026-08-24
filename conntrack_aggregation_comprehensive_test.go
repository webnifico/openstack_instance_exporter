package main

import (
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func mustCIDR(t *testing.T, value string) *net.IPNet {
	t.Helper()
	_, network, err := net.ParseCIDR(value)
	if err != nil {
		t.Fatal(err)
	}
	return network
}

func TestConntrackAggregateErrorFormattingAndDisabledFamilies(t *testing.T) {
	var nilErr *conntrackAggregateError
	if got := nilErr.Error(); got != "" {
		t.Fatalf("nil aggregate error=%q, want empty", got)
	}
	v4Err := errors.New("v4 broke")
	err := newConntrackAggregateError(true, true, v4Err, nil)
	if err == nil || !err.Partial || !strings.Contains(err.Error(), "partial") || !strings.Contains(err.Error(), "v4 broke") {
		t.Fatalf("partial aggregate error=%v", err)
	}
	if got := newConntrackAggregateError(false, false, v4Err, errors.New("v6 broke")); got != nil {
		t.Fatalf("errors for disabled families produced %v", got)
	}
}

func TestConntrackAggregatorCountsBothVMEndpointsAndAccountingCoverage(t *testing.T) {
	src := IPStrToKey("10.0.0.10")
	dst := IPStrToKey("10.0.0.20")
	public := IPStrToKey("198.51.100.30")
	cm := &ConntrackManager{outboundBehaviorEnabled: true, inboundBehaviorEnabled: true}
	agg, consume := cm.newConntrackAggregator([]VMIPIdentity{
		{InstanceUUID: "", IP: src},
		{InstanceUUID: "vm-src", IP: IPKey{}},
		{InstanceUUID: "vm-src", IP: src},
		{InstanceUUID: "vm-src", IP: src},
		{InstanceUUID: "vm-dst", IP: dst},
	}, nil)
	if len(agg.VMIndex) != 2 || len(agg.FlowsIn) != 2 || len(agg.FlowsOut) != 2 {
		t.Fatalf("VM index sizing index=%v in=%d out=%d", agg.VMIndex, len(agg.FlowsIn), len(agg.FlowsOut))
	}

	consume(ConntrackFlowLite{})
	consume(ConntrackFlowLite{SrcIP: public, DstIP: IPStrToKey("203.0.113.1"), Proto: 6})
	consume(ConntrackFlowLite{
		SrcIP: src, DstIP: dst, SrcPort: 40000, DstPort: 443, Proto: 6,
		Status: IPS_SEEN_REPLY, ForwardBytes: 100, ReverseBytes: 50,
		ForwardPackets: 10, ReversePackets: 5, BytesPresent: true, PacketsPresent: true,
	})

	srcIndex := int(agg.VMIndex[VMIPIdentity{InstanceUUID: "vm-src", IP: src}])
	dstIndex := int(agg.VMIndex[VMIPIdentity{InstanceUUID: "vm-dst", IP: dst}])
	if agg.FlowsOut[srcIndex] != 1 || agg.FlowsIn[dstIndex] != 1 {
		t.Fatalf("VM-to-VM directions out=%v in=%v", agg.FlowsOut, agg.FlowsIn)
	}
	if agg.InstanceFlowTotals["vm-src"] != 1 || agg.InstanceFlowTotals["vm-dst"] != 1 {
		t.Fatalf("VM-to-VM totals=%v", agg.InstanceFlowTotals)
	}
	if agg.OutboundStats[srcIndex] == nil || agg.InboundStats[dstIndex] == nil {
		t.Fatal("enabled behavior stats were not allocated")
	}
	bytesPerFlow, packetsPerFlow, bytesOK, packetsOK := agg.OutboundStats[srcIndex].accountingAverages()
	if !bytesOK || !packetsOK || bytesPerFlow != 150 || packetsPerFlow != 15 {
		t.Fatalf("aggregated accounting bytes=%v/%v packets=%v/%v", bytesPerFlow, bytesOK, packetsPerFlow, packetsOK)
	}

	// Two IPs belonging to one instance still represent one instance flow.
	cmSame := &ConntrackManager{}
	aggSame, consumeSame := cmSame.newConntrackAggregator([]VMIPIdentity{
		{InstanceUUID: "vm-same", IP: src},
		{InstanceUUID: "vm-same", IP: dst},
	}, nil)
	consumeSame(ConntrackFlowLite{SrcIP: src, DstIP: dst, Proto: 6})
	if aggSame.InstanceFlowTotals["vm-same"] != 1 {
		t.Fatalf("same-instance flow total=%v, want one", aggSame.InstanceFlowTotals)
	}
	// A self-address flow is outbound only; it must not be double-counted inbound.
	consumeSame(ConntrackFlowLite{SrcIP: src, DstIP: src, Proto: 6})
	idx := int(aggSame.VMIndex[VMIPIdentity{InstanceUUID: "vm-same", IP: src}])
	if aggSame.FlowsOut[idx] != 2 || aggSame.FlowsIn[idx] != 0 {
		t.Fatalf("self-flow directions out=%v in=%v", aggSame.FlowsOut, aggSame.FlowsIn)
	}
}

func TestConntrackAggregatorRoutesFreshSpamhausAndProviderThreats(t *testing.T) {
	now := time.Now()
	outProvider := newThreatStateTestProvider("OutboundProvider")
	outProvider.Direction = ContactOut
	outProvider.LastSuccess = float64(now.Unix())
	outProvider.EntryCount = 1
	inProvider := newThreatStateTestProvider("InboundProvider")
	inProvider.Direction = ContactIn
	inProvider.LastSuccess = float64(now.Unix())
	inProvider.EntryCount = 1
	anyProvider := newThreatStateTestProvider("AnyProvider")
	anyProvider.Direction = ContactAny
	anyProvider.LastSuccess = float64(now.Unix())
	anyProvider.EntryCount = 1

	vmSrc := IPStrToKey("10.0.0.10")
	vmDst := IPStrToKey("10.0.0.20")
	spamV4 := IPStrToKey("198.51.100.4")
	spamWideV4 := IPStrToKey("203.0.113.4")
	spamV6 := IPStrToKey("2001:db8::4")
	spamWideV6 := IPStrToKey("3001::4")
	outProvider.Set = map[IPKey]struct{}{spamV4: {}}
	outProvider.SetAtomic.Store(outProvider.Set)
	inProvider.Set = map[IPKey]struct{}{spamWideV4: {}}
	inProvider.SetAtomic.Store(inProvider.Set)
	anyProvider.Set = map[IPKey]struct{}{vmSrc: {}}
	anyProvider.SetAtomic.Store(anyProvider.Set)

	tm := newThreatStateTestManager(outProvider, inProvider, anyProvider)
	tm.spamEnabled = true
	tm.spamDir = ContactAny
	tm.spamLastSuccessUnix = float64(now.Unix())
	tm.spamRefresh = time.Hour
	tm.spamEntries = 4
	v4Bucket := uint16(spamV4[12])<<8 | uint16(spamV4[13])
	tm.spamBucketsV4[v4Bucket] = []*net.IPNet{mustCIDR(t, "198.51.100.0/24")}
	tm.spamWideV4 = []*net.IPNet{mustCIDR(t, "203.0.0.0/8")}
	v6Bucket := (uint32(spamV6[0]) << 24) | (uint32(spamV6[1]) << 16) | (uint32(spamV6[2]) << 8) | uint32(spamV6[3])
	tm.spamBucketsV6[v6Bucket] = []*net.IPNet{mustCIDR(t, "2001:db8::/32")}
	tm.spamWideV6 = []*net.IPNet{mustCIDR(t, "3001::/16")}

	cm := &ConntrackManager{}
	agg, consume := cm.newConntrackAggregator([]VMIPIdentity{
		{InstanceUUID: "vm-src", IP: vmSrc},
		{InstanceUUID: "vm-dst", IP: vmDst},
	}, tm)
	for i, remote := range []IPKey{spamV4, spamWideV4, spamV6, spamWideV6} {
		consume(ConntrackFlowLite{SrcIP: vmSrc, DstIP: remote, SrcPort: uint16(41000 + i), DstPort: 443, Proto: 6})
	}
	// Inbound provider direction only routes a listed source to the VM destination.
	consume(ConntrackFlowLite{SrcIP: spamWideV4, DstIP: vmDst, SrcPort: 443, DstPort: 42000, Proto: 6})
	// ContactAny on a VM-to-VM flow routes both resolved endpoints without duplicates.
	consume(ConntrackFlowLite{SrcIP: vmSrc, DstIP: vmDst, SrcPort: 43000, DstPort: 443, Proto: 6})

	if len(agg.SpamhausHits["vm-src"]) != 4 || len(agg.SpamhausHits["vm-dst"]) != 1 {
		t.Fatalf("Spamhaus routing src=%d dst=%d", len(agg.SpamhausHits["vm-src"]), len(agg.SpamhausHits["vm-dst"]))
	}
	if len(agg.ProviderHits[outProvider.Name]["vm-src"]) != 1 {
		t.Fatalf("outbound provider hits=%v", agg.ProviderHits[outProvider.Name])
	}
	if len(agg.ProviderHits[inProvider.Name]["vm-dst"]) != 1 {
		t.Fatalf("inbound provider hits=%v", agg.ProviderHits[inProvider.Name])
	}
	if len(agg.ProviderHits[anyProvider.Name]["vm-src"]) != 5 || len(agg.ProviderHits[anyProvider.Name]["vm-dst"]) != 1 {
		t.Fatalf("any-direction provider hits=%v", agg.ProviderHits[anyProvider.Name])
	}
}

func TestConntrackThreatHitCapsTrackDroppedEvidence(t *testing.T) {
	now := time.Now()
	provider := newThreatStateTestProvider("Capped")
	provider.Direction = ContactOut
	provider.LastSuccess = float64(now.Unix())
	provider.EntryCount = 1
	remote := IPStrToKey("198.51.100.9")
	provider.Set = map[IPKey]struct{}{remote: {}}
	provider.SetAtomic.Store(provider.Set)
	tm := newThreatStateTestManager(provider)
	tm.spamEnabled = true
	tm.spamDir = ContactOut
	tm.spamLastSuccessUnix = float64(now.Unix())
	tm.spamRefresh = time.Hour
	tm.spamEntries = 1
	bucket := uint16(remote[12])<<8 | uint16(remote[13])
	tm.spamBucketsV4[bucket] = []*net.IPNet{mustCIDR(t, "198.51.100.0/24")}

	vm := IPStrToKey("10.0.0.10")
	cm := &ConntrackManager{}
	agg, consume := cm.newConntrackAggregator([]VMIPIdentity{{InstanceUUID: "vm", IP: vm}}, tm)
	for i := 0; i < maxSpamhausHitsPerInstance+1; i++ {
		consume(ConntrackFlowLite{
			SrcIP: vm, DstIP: remote, SrcPort: uint16(i + 1), DstPort: 443, Proto: 6,
		})
	}
	if len(agg.SpamhausHits["vm"]) != maxSpamhausHitsPerInstance || agg.SpamhausHitsDropped["vm"] != 1 {
		t.Fatalf("Spamhaus cap kept=%d dropped=%d", len(agg.SpamhausHits["vm"]), agg.SpamhausHitsDropped["vm"])
	}
	if len(agg.ProviderHits[provider.Name]["vm"]) != maxProviderHitsPerInstance || agg.ProviderHitsDropped[provider.Name]["vm"] != 1 {
		t.Fatalf("provider cap kept=%d dropped=%d", len(agg.ProviderHits[provider.Name]["vm"]), agg.ProviderHitsDropped[provider.Name]["vm"])
	}
}

func TestConntrackThreatHitCapsRetainDeterministicIdentities(t *testing.T) {
	now := time.Now()
	provider := newThreatStateTestProvider("DeterministicCap")
	provider.Direction = ContactOut
	provider.LastSuccess = float64(now.Unix())
	provider.EntryCount = 1
	remote := IPStrToKey("198.51.100.19")
	provider.Set = map[IPKey]struct{}{remote: {}}
	provider.SetAtomic.Store(provider.Set)
	tm := newThreatStateTestManager(provider)
	tm.spamEnabled = true
	tm.spamDir = ContactOut
	tm.spamLastSuccessUnix = float64(now.Unix())
	tm.spamRefresh = time.Hour
	tm.spamEntries = 1
	bucket := uint16(remote[12])<<8 | uint16(remote[13])
	tm.spamBucketsV4[bucket] = []*net.IPNet{mustCIDR(t, "198.51.100.0/24")}

	vm := IPStrToKey("10.0.0.10")
	flows := make([]ConntrackFlowLite, maxSpamhausHitsPerInstance+1)
	for i := range flows {
		flows[i] = ConntrackFlowLite{
			SrcIP: vm, DstIP: remote, SrcPort: uint16(i + 1), DstPort: 443, Proto: 6,
		}
	}
	aggregate := func(reverse bool) *ConntrackAgg {
		cm := &ConntrackManager{}
		agg, consume := cm.newConntrackAggregator([]VMIPIdentity{{InstanceUUID: "vm", IP: vm}}, tm)
		if reverse {
			for i := len(flows) - 1; i >= 0; i-- {
				consume(flows[i])
			}
		} else {
			for i := range flows {
				consume(flows[i])
			}
		}
		return agg
	}

	forward := aggregate(false)
	reverse := aggregate(true)
	equalKeys := func(a, b map[PairKey]ConntrackEntry) bool {
		if len(a) != len(b) {
			return false
		}
		for key := range a {
			if _, ok := b[key]; !ok {
				return false
			}
		}
		return true
	}
	if !equalKeys(forward.SpamhausHits["vm"], reverse.SpamhausHits["vm"]) {
		t.Error("Spamhaus retained identities depend on conntrack iteration order")
	}
	if !equalKeys(forward.ProviderHits[provider.Name]["vm"], reverse.ProviderHits[provider.Name]["vm"]) {
		t.Error("provider retained identities depend on conntrack iteration order")
	}
	smallest := MakePairKey(vm, flows[0].SrcPort, remote, flows[0].DstPort, flows[0].Proto)
	largest := MakePairKey(vm, flows[len(flows)-1].SrcPort, remote, flows[len(flows)-1].DstPort, flows[len(flows)-1].Proto)
	for name, retained := range map[string]map[PairKey]ConntrackEntry{
		"spamhaus": forward.SpamhausHits["vm"],
		"provider": forward.ProviderHits[provider.Name]["vm"],
	} {
		if _, ok := retained[smallest]; !ok {
			t.Errorf("%s cap did not retain the smallest PairKey", name)
		}
		if _, ok := retained[largest]; ok {
			t.Errorf("%s cap retained the largest PairKey instead of the bounded smallest set", name)
		}
	}

	ipSet := map[string]struct{}{"10.0.0.10": {}}
	metrics := make([]prometheus.Metric, 0, 8)
	signal := 0.0
	tm.exportSpamhausHits(forward.SpamhausHits["vm"], forward.SpamhausHitsDropped["vm"], ipSet, "domain", "server", "vm", "project", "project-name", "user", &metrics, &signal, true)
	tm.exportProviderHits(provider, forward.ProviderHits[provider.Name]["vm"], forward.ProviderHitsDropped[provider.Name]["vm"], ipSet, "domain", "server", "vm", "project", "project-name", "user", &metrics, &signal, true)
	spamFirst := tm.spamCount["vm"]
	providerFirst := provider.CountMap["vm"]
	tm.exportSpamhausHits(reverse.SpamhausHits["vm"], reverse.SpamhausHitsDropped["vm"], ipSet, "domain", "server", "vm", "project", "project-name", "user", &metrics, &signal, true)
	tm.exportProviderHits(provider, reverse.ProviderHits[provider.Name]["vm"], reverse.ProviderHitsDropped[provider.Name]["vm"], ipSet, "domain", "server", "vm", "project", "project-name", "user", &metrics, &signal, true)
	if tm.spamCount["vm"] != spamFirst || provider.CountMap["vm"] != providerFirst {
		t.Fatalf("order-only retention churn incremented contacts: spamhaus %v->%v provider %v->%v", spamFirst, tm.spamCount["vm"], providerFirst, provider.CountMap["vm"])
	}
}

func TestConntrackOnePassAndDisabledFamiliesAreUnavailable(t *testing.T) {
	vm := IPStrToKey("10.0.0.10")
	v4Remote := IPStrToKey("198.51.100.10")
	v6Remote := IPStrToKey("2001:db8::10")
	cm := &ConntrackManager{}
	agg := cm.aggregateConntrackOnePassFamilies(
		[]ConntrackFlowLite{{SrcIP: vm, DstIP: v4Remote, Proto: 6}},
		[]ConntrackFlowLite{{SrcIP: vm, DstIP: v6Remote, Proto: 6}},
		[]VMIPIdentity{{InstanceUUID: "vm", IP: vm}}, nil,
	)
	if agg.InstanceFlowTotals["vm"] != 2 {
		t.Fatalf("one-pass family total=%v, want two", agg.InstanceFlowTotals)
	}

	v4, v6, err := cm.readConntrack()
	if err == nil || len(v4) != 0 || len(v6) != 0 || atomic.LoadUint64(&cm.conntrackRawOK) != 0 || atomic.LoadInt64(&cm.conntrackLastSuccessUnix) != 0 {
		t.Fatalf("disabled raw read looked successful: v4=%v v6=%v err=%v ok=%d last=%d", v4, v6, err, atomic.LoadUint64(&cm.conntrackRawOK), atomic.LoadInt64(&cm.conntrackLastSuccessUnix))
	}

	agg, count, err := cm.readAndAggregateConntrack([]VMIPIdentity{{InstanceUUID: "vm", IP: vm}}, nil)
	if err == nil || agg != nil || count != 0 {
		t.Fatalf("disabled aggregate read looked successful: agg=%v count=%d err=%v", agg, count, err)
	}
	if lastGood, lastCount, ok := cm.snapshotLastGoodConntrack(); ok || lastGood != nil || lastCount != 0 {
		t.Fatalf("disabled aggregate replaced last-good state: agg=%p count=%d ok=%v", lastGood, lastCount, ok)
	}

	valid := &ConntrackAgg{}
	cm.storeLastGoodConntrack(valid, 7)
	cm.storeLastGoodConntrack(nil, 99)
	if got, gotCount, gotOK := cm.snapshotLastGoodConntrack(); !gotOK || got != valid || gotCount != 7 {
		t.Fatal("nil last-good store replaced valid state")
	}
}
