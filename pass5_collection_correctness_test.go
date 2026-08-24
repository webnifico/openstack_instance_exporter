package main

import (
	"encoding/binary"
	"math"
	"syscall"
	"testing"
	"time"

	libvirt "github.com/digitalocean/go-libvirt"
	"github.com/prometheus/client_golang/prometheus"
)

func TestConntrackDatagramIgnoresValidNoopControlMessages(t *testing.T) {
	ne := nativeEndian()
	seq := uint32(991)
	dataType := uint16((nfnlSubsysCtNetlink << 8) | ipctnlMsgCtNew)
	data := testNetlinkMessage(ne, dataType, 0, seq, testConntrackPayload(ne, IPS_SEEN_REPLY, false, 1))
	noop := testNetlinkMessage(ne, syscall.NLMSG_NOOP, 0, seq, nil)
	done := testNetlinkMessage(ne, syscall.NLMSG_DONE, 0, seq, nil)
	datagram := append(noop, data...)
	datagram = append(datagram, done...)

	consumed := 0
	complete, count, parseErrs, err := parseConntrackNetlinkDatagram(datagram, 0, 0, 0, seq, syscall.AF_INET, func(ConntrackFlowLite) {
		consumed++
	})
	if err != nil || !complete || count != 1 || consumed != 1 || parseErrs != 0 {
		t.Fatalf("NOOP made complete dump fail: complete=%v count=%d consumed=%d parse_errors=%d err=%v", complete, count, consumed, parseErrs, err)
	}
}

func TestConntrackDatagramAcceptsRequesterPortIDFromKernelDump(t *testing.T) {
	ne := nativeEndian()
	seq := uint32(992)
	const requesterPortID = uint32(4242)
	dataType := uint16((nfnlSubsysCtNetlink << 8) | ipctnlMsgCtNew)
	data := testNetlinkMessage(ne, dataType, 0, seq, testConntrackPayload(ne, IPS_SEEN_REPLY, false, 1))
	done := testNetlinkMessage(ne, syscall.NLMSG_DONE, 0, seq, nil)
	ne.PutUint32(data[12:16], requesterPortID)
	ne.PutUint32(done[12:16], requesterPortID)
	datagram := append(data, done...)

	complete, count, parseErrs, err := parseConntrackNetlinkDatagram(datagram, 0, 0, requesterPortID, seq, syscall.AF_INET, func(ConntrackFlowLite) {})
	if err != nil || !complete || count != 1 || parseErrs != 0 {
		t.Fatalf("kernel dump addressed to requester was rejected: complete=%v count=%d parse_errors=%d err=%v", complete, count, parseErrs, err)
	}

	zeroHeaderData := testNetlinkMessage(ne, dataType, 0, seq, testConntrackPayload(ne, IPS_SEEN_REPLY, false, 1))
	zeroHeaderDone := testNetlinkMessage(ne, syscall.NLMSG_DONE, 0, seq, nil)
	complete, count, parseErrs, err = parseConntrackNetlinkDatagram(append(zeroHeaderData, zeroHeaderDone...), 0, 0, requesterPortID, seq, syscall.AF_INET, func(ConntrackFlowLite) {})
	if err != nil || !complete || count != 1 || parseErrs != 0 {
		t.Fatalf("compatible zero kernel header PID was rejected: complete=%v count=%d parse_errors=%d err=%v", complete, count, parseErrs, err)
	}

	wrongHeaderData := testNetlinkMessage(ne, dataType, 0, seq, testConntrackPayload(ne, IPS_SEEN_REPLY, false, 1))
	ne.PutUint32(wrongHeaderData[12:16], requesterPortID+1)
	if _, _, _, err := parseConntrackNetlinkDatagram(wrongHeaderData, 0, 0, requesterPortID, seq, syscall.AF_INET, func(ConntrackFlowLite) {}); err == nil {
		t.Fatal("arbitrary netlink header PID was accepted")
	}
}

func TestConntrackAccountingRequiresBothDirectionsPerAxis(t *testing.T) {
	ne := nativeEndian()
	value := make([]byte, 8)
	binary.BigEndian.PutUint64(value, 7)

	partial := testTCPConntrackPayload(ne, syscall.AF_INET, 6, true,
		testNestedNLA(ne, ctaCountersOrig, testNLA(ne, ctaCountersPackets, value)),
		testNestedNLA(ne, ctaCountersReply, testNLA(ne, ctaCountersBytes, value)),
	)
	var parseErrs uint64
	flow, ok := parseConntrackMessageLite(partial, syscall.AF_INET, ne, &parseErrs)
	if !ok || parseErrs != 0 {
		t.Fatalf("structurally valid partial counters failed parsing: ok=%v errors=%d", ok, parseErrs)
	}
	if flow.PacketsPresent || flow.BytesPresent {
		t.Fatalf("one-sided counters were exposed as full-flow totals: %+v", flow)
	}

	completePackets := testTCPConntrackPayload(ne, syscall.AF_INET, 6, true,
		testNestedNLA(ne, ctaCountersOrig, testNLA(ne, ctaCountersPackets, value)),
		testNestedNLA(ne, ctaCountersReply, testNLA(ne, ctaCountersPackets, value)),
	)
	parseErrs = 0
	flow, ok = parseConntrackMessageLite(completePackets, syscall.AF_INET, ne, &parseErrs)
	if !ok || parseErrs != 0 || !flow.PacketsPresent || flow.BytesPresent {
		t.Fatalf("independent complete packet coverage was not retained: ok=%v errors=%d flow=%+v", ok, parseErrs, flow)
	}
}

func TestConntrackAccountingSumsDoNotWrap(t *testing.T) {
	vm := IPStrToKey("10.0.0.10")
	remote := IPStrToKey("198.51.100.10")
	cm := &ConntrackManager{outboundBehaviorEnabled: true}
	agg, consume := cm.newConntrackAggregator([]VMIPIdentity{{InstanceUUID: "vm", IP: vm}}, nil)
	consume(ConntrackFlowLite{
		SrcIP: vm, DstIP: remote, SrcPort: 10000, DstPort: 443, Proto: 6,
		ForwardBytes: ^uint64(0), ReverseBytes: 1, BytesPresent: true,
		ForwardPackets: ^uint64(0), ReversePackets: 1, PacketsPresent: true,
	})
	idx := int(agg.VMIndex[VMIPIdentity{InstanceUUID: "vm", IP: vm}])
	bytesPerFlow, packetsPerFlow, bytesOK, packetsOK := agg.OutboundStats[idx].accountingAverages()
	if !bytesOK || !packetsOK || bytesPerFlow < float64(^uint64(0))/2 || packetsPerFlow < float64(^uint64(0))/2 {
		t.Fatalf("directional counter addition wrapped: bytes=%v/%v packets=%v/%v", bytesPerFlow, bytesOK, packetsPerFlow, packetsOK)
	}

	consume(ConntrackFlowLite{
		SrcIP: vm, DstIP: remote, SrcPort: 10001, DstPort: 443, Proto: 6,
		ForwardBytes: ^uint64(0), BytesPresent: true,
		ForwardPackets: ^uint64(0), PacketsPresent: true,
	})
	bytesPerFlow, packetsPerFlow, bytesOK, packetsOK = agg.OutboundStats[idx].accountingAverages()
	if !bytesOK || !packetsOK || bytesPerFlow < 1e18 || packetsPerFlow < 1e18 {
		t.Fatalf("cross-flow counter accumulation wrapped: bytes=%v/%v packets=%v/%v", bytesPerFlow, bytesOK, packetsPerFlow, packetsOK)
	}
}

func TestOVNZoneParserDoesNotUseNumericPrefixAsZone(t *testing.T) {
	port := "11111111-1111-1111-1111-111111111111"
	ip := IPStrToKey("192.0.2.42")
	zones, _, _, err := parseOVNZoneList(
		[]byte("123 prefix "+port+" 42\n"),
		map[string]string{port: "vm-42"},
		map[string][]IPKey{port: {ip}},
	)
	if err != nil {
		t.Fatalf("zone line with harmless prefix failed: %v", err)
	}
	if zones[42] != "vm-42" || zones[123] != "" {
		t.Fatalf("numeric prefix was mistaken for the port zone: %v", zones)
	}
}

func TestOVNPortIPSnapshotRejectsIPsFromPortsNotOwnedByInstance(t *testing.T) {
	port1 := "11111111-1111-1111-1111-111111111111"
	port2 := "22222222-2222-2222-2222-222222222222"
	ip1 := IPStrToKey("192.0.2.1")
	ip2 := IPStrToKey("192.0.2.2")
	ip3 := IPStrToKey("192.0.2.3")
	im := newInventoryStateTestManager()
	im.domainMeta["vm-1"] = &DomainStatic{
		PortUUIDs:     []string{port1},
		PortIPsByUUID: map[string][]IP{port1: {{Address: "192.0.2.1"}}},
	}
	im.domainMeta["vm-2"] = &DomainStatic{
		PortUUIDs: []string{port2},
		PortIPsByUUID: map[string][]IP{
			port1: {{Address: "192.0.2.2"}},
			port2: {{Address: "192.0.2.3"}},
		},
	}

	got := im.snapshotOVNPortToIPKeys(map[string]struct{}{"vm-1": {}, "vm-2": {}})
	if len(got[port1]) != 1 || got[port1][0] != ip1 || len(got[port2]) != 1 || got[port2][0] != ip3 {
		t.Fatalf("snapshot accepted cross-instance port/IP metadata: %v", got)
	}
	for _, key := range got[port1] {
		if key == ip2 {
			t.Fatal("vm-2 IP was attached to vm-1-owned port")
		}
	}
}

func TestOVNZoneParserRejectsOnePortMappedToMultipleZones(t *testing.T) {
	port := "11111111-1111-1111-1111-111111111111"
	ip := IPStrToKey("192.0.2.42")
	_, _, _, err := parseOVNZoneList(
		[]byte(port+" 42\n"+port+" 43\n"),
		map[string]string{port: "vm-42"},
		map[string][]IPKey{port: {ip}},
	)
	if err == nil {
		t.Fatal("one logical port was accepted with multiple conntrack zones")
	}
}

func TestPartialBlockStatsKeepInventoryCountButNotAggregateConfidence(t *testing.T) {
	mc := newCollectorOrchestrationTestCollector(t)
	now := time.Unix(1_700_300_000, 0)
	const instanceUUID = "vm-partial-blocks"
	meta := &DomainStatic{Disks: []DomainDisk{
		{TargetDev: "vda", Type: "network", SourceName: "rbd/volume-a"},
		{TargetDev: "vdb", Type: "network", SourceName: "rbd/volume-b"},
	}}
	idx := shardIndex(instanceUUID)
	mc.im.diskSamples[idx] = map[string]diskSample{
		instanceUUID + "|volume-a|vda": {
			rdReq: 1, wrReq: 1, rdBytes: 1, wrBytes: 1, rdTime: 1, wrTime: 1,
			rwPresent: true, ts: now.Add(-time.Second),
		},
	}
	partial := &ParsedStats{
		BlockCount: 2, BlockCountPresent: true,
		Disks: map[int]*DiskStat{0: fullDiskStat("vda", 10, 1000, 100_000_000, 0, 0)},
	}
	metrics := make([]prometheus.Metric, 0)
	count, _, _, available := mc.collectDomainDiskMetrics(
		meta, partial, now,
		"domain", "server", instanceUUID, "project", "project-name", "user",
		true, &metrics,
	)
	if count != 2 {
		t.Fatalf("partial block record undercounted known active disks: count=%d", count)
	}
	if available {
		t.Fatal("one of two block records was treated as complete aggregate disk telemetry")
	}
	if len(metrics) == 0 {
		t.Fatal("valid per-disk metrics were discarded with partial aggregate telemetry")
	}
}

func TestUnknownStatDiskWithoutDerivedTelemetryMakesAggregateUnavailable(t *testing.T) {
	mc := newCollectorOrchestrationTestCollector(t)
	now := time.Unix(1_700_050_000, 0)
	const instanceUUID = "vm-unknown-partial-disk"
	meta := &DomainStatic{Disks: []DomainDisk{{TargetDev: "vda", Type: "network", SourceName: "rbd/volume-a"}}}
	idx := shardIndex(instanceUUID)
	mc.im.diskSamples[idx] = map[string]diskSample{
		instanceUUID + "|volume-a|vda": {
			rdReq: 10, wrReq: 10, rdBytes: 1000, wrBytes: 1000,
			rdTime: 10, wrTime: 10, rwPresent: true, ts: now.Add(-time.Second),
		},
	}
	stats := &ParsedStats{Disks: map[int]*DiskStat{
		0: fullDiskStat("vda", 20, 2000, 100_000_010, 0, 0),
		1: {Name: "vdb", NamePresent: true, Capacity: 1024, CapacityPresent: true},
	}}
	metrics := make([]prometheus.Metric, 0)
	count, _, _, available := mc.collectDomainDiskMetrics(
		meta, stats, now,
		"domain", "server", instanceUUID, "project", "project-name", "user",
		true, &metrics,
	)
	if count != 2 {
		t.Fatalf("stat-only disk was omitted from inventory count: %d", count)
	}
	if available {
		t.Fatal("stat-only disk without derived telemetry was omitted from aggregate completeness")
	}
}

func TestUnnamedStatDiskWithoutBlockCountMakesAggregateUnavailable(t *testing.T) {
	mc := newCollectorOrchestrationTestCollector(t)
	now := time.Unix(1_700_055_000, 0)
	const instanceUUID = "vm-unnamed-partial-disk"
	meta := &DomainStatic{Disks: []DomainDisk{{TargetDev: "vda", Type: "network", SourceName: "rbd/volume-a"}}}
	idx := shardIndex(instanceUUID)
	mc.im.diskSamples[idx] = map[string]diskSample{
		instanceUUID + "|volume-a|vda": {
			rdReq: 10, wrReq: 10, rdBytes: 1000, wrBytes: 1000,
			rdTime: 10, wrTime: 10, rwPresent: true, ts: now.Add(-time.Second),
		},
	}
	stats := &ParsedStats{Disks: map[int]*DiskStat{
		0: fullDiskStat("vda", 20, 2000, 100_000_010, 0, 0),
		1: {Capacity: 1024, CapacityPresent: true},
	}}
	metrics := make([]prometheus.Metric, 0)
	_, _, _, available := mc.collectDomainDiskMetrics(
		meta, stats, now,
		"domain", "server", instanceUUID, "project", "project-name", "user",
		true, &metrics,
	)
	if available {
		t.Fatal("unnamed block record was silently omitted from aggregate completeness")
	}
}

func TestDiskInventoryCountUsesMetadataAndStatUnion(t *testing.T) {
	mc := newCollectorOrchestrationTestCollector(t)
	meta := &DomainStatic{Disks: []DomainDisk{{TargetDev: "vda", Type: "network", SourceName: "rbd/volume-a"}}}
	stats := &ParsedStats{Disks: map[int]*DiskStat{
		0: {Name: "vdb", NamePresent: true, Capacity: 1024, CapacityPresent: true},
	}}
	metrics := make([]prometheus.Metric, 0)
	count, _, _, available := mc.collectDomainDiskMetrics(
		meta, stats, time.Unix(1_700_060_000, 0),
		"domain", "server", "vm-disjoint-disk-inventory", "project", "project-name", "user",
		true, &metrics,
	)
	if count != 2 {
		t.Fatalf("disjoint metadata/stat disk inventory was undercounted: got %d want 2", count)
	}
	if available {
		t.Fatal("disjoint partial disk telemetry was available")
	}
}

func TestProjectAggregationUsesProjectIdentityNotDisplayName(t *testing.T) {
	mc := newCollectorOrchestrationTestCollector(t)
	agg := &hostAgg{projects: make(map[string]struct{})}
	records := []struct {
		uuid        libvirt.UUID
		projectUUID string
	}{
		{uuid: libvirt.UUID{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, projectUUID: "project-a"},
		{uuid: libvirt.UUID{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2}, projectUUID: "project-b"},
	}
	for _, item := range records {
		instanceUUID := uuidBytesToString(item.uuid[:])
		mc.im.domainMeta[instanceUUID] = &DomainStatic{
			Name: "server", InstanceUUID: instanceUUID,
			ProjectUUID: item.projectUUID, ProjectName: "shared-name", UserUUID: "user",
			LastUpdated: time.Now(),
		}
		mc.collectDomainMetrics(
			libvirt.DomainStatsRecord{
				Dom:    libvirt.Domain{Name: "domain", UUID: item.uuid},
				Params: []libvirt.TypedParam{typedParam("state.state", int32(libvirt.DomainPaused))},
			},
			nil, nil, agg, 0, false, false, true,
		)
	}
	if len(agg.projects) != 2 {
		t.Fatalf("different projects sharing a display name collapsed: %v", agg.projects)
	}
}

func TestLibvirtBooleanTypedParametersAreNotNumericTelemetry(t *testing.T) {
	boolean := *libvirt.NewTypedParamValueBoolean(1)
	stats := parseLibvirtStats([]libvirt.TypedParam{
		{Field: "state.state", Value: boolean},
		{Field: "cpu.time", Value: boolean},
		{Field: "balloon.current", Value: boolean},
		{Field: "vcpu.0.time", Value: boolean},
		{Field: "block.0.rd.reqs", Value: boolean},
		{Field: "net.0.rx.pkts", Value: boolean},
	})
	if stats.StatePresent || stats.CpuTimePresent || stats.MemCurPresent || len(stats.Vcpus) != 0 || len(stats.Disks) != 0 || len(stats.Nets) != 0 {
		t.Fatalf("boolean typed parameters became numeric telemetry: %+v", stats)
	}
}

func TestVMIPIndexKeepsOverlappingOwnershipAmbiguousAndRecovers(t *testing.T) {
	im := newInventoryStateTestManager()
	shared := IPStrToKey("192.0.2.50")
	im.updateVMIPIndex("vm-1", []IP{{Address: "192.0.2.50"}})
	im.updateVMIPIndex("vm-2", []IP{{Address: "192.0.2.50"}})
	set, owners := im.getVMIPIndexSnapshot()
	if _, ok := set[shared]; !ok || owners[shared] != "" {
		t.Fatalf("overlapping address silently chose an owner: set=%v owners=%v", set, owners)
	}
	if ownerSet := im.vmIPOwners[shared]; len(ownerSet) != 2 {
		t.Fatalf("incremental ownership did not retain both instances: %v", ownerSet)
	}

	im.removeVMIPIndex("vm-1")
	set, owners = im.getVMIPIndexSnapshot()
	if _, ok := set[shared]; !ok || owners[shared] != "vm-2" {
		t.Fatalf("removing one owner lost the remaining owner: set=%v owners=%v", set, owners)
	}
	if ownerSet := im.vmIPOwners[shared]; len(ownerSet) != 1 {
		t.Fatalf("incremental ownership did not remove only the departed instance: %v", ownerSet)
	} else if _, ok := ownerSet["vm-2"]; !ok {
		t.Fatalf("remaining owner missing from incremental state: %v", ownerSet)
	}
}

func TestDiskConfidenceComesFromDiskSupplyingPressure(t *testing.T) {
	mc := newCollectorOrchestrationTestCollector(t)
	now := time.Unix(1_700_100_000, 0)
	const instanceUUID = "vm-disk-confidence"
	meta := &DomainStatic{Disks: []DomainDisk{
		{TargetDev: "vda", Type: "network", SourceName: "rbd/slow"},
		{TargetDev: "vdb", Type: "network", SourceName: "rbd/busy"},
	}}

	idx := shardIndex(instanceUUID)
	mc.im.diskSamples[idx] = map[string]diskSample{
		instanceUUID + "|slow|vda": {
			rdReq: 10, wrReq: 10, rdBytes: 1000, wrBytes: 1000,
			rdTime: 10, wrTime: 10, rwPresent: true, ts: now.Add(-time.Second),
		},
		instanceUUID + "|busy|vdb": {
			rdReq: 10, wrReq: 10, rdBytes: 1000, wrBytes: 1000,
			rdTime: 10, wrTime: 10, rwPresent: true, ts: now.Add(-time.Second),
		},
	}

	stats := &ParsedStats{Disks: map[int]*DiskStat{
		0: {
			Name: "vda", NamePresent: true,
			RdReqs: 15, RdReqsPresent: true, WrReqs: 10, WrReqsPresent: true,
			RdBytes: 2000, RdBytesPresent: true, WrBytes: 1000, WrBytesPresent: true,
			RdTime: 5_000_000_010, RdTimePresent: true, WrTime: 10, WrTimePresent: true,
		},
		1: {
			Name: "vdb", NamePresent: true,
			RdReqs: 1010, RdReqsPresent: true, WrReqs: 1010, WrReqsPresent: true,
			RdBytes: 100_001_000, RdBytesPresent: true, WrBytes: 100_001_000, WrBytesPresent: true,
			RdTime: 10, RdTimePresent: true, WrTime: 10, WrTimePresent: true,
		},
	}}
	metrics := make([]prometheus.Metric, 0)
	_, pressure, activity, available := mc.collectDomainDiskMetrics(
		meta, stats, now,
		"domain", "server", instanceUUID, "project", "project-name", "user",
		true, &metrics,
	)
	if !available || pressure < 99 {
		t.Fatalf("high-latency disk pressure unavailable: pressure=%v available=%v", pressure, available)
	}
	if activity > 0.1 {
		t.Fatalf("slow disk inherited unrelated busy-disk confidence: activity=%v", activity)
	}
}

func TestDiskSelectionUsesPressureWithItsConfidence(t *testing.T) {
	mc := newCollectorOrchestrationTestCollector(t)
	now := time.Unix(1_700_150_000, 0)
	const instanceUUID = "vm-disk-projected-severity"
	meta := &DomainStatic{Disks: []DomainDisk{
		{TargetDev: "vda", Type: "network", SourceName: "rbd/rare-slow"},
		{TargetDev: "vdb", Type: "network", SourceName: "rbd/busy-degraded"},
	}}
	idx := shardIndex(instanceUUID)
	mc.im.diskSamples[idx] = map[string]diskSample{
		instanceUUID + "|rare-slow|vda": {
			rdReq: 10, wrReq: 10, rdBytes: 1000, wrBytes: 1000,
			rdTime: 10, wrTime: 10, rwPresent: true, ts: now.Add(-time.Second),
		},
		instanceUUID + "|busy-degraded|vdb": {
			rdReq: 10, wrReq: 10, rdBytes: 1000, wrBytes: 1000,
			rdTime: 10, wrTime: 10, rwPresent: true, ts: now.Add(-time.Second),
		},
	}
	stats := &ParsedStats{Disks: map[int]*DiskStat{
		0: {
			Name: "vda", NamePresent: true,
			RdReqs: 15, RdReqsPresent: true, WrReqs: 10, WrReqsPresent: true,
			RdBytes: 2000, RdBytesPresent: true, WrBytes: 1000, WrBytesPresent: true,
			RdTime: 500_000_010, RdTimePresent: true, WrTime: 10, WrTimePresent: true,
		},
		1: {
			Name: "vdb", NamePresent: true,
			RdReqs: 110, RdReqsPresent: true, WrReqs: 10, WrReqsPresent: true,
			RdBytes: 10_001_000, RdBytesPresent: true, WrBytes: 1000, WrBytesPresent: true,
			RdTime: 1_100_000_010, RdTimePresent: true, WrTime: 10, WrTimePresent: true,
		},
	}}
	metrics := make([]prometheus.Metric, 0)
	_, pressure, activity, available := mc.collectDomainDiskMetrics(
		meta, stats, now,
		"domain", "server", instanceUUID, "project", "project-name", "user",
		true, &metrics,
	)
	if !available {
		t.Fatal("complete disk telemetry was unavailable")
	}
	if pressure < 40 || pressure > 60 || activity < 0.9 {
		t.Fatalf("near-zero-confidence raw maximum masked the actionable disk: pressure=%v activity=%v", pressure, activity)
	}
}

func TestFlushOnlyDiskIntervalHasOwnActivityConfidenceAndResetRecovery(t *testing.T) {
	mc := newCollectorOrchestrationTestCollector(t)
	now := time.Unix(1_700_200_000, 0)
	const instanceUUID = "vm-flush-confidence"
	meta := &DomainStatic{Disks: []DomainDisk{{TargetDev: "vda", Type: "network", SourceName: "rbd/volume-a"}}}
	idx := shardIndex(instanceUUID)
	key := instanceUUID + "|volume-a|vda"
	mc.im.diskSamples[idx] = map[string]diskSample{
		key: {flReq: 10, flTime: 1_000_000_000, flushPresent: true, ts: now.Add(-time.Second)},
	}

	collect := func(at time.Time, reqs, duration uint64) (float64, float64, bool) {
		stats := &ParsedStats{Disks: map[int]*DiskStat{0: {
			Name: "vda", NamePresent: true,
			FlReqs: reqs, FlReqsPresent: true, FlTime: duration, FlTimePresent: true,
		}}}
		metrics := make([]prometheus.Metric, 0)
		_, pressure, activity, available := mc.collectDomainDiskMetrics(
			meta, stats, at,
			"domain", "server", instanceUUID, "project", "project-name", "user",
			true, &metrics,
		)
		return pressure, activity, available
	}

	pressure, activity, available := collect(now, 11, 101_000_000_000)
	if !available || pressure < 99 || activity <= 0 {
		t.Fatalf("flush-only pressure lost confidence: pressure=%v activity=%v available=%v", pressure, activity, available)
	}
	pressure, activity, available = collect(now.Add(time.Second), 1, 100)
	if available || pressure != 0 || activity != 0 {
		t.Fatalf("flush reset produced confident telemetry: pressure=%v activity=%v available=%v", pressure, activity, available)
	}
	pressure, activity, available = collect(now.Add(2*time.Second), 2, 100_000_100)
	if !available || pressure < 99 || activity <= 0 {
		t.Fatalf("flush telemetry did not recover after reset: pressure=%v activity=%v available=%v", pressure, activity, available)
	}
}

func TestDiskCountersRemainMonotonicAcrossSignedBoundary(t *testing.T) {
	mc := newCollectorOrchestrationTestCollector(t)
	now := time.Unix(1_700_250_000, 0)
	const instanceUUID = "vm-wide-disk-counters"
	meta := &DomainStatic{Disks: []DomainDisk{{TargetDev: "vda", Type: "network", SourceName: "rbd/volume-wide"}}}
	boundary := uint64(^uint64(0) >> 1)

	collect := func(at time.Time, value uint64) bool {
		stats := &ParsedStats{Disks: map[int]*DiskStat{0: fullDiskStat("vda", value, value, value, value, value)}}
		metrics := make([]prometheus.Metric, 0)
		_, _, _, available := mc.collectDomainDiskMetrics(
			meta, stats, at,
			"domain", "server", instanceUUID, "project", "project-name", "user",
			true, &metrics,
		)
		return available
	}

	if collect(now, boundary-100) {
		t.Fatal("first wide-counter disk sample was available")
	}
	if !collect(now.Add(time.Second), boundary+100) {
		t.Fatal("monotonic uint64 disk counters were mistaken for a reset at the signed boundary")
	}
}

func TestNetworkDropPressureDoesNotInheritConntrackAvailabilityConfidence(t *testing.T) {
	mc := newCollectorOrchestrationTestCollector(t)
	const instanceUUID = "00112233-4455-6677-8899-aabbccddeeff"
	uuid := libvirt.UUID{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	ip := IPStrToKey("192.0.2.10")
	mc.im.domainMeta[instanceUUID] = &DomainStatic{
		Name: "server", InstanceUUID: instanceUUID,
		ProjectUUID: "project", ProjectName: "project-name", UserUUID: "user",
		FixedIPs: []IP{{Address: "192.0.2.10", Family: "4"}}, Interfaces: []string{"tap0"},
		LastUpdated: time.Now(),
	}
	idx := shardIndex(instanceUUID)
	mc.im.netSamples[idx] = map[string]netSample{
		instanceUUID: {interfaceSet: "tap0", ts: time.Now().Add(-time.Second)},
	}
	record := libvirt.DomainStatsRecord{
		Dom: libvirt.Domain{Name: "domain", UUID: uuid},
		Params: []libvirt.TypedParam{
			typedParam("state.state", int32(libvirt.DomainRunning)),
			typedParam("net.count", uint32(1)),
			typedParam("net.0.name", "tap0"),
			typedParam("net.0.rx.pkts", uint64(0)),
			typedParam("net.0.tx.pkts", uint64(0)),
			typedParam("net.0.rx.drop", uint64(1)),
			typedParam("net.0.tx.drop", uint64(0)),
		},
	}
	connAgg := &ConntrackAgg{
		VMIndex:            map[VMIPIdentity]uint32{{InstanceUUID: instanceUUID, IP: ip}: 0},
		InstanceFlowTotals: map[string]int{instanceUUID: 0},
		FlowsIn:            []int{0}, FlowsOut: []int{0},
		InboundStats: []*behaviorStats{nil}, OutboundStats: []*behaviorStats{nil},
	}
	agg := &hostAgg{projects: make(map[string]struct{})}
	mc.collectDomainMetrics(record, connAgg, nil, agg, 100_000, true, true, true)

	state := mc.resourceV2[instanceUUID]
	if state == nil || !state.Net.Initialized {
		t.Fatal("network resource state was not initialized")
	}
	if state.Net.EWMA >= 0.01 {
		t.Fatalf("one low-rate drop inherited full confidence from zero-pressure conntrack availability: ewma=%v", state.Net.EWMA)
	}
}

func TestConntrackPressureDoesNotInheritUnrelatedPacketRateImpact(t *testing.T) {
	mc := newCollectorOrchestrationTestCollector(t)
	const instanceUUID = "10213243-5465-7687-98a9-bacbdcedfe0f"
	uuid := libvirt.UUID{0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f}
	ip := IPStrToKey("192.0.2.20")
	mc.im.domainMeta[instanceUUID] = &DomainStatic{
		Name: "server", InstanceUUID: instanceUUID,
		ProjectUUID: "project", ProjectName: "project-name", UserUUID: "user",
		FixedIPs: []IP{{Address: "192.0.2.20", Family: "4"}}, Interfaces: []string{"tap0"},
		LastUpdated: time.Now(),
	}
	idx := shardIndex(instanceUUID)
	mc.im.netSamples[idx] = map[string]netSample{
		instanceUUID: {interfaceSet: "tap0", ts: time.Now().Add(-time.Second)},
	}
	record := libvirt.DomainStatsRecord{
		Dom: libvirt.Domain{Name: "domain", UUID: uuid},
		Params: []libvirt.TypedParam{
			typedParam("state.state", int32(libvirt.DomainRunning)),
			typedParam("net.count", uint32(1)),
			typedParam("net.0.name", "tap0"),
			typedParam("net.0.rx.pkts", uint64(1_000_000_000)),
			typedParam("net.0.tx.pkts", uint64(1_000_000_000)),
			typedParam("net.0.rx.drop", uint64(0)),
			typedParam("net.0.tx.drop", uint64(0)),
		},
	}
	connAgg := &ConntrackAgg{
		VMIndex:            map[VMIPIdentity]uint32{{InstanceUUID: instanceUUID, IP: ip}: 0},
		InstanceFlowTotals: map[string]int{instanceUUID: 2_000},
		FlowsIn:            []int{0}, FlowsOut: []int{2_000},
		InboundStats: []*behaviorStats{nil}, OutboundStats: []*behaviorStats{nil},
	}
	agg := &hostAgg{projects: make(map[string]struct{})}
	mc.collectDomainMetrics(record, connAgg, nil, agg, 100_000, true, true, true)

	state := mc.resourceV2[instanceUUID]
	if state == nil || !state.Net.Initialized {
		t.Fatal("network resource state was not initialized")
	}
	if math.Abs(state.Net.Impact-0.2) > 0.02 {
		t.Fatalf("conntrack pressure inherited unrelated packet-rate impact: impact=%v want about 0.2", state.Net.Impact)
	}
}

func TestNetworkSourceSelectionUsesProjectedSeverity(t *testing.T) {
	mc := newCollectorOrchestrationTestCollector(t)
	const instanceUUID = "20314253-6475-8697-a8b9-cadbecfd0e1f"
	uuid := libvirt.UUID{0x20, 0x31, 0x42, 0x53, 0x64, 0x75, 0x86, 0x97, 0xa8, 0xb9, 0xca, 0xdb, 0xec, 0xfd, 0x0e, 0x1f}
	ip := IPStrToKey("192.0.2.30")
	mc.im.domainMeta[instanceUUID] = &DomainStatic{
		Name: "server", InstanceUUID: instanceUUID,
		ProjectUUID: "project", ProjectName: "project-name", UserUUID: "user",
		FixedIPs: []IP{{Address: "192.0.2.30", Family: "4"}}, Interfaces: []string{"tap0"},
		LastUpdated: time.Now(),
	}
	idx := shardIndex(instanceUUID)
	mc.im.netSamples[idx] = map[string]netSample{
		instanceUUID: {interfaceSet: "tap0", ts: time.Now().Add(-time.Second)},
	}
	record := libvirt.DomainStatsRecord{
		Dom: libvirt.Domain{Name: "domain", UUID: uuid},
		Params: []libvirt.TypedParam{
			typedParam("state.state", int32(libvirt.DomainRunning)),
			typedParam("net.count", uint32(1)),
			typedParam("net.0.name", "tap0"),
			typedParam("net.0.rx.pkts", uint64(0)),
			typedParam("net.0.tx.pkts", uint64(0)),
			typedParam("net.0.rx.drop", uint64(1)),
			typedParam("net.0.tx.drop", uint64(0)),
		},
	}
	connAgg := &ConntrackAgg{
		VMIndex:            map[VMIPIdentity]uint32{{InstanceUUID: instanceUUID, IP: ip}: 0},
		InstanceFlowTotals: map[string]int{instanceUUID: 1_450},
		FlowsIn:            []int{0}, FlowsOut: []int{1_450},
		InboundStats: []*behaviorStats{nil}, OutboundStats: []*behaviorStats{nil},
	}
	agg := &hostAgg{projects: make(map[string]struct{})}
	mc.collectDomainMetrics(record, connAgg, nil, agg, 100_000, true, true, true)

	state := mc.resourceV2[instanceUUID]
	if state == nil || !state.Net.Initialized {
		t.Fatal("network resource state was not initialized")
	}
	if state.Net.EWMA < 0.02 || state.Net.Impact < 0.1 {
		t.Fatalf("high-pressure but near-zero-confidence drop source masked conntrack pressure: ewma=%v impact=%v", state.Net.EWMA, state.Net.Impact)
	}
}

func TestNetworkAggregateCounterOverflowIsUnavailable(t *testing.T) {
	mc := newCollectorOrchestrationTestCollector(t)
	meta := &DomainStatic{Interfaces: []string{"tap0", "tap1"}}
	stats := &ParsedStats{
		NetCount: 2, NetCountPresent: true,
		Nets: map[int]*NetStat{
			0: {
				Name: "tap0", NamePresent: true,
				RxPkts: ^uint64(0), RxPktsPresent: true, TxPktsPresent: true,
				RxDropPresent: true, TxDropPresent: true,
			},
			1: {
				Name: "tap1", NamePresent: true,
				RxPkts: 1, RxPktsPresent: true, TxPktsPresent: true,
				RxDropPresent: true, TxDropPresent: true,
			},
		},
	}
	collect := func(now time.Time) bool {
		metrics := make([]prometheus.Metric, 0)
		_, _, _, _, _, available, _ := mc.collectDomainNetworkAndConntrack(
			meta, stats, now,
			"domain", "server", "vm-net-overflow", "project", "project-name", "user",
			true, nil, nil, nil, nil, 0, false, true, &metrics,
		)
		return available
	}
	now := time.Unix(1_700_450_000, 0)
	if collect(now) {
		t.Fatal("first network sample was available")
	}
	if collect(now.Add(time.Second)) {
		t.Fatal("overflowed multi-interface aggregate became a valid healthy zero rate")
	}
}

func TestZeroHostConntrackCapacityDoesNotMakeNetworkAvailable(t *testing.T) {
	mc := newCollectorOrchestrationTestCollector(t)
	const instanceUUID = "30415263-7485-96a7-b8c9-daebfc0d1e2f"
	uuid := libvirt.UUID{0x30, 0x41, 0x52, 0x63, 0x74, 0x85, 0x96, 0xa7, 0xb8, 0xc9, 0xda, 0xeb, 0xfc, 0x0d, 0x1e, 0x2f}
	ip := IPStrToKey("192.0.2.40")
	mc.im.domainMeta[instanceUUID] = &DomainStatic{
		Name: "server", InstanceUUID: instanceUUID,
		ProjectUUID: "project", ProjectName: "project-name", UserUUID: "user",
		FixedIPs:    []IP{{Address: "192.0.2.40", Family: "4"}},
		LastUpdated: time.Now(),
	}
	record := libvirt.DomainStatsRecord{
		Dom:    libvirt.Domain{Name: "domain", UUID: uuid},
		Params: []libvirt.TypedParam{typedParam("state.state", int32(libvirt.DomainRunning))},
	}
	connAgg := &ConntrackAgg{
		VMIndex:            map[VMIPIdentity]uint32{{InstanceUUID: instanceUUID, IP: ip}: 0},
		InstanceFlowTotals: map[string]int{instanceUUID: 0},
		FlowsIn:            []int{0}, FlowsOut: []int{0},
		InboundStats: []*behaviorStats{nil}, OutboundStats: []*behaviorStats{nil},
	}
	agg := &hostAgg{projects: make(map[string]struct{})}
	mc.collectDomainMetrics(record, connAgg, nil, agg, 0, true, true, true)

	if state := mc.resourceV2[instanceUUID]; state != nil && state.Net.Initialized {
		t.Fatal("available-but-zero host conntrack capacity initialized a healthy network axis")
	}
}
