package main

import (
	"math"
	"testing"
	"time"

	libvirt "github.com/digitalocean/go-libvirt"
	"github.com/prometheus/client_golang/prometheus"
)

func TestTypedParamNumericConversions(t *testing.T) {
	for _, value := range []interface{}{uint64(7), uint32(7), uint(7), int64(7), int32(7), int(7), true} {
		got, ok := typedParamUint64(value)
		if !ok || got != 7 && value != true {
			t.Fatalf("typedParamUint64(%T(%v))=(%d,%v)", value, value, got, ok)
		}
		if value == true && got != 1 {
			t.Fatalf("typedParamUint64(true)=%d, want 1", got)
		}
	}
	if got, ok := typedParamUint64(false); !ok || got != 0 {
		t.Fatalf("typedParamUint64(false)=(%d,%v)", got, ok)
	}
	for _, value := range []interface{}{int64(-1), int32(-1), int(-1), "7", float64(7)} {
		if got, ok := typedParamUint64(value); ok || got != 0 {
			t.Fatalf("typedParamUint64(%T(%v))=(%d,%v), want 0,false", value, value, got, ok)
		}
	}
	if got, ok := typedParamInt(uint64(math.MaxUint64)); ok || got != 0 {
		t.Fatalf("overflowing typedParamInt=(%d,%v)", got, ok)
	}
	if got, ok := typedParamInt(uint32(42)); !ok || got != 42 {
		t.Fatalf("typedParamInt(42)=(%d,%v)", got, ok)
	}
}

func TestParseLibvirtStatsCoversEveryTelemetryFamily(t *testing.T) {
	params := []libvirt.TypedParam{
		typedParam("state.state", uint32(libvirt.DomainBlocked)),
		typedParam("cpu.time", uint64(1)),
		typedParam("cpu.user", uint64(2)),
		typedParam("cpu.system", uint64(3)),
		typedParam("balloon.maximum", uint64(4)),
		typedParam("balloon.current", uint64(5)),
		typedParam("balloon.usable", uint64(6)),
		typedParam("balloon.rss", uint64(7)),
		typedParam("balloon.swap_in", uint64(8)),
		typedParam("balloon.swap_out", uint64(9)),
		typedParam("balloon.major_fault", uint64(10)),
		typedParam("balloon.minor_fault", uint64(11)),
		typedParam("balloon.hugetlb_pgalloc", uint64(12)),
		typedParam("balloon.hugetlb_pgfail", uint64(13)),
		typedParam("vcpu.2.state", uint64(1)),
		typedParam("vcpu.2.time", uint64(20)),
		typedParam("vcpu.2.wait", uint64(21)),
		typedParam("vcpu.2.delay", uint64(22)),
		typedParam("vcpu.bad.time", uint64(99)),
		typedParam("vcpu.-1.time", uint64(99)),
		typedParam("block.3.name", "vda"),
		typedParam("block.3.rd.reqs", uint64(30)),
		typedParam("block.3.rd.bytes", uint64(31)),
		typedParam("block.3.rd.times", uint64(32)),
		typedParam("block.3.wr.reqs", uint64(33)),
		typedParam("block.3.wr.bytes", uint64(34)),
		typedParam("block.3.wr.times", uint64(35)),
		typedParam("block.3.fl.reqs", uint64(36)),
		typedParam("block.3.fl.times", uint64(37)),
		typedParam("block.3.capacity", uint64(38)),
		typedParam("block.3.allocation", uint64(39)),
		typedParam("block.3.physical", uint64(40)),
		typedParam("block.bad.rd.reqs", uint64(99)),
		typedParam("net.4.name", "tap4"),
		typedParam("net.4.rx.bytes", uint64(40)),
		typedParam("net.4.rx.pkts", uint64(41)),
		typedParam("net.4.rx.errs", uint64(42)),
		typedParam("net.4.rx.drop", uint64(43)),
		typedParam("net.4.tx.bytes", uint64(44)),
		typedParam("net.4.tx.pkts", uint64(45)),
		typedParam("net.4.tx.errs", uint64(46)),
		typedParam("net.4.tx.drop", uint64(47)),
		typedParam("net.-1.rx.bytes", uint64(99)),
		typedParam("ignored.field", uint64(99)),
	}
	stats := parseLibvirtStats(params)
	if !stats.StatePresent || stats.State != int(libvirt.DomainBlocked) || !stats.CpuTimePresent || !stats.CpuUserPresent || !stats.CpuSystemPresent {
		t.Fatalf("top-level parsed stats=%+v", stats)
	}
	if stats.MemMax != 4 || stats.MemCur != 5 || stats.MemUsable != 6 || stats.MemRss != 7 || stats.SwapIn != 8 || stats.SwapOut != 9 || stats.MajorFault != 10 || stats.MinorFault != 11 || stats.HugetlbPgAlloc != 12 || stats.HugetlbPgFail != 13 {
		t.Fatalf("memory parsed stats=%+v", stats)
	}
	vcpu := stats.Vcpus[2]
	if vcpu == nil || !vcpu.StatePresent || !vcpu.TimePresent || !vcpu.WaitPresent || !vcpu.DelayPresent || vcpu.Time != 20 || len(stats.Vcpus) != 1 {
		t.Fatalf("vCPU parsed stats=%v all=%v", vcpu, stats.Vcpus)
	}
	disk := stats.Disks[3]
	if disk == nil || disk.Name != "vda" || disk.RdReqs != 30 || disk.WrReqs != 33 || disk.FlReqs != 36 || disk.Capacity != 38 || disk.Allocation != 39 || disk.Physical != 40 || len(stats.Disks) != 1 {
		t.Fatalf("disk parsed stats=%v all=%v", disk, stats.Disks)
	}
	nic := stats.Nets[4]
	if nic == nil || nic.Name != "tap4" || nic.RxBytes != 40 || nic.RxPkts != 41 || nic.RxErrs != 42 || nic.RxDrop != 43 || nic.TxBytes != 44 || nic.TxPkts != 45 || nic.TxErrs != 46 || nic.TxDrop != 47 || len(stats.Nets) != 1 {
		t.Fatalf("network parsed stats=%v all=%v", nic, stats.Nets)
	}
}

func TestMemoryMetricCollectionAvailabilityAndPressure(t *testing.T) {
	mc := newCollectorOrchestrationTestCollector(t)
	now := time.Unix(1_700_000_000, 0)
	stat := &ParsedStats{
		MemCur: 1000 * 1024, MemCurPresent: true,
		MemUsable: 100 * 1024, MemUsablePresent: true,
		MemRss: 800 * 1024, MemRssPresent: true,
		SwapIn: 100, SwapInPresent: true,
		SwapOut: 200, SwapOutPresent: true,
		MajorFault: 10, MajorFaultPresent: true,
		MinorFault: 20, MinorFaultPresent: true,
		HugetlbPgAlloc: 2, HugetlbPgAllocPresent: true,
		HugetlbPgFail: 3, HugetlbPgFailPresent: true,
	}
	firstMetrics := make([]prometheus.Metric, 0)
	used, severity, usedOK, pressureOK := mc.collectDomainMemoryMetrics(stat, now, "domain", "server", "vm-memory", "project", "project-name", "user", true, 1000, true, &firstMetrics)
	if used != 900 || severity <= 0 || !usedOK || !pressureOK || len(firstMetrics) != 8 {
		t.Fatalf("first memory collection used=%v severity=%v usedOK=%v pressureOK=%v metrics=%d", used, severity, usedOK, pressureOK, len(firstMetrics))
	}

	stat.SwapIn += 20_000
	stat.SwapOut += 10
	stat.MajorFault += 100
	stat.MinorFault += 10
	secondMetrics := make([]prometheus.Metric, 0)
	_, secondSeverity, _, secondPressureOK := mc.collectDomainMemoryMetrics(stat, now.Add(time.Second), "domain", "server", "vm-memory", "project", "project-name", "user", true, 1000, true, &secondMetrics)
	if secondSeverity <= severity || !secondPressureOK {
		t.Fatalf("memory rate pressure severity=%v, first=%v available=%v", secondSeverity, severity, secondPressureOK)
	}

	stoppedMetrics := make([]prometheus.Metric, 0)
	used, severity, usedOK, pressureOK = mc.collectDomainMemoryMetrics(stat, now.Add(2*time.Second), "domain", "server", "vm-stopped", "project", "project-name", "user", false, 1000, false, &stoppedMetrics)
	if used != 0 || severity != 0 || usedOK || pressureOK || len(stoppedMetrics) != 7 {
		t.Fatalf("stopped memory used=%v severity=%v usedOK=%v pressureOK=%v metrics=%d", used, severity, usedOK, pressureOK, len(stoppedMetrics))
	}
}

func TestCPUMetricCollectionFirstSampleStallsAndFreshness(t *testing.T) {
	mc := newCollectorOrchestrationTestCollector(t)
	stat := &ParsedStats{
		CpuTime:        1_000_000,
		CpuTimePresent: true,
		Vcpus: map[int]*VcpuStat{
			0: {Delay: 10, DelayPresent: true, Wait: 20, WaitPresent: true},
			1: {Delay: 30, DelayPresent: true, Wait: 40, WaitPresent: true},
		},
	}
	firstMetrics := make([]prometheus.Metric, 0)
	if signal, ok := mc.collectDomainCPUMetrics(stat, "domain", "server", "vm-cpu", "project", "project-name", "user", 2, true, &firstMetrics); ok || signal != 0 || len(firstMetrics) != 4 {
		t.Fatalf("first CPU collection signal=%v ok=%v metrics=%d", signal, ok, len(firstMetrics))
	}
	time.Sleep(2 * time.Millisecond)
	stat.CpuTime += 4_000_000
	stat.Vcpus[0].Delay += 1_000_000
	stat.Vcpus[0].Wait += 1_000_000
	stat.Vcpus[1].Delay += 1_000_000
	stat.Vcpus[1].Wait += 1_000_000
	secondMetrics := make([]prometheus.Metric, 0)
	if signal, ok := mc.collectDomainCPUMetrics(stat, "domain", "server", "vm-cpu", "project", "project-name", "user", 2, true, &secondMetrics); !ok || signal <= 0 || len(secondMetrics) != 5 {
		t.Fatalf("second CPU collection signal=%v ok=%v metrics=%d", signal, ok, len(secondMetrics))
	}

	staleMetrics := make([]prometheus.Metric, 0)
	if signal, ok := mc.collectDomainCPUMetrics(stat, "domain", "server", "vm-stale-cpu", "project", "project-name", "user", 2, false, &staleMetrics); ok || signal != 0 || len(staleMetrics) != 4 {
		t.Fatalf("stale CPU collection signal=%v ok=%v metrics=%d", signal, ok, len(staleMetrics))
	}
	stat.CpuTimePresent = false
	if signal, ok := mc.collectDomainCPUMetrics(stat, "domain", "server", "vm-missing-cpu", "project", "project-name", "user", 2, true, &staleMetrics); ok || signal != 0 {
		t.Fatalf("missing CPU counter signal=%v ok=%v", signal, ok)
	}
}

func fullDiskStat(name string, reqs uint64, bytes uint64, rwTime uint64, flushReqs uint64, flushTime uint64) *DiskStat {
	return &DiskStat{
		Name: name, NamePresent: name != "",
		RdReqs: reqs, RdReqsPresent: true,
		WrReqs: reqs, WrReqsPresent: true,
		RdBytes: bytes, RdBytesPresent: true,
		WrBytes: bytes, WrBytesPresent: true,
		RdTime: rwTime, RdTimePresent: true,
		WrTime: rwTime, WrTimePresent: true,
		FlReqs: flushReqs, FlReqsPresent: true,
		FlTime: flushTime, FlTimePresent: true,
		Capacity: 10_000, CapacityPresent: true,
		Physical: 5_000, PhysicalPresent: true,
	}
}

func TestDiskMetricCollectionDeduplicationFallbackAndLatency(t *testing.T) {
	mc := newCollectorOrchestrationTestCollector(t)
	meta := &DomainStatic{Disks: []DomainDisk{
		{TargetDev: "vda", Type: "file", SourceFile: "/var/lib/libvirt/images/vm.qcow2"},
		{TargetDev: "vdc", Type: "network", SourceName: "rbd/volume-1"},
	}}
	now := time.Unix(1_700_000_000, 0)
	firstVDA := fullDiskStat("vda", 10, 1000, 10_000_000, 1, 1_000_000)
	firstVDC := fullDiskStat("vdc", 10, 1000, 10_000_000, 1, 1_000_000)
	firstVDC.Allocation = 4_000
	firstVDC.AllocationPresent = true
	first := &ParsedStats{Disks: map[int]*DiskStat{
		0: firstVDA,
		1: fullDiskStat("vda", 10, 1000, 10_000_000, 1, 1_000_000),
		2: {Name: "vdb", NamePresent: true, Physical: 123, PhysicalPresent: true, Capacity: 456, CapacityPresent: true},
		3: {Name: "", NamePresent: false},
		4: firstVDC,
	}}
	firstMetrics := make([]prometheus.Metric, 0)
	count, severity, activity, derived := mc.collectDomainDiskMetrics(meta, first, now, "domain", "server", "vm-disk", "project", "project-name", "user", true, &firstMetrics)
	if count != 3 || severity != 0 || activity != 0 || derived || len(firstMetrics) == 0 {
		t.Fatalf("first disk count=%d severity=%v activity=%v derived=%v metrics=%d", count, severity, activity, derived, len(firstMetrics))
	}

	secondVDA := fullDiskStat("vda", 15, 2000, 110_000_000, 2, 21_000_000)
	secondVDC := fullDiskStat("vdc", 15, 2000, 110_000_000, 2, 21_000_000)
	secondVDC.Allocation = 4_500
	secondVDC.AllocationPresent = true
	second := &ParsedStats{Disks: map[int]*DiskStat{
		0: secondVDA,
		1: fullDiskStat("vda", 15, 2000, 110_000_000, 2, 21_000_000),
		2: {Name: "vdb", NamePresent: true, Physical: 124, PhysicalPresent: true, Capacity: 456, CapacityPresent: true},
		4: secondVDC,
	}}
	secondMetrics := make([]prometheus.Metric, 0)
	count, severity, activity, derived = mc.collectDomainDiskMetrics(meta, second, now.Add(time.Second), "domain", "server", "vm-disk", "project", "project-name", "user", true, &secondMetrics)
	if count != 3 || severity <= 0 || activity <= 0 || derived || len(secondMetrics) <= len(firstMetrics) {
		t.Fatalf("second disk count=%d severity=%v activity=%v derived=%v metrics=%d first=%d", count, severity, activity, derived, len(secondMetrics), len(firstMetrics))
	}
	reg := prometheus.NewRegistry()
	reg.MustRegister(staticMetricCollector{metrics: secondMetrics})
	if _, err := reg.Gather(); err != nil {
		t.Fatalf("disk metric gather failed: %v", err)
	}

	staleMetrics := make([]prometheus.Metric, 0)
	_, staleSeverity, staleActivity, staleDerived := mc.collectDomainDiskMetrics(meta, second, now.Add(2*time.Second), "domain", "server", "vm-stale-disk", "project", "project-name", "user", false, &staleMetrics)
	if staleSeverity != 0 || staleActivity != 0 || staleDerived {
		t.Fatalf("stale disk telemetry severity=%v activity=%v derived=%v", staleSeverity, staleActivity, staleDerived)
	}
}
