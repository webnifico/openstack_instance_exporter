package main

import (
	"math"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func newResourceTelemetryDeviceSampleManager(interval time.Duration) *InstanceManager {
	im := &InstanceManager{resourceSampleMaxAge: resourceAxisMaxRetainedAge(interval)}
	initializeInstanceSampleState(im)
	return im
}

func TestResourceTelemetryPerInterfaceResetCannotBeMaskedByAnotherNIC(t *testing.T) {
	im := newResourceTelemetryDeviceSampleManager(time.Second)
	now := time.Unix(1_700_500_000, 0)
	first := map[string]netDeviceCounters{
		"tap-a": {rxPkts: 100, txPkts: 100},
		"tap-b": {rxPkts: 100, txPkts: 100},
	}
	if _, _, _, valid := im.calculateNetRatesForInterfaces("vm-net-reset", first, now); valid {
		t.Fatal("first per-interface network sample was valid")
	}

	// The aggregate increased from 400 to 600 packets, but tap-a reset. An
	// aggregate-before-delta implementation would silently accept this sample.
	maskedReset := map[string]netDeviceCounters{
		"tap-a": {rxPkts: 0, txPkts: 0},
		"tap-b": {rxPkts: 300, txPkts: 300},
	}
	if _, _, _, valid := im.calculateNetRatesForInterfaces("vm-net-reset", maskedReset, now.Add(time.Second)); valid {
		t.Fatal("one NIC reset was masked by growth on another NIC")
	}

	recovered := map[string]netDeviceCounters{
		"tap-a": {rxPkts: 10, txPkts: 10},
		"tap-b": {rxPkts: 310, txPkts: 310},
	}
	pps, dropRate, dropsPerSecond, valid := im.calculateNetRatesForInterfaces("vm-net-reset", recovered, now.Add(2*time.Second))
	if !valid || pps != 40 || dropRate != 0 || dropsPerSecond != 0 {
		t.Fatalf("network rates did not recover from the reset baseline: pps=%v drop_rate=%v drops=%v valid=%v", pps, dropRate, dropsPerSecond, valid)
	}
}

func TestResourceTelemetryConfirmedZeroInterfaceSetClearsBaseline(t *testing.T) {
	im := newResourceTelemetryDeviceSampleManager(time.Second)
	now := time.Unix(1_700_500_100, 0)
	uuid := "vm-net-detach-all"
	one := map[string]netDeviceCounters{"tap-a": {rxPkts: 10, txPkts: 10}}
	if _, _, _, valid := im.calculateNetRatesForInterfaces(uuid, one, now); valid {
		t.Fatal("first network sample was valid")
	}
	one["tap-a"] = netDeviceCounters{rxPkts: 20, txPkts: 20}
	if _, _, _, valid := im.calculateNetRatesForInterfaces(uuid, one, now.Add(time.Second)); !valid {
		t.Fatal("second network sample was unavailable")
	}
	if _, _, _, valid := im.calculateNetRatesForInterfaces(uuid, map[string]netDeviceCounters{}, now.Add(2*time.Second)); valid {
		t.Fatal("zero-interface observation produced a rate")
	}
	idx := shardIndex(uuid)
	if _, exists := im.netSamples[idx][uuid]; exists {
		t.Fatal("confirmed zero-interface set retained the old network baseline")
	}

	reappeared := map[string]netDeviceCounters{"tap-a": {rxPkts: 1000, txPkts: 1000}}
	if _, _, _, valid := im.calculateNetRatesForInterfaces(uuid, reappeared, now.Add(3*time.Second)); valid {
		t.Fatal("reattached interface reused its pre-detach baseline")
	}
	reappeared["tap-a"] = netDeviceCounters{rxPkts: 1010, txPkts: 1010}
	if pps, _, _, valid := im.calculateNetRatesForInterfaces(uuid, reappeared, now.Add(4*time.Second)); !valid || pps != 20 {
		t.Fatalf("reattached interface did not recover from a new baseline: pps=%v valid=%v", pps, valid)
	}
}

func TestResourceTelemetryPerInterfaceNetworkAggregateOverflowIsUnavailable(t *testing.T) {
	im := newResourceTelemetryDeviceSampleManager(time.Second)
	now := time.Unix(1_700_500_150, 0)
	overflowing := map[string]netDeviceCounters{
		"tap-a": {rxPkts: ^uint64(0)},
		"tap-b": {rxPkts: 1},
	}
	for cycle := 0; cycle < 2; cycle++ {
		if _, _, _, valid := im.calculateNetRatesForInterfaces("vm-net-overflow", overflowing, now.Add(time.Duration(cycle)*time.Second)); valid {
			t.Fatalf("overflowing per-interface aggregate was valid on cycle %d", cycle)
		}
	}
	idx := shardIndex("vm-net-overflow")
	if _, exists := im.netSamples[idx]["vm-net-overflow"]; exists {
		t.Fatal("overflowing per-interface aggregate replaced the last valid baseline")
	}
}

func completeResourceTelemetryDiskStat(name string, value uint64) *DiskStat {
	return &DiskStat{
		Name: name, NamePresent: true,
		RdReqs: value, RdReqsPresent: true,
		WrReqs: value, WrReqsPresent: true,
		RdBytes: value, RdBytesPresent: true,
		WrBytes: value, WrBytesPresent: true,
		RdTime: value, RdTimePresent: true,
		WrTime: value, WrTimePresent: true,
		FlReqs: value, FlReqsPresent: true,
		FlTime: value, FlTimePresent: true,
	}
}

func TestResourceTelemetryAuthoritativeDiskSnapshotPrunesOnlyDetachedKeys(t *testing.T) {
	mc := newCollectorOrchestrationTestCollector(t)
	now := time.Unix(1_700_500_200, 0)
	uuid := "vm-disk-prune"
	idx := shardIndex(uuid)
	vdaKey := uuid + "|volume-a|vda"
	detachedKey := uuid + "|volume-b|vdb"
	mc.im.diskSamples[idx][vdaKey] = diskSample{rdReq: 1, wrReq: 1, rdBytes: 1, wrBytes: 1, rdTime: 1, wrTime: 1, flReq: 1, flTime: 1, rwPresent: true, flushPresent: true, ts: now.Add(-time.Second)}
	mc.im.diskSamples[idx][detachedKey] = diskSample{rdReq: 1, ts: now.Add(-time.Second)}
	meta := &DomainStatic{Disks: []DomainDisk{{TargetDev: "vda", Type: "network", SourceName: "rbd/volume-a"}}}
	stats := &ParsedStats{
		BlockCount: 1, BlockCountPresent: true,
		Disks: map[int]*DiskStat{0: completeResourceTelemetryDiskStat("vda", 2)},
	}
	metrics := make([]prometheus.Metric, 0)
	mc.collectDomainDiskMetrics(meta, stats, now, "domain", "server", uuid, "project", "project-name", "user", true, &metrics)
	if _, exists := mc.im.diskSamples[idx][detachedKey]; exists {
		t.Fatal("authoritative disk snapshot retained a detached disk baseline")
	}
	if _, exists := mc.im.diskSamples[idx][vdaKey]; !exists {
		t.Fatal("authoritative disk snapshot removed the active disk baseline")
	}

	// A transitional stat-only disk makes the inventory non-authoritative and
	// must not delete a last-known sample until XML and block stats agree.
	mc.im.diskSamples[idx][detachedKey] = diskSample{rdReq: 5, ts: now}
	partial := &ParsedStats{
		BlockCount: 2, BlockCountPresent: true,
		Disks: map[int]*DiskStat{
			0: completeResourceTelemetryDiskStat("vda", 3),
			1: completeResourceTelemetryDiskStat("vdb", 6),
		},
	}
	mc.collectDomainDiskMetrics(meta, partial, now.Add(time.Second), "domain", "server", uuid, "project", "project-name", "user", true, &metrics)
	if _, exists := mc.im.diskSamples[idx][detachedKey]; !exists {
		t.Fatal("non-authoritative disk snapshot pruned a baseline")
	}
}

func TestResourceTelemetryAuthoritativeZeroDiskSnapshotClearsBaselines(t *testing.T) {
	mc := newCollectorOrchestrationTestCollector(t)
	uuid := "vm-disk-detach-all"
	idx := shardIndex(uuid)
	mc.im.diskSamples[idx][uuid+"|volume-a|vda"] = diskSample{rdReq: 1}
	metrics := make([]prometheus.Metric, 0)
	mc.collectDomainDiskMetrics(
		&DomainStatic{},
		&ParsedStats{BlockCountPresent: true, Disks: map[int]*DiskStat{}},
		time.Unix(1_700_500_300, 0),
		"domain", "server", uuid, "project", "project-name", "user",
		true,
		&metrics,
	)
	if len(mc.im.diskSamples[idx]) != 0 {
		t.Fatalf("confirmed zero-disk snapshot retained baselines: %v", mc.im.diskSamples[idx])
	}
}

func TestResourceTelemetryRuntimeGenerationChangeResetsEveryRateBaseline(t *testing.T) {
	im := newResourceTelemetryDeviceSampleManager(time.Second)
	uuid := "vm-generation"
	idx := shardIndex(uuid)
	seed := func() {
		im.cpuSamples[idx][uuid] = cpuSample{total: 1}
		im.memSamples[idx][uuid] = memSample{swapIn: 1}
		im.netSamples[idx][uuid] = netSample{interfaces: map[string]netDeviceCounters{"tap-a": {rxPkts: 1}}}
		im.diskSamples[idx][uuid+"|volume-a|vda"] = diskSample{rdReq: 1}
	}
	if im.ensureInstanceResourceGeneration(uuid, 7) {
		t.Fatal("first runtime generation was reported as a generation change")
	}
	seed()
	if im.ensureInstanceResourceGeneration(uuid, 7) {
		t.Fatal("unchanged runtime generation reset valid baselines")
	}
	if len(im.cpuSamples[idx]) == 0 || len(im.memSamples[idx]) == 0 || len(im.netSamples[idx]) == 0 || len(im.diskSamples[idx]) == 0 {
		t.Fatal("unchanged runtime generation lost a baseline")
	}
	if !im.ensureInstanceResourceGeneration(uuid, 8) {
		t.Fatal("changed runtime generation was ignored")
	}
	if len(im.cpuSamples[idx])+len(im.memSamples[idx])+len(im.netSamples[idx])+len(im.diskSamples[idx]) != 0 {
		t.Fatal("changed runtime generation did not clear every baseline")
	}
}

func TestResourceTelemetrySameDomainIDCPUTimeRollbackStartsNewRuntimeGeneration(t *testing.T) {
	mc := newCollectorOrchestrationTestCollector(t)
	uuid := "vm-same-id-restart"
	idx := shardIndex(uuid)
	base := time.Unix(1_700_500_350, 0)
	if mc.im.observeInstanceResourceGeneration(uuid, 7, 20_000_000_000, true) {
		t.Fatal("first runtime witness was reported as a generation change")
	}

	mc.im.cpuSamples[idx][uuid] = cpuSample{total: 20_000_000_000, vcpuCount: 2, ts: base}
	mc.im.memSamples[idx][uuid] = memSample{swapIn: 100, ts: base}
	mc.im.netSamples[idx][uuid] = netSample{interfaces: map[string]netDeviceCounters{"tap-a": {rxPkts: 100}}, ts: base}
	mc.im.diskSamples[idx][uuid+"|volume-a|vda"] = diskSample{rdReq: 100, ts: base}
	mc.im.resourceDimensions[uuid] = resourceDimensions{
		vcpuCount: 2, memMB: 4096, vcpuKnown: true, memKnown: true,
		vcpuLiveObserved: true, memLiveObserved: true,
	}
	for cycle := 0; cycle < 3; cycle++ {
		out, state := mc.computeResourceV2(uuid, resourceTelemetryCPUInput(base.Add(time.Duration(cycle)*time.Second), 1))
		syncResourceV2EventState(out, state)
	}

	// A restarted QEMU can reuse both the instance UUID and numeric Libvirt ID.
	// The domain-lifetime CPU counter rollback is the independent incarnation
	// witness that prevents old rates, EWMA, persistence, and event state from
	// crossing that boundary.
	if !mc.im.observeInstanceResourceGeneration(uuid, 7, 10_000_000, true) {
		t.Fatal("same-ID QEMU restart was not detected from CPU-time rollback")
	}
	mc.resetResourceV2ForTransition(uuid)
	if len(mc.im.cpuSamples[idx])+len(mc.im.memSamples[idx])+len(mc.im.netSamples[idx])+len(mc.im.diskSamples[idx]) != 0 {
		t.Fatal("same-ID restart retained a rate baseline")
	}
	if _, exists := mc.im.resourceDimensions[uuid]; exists {
		t.Fatal("same-ID restart retained runtime dimension authority")
	}
	state, exists := mc.lookupResourceV2State(uuid)
	if !exists || !state.NeedsRebaseline || state.Cpu.Initialized || state.Composite.Initialized ||
		state.OverallHi95Streak != 0 || state.LastBand != 0 || state.LastTopAxis != "" || state.LastCapActive {
		t.Fatalf("same-ID restart retained axis/composite/persistence/event state: %+v", state)
	}

	first, state := mc.computeResourceV2(uuid, resourceTelemetryCPUInput(base.Add(10*time.Second), 1))
	if !first.StructuralChange || state.NeedsRebaseline || state.OverallHi95Streak != 0 {
		t.Fatalf("first new-generation observation was not a silent structural rebaseline: out=%+v state=%+v", first, state)
	}
}

func TestResourceTelemetryInactiveCleanupRemovesRuntimeGeneration(t *testing.T) {
	im := newResourceTelemetryDeviceSampleManager(time.Second)
	im.activeInstances = map[string]struct{}{"active": {}}
	im.resourceGeneration["active"] = 1
	im.resourceGeneration["stale"] = 2
	im.resourceGenerationCPUTime["active"] = 10
	im.resourceGenerationCPUTime["stale"] = 20
	im.resourceGenerationToken["active"] = "boot-a:1:10"
	im.resourceGenerationToken["stale"] = "boot-a:2:20"
	im.cleanupResourceSamples()
	if im.resourceGeneration["active"] != 1 {
		t.Fatal("active runtime generation was removed")
	}
	if _, exists := im.resourceGeneration["stale"]; exists {
		t.Fatal("inactive runtime generation was retained")
	}
	if got := im.resourceGenerationCPUTime["active"]; got != 10 {
		t.Fatalf("active runtime CPU-time witness=%d want 10", got)
	}
	if _, exists := im.resourceGenerationCPUTime["stale"]; exists {
		t.Fatal("inactive runtime CPU-time witness was retained")
	}
	if got := im.resourceGenerationToken["active"]; got != "boot-a:1:10" {
		t.Fatalf("active process token=%q", got)
	}
	if _, exists := im.resourceGenerationToken["stale"]; exists {
		t.Fatal("inactive process token was retained")
	}
}

func TestResourceTelemetryDetailedCPUAvailabilitySeparatesOptionalCounterReset(t *testing.T) {
	im := newResourceTelemetryDeviceSampleManager(time.Second)
	now := time.Unix(1_700_500_400, 0)
	uuid := "vm-cpu-detailed"
	if _, _, _, usageOK, stealOK, waitOK := im.calculateCPUUsageWithDetailedAvailabilityAt(1_000_000_000, 100, 100, true, true, uuid, 1, now); usageOK || stealOK || waitOK {
		t.Fatal("first detailed CPU sample was valid")
	}
	usage, steal, wait, usageOK, stealOK, waitOK := im.calculateCPUUsageWithDetailedAvailabilityAt(2_000_000_000, 10, 200, true, true, uuid, 1, now.Add(time.Second))
	if !usageOK || stealOK || !waitOK {
		t.Fatalf("detailed CPU availability did not isolate stall reset: usage=%v/%v steal=%v/%v wait=%v/%v", usage, usageOK, steal, stealOK, wait, waitOK)
	}
	if usage != 100 || steal != 0 || wait <= 0 {
		t.Fatalf("unexpected detailed CPU values: usage=%v steal=%v wait=%v", usage, steal, wait)
	}
}

func TestResourceTelemetryRateBaselinesRejectOverlongIntervals(t *testing.T) {
	interval := time.Second
	maxAge := resourceAxisMaxRetainedAge(interval)
	im := newResourceTelemetryDeviceSampleManager(interval)
	now := time.Unix(1_700_500_500, 0)
	overlong := now.Add(maxAge + time.Nanosecond)

	im.calculateCPUUsageWithDetailedAvailabilityAt(1, 1, 1, true, true, "vm-cpu-gap", 1, now)
	if _, _, _, usageOK, stealOK, waitOK := im.calculateCPUUsageWithDetailedAvailabilityAt(2, 2, 2, true, true, "vm-cpu-gap", 1, overlong); usageOK || stealOK || waitOK {
		t.Fatal("overlong CPU interval was accepted")
	}
	if _, _, _, usageOK, _, _ := im.calculateCPUUsageWithDetailedAvailabilityAt(1_000_000_002, 2, 2, true, true, "vm-cpu-gap", 1, overlong.Add(time.Second)); !usageOK {
		t.Fatal("CPU baseline did not recover after overlong interval rejection")
	}

	im.calculateMemRates("vm-mem-gap", 1, 1, 1, 1, now)
	if _, _, _, valid := im.calculateMemRates("vm-mem-gap", 2, 2, 2, 2, overlong); valid {
		t.Fatal("overlong memory interval was accepted")
	}
	if _, _, _, valid := im.calculateMemRates("vm-mem-gap", 3, 3, 3, 3, overlong.Add(time.Second)); !valid {
		t.Fatal("memory baseline did not recover after overlong interval rejection")
	}

	im.calculateDiskIO("vm-disk-gap|volume|vda", 1, 1, 1, 1, 1, 1, 1, 1, now)
	if _, _, _, _, _, _, _, _, _, _, valid := im.calculateDiskIO("vm-disk-gap|volume|vda", 2, 2, 2, 2, 2, 2, 2, 2, overlong); valid {
		t.Fatal("overlong disk interval was accepted")
	}
	if _, _, _, _, _, _, _, _, _, _, valid := im.calculateDiskIO("vm-disk-gap|volume|vda", 3, 3, 3, 3, 3, 3, 3, 3, overlong.Add(time.Second)); !valid {
		t.Fatal("disk baseline did not recover after overlong interval rejection")
	}

	firstNet := map[string]netDeviceCounters{"tap-a": {rxPkts: 1, txPkts: 1, rxDrop: 1, txDrop: 1}}
	im.calculateNetRatesForInterfaces("vm-net-gap", firstNet, now)
	secondNet := map[string]netDeviceCounters{"tap-a": {rxPkts: 2, txPkts: 2, rxDrop: 2, txDrop: 2}}
	if _, _, _, valid := im.calculateNetRatesForInterfaces("vm-net-gap", secondNet, overlong); valid {
		t.Fatal("overlong network interval was accepted")
	}
	thirdNet := map[string]netDeviceCounters{"tap-a": {rxPkts: 3, txPkts: 3, rxDrop: 3, txDrop: 3}}
	pps, dropRate, drops, valid := im.calculateNetRatesForInterfaces("vm-net-gap", thirdNet, overlong.Add(time.Second))
	if !valid || pps != 2 || drops != 2 || math.Abs(dropRate-0.5) > 1e-9 {
		t.Fatalf("network baseline did not recover after overlong interval rejection: pps=%v drop_rate=%v drops=%v valid=%v", pps, dropRate, drops, valid)
	}
}

func TestResourceTelemetryRateBaselineAcceptsExactMaximumRetainedInterval(t *testing.T) {
	interval := time.Second
	im := newResourceTelemetryDeviceSampleManager(interval)
	start := time.Unix(1_700_500_600, 0)
	maximum := resourceAxisMaxRetainedAge(interval)
	elapsed, seconds, ok := im.validResourceSampleInterval(start, start.Add(maximum))
	if !ok || elapsed != maximum || seconds != maximum.Seconds() {
		t.Fatalf("exact 8I rate interval rejected: elapsed=%v seconds=%v ok=%v", elapsed, seconds, ok)
	}
}
