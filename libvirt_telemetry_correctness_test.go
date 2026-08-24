package main

import (
	"math"
	"testing"
	"time"

	libvirt "github.com/digitalocean/go-libvirt"
	"github.com/prometheus/client_golang/prometheus"
)

func typedParam(name string, value interface{}) libvirt.TypedParam {
	return libvirt.TypedParam{Field: name, Value: libvirt.TypedParamValue{I: value}}
}

func TestParseLibvirtStatsTracksPresenceIncludingHealthyZeroes(t *testing.T) {
	stats := parseLibvirtStats([]libvirt.TypedParam{
		typedParam("state.state", int32(libvirt.DomainPaused)),
		typedParam("cpu.time", uint64(0)),
		typedParam("balloon.current", uint64(1024)),
		typedParam("balloon.usable", uint64(1024)),
		typedParam("balloon.hugetlb_pgalloc", uint64(0)),
		typedParam("balloon.hugetlb_pgfail", uint64(0)),
		typedParam("vcpu.0.time", uint64(0)),
		typedParam("net.0.name", "tap0"),
		typedParam("net.0.rx.pkts", uint64(0)),
	})
	if !stats.StatePresent || stats.State != int(libvirt.DomainPaused) {
		t.Fatalf("state presence lost: %+v", stats)
	}
	if !stats.CpuTimePresent || !stats.MemCurPresent || !stats.MemUsablePresent {
		t.Fatalf("present zero-valued telemetry marked unavailable: %+v", stats)
	}
	if !stats.HugetlbPgAllocPresent || !stats.HugetlbPgFailPresent {
		t.Fatalf("hugetlb telemetry presence lost: %+v", stats)
	}
	if stats.MemRssPresent || stats.SwapInPresent {
		t.Fatalf("missing memory telemetry marked present: %+v", stats)
	}
	if !stats.Vcpus[0].TimePresent || !stats.Nets[0].RxPktsPresent {
		t.Fatalf("nested telemetry presence lost: vcpu=%+v net=%+v", stats.Vcpus[0], stats.Nets[0])
	}
}

func TestParseLibvirtStatsUsesAuthoritativeCurrentVCPUCount(t *testing.T) {
	stats := parseLibvirtStats([]libvirt.TypedParam{
		typedParam("vcpu.current", uint32(8)),
		typedParam("vcpu.maximum", uint32(16)),
		typedParam("vcpu.0.time", uint64(10)),
		typedParam("vcpu.7.time", uint64(20)),
	})
	if !stats.VcpuCurrentPresent || stats.VcpuCurrent != 8 {
		t.Fatalf("vcpu.current was not parsed: %+v", stats)
	}
	if got := effectiveDomainVCPUCount(16, stats); got != 8 {
		t.Fatalf("effective vCPU count=%d, want current count 8", got)
	}
}

func TestEffectiveDomainVCPUCountFallbacks(t *testing.T) {
	stats := &ParsedStats{Vcpus: map[int]*VcpuStat{0: {}, 7: {}}}
	if got := effectiveDomainVCPUCount(16, stats); got != 16 {
		t.Fatalf("configured fallback=%d, want 16", got)
	}
	if got := effectiveDomainVCPUCount(0, stats); got != 2 {
		t.Fatalf("telemetry fallback=%d, want 2", got)
	}
	stats.VcpuCurrentPresent = true
	stats.VcpuCurrent = 0
	if got := effectiveDomainVCPUCount(16, stats); got != 16 {
		t.Fatalf("zero current count replaced configured count: got %d", got)
	}
	stats.VcpuCurrent = uint64(^uint(0)>>1) + 1
	if got := effectiveDomainVCPUCount(16, stats); got != 16 {
		t.Fatalf("overflowing current count replaced configured count: got %d", got)
	}
	if got := effectiveDomainVCPUCount(0, nil); got != 0 {
		t.Fatalf("nil telemetry fallback=%d, want zero", got)
	}
}

func TestParseLibvirtStatsDoesNotCreatePhantomDevicesForUnknownFields(t *testing.T) {
	stats := parseLibvirtStats([]libvirt.TypedParam{
		typedParam("vcpu.7.unknown", uint64(1)),
		typedParam("vcpu.8.time", "not-a-counter"),
		typedParam("vcpu.9.time.extra", uint64(1)),
		typedParam("block.7.unknown", uint64(1)),
		typedParam("block.8.name.extra", "vdb"),
		typedParam("block.9.rd.bytes.extra", uint64(1)),
		typedParam("net.7.unknown", uint64(1)),
		typedParam("net.8.name.extra", "tap8"),
		typedParam("net.9.rx.bytes.extra", uint64(1)),
	})
	if len(stats.Vcpus) != 0 || len(stats.Disks) != 0 || len(stats.Nets) != 0 {
		t.Fatalf("unknown fields created phantom telemetry records: vcpus=%v disks=%v nets=%v", stats.Vcpus, stats.Disks, stats.Nets)
	}
}

func TestGuestMemoryUsageDoesNotTreatRSSOrCurrentAsGuestUsed(t *testing.T) {
	if used, ok := guestMemoryUsedMB(&ParsedStats{MemRss: 512 * 1024, MemRssPresent: true}, true); ok || used != 0 {
		t.Fatalf("RSS was treated as guest-used memory: used=%v ok=%v", used, ok)
	}
	if used, ok := guestMemoryUsedMB(&ParsedStats{MemCur: 1024 * 1024, MemCurPresent: true}, true); ok || used != 0 {
		t.Fatalf("current balloon value without usable was treated as guest-used memory: used=%v ok=%v", used, ok)
	}
	used, ok := guestMemoryUsedMB(&ParsedStats{
		MemCur: 1024 * 1024, MemCurPresent: true,
		MemUsable: 1024 * 1024, MemUsablePresent: true,
	}, true)
	if !ok || used != 0 {
		t.Fatalf("healthy zero guest use was not available: used=%v ok=%v", used, ok)
	}
}

func TestCPUFirstSampleAndCounterResetAreUnavailable(t *testing.T) {
	im := &InstanceManager{}
	_, _, _, ok := im.calculateCPUUsage(100, 10, 5, "vm-1", 2)
	if ok {
		t.Fatal("first CPU sample was reported as a confident healthy zero")
	}
	_, _, _, ok = im.calculateCPUUsage(90, 9, 4, "vm-1", 2)
	if ok {
		t.Fatal("CPU counter reset was reported as a confident healthy zero")
	}
	_, _, _, ok = im.calculateCPUUsage(190, 19, 14, "vm-1", 2)
	if !ok {
		t.Fatal("post-reset CPU sample did not recover")
	}
}

func TestCPUCapacityChangeInvalidatesOnlyTheTransitionSample(t *testing.T) {
	im := &InstanceManager{}
	_, _, _, ok := im.calculateCPUUsage(100, 10, 5, "vm-hotplug", 1)
	if ok {
		t.Fatal("first CPU sample unexpectedly valid")
	}
	_, _, _, ok = im.calculateCPUUsage(200, 20, 10, "vm-hotplug", 2)
	if ok {
		t.Fatal("CPU interval spanning a vCPU-count change was reported valid")
	}
	_, _, _, ok = im.calculateCPUUsage(300, 30, 15, "vm-hotplug", 2)
	if !ok {
		t.Fatal("CPU rate did not recover on the next same-capacity sample")
	}
}

func TestCPUSampleCapacityDoesNotTreatUnknownAsWildcard(t *testing.T) {
	im := &InstanceManager{}
	uuid := "vm-cpu-capacity"
	idx := shardIndex(uuid)
	im.cpuSamples[idx] = map[string]cpuSample{
		uuid: {total: 100, ts: time.Now().Add(-time.Second)},
	}
	if _, _, _, ok := im.calculateCPUUsage(200, 0, 0, uuid, 1); ok {
		t.Fatal("an unknown previous vCPU capacity was treated as comparable")
	}
}

func TestSparsePerVCPUTelemetryDoesNotProducePartialStallPressure(t *testing.T) {
	mc, err := NewMetricsCollector(CollectorConfig{LibvirtURI: "qemu:///system", CollectionInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer close(mc.shutdownChan)

	uuid := "vm-sparse-vcpu"
	idx := shardIndex(uuid)
	mc.im.cpuSamples[idx][uuid] = cpuSample{
		total: 1_000_000_000, vcpuCount: 8,
		stealPresent: true, waitPresent: true,
		ts: time.Now().Add(-time.Second),
	}
	stat := &ParsedStats{
		CpuTime: 1_000_000_000, CpuTimePresent: true,
		VcpuCurrent: 8, VcpuCurrentPresent: true,
		Vcpus: map[int]*VcpuStat{
			0: {Delay: 1_000_000_000, DelayPresent: true, WaitPresent: true},
			7: {Delay: 1_000_000_000, DelayPresent: true, WaitPresent: true},
		},
	}
	metrics := make([]prometheus.Metric, 0, 8)
	pressure, available := mc.collectDomainCPUMetrics(
		stat,
		"domain", "server", uuid, "project", "project-name", "user",
		8,
		true,
		&metrics,
	)
	if !available {
		t.Fatal("complete cpu.time telemetry was made unavailable by optional per-vCPU data")
	}
	if pressure != 0 {
		t.Fatalf("partial per-vCPU delay counters produced stall pressure %v", pressure)
	}
}

func TestMissingOptionalCPUStallTelemetryDoesNotInvalidateUsage(t *testing.T) {
	im := &InstanceManager{}
	_, _, _, ok := im.calculateCPUUsageWithAvailability(100, 10, 5, true, true, "vm-optional-stall", 1)
	if ok {
		t.Fatal("first CPU sample unexpectedly valid")
	}
	time.Sleep(time.Millisecond)
	usage, steal, wait, ok := im.calculateCPUUsageWithAvailability(1_000_100, 0, 0, false, false, "vm-optional-stall", 1)
	if !ok || usage <= 0 {
		t.Fatalf("missing optional stall counters invalidated CPU usage: usage=%v ok=%v", usage, ok)
	}
	if steal != 0 || wait != 0 {
		t.Fatalf("missing stall counters produced healthy-looking rates: steal=%v wait=%v", steal, wait)
	}
}

func TestNetworkDropRatioUsesDeliveredPlusDroppedPackets(t *testing.T) {
	im := &InstanceManager{}
	uuid := "vm-1"
	now := time.Now()
	idx := shardIndex(uuid)
	im.netSamples[idx] = map[string]netSample{
		uuid: {rxPkts: 50, txPkts: 50, rxDrop: 5, txDrop: 5, ts: now.Add(-time.Second)},
	}
	pps, dropRate, _, ok := im.calculateNetRates(uuid, 95, 95, 10, 10, now)
	if !ok || math.Abs(pps-90) > 1e-9 {
		t.Fatalf("unexpected packet rate: pps=%v ok=%v", pps, ok)
	}
	if math.Abs(dropRate-0.1) > 1e-9 {
		t.Fatalf("drop ratio=%v want 0.1", dropRate)
	}
}

func TestNetworkSampleIdentityDoesNotTreatUnknownAsWildcard(t *testing.T) {
	im := &InstanceManager{}
	uuid := "vm-network-identity"
	now := time.Now()
	idx := shardIndex(uuid)
	im.netSamples[idx] = map[string]netSample{
		uuid: {rxPkts: 10, txPkts: 10, ts: now.Add(-time.Second)},
	}
	if _, _, _, ok := im.calculateNetRatesForInterfaceSet(uuid, "tap-a", 20, 20, 0, 0, now); ok {
		t.Fatal("an unknown previous interface identity was treated as comparable")
	}
}

func completeNetStat(name string, packets uint64) *NetStat {
	return &NetStat{
		Name: name, NamePresent: true,
		RxPkts: packets, RxPktsPresent: true,
		TxPkts: packets, TxPktsPresent: true,
		RxDropPresent: true,
		TxDropPresent: true,
	}
}

func collectTestNetworkRate(mc *MetricsCollector, meta *DomainStatic, stat *ParsedStats, uuid string, now time.Time) bool {
	metrics := make([]prometheus.Metric, 0, 16)
	_, _, _, _, _, available, _ := mc.collectDomainNetworkAndConntrack(
		meta,
		stat,
		now,
		"domain", "server", uuid, "project", "project-name", "user",
		true,
		nil,
		nil,
		map[string]struct{}{},
		map[string]struct{}{},
		0,
		false,
		true,
		&metrics,
	)
	return available
}

func TestNetworkRatesRejectIncompleteInterfaceSet(t *testing.T) {
	mc, err := NewMetricsCollector(CollectorConfig{LibvirtURI: "qemu:///system", CollectionInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer close(mc.shutdownChan)

	uuid := "vm-partial-network"
	meta := &DomainStatic{Interfaces: []string{"tap-a", "tap-b"}}
	now := time.Now()
	if collectTestNetworkRate(mc, meta, &ParsedStats{Nets: map[int]*NetStat{
		0: completeNetStat("tap-a", 10),
		1: completeNetStat("tap-b", 10),
	}}, uuid, now) {
		t.Fatal("first complete network sample unexpectedly valid")
	}
	if !collectTestNetworkRate(mc, meta, &ParsedStats{Nets: map[int]*NetStat{
		0: completeNetStat("tap-a", 20),
		1: completeNetStat("tap-b", 20),
	}}, uuid, now.Add(time.Second)) {
		t.Fatal("second complete network sample was unavailable")
	}
	if collectTestNetworkRate(mc, meta, &ParsedStats{Nets: map[int]*NetStat{
		0: completeNetStat("tap-a", 100),
	}}, uuid, now.Add(2*time.Second)) {
		t.Fatal("partial interface telemetry was treated as a complete aggregate sample")
	}
	if !collectTestNetworkRate(mc, meta, &ParsedStats{Nets: map[int]*NetStat{
		0: completeNetStat("tap-a", 110),
		1: completeNetStat("tap-b", 30),
	}}, uuid, now.Add(3*time.Second)) {
		t.Fatal("network rates did not resume when the complete interface set returned")
	}
}

func TestNetworkInterfaceReplacementInvalidatesOnlyTheTransitionSample(t *testing.T) {
	mc, err := NewMetricsCollector(CollectorConfig{LibvirtURI: "qemu:///system", CollectionInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer close(mc.shutdownChan)

	uuid := "vm-network-hotplug"
	now := time.Now()
	metaA := &DomainStatic{Interfaces: []string{"tap-a"}}
	metaB := &DomainStatic{Interfaces: []string{"tap-b"}}
	if collectTestNetworkRate(mc, metaA, &ParsedStats{Nets: map[int]*NetStat{0: completeNetStat("tap-a", 10)}}, uuid, now) {
		t.Fatal("first network sample unexpectedly valid")
	}
	if !collectTestNetworkRate(mc, metaA, &ParsedStats{Nets: map[int]*NetStat{0: completeNetStat("tap-a", 20)}}, uuid, now.Add(time.Second)) {
		t.Fatal("second same-interface network sample was unavailable")
	}
	if collectTestNetworkRate(mc, metaB, &ParsedStats{Nets: map[int]*NetStat{0: completeNetStat("tap-b", 100)}}, uuid, now.Add(2*time.Second)) {
		t.Fatal("network interval spanning an interface replacement was reported valid")
	}
	if !collectTestNetworkRate(mc, metaB, &ParsedStats{Nets: map[int]*NetStat{0: completeNetStat("tap-b", 110)}}, uuid, now.Add(3*time.Second)) {
		t.Fatal("network rates did not recover on the next same-interface sample")
	}
}

func TestNetworkRatesHonorAuthoritativeInterfaceCount(t *testing.T) {
	mc, err := NewMetricsCollector(CollectorConfig{LibvirtURI: "qemu:///system", CollectionInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer close(mc.shutdownChan)

	partialStats := func(packets uint64) *ParsedStats {
		return parseLibvirtStats([]libvirt.TypedParam{
			typedParam("net.count", uint32(2)),
			typedParam("net.0.name", "tap-a"),
			typedParam("net.0.rx.pkts", packets),
			typedParam("net.0.tx.pkts", packets),
			typedParam("net.0.rx.drop", uint64(0)),
			typedParam("net.0.tx.drop", uint64(0)),
		})
	}

	uuid := "vm-authoritative-net-count"
	meta := &DomainStatic{Interfaces: []string{"tap-a"}}
	now := time.Now()
	if collectTestNetworkRate(mc, meta, partialStats(10), uuid, now) {
		t.Fatal("first partial network sample unexpectedly valid")
	}
	if collectTestNetworkRate(mc, meta, partialStats(20), uuid, now.Add(time.Second)) {
		t.Fatal("net.count reported a missing interface but aggregate rates were available")
	}
}

func TestMemoryRatesUseIndependentCounterAvailability(t *testing.T) {
	im := &InstanceManager{}
	now := time.Now()
	_, _, _, _, _, _ = im.calculateMemRatesWithAvailability("vm-memory", 100, 0, 10, 0, true, false, true, false, now)
	swapInRate, _, majorRate, swapInOK, _, majorOK := im.calculateMemRatesWithAvailability(
		"vm-memory", 200, 0, 20, 0, true, false, true, false, now.Add(time.Second),
	)
	if !swapInOK || !majorOK || swapInRate != 100 || majorRate != 10 {
		t.Fatalf("independent memory rates unavailable: swap=%v/%v major=%v/%v", swapInRate, swapInOK, majorRate, majorOK)
	}
}

func TestDiskFirstSampleAndResetAreUnavailable(t *testing.T) {
	im := &InstanceManager{}
	now := time.Now()
	_, _, _, _, _, _, _, _, _, _, ok := im.calculateDiskIO("vm-1|disk", 10, 10, 100, 100, 10, 10, 1, 1, now)
	if ok {
		t.Fatal("first disk interval was reported as a valid zero")
	}
	_, _, _, _, _, _, _, _, _, _, ok = im.calculateDiskIO("vm-1|disk", 9, 11, 110, 110, 11, 11, 2, 2, now.Add(time.Second))
	if ok {
		t.Fatal("disk counter reset was reported as a valid interval")
	}
}

func TestDiskReadWriteRatesRemainAvailableWithoutFlushTelemetry(t *testing.T) {
	im := &InstanceManager{}
	now := time.Now()
	_, _, _, _, _, _, _, _, _, _, rwOK, flushOK := im.calculateDiskIOWithAvailability(
		"vm-1|no-flush", 10, 5, 1000, 500, 100_000_000, 50_000_000, 0, 0, true, false, now,
	)
	if rwOK || flushOK {
		t.Fatal("first disk sample unexpectedly valid")
	}
	rdIOPS, wrIOPS, rdLat, wrLat, _, _, _, _, _, _, rwOK, flushOK := im.calculateDiskIOWithAvailability(
		"vm-1|no-flush", 11, 6, 1100, 600, 110_000_000, 70_000_000, 0, 0, true, false, now.Add(time.Second),
	)
	if !rwOK || flushOK {
		t.Fatalf("read/write availability=%v flush availability=%v", rwOK, flushOK)
	}
	if rdIOPS != 1 || wrIOPS != 1 || math.Abs(rdLat-0.01) > 1e-9 || math.Abs(wrLat-0.02) > 1e-9 {
		t.Fatalf("unexpected no-flush disk rates: rdIOPS=%v wrIOPS=%v rdLat=%v wrLat=%v", rdIOPS, wrIOPS, rdLat, wrLat)
	}
}

func TestStaleMetadataCacheSurvivesRefreshFailure(t *testing.T) {
	var uuid libvirt.UUID
	for i := range uuid {
		uuid[i] = byte(i + 1)
	}
	id := uuidBytesToString(uuid[:])
	want := &DomainStatic{InstanceUUID: id, Name: "cached", LastUpdated: time.Now().Add(-time.Hour)}
	im := &InstanceManager{domainMeta: map[string]*DomainStatic{id: want}}
	got, err := im.getDomainMeta(libvirt.Domain{Name: "domain", UUID: uuid}, nil)
	if err != nil || got != want {
		t.Fatalf("stale metadata was discarded on unavailable refresh: got=%p err=%v", got, err)
	}
}
