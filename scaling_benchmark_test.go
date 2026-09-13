package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	libvirt "github.com/digitalocean/go-libvirt"
	"github.com/prometheus/client_golang/prometheus"
)

type scalingScaleCase struct {
	Entries int
	Domains int
}

var scalingScaleCases = []scalingScaleCase{
	{Entries: 100_000, Domains: 100},
	{Entries: 500_000, Domains: 500},
	{Entries: 1_000_000, Domains: 1_000},
	{Entries: 2_000_000, Domains: 1_000},
}

var scalingDomainCases = []int{100, 500, 1_000}

var (
	scalingSinkFlow    ConntrackFlowLite
	scalingSinkAgg     *ConntrackAgg
	scalingSinkMetrics []prometheus.Metric
)

type scalingScaleFixture struct {
	mc         *MetricsCollector
	records    []libvirt.DomainStatsRecord
	metadata   map[string]*DomainStatic
	identities []VMIPIdentity
	vmKeys     []IPKey
	entries    int
	failDump   bool
}

func scalingUUID(index int) (libvirt.UUID, string) {
	var uuid libvirt.UUID
	uuid[0] = 0x10
	binary.BigEndian.PutUint64(uuid[8:], uint64(index+1))
	return uuid, uuidBytesToString(uuid[:])
}

func scalingVMAddress(index int) ([4]byte, string) {
	address := [4]byte{10, 64 + byte((index/254)%64), byte((index/254)%254 + 1), byte(index%254 + 1)}
	return address, fmt.Sprintf("%d.%d.%d.%d", address[0], address[1], address[2], address[3])
}

func scalingRemoteKey(index int) IPKey {
	value := uint32(index) & 0x00ff_ffff
	return V4ToKey([4]byte{198, byte(18 + ((value >> 16) & 1)), byte(value >> 8), byte(value)})
}

func scalingUniqueRemoteKey(index int) IPKey {
	var address [16]byte
	address[0], address[1], address[2], address[3] = 0x20, 0x01, 0x0d, 0xb8
	binary.BigEndian.PutUint64(address[8:], uint64(index+1))
	return V6ToKey(address)
}

func scalingFlow(index int, vmKeys []IPKey) ConntrackFlowLite {
	vmIndex := index % len(vmKeys)
	perVM := index / len(vmKeys)
	return ConntrackFlowLite{
		SrcIP:          vmKeys[vmIndex],
		DstIP:          scalingRemoteKey(perVM % 512),
		SrcPort:        uint16(1024 + index%60_000),
		DstPort:        uint16(8_000 + perVM%128),
		Proto:          6,
		Status:         IPS_SEEN_REPLY | IPS_ASSURED,
		ForwardPackets: 8,
		ForwardBytes:   8_192,
		ReversePackets: 6,
		ReverseBytes:   4_096,
		PacketsPresent: true,
		BytesPresent:   true,
	}
}

func scalingDomainParams(index int) []libvirt.TypedParam {
	base := uint64(index+1) * 1_000_000_000
	return []libvirt.TypedParam{
		typedParam("state.state", int32(libvirt.DomainRunning)),
		typedParam("cpu.time", base),
		typedParam("cpu.user", base/2),
		typedParam("cpu.system", base/4),
		typedParam("vcpu.current", uint64(2)),
		typedParam("vcpu.0.state", uint64(1)),
		typedParam("vcpu.0.time", base/2),
		typedParam("vcpu.0.wait", base/100),
		typedParam("vcpu.1.state", uint64(1)),
		typedParam("vcpu.1.time", base/2),
		typedParam("vcpu.1.wait", base/100),
		typedParam("balloon.maximum", uint64(4*1024*1024)),
		typedParam("balloon.current", uint64(3*1024*1024)),
		typedParam("balloon.usable", uint64(1024*1024)),
		typedParam("balloon.rss", uint64(3*1024*1024)),
		typedParam("balloon.swap_in", uint64(index)),
		typedParam("balloon.swap_out", uint64(index/2)),
		typedParam("block.count", uint64(1)),
		typedParam("block.0.name", "vda"),
		typedParam("block.0.rd.reqs", uint64(index+100)),
		typedParam("block.0.rd.bytes", uint64(index+100)*4096),
		typedParam("block.0.rd.times", uint64(index+100)*1000),
		typedParam("block.0.wr.reqs", uint64(index+50)),
		typedParam("block.0.wr.bytes", uint64(index+50)*4096),
		typedParam("block.0.wr.times", uint64(index+50)*1000),
		typedParam("block.0.capacity", uint64(20*1024*1024*1024)),
		typedParam("block.0.allocation", uint64(10*1024*1024*1024)),
		typedParam("block.0.physical", uint64(10*1024*1024*1024)),
		typedParam("net.count", uint64(1)),
		typedParam("net.0.name", fmt.Sprintf("tap%04d", index)),
		typedParam("net.0.rx.bytes", uint64(index+100)*8192),
		typedParam("net.0.rx.pkts", uint64(index+100)*8),
		typedParam("net.0.rx.errs", uint64(0)),
		typedParam("net.0.rx.drop", uint64(0)),
		typedParam("net.0.tx.bytes", uint64(index+100)*4096),
		typedParam("net.0.tx.pkts", uint64(index+100)*6),
		typedParam("net.0.tx.errs", uint64(0)),
		typedParam("net.0.tx.drop", uint64(0)),
	}
}

func newScalingScaleFixture(domainCount, entries int) (*scalingScaleFixture, error) {
	mc, err := NewMetricsCollector(CollectorConfig{
		LibvirtURI:             "qemu:///system",
		WorkerCount:            minInt(runtime.NumCPU(), 8),
		CollectionInterval:     5 * time.Second,
		ConntrackIPv4Enable:    true,
		ConntrackIPv6Enable:    false,
		ConntrackAcctEnabled:   true,
		OutboundBehaviorEnable: true,
		InboundBehaviorEnable:  true,
		BehaviorSensitivity:    1,
		BehaviorEWMATauFast:    3 * time.Minute,
		BehaviorEWMATauSlow:    2 * time.Hour,
		ThreatEWMATau:          150 * time.Second,
		ThreatLogMinInterval:   5 * time.Minute,
		BehaviorThresholds: BehaviorThresholds{
			OutboundFlowsTotal: 2_000,
			InboundFlowsTotal:  2_000,
		},
		Severity: SeverityConfig{BehaviorWeight: 0.45, ResourceWeight: 0.45, ThreatWeight: 0.10},
	})
	if err != nil {
		return nil, err
	}
	fixture := &scalingScaleFixture{
		mc:         mc,
		records:    make([]libvirt.DomainStatsRecord, 0, domainCount),
		metadata:   make(map[string]*DomainStatic, domainCount),
		identities: make([]VMIPIdentity, 0, domainCount),
		vmKeys:     make([]IPKey, 0, domainCount),
		entries:    entries,
	}
	now := time.Now()
	for index := 0; index < domainCount; index++ {
		uuid, instanceUUID := scalingUUID(index)
		address, addressString := scalingVMAddress(index)
		ipKey := V4ToKey(address)
		interfaceName := fmt.Sprintf("tap%04d", index)
		meta := &DomainStatic{
			Name:            fmt.Sprintf("scaling-server-%04d", index),
			InstanceUUID:    instanceUUID,
			UserUUID:        "scaling-user",
			UserName:        "scaling-user",
			ProjectUUID:     "scaling-project",
			ProjectName:     "scaling-project",
			FlavorName:      "scaling.medium",
			VCPUCount:       2,
			MemMB:           4096,
			RootType:        "volume",
			CreatedAt:       "2026-08-31T00:00:00Z",
			MetadataVersion: "2.0.0",
			FixedIPs:        []IP{{Address: addressString, Family: "ipv4", Prefix: "24"}},
			Disks:           []DomainDisk{{Device: "disk", Type: "network", SourceName: "rbd/scaling", TargetDev: "vda"}},
			Interfaces:      []string{interfaceName},
			LastUpdated:     now,
		}
		fixture.records = append(fixture.records, libvirt.DomainStatsRecord{
			Dom:    libvirt.Domain{Name: fmt.Sprintf("instance-%04d", index), UUID: uuid, ID: int32(index + 1)},
			Params: scalingDomainParams(index),
		})
		fixture.metadata[instanceUUID] = meta
		fixture.identities = append(fixture.identities, VMIPIdentity{InstanceUUID: instanceUUID, IP: ipKey})
		fixture.vmKeys = append(fixture.vmKeys, ipKey)
		mc.im.domainMeta[instanceUUID] = meta
	}
	mc.fetchDomainStatsOverride = func() ([]libvirt.DomainStatsRecord, float64, error) {
		return fixture.records, 0, nil
	}
	mc.cm.conntrackDumpFamilyOverride = func(family int, _ int, _ time.Duration, consume func(ConntrackFlowLite)) (uint64, uint64, uint64, error) {
		if family != syscall.AF_INET {
			return 0, 0, 0, nil
		}
		limit := fixture.entries
		if fixture.failDump {
			limit /= 2
		}
		for index := 0; index < limit; index++ {
			consume(scalingFlow(index, fixture.vmKeys))
		}
		if fixture.failDump {
			return uint64(limit), 0, 1, errors.New("scaling synthetic incomplete dump")
		}
		return uint64(limit), 0, 0, nil
	}
	return fixture, nil
}

func (fixture *scalingScaleFixture) close() {
	if fixture != nil && fixture.mc != nil && fixture.mc.shutdownChan != nil {
		close(fixture.mc.shutdownChan)
	}
}

func scalingMustFixture(tb testing.TB, domainCount, entries int) *scalingScaleFixture {
	tb.Helper()
	fixture, err := newScalingScaleFixture(domainCount, entries)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(fixture.close)
	return fixture
}

func scalingEmptyAggregate(fixture *scalingScaleFixture) *ConntrackAgg {
	agg, _ := fixture.mc.cm.newConntrackAggregator(fixture.identities, nil)
	agg.ObservationUnix = time.Now().Unix()
	agg.ObservationTimeSet = true
	return agg
}

func TestScalingCollectionCyclesCannotOverlap(t *testing.T) {
	const callers = 32
	var active atomic.Int64
	var maximum atomic.Int64
	mc := &MetricsCollector{collectionRunner: func() []prometheus.Metric {
		current := active.Add(1)
		for {
			observed := maximum.Load()
			if current <= observed || maximum.CompareAndSwap(observed, current) {
				break
			}
		}
		time.Sleep(time.Millisecond)
		active.Add(-1)
		return nil
	}}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for index := 0; index < callers; index++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			mc.runCollectionCycle()
		}()
	}
	close(start)
	wg.Wait()
	if got := maximum.Load(); got != 1 {
		t.Fatalf("maximum concurrent collection cycles=%d, want 1", got)
	}
}

func TestScalingSeriesCardinalityGrowsLinearly(t *testing.T) {
	counts := make([]int, 0, len(scalingDomainCases))
	for _, domains := range scalingDomainCases {
		fixture := scalingMustFixture(t, domains, 0)
		counts = append(counts, len(fixture.mc.runCollectionCycle()))
	}
	firstDelta := counts[1] - counts[0]
	secondDelta := counts[2] - counts[1]
	if firstDelta <= 0 || secondDelta <= 0 || firstDelta%400 != 0 || secondDelta%500 != 0 {
		t.Fatalf("series counts=%v do not have integral per-domain growth", counts)
	}
	perDomainFirst := firstDelta / 400
	perDomainSecond := secondDelta / 500
	if perDomainFirst != perDomainSecond {
		t.Fatalf("series counts=%v grow by %d then %d series/domain", counts, perDomainFirst, perDomainSecond)
	}
	fixed := counts[0] - 100*perDomainFirst
	if fixed <= 0 {
		t.Fatalf("series counts=%v imply invalid fixed host series=%d", counts, fixed)
	}
}

func TestScalingBehaviorEvidenceMapsRemainHardBounded(t *testing.T) {
	cm := newBehaviorStateTestManager()
	identity := VMIPIdentity{InstanceUUID: "scaling-bound", IP: V4ToKey([4]byte{10, 90, 0, 1})}
	agg, consume := cm.newConntrackAggregator([]VMIPIdentity{identity}, nil)
	for index := 0; index < maxBehaviorRemotePortPairs+10_000; index++ {
		consume(ConntrackFlowLite{
			SrcIP: identity.IP, DstIP: scalingUniqueRemoteKey(index), SrcPort: uint16(1024 + index%60_000),
			DstPort: uint16(8_000 + index%50_000), Proto: 6, Status: IPS_SEEN_REPLY,
		})
	}
	stats := agg.OutboundStats[0]
	if stats == nil || !stats.remoteMapCapped || !stats.remotePortMapCapped || !stats.tcpRemoteMapCapped {
		t.Fatalf("saturation flags missing: %+v", stats)
	}
	for name, size := range map[string]int{
		"remotes": len(stats.remotes), "remote_zones": len(stats.remoteZones),
		"remote_private": len(stats.remoteIsPrivate), "per_remote": len(stats.perRemote),
		"remote_heap": len(stats.remoteCountHeap), "remote_heap_index": len(stats.remoteCountEntries),
		"tcp_remotes": len(stats.tcpRemotes), "tcp_per_remote": len(stats.tcpPerRemote),
	} {
		if size > maxRemoteMapSize {
			t.Errorf("%s size=%d exceeds cap %d", name, size, maxRemoteMapSize)
		}
	}
	if got := len(stats.perRemoteDstPort); got > maxBehaviorRemotePortPairs {
		t.Errorf("remote/port state=%d exceeds cap %d", got, maxBehaviorRemotePortPairs)
	}
	if len(stats.remoteCountHeap) != len(stats.remotes) || len(stats.remoteCountEntries) != len(stats.remotes) {
		t.Fatalf("heap/index/remotes sizes=%d/%d/%d", len(stats.remoteCountHeap), len(stats.remoteCountEntries), len(stats.remotes))
	}
	victim, count, ok := minRemoteCountEntry(stats.perRemote)
	if !ok || stats.remoteCountHeap[0].remote != victim || stats.remoteCountHeap[0].count != count {
		t.Fatalf("heap minimum=%v/%d, scan minimum=%v/%d/%v", stats.remoteCountHeap[0].remote, stats.remoteCountHeap[0].count, victim, count, ok)
	}
}

type scalingStateSizes struct {
	Behavior  int
	Mining    int
	Threat    int
	Resource  int
	Inventory int
}

func (sizes scalingStateSizes) total() int {
	return sizes.Behavior + sizes.Mining + sizes.Threat + sizes.Resource + sizes.Inventory
}

func scalingSeedOwnedState(mc *MetricsCollector, count int, lastSeen int64) {
	if mc.resourceV2 == nil {
		mc.resourceV2 = make(map[string]*resourceV2State, count)
	}
	provider := mc.tm.Providers[0]
	for index := 0; index < count; index++ {
		_, instanceUUID := scalingUUID(index)
		address, addressString := scalingVMAddress(index)
		ip := V4ToKey(address)
		ident := behaviorIdentityKey{InstanceUUID: instanceUUID, IP: ip, Direction: "outbound"}
		behaviorIndex := shardIndexBehavior(ident)
		mc.cm.behaviorEWMA[behaviorIndex][ident] = &behaviorEWMAState{LastSeenUnix: lastSeen}
		mc.cm.behaviorLastSeverity[behaviorIndex][ident] = 0.5
		key := BehaviorKey{InstanceUUID: instanceUUID, IP: ip}
		previousIndex := shardIndexBehavior(behaviorIdentityKey{InstanceUUID: instanceUUID, IP: ip, Direction: "outbound"})
		mc.cm.outboundPrev[previousIndex][key] = outboundPrev{}
		mc.cm.outboundPrevLastSeen[previousIndex][key] = lastSeen
		mc.cm.behaviorPersist[behaviorAlertKey{InstanceUUID: instanceUUID, IP: ip, Direction: "outbound", Kind: "scaling"}] = &behaviorPersistState{LastSeenUnix: lastSeen}
		mc.cm.behaviorEmit[behaviorEmitKey{InstanceUUID: instanceUUID, IP: ip, Direction: "outbound"}] = &behaviorEmitState{LastEmitUnix: lastSeen}
		mc.cm.miningAlerts[ident] = &miningAlertState{LastSeenUnix: lastSeen, Active: true, Confirmed: true}
		mc.intelHistory[instanceUUID] = &IntelHistory{Initialized: true, LastUpdateUnix: lastSeen}
		provider.CountMap[instanceUUID] = 1
		provider.PrevHits[instanceUUID] = map[string]struct{}{"scaling": {}}
		mc.tm.spamCount[instanceUUID] = 1
		mc.tm.spamPrevHits[instanceUUID] = map[string]struct{}{"scaling": {}}
		mc.tm.threatLastHit[instanceThreatThrottlePrefix+"SCALING|"+instanceUUID] = time.Unix(lastSeen, 0)
		mc.resourceV2[instanceUUID] = &resourceV2State{LastUpdate: time.Unix(lastSeen, 0)}
		mc.im.domainMeta[instanceUUID] = &DomainStatic{InstanceUUID: instanceUUID, FixedIPs: []IP{{Address: addressString, Family: "ipv4"}}}
		resourceIndex := shardIndex(instanceUUID)
		mc.im.cpuSamples[resourceIndex][instanceUUID] = cpuSample{ts: time.Unix(lastSeen, 0)}
	}
}

func scalingOwnedStateSizes(mc *MetricsCollector) scalingStateSizes {
	sizes := scalingStateSizes{}
	for index := 0; index < shardCount; index++ {
		sizes.Behavior += len(mc.cm.behaviorEWMA[index]) + len(mc.cm.behaviorLastSeverity[index])
		sizes.Behavior += len(mc.cm.outboundPrev[index]) + len(mc.cm.outboundPrevLastSeen[index])
		sizes.Inventory += len(mc.im.cpuSamples[index])
	}
	sizes.Behavior += len(mc.cm.behaviorPersist) + len(mc.cm.behaviorEmit)
	sizes.Mining = len(mc.cm.miningAlerts)
	sizes.Threat = len(mc.intelHistory) + len(mc.tm.spamCount) + len(mc.tm.spamPrevHits) + len(mc.tm.threatLastHit)
	for _, provider := range mc.tm.Providers {
		sizes.Threat += len(provider.CountMap) + len(provider.PrevHits)
	}
	sizes.Resource = len(mc.resourceV2)
	sizes.Inventory += len(mc.im.domainMeta)
	return sizes
}

func TestScalingDeletionAndExpirationReclaimOwnedState(t *testing.T) {
	fixture := scalingMustFixture(t, 1, 0)
	fixture.mc.im.domainMeta = make(map[string]*DomainStatic)
	now := time.Now().Unix()
	scalingSeedOwnedState(fixture.mc, 1_000, now)
	before := scalingOwnedStateSizes(fixture.mc)
	if before.Behavior < 6_000 || before.Mining != 1_000 || before.Threat < 5_000 || before.Resource != 1_000 || before.Inventory < 2_000 {
		t.Fatalf("incomplete scale-state seed: %+v", before)
	}
	fixture.mc.im.activeInstances = map[string]struct{}{}
	fixture.mc.cleanupCaches(map[string]struct{}{})
	afterDeletion := scalingOwnedStateSizes(fixture.mc)
	if afterDeletion.total() != 0 {
		t.Fatalf("deleted-instance state retained after cleanup: %+v", afterDeletion)
	}

	stale := now - behaviorPrevKeyTTLSeconds - 1
	scalingSeedOwnedState(fixture.mc, 1_000, stale)
	active := make(map[string]struct{}, 1_000)
	for index := 0; index < 1_000; index++ {
		_, instanceUUID := scalingUUID(index)
		active[instanceUUID] = struct{}{}
	}
	fixture.mc.cm.cleanupBehaviorMapsWithAging(active, false)
	fixture.mc.cm.cleanupBehaviorStateWithAging(active, false)
	sizes := scalingOwnedStateSizes(fixture.mc)
	if sizes.Behavior != 0 || sizes.Mining != 0 {
		t.Fatalf("expired behavior/mining state retained: %+v", sizes)
	}
}

func TestScalingIncompleteScaleCyclePreservesLastGoodAndRecovers(t *testing.T) {
	captureDataIntegrityStructuredLogs(t)
	fixture := scalingMustFixture(t, 100, 100_000)
	freshMetrics := fixture.mc.runCollectionCycle()
	lastGood, count, ok := fixture.mc.cm.snapshotLastGoodConntrack()
	if !ok || lastGood == nil || count != 100_000 {
		t.Fatalf("fresh scale snapshot=(%p,%d,%v)", lastGood, count, ok)
	}
	fixture.failDump = true
	failedMetrics := fixture.mc.runCollectionCycle()
	retained, retainedCount, retainedOK := fixture.mc.cm.snapshotLastGoodConntrack()
	if !retainedOK || retained != lastGood || retainedCount != count {
		t.Fatalf("incomplete cycle corrupted last-good snapshot: got=(%p,%d,%v) want=(%p,%d,true)", retained, retainedCount, retainedOK, lastGood, count)
	}
	failedDelta := len(failedMetrics) - len(freshMetrics)
	if failedDelta < 0 || failedDelta > len(fixture.records)*8+16 {
		t.Fatalf("incomplete cycle series=%d (delta=%d), want retained data plus bounded availability state", len(failedMetrics), failedDelta)
	}
	fixture.failDump = false
	recoveredMetrics := fixture.mc.runCollectionCycle()
	recovered, recoveredCount, recoveredOK := fixture.mc.cm.snapshotLastGoodConntrack()
	if !recoveredOK || recovered == nil || recovered == lastGood || recoveredCount != count {
		t.Fatalf("recovery snapshot=(%p,%d,%v), prior=%p", recovered, recoveredCount, recoveredOK, lastGood)
	}
	recoveredDelta := len(recoveredMetrics) - len(freshMetrics)
	if recoveredDelta < 0 || recoveredDelta > len(fixture.records)*8+16 {
		t.Fatalf("recovered cycle series=%d (delta=%d), want bounded recovery state", len(recoveredMetrics), recoveredDelta)
	}
	settledMetrics := fixture.mc.runCollectionCycle()
	if settledDelta := len(settledMetrics) - len(freshMetrics); settledDelta < 0 || settledDelta > len(fixture.records)*8+16 {
		t.Fatalf("settled cycle series=%d (delta=%d), want bounded post-recovery state", len(settledMetrics), settledDelta)
	}
}

func TestScalingStructuredThreatLogVolumeIsCollectionBounded(t *testing.T) {
	logs := captureDataIntegrityStructuredLogs(t)
	tm := newThreatStateTestManager()
	tm.threatLogMinInterval = 5 * time.Minute
	tm.threatLogNowOverride = func() time.Time { return time.Unix(2_000_000_000, 0) }
	hits := threatIntelligenceThreatHits(1, false)
	for index := 0; index < 1_000; index++ {
		instanceUUID := fmt.Sprintf("scaling-log-%04d", index)
		tm.logThreatHitSummary("SCALING", "domain", "server", instanceUUID, "project", "project", "user", hits, 0, nil, ContactOut)
	}
	firstBytes := logs.Len()
	for index := 0; index < 1_000; index++ {
		instanceUUID := fmt.Sprintf("scaling-log-%04d", index)
		tm.logThreatHitSummary("SCALING", "domain", "server", instanceUUID, "project", "project", "user", hits, 0, nil, ContactOut)
	}
	if logs.Len() != firstBytes {
		t.Fatalf("unchanged repeated evidence added %d bytes inside throttle interval", logs.Len()-firstBytes)
	}
	if records := strings.Count(logs.String(), "\n"); records != 2_000 {
		t.Fatalf("1,000 instance/list episodes emitted %d records, want exactly 2,000", records)
	}
	if firstBytes > 4*1024*1024 {
		t.Fatalf("representative 1,000-instance structured log burst=%d bytes, want <=4 MiB", firstBytes)
	}
	if len(tm.threatLastHit) != 1_000 || len(tm.threatLastHit) > maxThreatLogThrottleEntries {
		t.Fatalf("threat log throttle state=%d, cap=%d", len(tm.threatLastHit), maxThreatLogThrottleEntries)
	}
}

func BenchmarkScalingRawNetlinkParse(b *testing.B) {
	payload := testTCPConntrackPayload(nativeEndian(), syscall.AF_INET, 6, true)
	for _, scale := range scalingScaleCases {
		b.Run(fmt.Sprintf("entries_%d", scale.Entries), func(b *testing.B) {
			b.ReportAllocs()
			b.ReportMetric(float64(scale.Entries), "entries/op")
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				var parseErrors uint64
				for index := 0; index < scale.Entries; index++ {
					flow, ok := parseConntrackMessageLite(payload, syscall.AF_INET, nativeEndian(), &parseErrors)
					if !ok {
						b.Fatalf("parse stopped at entry %d with %d errors", index, parseErrors)
					}
					scalingSinkFlow = flow
				}
				if parseErrors != 0 {
					b.Fatalf("parse errors=%d", parseErrors)
				}
			}
		})
	}
}

func BenchmarkScalingConntrackAggregation(b *testing.B) {
	for _, scale := range scalingScaleCases {
		b.Run(fmt.Sprintf("entries_%d_domains_%d", scale.Entries, scale.Domains), func(b *testing.B) {
			fixture := scalingMustFixture(b, scale.Domains, scale.Entries)
			b.ReportAllocs()
			b.ReportMetric(float64(scale.Entries), "entries/op")
			b.ReportMetric(float64(scale.Domains), "domains/op")
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				agg, consume := fixture.mc.cm.newConntrackAggregator(fixture.identities, nil)
				for index := 0; index < scale.Entries; index++ {
					consume(scalingFlow(index, fixture.vmKeys))
				}
				scalingSinkAgg = agg
			}
		})
	}
}

func BenchmarkScalingRemoteCardinalitySaturation(b *testing.B) {
	for _, scale := range scalingScaleCases {
		b.Run(fmt.Sprintf("entries_%d", scale.Entries), func(b *testing.B) {
			b.ReportAllocs()
			b.ReportMetric(float64(scale.Entries), "unique-remotes/op")
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				stats := newBehaviorStats(false)
				for index := 0; index < scale.Entries; index++ {
					stats.updateDetailedWithCoverage(scalingUniqueRemoteKey(index), uint16(8_000+index%50_000), 6, 0, 0, 0, 0, false, false)
				}
				if len(stats.remotes) != maxRemoteMapSize || !stats.remoteMapCapped {
					b.Fatalf("remote state=%d capped=%v", len(stats.remotes), stats.remoteMapCapped)
				}
				b.ReportMetric(float64(len(stats.remotes)), "remote-state/op")
			}
		})
	}
}

func BenchmarkScalingLibvirtDomainCollection(b *testing.B) {
	for _, domains := range scalingDomainCases {
		b.Run(fmt.Sprintf("domains_%d", domains), func(b *testing.B) {
			fixture := scalingMustFixture(b, domains, 0)
			connAgg := scalingEmptyAggregate(fixture)
			b.ReportAllocs()
			b.ReportMetric(float64(domains), "domains/op")
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				prepared, err := fixture.mc.prepareLibvirtCycle(fixture.records)
				if err != nil {
					b.Fatal(err)
				}
				agg := fixture.mc.collectDomainStatsParallelPrepared(fixture.records, prepared.metadata, connAgg, nil, 4_000_000, true, true)
				scalingSinkMetrics = agg.metrics
			}
			b.StopTimer()
			b.ReportMetric(float64(len(scalingSinkMetrics)), "series/op")
		})
	}
}

func BenchmarkScalingTotalCollection(b *testing.B) {
	for _, scale := range scalingScaleCases {
		b.Run(fmt.Sprintf("entries_%d_domains_%d", scale.Entries, scale.Domains), func(b *testing.B) {
			fixture := scalingMustFixture(b, scale.Domains, scale.Entries)
			b.ReportAllocs()
			b.ReportMetric(float64(scale.Entries), "entries/op")
			b.ReportMetric(float64(scale.Domains), "domains/op")
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				scalingSinkMetrics = fixture.mc.runCollectionCycle()
			}
			b.StopTimer()
			sizes := scalingOwnedStateSizes(fixture.mc)
			b.ReportMetric(float64(len(scalingSinkMetrics)), "series/op")
			b.ReportMetric(float64(sizes.Behavior), "behavior-state/op")
			b.ReportMetric(float64(sizes.Mining), "mining-state/op")
			b.ReportMetric(float64(sizes.Threat), "threat-state/op")
		})
	}
}

func BenchmarkScalingDeletionCleanup(b *testing.B) {
	for _, domains := range scalingDomainCases {
		b.Run(fmt.Sprintf("domains_%d", domains), func(b *testing.B) {
			fixture := scalingMustFixture(b, 1, 0)
			b.ReportAllocs()
			b.ReportMetric(float64(domains), "instances/op")
			for iteration := 0; iteration < b.N; iteration++ {
				b.StopTimer()
				scalingSeedOwnedState(fixture.mc, domains, time.Now().Unix())
				b.StartTimer()
				fixture.mc.cleanupCaches(map[string]struct{}{})
				b.StopTimer()
				if remaining := scalingOwnedStateSizes(fixture.mc).total(); remaining != 0 {
					b.Fatalf("cleanup retained %d state entries", remaining)
				}
				b.StartTimer()
			}
		})
	}
}
