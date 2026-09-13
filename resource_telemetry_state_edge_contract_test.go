package main

import (
	"math"
	"testing"
	"time"

	libvirt "github.com/digitalocean/go-libvirt"
	"github.com/prometheus/client_golang/prometheus"
)

func resourceTelemetryStateEdgeAxisInput(axis string, now time.Time, pressure float64, sources []string) resourceV2Input {
	identity := axis + "-identity-v1"
	input := resourceV2Input{Now: now}
	switch axis {
	case "cpu":
		input.CpuAvailable = true
		input.CpuPRaw = pressure
		input.CpuConf = 1
		input.CpuImpact = 1
		input.CpuSources = sources
		input.CpuIdentity = identity
	case "mem":
		input.MemAvailable = true
		input.MemPRaw = pressure
		input.MemConf = 1
		input.MemImpact = 1
		input.MemSources = sources
		input.MemIdentity = identity
	case "disk":
		input.DiskAvailable = true
		input.DiskPRaw = pressure
		input.DiskConf = 1
		input.DiskImpact = 1
		input.DiskSources = sources
		input.DiskIdentity = identity
	case "net":
		input.NetAvailable = true
		input.NetPRaw = pressure
		input.NetConf = 1
		input.NetImpact = 1
		input.NetSources = sources
		input.NetIdentity = identity
	}
	return input
}

func resourceTelemetryStateEdgeAxisResult(out resourceV2Output, axis string) resourceAxisResult {
	switch axis {
	case "cpu":
		return out.CPU
	case "mem":
		return out.MEM
	case "disk":
		return out.DISK
	case "net":
		return out.NET
	default:
		return resourceAxisResult{}
	}
}

func resourceTelemetryStateEdgeAxisState(state *resourceV2State, axis string) *resourceAxisV2 {
	if state == nil {
		return nil
	}
	switch axis {
	case "cpu":
		return &state.Cpu
	case "mem":
		return &state.Mem
	case "disk":
		return &state.Disk
	case "net":
		return &state.Net
	default:
		return nil
	}
}

func TestResourceTelemetryConfirmedDeletionThenUUIDReuseStartsWithEmptyResourceState(t *testing.T) {
	mc := newCollectorOrchestrationTestCollector(t)
	const instanceUUID = "12345678-1234-5678-9abc-def012345678"
	base := time.Unix(1_700_600_000, 0)
	active := map[string]struct{}{instanceUUID: {}}
	mc.im.setActiveInstances(active)
	mc.im.domainMeta[instanceUUID] = &DomainStatic{
		Name:         "old-incarnation",
		InstanceUUID: instanceUUID,
		LastUpdated:  base,
	}

	var state *resourceV2State
	for cycle := 0; cycle < 3; cycle++ {
		out, current := mc.computeResourceV2(instanceUUID, resourceTelemetryStateEdgeAxisInput(
			"cpu",
			base.Add(time.Duration(cycle)*mc.collectionInterval),
			1,
			[]string{"cpu.time", "vcpu.delay", "vcpu.wait"},
		))
		state = current
		syncResourceV2EventState(out, state)
	}
	if state == nil || !state.Cpu.Initialized || state.Cpu.EWMA == 0 ||
		state.OverallHi95Streak != 3 || state.LastBand == 0 || state.LastTopAxis != "cpu" {
		t.Fatalf("old incarnation did not contain the state required by the test: %+v", state)
	}
	state.LastCapActive = true

	idx := shardIndex(instanceUUID)
	mc.im.cpuSamples[idx][instanceUUID] = cpuSample{total: 100, ts: base}
	mc.im.memSamples[idx][instanceUUID] = memSample{swapIn: 100, ts: base}
	mc.im.diskSamples[idx][instanceUUID+"|volume-old|vda"] = diskSample{rdReq: 100, ts: base}
	mc.im.netSamples[idx][instanceUUID] = netSample{
		interfaces: map[string]netDeviceCounters{"tap-old": {rxPkts: 100}},
		ts:         base,
	}
	mc.im.resourceDimensions[instanceUUID] = resourceDimensions{vcpuCount: 2, memMB: 4096, vcpuKnown: true, memKnown: true}
	if changed := mc.im.observeInstanceResourceGenerationWithToken(instanceUUID, 41, 100, true, "boot-a:41:1000", true); changed {
		t.Fatal("first old-incarnation runtime generation was reported as a change")
	}

	// A complete inventory cycle confirms deletion. Only this confirmed absence
	// authorizes removal of state that a transient Libvirt failure would retain.
	mc.im.setActiveInstances(map[string]struct{}{})
	mc.cleanupCaches(map[string]struct{}{})

	if _, exists := mc.lookupResourceV2State(instanceUUID); exists {
		t.Fatal("confirmed deletion retained resource-axis/composite/event state")
	}
	if _, exists := mc.im.domainMeta[instanceUUID]; exists {
		t.Fatal("confirmed deletion retained domain metadata")
	}
	if _, exists := mc.im.cpuSamples[idx][instanceUUID]; exists {
		t.Fatal("confirmed deletion retained CPU rate baseline")
	}
	if _, exists := mc.im.memSamples[idx][instanceUUID]; exists {
		t.Fatal("confirmed deletion retained memory rate baseline")
	}
	if _, exists := mc.im.netSamples[idx][instanceUUID]; exists {
		t.Fatal("confirmed deletion retained network rate baseline")
	}
	if _, exists := mc.im.diskSamples[idx][instanceUUID+"|volume-old|vda"]; exists {
		t.Fatal("confirmed deletion retained disk rate baseline")
	}
	if _, exists := mc.im.resourceGeneration[instanceUUID]; exists {
		t.Fatal("confirmed deletion retained runtime generation")
	}
	if _, exists := mc.im.resourceGenerationCPUTime[instanceUUID]; exists {
		t.Fatal("confirmed deletion retained runtime CPU-time witness")
	}
	if _, exists := mc.im.resourceDimensions[instanceUUID]; exists {
		t.Fatal("confirmed deletion retained runtime dimensions")
	}

	// Reuse of the UUID after cleanup is a new incarnation. Recording its first
	// domain generation must not be treated as a transition from the old QEMU.
	mc.im.setActiveInstances(active)
	if changed := mc.im.ensureInstanceResourceGeneration(instanceUUID, 99); changed {
		t.Fatal("same UUID after confirmed cleanup inherited the old runtime generation")
	}
	if got := mc.im.resourceGeneration[instanceUUID]; got != 99 {
		t.Fatalf("new incarnation generation=%d, want 99", got)
	}
	if len(mc.im.cpuSamples[idx])+len(mc.im.memSamples[idx])+len(mc.im.diskSamples[idx])+len(mc.im.netSamples[idx]) != 0 {
		t.Fatal("same UUID after confirmed cleanup inherited a rate baseline")
	}

	empty, newState := mc.computeResourceV2(instanceUUID, resourceV2Input{Now: base.Add(time.Hour)})
	if empty.Available || empty.Fresh || empty.Retained {
		t.Fatalf("same UUID began with inherited resource output: %+v", empty)
	}
	if newState.Cpu.Initialized || newState.Mem.Initialized || newState.Disk.Initialized || newState.Net.Initialized ||
		newState.Cpu.EWMA != 0 || newState.Mem.EWMA != 0 || newState.Disk.EWMA != 0 || newState.Net.EWMA != 0 ||
		newState.OverallHi95Streak != 0 || newState.Composite.Initialized ||
		newState.LastBand != 0 || newState.LastTopAxis != "" || newState.LastCapActive {
		t.Fatalf("same UUID inherited axis, persistence, composite, or event baseline: %+v", newState)
	}
}

func TestResourceTelemetryPartialSourceDisappearanceRetainsEveryResourceAxis(t *testing.T) {
	tests := []struct {
		axis       string
		complete   []string
		missingOne []string
	}{
		{
			axis:       "cpu",
			complete:   []string{"cpu.time", "vcpu.delay", "vcpu.wait"},
			missingOne: []string{"cpu.time", "vcpu.wait"},
		},
		{
			axis:       "mem",
			complete:   []string{"guest-used", "major-fault", "swap-in"},
			missingOne: []string{"guest-used", "major-fault"},
		},
		{
			axis:       "disk",
			complete:   []string{"vda:flush", "vda:rw"},
			missingOne: []string{"vda:rw"},
		},
		{
			axis:       "net",
			complete:   []string{"conntrack-pressure", "interface-drops"},
			missingOne: []string{"interface-drops"},
		},
	}

	for _, test := range tests {
		t.Run(test.axis, func(t *testing.T) {
			mc := resourceTelemetryResourceCollector(10 * time.Second)
			base := time.Unix(1_700_610_000, 0)
			instanceUUID := "vm-partial-source-" + test.axis
			fresh, state := mc.computeResourceV2(
				instanceUUID,
				resourceTelemetryStateEdgeAxisInput(test.axis, base, 1, test.complete),
			)
			freshAxis := resourceTelemetryStateEdgeAxisResult(fresh, test.axis)
			if !freshAxis.Fresh || !freshAxis.Available || freshAxis.EWMA == 0 {
				t.Fatalf("complete %s source set was not fresh: %+v", test.axis, freshAxis)
			}
			wantStreak := state.OverallHi95Streak

			retained, state := mc.computeResourceV2(
				instanceUUID,
				resourceTelemetryStateEdgeAxisInput(test.axis, base.Add(10*time.Second), 0, test.missingOne),
			)
			retainedAxis := resourceTelemetryStateEdgeAxisResult(retained, test.axis)
			axisState := resourceTelemetryStateEdgeAxisState(state, test.axis)
			if !retainedAxis.Available || retainedAxis.Fresh || !retainedAxis.Retained ||
				retainedAxis.State != resourceAxisStateRetained {
				t.Fatalf("partial %s source set was not retained: %+v", test.axis, retainedAxis)
			}
			if retainedAxis.EWMA != freshAxis.EWMA || retainedAxis.Sev != freshAxis.Sev ||
				retainedAxis.PRaw != freshAxis.PRaw || retainedAxis.LastSuccess != freshAxis.LastSuccess {
				t.Fatalf("partial %s source set became a fresh zero: fresh=%+v retained=%+v", test.axis, freshAxis, retainedAxis)
			}
			if axisState == nil || !axisState.Missing || !resourceAxisSourceSetsEqual(axisState.Sources, normalizeResourceAxisSources(test.complete)) {
				t.Fatalf("partial %s source set replaced complete coverage: %+v", test.axis, axisState)
			}
			if state.OverallHi95Streak != wantStreak || retained.OverallFinal != fresh.OverallFinal || retained.TopAxis != fresh.TopAxis {
				t.Fatalf("partial %s source set advanced or changed composite state: fresh=%+v retained=%+v streak=%d/%d", test.axis, fresh, retained, wantStreak, state.OverallHi95Streak)
			}
		})
	}
}

func TestResourceTelemetryAuthoritativeIdentityChangeDropsOldUnavailableAxis(t *testing.T) {
	for _, axis := range []string{"cpu", "disk", "net"} {
		t.Run(axis, func(t *testing.T) {
			mc := resourceTelemetryResourceCollector(10 * time.Second)
			base := time.Unix(1_700_615_000, 0)
			instanceUUID := "vm-authoritative-change-" + axis
			first := resourceTelemetryStateEdgeAxisInput(axis, base, 1, []string{"source-v1"})
			switch axis {
			case "cpu":
				first.CpuIdentityKnown = true
			case "disk":
				first.DiskIdentityKnown = true
			case "net":
				first.NetIdentityKnown = true
			}
			fresh, state := mc.computeResourceV2(instanceUUID, first)
			if !resourceTelemetryStateEdgeAxisResult(fresh, axis).Fresh {
				t.Fatalf("initial %s axis was not fresh", axis)
			}
			state.OverallHi95Streak = 3

			changed := resourceV2Input{Now: base.Add(10 * time.Second)}
			switch axis {
			case "cpu":
				changed.CpuIdentity = axis + "-identity-v2"
				changed.CpuIdentityKnown = true
			case "disk":
				changed.DiskIdentity = axis + "-identity-v2"
				changed.DiskIdentityKnown = true
			case "net":
				changed.NetIdentity = axis + "-identity-v2"
				changed.NetIdentityKnown = true
			}
			out, state := mc.computeResourceV2(instanceUUID, changed)
			got := resourceTelemetryStateEdgeAxisResult(out, axis)
			stored := resourceTelemetryStateEdgeAxisState(state, axis)
			if got.Available || got.Fresh || got.Retained || !got.StructuralChange || got.AgeSeconds != -1 {
				t.Fatalf("old %s identity survived authoritative replacement: %+v", axis, got)
			}
			if stored == nil || stored.Initialized || stored.EWMA != 0 || !stored.LastSuccess.IsZero() {
				t.Fatalf("old %s state survived authoritative replacement: %+v", axis, stored)
			}
			if out.Available || state.OverallHi95Streak != 0 {
				t.Fatalf("authoritative %s removal retained composite/persistence: out=%+v state=%+v", axis, out, state)
			}
		})
	}
}

func TestResourceTelemetryMemoryResizeIsAStructuralRebaseline(t *testing.T) {
	mc := resourceTelemetryResourceCollector(10 * time.Second)
	base := time.Unix(1_700_615_500, 0)
	first, state := mc.computeResourceV2("vm-memory-resize", resourceV2Input{
		Now:              base,
		MemAvailable:     true,
		MemPRaw:          1,
		MemConf:          1,
		MemImpact:        0.5,
		MemSources:       []string{"guest_used"},
		MemIdentity:      "memory:1024",
		MemIdentityKnown: true,
	})
	if !first.MEM.Fresh || first.MEM.EWMA != 1 {
		t.Fatalf("initial memory axis was not established: %+v", first.MEM)
	}
	state.OverallHi95Streak = 3
	resized, state := mc.computeResourceV2("vm-memory-resize", resourceV2Input{
		Now:              base.Add(10 * time.Second),
		MemAvailable:     true,
		MemPRaw:          0.25,
		MemConf:          1,
		MemImpact:        0.75,
		MemSources:       []string{"guest_used"},
		MemIdentity:      "memory:2048",
		MemIdentityKnown: true,
	})
	if !resized.MEM.Fresh || !resized.MEM.StructuralChange || resized.MEM.Recovery || resized.MEM.Alpha != 1 || resized.MEM.EWMA != 0.25 {
		t.Fatalf("memory resize blended incompatible allocations: %+v", resized.MEM)
	}
	if state.OverallHi95Streak != 0 {
		t.Fatalf("memory resize retained composite persistence: %d", state.OverallHi95Streak)
	}
}

func TestResourceTelemetryPausedDomainClearsRuntimeStateAndResumeSilentlyRebaselines(t *testing.T) {
	mc := newCollectorOrchestrationTestCollector(t)
	uuidBytes := libvirt.UUID{0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78}
	const uuid = "12345678-1234-5678-9abc-def012345678"
	base := time.Unix(1_700_616_000, 0)
	meta := &DomainStatic{
		Name: "server", InstanceUUID: uuid,
		ProjectUUID: "project", ProjectName: "project-name", UserUUID: "user",
		VCPUCount: 2, MemMB: 4096,
		Disks:      []DomainDisk{{Device: "disk", Type: "block", TargetDev: "vda", SourceDev: "/dev/volume-a"}},
		Interfaces: []string{"tap0"}, PortUUIDs: []string{"port-a"},
		FixedIPs: []IP{{Address: "192.0.2.10", Family: "4"}},
	}
	idx := shardIndex(uuid)
	mc.im.cpuSamples[idx][uuid] = cpuSample{total: 100, vcpuCount: 2, ts: base}
	mc.im.memSamples[idx][uuid] = memSample{swapIn: 100, ts: base}
	mc.im.diskSamples[idx][uuid+"|/dev/volume-a|vda"] = diskSample{rdReq: 100, ts: base}
	mc.im.netSamples[idx][uuid] = netSample{interfaceSet: resourceNetworkIdentity(meta, deduplicateIPs(meta.FixedIPs)), interfaces: map[string]netDeviceCounters{"tap0": {rxPkts: 100}}, ts: base}
	mc.im.resourceDimensions[uuid] = resourceDimensions{
		vcpuCount: 2, memMB: 4096, vcpuKnown: true, memKnown: true,
		vcpuLiveObserved: true, memLiveObserved: true,
	}
	if mc.im.observeInstanceResourceGenerationWithToken(uuid, 7, 100, true, "boot-a:7:1000", true) {
		t.Fatal("first runtime generation was reported as a transition")
	}
	seedInput := resourceV2Input{
		Now:          base,
		CpuAvailable: true, CpuPRaw: 1, CpuConf: 1, CpuImpact: 1, CpuSources: []string{"usage"}, CpuIdentity: "vcpu:2", CpuIdentityKnown: true,
		MemAvailable: true, MemPRaw: 1, MemConf: 1, MemImpact: 1, MemSources: []string{"guest_used"}, MemIdentity: "memory:4096", MemIdentityKnown: true,
		DiskAvailable: true, DiskPRaw: 1, DiskConf: 1, DiskImpact: 1, DiskSources: []string{"rw"}, DiskIdentity: "disk-a", DiskIdentityKnown: true,
		NetAvailable: true, NetPRaw: 1, NetConf: 1, NetImpact: 1, NetSources: []string{"nic_drop"}, NetIdentity: resourceNetworkIdentity(meta, deduplicateIPs(meta.FixedIPs)), NetIdentityKnown: true,
	}
	out, state := mc.computeResourceV2(uuid, seedInput)
	syncResourceV2EventState(out, state)
	state.OverallHi95Streak = 3
	state.LastCapActive = true

	pausedAgg := &hostAgg{projects: make(map[string]struct{})}
	mc.collectDomainMetricsWithMetadata(
		libvirt.DomainStatsRecord{
			Dom:    libvirt.Domain{Name: "domain", UUID: uuidBytes, ID: 7},
			Params: []libvirt.TypedParam{typedParam("state.state", int32(libvirt.DomainPaused))},
		},
		meta, nil, nil, pausedAgg, 0, false, false,
	)
	if len(mc.im.cpuSamples[idx])+len(mc.im.memSamples[idx])+len(mc.im.diskSamples[idx])+len(mc.im.netSamples[idx]) != 0 {
		t.Fatal("paused lifecycle boundary retained a rate baseline")
	}
	dimensions := mc.im.resourceDimensions[uuid]
	if dimensions.vcpuLiveObserved || dimensions.memLiveObserved {
		t.Fatalf("paused lifecycle boundary retained live dimension authority: %+v", dimensions)
	}
	state, ok := mc.lookupResourceV2State(uuid)
	if !ok || !state.NeedsRebaseline || state.Cpu.Initialized || state.Mem.Initialized || state.Disk.Initialized || state.Net.Initialized ||
		state.Composite.Initialized || state.OverallHi95Streak != 0 || state.LastCapActive || state.LastBand != 0 || state.LastTopAxis != "" {
		t.Fatalf("paused lifecycle boundary retained resource/composite/persistence/event state: %+v", state)
	}

	resumedAgg := &hostAgg{projects: make(map[string]struct{})}
	mc.collectDomainMetricsWithMetadata(
		libvirt.DomainStatsRecord{
			Dom: libvirt.Domain{Name: "domain", UUID: uuidBytes, ID: 7},
			Params: []libvirt.TypedParam{
				typedParam("state.state", int32(libvirt.DomainRunning)),
				typedParam("cpu.time", uint64(1_000)),
				typedParam("vcpu.current", uint64(2)),
				typedParam("balloon.maximum", uint64(4096*1024)),
				typedParam("balloon.current", uint64(4096*1024)),
				typedParam("balloon.usable", uint64(196*1024)),
				typedParam("balloon.swap_in", uint64(1_000)),
				typedParam("block.count", uint64(1)),
				typedParam("block.0.name", "vda"),
				typedParam("block.0.rd.reqs", uint64(1_000)),
				typedParam("block.0.rd.bytes", uint64(1_000)),
				typedParam("block.0.rd.times", uint64(1_000)),
				typedParam("block.0.wr.reqs", uint64(1_000)),
				typedParam("block.0.wr.bytes", uint64(1_000)),
				typedParam("block.0.wr.times", uint64(1_000)),
				typedParam("block.0.fl.reqs", uint64(1_000)),
				typedParam("block.0.fl.times", uint64(1_000)),
				typedParam("net.count", uint64(1)),
				typedParam("net.0.name", "tap0"),
				typedParam("net.0.rx.pkts", uint64(1_000)),
				typedParam("net.0.tx.pkts", uint64(1_000)),
				typedParam("net.0.rx.drop", uint64(0)),
				typedParam("net.0.tx.drop", uint64(0)),
			},
		},
		meta, nil, nil, resumedAgg, 0, false, false,
	)
	state, _ = mc.lookupResourceV2State(uuid)
	if state.NeedsRebaseline || !state.Mem.Initialized || state.Cpu.Initialized || state.Disk.Initialized || state.Net.Initialized ||
		state.OverallHi95Streak != 0 || state.LastCapActive {
		t.Fatalf("first resumed observation was not a clean silent structural baseline: %+v", state)
	}
	if got := mc.im.memSamples[idx][uuid]; got.swapIn != 1_000 {
		t.Fatalf("resumed memory baseline crossed paused runtime: %+v", got)
	}
}

func TestResourceTelemetryAddedAxisSourceIsStructuralAcrossAllAxes(t *testing.T) {
	for _, axis := range []string{"cpu", "mem", "disk", "net"} {
		t.Run(axis, func(t *testing.T) {
			mc := resourceTelemetryResourceCollector(10 * time.Second)
			base := time.Unix(1_700_617_000, 0)
			instanceUUID := "vm-added-source-" + axis
			initialInput := resourceTelemetryStateEdgeAxisInput(axis, base, 1, []string{"base"})
			initial, state := mc.computeResourceV2(instanceUUID, initialInput)
			syncResourceV2EventState(initial, state)
			state.OverallHi95Streak = 3
			state.LastCapActive = true

			addedInput := resourceTelemetryStateEdgeAxisInput(axis, base.Add(10*time.Second), 0.2, []string{"added", "base"})
			added, state := mc.computeResourceV2(instanceUUID, addedInput)
			axisOut := resourceTelemetryStateEdgeAxisResult(added, axis)
			if !axisOut.Fresh || !axisOut.StructuralChange || axisOut.Recovery || axisOut.Alpha != 1 || math.Abs(axisOut.EWMA-0.2) > 1e-12 {
				t.Fatalf("added %s source inherited the old EWMA: %+v", axis, axisOut)
			}
			if added.PersistenceTriggered || state.OverallHi95Streak != 0 {
				t.Fatalf("added %s source inherited persistence state: out=%+v state=%+v", axis, added, state)
			}
			syncResourceV2EventState(added, state)
			if state.LastBand != band30_60_85(added.OverallFinal) || state.LastTopAxis != added.TopAxis || state.LastCapActive != added.CapActive {
				t.Fatalf("added %s source did not silently synchronize event state: out=%+v state=%+v", axis, added, state)
			}
		})
	}
}

func TestResourceTelemetryMissingDomainStateRetainsInsteadOfResettingOrEmittingZero(t *testing.T) {
	mc := newCollectorOrchestrationTestCollector(t)
	const instanceUUID = "feedface-feed-face-feed-facefeedface"
	base := time.Now().Add(-mc.collectionInterval)
	fresh, state := mc.computeResourceV2(instanceUUID, resourceV2Input{
		Now:              base,
		CpuAvailable:     true,
		CpuPRaw:          1,
		CpuConf:          1,
		CpuImpact:        1,
		CpuSources:       []string{"usage"},
		CpuIdentity:      "vcpu:2",
		CpuIdentityKnown: true,
	})
	wantSeverity := fresh.OverallFinal
	wantSuccess := state.Cpu.LastSuccess

	meta := &DomainStatic{
		Name:         "missing-state",
		InstanceUUID: instanceUUID,
		ProjectUUID:  "project",
		ProjectName:  "project-name",
		UserUUID:     "user",
		VCPUCount:    2,
		MemMB:        1024,
	}
	record := libvirt.DomainStatsRecord{
		Dom: libvirt.Domain{Name: "instance-missing-state", ID: 7},
		// A successful record with no state.state is missing telemetry, not a
		// stopped-domain lifecycle transition.
		Params: nil,
	}
	agg := &hostAgg{projects: make(map[string]struct{})}
	mc.collectDomainMetricsWithMetadata(record, meta, nil, nil, agg, 0, false, false)

	retained, ok := mc.lookupResourceV2State(instanceUUID)
	if !ok || retained != state || !retained.Cpu.Initialized || !retained.Cpu.Missing || retained.Cpu.LastSuccess != wantSuccess {
		t.Fatalf("missing state field reset resource history: %+v", retained)
	}
	if got, ok := dataIntegrityMetricFamilyValue(t, agg.metrics, "oie_instance_resource_severity"); !ok || got != wantSeverity {
		t.Fatalf("missing state resource severity=(%v,%v), want retained %v", got, ok, wantSeverity)
	}
}

func TestResourceTelemetryPartialNICStatsKeepAuthoritativeNetworkIdentity(t *testing.T) {
	mc := newCollectorOrchestrationTestCollector(t)
	meta := &DomainStatic{Interfaces: []string{"tap0", "tap1"}}
	full := &ParsedStats{
		NetCount:        2,
		NetCountPresent: true,
		Nets: map[int]*NetStat{
			0: {Name: "tap0", NamePresent: true, RxPktsPresent: true, TxPktsPresent: true, RxDropPresent: true, TxDropPresent: true},
			1: {Name: "tap1", NamePresent: true, RxPktsPresent: true, TxPktsPresent: true, RxDropPresent: true, TxDropPresent: true},
		},
	}
	partial := &ParsedStats{
		NetCount:        2,
		NetCountPresent: true,
		Nets: map[int]*NetStat{
			0: {Name: "tap0", NamePresent: true, RxPktsPresent: true, TxPktsPresent: true, RxDropPresent: true, TxDropPresent: true},
		},
	}
	collect := func(stats *ParsedStats, now time.Time) (bool, string, []string) {
		metrics := make([]prometheus.Metric, 0)
		_, _, _, _, _, available, _, identity, sources := mc.collectDomainNetworkAndConntrackWithSources(
			meta, stats, now,
			"domain", "server", "vm-partial-nic", "project", "project-name", "user",
			true, nil, nil, nil, nil, 0, false, true, &metrics,
		)
		return available, identity, sources
	}
	base := time.Unix(1_700_616_000, 0)
	_, firstIdentity, _ := collect(full, base)
	available, completeIdentity, completeSources := collect(full, base.Add(time.Second))
	if !available || len(completeSources) != 1 || completeSources[0] != "nic_drop" {
		t.Fatalf("complete NIC observation=(available=%v sources=%v), want NIC source", available, completeSources)
	}
	available, partialIdentity, partialSources := collect(partial, base.Add(2*time.Second))
	if available || len(partialSources) != 0 {
		t.Fatalf("partial NIC stats became a complete rate: available=%v sources=%v", available, partialSources)
	}
	if firstIdentity != completeIdentity || partialIdentity != completeIdentity {
		t.Fatalf("partial NIC stats changed authoritative identity: first=%q complete=%q partial=%q", firstIdentity, completeIdentity, partialIdentity)
	}

	axisFresh, _ := mc.computeResourceV2("vm-partial-nic-axis", resourceV2Input{
		Now:              base,
		NetAvailable:     true,
		NetPRaw:          1,
		NetConf:          1,
		NetImpact:        1,
		NetSources:       []string{"conntrack_pressure", "nic_drop"},
		NetIdentity:      completeIdentity,
		NetIdentityKnown: true,
	})
	axisRetained, _ := mc.computeResourceV2("vm-partial-nic-axis", resourceV2Input{
		Now:              base.Add(10 * time.Second),
		NetAvailable:     true,
		NetPRaw:          0,
		NetConf:          1,
		NetImpact:        0,
		NetSources:       []string{"conntrack_pressure"},
		NetIdentity:      partialIdentity,
		NetIdentityKnown: true,
	})
	if !axisRetained.NET.Retained || axisRetained.NET.Sev != axisFresh.NET.Sev {
		t.Fatalf("partial NIC plus fresh conntrack replaced last complete network axis: fresh=%+v retained=%+v", axisFresh.NET, axisRetained.NET)
	}
}

func TestResourceTelemetryStatOnlyDiskCannotReplaceAuthoritativeDiskAxis(t *testing.T) {
	mc := newCollectorOrchestrationTestCollector(t)
	const instanceUUID = "vm-stat-only-disk"
	meta := &DomainStatic{Disks: []DomainDisk{{TargetDev: "vda", Type: "file", SourceFile: "/images/vda.qcow2"}}}
	collect := func(stats *ParsedStats, now time.Time) (bool, string, []string, bool) {
		metrics := make([]prometheus.Metric, 0)
		_, _, _, available, identity, sources, identityKnown := mc.collectDomainDiskMetricsWithSources(
			meta, stats, now,
			"domain", "server", instanceUUID, "project", "project-name", "user",
			true, &metrics,
		)
		return available, identity, sources, identityKnown
	}
	base := time.Unix(1_700_616_500, 0)
	authoritative := func(value uint64) *ParsedStats {
		return &ParsedStats{
			BlockCount:        1,
			BlockCountPresent: true,
			Disks:             map[int]*DiskStat{0: fullDiskStat("vda", value, value*1024, value*1_000_000, value, value*1_000_000)},
		}
	}
	collect(authoritative(10), base)
	available, identity, sources, identityKnown := collect(authoritative(20), base.Add(time.Second))
	if !available || !identityKnown || len(sources) == 0 {
		t.Fatalf("authoritative disk observation unavailable: available=%v known=%v sources=%v", available, identityKnown, sources)
	}
	fresh, _ := mc.computeResourceV2(instanceUUID, resourceV2Input{
		Now:               base.Add(time.Second),
		DiskAvailable:     true,
		DiskPRaw:          1,
		DiskConf:          1,
		DiskImpact:        1,
		DiskSources:       sources,
		DiskIdentity:      identity,
		DiskIdentityKnown: true,
	})

	mismatch := func(value uint64) *ParsedStats {
		return &ParsedStats{
			BlockCount:        2,
			BlockCountPresent: true,
			Disks: map[int]*DiskStat{
				0: fullDiskStat("vda", value, value*1024, value*1_000_000, value, value*1_000_000),
				1: fullDiskStat("vdb", value, value*1024, value*1_000_000, value, value*1_000_000),
			},
		}
	}
	collect(mismatch(30), base.Add(2*time.Second))
	available, mismatchIdentity, mismatchSources, mismatchKnown := collect(mismatch(40), base.Add(3*time.Second))
	if available || mismatchKnown {
		t.Fatalf("stat-only disk became authoritative: available=%v identity_known=%v identity=%q sources=%v", available, mismatchKnown, mismatchIdentity, mismatchSources)
	}
	retained, _ := mc.computeResourceV2(instanceUUID, resourceV2Input{
		Now:               base.Add(10 * time.Second),
		DiskAvailable:     available,
		DiskSources:       mismatchSources,
		DiskIdentity:      mismatchIdentity,
		DiskIdentityKnown: mismatchKnown,
	})
	if !retained.DISK.Retained || retained.DISK.Sev != fresh.DISK.Sev {
		t.Fatalf("non-authoritative stat-only disk replaced last complete axis: fresh=%+v retained=%+v", fresh.DISK, retained.DISK)
	}
}

func TestResourceTelemetryAttentionAvailabilityBlocksPositiveWeightRenormalization(t *testing.T) {
	scoring := SeverityConfig{ResourceWeight: 0.45, BehaviorWeight: 0.45, ThreatWeight: 0.10}
	completeScore := attentionSeverityWeighted(scoring, 100, true, 0, true, 0, true)
	renormalizedScore := attentionSeverityWeighted(scoring, 100, true, 0, false, 0, true)
	if renormalizedScore <= completeScore {
		t.Fatalf("test fixture did not expose denominator renormalization: complete=%v partial=%v", completeScore, renormalizedScore)
	}

	for _, test := range []struct {
		name                       string
		resource, behavior, threat bool
		wantAvailable              bool
	}{
		{name: "complete", resource: true, behavior: true, threat: true, wantAvailable: true},
		{name: "resource missing", resource: false, behavior: true, threat: true},
		{name: "behavior missing", resource: true, behavior: false, threat: true},
		{name: "threat missing", resource: true, behavior: true, threat: false},
		{name: "all missing"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := attentionInputsAvailable(scoring, test.resource, test.behavior, test.threat); got != test.wantAvailable {
				t.Fatalf("attention availability=%v, want %v", got, test.wantAvailable)
			}
		})
	}

	// Inputs that are not applicable have their weight removed before the
	// availability decision. Their absence must not block the remaining model.
	resourceAndThreatOnly := SeverityConfig{ResourceWeight: 0.45, BehaviorWeight: 0, ThreatWeight: 0.10}
	if !attentionInputsAvailable(resourceAndThreatOnly, true, false, true) {
		t.Fatal("missing zero-weight behavior input blocked applicable resource and threat inputs")
	}
	if attentionInputsAvailable(resourceAndThreatOnly, true, false, false) {
		t.Fatal("missing positively weighted threat input was renormalized away")
	}
}
