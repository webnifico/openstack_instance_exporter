package main

import (
	"testing"
	"time"

	libvirt "github.com/digitalocean/go-libvirt"
	"github.com/prometheus/client_golang/prometheus"
)

func TestResourceTelemetryLiveResourceDimensionDisappearanceIsMissingNotFresh(t *testing.T) {
	im := newResourceTelemetryDeviceSampleManager(time.Second)
	const uuid = "vm-live-dimensions"
	live := &ParsedStats{
		VcpuCurrent:        4,
		VcpuCurrentPresent: true,
		MemMax:             8192 * 1024,
		MemMaxPresent:      true,
	}
	vcpu, vcpuKnown, vcpuCurrent, memMB, memKnown, memCurrent := im.resolveResourceDimensions(uuid, 2, 4096, live)
	if vcpu != 4 || !vcpuKnown || !vcpuCurrent || memMB != 8192 || !memKnown || !memCurrent {
		t.Fatalf("live dimensions were not authoritative: vcpu=%d/%v/%v mem=%d/%v/%v", vcpu, vcpuKnown, vcpuCurrent, memMB, memKnown, memCurrent)
	}

	// Once the runtime source has appeared, its absence is missing telemetry.
	// The last value remains usable for stable labels/identity, but must not make
	// the CPU or memory observation fresh or silently fall back to stale flavor
	// metadata after a possible live resize.
	vcpu, vcpuKnown, vcpuCurrent, memMB, memKnown, memCurrent = im.resolveResourceDimensions(uuid, 2, 4096, &ParsedStats{})
	if vcpu != 4 || !vcpuKnown || vcpuCurrent || memMB != 8192 || !memKnown || memCurrent {
		t.Fatalf("missing live dimensions were treated as current: vcpu=%d/%v/%v mem=%d/%v/%v", vcpu, vcpuKnown, vcpuCurrent, memMB, memKnown, memCurrent)
	}

	recovered := &ParsedStats{
		VcpuCurrent:        6,
		VcpuCurrentPresent: true,
		MemMax:             12288 * 1024,
		MemMaxPresent:      true,
	}
	vcpu, vcpuKnown, vcpuCurrent, memMB, memKnown, memCurrent = im.resolveResourceDimensions(uuid, 2, 4096, recovered)
	if vcpu != 6 || !vcpuKnown || !vcpuCurrent || memMB != 12288 || !memKnown || !memCurrent {
		t.Fatalf("live dimension recovery was not accepted: vcpu=%d/%v/%v mem=%d/%v/%v", vcpu, vcpuKnown, vcpuCurrent, memMB, memKnown, memCurrent)
	}
}

func TestResourceTelemetryLegacyMetadataDimensionsRemainAuthoritativeUntilLiveSourceAppears(t *testing.T) {
	im := newResourceTelemetryDeviceSampleManager(time.Second)
	const uuid = "vm-metadata-dimensions"
	vcpu, vcpuKnown, vcpuCurrent, memMB, memKnown, memCurrent := im.resolveResourceDimensions(uuid, 2, 4096, &ParsedStats{})
	if vcpu != 2 || !vcpuKnown || !vcpuCurrent || memMB != 4096 || !memKnown || !memCurrent {
		t.Fatalf("legacy metadata dimensions unavailable: vcpu=%d/%v/%v mem=%d/%v/%v", vcpu, vcpuKnown, vcpuCurrent, memMB, memKnown, memCurrent)
	}

	// Before a live source has ever been observed, refreshed metadata remains
	// the consistent authority rather than a one-time cache.
	vcpu, vcpuKnown, vcpuCurrent, memMB, memKnown, memCurrent = im.resolveResourceDimensions(uuid, 3, 6144, &ParsedStats{})
	if vcpu != 3 || !vcpuKnown || !vcpuCurrent || memMB != 6144 || !memKnown || !memCurrent {
		t.Fatalf("metadata dimension refresh was ignored: vcpu=%d/%v/%v mem=%d/%v/%v", vcpu, vcpuKnown, vcpuCurrent, memMB, memKnown, memCurrent)
	}
}

func TestResourceTelemetryRuntimeDimensionFreshnessIsIndependentAndInvalidValuesDoNotReplaceCache(t *testing.T) {
	im := newResourceTelemetryDeviceSampleManager(time.Second)
	const uuid = "vm-independent-dimensions"
	_, _, _, _, _, _ = im.resolveResourceDimensions(uuid, 2, 4096, &ParsedStats{
		VcpuCurrent: 4, VcpuCurrentPresent: true,
		MemMax: 8192 * 1024, MemMaxPresent: true,
	})

	vcpu, vcpuKnown, vcpuFresh, memMB, memKnown, memFresh := im.resolveResourceDimensions(uuid, 2, 4096, &ParsedStats{
		MemMax: 8192 * 1024, MemMaxPresent: true,
	})
	if vcpu != 4 || !vcpuKnown || vcpuFresh || memMB != 8192 || !memKnown || !memFresh {
		t.Fatalf("CPU/MEM source modes were coupled: vcpu=%d/%v/%v mem=%d/%v/%v", vcpu, vcpuKnown, vcpuFresh, memMB, memKnown, memFresh)
	}

	vcpu, vcpuKnown, vcpuFresh, memMB, memKnown, memFresh = im.resolveResourceDimensions(uuid, 2, 4096, &ParsedStats{
		VcpuCurrentPresent: true,                      // zero is invalid and must not replace 4
		MemMax:             1023, MemMaxPresent: true, // sub-MiB is invalid
	})
	if vcpu != 4 || !vcpuKnown || vcpuFresh || memMB != 8192 || !memKnown || memFresh {
		t.Fatalf("invalid live dimensions replaced cache or became fresh: vcpu=%d/%v/%v mem=%d/%v/%v", vcpu, vcpuKnown, vcpuFresh, memMB, memKnown, memFresh)
	}

	vcpu, vcpuKnown, vcpuFresh, memMB, memKnown, memFresh = im.resolveResourceDimensions(uuid, 2, 4096, &ParsedStats{
		VcpuCurrent: 4, VcpuCurrentPresent: true,
	})
	if vcpu != 4 || !vcpuKnown || !vcpuFresh || memMB != 8192 || !memKnown || memFresh {
		t.Fatalf("independent CPU recovery changed missing memory state: vcpu=%d/%v/%v mem=%d/%v/%v", vcpu, vcpuKnown, vcpuFresh, memMB, memKnown, memFresh)
	}
}

func TestResourceTelemetryMissingLiveDimensionsDoNotAdvanceRateBaselines(t *testing.T) {
	mc := newCollectorOrchestrationTestCollector(t)
	const uuid = "vm-dimension-baselines"
	base := time.Unix(1_700_700_000, 0)
	live := &ParsedStats{
		VcpuCurrent:        2,
		VcpuCurrentPresent: true,
		MemMax:             4096 * 1024,
		MemMaxPresent:      true,
		CpuTime:            1_000_000_000,
		CpuTimePresent:     true,
		SwapIn:             10,
		SwapInPresent:      true,
	}
	vcpu, _, vcpuCurrent, memMB, _, memCurrent := mc.im.resolveResourceDimensions(uuid, 2, 4096, live)
	metrics := make([]prometheus.Metric, 0)
	mc.collectDomainCPUMetricsWithSources(live, base, "domain", "server", uuid, "project", "project-name", "user", vcpu, vcpuCurrent, &metrics)
	mc.collectDomainMemoryMetricsWithSources(live, base, "domain", "server", uuid, "project", "project-name", "user", true, memMB, memCurrent, &metrics)

	missing := &ParsedStats{
		CpuTime:        2_000_000_000,
		CpuTimePresent: true,
		SwapIn:         20,
		SwapInPresent:  true,
	}
	vcpu, _, vcpuCurrent, memMB, _, memCurrent = mc.im.resolveResourceDimensions(uuid, 2, 4096, missing)
	if vcpuCurrent || memCurrent {
		t.Fatal("missing runtime dimensions remained current")
	}
	mc.collectDomainCPUMetricsWithSources(missing, base.Add(time.Second), "domain", "server", uuid, "project", "project-name", "user", vcpu, vcpuCurrent, &metrics)
	mc.collectDomainMemoryMetricsWithSources(missing, base.Add(time.Second), "domain", "server", uuid, "project", "project-name", "user", true, memMB, memCurrent, &metrics)

	idx := shardIndex(uuid)
	if got := mc.im.cpuSamples[idx][uuid]; got.total != live.CpuTime || !got.ts.Equal(base) {
		t.Fatalf("missing CPU dimension advanced baseline: %+v", got)
	}
	if got := mc.im.memSamples[idx][uuid]; got.swapIn != live.SwapIn || !got.ts.Equal(base) {
		t.Fatalf("missing memory dimension advanced baseline: %+v", got)
	}
}

func TestResourceTelemetryFullDomainPathMissingLiveMemoryDimensionRetainsAxisAndBaseline(t *testing.T) {
	mc := newCollectorOrchestrationTestCollector(t)
	const uuid = "00112233-4455-6677-8899-aabbccddeeff"
	uuidBytes := libvirt.UUID{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	meta := &DomainStatic{
		Name: "server", InstanceUUID: uuid,
		ProjectUUID: "project", ProjectName: "project-name", UserUUID: "user",
		VCPUCount: 2, MemMB: 4096,
	}
	collect := func(cpuTime, swapIn uint64, includeLiveMemoryMaximum bool) {
		params := []libvirt.TypedParam{
			typedParam("state.state", int32(libvirt.DomainRunning)),
			typedParam("cpu.time", cpuTime),
			typedParam("vcpu.current", uint64(2)),
			typedParam("balloon.current", uint64(4096*1024)),
			typedParam("balloon.usable", uint64(196*1024)),
			typedParam("balloon.swap_in", swapIn),
		}
		if includeLiveMemoryMaximum {
			params = append(params, typedParam("balloon.maximum", uint64(4096*1024)))
		}
		agg := &hostAgg{projects: make(map[string]struct{})}
		mc.collectDomainMetricsWithMetadata(
			libvirt.DomainStatsRecord{Dom: libvirt.Domain{Name: "domain", UUID: uuidBytes, ID: 7}, Params: params},
			meta,
			nil,
			nil,
			agg,
			0,
			false,
			false,
		)
	}

	collect(100, 10, true)
	idx := shardIndex(uuid)
	firstSample, ok := mc.im.memSamples[idx][uuid]
	if !ok {
		t.Fatal("full domain path did not establish a memory rate baseline")
	}
	state, ok := mc.lookupResourceV2State(uuid)
	if !ok || !state.Mem.Initialized || state.Mem.Missing || state.Mem.EWMA <= 0 {
		t.Fatalf("full domain path did not establish a fresh memory axis: %+v", state)
	}
	lastSuccess := state.Mem.LastSuccess
	wantEWMA := state.Mem.EWMA
	wantStreak := state.OverallHi95Streak

	collect(200, 20, false)
	if got := mc.im.memSamples[idx][uuid]; got != firstSample {
		t.Fatalf("missing live memory maximum advanced the production rate baseline: first=%+v got=%+v", firstSample, got)
	}
	state, _ = mc.lookupResourceV2State(uuid)
	if !state.Mem.Missing || !state.Mem.LastSuccess.Equal(lastSuccess) || state.Mem.EWMA != wantEWMA {
		t.Fatalf("missing live memory maximum changed the retained axis: %+v", state.Mem)
	}
	if state.OverallHi95Streak != wantStreak {
		t.Fatalf("retained memory observation advanced persistence: got=%d want=%d", state.OverallHi95Streak, wantStreak)
	}
}

func TestResourceTelemetryFullDomainPathRetainedResourceOmitsAttention(t *testing.T) {
	mc := newCollectorOrchestrationTestCollector(t)
	mc.scoring = SeverityConfig{ResourceWeight: 1}
	const uuid = "00112233-4455-6677-8899-aabbccddeeff"
	uuidBytes := libvirt.UUID{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	meta := &DomainStatic{
		Name: "server", InstanceUUID: uuid,
		ProjectUUID: "project", ProjectName: "project-name", UserUUID: "user",
		VCPUCount: 2, MemMB: 4096,
	}
	collect := func(includeLiveMemoryMaximum bool) []prometheus.Metric {
		params := []libvirt.TypedParam{
			typedParam("state.state", int32(libvirt.DomainRunning)),
			typedParam("balloon.current", uint64(4096*1024)),
			typedParam("balloon.usable", uint64(196*1024)),
		}
		if includeLiveMemoryMaximum {
			params = append(params, typedParam("balloon.maximum", uint64(4096*1024)))
		}
		agg := &hostAgg{projects: make(map[string]struct{})}
		mc.collectDomainMetricsWithMetadata(
			libvirt.DomainStatsRecord{Dom: libvirt.Domain{Name: "domain", UUID: uuidBytes, ID: 7}, Params: params},
			meta, nil, nil, agg, 0, false, false,
		)
		return agg.metrics
	}

	fresh := collect(true)
	if !dataIntegrityHasMetricFamily(fresh, "oie_instance_resource_severity") || !dataIntegrityHasMetricFamily(fresh, "oie_instance_attention_severity") {
		t.Fatal("fresh resource input did not emit resource and attention severity")
	}
	retained := collect(false)
	if !dataIntegrityHasMetricFamily(retained, "oie_instance_resource_severity") {
		t.Fatal("retained resource severity was not preserved")
	}
	if dataIntegrityHasMetricFamily(retained, "oie_instance_attention_severity") {
		t.Fatal("retained resource input remained trustworthy for attention")
	}
}
