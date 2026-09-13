package main

import (
	"math"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func resourceTelemetryResourceCollector(interval time.Duration) *MetricsCollector {
	return &MetricsCollector{
		collectionInterval: interval,
		resourceV2:         make(map[string]*resourceV2State),
	}
}

func resourceTelemetryCPUInput(now time.Time, pressure float64) resourceV2Input {
	return resourceV2Input{
		Now:          now,
		CpuAvailable: true,
		CpuPRaw:      pressure,
		CpuConf:      1,
		CpuImpact:    1,
		CpuSources:   []string{"cpu.time"},
		CpuIdentity:  "vcpu-count=2",
	}
}

func TestResourceTelemetryResourceAxisFreshRetainedUnavailableRecoveryLifecycle(t *testing.T) {
	mc := resourceTelemetryResourceCollector(10 * time.Second)
	base := time.Unix(1_700_000_000, 0)

	fresh, _ := mc.computeResourceV2("vm-lifecycle", resourceTelemetryCPUInput(base, 0.8))
	if !fresh.Fresh || fresh.Retained || fresh.CPU.State != resourceAxisStateFresh ||
		!fresh.CPU.Available || fresh.CPU.AgeSeconds != 0 || !fresh.CPU.LastSuccess.Equal(base) {
		t.Fatalf("initial fresh axis state: %+v", fresh.CPU)
	}

	retained, state := mc.computeResourceV2("vm-lifecycle", resourceV2Input{Now: base.Add(10 * time.Second)})
	if retained.Fresh || !retained.Retained || retained.CPU.State != resourceAxisStateRetained ||
		!retained.CPU.Available || retained.CPU.AgeSeconds != 10 {
		t.Fatalf("one missing sample was not retained: %+v", retained.CPU)
	}
	if retained.CPU.EWMA != fresh.CPU.EWMA || state.Cpu.EWMA != fresh.CPU.EWMA {
		t.Fatalf("missing sample advanced EWMA: fresh=%v retained=%v state=%v", fresh.CPU.EWMA, retained.CPU.EWMA, state.Cpu.EWMA)
	}
	if retained.OverallRaw != fresh.OverallRaw || retained.OverallFinal != fresh.OverallFinal {
		t.Fatalf("retained input changed the complete composite: fresh=%+v retained=%+v", fresh, retained)
	}

	nearExpiry, _ := mc.computeResourceV2("vm-lifecycle", resourceV2Input{Now: base.Add(80 * time.Second)})
	if !nearExpiry.CPU.Available || nearExpiry.CPU.State != resourceAxisStateRetained {
		t.Fatalf("axis did not remain retained through the exact max age: %+v", nearExpiry.CPU)
	}

	expired, _ := mc.computeResourceV2("vm-lifecycle", resourceV2Input{Now: base.Add(81 * time.Second)})
	if expired.CPU.Available || expired.CPU.State != resourceAxisStateUnavailable || expired.Available || !expired.StructuralChange {
		t.Fatalf("expired axis remained logically available: %+v", expired)
	}

	recovered, recoveredState := mc.computeResourceV2("vm-lifecycle", resourceTelemetryCPUInput(base.Add(90*time.Second), 0.2))
	if !recovered.CPU.Fresh || !recovered.CPU.Recovery || recovered.CPU.State != resourceAxisStateFresh {
		t.Fatalf("expired axis did not mark recovery: %+v", recovered.CPU)
	}
	if math.Abs(recovered.CPU.EWMA-0.2) > 1e-12 || recovered.CPU.Alpha != 1 || recovered.CPU.Tau != 0 {
		t.Fatalf("expired axis did not reinitialize: %+v", recovered.CPU)
	}
	if recoveredState.OverallHi95Streak != 0 {
		t.Fatalf("recovery advanced persistence: streak=%d", recoveredState.OverallHi95Streak)
	}
}

func TestResourceTelemetryBackwardClockClampsRetainedAxisAgeToZero(t *testing.T) {
	mc := resourceTelemetryResourceCollector(10 * time.Second)
	base := time.Unix(1_700_000_500, 0)
	mc.computeResourceV2("vm-backward-clock", resourceTelemetryCPUInput(base, 0.8))
	out, _ := mc.computeResourceV2("vm-backward-clock", resourceV2Input{Now: base.Add(-time.Minute)})
	if !out.CPU.Retained || !out.CPU.Available || out.CPU.AgeSeconds != 0 || !out.CPU.LastSuccess.Equal(base) {
		t.Fatalf("backward clock produced invalid retained age: %+v", out.CPU)
	}
}

func TestResourceTelemetryNeverSampledAxisMetricsEmitFrozenUnavailableTuple(t *testing.T) {
	mc := newCollectorOrchestrationTestCollector(t)
	metrics := make([]prometheus.Metric, 0, 16)
	appendInstanceResourceAxisHealthMetrics(mc, &metrics, resourceV2Output{}, "domain", "server", "uuid", "project", "project-name", "user")
	if len(metrics) != 16 {
		t.Fatalf("initial lifecycle metrics=%d want 16", len(metrics))
	}
	want := []float64{0, 0, 0, -1}
	for axisIndex, axisName := range resourceAxisNames {
		for metricIndex, wantValue := range want {
			var encoded dto.Metric
			if err := metrics[axisIndex*4+metricIndex].Write(&encoded); err != nil {
				t.Fatal(err)
			}
			if got := encoded.GetGauge().GetValue(); got != wantValue {
				t.Fatalf("never-sampled axis=%s metric-index=%d value=%v want=%v", axisName, metricIndex, got, wantValue)
			}
		}
	}
}

func TestResourceTelemetryShortAxisRecoveryUsesOneNormalInterval(t *testing.T) {
	mc := resourceTelemetryResourceCollector(10 * time.Second)
	base := time.Unix(1_700_001_000, 0)
	mc.computeResourceV2("vm-short-gap", resourceTelemetryCPUInput(base, 1))
	mc.computeResourceV2("vm-short-gap", resourceV2Input{Now: base.Add(10 * time.Second)})

	recovered, _ := mc.computeResourceV2("vm-short-gap", resourceTelemetryCPUInput(base.Add(20*time.Second), 0))
	wantAlpha := ewmaAlpha(10, 120)
	wantEWMA := 1 - wantAlpha
	if recovered.CPU.Recovery || recovered.CPU.Retained || !recovered.CPU.Fresh {
		t.Fatalf("short recovery was not a normal fresh update: %+v", recovered.CPU)
	}
	if math.Abs(recovered.CPU.Alpha-wantAlpha) > 1e-12 || math.Abs(recovered.CPU.EWMA-wantEWMA) > 1e-12 {
		t.Fatalf("short recovery used outage wall time: got alpha=%v ewma=%v want alpha=%v ewma=%v", recovered.CPU.Alpha, recovered.CPU.EWMA, wantAlpha, wantEWMA)
	}
}

func TestResourceTelemetryRecoveryAfterGraceReinitializesBeforeMaximumAge(t *testing.T) {
	mc := resourceTelemetryResourceCollector(10 * time.Second)
	base := time.Unix(1_700_002_000, 0)
	mc.computeResourceV2("vm-grace", resourceTelemetryCPUInput(base, 1))
	mc.computeResourceV2("vm-grace", resourceV2Input{Now: base.Add(10 * time.Second)})

	recovered, _ := mc.computeResourceV2("vm-grace", resourceTelemetryCPUInput(base.Add(21*time.Second), 0))
	if !recovered.CPU.Recovery || recovered.CPU.Alpha != 1 || recovered.CPU.EWMA != 0 {
		t.Fatalf("post-grace recovery did not silently reinitialize: %+v", recovered.CPU)
	}
}

func TestResourceTelemetryNonFiniteAxisObservationsAreMissing(t *testing.T) {
	mc := resourceTelemetryResourceCollector(10 * time.Second)
	base := time.Unix(1_700_003_000, 0)
	initial, _ := mc.computeResourceV2("vm-non-finite", resourceTelemetryCPUInput(base, 0.7))

	invalid := []resourceV2Input{
		{Now: base.Add(10 * time.Second), CpuAvailable: true, CpuPRaw: math.NaN(), CpuConf: 1, CpuImpact: 1},
		{Now: base.Add(20 * time.Second), CpuAvailable: true, CpuPRaw: 1, CpuConf: math.Inf(1), CpuImpact: 1},
		{Now: base.Add(30 * time.Second), CpuAvailable: true, CpuPRaw: 1, CpuConf: 1, CpuImpact: math.Inf(-1)},
	}
	for index, input := range invalid {
		out, _ := mc.computeResourceV2("vm-non-finite", input)
		if out.CPU.State != resourceAxisStateRetained || !out.CPU.Retained || out.CPU.EWMA != initial.CPU.EWMA {
			t.Fatalf("non-finite observation %d was accepted: %+v", index, out.CPU)
		}
		for _, value := range []float64{out.CPU.PRaw, out.CPU.Conf, out.CPU.Impact, out.CPU.PEff, out.CPU.EWMA, out.CPU.Sev} {
			if math.IsNaN(value) || math.IsInf(value, 0) {
				t.Fatalf("non-finite observation %d escaped into output: %+v", index, out.CPU)
			}
		}
	}
}

func TestResourceTelemetryPreviouslySeenMissingSubsourceRetainsUntilExpiry(t *testing.T) {
	mc := resourceTelemetryResourceCollector(10 * time.Second)
	base := time.Unix(1_700_004_000, 0)
	full := resourceV2Input{
		Now:          base,
		MemAvailable: true, MemPRaw: 1, MemConf: 1, MemImpact: 1,
		MemSources:  []string{"guest-used", "major-fault", "swap-in"},
		MemIdentity: "memory-v1",
	}
	initial, _ := mc.computeResourceV2("vm-coverage", full)

	partial := full
	partial.Now = base.Add(10 * time.Second)
	partial.MemPRaw = 0
	partial.MemSources = []string{"guest-used", "major-fault"}
	retained, _ := mc.computeResourceV2("vm-coverage", partial)
	if retained.MEM.State != resourceAxisStateRetained || retained.MEM.EWMA != initial.MEM.EWMA {
		t.Fatalf("missing subsource was converted into a reduced fresh observation: %+v", retained.MEM)
	}

	partial.Now = base.Add(81 * time.Second)
	recovered, state := mc.computeResourceV2("vm-coverage", partial)
	if !recovered.MEM.Fresh || !recovered.MEM.Recovery || !recovered.MEM.StructuralChange || recovered.MEM.EWMA != 0 {
		t.Fatalf("expired subsource coverage did not establish a new baseline: %+v", recovered.MEM)
	}
	if len(state.Mem.Sources) != 2 || state.Mem.Sources[0] != "guest-used" || state.Mem.Sources[1] != "major-fault" {
		t.Fatalf("new source coverage was not committed: %v", state.Mem.Sources)
	}

	changedIdentity := partial
	changedIdentity.Now = base.Add(91 * time.Second)
	changedIdentity.MemPRaw = 0.5
	changedIdentity.MemIdentity = "memory-v2"
	identityOut, _ := mc.computeResourceV2("vm-coverage", changedIdentity)
	if !identityOut.MEM.StructuralChange || identityOut.MEM.Recovery || identityOut.MEM.Alpha != 1 || identityOut.MEM.EWMA != 0.5 {
		t.Fatalf("identity change was not an immediate structural rebaseline: %+v", identityOut.MEM)
	}
}

func TestResourceTelemetryMonotoneCompositeCannotDiluteOrInflateOnAxisRemoval(t *testing.T) {
	cpu := resourceAxisResult{Available: true, Sev: 60}
	mem := resourceAxisResult{Available: true, Sev: 40}
	disk := resourceAxisResult{Available: true, Sev: 30}

	single := resourceV2MonotoneComposite(cpu, resourceAxisResult{}, resourceAxisResult{}, resourceAxisResult{})
	withMemory := resourceV2MonotoneComposite(cpu, mem, resourceAxisResult{}, resourceAxisResult{})
	withMemoryAndDisk := resourceV2MonotoneComposite(cpu, mem, disk, resourceAxisResult{})
	removedAgain := resourceV2MonotoneComposite(cpu, resourceAxisResult{}, resourceAxisResult{}, resourceAxisResult{})
	if single != 60 {
		t.Fatalf("single axis was diluted: got %v want 60", single)
	}
	if withMemory < single || withMemoryAndDisk < withMemory {
		t.Fatalf("adding available evidence reduced severity: single=%v memory=%v disk=%v", single, withMemory, withMemoryAndDisk)
	}
	if removedAgain != single || removedAgain > withMemoryAndDisk {
		t.Fatalf("removing axes inflated severity: single=%v all=%v removed=%v", single, withMemoryAndDisk, removedAgain)
	}
	if got := resourceV2MonotoneComposite(resourceAxisResult{}, resourceAxisResult{}, resourceAxisResult{}, resourceAxisResult{}); got != 0 {
		t.Fatalf("unavailable composite=%v want 0", got)
	}
}

func TestResourceTelemetryMonotoneCompositeAcrossEveryTopAxisCrossover(t *testing.T) {
	axisNames := []string{"cpu", "mem", "disk", "net"}
	for varied := range axisNames {
		t.Run(axisNames[varied], func(t *testing.T) {
			severities := [4]float64{60, 59, 61, 58}
			previous := -1.0
			for step := 0; step <= 400; step++ {
				severities[varied] = float64(step) / 4
				axes := [4]resourceAxisResult{}
				for index := range axes {
					axes[index] = resourceAxisResult{Available: true, Sev: severities[index]}
				}
				got := resourceV2MonotoneComposite(axes[0], axes[1], axes[2], axes[3])
				if got+1e-12 < previous {
					t.Fatalf("increasing %s to %.2f lowered composite: previous=%v current=%v severities=%v", axisNames[varied], severities[varied], previous, got, severities)
				}
				previous = got
			}
		})
	}
}

func TestResourceTelemetryCompositeFormulaAndFrozenAxisWeights(t *testing.T) {
	axis := func(severity float64) resourceAxisResult {
		return resourceAxisResult{Available: true, Sev: severity}
	}
	tests := []struct {
		name                string
		cpu, mem, disk, net resourceAxisResult
		want                float64
	}{
		{
			name: "cpu_disk_unequal_weights",
			cpu:  axis(60), disk: axis(50),
			want: 66,
		},
		{
			name: "memory_network_unequal_weights",
			mem:  axis(40), net: axis(80),
			want: 82,
		},
		{
			name: "three_axes",
			cpu:  axis(20), mem: axis(40), disk: axis(60),
			want: 65.8,
		},
		{
			name: "four_axes_network_baseline",
			cpu:  axis(60), mem: axis(70), disk: axis(50), net: axis(80),
			want: 88.07875,
		},
		{
			name: "disk_network_crossover",
			disk: axis(80), net: axis(79),
			// net candidate: 1 - (1-.79)*(1-.30*.80)
			want: 84.04,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := resourceV2MonotoneComposite(test.cpu, test.mem, test.disk, test.net)
			if math.Abs(got-test.want) > 1e-9 {
				t.Fatalf("composite=%0.12f want %0.12f", got, test.want)
			}
		})
	}
}

func TestResourceTelemetryRetainedAxisFreezesCompositeAndPersistence(t *testing.T) {
	mc := resourceTelemetryResourceCollector(10 * time.Second)
	base := time.Unix(1_700_005_000, 0)
	input := resourceTelemetryCPUInput(base, 1)
	input.MemAvailable = true
	input.MemPRaw = 0.5
	input.MemConf = 1
	input.MemImpact = 1
	input.MemSources = []string{"guest-used"}
	input.MemIdentity = "memory-v1"
	first, state := mc.computeResourceV2("vm-freeze", input)
	if state.OverallHi95Streak != 1 {
		t.Fatalf("initial persistence streak=%d want 1", state.OverallHi95Streak)
	}

	input.Now = base.Add(10 * time.Second)
	input.CpuAvailable = false
	input.MemPRaw = 1
	retained, state := mc.computeResourceV2("vm-freeze", input)
	if !retained.Retained || retained.Fresh || state.OverallHi95Streak != 1 {
		t.Fatalf("retained composite advanced persistence: out=%+v streak=%d", retained, state.OverallHi95Streak)
	}
	if retained.OverallRaw != first.OverallRaw || retained.OverallFinal != first.OverallFinal || retained.TopAxis != first.TopAxis {
		t.Fatalf("unrelated fresh axis changed retained composite: first=%+v retained=%+v", first, retained)
	}

	input.Now = base.Add(20 * time.Second)
	input.CpuAvailable = true
	secondFresh, state := mc.computeResourceV2("vm-freeze", input)
	if !secondFresh.Fresh || secondFresh.PersistenceTriggered || state.OverallHi95Streak != 2 {
		t.Fatalf("short recovery did not resume persistence once: out=%+v streak=%d", secondFresh, state.OverallHi95Streak)
	}

	input.Now = base.Add(30 * time.Second)
	thirdFresh, state := mc.computeResourceV2("vm-freeze", input)
	if !thirdFresh.PersistenceTriggered || state.OverallHi95Streak != 3 {
		t.Fatalf("third complete qualifying collection did not trigger persistence: out=%+v streak=%d", thirdFresh, state.OverallHi95Streak)
	}

	input.Now = base.Add(40 * time.Second)
	input.CpuIdentity = "vcpu-count=4"
	input.MemAvailable = false
	structural, state := mc.computeResourceV2("vm-freeze", input)
	if !structural.Retained || !structural.StructuralChange || structural.PersistenceTriggered || state.OverallHi95Streak != 0 {
		t.Fatalf("structural rebaseline did not reset persistence: out=%+v streak=%d", structural, state.OverallHi95Streak)
	}
}

func TestResourceTelemetryCachedMembershipChangeCannotReuseOldPersistenceCap(t *testing.T) {
	mc := resourceTelemetryResourceCollector(10 * time.Second)
	base := time.Unix(1_700_005_500, 0)
	state := mc.getResourceV2State("vm-cached-cap")
	state.Cpu = resourceAxisV2{
		Initialized: true,
		EWMA:        1,
		PRaw:        1,
		Conf:        1,
		Impact:      1,
		LastSuccess: base,
	}
	state.Mem = resourceAxisV2{
		Initialized: true,
		EWMA:        1,
		PRaw:        1,
		Conf:        1,
		Impact:      1,
		LastSuccess: base.Add(70 * time.Second),
	}
	state.Composite = resourceV2CompositeState{
		Initialized:   true,
		AvailableMask: 0b0011,
		OverallRaw:    100,
		OverallFinal:  100,
		AxesGE90:      2,
		TopAxis:       "cpu",
	}
	state.OverallHi95Streak = 3

	snapshot, ok := mc.snapshotResourceV2("vm-cached-cap", base.Add(81*time.Second))
	if !ok || !snapshot.StructuralChange || snapshot.CPU.Available || !snapshot.MEM.Available {
		t.Fatalf("staggered cached expiry did not change membership: %+v", snapshot)
	}
	if snapshot.OverallRaw != 100 || snapshot.OverallFinal != 95 || !snapshot.CapActive || snapshot.AxesGE90 != 1 {
		t.Fatalf("cached structural expiry reused old persistence cap: %+v", snapshot)
	}
	if state.OverallHi95Streak != 3 {
		t.Fatalf("read-only cached snapshot mutated stored streak: %d", state.OverallHi95Streak)
	}
}

func TestResourceTelemetryRuntimeTransitionMakesFirstFreshCycleStructural(t *testing.T) {
	mc := resourceTelemetryResourceCollector(10 * time.Second)
	base := time.Unix(1_700_005_800, 0)
	old, oldState := mc.computeResourceV2("vm-runtime-transition", resourceTelemetryCPUInput(base, 1))
	if !old.Fresh || oldState.OverallHi95Streak != 1 {
		t.Fatalf("old runtime fixture was not established: out=%+v state=%+v", old, oldState)
	}

	mc.resetResourceV2ForTransition("vm-runtime-transition")
	baseline, state := mc.computeResourceV2("vm-runtime-transition", resourceV2Input{
		Now:              base.Add(10 * time.Second),
		MemAvailable:     true,
		MemPRaw:          1,
		MemConf:          1,
		MemImpact:        1,
		MemSources:       []string{"guest_used"},
		MemIdentity:      "memory:8192",
		MemIdentityKnown: true,
	})
	if !baseline.Fresh || !baseline.StructuralChange || state.NeedsRebaseline {
		t.Fatalf("first new-runtime sample was not a consumed structural baseline: out=%+v state=%+v", baseline, state)
	}
	if state.OverallHi95Streak != 0 || baseline.PersistenceTriggered {
		t.Fatalf("new-runtime baseline inherited/advanced persistence: out=%+v state=%+v", baseline, state)
	}

	next, state := mc.computeResourceV2("vm-runtime-transition", resourceV2Input{
		Now:              base.Add(20 * time.Second),
		MemAvailable:     true,
		MemPRaw:          1,
		MemConf:          1,
		MemImpact:        1,
		MemSources:       []string{"guest_used"},
		MemIdentity:      "memory:8192",
		MemIdentityKnown: true,
	})
	if next.StructuralChange || !next.Fresh || state.OverallHi95Streak != 1 {
		t.Fatalf("post-transition comparable cycle did not resume normally: out=%+v state=%+v", next, state)
	}
}

func TestResourceTelemetrySnapshotAgesWithoutMutatingState(t *testing.T) {
	mc := resourceTelemetryResourceCollector(10 * time.Second)
	base := time.Unix(1_700_006_000, 0)
	fresh, state := mc.computeResourceV2("vm-snapshot", resourceTelemetryCPUInput(base, 0.9))
	wantEWMA := state.Cpu.EWMA
	wantLastSuccess := state.Cpu.LastSuccess
	wantStreak := state.OverallHi95Streak
	wantLastState := state.Cpu.LastStateCode

	retained, ok := mc.snapshotResourceV2("vm-snapshot", base.Add(10*time.Second))
	if !ok || !retained.Retained || retained.CPU.State != resourceAxisStateRetained || retained.CPU.AgeSeconds != 10 {
		t.Fatalf("snapshot did not derive retained state: ok=%v out=%+v", ok, retained)
	}
	if retained.OverallRaw != fresh.OverallRaw || retained.OverallFinal != fresh.OverallFinal {
		t.Fatalf("snapshot changed complete composite: fresh=%+v retained=%+v", fresh, retained)
	}
	if state.Cpu.EWMA != wantEWMA || !state.Cpu.LastSuccess.Equal(wantLastSuccess) ||
		state.OverallHi95Streak != wantStreak || state.Cpu.LastStateCode != wantLastState {
		t.Fatalf("snapshot mutated state: %+v", state)
	}

	expired, ok := mc.snapshotResourceV2("vm-snapshot", base.Add(81*time.Second))
	if !ok || expired.CPU.Available || expired.Available {
		t.Fatalf("snapshot did not expire old axis: ok=%v out=%+v", ok, expired)
	}
	if _, ok := mc.snapshotResourceV2("unknown", base); ok {
		t.Fatal("snapshot created state for an unknown instance")
	}
}

func TestResourceTelemetryResetResourceV2DeletesRuntimeGenerationState(t *testing.T) {
	mc := resourceTelemetryResourceCollector(10 * time.Second)
	mc.computeResourceV2("vm-reset", resourceTelemetryCPUInput(time.Unix(1_700_007_000, 0), 1))
	mc.resetResourceV2("vm-reset")
	if _, ok := mc.lookupResourceV2State("vm-reset"); ok {
		t.Fatal("resource runtime-generation state survived reset")
	}
	mc.resetResourceV2("vm-reset")
}

func TestResourceTelemetryResourceAxisPolicyUsesConfiguredAndDefaultIntervals(t *testing.T) {
	if got := resourceAxisMissingGracePeriod(10 * time.Second); got != 20*time.Second {
		t.Fatalf("grace=%v want 20s", got)
	}
	if got := resourceAxisMaxRetainedAge(10 * time.Second); got != 80*time.Second {
		t.Fatalf("max retained=%v want 80s", got)
	}
	if got := resourceAxisMissingGracePeriod(0); got != 30*time.Second {
		t.Fatalf("default grace=%v want 30s", got)
	}
	if got := resourceAxisMaxRetainedAge(0); got != 120*time.Second {
		t.Fatalf("default max retained=%v want 120s", got)
	}
}

func TestResourceTelemetryAxisStructuredFreshnessFields(t *testing.T) {
	lastSuccess := time.Unix(1_700_008_000, 0)
	axis := resourceAxisResult{
		Available:   true,
		Retained:    true,
		State:       resourceAxisStateRetained,
		LastSuccess: lastSuccess,
		AgeSeconds:  12.5,
	}
	fields := make([]any, 0, 24)
	appendAxisFieldsV2(&fields, "cpu", axis)
	if len(fields) != 24 {
		t.Fatalf("structured axis field slots=%d want 24", len(fields))
	}
	values := make(map[string]any, len(fields)/2)
	for index := 0; index < len(fields); index += 2 {
		key, ok := fields[index].(string)
		if !ok {
			t.Fatalf("structured key %d has type %T", index, fields[index])
		}
		values[key] = fields[index+1]
	}
	if values["cpu_fresh"] != false || values["cpu_available"] != true ||
		values["cpu_last_success_timestamp_seconds"] != float64(lastSuccess.Unix()) ||
		values["cpu_stale_seconds"] != 12.5 {
		t.Fatalf("structured freshness fields=%v", values)
	}
}
