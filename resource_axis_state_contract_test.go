package main

import (
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

func resourceTelemetryCPUInput(now time.Time) resourceV2Input {
	return resourceV2Input{
		Now:          now,
		CpuAvailable: true,

		CpuSources:  []string{"cpu.time"},
		CpuIdentity: "vcpu-count=2",
	}
}

func TestResourceTelemetryResourceAxisFreshRetainedUnavailableRecoveryLifecycle(t *testing.T) {
	mc := resourceTelemetryResourceCollector(10 * time.Second)
	base := time.Unix(1_700_000_000, 0)

	fresh, _ := mc.computeResourceV2("vm-lifecycle", resourceTelemetryCPUInput(base))
	if !fresh.Fresh || fresh.Retained || fresh.CPU.State != resourceAxisStateFresh ||
		!fresh.CPU.Available || fresh.CPU.AgeSeconds != 0 || !fresh.CPU.LastSuccess.Equal(base) {
		t.Fatalf("initial fresh axis state: %+v", fresh.CPU)
	}

	retained, _ := mc.computeResourceV2("vm-lifecycle", resourceV2Input{Now: base.Add(10 * time.Second)})
	if retained.Fresh || !retained.Retained || retained.CPU.State != resourceAxisStateRetained ||
		!retained.CPU.Available || retained.CPU.AgeSeconds != 10 {
		t.Fatalf("one missing sample was not retained: %+v", retained.CPU)
	}

	nearExpiry, _ := mc.computeResourceV2("vm-lifecycle", resourceV2Input{Now: base.Add(80 * time.Second)})
	if !nearExpiry.CPU.Available || nearExpiry.CPU.State != resourceAxisStateRetained {
		t.Fatalf("axis did not remain retained through the exact max age: %+v", nearExpiry.CPU)
	}

	expired, _ := mc.computeResourceV2("vm-lifecycle", resourceV2Input{Now: base.Add(81 * time.Second)})
	if expired.CPU.Available || expired.CPU.State != resourceAxisStateUnavailable || expired.Available || !expired.StructuralChange {
		t.Fatalf("expired axis remained logically available: %+v", expired)
	}

	recovered, _ := mc.computeResourceV2("vm-lifecycle", resourceTelemetryCPUInput(base.Add(90*time.Second)))
	if !recovered.CPU.Fresh || !recovered.CPU.Recovery || recovered.CPU.State != resourceAxisStateFresh {
		t.Fatalf("expired axis did not mark recovery: %+v", recovered.CPU)
	}

}

func TestResourceTelemetryBackwardClockClampsRetainedAxisAgeToZero(t *testing.T) {
	mc := resourceTelemetryResourceCollector(10 * time.Second)
	base := time.Unix(1_700_000_500, 0)
	mc.computeResourceV2("vm-backward-clock", resourceTelemetryCPUInput(base))
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
	mc.computeResourceV2("vm-short-gap", resourceTelemetryCPUInput(base))
	mc.computeResourceV2("vm-short-gap", resourceV2Input{Now: base.Add(10 * time.Second)})

	recovered, _ := mc.computeResourceV2("vm-short-gap", resourceTelemetryCPUInput(base.Add(20*time.Second)))
	if recovered.CPU.Recovery || recovered.CPU.Retained || !recovered.CPU.Fresh {
		t.Fatalf("short recovery was not a normal fresh update: %+v", recovered.CPU)
	}

}

func TestResourceTelemetryRecoveryAfterGraceReinitializesBeforeMaximumAge(t *testing.T) {
	mc := resourceTelemetryResourceCollector(10 * time.Second)
	base := time.Unix(1_700_002_000, 0)
	mc.computeResourceV2("vm-grace", resourceTelemetryCPUInput(base))
	mc.computeResourceV2("vm-grace", resourceV2Input{Now: base.Add(10 * time.Second)})

	recovered, _ := mc.computeResourceV2("vm-grace", resourceTelemetryCPUInput(base.Add(21*time.Second)))
	if !recovered.CPU.Recovery {
		t.Fatalf("post-grace recovery did not silently reinitialize: %+v", recovered.CPU)
	}
}

func TestResourceTelemetryPreviouslySeenMissingSubsourceRetainsUntilExpiry(t *testing.T) {
	mc := resourceTelemetryResourceCollector(10 * time.Second)
	base := time.Unix(1_700_004_000, 0)
	full := resourceV2Input{
		Now:          base,
		MemAvailable: true,
		MemSources:   []string{"guest-used", "major-fault", "swap-in"},
		MemIdentity:  "memory-v1",
	}
	_, _ = mc.computeResourceV2("vm-coverage", full)

	partial := full
	partial.Now = base.Add(10 * time.Second)

	partial.MemSources = []string{"guest-used", "major-fault"}
	retained, _ := mc.computeResourceV2("vm-coverage", partial)
	if retained.MEM.State != resourceAxisStateRetained {
		t.Fatalf("missing subsource was converted into a reduced fresh observation: %+v", retained.MEM)
	}

	partial.Now = base.Add(81 * time.Second)
	recovered, state := mc.computeResourceV2("vm-coverage", partial)
	if !recovered.MEM.Fresh || !recovered.MEM.Recovery || !recovered.MEM.StructuralChange {
		t.Fatalf("expired subsource coverage did not establish a new baseline: %+v", recovered.MEM)
	}
	if len(state.Mem.Sources) != 2 || state.Mem.Sources[0] != "guest-used" || state.Mem.Sources[1] != "major-fault" {
		t.Fatalf("new source coverage was not committed: %v", state.Mem.Sources)
	}

	changedIdentity := partial
	changedIdentity.Now = base.Add(91 * time.Second)

	changedIdentity.MemIdentity = "memory-v2"
	identityOut, _ := mc.computeResourceV2("vm-coverage", changedIdentity)
	if !identityOut.MEM.StructuralChange || identityOut.MEM.Recovery {
		t.Fatalf("identity change was not an immediate structural rebaseline: %+v", identityOut.MEM)
	}
}

func TestResourceTelemetryRuntimeTransitionMakesFirstFreshCycleStructural(t *testing.T) {
	mc := resourceTelemetryResourceCollector(10 * time.Second)
	base := time.Unix(1_700_005_800, 0)
	old, oldState := mc.computeResourceV2("vm-runtime-transition", resourceTelemetryCPUInput(base))
	if !old.Fresh {
		t.Fatalf("old runtime fixture was not established: out=%+v state=%+v", old, oldState)
	}

	mc.resetResourceV2ForTransition("vm-runtime-transition")
	baseline, state := mc.computeResourceV2("vm-runtime-transition", resourceV2Input{
		Now:          base.Add(10 * time.Second),
		MemAvailable: true,

		MemSources:       []string{"guest_used"},
		MemIdentity:      "memory:8192",
		MemIdentityKnown: true,
	})
	if !baseline.Fresh || !baseline.StructuralChange || state.NeedsRebaseline {
		t.Fatalf("first new-runtime sample was not a consumed structural baseline: out=%+v state=%+v", baseline, state)
	}

	next, state := mc.computeResourceV2("vm-runtime-transition", resourceV2Input{
		Now:          base.Add(20 * time.Second),
		MemAvailable: true,

		MemSources:       []string{"guest_used"},
		MemIdentity:      "memory:8192",
		MemIdentityKnown: true,
	})
	if next.StructuralChange || !next.Fresh {
		t.Fatalf("post-transition comparable cycle did not resume normally: out=%+v state=%+v", next, state)
	}
}

func TestResourceTelemetrySnapshotAgesWithoutMutatingState(t *testing.T) {
	mc := resourceTelemetryResourceCollector(10 * time.Second)
	base := time.Unix(1_700_006_000, 0)
	_, state := mc.computeResourceV2("vm-snapshot", resourceTelemetryCPUInput(base))

	wantLastSuccess := state.Cpu.LastSuccess

	wantLastState := state.Cpu.LastStateCode

	retained, ok := mc.snapshotResourceV2("vm-snapshot", base.Add(10*time.Second))
	if !ok || !retained.Retained || retained.CPU.State != resourceAxisStateRetained || retained.CPU.AgeSeconds != 10 {
		t.Fatalf("snapshot did not derive retained state: ok=%v out=%+v", ok, retained)
	}

	if !state.Cpu.LastSuccess.Equal(wantLastSuccess) ||
		state.Cpu.LastStateCode != wantLastState {
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
	mc.computeResourceV2("vm-reset", resourceTelemetryCPUInput(time.Unix(1_700_007_000, 0)))
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
