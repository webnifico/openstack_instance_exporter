package main

import (
	"runtime"
	"testing"
)

func TestEffectiveDomainWorkerCountHonorsConfiguredValueAndCap(t *testing.T) {
	tests := []struct {
		name       string
		configured int
		want       int
	}{
		{name: "configured", configured: 4, want: 4},
		{name: "single worker", configured: 1, want: 1},
		{name: "at cap", configured: maxDomainWorkers, want: maxDomainWorkers},
		{name: "above cap", configured: maxDomainWorkers + 1, want: maxDomainWorkers},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := effectiveDomainWorkerCount(tc.configured); got != tc.want {
				t.Fatalf("effectiveDomainWorkerCount(%d)=%d, want %d", tc.configured, got, tc.want)
			}
		})
	}
}

func TestEffectiveDomainWorkerCountDefaultsToAvailableCPUWithinCap(t *testing.T) {
	want := runtime.NumCPU()
	if want > maxDomainWorkers {
		want = maxDomainWorkers
	}
	for _, configured := range []int{0, -1} {
		if got := effectiveDomainWorkerCount(configured); got != want {
			t.Fatalf("effectiveDomainWorkerCount(%d)=%d, want capped available CPU count %d", configured, got, want)
		}
	}
}
