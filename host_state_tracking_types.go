package main

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

type hostAgg struct {
	mu       sync.Mutex
	disks    int
	fixedIPs int
	projects map[string]struct{}
	vcpus    int
	metrics  []prometheus.Metric
}

// -----------------------------------------------------------------------------
// Host CPU State
// -----------------------------------------------------------------------------
type HostCpuState struct {
	prevTotal   float64
	prevIdle    float64
	initialized bool
	mu          sync.Mutex
}
