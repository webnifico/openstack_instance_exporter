package main

import (
	"sort"
	"strings"
	"time"
)

const (
	resourceAxisStateUnavailable = iota
	resourceAxisStateRetained
	resourceAxisStateFresh
)

const resourceAxisPrimarySource = "primary"

// Resource state tracks measurement identity and freshness, independently of values.
type resourceAxisV2 struct {
	Initialized   bool
	LastSuccess   time.Time
	Missing       bool
	Identity      string
	Sources       []string
	LastStateCode int
}
type resourceV2State struct {
	Cpu             resourceAxisV2
	Mem             resourceAxisV2
	Disk            resourceAxisV2
	Net             resourceAxisV2
	NeedsRebaseline bool
}
type resourceAxisResult struct {
	Available        bool
	Fresh            bool
	Retained         bool
	Recovery         bool
	StructuralChange bool
	State            int
	LastSuccess      time.Time
	AgeSeconds       float64
}
type resourceV2Input struct {
	Now               time.Time
	CpuAvailable      bool
	CpuSources        []string
	CpuIdentity       string
	CpuIdentityKnown  bool
	MemAvailable      bool
	MemSources        []string
	MemIdentity       string
	MemIdentityKnown  bool
	DiskAvailable     bool
	DiskSources       []string
	DiskIdentity      string
	DiskIdentityKnown bool
	NetAvailable      bool
	NetSources        []string
	NetIdentity       string
	NetIdentityKnown  bool
}
type resourceV2Output struct {
	Available        bool
	Fresh            bool
	Retained         bool
	Recovery         bool
	StructuralChange bool
	CPU              resourceAxisResult
	MEM              resourceAxisResult
	DISK             resourceAxisResult
	NET              resourceAxisResult
}

func resourceAxisPolicyInterval(collectionInterval time.Duration) time.Duration {
	if collectionInterval <= 0 {
		return 15 * time.Second
	}
	return collectionInterval
}

func resourceAxisScaledDuration(collectionInterval time.Duration, multiplier int64) time.Duration {
	interval := resourceAxisPolicyInterval(collectionInterval)
	const maxDuration = time.Duration(1<<63 - 1)
	if multiplier <= 0 {
		return 0
	}
	if interval > maxDuration/time.Duration(multiplier) {
		return maxDuration
	}
	return interval * time.Duration(multiplier)
}

func resourceAxisMissingGracePeriod(collectionInterval time.Duration) time.Duration {
	return resourceAxisScaledDuration(collectionInterval, 2)
}

func resourceAxisMaxRetainedAge(collectionInterval time.Duration) time.Duration {
	return resourceAxisScaledDuration(collectionInterval, 8)
}

func resourceAxisAge(now, lastSuccess time.Time) time.Duration {
	if lastSuccess.IsZero() {
		return -1
	}
	age := now.Sub(lastSuccess)
	if age < 0 {
		return 0
	}
	return age
}

func normalizeResourceAxisIdentity(identity string) string {
	identity = strings.TrimSpace(identity)
	if identity == "" {
		return resourceAxisPrimarySource
	}
	return identity
}

func normalizeResourceAxisSources(sources []string) []string {
	normalized := make([]string, 0, len(sources)+1)
	seen := make(map[string]struct{}, len(sources)+1)
	for _, source := range sources {
		source = strings.TrimSpace(source)
		if source == "" {
			continue
		}
		if _, duplicate := seen[source]; duplicate {
			continue
		}
		seen[source] = struct{}{}
		normalized = append(normalized, source)
	}
	if len(normalized) == 0 {
		normalized = append(normalized, resourceAxisPrimarySource)
	}
	sort.Strings(normalized)
	return normalized
}

func resourceAxisSourceSetsEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func resourceAxisSourcesCovered(required, observed []string) bool {
	if len(required) == 0 {
		return true
	}
	observedIndex := 0
	for _, source := range required {
		for observedIndex < len(observed) && observed[observedIndex] < source {
			observedIndex++
		}
		if observedIndex >= len(observed) || observed[observedIndex] != source {
			return false
		}
		observedIndex++
	}
	return true
}

func (mc *MetricsCollector) getResourceV2State(instanceUUID string) *resourceV2State {
	mc.resourceV2Mu.Lock()
	defer mc.resourceV2Mu.Unlock()
	if mc.resourceV2 == nil {
		mc.resourceV2 = make(map[string]*resourceV2State)
	}
	s, ok := mc.resourceV2[instanceUUID]
	if !ok {
		s = &resourceV2State{}
		mc.resourceV2[instanceUUID] = s
	}
	return s
}

func (mc *MetricsCollector) lookupResourceV2State(instanceUUID string) (*resourceV2State, bool) {
	mc.resourceV2Mu.Lock()
	defer mc.resourceV2Mu.Unlock()
	if mc.resourceV2 == nil {
		return nil, false
	}
	s, ok := mc.resourceV2[instanceUUID]
	return s, ok
}

func (mc *MetricsCollector) resetResourceV2ForTransition(instanceUUID string) {
	if instanceUUID == "" {
		return
	}
	mc.resourceV2Mu.Lock()
	if mc.resourceV2 == nil {
		mc.resourceV2 = make(map[string]*resourceV2State)
	}
	mc.resourceV2[instanceUUID] = &resourceV2State{NeedsRebaseline: true}
	mc.resourceV2Mu.Unlock()
}

func (mc *MetricsCollector) cleanupResourceV2(activeSet map[string]struct{}) {
	mc.resourceV2Mu.Lock()
	defer mc.resourceV2Mu.Unlock()
	if mc.resourceV2 == nil {
		return
	}
	for uuid := range mc.resourceV2 {
		if _, ok := activeSet[uuid]; !ok {
			delete(mc.resourceV2, uuid)
		}
	}
}

func resourceAxisResultFromState(state *resourceAxisV2, now time.Time, maxRetainedAge time.Duration) resourceAxisResult {
	result := resourceAxisResult{
		State:       resourceAxisStateUnavailable,
		LastSuccess: state.LastSuccess,
		AgeSeconds:  -1,
	}
	if state.LastSuccess.IsZero() {
		return result
	}

	age := resourceAxisAge(now, state.LastSuccess)
	result.AgeSeconds = age.Seconds()
	if !state.Initialized || age > maxRetainedAge {
		return result
	}

	result.Available = true
	result.Retained = true
	result.State = resourceAxisStateRetained
	return result
}

func updateResourceAxisState(
	state *resourceAxisV2,
	now time.Time,
	collectionInterval time.Duration,
	available bool,
	sources []string,
	identity string,
	identityKnown bool,
) resourceAxisResult {
	interval := resourceAxisPolicyInterval(collectionInterval)
	grace := resourceAxisMissingGracePeriod(interval)
	maxRetainedAge := resourceAxisMaxRetainedAge(interval)
	age := resourceAxisAge(now, state.LastSuccess)
	expired := state.Initialized && age > maxRetainedAge

	validObservation := available
	var normalizedSources []string
	normalizedIdentity := ""
	if identityKnown || validObservation {
		normalizedIdentity = normalizeResourceAxisIdentity(identity)
	}
	if identityKnown && state.Initialized && state.Identity != normalizedIdentity && !validObservation {
		// An authoritative topology changed while its first comparable rate
		// sample is necessarily unavailable. The old observation belongs to
		// the previous identity and must not be retained as missing telemetry.
		*state = resourceAxisV2{Identity: normalizedIdentity, LastStateCode: resourceAxisStateUnavailable}
		return resourceAxisResult{
			StructuralChange: true,
			State:            resourceAxisStateUnavailable,
			AgeSeconds:       -1,
		}
	}
	structuralChange := false
	coverageMissing := false
	if validObservation {
		normalizedSources = normalizeResourceAxisSources(sources)
		if state.Initialized {
			identityChanged := state.Identity != normalizedIdentity
			if identityChanged {
				structuralChange = true
			} else if !resourceAxisSourcesCovered(state.Sources, normalizedSources) {
				coverageMissing = true
			} else if !resourceAxisSourceSetsEqual(state.Sources, normalizedSources) {
				structuralChange = true
			}
		}
	}

	// A source that was part of the last complete axis observation cannot be
	// converted to zero merely because it disappeared. Retain the complete
	// axis until its maximum age expires; only then may the reduced source set
	// establish a new baseline.
	if coverageMissing && !expired {
		validObservation = false
	}

	if !validObservation {
		state.Missing = true
		result := resourceAxisResultFromState(state, now, maxRetainedAge)
		if state.LastStateCode != resourceAxisStateUnavailable && result.State == resourceAxisStateUnavailable {
			result.StructuralChange = true
		}
		state.LastStateCode = result.State
		return result
	}

	recovery := state.Initialized && age > grace
	if coverageMissing && expired {
		structuralChange = true
	}
	result := resourceAxisResult{
		Available:        true,
		Fresh:            true,
		Recovery:         recovery,
		StructuralChange: structuralChange,
		State:            resourceAxisStateFresh,
		LastSuccess:      now,
		AgeSeconds:       0,
	}
	state.Initialized = true
	state.LastSuccess = now
	state.Missing = false
	state.Identity = normalizedIdentity
	state.Sources = append(state.Sources[:0], normalizedSources...)
	state.LastStateCode = resourceAxisStateFresh

	return result
}

func (mc *MetricsCollector) snapshotResourceV2(instanceUUID string, now time.Time) (resourceV2Output, bool) {
	s, ok := mc.lookupResourceV2State(instanceUUID)
	if !ok || s == nil {
		return resourceV2Output{}, false
	}

	maxRetainedAge := resourceAxisMaxRetainedAge(mc.collectionInterval)
	out := resourceV2Output{
		CPU:  resourceAxisResultFromState(&s.Cpu, now, maxRetainedAge),
		MEM:  resourceAxisResultFromState(&s.Mem, now, maxRetainedAge),
		DISK: resourceAxisResultFromState(&s.Disk, now, maxRetainedAge),
		NET:  resourceAxisResultFromState(&s.Net, now, maxRetainedAge),
	}
	populateResourceFreshness(&out)
	return out, true
}

func (mc *MetricsCollector) markResourceV2Missing(instanceUUID string) {
	mc.resourceV2Mu.Lock()
	defer mc.resourceV2Mu.Unlock()
	if mc.resourceV2 == nil {
		return
	}
	state := mc.resourceV2[instanceUUID]
	if state == nil {
		return
	}
	for _, axis := range []*resourceAxisV2{&state.Cpu, &state.Mem, &state.Disk, &state.Net} {
		if axis.Initialized {
			axis.Missing = true
		}
	}
}

func populateResourceFreshness(out *resourceV2Output) {
	out.Available = out.CPU.Available || out.MEM.Available || out.DISK.Available || out.NET.Available
	out.Retained = out.CPU.Retained || out.MEM.Retained || out.DISK.Retained || out.NET.Retained
	out.Fresh = out.Available && !out.Retained
	out.Recovery = out.CPU.Recovery || out.MEM.Recovery || out.DISK.Recovery || out.NET.Recovery
	out.StructuralChange = out.StructuralChange || out.CPU.StructuralChange || out.MEM.StructuralChange || out.DISK.StructuralChange || out.NET.StructuralChange
}

func (mc *MetricsCollector) computeResourceV2(instanceUUID string, in resourceV2Input) (resourceV2Output, *resourceV2State) {
	s := mc.getResourceV2State(instanceUUID)
	out := resourceV2Output{}
	out.CPU = updateResourceAxisState(&s.Cpu, in.Now, mc.collectionInterval, in.CpuAvailable, in.CpuSources, in.CpuIdentity, in.CpuIdentityKnown)
	out.MEM = updateResourceAxisState(&s.Mem, in.Now, mc.collectionInterval, in.MemAvailable, in.MemSources, in.MemIdentity, in.MemIdentityKnown)
	out.DISK = updateResourceAxisState(&s.Disk, in.Now, mc.collectionInterval, in.DiskAvailable, in.DiskSources, in.DiskIdentity, in.DiskIdentityKnown)
	out.NET = updateResourceAxisState(&s.Net, in.Now, mc.collectionInterval, in.NetAvailable, in.NetSources, in.NetIdentity, in.NetIdentityKnown)
	if s.NeedsRebaseline && (out.CPU.Fresh || out.MEM.Fresh || out.DISK.Fresh || out.NET.Fresh) {
		out.StructuralChange = true
		s.NeedsRebaseline = false
	}
	populateResourceFreshness(&out)
	return out, s
}
