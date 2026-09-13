package main

import (
	"math"
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

type resourceAxisV2 struct {
	EWMA          float64
	PRaw          float64
	Conf          float64
	Impact        float64
	Initialized   bool
	LastSuccess   time.Time
	Missing       bool
	Identity      string
	Sources       []string
	LastStateCode int
}
type resourceV2State struct {
	LastUpdate        time.Time
	Cpu               resourceAxisV2
	Mem               resourceAxisV2
	Disk              resourceAxisV2
	Net               resourceAxisV2
	Composite         resourceV2CompositeState
	OverallHi95Streak int
	LastBand          int
	LastTopAxis       string
	LastCapActive     bool
	NeedsRebaseline   bool
}

type resourceV2CompositeState struct {
	Initialized   bool
	AvailableMask uint8
	OverallRaw    float64
	OverallFinal  float64
	CapActive     bool
	AxesGE90      int
	TopAxis       string
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
	PRaw             float64
	Conf             float64
	Impact           float64
	PEff             float64
	EWMA             float64
	Sev              float64
	Alpha            float64
	Tau              float64
}
type resourceV2Input struct {
	Now time.Time

	CpuAvailable     bool
	CpuPRaw          float64
	CpuConf          float64
	CpuImpact        float64
	CpuSources       []string
	CpuIdentity      string
	CpuIdentityKnown bool

	MemAvailable     bool
	MemPRaw          float64
	MemConf          float64
	MemImpact        float64
	MemSources       []string
	MemIdentity      string
	MemIdentityKnown bool

	DiskAvailable     bool
	DiskPRaw          float64
	DiskConf          float64
	DiskImpact        float64
	DiskSources       []string
	DiskIdentity      string
	DiskIdentityKnown bool

	NetAvailable     bool
	NetPRaw          float64
	NetConf          float64
	NetImpact        float64
	NetSources       []string
	NetIdentity      string
	NetIdentityKnown bool
}
type resourceV2Output struct {
	Available            bool
	Fresh                bool
	Retained             bool
	Recovery             bool
	StructuralChange     bool
	DtSeconds            float64
	OverallRaw           float64
	OverallFinal         float64
	CapActive            bool
	PersistenceTriggered bool
	AxesGE90             int
	TopAxis              string

	CPU  resourceAxisResult
	MEM  resourceAxisResult
	DISK resourceAxisResult
	NET  resourceAxisResult
}

func attentionSeverityWeighted(scoring SeverityConfig, resourceSeverity float64, resourceActive bool, behaviorScore float64, behaviorActive bool, threatSeverity float64, threatActive bool) float64 {
	maxWeight := 0.0
	if resourceActive && scoring.ResourceWeight > maxWeight {
		maxWeight = scoring.ResourceWeight
	}
	if behaviorActive && scoring.BehaviorWeight > maxWeight {
		maxWeight = scoring.BehaviorWeight
	}
	if threatActive && scoring.ThreatWeight > maxWeight {
		maxWeight = scoring.ThreatWeight
	}
	if maxWeight <= 0 {
		return 0
	}

	totalW := 0.0
	sum := 0.0
	if resourceActive && scoring.ResourceWeight > 0 {
		weight := scoring.ResourceWeight / maxWeight
		totalW += weight
		sum += resourceSeverity * weight
	}
	if behaviorActive && scoring.BehaviorWeight > 0 {
		weight := scoring.BehaviorWeight / maxWeight
		totalW += weight
		sum += behaviorScore * weight
	}
	if threatActive && scoring.ThreatWeight > 0 {
		weight := scoring.ThreatWeight / maxWeight
		totalW += weight
		sum += threatSeverity * weight
	}
	return sum / totalW
}

func attentionInputsAvailable(scoring SeverityConfig, resourceActive, behaviorActive, threatActive bool) bool {
	configured := false
	for _, input := range []struct {
		weight float64
		active bool
	}{
		{weight: scoring.ResourceWeight, active: resourceActive},
		{weight: scoring.BehaviorWeight, active: behaviorActive},
		{weight: scoring.ThreatWeight, active: threatActive},
	} {
		if input.weight <= 0 {
			continue
		}
		configured = true
		if !input.active {
			return false
		}
	}
	return configured
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

func resourceAxisObservationFinite(pRaw, conf, impact float64) bool {
	return !math.IsNaN(pRaw) && !math.IsInf(pRaw, 0) &&
		!math.IsNaN(conf) && !math.IsInf(conf, 0) &&
		!math.IsNaN(impact) && !math.IsInf(impact, 0)
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

func updateAxisV2(a *resourceAxisV2, pEff, dtSeconds, riseTau, fallTau float64) (ewmaOut, alphaOut, tauUsed float64) {
	if !a.Initialized {
		a.EWMA = clamp01(pEff)
		a.Initialized = true
		return a.EWMA, 1, 0
	}
	tauUsed = fallTau
	if pEff > a.EWMA {
		tauUsed = riseTau
	}
	alphaOut = ewmaAlpha(dtSeconds, tauUsed)
	a.EWMA = clamp01(a.EWMA + alphaOut*(pEff-a.EWMA))
	return a.EWMA, alphaOut, tauUsed
}
func axisSeverityV2(ewma, scale, power, impact float64) float64 {
	x := clamp01(ewma * scale)
	if power > 0 {
		x = math.Pow(x, power)
	}
	return clamp01(x) * 100.0 * clamp01(impact)
}
func lpBlend(p float64, cpu, mem, disk, net float64, wCPU, wMem, wDisk, wNet float64) float64 {
	if p <= 0 {
		p = 3
	}
	sumW := wCPU + wMem + wDisk + wNet
	if sumW <= 0 {
		return 0
	}
	f := func(x float64) float64 {
		return math.Pow(clamp01(x/100.0), p)
	}
	s := wCPU*f(cpu) + wMem*f(mem) + wDisk*f(disk) + wNet*f(net)
	s = s / sumW
	return clamp01(math.Pow(s, 1.0/p)) * 100.0
}
func band30_60_85(overall float64) int {
	if overall >= 85 {
		return 85
	}
	if overall >= 60 {
		return 60
	}
	if overall >= 30 {
		return 30
	}
	return 0
}
func countAxesAbove90(cpu, mem, disk, net float64) int {
	n := 0
	if cpu >= 90 {
		n++
	}
	if mem >= 90 {
		n++
	}
	if disk >= 90 {
		n++
	}
	if net >= 90 {
		n++
	}
	return n
}
func topAxisName(cpu, mem, disk, net float64) string {
	top := "cpu"
	val := cpu
	if mem > val {
		top = "mem"
		val = mem
	}
	if disk > val {
		top = "disk"
		val = disk
	}
	if net > val {
		top = "net"
	}
	return top
}

func topAvailableAxisName(cpu, mem, disk, net resourceAxisResult) string {
	top := ""
	value := -1.0
	for _, candidate := range []struct {
		name string
		axis resourceAxisResult
	}{
		{name: "cpu", axis: cpu},
		{name: "mem", axis: mem},
		{name: "disk", axis: disk},
		{name: "net", axis: net},
	} {
		if candidate.axis.Available && candidate.axis.Sev > value {
			top = candidate.name
			value = candidate.axis.Sev
		}
	}
	return top
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

func (mc *MetricsCollector) resetResourceV2(instanceUUID string) {
	mc.resourceV2Mu.Lock()
	if mc.resourceV2 != nil {
		delete(mc.resourceV2, instanceUUID)
	}
	mc.resourceV2Mu.Unlock()
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
	result.PRaw = state.PRaw
	result.Conf = state.Conf
	result.Impact = state.Impact
	result.PEff = clamp01(state.PRaw * state.Conf)
	result.EWMA = state.EWMA
	result.Sev = axisSeverityV2(state.EWMA, 1, 2, state.Impact)
	return result
}

func updateResourceAxisState(
	state *resourceAxisV2,
	now time.Time,
	collectionInterval time.Duration,
	available bool,
	pRaw, conf, impact float64,
	sources []string,
	identity string,
	identityKnown bool,
	riseTau, fallTau float64,
) resourceAxisResult {
	interval := resourceAxisPolicyInterval(collectionInterval)
	grace := resourceAxisMissingGracePeriod(interval)
	maxRetainedAge := resourceAxisMaxRetainedAge(interval)
	age := resourceAxisAge(now, state.LastSuccess)
	expired := state.Initialized && age > maxRetainedAge

	validObservation := available && resourceAxisObservationFinite(pRaw, conf, impact)
	var normalizedSources []string
	normalizedIdentity := ""
	if identityKnown || validObservation {
		normalizedIdentity = normalizeResourceAxisIdentity(identity)
	}
	if identityKnown && state.Initialized && state.Identity != normalizedIdentity && !validObservation {
		// An authoritative topology changed while its first comparable rate
		// sample is necessarily unavailable. The old device pressure belongs to
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
	reinitialize := recovery || structuralChange
	wasInitialized := state.Initialized
	wasMissing := state.Missing
	if reinitialize {
		state.Initialized = false
	}

	result := resourceAxisResult{
		Available:        true,
		Fresh:            true,
		Recovery:         recovery,
		StructuralChange: structuralChange,
		State:            resourceAxisStateFresh,
		LastSuccess:      now,
		AgeSeconds:       0,
		PRaw:             clamp01(pRaw),
		Conf:             clamp01(conf),
		Impact:           clamp01(impact),
	}
	result.PEff = clamp01(result.PRaw * result.Conf)

	axisDT := interval.Seconds()
	if wasInitialized && !wasMissing && !reinitialize {
		if elapsed := now.Sub(state.LastSuccess).Seconds(); elapsed > 0 {
			axisDT = elapsed
		}
	}
	if axisDT <= 0 {
		axisDT = 1
	}

	state.PRaw = result.PRaw
	state.Conf = result.Conf
	state.Impact = result.Impact
	ewma, alpha, tau := updateAxisV2(state, result.PEff, axisDT, riseTau, fallTau)
	state.LastSuccess = now
	state.Missing = false
	state.Identity = normalizedIdentity
	state.Sources = append(state.Sources[:0], normalizedSources...)
	state.LastStateCode = resourceAxisStateFresh

	result.EWMA = ewma
	result.Alpha = alpha
	result.Tau = tau
	result.Sev = axisSeverityV2(ewma, 1, 2, state.Impact)
	return result
}

func resourceV2MonotoneComposite(cpu, mem, disk, net resourceAxisResult) float64 {
	const (
		wCPU  = 0.25
		wMEM  = 0.25
		wDISK = 0.30
		wNET  = 0.20
	)
	candidates := []struct {
		axis   resourceAxisResult
		weight float64
	}{
		{axis: cpu, weight: wCPU},
		{axis: mem, weight: wMEM},
		{axis: disk, weight: wDISK},
		{axis: net, weight: wNET},
	}

	// Evaluate every available axis as the baseline and take the greatest
	// bounded headroom blend. Choosing only the numerically highest axis as the
	// baseline is discontinuous when unequal axis weights cross: increasing an
	// axis can then lower the composite. Every candidate below is independently
	// monotone in every input, so their maximum is monotone too. A single axis
	// remains unchanged and adding evidence can never dilute the score.
	overall := 0.0
	available := false
	for baselineIndex, baseline := range candidates {
		if !baseline.axis.Available {
			continue
		}
		available = true
		baselineSeverity := clamp01(baseline.axis.Sev / 100.0)
		remainingHeadroom := 1.0
		for index, evidence := range candidates {
			if index == baselineIndex || !evidence.axis.Available {
				continue
			}
			remainingHeadroom *= 1.0 - evidence.weight*clamp01(evidence.axis.Sev/100.0)
		}
		candidateScore := 1.0 - (1.0-baselineSeverity)*remainingHeadroom
		if candidateScore > overall {
			overall = candidateScore
		}
	}
	if !available {
		return 0
	}
	return clamp01(overall) * 100.0
}

func countAvailableAxesAbove90(cpu, mem, disk, net resourceAxisResult) int {
	count := 0
	for _, axis := range []resourceAxisResult{cpu, mem, disk, net} {
		if axis.Available && axis.Sev >= 90 {
			count++
		}
	}
	return count
}

func resourceV2AvailabilityMask(cpu, mem, disk, net resourceAxisResult) uint8 {
	var mask uint8
	if cpu.Available {
		mask |= 1 << 0
	}
	if mem.Available {
		mask |= 1 << 1
	}
	if disk.Available {
		mask |= 1 << 2
	}
	if net.Available {
		mask |= 1 << 3
	}
	return mask
}

func storeResourceV2Composite(state *resourceV2State, mask uint8, out resourceV2Output) {
	state.Composite = resourceV2CompositeState{
		Initialized:   true,
		AvailableMask: mask,
		OverallRaw:    out.OverallRaw,
		OverallFinal:  out.OverallFinal,
		CapActive:     out.CapActive,
		AxesGE90:      out.AxesGE90,
		TopAxis:       out.TopAxis,
	}
}

func restoreResourceV2Composite(out *resourceV2Output, composite resourceV2CompositeState) {
	out.OverallRaw = composite.OverallRaw
	out.OverallFinal = composite.OverallFinal
	out.CapActive = composite.CapActive
	out.AxesGE90 = composite.AxesGE90
	out.TopAxis = composite.TopAxis
}

func populateResourceV2Composite(out *resourceV2Output, state *resourceV2State, mutatePersistence, resetPersistence bool) {
	out.Available = out.CPU.Available || out.MEM.Available || out.DISK.Available || out.NET.Available
	out.Retained = out.CPU.Retained || out.MEM.Retained || out.DISK.Retained || out.NET.Retained
	out.Fresh = out.Available && !out.Retained
	out.Recovery = out.CPU.Recovery || out.MEM.Recovery || out.DISK.Recovery || out.NET.Recovery
	out.StructuralChange = out.StructuralChange || out.CPU.StructuralChange || out.MEM.StructuralChange || out.DISK.StructuralChange || out.NET.StructuralChange
	availabilityMask := resourceV2AvailabilityMask(out.CPU, out.MEM, out.DISK, out.NET)
	availabilityChanged := state.Composite.Initialized && state.Composite.AvailableMask != availabilityMask
	if availabilityChanged {
		out.StructuralChange = true
	}

	// A retained input cannot update a dependent score. With the same axis
	// membership, publish the exact last complete composite until every
	// contributing axis is fresh again. Membership changes are structural and
	// are recomputed once, silently, with unavailable axes excluded.
	if out.Retained && state.Composite.Initialized && !availabilityChanged {
		if mutatePersistence && (resetPersistence || out.Recovery || out.StructuralChange) {
			state.OverallHi95Streak = 0
		}
		restoreResourceV2Composite(out, state.Composite)
		return
	}

	out.OverallRaw = resourceV2MonotoneComposite(out.CPU, out.MEM, out.DISK, out.NET)
	out.AxesGE90 = countAvailableAxesAbove90(out.CPU, out.MEM, out.DISK, out.NET)
	out.TopAxis = topAvailableAxisName(out.CPU, out.MEM, out.DISK, out.NET)

	effectiveStreak := state.OverallHi95Streak
	if resetPersistence || out.Recovery || out.StructuralChange {
		effectiveStreak = 0
		if mutatePersistence {
			state.OverallHi95Streak = 0
		}
	} else if mutatePersistence && out.Fresh {
		if out.OverallRaw >= 95 {
			state.OverallHi95Streak++
		} else {
			state.OverallHi95Streak = 0
		}
		effectiveStreak = state.OverallHi95Streak
	}

	allowOver95 := out.AxesGE90 >= 2
	if !allowOver95 && effectiveStreak >= 3 {
		allowOver95 = true
		if mutatePersistence && out.Fresh && !out.Recovery && !out.StructuralChange {
			out.PersistenceTriggered = effectiveStreak == 3
		}
	}

	out.OverallFinal = out.OverallRaw
	if out.OverallRaw > 95 && !allowOver95 {
		out.OverallFinal = 95
		out.CapActive = true
	}
	if mutatePersistence && (out.Available || state.Composite.Initialized) {
		storeResourceV2Composite(state, availabilityMask, *out)
	}
}

func (mc *MetricsCollector) computeResourceV2(instanceUUID string, in resourceV2Input) (resourceV2Output, *resourceV2State) {
	out := resourceV2Output{}
	s := mc.getResourceV2State(instanceUUID)

	now := in.Now
	dt := resourceAxisPolicyInterval(mc.collectionInterval).Seconds()
	if !s.LastUpdate.IsZero() {
		if d := now.Sub(s.LastUpdate).Seconds(); d > 0 {
			dt = d
		}
	}
	if dt <= 0 {
		dt = 1
	}
	const cpuRiseTau = 30.0
	const cpuFallTau = 120.0
	const memRiseTau = 45.0
	const memFallTau = 180.0
	const diskRiseTau = 30.0
	const diskFallTau = 180.0
	const netRiseTau = 30.0
	const netFallTau = 120.0

	out.CPU = updateResourceAxisState(&s.Cpu, now, mc.collectionInterval, in.CpuAvailable, in.CpuPRaw, in.CpuConf, in.CpuImpact, in.CpuSources, in.CpuIdentity, in.CpuIdentityKnown, cpuRiseTau, cpuFallTau)
	out.MEM = updateResourceAxisState(&s.Mem, now, mc.collectionInterval, in.MemAvailable, in.MemPRaw, in.MemConf, in.MemImpact, in.MemSources, in.MemIdentity, in.MemIdentityKnown, memRiseTau, memFallTau)
	out.DISK = updateResourceAxisState(&s.Disk, now, mc.collectionInterval, in.DiskAvailable, in.DiskPRaw, in.DiskConf, in.DiskImpact, in.DiskSources, in.DiskIdentity, in.DiskIdentityKnown, diskRiseTau, diskFallTau)
	out.NET = updateResourceAxisState(&s.Net, now, mc.collectionInterval, in.NetAvailable, in.NetPRaw, in.NetConf, in.NetImpact, in.NetSources, in.NetIdentity, in.NetIdentityKnown, netRiseTau, netFallTau)
	anyFresh := out.CPU.Fresh || out.MEM.Fresh || out.DISK.Fresh || out.NET.Fresh
	if anyFresh {
		s.LastUpdate = now
	}
	if s.NeedsRebaseline && anyFresh {
		out.StructuralChange = true
		s.NeedsRebaseline = false
	}
	out.DtSeconds = dt
	populateResourceV2Composite(&out, s, true, false)

	return out, s
}

func (mc *MetricsCollector) snapshotResourceV2(instanceUUID string, now time.Time) (resourceV2Output, bool) {
	s, ok := mc.lookupResourceV2State(instanceUUID)
	if !ok || s == nil {
		return resourceV2Output{}, false
	}

	maxRetainedAge := resourceAxisMaxRetainedAge(mc.collectionInterval)
	out := resourceV2Output{
		DtSeconds: resourceAxisPolicyInterval(mc.collectionInterval).Seconds(),
		CPU:       resourceAxisResultFromState(&s.Cpu, now, maxRetainedAge),
		MEM:       resourceAxisResultFromState(&s.Mem, now, maxRetainedAge),
		DISK:      resourceAxisResultFromState(&s.Disk, now, maxRetainedAge),
		NET:       resourceAxisResultFromState(&s.Net, now, maxRetainedAge),
	}
	populateResourceV2Composite(&out, s, false, false)
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
func appendAxisFieldsV2(kv *[]any, prefix string, r resourceAxisResult) {
	lastSuccessTimestamp := float64(0)
	if !r.LastSuccess.IsZero() {
		lastSuccessTimestamp = float64(r.LastSuccess.Unix())
	}
	*kv = append(*kv,
		prefix+"_p_raw", roundToFiveDecimals(r.PRaw),
		prefix+"_conf", roundToFiveDecimals(r.Conf),
		prefix+"_impact", roundToFiveDecimals(r.Impact),
		prefix+"_p_eff", roundToFiveDecimals(r.PEff),
		prefix+"_ewma", roundToFiveDecimals(r.EWMA),
		prefix+"_sev", roundToFiveDecimals(r.Sev),
		prefix+"_alpha", roundToFiveDecimals(r.Alpha),
		prefix+"_tau", roundToFiveDecimals(r.Tau),
		prefix+"_fresh", r.Fresh,
		prefix+"_available", r.Available,
		prefix+"_last_success_timestamp_seconds", lastSuccessTimestamp,
		prefix+"_stale_seconds", roundToFiveDecimals(r.AgeSeconds),
	)
}

func syncResourceV2EventState(out resourceV2Output, s *resourceV2State) {
	if s == nil {
		return
	}
	s.LastBand = band30_60_85(out.OverallFinal)
	s.LastTopAxis = out.TopAxis
	s.LastCapActive = out.CapActive
}

func (mc *MetricsCollector) maybeLogResourceV2Event(domain, serverName, instanceUUID, projectUUID, projectName, userUUID string, out resourceV2Output, s *resourceV2State) {
	if s == nil {
		return
	}
	if !out.Fresh || out.Retained || out.Recovery || out.StructuralChange {
		syncResourceV2EventState(out, s)
		return
	}
	band := band30_60_85(out.OverallFinal)
	top := out.TopAxis

	bandChanged := (s.LastBand != band)
	topChanged := (s.LastTopAxis != "" && s.LastTopAxis != top)
	capChanged := (s.LastCapActive != out.CapActive)

	shouldLog := false
	if bandChanged {
		if band >= 30 || s.LastBand >= 30 {
			shouldLog = true
		}
	}
	if topChanged {
		if band >= 30 || s.LastBand >= 30 {
			shouldLog = true
		}
	}
	if capChanged {
		if band >= 30 || s.LastBand >= 30 || out.OverallFinal >= 95 {
			shouldLog = true
		}
	}
	if out.PersistenceTriggered {
		shouldLog = true
	}

	if !shouldLog {
		s.LastBand = band
		s.LastTopAxis = top
		s.LastCapActive = out.CapActive
		return
	}
	if out.OverallFinal >= 30 {
		kv := make([]any, 0, 128)
		kv = append(kv,
			"domain", domain,
			"server_name", serverName,
			"instance_uuid", instanceUUID,
			"project_uuid", projectUUID,
			"project_name", projectName,
			"user_uuid", userUUID,
			"overall_raw", roundToFiveDecimals(out.OverallRaw),
			"overall", roundToFiveDecimals(out.OverallFinal),
			"band", band,
			"cap_active", out.CapActive,
			"hi95_streak", s.OverallHi95Streak,
			"axes_ge90", out.AxesGE90,
			"top_axis", top,
			"dt_seconds", roundToFiveDecimals(out.DtSeconds),
		)
		appendAxisFieldsV2(&kv, "cpu", out.CPU)
		appendAxisFieldsV2(&kv, "mem", out.MEM)
		appendAxisFieldsV2(&kv, "disk", out.DISK)
		appendAxisFieldsV2(&kv, "net", out.NET)
		logKV(LogLevelInfo, "severity", "severity", "resource_v2_event", kv...)
	}
	s.LastBand = band
	s.LastTopAxis = top
	s.LastCapActive = out.CapActive
}
