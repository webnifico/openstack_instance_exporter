package main

import (
	"math"
	"sort"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func combineThreatSignalsUnion(current float64, signal float64) float64 {
	signal = clamp01(signal)
	current = clamp01(current)
	if signal <= 0 {
		return current
	}
	return clamp01(1.0 - (1.0-current)*(1.0-signal))
}

func (mc *MetricsCollector) updateIntelHistory(instanceUUID string, instant float64, observationUnix int64) float64 {
	return mc.updateIntelHistoryWithSourceSet(instanceUUID, instant, observationUnix, "", false)
}

func (mc *MetricsCollector) updateIntelHistoryForSourceSet(instanceUUID string, instant float64, observationUnix int64, sourceSet string) float64 {
	return mc.updateIntelHistoryWithSourceSet(instanceUUID, instant, observationUnix, sourceSet, true)
}

func (mc *MetricsCollector) updateIntelHistoryWithSourceSet(instanceUUID string, instant float64, observationUnix int64, sourceSet string, sourceSetKnown bool) float64 {
	instant = clamp01(instant)
	mc.intelMu.Lock()
	defer mc.intelMu.Unlock()

	if mc.intelHistory == nil {
		mc.intelHistory = make(map[string]*IntelHistory)
	}

	s, ok := mc.intelHistory[instanceUUID]
	if !ok || s == nil || !s.Initialized {
		s = &IntelHistory{
			EWMA:             instant,
			LastInstant:      instant,
			LastUpdateUnix:   observationUnix,
			SourceSet:        sourceSet,
			SourcesAvailable: true,
			SourceSetKnown:   sourceSetKnown,
			Initialized:      true,
		}
		mc.intelHistory[instanceUUID] = s
		return s.EWMA
	}
	if !s.SourcesAvailable {
		s.EWMA = instant
		s.LastInstant = instant
		s.LastUpdateUnix = observationUnix
		s.SourcesAvailable = true
		s.SourceSet = sourceSet
		s.SourceSetKnown = sourceSetKnown
		return s.EWMA
	}
	if sourceSetKnown {
		if s.SourceSetKnown && s.SourceSet != sourceSet {
			s.EWMA = instant
			s.LastInstant = instant
			s.LastUpdateUnix = observationUnix
			s.SourceSet = sourceSet
			return s.EWMA
		}
		s.SourceSet = sourceSet
		s.SourceSetKnown = true
	}

	// A complete snapshot is identified by its shared observation timestamp.
	// Replays are idempotent; a strict clock regression establishes a fresh
	// baseline so history does not remain pinned to an unreachable future.
	if observationUnix == s.LastUpdateUnix {
		return s.EWMA
	}
	if observationUnix < s.LastUpdateUnix {
		s.EWMA = instant
		s.LastInstant = instant
		s.LastUpdateUnix = observationUnix
		return s.EWMA
	}

	tau := mc.threatEWMATau
	if tau <= 0 {
		tau = defaultThreatEWMATau
	}
	dtSeconds := float64(observationUnix) - float64(s.LastUpdateUnix)
	alpha := ewmaAlpha(dtSeconds, tau.Seconds())
	s.EWMA = clamp01(s.EWMA + alpha*(instant-s.EWMA))
	s.LastInstant = instant
	s.LastUpdateUnix = observationUnix
	return s.EWMA
}

func threatSourceSetFingerprint(connAgg *ConntrackAgg) string {
	if connAgg == nil {
		return ""
	}
	parts := make([]string, 0, len(connAgg.ProviderSourcesIncluded)+1)
	if connAgg.SpamhausSourceIncluded {
		parts = append(parts, "spamhaus")
	}
	for provider := range connAgg.ProviderSourcesIncluded {
		parts = append(parts, provider)
	}
	sort.Strings(parts)
	return strings.Join(parts, "\x00")
}

func shiftIntelTimestamp(timestamp, deltaSeconds int64) int64 {
	if deltaSeconds > 0 && timestamp > math.MaxInt64-deltaSeconds {
		return math.MaxInt64
	}
	return timestamp + deltaSeconds
}

func (mc *MetricsCollector) shiftIntelHistoryClock(deltaSeconds int64) {
	if mc == nil || deltaSeconds <= 0 {
		return
	}
	mc.intelMu.Lock()
	for _, history := range mc.intelHistory {
		if history != nil && history.Initialized {
			history.LastUpdateUnix = shiftIntelTimestamp(history.LastUpdateUnix, deltaSeconds)
		}
	}
	mc.intelMu.Unlock()
}

func (mc *MetricsCollector) shiftIntelHistoryClockForInstance(instanceUUID string, deltaSeconds int64) {
	if mc == nil || instanceUUID == "" || deltaSeconds <= 0 {
		return
	}
	mc.intelMu.Lock()
	if history := mc.intelHistory[instanceUUID]; history != nil && history.Initialized {
		history.LastUpdateUnix = shiftIntelTimestamp(history.LastUpdateUnix, deltaSeconds)
	}
	mc.intelMu.Unlock()
}

func (mc *MetricsCollector) resetIntelHistoryForInstance(instanceUUID string) {
	if mc == nil || instanceUUID == "" {
		return
	}
	mc.intelMu.Lock()
	delete(mc.intelHistory, instanceUUID)
	mc.intelMu.Unlock()
}

func (mc *MetricsCollector) resetThreatStateForInstance(instanceUUID string) {
	if mc == nil || instanceUUID == "" {
		return
	}
	mc.resetIntelHistoryForInstance(instanceUUID)
	mc.tm.resetInstanceThreatLifecycle(instanceUUID)
}

func (mc *MetricsCollector) markIntelSourcesUnavailable(instanceUUID string) {
	if mc == nil || instanceUUID == "" {
		return
	}
	mc.intelMu.Lock()
	if history := mc.intelHistory[instanceUUID]; history != nil && history.Initialized {
		history.SourcesAvailable = false
	}
	mc.intelMu.Unlock()
}

func (mc *MetricsCollector) intelSourceRecoveryPending(instanceUUID string) bool {
	if mc == nil || instanceUUID == "" {
		return false
	}
	mc.intelMu.Lock()
	history := mc.intelHistory[instanceUUID]
	pending := history != nil && history.Initialized && !history.SourcesAvailable
	mc.intelMu.Unlock()
	return pending
}

func (mc *MetricsCollector) snapshotIntelHistory(instanceUUID string, fallback float64) float64 {
	value, ok := mc.snapshotIntelHistoryAvailable(instanceUUID)
	if !ok {
		return fallback
	}
	return value
}

func (mc *MetricsCollector) snapshotIntelHistoryAvailable(instanceUUID string) (float64, bool) {
	mc.intelMu.Lock()
	defer mc.intelMu.Unlock()
	s := mc.intelHistory[instanceUUID]
	if s == nil || !s.Initialized || !s.SourcesAvailable {
		return 0, false
	}
	return s.EWMA, true
}

func (mc *MetricsCollector) snapshotIntelCombinedAvailable(instanceUUID string) (float64, bool) {
	mc.intelMu.Lock()
	defer mc.intelMu.Unlock()
	s := mc.intelHistory[instanceUUID]
	if s == nil || !s.Initialized || !s.SourcesAvailable {
		return 0, false
	}
	return clamp01(0.5*s.LastInstant + 0.5*s.EWMA), true
}

func saturatingThreatEvidenceTotal(retained int, dropped uint64) uint64 {
	total := uint64(retained)
	if ^uint64(0)-total < dropped {
		return ^uint64(0)
	}
	return total + dropped
}

// combinedThreatActiveFlows returns the bounded single-scan union in production.
// Once that union reaches its evidence cap, CombinedThreatHitsDropped is a
// presence marker rather than an exact tail cardinality: this keeps repeated
// or reordered raw flows from multiplying severity while retaining the useful
// lower bound of cap+1 (well above the score's saturation point). The fallback
// supports synthetic/retained aggregates created before the combined union
// existed; it never adds unknown capped tails from overlapping feeds, using
// the largest source total as their conservative lower bound.
func combinedThreatActiveFlows(connAgg *ConntrackAgg, instanceUUID string) uint64 {
	if connAgg == nil {
		return 0
	}
	if connAgg.CombinedThreatHits != nil || connAgg.CombinedThreatHitsDropped != nil {
		return saturatingThreatEvidenceTotal(
			len(connAgg.CombinedThreatHits[instanceUUID]),
			connAgg.CombinedThreatHitsDropped[instanceUUID],
		)
	}

	known := make(map[PairKey]struct{})
	maxSourceTotal := uint64(0)
	addSource := func(hits map[PairKey]ConntrackEntry, dropped uint64) {
		for key := range hits {
			known[key] = struct{}{}
		}
		// Legacy per-list dropped counters may have counted a re-seen key after
		// eviction. They establish overflow, but not exact tail cardinality.
		overflow := uint64(0)
		if dropped > 0 {
			overflow = 1
		}
		if total := saturatingThreatEvidenceTotal(len(hits), overflow); total > maxSourceTotal {
			maxSourceTotal = total
		}
	}
	if connAgg.SpamhausSourceIncluded {
		addSource(connAgg.SpamhausHits[instanceUUID], connAgg.SpamhausHitsDropped[instanceUUID])
	}
	for provider := range connAgg.ProviderSourcesIncluded {
		var hits map[PairKey]ConntrackEntry
		if perInstance := connAgg.ProviderHits[provider]; perInstance != nil {
			hits = perInstance[instanceUUID]
		}
		var dropped uint64
		if perInstance := connAgg.ProviderHitsDropped[provider]; perInstance != nil {
			dropped = perInstance[instanceUUID]
		}
		addSource(hits, dropped)
	}
	if uint64(len(known)) > maxSourceTotal {
		return uint64(len(known))
	}
	return maxSourceTotal
}

func (mc *MetricsCollector) collectDomainThreatSignals(
	connAgg *ConntrackAgg,
	ipSet map[string]struct{},
	domain, serverName, instanceUUID, projectUUID, projectName, userUUID string,
	snapshotFresh, updateState, retainOutput bool,
	dynamicMetrics *[]prometheus.Metric,
) (float64, bool) {

	if mc.tm == nil {
		return 0.0, false
	}
	// A known non-running state is an authoritative lifecycle boundary. It
	// cannot emit even retained per-list evidence after its episode reset. A
	// missing state field is non-authoritative and passes retainOutput=true.
	if !retainOutput {
		return 0, false
	}
	if !conntrackSnapshotMatchesInstanceIPs(connAgg, instanceUUID, ipSet) {
		return 0.0, false
	}
	if !connAgg.SpamhausSourceIncluded && len(connAgg.ProviderSourcesIncluded) == 0 {
		// Source availability belongs to the globally complete snapshot, not
		// to per-instance lifecycle eligibility. A fresh zero-source aggregate
		// therefore starts a source gap even while this instance is frozen.
		if snapshotFresh {
			mc.markIntelSourcesUnavailable(instanceUUID)
			return 0, false
		}
		return mc.snapshotIntelCombinedAvailable(instanceUUID)
	}
	eligibleFresh := snapshotFresh && updateState
	sourceRecovery := eligibleFresh && mc.intelSourceRecoveryPending(instanceUUID)
	advancePerListState := eligibleFresh && !sourceRecovery
	if connAgg.SpamhausSourceIncluded {
		spamSignal := 0.0
		var hits map[PairKey]ConntrackEntry
		var droppedHits uint64
		if connAgg != nil {
			hits = connAgg.SpamhausHits[instanceUUID]
			droppedHits = connAgg.SpamhausHitsDropped[instanceUUID]
		}
		mc.tm.exportSpamhausHits(hits, droppedHits, ipSet, domain, serverName, instanceUUID, projectUUID, projectName, userUUID, dynamicMetrics, &spamSignal, advancePerListState)
		if sourceRecovery {
			mc.tm.reconcileSpamhausHitIdentities(instanceUUID, hits)
			if len(hits) > 0 || droppedHits > 0 {
				mc.tm.reconcileThreatSummaryThrottle("spamhaus", instanceUUID, time.Unix(connAgg.ObservationUnix, 0))
			}
		}
	}

	for _, p := range mc.tm.Providers {
		if p == nil {
			continue
		}
		if _, included := connAgg.ProviderSourcesIncluded[p.Name]; !included {
			continue
		}
		providerSignal := 0.0
		var hits map[PairKey]ConntrackEntry
		var droppedHits uint64
		if connAgg != nil {
			if pm, ok := connAgg.ProviderHits[p.Name]; ok {
				hits = pm[instanceUUID]
			}
			if dm, ok := connAgg.ProviderHitsDropped[p.Name]; ok {
				droppedHits = dm[instanceUUID]
			}
		}
		mc.tm.exportProviderHits(p, hits, droppedHits, ipSet, domain, serverName, instanceUUID, projectUUID, projectName, userUUID, dynamicMetrics, &providerSignal, advancePerListState)
		if sourceRecovery {
			mc.tm.reconcileProviderHitIdentities(p, instanceUUID, hits)
			if len(hits) > 0 || droppedHits > 0 {
				mc.tm.reconcileThreatSummaryThrottle(p.LogTag, instanceUUID, time.Unix(connAgg.ObservationUnix, 0))
			}
		}
	}

	if eligibleFresh {
		intelCombinedInstant := clamp01(float64(combinedThreatActiveFlows(connAgg, instanceUUID)) / 10.0)
		mc.updateIntelHistoryForSourceSet(instanceUUID, intelCombinedInstant, connAgg.ObservationUnix, threatSourceSetFingerprint(connAgg))
	}
	intelCombined, available := mc.snapshotIntelCombinedAvailable(instanceUUID)
	if !available {
		return 0, false
	}
	return intelCombined, true
}

func conntrackSnapshotMatchesInstanceIPs(connAgg *ConntrackAgg, instanceUUID string, ipSet map[string]struct{}) bool {
	if connAgg == nil || connAgg.VMIndex == nil || instanceUUID == "" || len(ipSet) == 0 {
		return false
	}
	current := make(map[IPKey]struct{}, len(ipSet))
	for address := range ipSet {
		key := IPStrToKey(address)
		if key == (IPKey{}) {
			continue
		}
		current[key] = struct{}{}
		if _, ok := connAgg.VMIndex[VMIPIdentity{InstanceUUID: instanceUUID, IP: key}]; !ok {
			return false
		}
	}
	if len(current) == 0 {
		return false
	}
	matched := 0
	for identity := range connAgg.VMIndex {
		if identity.InstanceUUID == instanceUUID {
			matched++
		}
	}
	return matched == len(current)
}
