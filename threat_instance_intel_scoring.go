package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"time"
)

func combineThreatSignalsUnion(current float64, signal float64) float64 {
	signal = clamp01(signal)
	current = clamp01(current)
	if signal <= 0 {
		return current
	}
	return clamp01(1.0 - (1.0-current)*(1.0-signal))
}

func (mc *MetricsCollector) updateIntelHistory(instanceUUID string, instant float64) float64 {
	const alphaIntel = 0.1

	mc.intelMu.Lock()
	defer mc.intelMu.Unlock()

	if mc.intelHistory == nil {
		mc.intelHistory = make(map[string]*IntelHistory)
	}

	s, ok := mc.intelHistory[instanceUUID]
	if !ok {
		s = &IntelHistory{
			EWMA:        instant,
			Initialized: true,
		}
		mc.intelHistory[instanceUUID] = s
		return s.EWMA
	}

	s.EWMA = s.EWMA + alphaIntel*(instant-s.EWMA)
	return s.EWMA
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
	s := mc.intelHistory[instanceUUID]
	mc.intelMu.Unlock()
	if s == nil || !s.Initialized {
		return 0, false
	}
	return s.EWMA, true
}

func (mc *MetricsCollector) collectDomainThreatSignals(
	connAgg *ConntrackAgg,
	ipSet map[string]struct{},
	domain, serverName, instanceUUID, projectUUID, projectName, userUUID string,
	conntrackFresh bool,
	dynamicMetrics *[]prometheus.Metric,
) (float64, bool) {

	if mc.tm == nil {
		return 0.0, false
	}
	now := time.Now()
	spamFresh, freshProviders := mc.tm.freshThreatSources(now)
	if !spamFresh && len(freshProviders) == 0 {
		return 0.0, false
	}
	if connAgg == nil {
		if previous, ok := mc.snapshotIntelHistoryAvailable(instanceUUID); ok {
			return clamp01(previous), true
		}
		return 0.0, false
	}

	intelCombinedInstant := 0.0

	if spamFresh {
		spamSignal := 0.0
		var hits map[PairKey]ConntrackEntry
		var droppedHits uint64
		if connAgg != nil {
			hits = connAgg.SpamhausHits[instanceUUID]
			droppedHits = connAgg.SpamhausHitsDropped[instanceUUID]
		}
		mc.tm.exportSpamhausHits(hits, droppedHits, ipSet, domain, serverName, instanceUUID, projectUUID, projectName, userUUID, dynamicMetrics, &spamSignal, conntrackFresh)
		intelCombinedInstant = combineThreatSignalsUnion(intelCombinedInstant, spamSignal)
	}

	for _, p := range freshProviders {
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
		mc.tm.exportProviderHits(p, hits, droppedHits, ipSet, domain, serverName, instanceUUID, projectUUID, projectName, userUUID, dynamicMetrics, &providerSignal, conntrackFresh)
		intelCombinedInstant = combineThreatSignalsUnion(intelCombinedInstant, providerSignal)
	}

	intelBurst := intelCombinedInstant
	intelLong := mc.snapshotIntelHistory(instanceUUID, intelBurst)
	if conntrackFresh {
		intelLong = mc.updateIntelHistory(instanceUUID, intelBurst)
	}
	intelCombined := clamp01(0.5*intelBurst + 0.5*intelLong)
	return intelCombined, true
}
