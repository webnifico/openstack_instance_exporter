package main

import (
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

func (mc *MetricsCollector) collectDomainThreatSignals(
	connAgg *ConntrackAgg,
	ipSet map[string]struct{},
	domain, serverName, instanceUUID, projectUUID, projectName, userUUID string,
	dynamicMetrics *[]prometheus.Metric,
) float64 {

	if mc.tm == nil {
		return 0.0
	}

	intelCombinedInstant := 0.0

	if mc.tm.spamEnabled {
		spamSignal := 0.0
		var hits map[PairKey]ConntrackEntry
		if connAgg != nil {
			hits = connAgg.SpamhausHits[instanceUUID]
		}
		mc.tm.exportSpamhausHits(hits, ipSet, domain, serverName, instanceUUID, projectUUID, projectName, userUUID, dynamicMetrics, &spamSignal)
		intelCombinedInstant = combineThreatSignalsUnion(intelCombinedInstant, spamSignal)
	}

	for _, p := range mc.tm.Providers {
		if !p.Enabled {
			continue
		}

		providerSignal := 0.0
		var hits map[PairKey]ConntrackEntry
		if connAgg != nil {
			if pm, ok := connAgg.ProviderHits[p.Name]; ok {
				hits = pm[instanceUUID]
			}
		}
		mc.tm.exportProviderHits(p, hits, ipSet, domain, serverName, instanceUUID, projectUUID, projectName, userUUID, dynamicMetrics, &providerSignal)
		intelCombinedInstant = combineThreatSignalsUnion(intelCombinedInstant, providerSignal)
	}

	intelBurst := intelCombinedInstant
	intelLong := mc.updateIntelHistory(instanceUUID, intelBurst)
	intelCombined := clamp01(0.5*intelBurst + 0.5*intelLong)
	return intelCombined
}
