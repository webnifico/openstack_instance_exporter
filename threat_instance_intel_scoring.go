package main

import (
	"github.com/prometheus/client_golang/prometheus"
)

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

	intelSum := 0.0
	intelCount := 0.0

	if mc.tm.spamEnabled {
		spamSignal := 0.0
		var hits map[PairKey]ConntrackEntry
		if connAgg != nil {
			hits = connAgg.SpamhausHits[instanceUUID]
		}
		mc.tm.exportSpamhausHits(hits, ipSet, domain, serverName, instanceUUID, projectUUID, projectName, userUUID, dynamicMetrics, &spamSignal)
		intelSum += spamSignal
		intelCount++
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
		intelSum += providerSignal
		intelCount++
	}

	intel01 := 0.0
	if intelCount > 0 {
		intel01 = clamp01(intelSum / intelCount)
	}

	intelBurst := intel01
	intelLong := mc.updateIntelHistory(instanceUUID, intelBurst)
	intelCombined := clamp01(0.5*intelBurst + 0.5*intelLong)
	return intelCombined
}
