package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"time"
)

// recordThreatObservation remembers source availability so the first complete
// collection after a feed outage can reconcile contacts without logging a burst.
func (mc *MetricsCollector) recordThreatObservation(instanceUUID string, sources ...string) {
	mc.intelMu.Lock()
	defer mc.intelMu.Unlock()
	if mc.threatSourceState == nil {
		mc.threatSourceState = make(map[string]*ThreatSourceState)
	}
	history := mc.threatSourceState[instanceUUID]
	if history == nil {
		history = &ThreatSourceState{}
		mc.threatSourceState[instanceUUID] = history
	}
	if len(sources) > 0 && history.Lists == nil {
		history.Lists = make(map[string]bool, len(sources))
	}
	for _, source := range sources {
		history.Lists[source] = true
	}
}

func (mc *MetricsCollector) resetThreatSourceStateForInstance(instanceUUID string) {
	if mc == nil || instanceUUID == "" {
		return
	}
	mc.intelMu.Lock()
	delete(mc.threatSourceState, instanceUUID)
	mc.intelMu.Unlock()
}

func (mc *MetricsCollector) resetThreatStateForInstance(instanceUUID string) {
	if mc == nil || instanceUUID == "" {
		return
	}
	mc.resetThreatSourceStateForInstance(instanceUUID)
	mc.tm.resetInstanceThreatLifecycle(instanceUUID)
}

// A feed gap belongs to its list even when another list remains usable. Only
// already observed lists own recovery state: a provider's first successful
// load still counts its initial contacts normally.
func (mc *MetricsCollector) markMissingIntelSourcesUnavailable(instanceUUID string, agg *ConntrackAgg) {
	mc.intelMu.Lock()
	defer mc.intelMu.Unlock()
	history := mc.threatSourceState[instanceUUID]
	if history == nil {
		return
	}
	for source := range history.Lists {
		available := agg.SpamhausSourceIncluded
		if source != "spamhaus" {
			_, available = agg.ProviderSourcesIncluded[source]
		}
		if !available {
			history.Lists[source] = false
		}
	}
}

func (mc *MetricsCollector) intelListSourceNeedsRebaseline(instanceUUID, source string, observationRecovery bool) bool {
	mc.intelMu.Lock()
	defer mc.intelMu.Unlock()
	history := mc.threatSourceState[instanceUUID]
	if history == nil {
		return false
	}
	available, observed := history.Lists[source]
	return observed && (!available || observationRecovery)
}

func (mc *MetricsCollector) collectDomainThreatSignals(
	connAgg *ConntrackAgg,
	ipSet map[string]struct{},
	domain, serverName, instanceUUID, projectUUID, projectName, userUUID string,
	snapshotFresh, updateState, retainOutput bool,
	dynamicMetrics *[]prometheus.Metric,
) {

	if mc.tm == nil {
		return
	}
	// A known non-running state is an authoritative lifecycle boundary. It
	// cannot emit even retained per-list evidence after its episode reset. A
	// missing state field is non-authoritative and passes retainOutput=true.
	if !retainOutput {
		return
	}
	if !conntrackSnapshotMatchesInstanceIPs(connAgg, instanceUUID, ipSet) {
		return
	}
	if snapshotFresh {
		// Globally complete conntrack snapshots establish source gaps even when
		// this instance is temporarily ineligible to advance its event state.
		mc.markMissingIntelSourcesUnavailable(instanceUUID, connAgg)
	}
	if !connAgg.SpamhausSourceIncluded && len(connAgg.ProviderSourcesIncluded) == 0 {
		return
	}
	eligibleFresh := snapshotFresh && updateState
	observationRecovery := eligibleFresh && (mc.cm.behaviorNeedsRecoveryRebaseline() || mc.cm.behaviorInstanceNeedsRecoveryRebaseline(instanceUUID))
	observedSources := make([]string, 0, len(mc.tm.Providers)+1)
	if connAgg.SpamhausSourceIncluded {
		sourceRecovery := eligibleFresh && mc.intelListSourceNeedsRebaseline(instanceUUID, "spamhaus", observationRecovery)
		advancePerListState := eligibleFresh && !sourceRecovery
		var hits map[PairKey]ConntrackEntry
		var droppedHits uint64
		if connAgg != nil {
			hits = connAgg.SpamhausHits[instanceUUID]
			droppedHits = connAgg.SpamhausHitsDropped[instanceUUID]
		}
		mc.tm.exportSpamhausHits(hits, droppedHits, ipSet, domain, serverName, instanceUUID, projectUUID, projectName, userUUID, dynamicMetrics, advancePerListState)
		if sourceRecovery {
			mc.tm.reconcileSpamhausHitIdentities(instanceUUID, hits)
			if len(hits) > 0 || droppedHits > 0 {
				mc.tm.reconcileThreatSummaryThrottle("spamhaus", instanceUUID, time.Unix(connAgg.ObservationUnix, 0))
			}
		}
		observedSources = append(observedSources, "spamhaus")
	}

	for _, p := range mc.tm.Providers {
		if p == nil {
			continue
		}
		if _, included := connAgg.ProviderSourcesIncluded[p.Name]; !included {
			continue
		}
		sourceRecovery := eligibleFresh && mc.intelListSourceNeedsRebaseline(instanceUUID, p.Name, observationRecovery)
		advancePerListState := eligibleFresh && !sourceRecovery
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
		observedSources = append(observedSources, p.Name)
		mc.tm.exportProviderHits(p, hits, droppedHits, ipSet, domain, serverName, instanceUUID, projectUUID, projectName, userUUID, dynamicMetrics, advancePerListState)
		if sourceRecovery {
			mc.tm.reconcileProviderHitIdentities(p, instanceUUID, hits)
			if len(hits) > 0 || droppedHits > 0 {
				mc.tm.reconcileThreatSummaryThrottle(p.LogTag, instanceUUID, time.Unix(connAgg.ObservationUnix, 0))
			}
		}
	}

	if eligibleFresh {
		mc.recordThreatObservation(instanceUUID, observedSources...)
	}
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
		if connAgg.ObservedFamilies != 0 {
			family := conntrackObservedIPv6
			if isIPv4MappedKey(key) {
				family = conntrackObservedIPv4
			}
			if connAgg.ObservedFamilies&family == 0 {
				continue
			}
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
