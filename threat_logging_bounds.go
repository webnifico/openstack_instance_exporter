package main

import (
	"sort"
	"strings"
	"time"
)

const (
	// One collection can retain considerably more matching flows for metric and
	// scoring accuracy, but a log entry only needs a small, stable sample.
	maxThreatLogRepresentativeEvidence = 4
	// This bounds the global THREAT/POLICY repeat-throttle state. Once full,
	// unseen keys are suppressed until normal expiry cleanup creates room.
	maxThreatLogThrottleEntries = 4096
	// Conntrack aggregation already enforces this limit. Apply it again at the
	// state boundary so direct callers cannot grow retained contact identity
	// state without limit.
	maxThreatContactIdentitiesPerInstance = 5000
)

const instanceThreatThrottlePrefix = "INSTANCE_THREAT|"

type threatLogEvidence struct {
	Src       string `json:"src"`
	Dst       string `json:"dst"`
	SrcPort   uint16 `json:"src_port"`
	DstPort   uint16 `json:"dst_port"`
	Protocol  uint8  `json:"protocol"`
	ICMPID    uint16 `json:"icmp_id"`
	ICMPType  uint8  `json:"icmp_type"`
	ICMPCode  uint8  `json:"icmp_code"`
	Direction string `json:"direction"`
}

func (tm *ThreatManager) threatLogNow() time.Time {
	if tm != nil && tm.threatLogNowOverride != nil {
		return tm.threatLogNowOverride()
	}
	return time.Now()
}

func sortedThreatHitKeys(hits map[PairKey]ConntrackEntry) []PairKey {
	keys := make([]PairKey, 0, len(hits))
	for key := range hits {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		return compareThreatPairKey(keys[i], keys[j]) < 0
	})
	return keys
}

func boundedThreatContactKeys(hits map[PairKey]ConntrackEntry) map[string]struct{} {
	limit := len(hits)
	if limit > maxThreatContactIdentitiesPerInstance {
		limit = maxThreatContactIdentitiesPerInstance
	}
	current := make(map[string]struct{}, limit)
	if limit == 0 {
		return current
	}
	if len(hits) <= maxThreatContactIdentitiesPerInstance {
		for key := range hits {
			current[PairKeyString(key)] = struct{}{}
		}
		return current
	}
	keys := sortedThreatHitKeys(hits)
	for _, key := range keys[:limit] {
		current[PairKeyString(key)] = struct{}{}
	}
	return current
}

func threatSummaryDirection(listDirection ContactDirection, ipSet map[IPKey]struct{}, ct ConntrackEntry) string {
	direction := flowDirection(ipSet, ct)
	if direction == "any" {
		direction = listDirection.String()
	}
	return normalizeDirectionForLog(direction)
}

func (tm *ThreatManager) logThreatHitSummary(
	tag string,
	domain string,
	serverName string,
	instanceUUID string,
	projectUUID string,
	projectName string,
	userUUID string,
	hits map[PairKey]ConntrackEntry,
	droppedHits uint64,
	ipSet map[IPKey]struct{},
	listDirection ContactDirection,
) {
	if tm == nil {
		return
	}
	retainedHits := uint64(len(hits))
	if retainedHits == 0 && droppedHits == 0 {
		return
	}
	activeFlows := saturatingAddUint64(retainedHits, droppedHits)
	key := instanceThreatThrottlePrefix + strings.ToUpper(strings.TrimSpace(tag)) + "|" + instanceUUID
	if !tm.shouldLogThreatHit(key, tm.threatLogNow()) {
		return
	}

	keys := sortedThreatHitKeys(hits)
	evidence := make([]threatLogEvidence, 0, maxThreatLogRepresentativeEvidence)
	first := ConntrackEntry{}
	firstDirection := normalizeDirectionForLog(listDirection.String())
	summaryDirection := normalizeDirectionForLog(listDirection.String())
	for _, key := range keys {
		ct := hits[key]
		if len(evidence) >= maxThreatLogRepresentativeEvidence {
			break
		}
		normalizedDirection := threatSummaryDirection(listDirection, ipSet, ct)
		if len(evidence) == 0 {
			first = ct
			firstDirection = normalizedDirection
		}
		evidence = append(evidence, threatLogEvidence{
			Src:       ct.Src,
			Dst:       ct.Dst,
			SrcPort:   ct.SrcPort,
			DstPort:   ct.DstPort,
			Protocol:  ct.Proto,
			ICMPID:    ct.ICMPID,
			ICMPType:  ct.ICMPType,
			ICMPCode:  ct.ICMPCode,
			Direction: normalizedDirection,
		})
	}

	logKV(LogLevelNotice, "threat", "threat", "threat_list_hit",
		"tag", tag,
		"kind", tag,
		"list", tag,
		"domain", domain,
		"server_name", serverName,
		"instance_uuid", instanceUUID,
		"project_uuid", projectUUID,
		"project_name", projectName,
		"user_uuid", userUUID,
		// Keep the original scalar evidence fields for structured-log
		// compatibility. They are the first item in the deterministic sample.
		"src", first.Src,
		"dst", first.Dst,
		"direction", firstDirection,
	)
	logKV(LogLevelNotice, "threat", "threat", "threat_list_summary",
		"tag", tag,
		"kind", tag,
		"list", tag,
		"domain", domain,
		"server_name", serverName,
		"instance_uuid", instanceUUID,
		"project_uuid", projectUUID,
		"project_name", projectName,
		"user_uuid", userUUID,
		"direction", summaryDirection,
		"active_flows", activeFlows,
		"retained_hits", retainedHits,
		"dropped_hits", droppedHits,
		"evidence_count", len(evidence),
		"evidence_capped", activeFlows > uint64(len(evidence)),
		"representative_evidence", evidence,
	)
}

func (tm *ThreatManager) cleanupInstanceThreatThrottleState(activeInstances map[string]struct{}) {
	if tm == nil {
		return
	}
	tm.threatLastHitMu.Lock()
	defer tm.threatLastHitMu.Unlock()
	for key := range tm.threatLastHit {
		instanceUUID, ok := instanceThreatThrottleOwner(key)
		if strings.HasPrefix(key, instanceThreatThrottlePrefix) && !ok {
			delete(tm.threatLastHit, key)
			continue
		}
		if !ok {
			continue
		}
		if _, active := activeInstances[instanceUUID]; !active {
			delete(tm.threatLastHit, key)
		}
	}
}

func instanceThreatThrottleOwner(key string) (string, bool) {
	if !strings.HasPrefix(key, instanceThreatThrottlePrefix) {
		return "", false
	}
	parts := strings.SplitN(strings.TrimPrefix(key, instanceThreatThrottlePrefix), "|", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return "", false
	}
	return parts[1], true
}

// resetInstanceThreatLifecycle clears identity-diff and summary-throttle state
// that must not cross an authoritative runtime/IP ownership boundary. Contact
// counters are cumulative Prometheus counters and deliberately survive.
func (tm *ThreatManager) resetInstanceThreatLifecycle(instanceUUID string) {
	if tm == nil || instanceUUID == "" {
		return
	}
	for _, provider := range tm.Providers {
		if provider == nil {
			continue
		}
		provider.PrevHitsMu.Lock()
		delete(provider.PrevHits, instanceUUID)
		provider.PrevHitsMu.Unlock()
	}
	tm.spamPrevHitsMu.Lock()
	delete(tm.spamPrevHits, instanceUUID)
	tm.spamPrevHitsMu.Unlock()

	tm.threatLastHitMu.Lock()
	for key := range tm.threatLastHit {
		owner, ok := instanceThreatThrottleOwner(key)
		if ok && owner == instanceUUID {
			delete(tm.threatLastHit, key)
		}
	}
	tm.threatLastHitMu.Unlock()
}

func (tm *ThreatManager) reconcileSpamhausHitIdentities(instanceUUID string, hits map[PairKey]ConntrackEntry) {
	if tm == nil || instanceUUID == "" {
		return
	}
	current := boundedThreatContactKeys(hits)
	tm.spamPrevHitsMu.Lock()
	if tm.spamPrevHits == nil {
		tm.spamPrevHits = make(map[string]map[string]struct{})
	}
	tm.spamPrevHits[instanceUUID] = current
	tm.spamPrevHitsMu.Unlock()
}

func (tm *ThreatManager) reconcileProviderHitIdentities(p *IPThreatProvider, instanceUUID string, hits map[PairKey]ConntrackEntry) {
	if tm == nil || p == nil || instanceUUID == "" {
		return
	}
	current := boundedThreatContactKeys(hits)
	p.PrevHitsMu.Lock()
	if p.PrevHits == nil {
		p.PrevHits = make(map[string]map[string]struct{})
	}
	p.PrevHits[instanceUUID] = current
	p.PrevHitsMu.Unlock()
}

// reconcileThreatSummaryThrottle makes a source-recovery baseline silent and
// keeps the next unchanged collection quiet for the configured repeat window.
// A zero interval remains the explicit operator opt-out and owns no state.
func (tm *ThreatManager) reconcileThreatSummaryThrottle(tag, instanceUUID string, now time.Time) {
	if tm == nil || instanceUUID == "" || tm.threatLogMinInterval <= 0 {
		return
	}
	if now.IsZero() {
		now = tm.threatLogNow()
	}
	key := instanceThreatThrottlePrefix + strings.ToUpper(strings.TrimSpace(tag)) + "|" + instanceUUID
	tm.threatLastHitMu.Lock()
	if tm.threatLastHit == nil {
		tm.threatLastHit = make(map[string]time.Time)
	}
	if _, exists := tm.threatLastHit[key]; exists || len(tm.threatLastHit) < maxThreatLogThrottleEntries {
		tm.threatLastHit[key] = now
	}
	tm.threatLastHitMu.Unlock()
}
