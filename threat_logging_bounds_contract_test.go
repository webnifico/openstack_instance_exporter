package main

import (
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func threatIntelligenceThreatHits(count int, reverse bool) map[PairKey]ConntrackEntry {
	hits := make(map[PairKey]ConntrackEntry, count)
	vm := IPStrToKey("10.0.0.10")
	remote := IPStrToKey("198.51.100.20")
	for offset := 0; offset < count; offset++ {
		index := offset
		if reverse {
			index = count - offset - 1
		}
		entry := ConntrackEntry{
			Src: "10.0.0.10", Dst: "198.51.100.20",
			SrcPort: uint16(index + 1), DstPort: 443, Proto: 6,
		}
		key := MakePairKey(vm, entry.SrcPort, remote, entry.DstPort, entry.Proto)
		hits[key] = entry
	}
	return hits
}

func threatIntelligenceThreatSummary(t *testing.T, events []map[string]interface{}) map[string]interface{} {
	t.Helper()
	return findDataIntegrityStructuredEvent(t, events, "threat_list_summary", "TESTLIST")
}

func threatIntelligenceJSONNumberUint64(t *testing.T, value interface{}) uint64 {
	t.Helper()
	number, ok := value.(json.Number)
	if !ok {
		t.Fatalf("value=%v (%T), want json.Number", value, value)
	}
	parsed, err := number.Int64()
	if err != nil || parsed < 0 {
		t.Fatalf("number=%q is not a non-negative integer: %v", number, err)
	}
	return uint64(parsed)
}

func TestThreatIntelligenceThreatLoggingSummarizesLargeHitSetWithBoundedEvidence(t *testing.T) {
	logs := captureDataIntegrityStructuredLogs(t)
	now := time.Unix(1_900_000_000, 0)
	tm := newThreatStateTestManager()
	tm.threatLogMinInterval = time.Hour
	tm.threatLogNowOverride = func() time.Time { return now }

	hits := threatIntelligenceThreatHits(maxThreatContactIdentitiesPerInstance+1000, true)
	metrics := make([]prometheus.Metric, 0, 2)
	activeDesc := prometheus.NewDesc("threat_intelligence_test_active", "test", labelsInstance("direction"), nil)
	totalDesc := prometheus.NewDesc("threat_intelligence_test_total", "test", labelsInstance("direction"), nil)
	countMap := make(map[string]float64)
	prevHits := make(map[string]map[string]struct{})
	var countMu sync.Mutex
	var prevHitsMu sync.Mutex
	signal := 0.0
	tm.exportThreatHitsCommon(
		"TESTLIST", ContactOut, hits, 17, map[string]struct{}{"10.0.0.10": {}},
		"domain", "server", "vm-large", "project", "project-name", "user",
		&metrics, &signal, activeDesc, totalDesc, countMap, &countMu, prevHits, &prevHitsMu, true,
	)

	events := decodeDataIntegrityStructuredLogs(t, logs.String())
	if got := len(events); got != 2 {
		t.Fatalf("large hit set emitted %d events, want one compatible hit plus one summary", got)
	}
	summary := threatIntelligenceThreatSummary(t, events)
	if got, want := threatIntelligenceJSONNumberUint64(t, summary["active_flows"]), uint64(len(hits))+17; got != want {
		t.Fatalf("active_flows=%d, want %d", got, want)
	}
	if got := threatIntelligenceJSONNumberUint64(t, summary["retained_hits"]); got != uint64(len(hits)) {
		t.Fatalf("retained_hits=%d, want %d", got, len(hits))
	}
	if got := threatIntelligenceJSONNumberUint64(t, summary["dropped_hits"]); got != 17 {
		t.Fatalf("dropped_hits=%d, want 17", got)
	}
	if summary["evidence_capped"] != true {
		t.Fatalf("evidence_capped=%v, want true", summary["evidence_capped"])
	}
	evidence, ok := summary["representative_evidence"].([]interface{})
	if !ok || len(evidence) != maxThreatLogRepresentativeEvidence {
		t.Fatalf("representative evidence=%T/%d, want %d items", summary["representative_evidence"], len(evidence), maxThreatLogRepresentativeEvidence)
	}
	for index, item := range evidence {
		entry, ok := item.(map[string]interface{})
		if !ok {
			t.Fatalf("evidence %d=%T, want object", index, item)
		}
		if got := threatIntelligenceJSONNumberUint64(t, entry["src_port"]); got != uint64(index+1) {
			t.Fatalf("evidence %d src_port=%d, want canonical port %d", index, got, index+1)
		}
	}
	if len(prevHits["vm-large"]) != maxThreatContactIdentitiesPerInstance {
		t.Fatalf("retained contact identities=%d, want hard cap %d", len(prevHits["vm-large"]), maxThreatContactIdentitiesPerInstance)
	}
	if len(tm.threatLastHit) != 1 {
		t.Fatalf("per-flow throttle state leaked: entries=%d, want one instance/list key", len(tm.threatLastHit))
	}
}

func TestThreatIntelligenceThreatSummaryEvidenceIsIterationOrderIndependent(t *testing.T) {
	collect := func(reverse bool) []interface{} {
		logs := captureDataIntegrityStructuredLogs(t)
		tm := newThreatStateTestManager()
		tm.threatLogNowOverride = func() time.Time { return time.Unix(1_900_000_100, 0) }
		tm.logThreatHitSummary(
			"TESTLIST", "domain", "server", fmt.Sprintf("vm-%v", reverse),
			"project", "project-name", "user", threatIntelligenceThreatHits(1000, reverse), 0,
			map[IPKey]struct{}{IPStrToKey("10.0.0.10"): {}}, ContactOut,
		)
		events := decodeDataIntegrityStructuredLogs(t, logs.String())
		return threatIntelligenceThreatSummary(t, events)["representative_evidence"].([]interface{})
	}

	forward := collect(false)
	reverse := collect(true)
	if !reflect.DeepEqual(forward, reverse) {
		t.Fatalf("representative evidence depends on insertion order:\nforward=%#v\nreverse=%#v", forward, reverse)
	}
}

func TestThreatIntelligenceThreatSummaryEvidencePreservesICMPIdentity(t *testing.T) {
	logs := captureDataIntegrityStructuredLogs(t)
	tm := newThreatStateTestManager()
	tm.threatLogNowOverride = func() time.Time { return time.Unix(1_900_000_125, 0) }
	src := IPStrToKey("10.0.0.10")
	dst := IPStrToKey("198.51.100.20")
	hits := make(map[PairKey]ConntrackEntry)
	for _, entry := range []ConntrackEntry{
		{Src: "10.0.0.10", Dst: "198.51.100.20", Proto: 1, ICMPID: 7, ICMPType: 8, ICMPCode: 0},
		{Src: "10.0.0.10", Dst: "198.51.100.20", Proto: 1, ICMPID: 3, ICMPType: 8, ICMPCode: 0},
		{Src: "10.0.0.10", Dst: "198.51.100.20", Proto: 1, ICMPID: 3, ICMPType: 3, ICMPCode: 1},
	} {
		key := MakeConntrackPairKey(src, 0, dst, 0, entry.Proto, entry.ICMPID, entry.ICMPType, entry.ICMPCode)
		hits[key] = entry
	}
	tm.logThreatHitSummary(
		"TESTLIST", "domain", "server", "vm-icmp", "project", "project-name", "user",
		hits, 0, map[IPKey]struct{}{src: {}}, ContactOut,
	)

	summary := threatIntelligenceThreatSummary(t, decodeDataIntegrityStructuredLogs(t, logs.String()))
	evidence := summary["representative_evidence"].([]interface{})
	want := [][3]uint64{{3, 3, 1}, {3, 8, 0}, {7, 8, 0}}
	if len(evidence) != len(want) {
		t.Fatalf("ICMP evidence records=%d, want %d", len(evidence), len(want))
	}
	for index, raw := range evidence {
		entry := raw.(map[string]interface{})
		got := [3]uint64{
			threatIntelligenceJSONNumberUint64(t, entry["icmp_id"]),
			threatIntelligenceJSONNumberUint64(t, entry["icmp_type"]),
			threatIntelligenceJSONNumberUint64(t, entry["icmp_code"]),
		}
		if got != want[index] {
			t.Fatalf("ICMP evidence %d identity=%v, want %v", index, got, want[index])
		}
	}
}

func TestThreatIntelligenceThreatSummaryTrustsRoutedAmbiguousHits(t *testing.T) {
	logs := captureDataIntegrityStructuredLogs(t)
	tm := newThreatStateTestManager()
	tm.threatLogNowOverride = func() time.Time { return time.Unix(1_900_000_150, 0) }
	src := IPStrToKey("10.0.0.10")
	dst := IPStrToKey("10.0.0.11")
	entry := ConntrackEntry{Src: "10.0.0.10", Dst: "10.0.0.11", SrcPort: 44000, DstPort: 443, Proto: 6}
	hits := map[PairKey]ConntrackEntry{MakePairKey(src, entry.SrcPort, dst, entry.DstPort, entry.Proto): entry}
	tm.logThreatHitSummary(
		"TESTLIST", "domain", "server", "vm-ambiguous", "project", "project-name", "user",
		hits, 0, map[IPKey]struct{}{src: {}, dst: {}}, ContactOut,
	)

	summary := threatIntelligenceThreatSummary(t, decodeDataIntegrityStructuredLogs(t, logs.String()))
	if got := threatIntelligenceJSONNumberUint64(t, summary["active_flows"]); got != 1 {
		t.Fatalf("ambiguous routed active_flows=%d, want 1", got)
	}
	if summary["direction"] != "outbound" {
		t.Fatalf("ambiguous summary direction=%v, want configured outbound", summary["direction"])
	}
	evidence := summary["representative_evidence"].([]interface{})
	if got := evidence[0].(map[string]interface{})["direction"]; got != "outbound" {
		t.Fatalf("ambiguous evidence direction=%v, want configured outbound", got)
	}
}

func TestThreatIntelligenceThreatSummaryReportsDroppedOnlyEvidence(t *testing.T) {
	logs := captureDataIntegrityStructuredLogs(t)
	tm := newThreatStateTestManager()
	tm.threatLogNowOverride = func() time.Time { return time.Unix(1_900_000_175, 0) }
	tm.logThreatHitSummary(
		"TESTLIST", "domain", "server", "vm-dropped", "project", "project-name", "user",
		nil, 23, map[IPKey]struct{}{IPStrToKey("10.0.0.10"): {}}, ContactIn,
	)

	events := decodeDataIntegrityStructuredLogs(t, logs.String())
	if len(events) != 2 {
		t.Fatalf("dropped-only summary emitted %d events, want two", len(events))
	}
	summary := threatIntelligenceThreatSummary(t, events)
	if got := threatIntelligenceJSONNumberUint64(t, summary["active_flows"]); got != 23 {
		t.Fatalf("dropped-only active_flows=%d, want 23", got)
	}
	if got := threatIntelligenceJSONNumberUint64(t, summary["retained_hits"]); got != 0 {
		t.Fatalf("dropped-only retained_hits=%d, want zero", got)
	}
	if got := threatIntelligenceJSONNumberUint64(t, summary["evidence_count"]); got != 0 {
		t.Fatalf("dropped-only evidence_count=%d, want zero", got)
	}
	if summary["direction"] != "inbound" || summary["evidence_capped"] != true {
		t.Fatalf("dropped-only direction/cap=%v/%v, want inbound/true", summary["direction"], summary["evidence_capped"])
	}
	if evidence := summary["representative_evidence"].([]interface{}); len(evidence) != 0 {
		t.Fatalf("dropped-only evidence=%v, want empty", evidence)
	}
}

func TestThreatIntelligenceThreatSummaryRepeatThrottleAndBackwardClock(t *testing.T) {
	logs := captureDataIntegrityStructuredLogs(t)
	now := time.Unix(1_900_000_200, 0)
	tm := newThreatStateTestManager()
	tm.threatLogMinInterval = time.Hour
	tm.threatLogNowOverride = func() time.Time { return now }
	hits := threatIntelligenceThreatHits(10, false)
	args := func() {
		tm.logThreatHitSummary(
			"TESTLIST", "domain", "server", "vm-repeat", "project", "project-name", "user",
			hits, 0, map[IPKey]struct{}{IPStrToKey("10.0.0.10"): {}}, ContactOut,
		)
	}

	args()
	args()
	now = now.Add(time.Hour - time.Nanosecond)
	args()
	now = now.Add(time.Nanosecond)
	args()
	now = now.Add(-2 * time.Hour)
	args()

	events := decodeDataIntegrityStructuredLogs(t, logs.String())
	owned := map[string]int{
		"threat_list_hit":     0,
		"threat_list_summary": 0,
	}
	for _, event := range events {
		message, _ := event["msg"].(string)
		if _, expected := owned[message]; expected {
			owned[message]++
		}
	}
	if owned["threat_list_hit"] != 3 || owned["threat_list_summary"] != 3 {
		t.Fatalf("summary repeat throttle emitted owned events=%v, want three admitted report pairs", owned)
	}
}

func TestThreatIntelligenceThreatThrottleMemoryCapAndConcurrentAdmission(t *testing.T) {
	tm := newThreatStateTestManager()
	tm.threatLogMinInterval = time.Hour
	now := time.Unix(1_900_000_300, 0)
	const candidates = maxThreatLogThrottleEntries * 3
	var admitted atomic.Int64
	var wg sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for index := worker; index < candidates; index += 16 {
				if tm.shouldLogThreatHit(fmt.Sprintf("THREAT|candidate-%08d", index), now) {
					admitted.Add(1)
				}
			}
		}(worker)
	}
	wg.Wait()
	if got := len(tm.threatLastHit); got != maxThreatLogThrottleEntries {
		t.Fatalf("throttle state=%d, want hard cap %d", got, maxThreatLogThrottleEntries)
	}
	if got := admitted.Load(); got != maxThreatLogThrottleEntries {
		t.Fatalf("admitted unique events=%d, want burst cap %d", got, maxThreatLogThrottleEntries)
	}
	if tm.shouldLogThreatHit("THREAT|overflow", now) {
		t.Fatal("full throttle state admitted an unseen event")
	}
	tm.threatLastHitMu.Lock()
	existing := ""
	for key := range tm.threatLastHit {
		existing = key
		break
	}
	tm.threatLastHitMu.Unlock()
	if existing == "" || !tm.shouldLogThreatHit(existing, now.Add(-time.Second)) {
		t.Fatal("backward clock failed to reopen an existing throttle key")
	}
}

func TestThreatIntelligenceThreatThrottleFreezeCleanupAndExpiration(t *testing.T) {
	tm := newThreatStateTestManager()
	tm.threatLogMinInterval = time.Minute
	old := time.Now().Add(-2 * time.Minute)
	tm.threatLastHit = map[string]time.Time{
		instanceThreatThrottlePrefix + "TESTLIST|vm-active":   old,
		instanceThreatThrottlePrefix + "TESTLIST|vm-inactive": old,
		hostThreatThrottlePrefix + "TESTLIST|192.0.2.8":       old,
	}
	tm.cleanupInstanceThreatThrottleState(map[string]struct{}{"vm-active": {}})
	if _, ok := tm.threatLastHit[instanceThreatThrottlePrefix+"TESTLIST|vm-inactive"]; ok {
		t.Fatal("inactive instance/list summary throttle survived ownership cleanup")
	}

	tm.cleanupThreatLastHitWithConntrackFreeze(true)
	if len(tm.threatLastHit) != 1 {
		t.Fatalf("freeze cleanup state=%v, want only retained instance summary", tm.threatLastHit)
	}
	if _, ok := tm.threatLastHit[instanceThreatThrottlePrefix+"TESTLIST|vm-active"]; !ok {
		t.Fatal("conntrack freeze expired instance/list summary throttle")
	}
	tm.shiftThreatEventClock(30)
	if got := tm.threatLastHit[instanceThreatThrottlePrefix+"TESTLIST|vm-active"]; !got.Equal(old.Add(30 * time.Second)) {
		t.Fatalf("frozen summary throttle shifted to %v, want %v", got, old.Add(30*time.Second))
	}
	tm.cleanupThreatLastHitWithConntrackFreeze(false)
	if len(tm.threatLastHit) != 0 {
		t.Fatalf("normal cleanup retained expired summary throttle: %v", tm.threatLastHit)
	}
}

func TestThreatIntelligenceInstanceMissingStatePreservesAndShiftsSummaryThrottle(t *testing.T) {
	tm := newThreatStateTestManager()
	tm.threatLogMinInterval = time.Minute
	key := instanceThreatThrottlePrefix + "TESTLIST|vm-missing"
	original := time.Unix(100, 0)
	tm.threatLastHit[key] = original

	cm := &ConntrackManager{}
	cm.observeBehaviorInstanceLifecycle("vm-missing", false, false, time.Unix(150, 0))
	tm.cleanupThreatLastHitWithFrozenInstances(false, cm.snapshotBehaviorFrozenInstances())
	if got, ok := tm.threatLastHit[key]; !ok || !got.Equal(original) {
		t.Fatalf("conntrack-fresh cleanup expired frozen instance summary: got %v present=%v", got, ok)
	}

	if !cm.observeBehaviorInstanceLifecycle("vm-missing", true, true, time.Unix(250, 0)) {
		t.Fatal("missing-state recovery marker was not created")
	}
	recoveryShift := cm.takeBehaviorInstanceRecoveryShiftSeconds("vm-missing")
	if recoveryShift != 100 {
		t.Fatalf("missing-state recovery shift=%d, want 100", recoveryShift)
	}
	tm.shiftThreatEventClockForInstance("vm-missing", recoveryShift)
	if got := tm.threatLastHit[key]; !got.Equal(time.Unix(200, 0)) {
		t.Fatalf("missing-state summary timestamp=%v, want 200", got)
	}
	if tm.shouldLogThreatHit(key, time.Unix(250, 0)) {
		t.Fatal("recovery log was admitted solely because of missing-state outage time")
	}
}

func TestThreatIntelligenceInstanceAndGlobalOutageShiftSummaryThrottleUnionOnce(t *testing.T) {
	tm := newThreatStateTestManager()
	tm.threatLogMinInterval = 30 * time.Second
	instanceKey := instanceThreatThrottlePrefix + "TESTLIST|vm-overlap"
	policyKey := "POLICY|event|vm-overlap|domain|kind"
	hostKey := hostThreatThrottlePrefix + "TESTLIST|192.0.2.8"
	original := time.Unix(35, 0)
	tm.threatLastHit = map[string]time.Time{
		instanceKey: original,
		policyKey:   original,
		hostKey:     original,
	}

	cm := &ConntrackManager{}
	cm.observeBehaviorInstanceLifecycle("vm-overlap", false, false, time.Unix(50, 0))
	cm.beginBehaviorStateFreeze(time.Unix(100, 0))
	globalShift := cm.resumeBehaviorStateClock(time.Unix(200, 0))
	if globalShift != 100 {
		t.Fatalf("global recovery shift=%d, want 100", globalShift)
	}
	tm.shiftThreatEventClock(globalShift)
	if !cm.observeBehaviorInstanceLifecycle("vm-overlap", true, true, time.Unix(200, 0)) {
		t.Fatal("overlapping recovery marker was not created")
	}
	instanceShift := cm.takeBehaviorInstanceRecoveryShiftSeconds("vm-overlap")
	if instanceShift != 50 {
		t.Fatalf("non-overlap instance prefix=%d, want 50", instanceShift)
	}
	tm.shiftThreatEventClockForInstance("vm-overlap", instanceShift)

	if got := tm.threatLastHit[instanceKey]; !got.Equal(time.Unix(185, 0)) {
		t.Fatalf("overlap summary timestamp=%v, want exact union shift to 185", got)
	}
	if got := tm.threatLastHit[policyKey]; !got.Equal(time.Unix(135, 0)) {
		t.Fatalf("policy timestamp=%v, want global-only shift to 135", got)
	}
	if got := tm.threatLastHit[hostKey]; !got.Equal(original) {
		t.Fatalf("host timestamp=%v, want unchanged %v", got, original)
	}
	if tm.shouldLogThreatHit(instanceKey, time.Unix(200, 0)) {
		t.Fatal("overlap recovery log was admitted solely because outage clocks were mishandled")
	}
	if second := cm.takeBehaviorInstanceRecoveryShiftSeconds("vm-overlap"); second != 0 {
		t.Fatalf("instance recovery shift was consumable twice: %d", second)
	}
	tm.shiftThreatEventClockForInstance("vm-overlap", 0)
	if got := tm.threatLastHit[instanceKey]; !got.Equal(time.Unix(185, 0)) {
		t.Fatalf("zero second shift changed timestamp to %v", got)
	}
}

func TestThreatIntelligenceAuthoritativeThreatLifecycleResetPreservesCounters(t *testing.T) {
	provider := newThreatStateTestProvider("Provider")
	provider.CountMap = map[string]float64{"vm-reset": 9, "vm-keep": 4}
	provider.PrevHits = map[string]map[string]struct{}{
		"vm-reset": {"old-reset": {}},
		"vm-keep":  {"old-keep": {}},
	}
	tm := newThreatStateTestManager(provider)
	tm.spamCount = map[string]float64{"vm-reset": 7, "vm-keep": 3}
	tm.spamPrevHits = map[string]map[string]struct{}{
		"vm-reset": {"spam-reset": {}},
		"vm-keep":  {"spam-keep": {}},
	}
	tm.threatLastHit = map[string]time.Time{
		instanceThreatThrottlePrefix + "PROVIDER|vm-reset": time.Unix(100, 0),
		instanceThreatThrottlePrefix + "PROVIDER|vm-keep":  time.Unix(100, 0),
		"POLICY|event|vm-reset|domain|kind":                time.Unix(100, 0),
		hostThreatThrottlePrefix + "PROVIDER|192.0.2.8":    time.Unix(100, 0),
	}

	tm.resetInstanceThreatLifecycle("vm-reset")
	if _, ok := provider.PrevHits["vm-reset"]; ok {
		t.Fatal("provider previous contacts crossed authoritative lifecycle reset")
	}
	if _, ok := tm.spamPrevHits["vm-reset"]; ok {
		t.Fatal("Spamhaus previous contacts crossed authoritative lifecycle reset")
	}
	if provider.CountMap["vm-reset"] != 9 || tm.spamCount["vm-reset"] != 7 {
		t.Fatalf("cumulative counters were reset: provider=%v spam=%v", provider.CountMap, tm.spamCount)
	}
	if _, ok := tm.threatLastHit[instanceThreatThrottlePrefix+"PROVIDER|vm-reset"]; ok {
		t.Fatal("instance summary throttle crossed authoritative lifecycle reset")
	}
	for _, retained := range []string{
		instanceThreatThrottlePrefix + "PROVIDER|vm-keep",
		"POLICY|event|vm-reset|domain|kind",
		hostThreatThrottlePrefix + "PROVIDER|192.0.2.8",
	} {
		if _, ok := tm.threatLastHit[retained]; !ok {
			t.Fatalf("reset removed unrelated/non-instance throttle %q", retained)
		}
	}
	if _, ok := provider.PrevHits["vm-keep"]; !ok {
		t.Fatal("reset removed survivor provider state")
	}
	if _, ok := tm.spamPrevHits["vm-keep"]; !ok {
		t.Fatal("reset removed survivor Spamhaus state")
	}
}

func TestThreatIntelligenceThreatIdentityReconciliationIsSilentAndCounterNeutral(t *testing.T) {
	logs := captureDataIntegrityStructuredLogs(t)
	provider := newThreatStateTestProvider("Provider")
	provider.CountMap = map[string]float64{"vm-reconcile": 11}
	provider.PrevHits = map[string]map[string]struct{}{"vm-reconcile": {"old": {}}}
	tm := newThreatStateTestManager(provider)
	tm.spamCount = map[string]float64{"vm-reconcile": 13}
	tm.spamPrevHits = map[string]map[string]struct{}{"vm-reconcile": {"old": {}}}
	hits := threatIntelligenceThreatHits(maxThreatContactIdentitiesPerInstance+500, true)

	tm.reconcileSpamhausHitIdentities("vm-reconcile", hits)
	tm.reconcileProviderHitIdentities(provider, "vm-reconcile", hits)

	if len(tm.spamPrevHits["vm-reconcile"]) != maxThreatContactIdentitiesPerInstance ||
		len(provider.PrevHits["vm-reconcile"]) != maxThreatContactIdentitiesPerInstance {
		t.Fatalf("reconciled identities exceeded bounds: spam=%d provider=%d",
			len(tm.spamPrevHits["vm-reconcile"]), len(provider.PrevHits["vm-reconcile"]))
	}
	if tm.spamCount["vm-reconcile"] != 13 || provider.CountMap["vm-reconcile"] != 11 {
		t.Fatalf("reconciliation advanced counters: spam=%v provider=%v", tm.spamCount, provider.CountMap)
	}
	if logs.Len() != 0 || len(tm.threatLastHit) != 0 {
		t.Fatalf("reconciliation emitted/throttled a log: logs=%q throttle=%v", logs.String(), tm.threatLastHit)
	}
}

func TestThreatIntelligenceThreatSummaryThrottleReconciliationIsSilentAndBounded(t *testing.T) {
	tm := newThreatStateTestManager()
	tm.threatLogMinInterval = time.Hour
	now := time.Unix(1_900_000_450, 0)
	key := instanceThreatThrottlePrefix + "TESTLIST|vm-recovery"
	tm.reconcileThreatSummaryThrottle("testlist", "vm-recovery", now)
	if got := tm.threatLastHit[key]; !got.Equal(now) {
		t.Fatalf("reconciled summary throttle=%v, want %v", got, now)
	}
	if tm.shouldLogThreatHit(key, now.Add(time.Hour-time.Nanosecond)) {
		t.Fatal("unchanged post-recovery cycle escaped the reconciled repeat window")
	}
	if !tm.shouldLogThreatHit(key, now.Add(time.Hour)) {
		t.Fatal("reconciled repeat window did not reopen at its exact boundary")
	}

	unthrottled := newThreatStateTestManager()
	unthrottled.threatLogMinInterval = 0
	unthrottled.reconcileThreatSummaryThrottle("TESTLIST", "vm-recovery", now)
	if len(unthrottled.threatLastHit) != 0 || !unthrottled.shouldLogThreatHit(key, now) {
		t.Fatal("zero-interval operator opt-out acquired reconciliation throttle state")
	}

	full := newThreatStateTestManager()
	full.threatLogMinInterval = time.Hour
	for index := 0; index < maxThreatLogThrottleEntries; index++ {
		full.threatLastHit[fmt.Sprintf("POLICY|%08d", index)] = now
	}
	full.reconcileThreatSummaryThrottle("TESTLIST", "vm-overflow", now)
	if len(full.threatLastHit) != maxThreatLogThrottleEntries {
		t.Fatalf("reconciliation exceeded throttle cap: %d", len(full.threatLastHit))
	}
}

func TestThreatIntelligencePerListOverflowIsDuplicateSafeMarker(t *testing.T) {
	now := time.Now()
	provider := newThreatStateTestProvider("OverflowProvider")
	provider.Direction = ContactOut
	provider.LastSuccess = float64(now.Unix())
	provider.EntryCount = 1
	remote := IPStrToKey("198.51.100.19")
	provider.Set = map[IPKey]struct{}{remote: {}}
	provider.SetAtomic.Store(provider.Set)
	tm := newThreatStateTestManager(provider)
	tm.threatLogMinInterval = 0
	tm.spamEnabled = true
	tm.spamDir = ContactOut
	tm.spamLastSuccessUnix = float64(now.Unix())
	tm.spamRefresh = time.Hour
	tm.spamEntries = 1
	bucket := uint16(remote[12])<<8 | uint16(remote[13])
	tm.spamBucketsV4[bucket] = []*net.IPNet{mustCIDR(t, "198.51.100.0/24")}

	vm := IPStrToKey("10.0.0.10")
	flows := make([]ConntrackFlowLite, maxSpamhausHitsPerInstance+2)
	for index := range flows {
		flows[index] = ConntrackFlowLite{
			SrcIP: vm, DstIP: remote, SrcPort: uint16(index + 1), DstPort: 443, Proto: 6,
		}
	}
	sequence := append([]ConntrackFlowLite(nil), flows...)
	for repeat := 0; repeat < 100; repeat++ {
		sequence = append(sequence, flows[len(flows)-1])
	}
	aggregate := func(reverse bool) *ConntrackAgg {
		cm := &ConntrackManager{}
		agg, consume := cm.newConntrackAggregator([]VMIPIdentity{{InstanceUUID: "vm-overflow", IP: vm}}, tm)
		if reverse {
			for index := len(sequence) - 1; index >= 0; index-- {
				consume(sequence[index])
			}
		} else {
			for _, flow := range sequence {
				consume(flow)
			}
		}
		return agg
	}
	forward := aggregate(false)
	reverse := aggregate(true)
	for name, dropped := range map[string][2]uint64{
		"spamhaus": {forward.SpamhausHitsDropped["vm-overflow"], reverse.SpamhausHitsDropped["vm-overflow"]},
		"provider": {
			forward.ProviderHitsDropped[provider.Name]["vm-overflow"],
			reverse.ProviderHitsDropped[provider.Name]["vm-overflow"],
		},
	} {
		if dropped != [2]uint64{1, 1} {
			t.Fatalf("%s overflow markers forward/reverse=%v, want [1 1]", name, dropped)
		}
	}
	for _, pair := range [][2]map[PairKey]ConntrackEntry{
		{forward.SpamhausHits["vm-overflow"], reverse.SpamhausHits["vm-overflow"]},
		{forward.ProviderHits[provider.Name]["vm-overflow"], reverse.ProviderHits[provider.Name]["vm-overflow"]},
	} {
		if len(pair[0]) != maxProviderHitsPerInstance || len(pair[1]) != maxProviderHitsPerInstance {
			t.Fatalf("retained per-list hits forward/reverse=%d/%d", len(pair[0]), len(pair[1]))
		}
		for key := range pair[0] {
			if _, ok := pair[1][key]; !ok {
				t.Fatal("per-list retained identities depend on duplicate/reversed input order")
			}
		}
	}

	logs := captureDataIntegrityStructuredLogs(t)
	metrics := make([]prometheus.Metric, 0, 4)
	signal := 0.0
	ipSet := map[string]struct{}{"10.0.0.10": {}}
	tm.exportSpamhausHits(
		forward.SpamhausHits["vm-overflow"], forward.SpamhausHitsDropped["vm-overflow"], ipSet,
		"domain", "server", "vm-overflow", "project", "project-name", "user", &metrics, &signal, true,
	)
	tm.exportProviderHits(
		provider, forward.ProviderHits[provider.Name]["vm-overflow"], forward.ProviderHitsDropped[provider.Name]["vm-overflow"], ipSet,
		"domain", "server", "vm-overflow", "project", "project-name", "user", &metrics, &signal, true,
	)
	if len(metrics) != 4 || threatIntelligenceMetricValue(t, metrics[0]) != 5001 || threatIntelligenceMetricValue(t, metrics[2]) != 5001 {
		t.Fatalf("per-list capped active gauges=%v, want conservative 5001", []float64{threatIntelligenceMetricValue(t, metrics[0]), threatIntelligenceMetricValue(t, metrics[2])})
	}
	events := decodeDataIntegrityStructuredLogs(t, logs.String())
	for _, kind := range []string{"spamhaus", provider.LogTag} {
		summary := findDataIntegrityStructuredEvent(t, events, "threat_list_summary", kind)
		if threatIntelligenceJSONNumberUint64(t, summary["active_flows"]) != 5001 ||
			threatIntelligenceJSONNumberUint64(t, summary["dropped_hits"]) != 1 {
			t.Fatalf("%s capped summary=%v", kind, summary)
		}
	}
}

func BenchmarkThreatIntelligenceSuppressedThreatSummary(b *testing.B) {
	tm := newThreatStateTestManager()
	tm.threatLogMinInterval = time.Hour
	now := time.Unix(1_900_000_400, 0)
	tm.threatLogNowOverride = func() time.Time { return now }
	hits := threatIntelligenceThreatHits(maxThreatContactIdentitiesPerInstance, true)
	ipSet := map[IPKey]struct{}{IPStrToKey("10.0.0.10"): {}}
	tm.threatLastHit[instanceThreatThrottlePrefix+"TESTLIST|vm-benchmark"] = now
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		tm.logThreatHitSummary(
			"TESTLIST", "domain", "server", "vm-benchmark", "project", "project-name", "user",
			hits, 0, ipSet, ContactOut,
		)
	}
}
