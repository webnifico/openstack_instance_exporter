package main

import (
	"math"
	"net"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func threatIntelligenceThreatHistoryAtInterval(t *testing.T, interval time.Duration) float64 {
	t.Helper()
	mc := &MetricsCollector{
		intelHistory:  make(map[string]*IntelHistory),
		threatEWMATau: defaultThreatEWMATau,
	}
	if got := mc.updateIntelHistory("vm", 0, 0); got != 0 {
		t.Fatalf("epoch-zero baseline=%v, want 0", got)
	}
	for elapsed := interval; elapsed <= 5*time.Minute; elapsed += interval {
		mc.updateIntelHistory("vm", 1, int64(elapsed/time.Second))
	}
	history := mc.intelHistory["vm"]
	if history == nil || !history.Initialized || history.LastUpdateUnix != 300 {
		t.Fatalf("interval %s history=%+v", interval, history)
	}
	return history.EWMA
}

func TestThreatIntelligenceThreatEWMAIsElapsedTimeInvariant(t *testing.T) {
	want := 1 - math.Exp(-300/defaultThreatEWMATau.Seconds())
	for _, interval := range []time.Duration{10 * time.Second, 15 * time.Second, 30 * time.Second} {
		got := threatIntelligenceThreatHistoryAtInterval(t, interval)
		if math.Abs(got-want) > 1e-12 {
			t.Fatalf("interval %s EWMA=%0.15f, want %0.15f", interval, got, want)
		}
	}
}

func TestThreatIntelligenceThreatEWMAReplayBackwardClockAndEpochZero(t *testing.T) {
	mc := &MetricsCollector{
		intelHistory:  make(map[string]*IntelHistory),
		threatEWMATau: defaultThreatEWMATau,
	}
	if got := mc.updateIntelHistory("epoch", 0.25, 0); got != 0.25 {
		t.Fatalf("epoch-zero initial EWMA=%v", got)
	}
	if state := mc.intelHistory["epoch"]; state == nil || state.LastUpdateUnix != 0 || !state.Initialized {
		t.Fatalf("epoch-zero timestamp was treated as unset: %+v", state)
	}

	first := mc.updateIntelHistory("vm", 0.2, 100)
	advanced := mc.updateIntelHistory("vm", 0.8, 115)
	if advanced == first {
		t.Fatal("forward elapsed time did not advance threat history")
	}
	if replay := mc.updateIntelHistory("vm", 0, 115); replay != advanced {
		t.Fatalf("same observation timestamp replay changed EWMA: %v -> %v", advanced, replay)
	}
	if state := mc.intelHistory["vm"]; state.LastUpdateUnix != 115 {
		t.Fatalf("same timestamp replay changed clock: %+v", state)
	}

	if rollback := mc.updateIntelHistory("vm", 0.4, -100); rollback != 0.4 {
		t.Fatalf("strict backward clock did not rebaseline: %v", rollback)
	}
	state := mc.intelHistory["vm"]
	if state.LastUpdateUnix != -100 {
		t.Fatalf("backward clock retained an unreachable future timestamp: %+v", state)
	}
	if next := mc.updateIntelHistory("vm", 0.8, -90); next <= 0.4 || next >= 0.8 {
		t.Fatalf("permanent rollback could not resume elapsed-time updates: %v", next)
	}
}

func TestThreatIntelligenceThreatEWMAFreezesFailedCyclesAndExcludesOutageWallTime(t *testing.T) {
	control := &MetricsCollector{intelHistory: make(map[string]*IntelHistory), threatEWMATau: defaultThreatEWMATau}
	control.updateIntelHistory("vm", 0.8, 100)
	want := control.updateIntelHistory("vm", 0.2, 115)

	mc := &MetricsCollector{intelHistory: make(map[string]*IntelHistory), threatEWMATau: defaultThreatEWMATau}
	mc.updateIntelHistory("vm", 0.8, 100)
	cm := &ConntrackManager{}
	initializeConntrackState(cm)
	cm.beginBehaviorStateFreeze(time.Unix(115, 0))

	// Failed/retained cycles emit last-good evidence but never call the history
	// updater. Repeating them must leave both value and timestamp untouched.
	for range 4 {
		if got, ok := mc.snapshotIntelHistoryAvailable("vm"); !ok || got != 0.8 {
			t.Fatalf("failed cycle changed retained history: (%v,%v)", got, ok)
		}
	}
	if state := mc.intelHistory["vm"]; state.LastUpdateUnix != 100 {
		t.Fatalf("failed cycles advanced threat clock: %+v", state)
	}

	outageDelta := cm.resumeBehaviorStateClock(time.Unix(1015, 0))
	mc.shiftIntelHistoryClock(outageDelta)
	got := mc.updateIntelHistory("vm", 0.2, 1015)
	if math.Abs(got-want) > 1e-12 {
		t.Fatalf("recovery included outage wall time: got=%v want normal-15s=%v", got, want)
	}
	if state := mc.intelHistory["vm"]; state.LastUpdateUnix != 1015 {
		t.Fatalf("recovery threat clock=%+v", state)
	}
}

func TestThreatIntelligenceThreatEWMAExcludesNegativeToEpochZeroOutage(t *testing.T) {
	control := &MetricsCollector{intelHistory: make(map[string]*IntelHistory), threatEWMATau: defaultThreatEWMATau}
	control.updateIntelHistory("vm", 0.8, 0)
	want := control.updateIntelHistory("vm", 0.2, 15)

	mc := &MetricsCollector{intelHistory: make(map[string]*IntelHistory), threatEWMATau: defaultThreatEWMATau}
	mc.updateIntelHistory("vm", 0.8, -115)
	cm := &ConntrackManager{}
	initializeConntrackState(cm)
	cm.beginBehaviorStateFreeze(time.Unix(-100, 0))
	cm.beginBehaviorStateFreeze(time.Unix(-50, 0))
	recovery := &ConntrackAgg{ObservationUnix: 0, ObservationTimeSet: true}
	recoveryNow := conntrackObservationTime(recovery, time.Unix(999, 0))
	if !recoveryNow.Equal(time.Unix(0, 0)) {
		t.Fatalf("epoch-zero complete observation fell back to wall clock: %v", recoveryNow)
	}
	if delta := cm.resumeBehaviorStateClock(recoveryNow); delta != 100 {
		t.Fatalf("negative-boundary outage shift=%d, want 100", delta)
	} else {
		mc.shiftIntelHistoryClock(delta)
	}
	if cm.behaviorFreezeActive {
		t.Fatal("epoch-zero recovery left the global freeze active")
	}
	if got := mc.updateIntelHistory("vm", 0.2, 0); math.Abs(got-want) > 1e-12 {
		t.Fatalf("negative-to-epoch recovery EWMA=%v, want one eligible 15s interval %v", got, want)
	}
}

func TestThreatIntelligenceRetainedConntrackAggregateCannotAdvanceThreatState(t *testing.T) {
	const (
		instanceUUID = "vm-retained"
		vmAddress    = "10.0.0.10"
		remote       = "198.51.100.10"
	)
	provider := newThreatStateTestProvider("RetainedProvider")
	tm := newThreatStateTestManager(provider)
	mc := &MetricsCollector{tm: tm, intelHistory: make(map[string]*IntelHistory), threatEWMATau: defaultThreatEWMATau}
	makeAggregate := func(hitCount int) *ConntrackAgg {
		hits := make(map[PairKey]ConntrackEntry, hitCount)
		for index := 0; index < hitCount; index++ {
			port := uint16(41000 + index)
			pair := MakePairKey(IPStrToKey(vmAddress), port, IPStrToKey(remote), 443, 6)
			hits[pair] = ConntrackEntry{Src: vmAddress, Dst: remote, SrcPort: port, DstPort: 443, Proto: 6}
		}
		return &ConntrackAgg{
			VMIndex:                 map[VMIPIdentity]uint32{{InstanceUUID: instanceUUID, IP: IPStrToKey(vmAddress)}: 0},
			ObservationUnix:         100,
			ProviderSourcesIncluded: map[string]struct{}{provider.Name: {}},
			ProviderHits: map[string]map[string]map[PairKey]ConntrackEntry{
				provider.Name: {instanceUUID: hits},
			},
			CombinedThreatHits: map[string]map[PairKey]ConntrackEntry{instanceUUID: hits},
		}
	}

	for _, test := range []struct {
		name          string
		lastFresh     float64
		currentHits   int
		currentEffect string
	}{
		{name: "cannot fall", lastFresh: 0.8, currentHits: 1, currentEffect: "lower"},
		{name: "cannot rise", lastFresh: 0.2, currentHits: 10, currentEffect: "higher"},
	} {
		t.Run(test.name, func(t *testing.T) {
			mc.resetIntelHistoryForInstance(instanceUUID)
			mc.updateIntelHistory(instanceUUID, test.lastFresh, 100)
			agg := makeAggregate(test.currentHits)
			for range 3 {
				metrics := make([]prometheus.Metric, 0, 2)
				score, available := mc.collectDomainThreatSignals(
					agg,
					map[string]struct{}{vmAddress: {}},
					"domain", "server", instanceUUID, "project", "project-name", "user",
					true,
					false,
					true,
					&metrics,
				)
				if !available || score != test.lastFresh || len(metrics) != 2 {
					t.Fatalf("retained %s evidence changed combined score: score=(%v,%v), want %v; metrics=%d", test.currentEffect, score, available, test.lastFresh, len(metrics))
				}
			}
			state := mc.intelHistory[instanceUUID]
			if state == nil || state.EWMA != test.lastFresh || state.LastInstant != test.lastFresh || state.LastUpdateUnix != 100 {
				t.Fatalf("retained aggregate advanced threat state: %+v", state)
			}
		})
	}
	if _, ok := provider.CountMap[instanceUUID]; ok {
		t.Fatal("retained aggregate advanced per-list contact counter")
	}
	if _, ok := provider.PrevHits[instanceUUID]; ok {
		t.Fatal("retained aggregate replaced per-list contact diff state")
	}
	if len(tm.threatLastHit) != 0 {
		t.Fatalf("retained aggregate emitted threat logs: %v", tm.threatLastHit)
	}

	mc.resetIntelHistoryForInstance(instanceUUID)
	metrics := make([]prometheus.Metric, 0, 2)
	if score, available := mc.collectDomainThreatSignals(
		makeAggregate(10),
		map[string]struct{}{vmAddress: {}},
		"domain", "server", instanceUUID, "project", "project-name", "user",
		true,
		false,
		false,
		&metrics,
	); available || score != 0 || len(metrics) != 0 {
		t.Fatalf("stopped/reset instance synthesized combined state: score=(%v,%v), metrics=%d", score, available, len(metrics))
	}
	if _, ok := mc.intelHistory[instanceUUID]; ok {
		t.Fatal("stopped/reset retained collection recreated IntelHistory")
	}
}

func TestThreatIntelligenceThreatEWMAPerInstanceAndGlobalFreezeUnion(t *testing.T) {
	mc := &MetricsCollector{intelHistory: make(map[string]*IntelHistory), threatEWMATau: defaultThreatEWMATau}
	mc.updateIntelHistory("vm", 0.8, 35)
	cm := &ConntrackManager{}
	initializeConntrackState(cm)

	cm.observeBehaviorInstanceLifecycle("vm", false, false, time.Unix(50, 0))
	cm.beginBehaviorStateFreeze(time.Unix(100, 0))
	globalDelta := cm.resumeBehaviorStateClock(time.Unix(200, 0))
	mc.shiftIntelHistoryClock(globalDelta)
	if !cm.observeBehaviorInstanceLifecycle("vm", true, true, time.Unix(200, 0)) {
		t.Fatal("instance recovery was not marked after overlapping freezes")
	}
	mc.shiftIntelHistoryClockForInstance("vm", cm.takeBehaviorInstanceRecoveryShiftSeconds("vm"))
	if state := mc.intelHistory["vm"]; state.LastUpdateUnix != 185 {
		t.Fatalf("overlapping freeze clocks were added twice or lost: %+v", state)
	}

	wantControl := &MetricsCollector{intelHistory: make(map[string]*IntelHistory), threatEWMATau: defaultThreatEWMATau}
	wantControl.updateIntelHistory("vm", 0.8, 0)
	wantEWMA := wantControl.updateIntelHistory("vm", 0.2, 15)
	wantCombined := 0.5*0.2 + 0.5*wantEWMA
	provider := newThreatStateTestProvider("RecoveryProvider")
	mc.tm = newThreatStateTestManager(provider)
	vmIP := IPStrToKey("10.0.0.10")
	remoteIP := IPStrToKey("198.51.100.10")
	hits := make(map[PairKey]ConntrackEntry, 2)
	for index := 0; index < 2; index++ {
		port := uint16(41000 + index)
		pair := MakePairKey(vmIP, port, remoteIP, 443, 6)
		hits[pair] = ConntrackEntry{Src: "10.0.0.10", Dst: "198.51.100.10", SrcPort: port, DstPort: 443, Proto: 6}
	}
	agg := &ConntrackAgg{
		VMIndex:                 map[VMIPIdentity]uint32{{InstanceUUID: "vm", IP: vmIP}: 0},
		ObservationUnix:         200,
		ProviderSourcesIncluded: map[string]struct{}{provider.Name: {}},
		ProviderHits: map[string]map[string]map[PairKey]ConntrackEntry{
			provider.Name: {"vm": hits},
		},
		CombinedThreatHits: map[string]map[PairKey]ConntrackEntry{"vm": hits},
	}
	metrics := make([]prometheus.Metric, 0, 2)
	got, available := mc.collectDomainThreatSignals(
		agg,
		map[string]struct{}{"10.0.0.10": {}},
		"domain", "server", "vm", "project", "project-name", "user",
		true,
		true,
		true,
		&metrics,
	)
	if !available || math.Abs(got-wantCombined) > 1e-12 {
		t.Fatalf("overlapping freeze recovery combined score=(%v,%v), want one normal interval %v", got, available, wantCombined)
	}
	if state := mc.intelHistory["vm"]; state.LastUpdateUnix != 200 || state.LastInstant != 0.2 || math.Abs(state.EWMA-wantEWMA) > 1e-12 {
		t.Fatalf("recovery did not advance exactly one eligible observation: %+v", state)
	}
}

func TestThreatIntelligenceThreatEWMAMissingStateRecoversDuringGlobalFreeze(t *testing.T) {
	mc := &MetricsCollector{intelHistory: make(map[string]*IntelHistory), threatEWMATau: defaultThreatEWMATau}
	mc.updateIntelHistory("vm", 0.8, 35)
	cm := &ConntrackManager{}
	initializeConntrackState(cm)

	cm.observeBehaviorInstanceLifecycle("vm", false, false, time.Unix(50, 0))
	cm.beginBehaviorStateFreeze(time.Unix(100, 0))
	if cm.observeBehaviorInstanceLifecycle("vm", true, true, time.Unix(150, 0)) {
		t.Fatal("known instance state incorrectly completed recovery while conntrack remained frozen")
	}
	mc.shiftIntelHistoryClockForInstance("vm", cm.takeBehaviorInstanceRecoveryShiftSeconds("vm"))
	if state := mc.intelHistory["vm"]; state.LastUpdateUnix != 85 {
		t.Fatalf("missing-state prefix was lost while global freeze remained active: %+v", state)
	}

	globalDelta := cm.resumeBehaviorStateClock(time.Unix(200, 0))
	mc.shiftIntelHistoryClock(globalDelta)
	if state := mc.intelHistory["vm"]; state.LastUpdateUnix != 185 {
		t.Fatalf("freeze union did not include each segment exactly once: %+v", state)
	}

	control := &MetricsCollector{intelHistory: make(map[string]*IntelHistory), threatEWMATau: defaultThreatEWMATau}
	control.updateIntelHistory("vm", 0.8, 0)
	want := control.updateIntelHistory("vm", 0.2, 15)
	if got := mc.updateIntelHistory("vm", 0.2, 200); math.Abs(got-want) > 1e-12 {
		t.Fatalf("recovery-during-global-freeze EWMA=%v, want one normal interval %v", got, want)
	}
}

func TestThreatIntelligenceThreatSourceGapRecoverySilentlyRebaselines(t *testing.T) {
	const (
		instanceUUID = "vm-source-gap"
		vmAddress    = "10.0.0.10"
		remote       = "198.51.100.10"
	)
	logs := captureDataIntegrityStructuredLogs(t)
	provider := newThreatStateTestProvider("RecoveryProvider")
	tm := newThreatStateTestManager(provider)
	tm.threatLogMinInterval = time.Hour
	logNow := time.Unix(100, 0)
	tm.threatLogNowOverride = func() time.Time { return logNow }
	mc := &MetricsCollector{tm: tm, intelHistory: make(map[string]*IntelHistory), threatEWMATau: defaultThreatEWMATau}
	vmIP := IPStrToKey(vmAddress)
	remoteIP := IPStrToKey(remote)
	ipSet := map[string]struct{}{vmAddress: {}}

	makeHits := func(count int) map[PairKey]ConntrackEntry {
		hits := make(map[PairKey]ConntrackEntry, count)
		for index := 0; index < count; index++ {
			sourcePort := uint16(41000 + index)
			key := MakePairKey(vmIP, sourcePort, remoteIP, 443, 6)
			hits[key] = ConntrackEntry{Src: vmAddress, Dst: remote, SrcPort: sourcePort, DstPort: 443, Proto: 6}
		}
		return hits
	}
	makeAggregate := func(observationUnix int64, hits map[PairKey]ConntrackEntry, includeSource bool) *ConntrackAgg {
		agg := &ConntrackAgg{
			VMIndex:                 map[VMIPIdentity]uint32{{InstanceUUID: instanceUUID, IP: vmIP}: 0},
			ObservationUnix:         observationUnix,
			ObservationTimeSet:      true,
			ProviderSourcesIncluded: make(map[string]struct{}),
		}
		if includeSource {
			agg.ProviderSourcesIncluded[provider.Name] = struct{}{}
			agg.ProviderHits = map[string]map[string]map[PairKey]ConntrackEntry{
				provider.Name: {instanceUUID: hits},
			}
			agg.CombinedThreatHits = map[string]map[PairKey]ConntrackEntry{instanceUUID: hits}
		}
		return agg
	}
	collect := func(agg *ConntrackAgg, snapshotFresh, updateState bool) (float64, bool, int) {
		metrics := make([]prometheus.Metric, 0, 2)
		score, available := mc.collectDomainThreatSignals(
			agg,
			ipSet,
			"domain", "server", instanceUUID, "project", "project-name", "user",
			snapshotFresh,
			updateState,
			true,
			&metrics,
		)
		return score, available, len(metrics)
	}

	baseline := makeAggregate(100, makeHits(1), true)
	if score, available, metricCount := collect(baseline, true, true); !available || score != 0.1 || metricCount != 2 {
		t.Fatalf("fresh baseline=(%v,%v), metrics=%d; want (0.1,true), metrics=2", score, available, metricCount)
	}
	if provider.CountMap[instanceUUID] != 1 || len(provider.PrevHits[instanceUUID]) != 1 {
		t.Fatalf("fresh baseline per-list state: count=%v prev=%v", provider.CountMap, provider.PrevHits)
	}
	logs.Reset()
	tm.threatLastHitMu.Lock()
	tm.threatLastHit = make(map[string]time.Time)
	tm.threatLastHitMu.Unlock()

	// A globally fresh aggregate owns feed availability even while this
	// instance is not eligible to update due to missing Libvirt state.
	zeroSources := makeAggregate(10_000, nil, false)
	if score, available, metricCount := collect(zeroSources, true, false); available || score != 0 || metricCount != 0 {
		t.Fatalf("fresh zero-source cycle=(%v,%v), metrics=%d; want unavailable", score, available, metricCount)
	}
	history := mc.intelHistory[instanceUUID]
	if history == nil || history.SourcesAvailable || history.EWMA != 0.1 || history.LastInstant != 0.1 || history.LastUpdateUnix != 100 {
		t.Fatalf("fresh zero-source cycle did not freeze and mark history unavailable: %+v", history)
	}
	if score, available, metricCount := collect(zeroSources, false, false); available || score != 0 || metricCount != 0 {
		t.Fatalf("retained zero-source cycle re-emitted prior severity: (%v,%v), metrics=%d", score, available, metricCount)
	}

	// The first eligible source recovery is a complete new baseline, not a
	// 19,900-second EWMA interval. Per-list identities reconcile without
	// counting or logging feed changes that happened during the gap.
	logNow = time.Unix(20_000, 0)
	recoveredHits := makeHits(8)
	recovered := makeAggregate(20_000, recoveredHits, true)
	if score, available, metricCount := collect(recovered, true, true); !available || score != 0.8 || metricCount != 2 {
		t.Fatalf("source recovery=(%v,%v), metrics=%d; want silent 0.8 baseline and two per-list metrics", score, available, metricCount)
	}
	history = mc.intelHistory[instanceUUID]
	if history == nil || !history.SourcesAvailable || history.EWMA != 0.8 || history.LastInstant != 0.8 || history.LastUpdateUnix != 20_000 {
		t.Fatalf("source recovery did not fully rebaseline: %+v", history)
	}
	if provider.CountMap[instanceUUID] != 1 || len(provider.PrevHits[instanceUUID]) != len(recoveredHits) {
		t.Fatalf("source recovery advanced counters or failed identity reconciliation: count=%v prev=%d", provider.CountMap, len(provider.PrevHits[instanceUUID]))
	}
	if logs.Len() != 0 {
		t.Fatalf("source recovery emitted a summary: %q", logs.String())
	}

	logNow = time.Unix(20_015, 0)
	recovered.ObservationUnix = 20_015
	if score, available, metricCount := collect(recovered, true, true); !available || score != 0.8 || metricCount != 2 {
		t.Fatalf("unchanged post-recovery cycle=(%v,%v), metrics=%d", score, available, metricCount)
	}
	if provider.CountMap[instanceUUID] != 1 {
		t.Fatalf("unchanged post-recovery cycle counted outage-time contacts: %v", provider.CountMap)
	}
	if logs.Len() != 0 {
		t.Fatalf("unchanged post-recovery cycle bypassed the reconciled summary window: %q", logs.String())
	}
}

func threatIntelligenceOverlappingThreatManager(t *testing.T, remotes ...string) *ThreatManager {
	t.Helper()
	now := time.Now()
	providers := []*IPThreatProvider{
		newThreatStateTestProvider("TorExit"),
		newThreatStateTestProvider("TorRelay"),
		newThreatStateTestProvider("EmergingThreats"),
		newThreatStateTestProvider("CustomList"),
	}
	sets := make(map[IPKey]struct{}, len(remotes))
	for _, address := range remotes {
		sets[IPStrToKey(address)] = struct{}{}
	}
	for _, provider := range providers {
		provider.Direction = ContactOut
		provider.LastSuccess = float64(now.Unix())
		provider.EntryCount = len(sets)
		provider.Set = sets
		provider.SetAtomic.Store(provider.Set)
	}
	tm := newThreatStateTestManager(providers...)
	tm.spamEnabled = true
	tm.spamDir = ContactOut
	tm.spamLastSuccessUnix = float64(now.Unix())
	tm.spamRefresh = time.Hour
	tm.spamEntries = len(sets)
	tm.spamWideV4 = []*net.IPNet{mustCIDR(t, "198.0.0.0/8")}
	tm.spamWideV6 = []*net.IPNet{mustCIDR(t, "2001:db8::/32")}
	return tm
}

func TestThreatIntelligenceThreatOverlapDoesNotMultiplyIPv4OrIPv6Flows(t *testing.T) {
	const vmAddress = "10.0.0.10"
	remotes := []string{"198.51.100.55", "2001:db8::55"}
	tm := threatIntelligenceOverlappingThreatManager(t, remotes...)
	cm := &ConntrackManager{conntrackNowOverride: func() time.Time { return time.Unix(100, 0) }}
	agg := cm.aggregateConntrackOnePassFamilies(
		[]ConntrackFlowLite{{SrcIP: IPStrToKey(vmAddress), DstIP: IPStrToKey(remotes[0]), SrcPort: 41000, DstPort: 443, Proto: 6}},
		[]ConntrackFlowLite{{SrcIP: IPStrToKey(vmAddress), DstIP: IPStrToKey(remotes[1]), SrcPort: 41001, DstPort: 443, Proto: 6}},
		[]VMIPIdentity{{InstanceUUID: "vm", IP: IPStrToKey(vmAddress)}},
		tm,
	)
	if got := len(agg.SpamhausHits["vm"]); got != 2 {
		t.Fatalf("Spamhaus per-list evidence=%d, want 2", got)
	}
	for _, provider := range tm.Providers {
		if got := len(agg.ProviderHits[provider.Name]["vm"]); got != 2 {
			t.Fatalf("provider %s per-list evidence=%d, want 2", provider.Name, got)
		}
	}
	if got := combinedThreatActiveFlows(agg, "vm"); got != 2 {
		t.Fatalf("Spamhaus/Tor exit/Tor relay/Emerging Threats/custom overlap multiplied two unique flows to %d", got)
	}

	mc := &MetricsCollector{tm: tm, intelHistory: make(map[string]*IntelHistory), threatEWMATau: defaultThreatEWMATau}
	metrics := make([]prometheus.Metric, 0, 10)
	signal, available := mc.collectDomainThreatSignals(
		agg,
		map[string]struct{}{vmAddress: {}},
		"domain", "server", "vm", "project", "project-name", "user",
		true,
		true,
		true,
		&metrics,
	)
	if !available || signal != 0.2 {
		t.Fatalf("overlap-deduplicated signal=(%v,%v), want (0.2,true)", signal, available)
	}
	if len(metrics) != 10 {
		t.Fatalf("per-list metrics for Spamhaus, Tor exit/relay, Emerging Threats, and custom were collapsed: got %d want 10", len(metrics))
	}
}

func TestThreatIntelligenceThreatOverlapCombinedCapCountsUniqueEvidenceOnce(t *testing.T) {
	const vmAddress = "10.0.0.10"
	const remoteAddress = "198.51.100.99"
	tm := threatIntelligenceOverlappingThreatManager(t, remoteAddress)
	cm := &ConntrackManager{}
	agg, consume := cm.newConntrackAggregator(
		[]VMIPIdentity{{InstanceUUID: "vm", IP: IPStrToKey(vmAddress)}},
		tm,
	)
	for index := 0; index < maxCombinedThreatHitsPerInstance+1; index++ {
		consume(ConntrackFlowLite{
			SrcIP:   IPStrToKey(vmAddress),
			DstIP:   IPStrToKey(remoteAddress),
			SrcPort: uint16(index + 1),
			DstPort: 443,
			Proto:   6,
		})
	}
	// Raw conntrack input can repeat a canonical key, including a key already
	// outside the retained set. Repetition and reordering must not inflate the
	// bounded overflow marker.
	for _, sourcePort := range []uint16{maxCombinedThreatHitsPerInstance + 1, 0, maxCombinedThreatHitsPerInstance} {
		consume(ConntrackFlowLite{
			SrcIP:   IPStrToKey(vmAddress),
			DstIP:   IPStrToKey(remoteAddress),
			SrcPort: sourcePort,
			DstPort: 443,
			Proto:   6,
		})
	}
	if retained := len(agg.CombinedThreatHits["vm"]); retained != maxCombinedThreatHitsPerInstance {
		t.Fatalf("combined retained evidence=%d, want cap %d", retained, maxCombinedThreatHitsPerInstance)
	}
	if dropped := agg.CombinedThreatHitsDropped["vm"]; dropped != 1 {
		t.Fatalf("combined overflow marker=%d, want 1", dropped)
	}
	if got := combinedThreatActiveFlows(agg, "vm"); got != uint64(maxCombinedThreatHitsPerInstance+1) {
		t.Fatalf("overlapping capped feeds lower bound=%d, want %d", got, maxCombinedThreatHitsPerInstance+1)
	}
}

func TestThreatIntelligenceLegacyCombinedFallbackTreatsDroppedAsOverflowMarker(t *testing.T) {
	key := MakePairKey(IPStrToKey("10.0.0.10"), 41000, IPStrToKey("198.51.100.10"), 443, 6)
	hit := ConntrackEntry{Src: "10.0.0.10", Dst: "198.51.100.10", SrcPort: 41000, DstPort: 443, Proto: 6}
	agg := &ConntrackAgg{
		ProviderSourcesIncluded: map[string]struct{}{"one": {}, "two": {}},
		ProviderHits: map[string]map[string]map[PairKey]ConntrackEntry{
			"one": {"vm": {key: hit}},
			"two": {"vm": {key: hit}},
		},
		ProviderHitsDropped: map[string]map[string]uint64{
			"one": {"vm": 1_000_000},
			"two": {"vm": 2_000_000},
		},
	}
	if got := combinedThreatActiveFlows(agg, "vm"); got != 2 {
		t.Fatalf("legacy per-list duplicate tails inflated combined lower bound to %d, want retained union plus one overflow marker", got)
	}
}
