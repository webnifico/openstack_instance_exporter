package main

import (
	"maps"
	"net"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func TestThreatIntelligenceEnabledFamilySnapshotMatchesDualStackInventory(t *testing.T) {
	for _, enabledFamily := range []int{syscall.AF_INET, syscall.AF_INET6} {
		name := "IPv4-only"
		enabledIP, disabledIP, remoteIP := "10.0.0.10", "2001:db8::10", "198.51.100.10"
		changedEnabledIP, changedDisabledIP := "10.0.0.20", "2001:db8::20"
		if enabledFamily == syscall.AF_INET6 {
			name = "IPv6-only"
			enabledIP, disabledIP, remoteIP = "2001:db8::10", "10.0.0.10", "2001:db8:1::10"
			changedEnabledIP, changedDisabledIP = "2001:db8::20", "10.0.0.20"
		}
		t.Run(name, func(t *testing.T) {
			provider := newThreatStateTestProvider("EnabledFamily")
			provider.LastSuccess = float64(time.Now().Unix())
			provider.EntryCount = 1
			provider.Set = map[IPKey]struct{}{IPStrToKey(remoteIP): {}}
			provider.SetAtomic.Store(provider.Set)
			tm := newThreatStateTestManager(provider)
			cm := newConntrackManager(CollectorConfig{
				ConntrackIPv4Enable: enabledFamily == syscall.AF_INET,
				ConntrackIPv6Enable: enabledFamily == syscall.AF_INET6,
			})
			cm.conntrackDumpFamilyOverride = func(family int, _ int, _ time.Duration, consume func(ConntrackFlowLite)) (uint64, uint64, uint64, error) {
				if family != enabledFamily {
					t.Fatalf("disabled family %d was read", family)
				}
				consume(ConntrackFlowLite{SrcIP: IPStrToKey(enabledIP), DstIP: IPStrToKey(remoteIP), SrcPort: 41000, DstPort: 443, Proto: 6})
				return 1, 0, 0, nil
			}
			agg, count, err := cm.readAndAggregateConntrack([]VMIPIdentity{
				{InstanceUUID: "vm", IP: IPStrToKey(enabledIP)},
				{InstanceUUID: "vm", IP: IPStrToKey(disabledIP)},
			}, tm)
			if err != nil || count != 1 || len(agg.VMIndex) != 1 {
				t.Fatalf("enabled-family snapshot: count=%d aggregate=%+v error=%v", count, agg, err)
			}
			mc := &MetricsCollector{cm: cm, tm: tm}
			collect := func(snapshot *ConntrackAgg, ips map[string]struct{}, fresh bool) []prometheus.Metric {
				var metrics []prometheus.Metric
				mc.collectDomainThreatSignals(snapshot, ips, "domain", "server", "vm", "project", "project-name", "user", fresh, fresh, true, &metrics)
				return metrics
			}
			originalIPs := map[string]struct{}{enabledIP: {}, disabledIP: {}}
			metrics := collect(agg, originalIPs, true)
			if len(metrics) != 2 || threatIntelligenceMetricValue(t, metrics[0]) != 1 || provider.CountMap["vm"] != 1 {
				t.Fatalf("dual-stack inventory suppressed enabled-family threat: metrics=%d count=%v", len(metrics), provider.CountMap["vm"])
			}
			if len(collect(agg, originalIPs, false)) != 2 {
				t.Fatal("retained enabled-family snapshot lost its threat measurements")
			}
			for _, ips := range []map[string]struct{}{
				{changedEnabledIP: {}, disabledIP: {}},
				{enabledIP: {}, changedEnabledIP: {}, disabledIP: {}},
				{disabledIP: {}},
			} {
				if len(collect(agg, ips, false)) != 0 {
					t.Fatalf("retained snapshot accepted changed enabled-family membership: %v", ips)
				}
			}
			if len(collect(agg, map[string]struct{}{enabledIP: {}, changedDisabledIP: {}}, false)) != 2 {
				t.Fatal("unobserved disabled-family membership suppressed valid measurements")
			}
			extra := *agg
			extra.VMIndex = maps.Clone(agg.VMIndex)
			extra.VMIndex[VMIPIdentity{InstanceUUID: "vm", IP: IPStrToKey(changedEnabledIP)}] = 1
			if conntrackSnapshotMatchesInstanceIPs(&extra, "vm", originalIPs) {
				t.Fatal("snapshot with an extra removed enabled-family address matched inventory")
			}
			unscoped := *agg
			unscoped.ObservedFamilies = 0
			if conntrackSnapshotMatchesInstanceIPs(&unscoped, "vm", originalIPs) {
				t.Fatal("generic snapshot no longer requires its full inventory")
			}
		})
	}
}

func TestThreatIntelligenceObservationRecoverySilentlyRebaselines(t *testing.T) {
	for _, source := range []string{"conntrack", "instance-state"} {
		t.Run(source, func(t *testing.T) {
			logs := captureDataIntegrityStructuredLogs(t)
			mc := newDataIntegrityRetainedSemanticsCollector(t)
			provider := newThreatStateTestProvider("ObservationRecovery")
			late := newThreatStateTestProvider("LateObservation")
			mc.tm = newThreatStateTestManager(provider, late)
			const instanceUUID = "vm-observation-recovery"
			const vmIP = "10.0.0.10"
			ip := IPStrToKey(vmIP)
			meta := dataIntegrityRetainedMeta(instanceUUID, vmIP)
			now := time.Unix(100, 0)
			mc.cm.conntrackNowOverride = func() time.Time { return now }
			mc.tm.threatLogNowOverride = func() time.Time { return now }
			mc.tm.threatLogMinInterval = time.Hour
			collect := func(hitCount int, conntrackFresh, stateKnown, includeLate bool) []prometheus.Metric {
				hits := make(map[PairKey]ConntrackEntry, hitCount)
				for index := 0; index < hitCount; index++ {
					port := uint16(41000 + index)
					key := MakeConntrackPairKey(ip, port, IPStrToKey("198.51.100.10"), 443, 6, 0, 0, 0)
					hits[key] = ConntrackEntry{Src: vmIP, Dst: "198.51.100.10", SrcPort: port, DstPort: 443, Proto: 6}
				}
				connAgg := &ConntrackAgg{
					VMIndex:         map[VMIPIdentity]uint32{{InstanceUUID: instanceUUID, IP: ip}: 0},
					ObservationUnix: now.Unix(), ObservationTimeSet: true,
					InstanceFlowTotals: map[string]int{instanceUUID: hitCount},
					FlowsIn:            []int{0}, FlowsOut: []int{hitCount},
					OutboundStats:           []*behaviorStats{newBehaviorStats(false)},
					ProviderSourcesIncluded: map[string]struct{}{provider.Name: {}},
					ProviderHits: map[string]map[string]map[PairKey]ConntrackEntry{
						provider.Name: {instanceUUID: hits},
					},
				}
				if includeLate {
					connAgg.ProviderSourcesIncluded[late.Name] = struct{}{}
					connAgg.ProviderHits[late.Name] = map[string]map[PairKey]ConntrackEntry{instanceUUID: hits}
				}
				record := dataIntegrityRetainedRunningRecord()
				if !stateKnown {
					record.Params = nil
				}
				agg := &hostAgg{projects: make(map[string]struct{})}
				mc.collectDomainMetricsWithMetadata(record, meta, connAgg, nil, agg, 100_000, true, conntrackFresh)
				return agg.metrics
			}
			collect(1, true, true, false)
			if provider.CountMap[instanceUUID] != 1 {
				t.Fatal("initial complete observation did not count its contact")
			}
			now = time.Unix(150, 0)
			if source == "conntrack" {
				mc.cm.beginBehaviorStateFreeze(now)
				collect(1, false, true, false)
			} else {
				collect(3, true, false, false)
			}
			logs.Reset()
			now = time.Unix(20_000, 0)
			if source == "conntrack" {
				mc.tm.shiftThreatEventClock(mc.cm.resumeBehaviorStateClock(now))
			}
			metrics := collect(3, true, true, true)
			mc.cm.finishBehaviorRecoveryRebaseline()
			if provider.CountMap[instanceUUID] != 1 || len(provider.PrevHits[instanceUUID]) != 3 {
				t.Fatalf("recovery counted gap contacts or missed baseline: count=%v identities=%d", provider.CountMap[instanceUUID], len(provider.PrevHits[instanceUUID]))
			}
			if late.CountMap[instanceUUID] != 3 {
				t.Fatalf("first load of a previously unobserved list lost initial contacts: %v", late.CountMap[instanceUUID])
			}
			activeSeen := false
			for _, metric := range metrics {
				if metric.Desc() == provider.InstanceActiveFlowsDesc {
					activeSeen = threatIntelligenceMetricValue(t, metric) == 3
				}
			}
			if !activeSeen || strings.Contains(logs.String(), `"list":"`+provider.LogTag+`"`) {
				t.Fatalf("recovery lost current measurements or logged gap evidence: active=%v logs=%s", activeSeen, logs.String())
			}
			now = now.Add(15 * time.Second)
			collect(3, true, true, true)
			if provider.CountMap[instanceUUID] != 1 {
				t.Fatal("unchanged post-recovery observation counted gap contacts")
			}
			collect(4, true, true, true)
			if provider.CountMap[instanceUUID] != 2 {
				t.Fatal("real post-recovery contact was suppressed")
			}
			if mc.cm.behaviorInstanceNeedsRecoveryRebaseline(instanceUUID) {
				t.Fatal("completed instance recovery was not cleared")
			}
		})
	}
}

func TestThreatIntelligencePartialFeedGapRecoveryRebaselinesOnlyRecoveredList(t *testing.T) {
	for _, source := range []string{"provider", "spamhaus"} {
		for _, eligibleDuringGap := range []bool{false, true} {
			t.Run(source+"/eligible="+strconv.FormatBool(eligibleDuringGap), func(t *testing.T) {
				logs := captureDataIntegrityStructuredLogs(t)
				first := newThreatStateTestProvider("First")
				other := newThreatStateTestProvider("Other")
				tm := newThreatStateTestManager(first, other)
				mc := &MetricsCollector{tm: tm, threatSourceState: make(map[string]*ThreatSourceState)}
				ip := IPStrToKey("10.0.0.10")
				ipSet := map[string]struct{}{"10.0.0.10": {}}
				logNow := time.Unix(100, 0)
				tm.threatLogNowOverride = func() time.Time { return logNow }
				tm.threatLogMinInterval = time.Hour
				makeHits := func(port uint16) map[PairKey]ConntrackEntry {
					key := MakeConntrackPairKey(ip, port, IPStrToKey("198.51.100.10"), 443, 6, 0, 0, 0)
					return map[PairKey]ConntrackEntry{key: {
						Src: "10.0.0.10", Dst: "198.51.100.10", SrcPort: port, DstPort: 443, Proto: 6,
					}}
				}
				collect := func(includeFirst bool, firstPort, otherPort uint16, fresh, eligible bool) {
					agg := &ConntrackAgg{
						VMIndex:                 map[VMIPIdentity]uint32{{InstanceUUID: "vm", IP: ip}: 0},
						ObservationUnix:         logNow.Unix(),
						ProviderSourcesIncluded: map[string]struct{}{other.Name: {}},
						ProviderHits: map[string]map[string]map[PairKey]ConntrackEntry{
							other.Name: {"vm": makeHits(otherPort)},
						},
					}
					if includeFirst {
						if source == "spamhaus" {
							agg.SpamhausSourceIncluded = true
							agg.SpamhausHits = map[string]map[PairKey]ConntrackEntry{"vm": makeHits(firstPort)}
						} else {
							agg.ProviderSourcesIncluded[first.Name] = struct{}{}
							agg.ProviderHits[first.Name] = map[string]map[PairKey]ConntrackEntry{"vm": makeHits(firstPort)}
						}
					}
					var metrics []prometheus.Metric
					mc.collectDomainThreatSignals(agg, ipSet, "domain", "server", "vm", "project", "project-name", "user", fresh, eligible, true, &metrics)
				}
				firstCount := func() float64 {
					if source == "spamhaus" {
						return tm.spamCount["vm"]
					}
					return first.CountMap["vm"]
				}
				collect(true, 41000, 42000, true, true)
				collect(false, 41000, 42001, true, eligibleDuringGap)
				logs.Reset()
				logNow = time.Unix(20_000, 0)
				collect(true, 41001, 42002, true, true)
				if firstCount() != 1 {
					t.Fatalf("recovering list counted unobserved gap contacts: %v, want 1", firstCount())
				}
				wantOther := 2.0
				if eligibleDuringGap {
					wantOther = 3
				}
				if other.CountMap["vm"] != wantOther {
					t.Fatalf("continuously available list lost eligible contacts: %v, want %v", other.CountMap["vm"], wantOther)
				}
				tag := first.LogTag
				if source == "spamhaus" {
					tag = "spamhaus"
				}
				if strings.Contains(logs.String(), `"list":"`+tag+`"`) {
					t.Fatalf("recovering list emitted gap contacts: %s", logs.String())
				}
				logNow = logNow.Add(15 * time.Second)
				collect(true, 41001, 42002, true, true)
				if firstCount() != 1 || strings.Contains(logs.String(), `"list":"`+tag+`"`) {
					t.Fatal("unchanged post-recovery collection bypassed the silent baseline")
				}
				collect(true, 41002, 42002, true, true)
				if firstCount() != 2 {
					t.Fatalf("new post-recovery contact was suppressed: %v, want 2", firstCount())
				}
			})
		}
	}
}

func TestThreatIntelligenceFirstSuccessfulListLoadCountsContactsAfterOtherListGap(t *testing.T) {
	first := newThreatStateTestProvider("First")
	late := newThreatStateTestProvider("Late")
	tm := newThreatStateTestManager(first, late)
	mc := &MetricsCollector{tm: tm, threatSourceState: make(map[string]*ThreatSourceState)}
	ip := IPStrToKey("10.0.0.10")
	collect := func(provider *IPThreatProvider, port uint16, fresh bool) {
		agg := &ConntrackAgg{
			VMIndex:                 map[VMIPIdentity]uint32{{InstanceUUID: "vm", IP: ip}: 0},
			ProviderSourcesIncluded: make(map[string]struct{}),
		}
		if provider != nil {
			key := MakeConntrackPairKey(ip, port, IPStrToKey("198.51.100.10"), 443, 6, 0, 0, 0)
			agg.ProviderSourcesIncluded[provider.Name] = struct{}{}
			agg.ProviderHits = map[string]map[string]map[PairKey]ConntrackEntry{
				provider.Name: {"vm": {key: {Src: "10.0.0.10", Dst: "198.51.100.10", SrcPort: port, DstPort: 443, Proto: 6}}},
			}
		}
		var metrics []prometheus.Metric
		mc.collectDomainThreatSignals(agg, map[string]struct{}{"10.0.0.10": {}}, "domain", "server", "vm", "project", "project-name", "user", fresh, fresh, true, &metrics)
	}
	collect(first, 41000, true)
	// A retained aggregate cannot establish a source gap.
	collect(nil, 0, false)
	collect(first, 41001, true)
	if first.CountMap["vm"] != 2 {
		t.Fatal("retained aggregate incorrectly created a feed-recovery baseline")
	}
	collect(nil, 0, true)
	collect(late, 42000, true)
	if late.CountMap["vm"] != 1 {
		t.Fatal("provider's first successful load was treated as a recovery")
	}
	collect(first, 41002, true)
	if first.CountMap["vm"] != 2 {
		t.Fatal("known provider's delayed recovery counted gap contacts")
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
	mc := &MetricsCollector{tm: tm, threatSourceState: make(map[string]*ThreatSourceState)}
	makeAggregate := func(hitCount int) *ConntrackAgg {
		hits := make(map[PairKey]ConntrackEntry, hitCount)
		for index := 0; index < hitCount; index++ {
			port := uint16(41000 + index)
			pair := MakeConntrackPairKey(IPStrToKey(vmAddress), port, IPStrToKey(remote), 443, 6, 0, 0, 0)
			hits[pair] = ConntrackEntry{Src: vmAddress, Dst: remote, SrcPort: port, DstPort: 443, Proto: 6}
		}
		return &ConntrackAgg{
			VMIndex:                 map[VMIPIdentity]uint32{{InstanceUUID: instanceUUID, IP: IPStrToKey(vmAddress)}: 0},
			ObservationUnix:         100,
			ProviderSourcesIncluded: map[string]struct{}{provider.Name: {}},
			ProviderHits: map[string]map[string]map[PairKey]ConntrackEntry{
				provider.Name: {instanceUUID: hits},
			},
		}
	}

	mc.recordThreatObservation(instanceUUID, provider.Name)
	initial := *mc.threatSourceState[instanceUUID]
	initial.Lists = maps.Clone(initial.Lists)
	for _, hitCount := range []int{1, 10} {
		for range 3 {
			var metrics []prometheus.Metric
			mc.collectDomainThreatSignals(makeAggregate(hitCount), map[string]struct{}{vmAddress: {}},
				"domain", "server", instanceUUID, "project", "project-name", "user", true, false, true, &metrics)
			if len(metrics) != 2 || !reflect.DeepEqual(*mc.threatSourceState[instanceUUID], initial) {
				t.Fatal("retained collection changed source state or lost measurements")
			}
		}
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

	mc.resetThreatSourceStateForInstance(instanceUUID)
	metrics := make([]prometheus.Metric, 0, 2)
	mc.collectDomainThreatSignals(
		makeAggregate(10),
		map[string]struct{}{vmAddress: {}},
		"domain", "server", instanceUUID, "project", "project-name", "user",
		true,
		false,
		false,
		&metrics,
	)
	if len(metrics) != 0 {
		t.Fatal("unexpected measurement/lifecycle state: len(metrics) != 0")

	}
	if _, ok := mc.threatSourceState[instanceUUID]; ok {
		t.Fatal("stopped/reset retained collection recreated IntelHistory")
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
	mc := &MetricsCollector{tm: tm, threatSourceState: make(map[string]*ThreatSourceState)}
	vmIP := IPStrToKey(vmAddress)
	remoteIP := IPStrToKey(remote)
	ipSet := map[string]struct{}{vmAddress: {}}

	makeHits := func(count int) map[PairKey]ConntrackEntry {
		hits := make(map[PairKey]ConntrackEntry, count)
		for index := 0; index < count; index++ {
			sourcePort := uint16(41000 + index)
			key := MakeConntrackPairKey(vmIP, sourcePort, remoteIP, 443, 6, 0, 0, 0)
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
		}
		return agg
	}
	collect := func(agg *ConntrackAgg, snapshotFresh, updateState bool) int {
		metrics := make([]prometheus.Metric, 0, 2)
		mc.collectDomainThreatSignals(
			agg,
			ipSet,
			"domain", "server", instanceUUID, "project", "project-name", "user",
			snapshotFresh,
			updateState,
			true,
			&metrics,
		)
		return len(metrics)
	}

	baseline := makeAggregate(100, makeHits(1), true)
	if metricCount := collect(baseline, true, true); metricCount != 2 {
		t.Fatalf("unexpected source measurement count: %d", metricCount)
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
	if metricCount := collect(zeroSources, true, false); metricCount != 0 {
		t.Fatalf("unexpected source measurement count: %d", metricCount)
	}
	history := mc.threatSourceState[instanceUUID]
	if history == nil || len(history.Lists) != 1 || history.Lists[provider.Name] {
		t.Fatalf("fresh zero-source cycle did not freeze and mark history unavailable: %+v", history)
	}
	if metricCount := collect(zeroSources, false, false); metricCount != 0 {
		t.Fatalf("unexpected source measurement count: %d", metricCount)
	}

	// The first eligible source recovery is a complete new baseline, not a
	// accumulated event interval. Per-list identities reconcile without
	// counting or logging feed changes that happened during the gap.
	logNow = time.Unix(20_000, 0)
	recoveredHits := makeHits(8)
	recovered := makeAggregate(20_000, recoveredHits, true)
	if metricCount := collect(recovered, true, true); metricCount != 2 {
		t.Fatalf("unexpected source measurement count: %d", metricCount)
	}
	history = mc.threatSourceState[instanceUUID]
	if history == nil || !history.Lists[provider.Name] {
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
	if metricCount := collect(recovered, true, true); metricCount != 2 {
		t.Fatalf("unexpected source measurement count: %d", metricCount)
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

	mc := &MetricsCollector{tm: tm, threatSourceState: make(map[string]*ThreatSourceState)}
	metrics := make([]prometheus.Metric, 0, 10)
	mc.collectDomainThreatSignals(
		agg,
		map[string]struct{}{vmAddress: {}},
		"domain", "server", "vm", "project", "project-name", "user",
		true,
		true,
		true,
		&metrics,
	)

	if len(metrics) != 10 {
		t.Fatalf("per-list metrics for Spamhaus, Tor exit/relay, Emerging Threats, and custom were collapsed: got %d want 10", len(metrics))
	}
}
