package main

import (
	"strings"
	"testing"
	"time"

	libvirt "github.com/digitalocean/go-libvirt"
	"github.com/prometheus/client_golang/prometheus"
)

func newDataIntegrityRetainedSemanticsCollector(t *testing.T) *MetricsCollector {
	t.Helper()
	mc, err := NewMetricsCollector(CollectorConfig{
		LibvirtURI:             "qemu:///system",
		WorkerCount:            1,
		CollectionInterval:     time.Hour,
		ConntrackIPv4Enable:    true,
		OutboundBehaviorEnable: true,
		BehaviorSensitivity:    1,
		BehaviorThresholds: BehaviorThresholds{
			OutboundFlowsTotal: 2000,
		},
		Severity: SeverityConfig{
			ResourceWeight: 1,
			BehaviorWeight: 1,
		},
	})
	if err != nil {
		t.Fatalf("NewMetricsCollector: %v", err)
	}
	t.Cleanup(func() { close(mc.shutdownChan) })
	return mc
}

func dataIntegrityRetainedMetricNames(metrics []prometheus.Metric) map[string]struct{} {
	names := make(map[string]struct{}, len(metrics))
	for _, metric := range metrics {
		desc := metric.Desc().String()
		const marker = `fqName: "`
		start := strings.Index(desc, marker)
		if start < 0 {
			continue
		}
		start += len(marker)
		end := strings.IndexByte(desc[start:], '"')
		if end >= 0 {
			names[desc[start:start+end]] = struct{}{}
		}
	}
	return names
}

func dataIntegrityRetainedRunningRecord() libvirt.DomainStatsRecord {
	return libvirt.DomainStatsRecord{
		Dom: libvirt.Domain{Name: "instance-data-integrity-retained"},
		Params: []libvirt.TypedParam{
			typedParam("state.state", int32(libvirt.DomainRunning)),
			typedParam("balloon.maximum", uint64(1024*1024)),
			typedParam("balloon.current", uint64(1024*1024)),
			typedParam("balloon.usable", uint64(256*1024)),
		},
	}
}

func dataIntegrityRetainedMeta(instanceUUID string, fixedIPs ...string) *DomainStatic {
	ips := make([]IP, 0, len(fixedIPs))
	for _, address := range fixedIPs {
		ips = append(ips, IP{Address: address, Family: "ipv4"})
	}
	return &DomainStatic{
		Name:         "data-integrity-retained-server",
		InstanceUUID: instanceUUID,
		ProjectUUID:  "project",
		ProjectName:  "project-name",
		UserUUID:     "user",
		VCPUCount:    1,
		MemMB:        1024,
		FixedIPs:     ips,
		LastUpdated:  time.Now(),
	}
}

func TestDataIntegrityRetainedSnapshotRequiresExactFullVMIPIdentity(t *testing.T) {
	const (
		instanceUUID = "vm-retained-identity"
		matchingIP   = "10.0.0.10"
		currentIP    = "10.0.0.20"
		removedIP    = "10.0.0.30"
	)
	matchingKey := IPStrToKey(matchingIP)
	currentKey := IPStrToKey(currentIP)
	removedKey := IPStrToKey(removedIP)
	currentIPs := map[string]struct{}{matchingIP: {}, currentIP: {}}
	retained := &ConntrackAgg{
		VMIndex: map[VMIPIdentity]uint32{
			{InstanceUUID: instanceUUID, IP: matchingKey}: 0,
			{InstanceUUID: instanceUUID, IP: removedKey}:  1,
		},
		InstanceFlowTotals:      map[string]int{instanceUUID: 4},
		FlowsIn:                 []int{0, 0},
		FlowsOut:                []int{4, 0},
		OutboundStats:           []*behaviorStats{newBehaviorStats(false), newBehaviorStats(false)},
		ProviderSourcesIncluded: map[string]struct{}{"SnapshotProvider": {}},
	}

	if conntrackSnapshotMatchesInstanceIPs(retained, instanceUUID, currentIPs) {
		t.Fatal("retained snapshot with one current and one removed address matched the current full IP set")
	}

	provider := newThreatStateTestProvider("SnapshotProvider")
	tm := newThreatStateTestManager(provider)
	threatCollector := &MetricsCollector{tm: tm, intelHistory: make(map[string]*IntelHistory)}
	threatMetrics := make([]prometheus.Metric, 0)
	if score, available := threatCollector.collectDomainThreatSignals(
		retained,
		currentIPs,
		"domain", "server", instanceUUID, "project", "project-name", "user",
		false,
		false,
		true,
		&threatMetrics,
	); available || score != 0 || len(threatMetrics) != 0 {
		t.Fatalf("identity-mismatched retained threat snapshot reported available: score=%v available=%v metrics=%d", score, available, len(threatMetrics))
	}

	mc := newDataIntegrityRetainedSemanticsCollector(t)
	mc.cm.storeBehaviorSeverity(behaviorIdentityKey{InstanceUUID: instanceUUID, IP: matchingKey, Direction: "outbound"}, 0.8)
	mc.cm.storeBehaviorSeverity(behaviorIdentityKey{InstanceUUID: instanceUUID, IP: currentKey, Direction: "outbound"}, 0.8)
	agg := &hostAgg{projects: make(map[string]struct{})}
	mc.collectDomainMetricsWithMetadata(
		dataIntegrityRetainedRunningRecord(),
		dataIntegrityRetainedMeta(instanceUUID, matchingIP, currentIP),
		retained,
		nil,
		agg,
		100_000,
		true,
		false,
	)
	names := dataIntegrityRetainedMetricNames(agg.metrics)
	if _, ok := names["oie_instance_behavior_severity"]; ok {
		t.Fatal("identity-mismatched retained snapshot emitted instance behavior severity")
	}
}

func TestDataIntegrityRetainedThreatRosterDoesNotAcquireNewlyFreshProvider(t *testing.T) {
	const (
		instanceUUID = "vm-retained-roster"
		vmIP         = "10.0.0.40"
		remoteIP     = "198.51.100.40"
	)
	now := time.Now()
	snapshotProvider := newThreatStateTestProvider("SnapshotProvider")
	snapshotProvider.LastSuccess = float64(now.Unix())
	snapshotProvider.EntryCount = 1
	newProvider := newThreatStateTestProvider("NewlyFreshProvider")
	newProvider.LastSuccess = float64(now.Unix())
	newProvider.EntryCount = 1
	tm := newThreatStateTestManager(snapshotProvider, newProvider)
	mc := &MetricsCollector{tm: tm, intelHistory: make(map[string]*IntelHistory)}

	hitKey := MakePairKey(IPStrToKey(vmIP), 49152, IPStrToKey(remoteIP), 443, 6)
	retained := &ConntrackAgg{
		VMIndex: map[VMIPIdentity]uint32{
			{InstanceUUID: instanceUUID, IP: IPStrToKey(vmIP)}: 0,
		},
		ProviderSourcesIncluded: map[string]struct{}{snapshotProvider.Name: {}},
		ProviderHits: map[string]map[string]map[PairKey]ConntrackEntry{
			snapshotProvider.Name: {
				instanceUUID: {
					hitKey: {Src: vmIP, Dst: remoteIP, SrcPort: 49152, DstPort: 443, Proto: 6},
				},
			},
		},
	}
	metrics := make([]prometheus.Metric, 0)
	signal, available := mc.collectDomainThreatSignals(
		retained,
		map[string]struct{}{vmIP: {}},
		"domain", "server", instanceUUID, "project", "project-name", "user",
		false,
		false,
		true,
		&metrics,
	)
	if available || signal != 0 {
		t.Fatalf("retained snapshot without prior combined history signal=(%v,%v), want unavailable", signal, available)
	}
	names := dataIntegrityRetainedMetricNames(metrics)
	if _, ok := names[snapshotProvider.InstanceActiveMetricName]; !ok {
		t.Fatalf("retained snapshot omitted source %q that was present when captured", snapshotProvider.Name)
	}
	if _, ok := names[newProvider.InstanceActiveMetricName]; ok {
		t.Fatalf("retained snapshot acquired provider %q that became fresh later", newProvider.Name)
	}
	if _, ok := mc.snapshotIntelHistoryAvailable(instanceUUID); ok {
		t.Fatal("retained threat snapshot created new long-term intelligence history")
	}
	if _, ok := newProvider.CountMap[instanceUUID]; ok {
		t.Fatal("retained threat snapshot mutated newly fresh provider state")
	}
}

func TestDataIntegrityAttentionIsOmittedWhileWeightedConntrackInputIsStale(t *testing.T) {
	const (
		instanceUUID = "vm-retained-attention"
		vmIP         = "10.0.0.50"
	)
	mc := newDataIntegrityRetainedSemanticsCollector(t)
	ipKey := IPStrToKey(vmIP)
	mc.cm.storeBehaviorSeverity(behaviorIdentityKey{InstanceUUID: instanceUUID, IP: ipKey, Direction: "outbound"}, 0.75)
	retained := &ConntrackAgg{
		VMIndex: map[VMIPIdentity]uint32{
			{InstanceUUID: instanceUUID, IP: ipKey}: 0,
		},
		InstanceFlowTotals: map[string]int{instanceUUID: 6},
		FlowsIn:            []int{0},
		FlowsOut:           []int{6},
		OutboundStats:      []*behaviorStats{newBehaviorStats(false)},
	}
	agg := &hostAgg{projects: make(map[string]struct{})}
	mc.collectDomainMetricsWithMetadata(
		dataIntegrityRetainedRunningRecord(),
		dataIntegrityRetainedMeta(instanceUUID, vmIP),
		retained,
		nil,
		agg,
		100_000,
		true,
		false,
	)
	names := dataIntegrityRetainedMetricNames(agg.metrics)
	if _, ok := names["oie_instance_resource_severity"]; !ok {
		t.Fatal("test fixture did not provide the fresh resource input needed to expose attention renormalization")
	}
	if _, ok := names["oie_instance_behavior_severity"]; !ok {
		t.Fatal("test fixture did not retain the prior behavior severity")
	}
	if _, ok := names["oie_instance_attention_severity"]; ok {
		t.Fatal("attention severity was renormalized and emitted while its positively weighted Conntrack input was stale")
	}
}

func TestDataIntegrityRecoveryRebaselineOmitsBehaviorAndAttentionUntilACompleteInterval(t *testing.T) {
	const (
		instanceUUID = "vm-recovery-rebaseline"
		vmIP         = "10.0.0.55"
	)
	mc := newDataIntegrityRetainedSemanticsCollector(t)
	ipKey := IPStrToKey(vmIP)
	ident := behaviorIdentityKey{InstanceUUID: instanceUUID, IP: ipKey, Direction: "outbound"}
	mc.cm.storeBehaviorSeverity(ident, 0.9)
	mc.cm.beginBehaviorStateFreeze(time.Unix(1_700_000_000, 0))
	if delta := mc.cm.resumeBehaviorStateClock(time.Unix(1_700_000_030, 0)); delta != 30 {
		t.Fatalf("recovery clock delta=%d, want 30", delta)
	}

	stats := newBehaviorStats(false)
	stats.updateDetailedWithCoverage(IPStrToKey("198.51.100.55"), 8443, 6, IPS_SEEN_REPLY, 1, 0, 0, false, false)
	recovered := &ConntrackAgg{
		VMIndex: map[VMIPIdentity]uint32{
			{InstanceUUID: instanceUUID, IP: ipKey}: 0,
		},
		InstanceFlowTotals: map[string]int{instanceUUID: 1},
		FlowsIn:            []int{0},
		FlowsOut:           []int{1},
		OutboundStats:      []*behaviorStats{stats},
	}
	agg := &hostAgg{projects: make(map[string]struct{})}
	mc.collectDomainMetricsWithMetadata(
		dataIntegrityRetainedRunningRecord(),
		dataIntegrityRetainedMeta(instanceUUID, vmIP),
		recovered,
		nil,
		agg,
		100_000,
		true,
		true,
	)
	names := dataIntegrityRetainedMetricNames(agg.metrics)
	if _, ok := names["oie_instance_resource_severity"]; !ok {
		t.Fatal("test fixture did not emit its independent fresh resource severity")
	}
	if _, ok := names["oie_instance_outbound_flows"]; !ok {
		t.Fatal("recovery rebaseline did not emit the current raw behavior observation")
	}
	for _, name := range []string{
		"oie_instance_behavior_severity",
		"oie_instance_attention_severity",
		"oie_instance_mining_suspected",
	} {
		if _, ok := names[name]; ok {
			t.Fatalf("recovery rebaseline emitted %s before a complete post-recovery interval", name)
		}
	}
	if _, available := mc.cm.behaviorSeveritySnapshotAvailable(ident); available {
		t.Fatal("recovery rebaseline retained the pre-outage behavior severity as fresh")
	}
}

func TestDataIntegritySuppressedResourceTransitionDoesNotBecomeARecoveryEvent(t *testing.T) {
	buf := captureDataIntegrityStructuredLogs(t)
	mc := &MetricsCollector{
		collectionInterval: 15 * time.Second,
		resourceV2:         make(map[string]*resourceV2State),
	}
	base := time.Unix(1_700_000_000, 0)
	var stale resourceV2Output
	var state *resourceV2State
	for cycle := 0; cycle < 3; cycle++ {
		stale, state = mc.computeResourceV2("vm-resource-recovery", resourceV2Input{
			Now:          base.Add(time.Duration(cycle) * 15 * time.Second),
			CpuAvailable: true,
			CpuPRaw:      1,
			CpuConf:      1,
			CpuImpact:    1,
		})
		syncResourceV2EventState(stale, state)
	}
	if !stale.PersistenceTriggered {
		t.Fatal("test fixture did not cross the resource persistence threshold during the suppressed interval")
	}
	if buf.Len() != 0 {
		t.Fatalf("silent stale-state synchronization logged a resource event: %s", buf.String())
	}

	recovered, state := mc.computeResourceV2("vm-resource-recovery", resourceV2Input{
		Now:          base.Add(45 * time.Second),
		CpuAvailable: true,
		CpuPRaw:      1,
		CpuConf:      1,
		CpuImpact:    1,
	})
	if recovered.PersistenceTriggered {
		t.Fatal("resource persistence transition retriggered on recovery")
	}
	mc.maybeLogResourceV2Event(
		"domain", "server", "vm-resource-recovery", "project", "project-name", "user",
		recovered,
		state,
	)
	if buf.Len() != 0 {
		t.Fatalf("suppressed stale resource transition surfaced as a recovery event: %s", buf.String())
	}
}

func TestDataIntegrityRetainedBehaviorWithoutPriorSeverityIsUnavailable(t *testing.T) {
	const (
		instanceUUID = "vm-retained-no-behavior-history"
		vmIP         = "10.0.0.60"
	)
	mc := newDataIntegrityRetainedSemanticsCollector(t)
	ipKey := IPStrToKey(vmIP)
	retained := &ConntrackAgg{
		VMIndex: map[VMIPIdentity]uint32{
			{InstanceUUID: instanceUUID, IP: ipKey}: 0,
		},
		InstanceFlowTotals: map[string]int{instanceUUID: 0},
		FlowsIn:            []int{0},
		FlowsOut:           []int{0},
		OutboundStats:      []*behaviorStats{newBehaviorStats(false)},
	}
	agg := &hostAgg{projects: make(map[string]struct{})}
	mc.collectDomainMetricsWithMetadata(
		dataIntegrityRetainedRunningRecord(),
		dataIntegrityRetainedMeta(instanceUUID, vmIP),
		retained,
		nil,
		agg,
		100_000,
		true,
		false,
	)
	names := dataIntegrityRetainedMetricNames(agg.metrics)
	for _, name := range []string{
		"oie_instance_outbound_flows",
		"oie_instance_outbound_unique_remotes",
		"oie_instance_outbound_new_remotes",
		"oie_instance_behavior_severity",
	} {
		if _, ok := names[name]; ok {
			t.Fatalf("retained behavior with no prior severity emitted healthy-looking family %s", name)
		}
	}
	if _, ok := names["oie_instance_conntrack_ip_flows"]; !ok {
		t.Fatal("test fixture did not emit the retained raw Conntrack sample")
	}
}

func TestDataIntegrityConntrackFreezeDoesNotShiftHostThreatThrottle(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	hostKey := hostThreatThrottlePrefix + "TOR_EXIT|203.0.113.10"
	flowKey := "TOREXIT|vm|10.0.0.70|203.0.113.10|443"
	tm := &ThreatManager{threatLastHit: map[string]time.Time{
		hostKey: base,
		flowKey: base,
	}}

	tm.shiftThreatEventClock(90)

	if got := tm.threatLastHit[hostKey]; !got.Equal(base) {
		t.Fatalf("Conntrack recovery shifted live host threat throttle from %v to %v", base, got)
	}
	if got := tm.threatLastHit[flowKey]; !got.Equal(base.Add(90 * time.Second)) {
		t.Fatalf("Conntrack-derived threat clock=%v, want %v", got, base.Add(90*time.Second))
	}
}
