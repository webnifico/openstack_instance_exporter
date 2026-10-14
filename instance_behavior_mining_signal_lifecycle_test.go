package main

import (
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

type capturedBehaviorSignal map[string]interface{}

func captureBehaviorSignals(cm *ConntrackManager) *[]capturedBehaviorSignal {
	events := make([]capturedBehaviorSignal, 0, 2)
	cm.LogThreat = func(tag, event, domain, instanceUUID, projectUUID, projectName, userUUID string, kvpairs ...interface{}) {
		fields := capturedBehaviorSignal{
			"tag":   tag,
			"event": event,
		}
		for i := 0; i+1 < len(kvpairs); i += 2 {
			key, ok := kvpairs[i].(string)
			if ok {
				fields[key] = kvpairs[i+1]
			}
		}
		events = append(events, fields)
	}
	return &events
}

func analyzeMiningSignalTestCycle(cm *ConntrackManager, stats *behaviorStats, instanceUUID string) {
	analyzeMiningSignalTestCycleWithState(cm, stats, instanceUUID, nil, false)
}

func analyzeMiningSignalTestCycleWithState(cm *ConntrackManager, stats *behaviorStats, instanceUUID string, metrics *[]prometheus.Metric, freeze bool) {
	ident := behaviorIdentityKey{InstanceUUID: instanceUUID, IP: IPStrToKey("10.0.0.10"), Direction: "outbound"}
	observationUnix := int64(100)
	cm.behaviorSignalMu.Lock()
	if state := cm.miningSignals[ident]; state != nil && state.LastSeenUnix >= observationUnix {
		observationUnix = state.LastSeenUnix + behaviorPersistenceReferenceSeconds
	}
	cm.behaviorSignalMu.Unlock()
	cm.analyzeBehavior(
		stats,
		IPStrToKey("10.0.0.10"),
		"10.0.0.10", "ipv4", "domain", "server", instanceUUID, "project", "project-name", "user",
		metrics,
		metricDescGroup{thresholdConfigKey: "outbound"},
		BehaviorContext{ObservationUnix: observationUnix, FreezeState: freeze},
	)
}

func appendMiningSignalTestFlow(stats *behaviorStats, remote IPKey, port uint16, status uint32) {
	stats.updateDetailedWithCoverage(remote, port, 6, status, 1, 0, 0, false, false)
	stats.updateOutboundMining(remote, port, 6, status, true)
}

func TestMiningSignalLifecycleUsesMiningEndpointWhenWebTrafficDominates(t *testing.T) {
	cm := newBehaviorStateTestManager()
	cm.behaviorOutboundPortNames = builtinBehaviorOutboundMonitoredPorts()
	events := captureBehaviorSignals(cm)
	stats := newBehaviorStats(false)

	webRemote := IPStrToKey("198.51.100.10")
	for i := 0; i < 499; i++ {
		appendMiningSignalTestFlow(stats, webRemote, 443, IPS_SEEN_REPLY)
	}
	miningRemote := IPStrToKey("198.51.100.44")
	appendMiningSignalTestFlow(stats, miningRemote, 10128, IPS_SEEN_REPLY)
	appendMiningSignalTestFlow(stats, miningRemote, 10128, IPS_SEEN_REPLY)

	for cycle := 1; cycle <= 3; cycle++ {
		analyzeMiningSignalTestCycle(cm, stats, "vm-web-dominant")
		if cycle < 3 && len(*events) != 0 {
			t.Fatalf("cycle %d emitted before the mining persistence gate: %#v", cycle, *events)
		}
	}

	if len(*events) != 1 {
		t.Fatalf("mining signal count=%d, want 1: %#v", len(*events), *events)
	}
	event := (*events)[0]
	if event["signal"] != "outbound_stratum_mining_suspected" {
		t.Fatalf("signal=%v, want mining classification: %#v", event["signal"], event)
	}
	if event["top_dst_port"] != 10128 || event["top_dst_port_name"] != "moneroocean_randomx_stratum" {
		t.Fatalf("mining endpoint=%v/%v, want 10128/moneroocean_randomx_stratum: %#v", event["top_dst_port"], event["top_dst_port_name"], event)
	}
	if event["dst_ip"] != "198.51.100.44" {
		t.Fatalf("mining destination=%v, want 198.51.100.44: %#v", event["dst_ip"], event)
	}
}

func TestMiningSignalPersistsIndependentlyOfEarlierScanClassification(t *testing.T) {
	cm := newBehaviorStateTestManager()
	cm.behaviorOutboundPortNames = builtinBehaviorOutboundMonitoredPorts()
	events := captureBehaviorSignals(cm)
	stats := newBehaviorStats(false)

	for i := 1; i <= 30; i++ {
		remote := IPKey{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 198, 51, 100, byte(i)}
		appendMiningSignalTestFlow(stats, remote, 22, 0)
	}
	appendMiningSignalTestFlow(stats, IPStrToKey("203.0.113.44"), 10128, IPS_ASSURED)
	appendMiningSignalTestFlow(stats, IPStrToKey("203.0.113.44"), 10128, IPS_ASSURED)

	for cycle := 0; cycle < 3; cycle++ {
		analyzeMiningSignalTestCycle(cm, stats, "vm-scan-and-mining")
	}

	foundMining := false
	foundScan := false
	for _, event := range *events {
		switch event["signal"] {
		case "outbound_stratum_mining_suspected":
			foundMining = true
		case "outbound_horizontal_scan_suspected":
			foundScan = true
		}
	}
	if !foundMining || !foundScan {
		t.Fatalf("simultaneous scan/mining did not preserve both lifecycles: mining=%v scan=%v events=%#v", foundMining, foundScan, *events)
	}
}

func TestConfirmedMiningExportsDedicatedMetricAndFreezesLastGoodState(t *testing.T) {
	cm := newBehaviorStateTestManager()
	cm.behaviorOutboundPortNames = builtinBehaviorOutboundMonitoredPorts()
	events := captureBehaviorSignals(cm)
	stats := newBehaviorStats(false)
	appendMiningSignalTestFlow(stats, IPStrToKey("198.51.100.44"), 10128, IPS_SEEN_REPLY)
	appendMiningSignalTestFlow(stats, IPStrToKey("198.51.100.44"), 10128, IPS_SEEN_REPLY)

	for cycle := 1; cycle <= 3; cycle++ {
		metrics := make([]prometheus.Metric, 0, 1)
		analyzeMiningSignalTestCycleWithState(cm, stats, "vm-mining-metric", &metrics, false)
		if cycle < 3 && len(metrics) != 0 {
			t.Fatalf("cycle %d exported mining metric before persistence: %d metrics", cycle, len(metrics))
		}
		if cycle == 3 {
			assertMiningMetric(t, metrics)
		}
	}
	if len(*events) != 1 {
		t.Fatalf("mining signal events=%d, want 1", len(*events))
	}

	frozenMetrics := make([]prometheus.Metric, 0, 1)
	analyzeMiningSignalTestCycleWithState(cm, stats, "vm-mining-metric", &frozenMetrics, true)
	assertMiningMetric(t, frozenMetrics)
	if len(*events) != 1 {
		t.Fatalf("frozen conntrack state emitted another mining event: %#v", *events)
	}

	cleanMetrics := make([]prometheus.Metric, 0, 1)
	analyzeMiningSignalTestCycleWithState(cm, newBehaviorStats(false), "vm-mining-metric", &cleanMetrics, false)
	if len(cleanMetrics) != 0 {
		t.Fatalf("fresh clean conntrack state retained mining metric: %d metrics", len(cleanMetrics))
	}
}

func assertMiningMetric(t *testing.T, metrics []prometheus.Metric) {
	t.Helper()
	if len(metrics) != 1 {
		t.Fatalf("mining metrics=%d, want 1", len(metrics))
	}
	if !strings.Contains(metrics[0].Desc().String(), `fqName: "oie_instance_mining_suspected"`) {
		t.Fatalf("unexpected mining metric descriptor: %s", metrics[0].Desc())
	}
	var metric dto.Metric
	if err := metrics[0].Write(&metric); err != nil {
		t.Fatal(err)
	}
	labels := make(map[string]string, len(metric.Label))
	for _, pair := range metric.Label {
		labels[pair.GetName()] = pair.GetValue()
	}
	for name, want := range map[string]string{
		"ip":         "10.0.0.10",
		"family":     "ipv4",
		"port":       "10128",
		"port_name":  "moneroocean_randomx_stratum",
		"confidence": "high",
	} {
		if labels[name] != want {
			t.Fatalf("mining metric label %s=%q, want %q; labels=%v", name, labels[name], want, labels)
		}
	}
	if metric.GetGauge().GetValue() != 1 {
		t.Fatalf("mining metric value=%v, want 1", metric.GetGauge().GetValue())
	}
}

func assertMiningMetricLabels(t *testing.T, metrics []prometheus.Metric, want map[string]string) {
	t.Helper()
	if len(metrics) != 1 {
		t.Fatalf("mining metrics=%d, want 1", len(metrics))
	}
	var metric dto.Metric
	if err := metrics[0].Write(&metric); err != nil {
		t.Fatal(err)
	}
	labels := make(map[string]string, len(metric.Label))
	for _, pair := range metric.Label {
		labels[pair.GetName()] = pair.GetValue()
	}
	for name, value := range want {
		if labels[name] != value {
			t.Fatalf("mining metric label %s=%q, want %q; labels=%v", name, labels[name], value, labels)
		}
	}
}

func miningSignalStateFeature(confidence miningPortConfidence, remote string, flows, replied int) BehaviorFeature {
	remoteKey := IPStrToKey(remote)
	return BehaviorFeature{
		Direction:         "outbound",
		Flows:             maxInt(flows, 1),
		UniqueRemotes:     1,
		UniqueDstPorts:    1,
		MaxSingleRemote:   maxInt(flows, 1),
		MaxSingleDstPort:  maxInt(flows, 1),
		TopDstPort:        10128,
		HostImpactPercent: 100,
		UnrepliedRatio:    0.90,
		Mining: miningDetectionEvidence{
			Valid:      true,
			Confidence: confidence,
			miningTierSummary: miningTierSummary{
				Flows:            flows,
				RepliedFlows:     replied,
				UniqueRemotes:    1,
				UniquePorts:      1,
				TopPort:          10128,
				TopPairFlows:     flows,
				TopPairReplied:   replied,
				TopPortFlows:     flows,
				TopPortReplied:   replied,
				TopRemote:        remoteKey,
				TopRemoteFlows:   flows,
				TopRemoteReplied: replied,
			},
		},
	}
}

func TestDedicatedMiningRequiresThreeObservationsDespiteUnrelatedTraffic(t *testing.T) {
	cm := newBehaviorStateTestManager()
	feature := miningSignalStateFeature(miningPortConfidenceHigh, "198.51.100.40", 2, 2)
	feature.Flows = 1_000_000
	ident := behaviorIdentityKey{InstanceUUID: "vm-dedicated", IP: IPStrToKey("10.0.0.20"), Direction: "outbound"}
	for cycle := 0; cycle < 3; cycle++ {
		got := cm.updateMiningSignalState(feature, ident, 100+int64(cycle)*15)
		if got.PersistenceRequired != 3 || got.PersistenceMinimumElapsedSeconds != 30 {
			t.Fatalf("unexpected persistence gate: %+v", got)
		}
		if cycle < 2 && (got.Confirmed || got.ShouldEmit) {
			t.Fatalf("brief burst qualified: %+v", got)
		}
		if cycle == 2 && (!got.Confirmed || !got.ShouldEmit || got.EmitReason != "new_signal") {
			t.Fatalf("sustained endpoint failed to qualify: %+v", got)
		}
	}
}

func TestSharedMiningRequiresThreeCycles(t *testing.T) {
	cm := newBehaviorStateTestManager()
	feature := miningSignalStateFeature(miningPortConfidenceShared, "198.51.100.41", 3, 2)
	feature.Mining.TopPort = 5555
	ident := behaviorIdentityKey{InstanceUUID: "vm-shared", IP: IPStrToKey("10.0.0.21"), Direction: "outbound"}

	for cycle := int64(1); cycle <= 3; cycle++ {
		outcome := cm.updateMiningSignalState(feature, ident, 100+(cycle-1)*15)
		if outcome.PersistenceRequired != 3 {
			t.Fatalf("shared cycle %d persistence=%d, want 3", cycle, outcome.PersistenceRequired)
		}
		if cycle < 3 && outcome.Confirmed {
			t.Fatalf("shared mining confirmed on cycle %d: %+v", cycle, outcome)
		}
		if cycle == 3 && (!outcome.Confirmed || outcome.ShouldEmit || outcome.SuppressReason != "corroboration_required") {
			t.Fatalf("shared mining candidate outcome on third cycle: %+v", outcome)
		}
		if cycle == 3 && (outcome.PersistenceElapsedSeconds != 30 || outcome.PersistenceMinimumElapsedSeconds != 30) {
			t.Fatalf("shared mining elapsed gate=%+v, want 30 seconds", outcome)
		}
	}
}

func TestCandidatePromotionToHighEmitsStructuredSignal(t *testing.T) {
	cm := newBehaviorStateTestManager()
	ident := behaviorIdentityKey{InstanceUUID: "vm-promotion", IP: IPStrToKey("10.0.0.29"), Direction: "outbound"}
	candidate := miningSignalStateFeature(miningPortConfidenceHighPersistent, "198.51.100.49", 1, 1)
	for cycle, now := range []int64{100, 115, 130} {
		outcome := cm.updateMiningSignalState(candidate, ident, now)
		if cycle == 2 && (!outcome.Confirmed || outcome.ShouldEmit || outcome.SuppressReason != "corroboration_required") {
			t.Fatalf("candidate confirmation=%+v", outcome)
		}
	}

	high := miningSignalStateFeature(miningPortConfidenceHigh, "198.51.100.49", 2, 2)
	outcome := cm.updateMiningSignalState(high, ident, 145)
	if !outcome.Confirmed || !outcome.ShouldEmit || outcome.EmitReason != "new_signal" {
		t.Fatalf("promoted high evidence did not emit: %+v", outcome)
	}
}

func TestSinglePersistentSharedMiningConnectionExportsCandidate(t *testing.T) {
	cm := newBehaviorStateTestManager()
	cm.behaviorOutboundPortNames = builtinBehaviorOutboundMonitoredPorts()
	events := captureBehaviorSignals(cm)
	stats := newBehaviorStats(false)
	appendMiningSignalTestFlow(stats, IPStrToKey("198.51.100.77"), 7777, IPS_SEEN_REPLY|IPS_ASSURED)

	for cycle := 1; cycle <= 6; cycle++ {
		metrics := make([]prometheus.Metric, 0, 1)
		analyzeMiningSignalTestCycleWithState(cm, stats, "vm-single-shared", &metrics, false)
		if cycle < 6 && len(metrics) != 0 {
			t.Fatalf("cycle %d exported a single-flow shared candidate early", cycle)
		}
		if cycle == 6 {
			assertMiningMetricLabels(t, metrics, map[string]string{
				"port":       "7777",
				"port_name":  "common_randomx_stratum",
				"confidence": "shared_persistent",
			})
		}
	}
	if len(*events) != 0 {
		t.Fatalf("uncorroborated shared-port candidate emitted a structured signal: %#v", *events)
	}
}

func TestMultipleSharedPortConnectionsRemainCorroboratedCandidates(t *testing.T) {
	cm := newBehaviorStateTestManager()
	cm.behaviorOutboundPortNames = builtinBehaviorOutboundMonitoredPorts()
	events := captureBehaviorSignals(cm)
	stats := newBehaviorStats(false)
	for i := 0; i < 3; i++ {
		appendMiningSignalTestFlow(stats, IPStrToKey("198.51.100.79"), 7777, IPS_SEEN_REPLY|IPS_ASSURED)
	}

	for cycle := 1; cycle <= 3; cycle++ {
		metrics := make([]prometheus.Metric, 0, 1)
		analyzeMiningSignalTestCycleWithState(cm, stats, "vm-multiple-shared", &metrics, false)
		if cycle == 3 {
			assertMiningMetricLabels(t, metrics, map[string]string{
				"port":       "7777",
				"confidence": "shared",
			})
		}
	}
	if len(*events) != 0 {
		t.Fatalf("uncorroborated ambiguous-port evidence emitted a structured signal: %#v", *events)
	}
}

func TestSingleDedicatedPortConnectionExportsCandidateWithoutStructuredSignal(t *testing.T) {
	cm := newBehaviorStateTestManager()
	cm.behaviorOutboundPortNames = builtinBehaviorOutboundMonitoredPorts()
	events := captureBehaviorSignals(cm)
	stats := newBehaviorStats(false)
	appendMiningSignalTestFlow(stats, IPStrToKey("198.51.100.78"), 10128, IPS_SEEN_REPLY|IPS_ASSURED)

	for cycle := 1; cycle <= 3; cycle++ {
		metrics := make([]prometheus.Metric, 0, 1)
		analyzeMiningSignalTestCycleWithState(cm, stats, "vm-single-dedicated", &metrics, false)
		if cycle == 3 {
			assertMiningMetricLabels(t, metrics, map[string]string{
				"port":       "10128",
				"confidence": "high_persistent",
			})
		}
	}
	if len(*events) != 0 {
		t.Fatalf("uncorroborated dedicated-port candidate emitted a structured signal: %#v", *events)
	}
}

func TestMiningPersistenceRequiresStableEndpoint(t *testing.T) {
	cm := newBehaviorStateTestManager()
	ident := behaviorIdentityKey{InstanceUUID: "vm-changing-endpoint", IP: IPStrToKey("10.0.0.30"), Direction: "outbound"}

	first := miningSignalStateFeature(miningPortConfidenceHigh, "198.51.100.40", 1, 1)
	second := miningSignalStateFeature(miningPortConfidenceHigh, "198.51.100.41", 1, 1)
	third := miningSignalStateFeature(miningPortConfidenceHigh, "198.51.100.42", 1, 1)

	if outcome := cm.updateMiningSignalState(first, ident, 100); outcome.PersistenceHits != 1 || outcome.Confirmed {
		t.Fatalf("first endpoint outcome=%+v", outcome)
	}
	if outcome := cm.updateMiningSignalState(second, ident, 115); outcome.PersistenceHits != 1 || outcome.Confirmed {
		t.Fatalf("changed endpoint reused persistence: %+v", outcome)
	}
	if outcome := cm.updateMiningSignalState(third, ident, 130); outcome.PersistenceHits != 1 || outcome.Confirmed {
		t.Fatalf("third endpoint reused persistence: %+v", outcome)
	}
}

func TestConfirmedMiningPoolSwitchKeepsOldPublicationUntilNewPairQualifies(t *testing.T) {
	cm := newBehaviorStateTestManager()
	ident := behaviorIdentityKey{InstanceUUID: "vm-pool-switch", IP: IPStrToKey("10.0.0.32"), Direction: "outbound"}
	firstPool := miningSignalStateFeature(miningPortConfidenceHigh, "198.51.100.80", 2, 2)
	firstPool.HostImpactPercent = 0
	firstPool.UnrepliedRatio = 0

	for _, now := range []int64{100, 115, 130} {
		outcome := cm.updateMiningSignalState(firstPool, ident, now)
		if now == 130 && (!outcome.Active || outcome.Evidence.TopRemote != firstPool.Mining.TopRemote) {
			t.Fatalf("initial pool did not confirm: %+v", outcome)
		}
	}

	secondPool := miningSignalStateFeature(miningPortConfidenceHigh, "198.51.100.81", 2, 2)
	secondPool.HostImpactPercent = 0
	secondPool.UnrepliedRatio = 0
	secondPool.TopDstPort = 14433
	secondPool.Mining.TopPort = 14433
	for cycle, now := range []int64{145, 160, 175} {
		outcome := cm.updateMiningSignalState(secondPool, ident, now)
		if !outcome.Active || !outcome.Confirmed {
			t.Fatalf("pool switch made confirmed episode disappear at cycle %d: %+v", cycle+1, outcome)
		}
		if cycle < 2 && outcome.Evidence.TopRemote != firstPool.Mining.TopRemote {
			t.Fatalf("new pool published before independent qualification at cycle %d: %+v", cycle+1, outcome)
		}
		if cycle == 2 && outcome.Evidence.TopRemote != secondPool.Mining.TopRemote {
			t.Fatalf("qualified replacement pool was not published: %+v", outcome)
		}
		metrics := make([]prometheus.Metric, 0, 1)
		cm.appendMiningMetric(
			&metrics,
			outcome,
			"domain", "server", ident.InstanceUUID, "project", "project-name", "user", "10.0.0.32", "ipv4",
		)
		wantPort := "10128"
		if cycle == 2 {
			wantPort = "14433"
		}
		assertMiningMetricLabels(t, metrics, map[string]string{"port": wantPort, "confidence": "high"})
	}

	if outcome := cm.updateMiningSignalState(BehaviorFeature{Direction: "outbound"}, ident, 190); outcome.Active {
		t.Fatalf("complete clean collection did not clear switched mining episode: %+v", outcome)
	}
	if snapshot := cm.miningSignalSnapshot(ident); snapshot.Active {
		t.Fatalf("clean collection left a published mining snapshot: %+v", snapshot)
	}
}

func TestMiningRecoveryReconcilesWithoutAdvancingPersistence(t *testing.T) {
	cm := newBehaviorStateTestManager()
	ident := behaviorIdentityKey{InstanceUUID: "vm-mining-recovery", IP: IPStrToKey("10.0.0.33"), Direction: "outbound"}
	firstPool := miningSignalStateFeature(miningPortConfidenceHigh, "198.51.100.82", 2, 2)
	firstPool.HostImpactPercent = 0
	firstPool.UnrepliedRatio = 0
	for _, now := range []int64{100, 115, 130} {
		cm.updateMiningSignalState(firstPool, ident, now)
	}

	before := *cm.miningSignals[ident]
	same := cm.reconcileMiningRecovery(firstPool, ident, 145)
	afterSame := cm.miningSignals[ident]
	if !same.Active || same.Evidence.TopRemote != firstPool.Mining.TopRemote {
		t.Fatalf("same positive recovery did not preserve active publication: %+v", same)
	}
	if afterSame.Hits != before.Hits || afterSame.FirstSeenUnix != before.FirstSeenUnix || afterSame.LastSeenUnix != before.LastSeenUnix {
		t.Fatalf("same positive recovery advanced persistence: before=%+v after=%+v", before, *afterSame)
	}

	secondPool := miningSignalStateFeature(miningPortConfidenceHigh, "198.51.100.83", 2, 2)
	secondPool.HostImpactPercent = 0
	secondPool.UnrepliedRatio = 0
	changed := cm.reconcileMiningRecovery(secondPool, ident, 145)
	state := cm.miningSignals[ident]
	if !changed.Active || changed.Evidence.TopRemote != firstPool.Mining.TopRemote {
		t.Fatalf("changed positive recovery dropped old confirmed publication: %+v", changed)
	}
	if state.Hits != 0 || state.FirstSeenUnix != 0 || state.LastSeenUnix != 0 ||
		state.CandidateTopRemote != secondPool.Mining.TopRemote || state.Evidence.TopRemote != firstPool.Mining.TopRemote {
		t.Fatalf("changed positive recovery did not reset only replacement qualification: %+v", *state)
	}

	clean := cm.reconcileMiningRecovery(BehaviorFeature{Direction: "outbound"}, ident, 145)
	if clean.Active || cm.miningSignalSnapshot(ident).Active {
		t.Fatalf("clean recovery retained active mining state: outcome=%+v state=%+v", clean, *cm.miningSignals[ident])
	}
}

func TestMiningRecoveryChangedPairClearsUnconfirmedCandidate(t *testing.T) {
	cm := newBehaviorStateTestManager()
	ident := behaviorIdentityKey{InstanceUUID: "vm-mining-recovery-pending", IP: IPStrToKey("10.0.0.34"), Direction: "outbound"}
	firstPool := miningSignalStateFeature(miningPortConfidenceHigh, "198.51.100.84", 2, 2)
	cm.updateMiningSignalState(firstPool, ident, 100)

	secondPool := miningSignalStateFeature(miningPortConfidenceHigh, "198.51.100.85", 2, 2)
	if outcome := cm.reconcileMiningRecovery(secondPool, ident, 115); outcome.Active {
		t.Fatalf("unconfirmed recovery pair change became active: %+v", outcome)
	}
	state := cm.miningSignals[ident]
	if state.Hits != 0 || state.Confirmed || state.Active || state.CandidateTopRemote != (IPKey{}) || state.CandidateTopDstPort != 0 {
		t.Fatalf("unconfirmed recovery pair change retained stale candidate: %+v", *state)
	}
}

func TestMiningRecoveryEndpointSwitchSurvivesCleanupAndRequalifies(t *testing.T) {
	cm := newBehaviorStateTestManager()
	ident := behaviorIdentityKey{InstanceUUID: "vm-mining-recovery-cleanup", IP: IPStrToKey("10.0.0.35"), Direction: "outbound"}
	firstPool := miningSignalStateFeature(miningPortConfidenceHigh, "198.51.100.88", 2, 2)
	firstPool.Flows = 1_000_000
	secondPool := miningSignalStateFeature(miningPortConfidenceHigh, "198.51.100.89", 2, 2)
	secondPool.Flows = 1_000_000
	secondPool.TopDstPort = 14433
	secondPool.Mining.TopPort = 14433
	nowUnix := time.Now().Unix()

	cm.updateMiningSignalState(firstPool, ident, nowUnix-45)
	cm.updateMiningSignalState(firstPool, ident, nowUnix-30)
	confirmed := cm.updateMiningSignalState(firstPool, ident, nowUnix-15)
	if !confirmed.Active || !confirmed.Confirmed {
		t.Fatalf("initial pool did not confirm: %+v", confirmed)
	}

	recovery := cm.reconcileMiningRecovery(secondPool, ident, nowUnix)
	if !recovery.Active || recovery.Evidence.TopRemote != firstPool.Mining.TopRemote {
		t.Fatalf("changed recovery did not retain old publication: %+v", recovery)
	}
	state := cm.miningSignals[ident]
	if state == nil || state.LastSeenUnix != 0 || state.LastRecoveryObservationUnix != nowUnix || !state.Active || !state.Confirmed {
		t.Fatalf("changed recovery state=%+v, want active publication with a zero replacement clock", state)
	}

	cm.cleanupBehaviorStateWithAging(map[string]struct{}{ident.InstanceUUID: {}}, false)
	if snapshot := cm.miningSignalSnapshot(ident); !snapshot.Active || snapshot.Evidence.TopRemote != firstPool.Mining.TopRemote {
		t.Fatalf("cleanup removed or replaced the retained publication: %+v", snapshot)
	}

	firstReplacementHit := cm.updateMiningSignalState(secondPool, ident, nowUnix)
	if !firstReplacementHit.Active || firstReplacementHit.Evidence.TopRemote != firstPool.Mining.TopRemote {
		t.Fatalf("first replacement hit stopped retaining old publication: %+v", firstReplacementHit)
	}
	cm.updateMiningSignalState(secondPool, ident, nowUnix+15)
	qualifiedReplacement := cm.updateMiningSignalState(secondPool, ident, nowUnix+30)
	if !qualifiedReplacement.Active || !qualifiedReplacement.Confirmed || qualifiedReplacement.Evidence.TopRemote != secondPool.Mining.TopRemote ||
		qualifiedReplacement.Evidence.TopPort != secondPool.Mining.TopPort {
		t.Fatalf("replacement did not independently requalify after cleanup: %+v", qualifiedReplacement)
	}
}

func TestMiningRecoveryEndpointSwitchCleanupReferenceExpires(t *testing.T) {
	cm := newBehaviorStateTestManager()
	ident := behaviorIdentityKey{InstanceUUID: "vm-mining-recovery-expiry", IP: IPStrToKey("10.0.0.37"), Direction: "outbound"}
	firstPool := miningSignalStateFeature(miningPortConfidenceHigh, "198.51.100.91", 2, 2)
	firstPool.Flows = 1_000_000
	secondPool := miningSignalStateFeature(miningPortConfidenceHigh, "198.51.100.92", 2, 2)
	secondPool.Flows = 1_000_000
	nowUnix := time.Now().Unix()
	staleRecoveryUnix := nowUnix - behaviorIdentityTTLSeconds - 1

	cm.updateMiningSignalState(firstPool, ident, staleRecoveryUnix-45)
	cm.updateMiningSignalState(firstPool, ident, staleRecoveryUnix-30)
	confirmed := cm.updateMiningSignalState(firstPool, ident, staleRecoveryUnix-15)
	if !confirmed.Active || !confirmed.Confirmed {
		t.Fatalf("initial pool did not confirm: %+v", confirmed)
	}
	if recovery := cm.reconcileMiningRecovery(secondPool, ident, staleRecoveryUnix); !recovery.Active {
		t.Fatalf("changed recovery did not retain old publication initially: %+v", recovery)
	}

	cm.cleanupBehaviorStateWithAging(map[string]struct{}{ident.InstanceUUID: {}}, false)
	if _, exists := cm.miningSignals[ident]; exists {
		t.Fatalf("recovery-only mining publication survived beyond its %ds TTL", behaviorIdentityTTLSeconds)
	}
}

func TestMiningCleanCleanupRetainsEmissionHistoryUntilTTL(t *testing.T) {
	cm := newBehaviorStateTestManager()
	ident := behaviorIdentityKey{InstanceUUID: "vm-mining-clean-history", IP: IPStrToKey("10.0.0.36"), Direction: "outbound"}
	feature := miningSignalStateFeature(miningPortConfidenceHigh, "198.51.100.90", 2, 2)
	feature.Flows = 1_000_000
	nowUnix := time.Now().Unix()

	cm.updateMiningSignalState(feature, ident, nowUnix-45)
	cm.updateMiningSignalState(feature, ident, nowUnix-30)
	confirmed := cm.updateMiningSignalState(feature, ident, nowUnix-15)
	if !confirmed.ShouldEmit {
		t.Fatalf("initial direct mining episode did not emit: %+v", confirmed)
	}
	lastEmitUnix := cm.miningSignals[ident].LastEmitUnix
	if lastEmitUnix == 0 {
		t.Fatal("initial direct mining episode did not retain emission history")
	}
	if clean := cm.updateMiningSignalState(BehaviorFeature{Direction: "outbound"}, ident, nowUnix); clean.Active {
		t.Fatalf("clean observation retained active publication: %+v", clean)
	}

	cm.cleanupBehaviorStateWithAging(map[string]struct{}{ident.InstanceUUID: {}}, false)
	retained := cm.miningSignals[ident]
	if retained == nil || retained.Active || retained.Confirmed || retained.LastSeenUnix != 0 || retained.LastEmitUnix != lastEmitUnix {
		t.Fatalf("cleanup lost fresh recurrence history after clean observation: %+v", retained)
	}

	retained.LastEmitUnix = time.Now().Unix() - behaviorIdentityTTLSeconds - 1
	cm.cleanupBehaviorStateWithAging(map[string]struct{}{ident.InstanceUUID: {}}, false)
	if _, exists := cm.miningSignals[ident]; exists {
		t.Fatalf("cleanup retained mining emission history beyond its %ds TTL", behaviorIdentityTTLSeconds)
	}
}

func TestMiningRecoveryRebaselinePathPreservesPublishedMetricWithoutAdvancing(t *testing.T) {
	cm := newBehaviorStateTestManager()
	cm.behaviorOutboundPortNames = builtinBehaviorOutboundMonitoredPorts()
	events := captureBehaviorSignals(cm)
	const instanceUUID = "vm-mining-rebaseline-path"
	ident := behaviorIdentityKey{InstanceUUID: instanceUUID, IP: IPStrToKey("10.0.0.10"), Direction: "outbound"}
	feature := miningSignalStateFeature(miningPortConfidenceHigh, "198.51.100.87", 2, 2)
	feature.HostImpactPercent = 0
	feature.UnrepliedRatio = 0
	for _, now := range []int64{100, 115, 130} {
		cm.updateMiningSignalState(feature, ident, now)
	}
	before := *cm.miningSignals[ident]

	stats := newBehaviorStats(false)
	appendMiningSignalTestFlow(stats, feature.Mining.TopRemote, feature.Mining.TopPort, IPS_SEEN_REPLY|IPS_ASSURED)
	appendMiningSignalTestFlow(stats, feature.Mining.TopRemote, feature.Mining.TopPort, IPS_SEEN_REPLY|IPS_ASSURED)
	metrics := make([]prometheus.Metric, 0, 1)
	cm.analyzeBehavior(
		stats,
		ident.IP,
		"10.0.0.10", "ipv4", "domain", "server", instanceUUID, "project", "project-name", "user",
		&metrics,
		metricDescGroup{thresholdConfigKey: "outbound"},
		BehaviorContext{ObservationUnix: 145, Rebaseline: true},
	)

	assertMiningMetricLabels(t, metrics, map[string]string{"port": "10128", "confidence": "high"})
	if len(*events) != 0 {
		t.Fatalf("recovery rebaseline emitted mining events: %#v", *events)
	}
	after := cm.miningSignals[ident]
	if after.Hits != before.Hits || after.FirstSeenUnix != before.FirstSeenUnix || after.LastSeenUnix != before.LastSeenUnix ||
		!after.Active || !after.Confirmed || after.Evidence.TopRemote != before.Evidence.TopRemote {
		t.Fatalf("recovery rebaseline advanced or replaced mining publication: before=%+v after=%+v", before, *after)
	}
}

func TestMiningPersistenceRequiresConsecutiveCompleteCycles(t *testing.T) {
	cm := newBehaviorStateTestManager()
	ident := behaviorIdentityKey{InstanceUUID: "vm-intermittent", IP: IPStrToKey("10.0.0.31"), Direction: "outbound"}
	feature := miningSignalStateFeature(miningPortConfidenceHigh, "198.51.100.50", 1, 1)

	cm.updateMiningSignalState(feature, ident, 100)
	if outcome := cm.updateMiningSignalState(feature, ident, 115); outcome.PersistenceHits != 2 || outcome.Confirmed {
		t.Fatalf("second matching cycle=%+v", outcome)
	}
	if outcome := cm.updateMiningSignalState(BehaviorFeature{Direction: "outbound"}, ident, 130); outcome.Active {
		t.Fatalf("clean complete cycle left mining active: %+v", outcome)
	}
	if outcome := cm.updateMiningSignalState(feature, ident, 145); outcome.PersistenceHits != 1 || outcome.Confirmed {
		t.Fatalf("interrupted evidence reused old persistence: %+v", outcome)
	}
}

func TestMiningPersistenceCountsOneHitPerCompleteSnapshot(t *testing.T) {
	cm := newBehaviorStateTestManager()
	ident := behaviorIdentityKey{InstanceUUID: "vm-mining-snapshot-idempotence", IP: IPStrToKey("10.0.0.35"), Direction: "outbound"}
	feature := miningSignalStateFeature(miningPortConfidenceHighPersistent, "198.51.100.88", 1, 1)

	for duplicate := 0; duplicate < 3; duplicate++ {
		outcome := cm.updateMiningSignalState(feature, ident, 100)
		if outcome.Confirmed || outcome.PersistenceHits != 1 {
			t.Fatalf("duplicate complete snapshot %d advanced mining state: %+v", duplicate+1, outcome)
		}
	}
	second := cm.updateMiningSignalState(feature, ident, 115)
	if second.Confirmed || second.PersistenceHits != 2 {
		t.Fatalf("second distinct complete snapshot=%+v, want two unconfirmed hits", second)
	}
	third := cm.updateMiningSignalState(feature, ident, 130)
	if !third.Confirmed || third.PersistenceHits != 3 || third.PersistenceElapsedSeconds != 30 {
		t.Fatalf("third distinct complete snapshot=%+v, want confirmation at 30 seconds", third)
	}
}

func TestFailedConntrackCyclePreservesButDoesNotAdvancePendingMining(t *testing.T) {
	cm := newBehaviorStateTestManager()
	cm.behaviorOutboundPortNames = builtinBehaviorOutboundMonitoredPorts()
	const instanceUUID = "vm-mining-pending-freeze"
	ident := behaviorIdentityKey{InstanceUUID: instanceUUID, IP: IPStrToKey("10.0.0.10"), Direction: "outbound"}
	feature := miningSignalStateFeature(miningPortConfidenceHigh, "198.51.100.86", 2, 2)
	feature.HostImpactPercent = 0
	feature.UnrepliedRatio = 0
	if first := cm.updateMiningSignalState(feature, ident, 100); first.Confirmed || first.PersistenceHits != 1 {
		t.Fatalf("first pending observation=%+v", first)
	}
	before := *cm.miningSignals[ident]

	stats := newBehaviorStats(false)
	appendMiningSignalTestFlow(stats, feature.Mining.TopRemote, 10128, IPS_SEEN_REPLY|IPS_ASSURED)
	appendMiningSignalTestFlow(stats, feature.Mining.TopRemote, 10128, IPS_SEEN_REPLY|IPS_ASSURED)
	for cycle := 0; cycle < 3; cycle++ {
		metrics := make([]prometheus.Metric, 0, 1)
		analyzeMiningSignalTestCycleWithState(cm, stats, instanceUUID, &metrics, true)
		if len(metrics) != 0 {
			t.Fatalf("failed cycle %d exported an unconfirmed mining metric", cycle+1)
		}
	}
	after := cm.miningSignals[ident]
	if after.Hits != before.Hits || after.FirstSeenUnix != before.FirstSeenUnix || after.LastSeenUnix != before.LastSeenUnix || after.Confirmed || after.Active {
		t.Fatalf("failed cycles mutated pending mining state: before=%+v after=%+v", before, *after)
	}

	if second := cm.updateMiningSignalState(feature, ident, 115); second.Confirmed || second.PersistenceHits != 2 {
		t.Fatalf("first post-failure observation matured candidate: %+v", second)
	}
	if third := cm.updateMiningSignalState(feature, ident, 130); !third.Confirmed || third.PersistenceHits != 3 {
		t.Fatalf("candidate did not mature from complete observations only: %+v", third)
	}
}

func TestMiningPersistenceResetsAfterLongGap(t *testing.T) {
	cm := newBehaviorStateTestManager()
	feature := miningSignalStateFeature(miningPortConfidenceHigh, "198.51.100.42", 1, 1)
	feature.HostImpactPercent = 0
	feature.UnrepliedRatio = 0
	ident := behaviorIdentityKey{InstanceUUID: "vm-gap", IP: IPStrToKey("10.0.0.22"), Direction: "outbound"}

	cm.updateMiningSignalState(feature, ident, 100)
	cm.updateMiningSignalState(feature, ident, 115)
	afterGap := cm.updateMiningSignalState(feature, ident, 296)
	if afterGap.PersistenceHits != 1 || afterGap.Confirmed {
		t.Fatalf("long-gap outcome=%+v, want reset to first hit", afterGap)
	}
	cm.updateMiningSignalState(feature, ident, 311)
	confirmed := cm.updateMiningSignalState(feature, ident, 326)
	if !confirmed.Confirmed || confirmed.PersistenceHits != 3 {
		t.Fatalf("post-gap mining did not require three new hits: %+v", confirmed)
	}
}

func TestMiningReconfirmedAfterPersistenceGapEmitsAgain(t *testing.T) {
	cm := newBehaviorStateTestManager()
	feature := miningSignalStateFeature(miningPortConfidenceHigh, "198.51.100.52", 1, 1)
	feature.HostImpactPercent = 0
	feature.UnrepliedRatio = 0
	ident := behaviorIdentityKey{InstanceUUID: "vm-mining-recurrence", IP: IPStrToKey("10.0.0.25"), Direction: "outbound"}

	for cycle, now := range []int64{100, 115, 130} {
		outcome := cm.updateMiningSignalState(feature, ident, now)
		if cycle == 2 && (!outcome.Confirmed || !outcome.ShouldEmit || outcome.EmitReason != "new_signal") {
			t.Fatalf("initial mining episode=%+v, want a confirmed new-signal emission", outcome)
		}
	}
	if outcome := cm.updateMiningSignalState(BehaviorFeature{Direction: "outbound"}, ident, 145); outcome.Active {
		t.Fatalf("cleared mining episode remained active: %+v", outcome)
	}

	for cycle, now := range []int64{330, 345, 360} {
		outcome := cm.updateMiningSignalState(feature, ident, now)
		if cycle < 2 && outcome.Confirmed {
			t.Fatalf("recurrent mining episode reconfirmed early at %d: %+v", now, outcome)
		}
		if cycle == 2 && (!outcome.Confirmed || !outcome.ShouldEmit || outcome.EmitReason != "changed") {
			t.Fatalf("reconfirmed mining episode=%+v, want a changed emission", outcome)
		}
	}
}

func TestMiningCooldownAndHeartbeatBoundaries(t *testing.T) {
	cm := newBehaviorStateTestManager()
	feature := miningSignalStateFeature(miningPortConfidenceHigh, "198.51.100.43", 2, 2)
	feature.Flows = 1_000_000
	feature.NewRemotes = 1
	feature.NewDstPorts = 1
	ident := behaviorIdentityKey{InstanceUUID: "vm-timers", IP: IPStrToKey("10.0.0.23"), Direction: "outbound"}

	cm.updateMiningSignalState(feature, ident, 85)
	cm.updateMiningSignalState(feature, ident, 100)
	initial := cm.updateMiningSignalState(feature, ident, 115)
	if !initial.ShouldEmit {
		t.Fatalf("initial mining signal was not emitted: %+v", initial)
	}

	changed := miningSignalStateFeature(miningPortConfidenceHigh, "198.51.100.99", 2, 2)
	changed.Flows = 1_000_000
	changed.NewRemotes = 1
	changed.NewDstPorts = 1
	pending := cm.updateMiningSignalState(changed, ident, 130)
	if pending.ShouldEmit || pending.SuppressReason != "persistence_gate" || pending.Evidence.TopRemote != feature.Mining.TopRemote {
		t.Fatalf("changed destination did not retain the confirmed episode while requalifying: %+v", pending)
	}
	cm.updateMiningSignalState(changed, ident, 145)
	suppressed := cm.updateMiningSignalState(changed, ident, 160)
	if suppressed.ShouldEmit || suppressed.SuppressReason != "cooldown" || suppressed.Evidence.TopRemote != changed.Mining.TopRemote {
		t.Fatalf("requalified destination bypassed cooldown: %+v", suppressed)
	}
	atBoundary := cm.updateMiningSignalState(changed, ident, 115+behaviorSignalCooldownSeconds)
	if !atBoundary.ShouldEmit || atBoundary.EmitReason != "changed" {
		t.Fatalf("changed destination did not emit at cooldown boundary: %+v", atBoundary)
	}

	heartbeatBase := atBoundary
	beforeHeartbeatUnix := int64(115) + behaviorSignalCooldownSeconds + behaviorSignalHeartbeatSeconds - 1
	cm.miningSignals[ident].LastSeenUnix = beforeHeartbeatUnix - 1
	beforeHeartbeat := cm.updateMiningSignalState(changed, ident, beforeHeartbeatUnix)
	if beforeHeartbeat.ShouldEmit {
		t.Fatalf("heartbeat emitted early: base=%+v before=%+v", heartbeatBase, beforeHeartbeat)
	}
	heartbeat := cm.updateMiningSignalState(changed, ident, beforeHeartbeatUnix+1)
	if !heartbeat.ShouldEmit || heartbeat.EmitReason != "heartbeat" {
		t.Fatalf("heartbeat did not emit at boundary: %+v", heartbeat)
	}

}
