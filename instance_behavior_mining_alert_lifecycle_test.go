package main

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

type capturedBehaviorAlert map[string]interface{}

func captureBehaviorAlerts(cm *ConntrackManager) *[]capturedBehaviorAlert {
	events := make([]capturedBehaviorAlert, 0, 2)
	cm.LogThreat = func(tag, event, domain, instanceUUID, projectUUID, projectName, userUUID string, kvpairs ...interface{}) {
		fields := capturedBehaviorAlert{
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

func analyzeMiningAlertTestCycle(cm *ConntrackManager, stats *behaviorStats, instanceUUID string) float64 {
	return analyzeMiningAlertTestCycleWithState(cm, stats, instanceUUID, nil, false)
}

func analyzeMiningAlertTestCycleWithState(cm *ConntrackManager, stats *behaviorStats, instanceUUID string, metrics *[]prometheus.Metric, freeze bool) float64 {
	return cm.analyzeBehavior(
		stats,
		IPStrToKey("10.0.0.10"),
		"10.0.0.10", "ipv4", "domain", "server", instanceUUID, "project", "project-name", "user",
		metrics,
		metricDescGroup{thresholdConfigKey: "outbound"},
		BehaviorContext{FreezeState: freeze},
	)
}

func appendMiningAlertTestFlow(stats *behaviorStats, remote IPKey, port uint16, status uint32) {
	stats.updateDetailedWithCoverage(remote, port, 6, status, 1, 0, 0, false, false)
	stats.updateOutboundMining(remote, port, 6, status, true)
}

func TestMiningAlertLifecycleUsesMiningEndpointWhenWebTrafficDominates(t *testing.T) {
	cm := newBehaviorStateTestManager()
	cm.behaviorOutboundPortNames = builtinBehaviorOutboundMonitoredPorts()
	events := captureBehaviorAlerts(cm)
	stats := newBehaviorStats(false)

	webRemote := IPStrToKey("198.51.100.10")
	for i := 0; i < 499; i++ {
		appendMiningAlertTestFlow(stats, webRemote, 443, IPS_SEEN_REPLY)
	}
	miningRemote := IPStrToKey("198.51.100.44")
	appendMiningAlertTestFlow(stats, miningRemote, 10128, IPS_SEEN_REPLY)
	appendMiningAlertTestFlow(stats, miningRemote, 10128, IPS_SEEN_REPLY)

	for cycle := 1; cycle <= 3; cycle++ {
		analyzeMiningAlertTestCycle(cm, stats, "vm-web-dominant")
		if cycle < 3 && len(*events) != 0 {
			t.Fatalf("cycle %d emitted before the mining persistence gate: %#v", cycle, *events)
		}
	}

	if len(*events) != 1 {
		t.Fatalf("mining alert count=%d, want 1: %#v", len(*events), *events)
	}
	event := (*events)[0]
	if event["kind"] != "outbound_stratum_mining_suspected" {
		t.Fatalf("kind=%v, want mining classification: %#v", event["kind"], event)
	}
	if event["top_dst_port"] != 10128 || event["top_dst_port_name"] != "moneroocean_randomx_stratum" {
		t.Fatalf("mining endpoint=%v/%v, want 10128/moneroocean_randomx_stratum: %#v", event["top_dst_port"], event["top_dst_port_name"], event)
	}
	if event["dst_ip"] != "198.51.100.44" {
		t.Fatalf("mining destination=%v, want 198.51.100.44: %#v", event["dst_ip"], event)
	}
}

func TestMiningAlertPersistsIndependentlyOfEarlierScanClassification(t *testing.T) {
	cm := newBehaviorStateTestManager()
	cm.behaviorOutboundPortNames = builtinBehaviorOutboundMonitoredPorts()
	events := captureBehaviorAlerts(cm)
	stats := newBehaviorStats(false)

	for i := 1; i <= 30; i++ {
		remote := IPKey{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 198, 51, 100, byte(i)}
		appendMiningAlertTestFlow(stats, remote, 22, 0)
	}
	appendMiningAlertTestFlow(stats, IPStrToKey("203.0.113.44"), 10128, IPS_ASSURED)
	appendMiningAlertTestFlow(stats, IPStrToKey("203.0.113.44"), 10128, IPS_ASSURED)

	for cycle := 0; cycle < 3; cycle++ {
		analyzeMiningAlertTestCycle(cm, stats, "vm-scan-and-mining")
	}

	foundMining := false
	for _, event := range *events {
		if event["kind"] == "outbound_stratum_mining_suspected" {
			foundMining = true
			break
		}
	}
	if !foundMining {
		t.Fatalf("earlier scan classification suppressed the independent mining alert: %#v", *events)
	}
}

func TestConfirmedMiningExportsDedicatedMetricAndFreezesLastGoodState(t *testing.T) {
	cm := newBehaviorStateTestManager()
	cm.behaviorOutboundPortNames = builtinBehaviorOutboundMonitoredPorts()
	events := captureBehaviorAlerts(cm)
	stats := newBehaviorStats(false)
	appendMiningAlertTestFlow(stats, IPStrToKey("198.51.100.44"), 10128, IPS_SEEN_REPLY)
	appendMiningAlertTestFlow(stats, IPStrToKey("198.51.100.44"), 10128, IPS_SEEN_REPLY)

	for cycle := 1; cycle <= 3; cycle++ {
		metrics := make([]prometheus.Metric, 0, 1)
		analyzeMiningAlertTestCycleWithState(cm, stats, "vm-mining-metric", &metrics, false)
		if cycle < 3 && len(metrics) != 0 {
			t.Fatalf("cycle %d exported mining metric before persistence: %d metrics", cycle, len(metrics))
		}
		if cycle == 3 {
			assertMiningMetric(t, metrics)
		}
	}
	if len(*events) != 1 {
		t.Fatalf("mining alert events=%d, want 1", len(*events))
	}

	frozenMetrics := make([]prometheus.Metric, 0, 1)
	analyzeMiningAlertTestCycleWithState(cm, stats, "vm-mining-metric", &frozenMetrics, true)
	assertMiningMetric(t, frozenMetrics)
	if len(*events) != 1 {
		t.Fatalf("frozen conntrack state emitted another mining event: %#v", *events)
	}

	cleanMetrics := make([]prometheus.Metric, 0, 1)
	analyzeMiningAlertTestCycleWithState(cm, newBehaviorStats(false), "vm-mining-metric", &cleanMetrics, false)
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
		"priority":   "P4",
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

func miningAlertStateFeature(confidence miningPortConfidence, remote string, flows, replied int) BehaviorFeature {
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
				TopPortFlows:     flows,
				TopPortReplied:   replied,
				TopRemote:        remoteKey,
				TopRemoteFlows:   flows,
				TopRemoteReplied: replied,
			},
		},
	}
}

func TestHighPriorityMiningConfirmsAfterTwoCycles(t *testing.T) {
	cm := newBehaviorStateTestManager()
	feature := miningAlertStateFeature(miningPortConfidenceHigh, "198.51.100.40", 2, 2)
	feature.Flows = 1_000_000
	ident := behaviorIdentityKey{InstanceUUID: "vm-p2", IP: IPStrToKey("10.0.0.20"), Direction: "outbound"}

	first := cm.updateMiningAlertState(feature, ident, 100)
	if first.Confirmed || first.PersistenceRequired != 2 || first.Priority != "P2" {
		t.Fatalf("first high-priority outcome=%+v, want unconfirmed P2 with two-cycle persistence", first)
	}
	second := cm.updateMiningAlertState(feature, ident, 101)
	if !second.Confirmed || !second.ShouldEmit || second.PersistenceHits != 2 || second.EmitReason != "new_kind" {
		t.Fatalf("second high-priority outcome=%+v, want confirmed new alert", second)
	}
	if got := applyConfirmedBehaviorPriorityFloor(0, second); got != 0.7 {
		t.Fatalf("P2 mining severity floor=%v, want 0.7", got)
	}
}

func TestSharedMiningStillRequiresThreeCyclesAtHighPriority(t *testing.T) {
	cm := newBehaviorStateTestManager()
	feature := miningAlertStateFeature(miningPortConfidenceShared, "198.51.100.41", 3, 2)
	feature.Mining.TopPort = 5555
	ident := behaviorIdentityKey{InstanceUUID: "vm-shared", IP: IPStrToKey("10.0.0.21"), Direction: "outbound"}

	for cycle := int64(1); cycle <= 3; cycle++ {
		outcome := cm.updateMiningAlertState(feature, ident, 100+cycle)
		if outcome.PersistenceRequired != 3 {
			t.Fatalf("shared cycle %d persistence=%d, want 3", cycle, outcome.PersistenceRequired)
		}
		if cycle < 3 && outcome.Confirmed {
			t.Fatalf("shared mining confirmed on cycle %d: %+v", cycle, outcome)
		}
		if cycle == 3 && (!outcome.Confirmed || outcome.ShouldEmit || outcome.SuppressReason != "corroboration_required") {
			t.Fatalf("shared mining candidate outcome on third cycle: %+v", outcome)
		}
	}
}

func TestCandidatePromotionToHighEmitsStructuredAlert(t *testing.T) {
	cm := newBehaviorStateTestManager()
	ident := behaviorIdentityKey{InstanceUUID: "vm-promotion", IP: IPStrToKey("10.0.0.29"), Direction: "outbound"}
	candidate := miningAlertStateFeature(miningPortConfidenceHighPersistent, "198.51.100.49", 1, 1)
	for now := int64(100); now <= 102; now++ {
		outcome := cm.updateMiningAlertState(candidate, ident, now)
		if now == 102 && (!outcome.Confirmed || outcome.ShouldEmit || outcome.SuppressReason != "corroboration_required") {
			t.Fatalf("candidate confirmation=%+v", outcome)
		}
	}

	high := miningAlertStateFeature(miningPortConfidenceHigh, "198.51.100.49", 2, 2)
	outcome := cm.updateMiningAlertState(high, ident, 103)
	if !outcome.Confirmed || !outcome.ShouldEmit || outcome.EmitReason != "new_kind" {
		t.Fatalf("promoted high evidence did not emit: %+v", outcome)
	}
}

func TestSinglePersistentSharedMiningConnectionExportsCandidate(t *testing.T) {
	cm := newBehaviorStateTestManager()
	cm.behaviorOutboundPortNames = builtinBehaviorOutboundMonitoredPorts()
	events := captureBehaviorAlerts(cm)
	stats := newBehaviorStats(false)
	appendMiningAlertTestFlow(stats, IPStrToKey("198.51.100.77"), 7777, IPS_SEEN_REPLY|IPS_ASSURED)

	for cycle := 1; cycle <= 6; cycle++ {
		metrics := make([]prometheus.Metric, 0, 1)
		analyzeMiningAlertTestCycleWithState(cm, stats, "vm-single-shared", &metrics, false)
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
		t.Fatalf("uncorroborated shared-port candidate emitted a structured alert: %#v", *events)
	}
}

func TestMultipleSharedPortConnectionsRemainCorroboratedCandidates(t *testing.T) {
	cm := newBehaviorStateTestManager()
	cm.behaviorOutboundPortNames = builtinBehaviorOutboundMonitoredPorts()
	events := captureBehaviorAlerts(cm)
	stats := newBehaviorStats(false)
	for i := 0; i < 3; i++ {
		appendMiningAlertTestFlow(stats, IPStrToKey("198.51.100.79"), 7777, IPS_SEEN_REPLY|IPS_ASSURED)
	}

	for cycle := 1; cycle <= 3; cycle++ {
		metrics := make([]prometheus.Metric, 0, 1)
		analyzeMiningAlertTestCycleWithState(cm, stats, "vm-multiple-shared", &metrics, false)
		if cycle == 3 {
			assertMiningMetricLabels(t, metrics, map[string]string{
				"port":       "7777",
				"confidence": "shared",
			})
		}
	}
	if len(*events) != 0 {
		t.Fatalf("uncorroborated ambiguous-port evidence emitted a structured alert: %#v", *events)
	}
}

func TestSingleDedicatedPortConnectionExportsCandidateWithoutStructuredAlert(t *testing.T) {
	cm := newBehaviorStateTestManager()
	cm.behaviorOutboundPortNames = builtinBehaviorOutboundMonitoredPorts()
	events := captureBehaviorAlerts(cm)
	stats := newBehaviorStats(false)
	appendMiningAlertTestFlow(stats, IPStrToKey("198.51.100.78"), 10128, IPS_SEEN_REPLY|IPS_ASSURED)

	for cycle := 1; cycle <= 3; cycle++ {
		metrics := make([]prometheus.Metric, 0, 1)
		analyzeMiningAlertTestCycleWithState(cm, stats, "vm-single-dedicated", &metrics, false)
		if cycle == 3 {
			assertMiningMetricLabels(t, metrics, map[string]string{
				"port":       "10128",
				"confidence": "high_persistent",
			})
		}
	}
	if len(*events) != 0 {
		t.Fatalf("uncorroborated dedicated-port candidate emitted a structured alert: %#v", *events)
	}
}

func TestMiningPersistenceRequiresStableEndpoint(t *testing.T) {
	cm := newBehaviorStateTestManager()
	ident := behaviorIdentityKey{InstanceUUID: "vm-changing-endpoint", IP: IPStrToKey("10.0.0.30"), Direction: "outbound"}

	first := miningAlertStateFeature(miningPortConfidenceHigh, "198.51.100.40", 1, 1)
	second := miningAlertStateFeature(miningPortConfidenceHigh, "198.51.100.41", 1, 1)
	third := miningAlertStateFeature(miningPortConfidenceHigh, "198.51.100.42", 1, 1)

	if outcome := cm.updateMiningAlertState(first, ident, 100); outcome.PersistenceHits != 1 || outcome.Confirmed {
		t.Fatalf("first endpoint outcome=%+v", outcome)
	}
	if outcome := cm.updateMiningAlertState(second, ident, 101); outcome.PersistenceHits != 1 || outcome.Confirmed {
		t.Fatalf("changed endpoint reused persistence: %+v", outcome)
	}
	if outcome := cm.updateMiningAlertState(third, ident, 102); outcome.PersistenceHits != 1 || outcome.Confirmed {
		t.Fatalf("third endpoint reused persistence: %+v", outcome)
	}
}

func TestMiningPersistenceRequiresConsecutiveCompleteCycles(t *testing.T) {
	cm := newBehaviorStateTestManager()
	ident := behaviorIdentityKey{InstanceUUID: "vm-intermittent", IP: IPStrToKey("10.0.0.31"), Direction: "outbound"}
	feature := miningAlertStateFeature(miningPortConfidenceHigh, "198.51.100.50", 1, 1)

	cm.updateMiningAlertState(feature, ident, 100)
	if outcome := cm.updateMiningAlertState(feature, ident, 101); outcome.PersistenceHits != 2 || outcome.Confirmed {
		t.Fatalf("second matching cycle=%+v", outcome)
	}
	if outcome := cm.updateMiningAlertState(BehaviorFeature{Direction: "outbound"}, ident, 102); outcome.Active {
		t.Fatalf("clean complete cycle left mining active: %+v", outcome)
	}
	if outcome := cm.updateMiningAlertState(feature, ident, 103); outcome.PersistenceHits != 1 || outcome.Confirmed {
		t.Fatalf("interrupted evidence reused old persistence: %+v", outcome)
	}
}

func TestMiningPersistenceResetsAfterLongGap(t *testing.T) {
	cm := newBehaviorStateTestManager()
	feature := miningAlertStateFeature(miningPortConfidenceHigh, "198.51.100.42", 1, 1)
	feature.HostImpactPercent = 0
	feature.UnrepliedRatio = 0
	ident := behaviorIdentityKey{InstanceUUID: "vm-gap", IP: IPStrToKey("10.0.0.22"), Direction: "outbound"}

	cm.updateMiningAlertState(feature, ident, 100)
	cm.updateMiningAlertState(feature, ident, 101)
	afterGap := cm.updateMiningAlertState(feature, ident, 282)
	if afterGap.PersistenceHits != 1 || afterGap.Confirmed {
		t.Fatalf("long-gap outcome=%+v, want reset to first hit", afterGap)
	}
	cm.updateMiningAlertState(feature, ident, 283)
	confirmed := cm.updateMiningAlertState(feature, ident, 284)
	if !confirmed.Confirmed || confirmed.PersistenceHits != 3 {
		t.Fatalf("post-gap mining did not require three new hits: %+v", confirmed)
	}
}

func TestMiningReconfirmedAfterPersistenceGapEmitsAgain(t *testing.T) {
	cm := newBehaviorStateTestManager()
	feature := miningAlertStateFeature(miningPortConfidenceHigh, "198.51.100.52", 1, 1)
	feature.HostImpactPercent = 0
	feature.UnrepliedRatio = 0
	ident := behaviorIdentityKey{InstanceUUID: "vm-mining-recurrence", IP: IPStrToKey("10.0.0.25"), Direction: "outbound"}

	for now := int64(100); now <= 102; now++ {
		outcome := cm.updateMiningAlertState(feature, ident, now)
		if now == 102 && (!outcome.Confirmed || !outcome.ShouldEmit || outcome.EmitReason != "new_kind") {
			t.Fatalf("initial mining episode=%+v, want a confirmed new-kind emission", outcome)
		}
	}
	if outcome := cm.updateMiningAlertState(BehaviorFeature{Direction: "outbound"}, ident, 103); outcome.Active {
		t.Fatalf("cleared mining episode remained active: %+v", outcome)
	}

	for now := int64(283); now <= 285; now++ {
		outcome := cm.updateMiningAlertState(feature, ident, now)
		if now < 285 && outcome.Confirmed {
			t.Fatalf("recurrent mining episode reconfirmed early at %d: %+v", now, outcome)
		}
		if now == 285 && (!outcome.Confirmed || !outcome.ShouldEmit || outcome.EmitReason != "changed") {
			t.Fatalf("reconfirmed mining episode=%+v, want a changed emission", outcome)
		}
	}
}

func TestMiningCooldownAndHeartbeatBoundaries(t *testing.T) {
	cm := newBehaviorStateTestManager()
	feature := miningAlertStateFeature(miningPortConfidenceHigh, "198.51.100.43", 2, 2)
	feature.Flows = 1_000_000
	feature.NewRemotes = 1
	feature.NewDstPorts = 1
	ident := behaviorIdentityKey{InstanceUUID: "vm-timers", IP: IPStrToKey("10.0.0.23"), Direction: "outbound"}

	cm.updateMiningAlertState(feature, ident, 100)
	initial := cm.updateMiningAlertState(feature, ident, 101)
	if !initial.ShouldEmit {
		t.Fatalf("initial mining alert was not emitted: %+v", initial)
	}

	changed := miningAlertStateFeature(miningPortConfidenceHigh, "198.51.100.99", 2, 2)
	changed.Flows = 1_000_000
	changed.NewRemotes = 1
	changed.NewDstPorts = 1
	suppressed := cm.updateMiningAlertState(changed, ident, 102)
	if suppressed.ShouldEmit || suppressed.SuppressReason != "cooldown" {
		t.Fatalf("changed destination bypassed cooldown: %+v", suppressed)
	}
	atBoundary := cm.updateMiningAlertState(changed, ident, 101+behaviorAlertCooldownSeconds)
	if !atBoundary.ShouldEmit || atBoundary.EmitReason != "changed" {
		t.Fatalf("changed destination did not emit at cooldown boundary: %+v", atBoundary)
	}

	heartbeatBase := atBoundary
	beforeHeartbeatUnix := int64(101) + behaviorAlertCooldownSeconds + behaviorAlertHeartbeatSeconds - 1
	cm.miningAlerts[ident].LastSeenUnix = beforeHeartbeatUnix - 1
	beforeHeartbeat := cm.updateMiningAlertState(changed, ident, beforeHeartbeatUnix)
	if beforeHeartbeat.ShouldEmit {
		t.Fatalf("heartbeat emitted early: base=%+v before=%+v", heartbeatBase, beforeHeartbeat)
	}
	heartbeat := cm.updateMiningAlertState(changed, ident, beforeHeartbeatUnix+1)
	if !heartbeat.ShouldEmit || heartbeat.EmitReason != "heartbeat" {
		t.Fatalf("heartbeat did not emit at boundary: %+v", heartbeat)
	}

}

func TestMiningSummaryThrottleUsesProvidedAnalysisTimestamp(t *testing.T) {
	_ = capturePassOneStructuredLogs(t)
	resetPassOneBehaviorRuleLogState(t)

	cm := newBehaviorStateTestManager()
	cm.LogThreat = func(tag, event, domain, instanceUUID, projectUUID, projectName, userUUID string, kvpairs ...interface{}) {
	}
	feature := miningAlertStateFeature(miningPortConfidenceHigh, "198.51.100.50", 2, 2)
	feature.Flows = 1_000_000
	ident := behaviorIdentityKey{InstanceUUID: "vm-summary-clock", IP: IPStrToKey("10.0.0.24"), Direction: "outbound"}

	cm.updateMiningAlertState(feature, ident, 100)
	outcome := cm.updateMiningAlertState(feature, ident, 101)
	if !outcome.ShouldEmit || outcome.EmitReason != "new_kind" {
		t.Fatalf("mining outcome=%+v, want initial summary-producing emission", outcome)
	}

	const analysisNowUnix int64 = 4242
	cm.emitMiningBehaviorAlert(
		feature,
		newBehaviorStats(false),
		outcome,
		"10.0.0.24", "domain", "server", "vm-summary-clock", "project", "project-name", "user",
		BehaviorContext{},
		0, 0,
		false,
		analysisNowUnix,
	)

	emitKey := behaviorEmitKey{InstanceUUID: "vm-summary-clock", IP: IPStrToKey("10.0.0.24"), Direction: "outbound"}
	behaviorRuleLogMu.Lock()
	state := behaviorRuleLogStateMap[emitKey]
	lastSummaryUnix := int64(0)
	if state != nil {
		lastSummaryUnix = state.LastSummaryUnix
	}
	behaviorRuleLogMu.Unlock()
	if state == nil || lastSummaryUnix != analysisNowUnix {
		t.Fatalf("summary throttle last timestamp=%d, want supplied analysis timestamp %d", lastSummaryUnix, analysisNowUnix)
	}
}
