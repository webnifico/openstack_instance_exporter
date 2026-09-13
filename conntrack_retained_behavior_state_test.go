package main

import (
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestBehaviorCleanupFreezeAgingRetainsActiveStateAndPrunesInactiveState(t *testing.T) {
	cm := newBehaviorStateTestManager()
	now := time.Now().Unix()
	activeIP := IPStrToKey("192.0.2.40")
	inactiveIP := IPStrToKey("192.0.2.41")
	activeIdent := behaviorIdentityKey{InstanceUUID: "active", IP: activeIP, Direction: "outbound"}
	inactiveIdent := behaviorIdentityKey{InstanceUUID: "inactive", IP: inactiveIP, Direction: "outbound"}

	for _, ident := range []behaviorIdentityKey{activeIdent, inactiveIdent} {
		idx := shardIndexBehavior(ident)
		cm.behaviorEWMA[idx][ident] = &behaviorEWMAState{
			LastSeenUnix: now - behaviorIdentityTTLSeconds - 1,
			LastInterval: behaviorIntervalSnapshot{
				NewRemotes: 7, NewDstPorts: 5, Initialized: true,
			},
		}
		cm.behaviorLastSeverity[idx][ident] = 0.8
	}

	activeKey := BehaviorKey{InstanceUUID: "active", IP: activeIP}
	inactiveKey := BehaviorKey{InstanceUUID: "inactive", IP: inactiveIP}
	for ident, key := range map[behaviorIdentityKey]BehaviorKey{
		activeIdent:   activeKey,
		inactiveIdent: inactiveKey,
	} {
		idx := shardIndexBehavior(ident)
		cm.outboundPrev[idx][key] = outboundPrev{remotes: map[IPKey]struct{}{IPStrToKey("198.51.100.10"): {}}}
		cm.outboundPrevDstPorts[idx][key] = outboundPrevDstPorts{ports: map[uint16]struct{}{443: {}}}
		cm.outboundPrevLastSeen[idx][key] = now - behaviorPrevKeyTTLSeconds - 1
	}

	activeAlert := behaviorAlertKey{InstanceUUID: "active", IP: activeIP, Direction: "outbound", Kind: "scan"}
	inactiveAlert := behaviorAlertKey{InstanceUUID: "inactive", IP: inactiveIP, Direction: "outbound", Kind: "scan"}
	cm.behaviorPersist[activeAlert] = &behaviorPersistState{LastSeenUnix: now - 3601}
	cm.behaviorPersist[inactiveAlert] = &behaviorPersistState{LastSeenUnix: now}
	activeEmit := behaviorEmitKey{InstanceUUID: "active", IP: activeIP, Direction: "outbound"}
	inactiveEmit := behaviorEmitKey{InstanceUUID: "inactive", IP: inactiveIP, Direction: "outbound"}
	cm.behaviorEmit[activeEmit] = &behaviorEmitState{LastEmitUnix: now - behaviorPrevKeyTTLSeconds - 1}
	cm.behaviorEmit[inactiveEmit] = &behaviorEmitState{LastEmitUnix: now}
	cm.miningAlerts[activeIdent] = &miningAlertState{LastSeenUnix: now - behaviorIdentityTTLSeconds - 1, Confirmed: true, Active: true}
	cm.miningAlerts[inactiveIdent] = &miningAlertState{LastSeenUnix: now, Confirmed: true, Active: true}

	activeSet := map[string]struct{}{"active": {}}
	cm.cleanupBehaviorMapsWithAging(activeSet, true)
	cm.cleanupBehaviorStateWithAging(activeSet, true)

	activeIdx := shardIndexBehavior(activeIdent)
	if cm.behaviorEWMA[activeIdx][activeIdent] == nil || cm.behaviorLastSeverity[activeIdx][activeIdent] != 0.8 {
		t.Fatal("TTL-aged active behavior state was removed while source aging was frozen")
	}
	if _, ok := cm.outboundPrev[activeIdx][activeKey]; !ok {
		t.Fatal("TTL-aged active remote baseline was removed while source aging was frozen")
	}
	if _, ok := cm.outboundPrevDstPorts[activeIdx][activeKey]; !ok {
		t.Fatal("TTL-aged active port baseline was removed while source aging was frozen")
	}
	if cm.behaviorPersist[activeAlert] == nil || cm.behaviorEmit[activeEmit] == nil || cm.miningAlerts[activeIdent] == nil {
		t.Fatal("TTL-aged active alert state was removed while source aging was frozen")
	}

	inactiveIdx := shardIndexBehavior(inactiveIdent)
	if cm.behaviorEWMA[inactiveIdx][inactiveIdent] != nil {
		t.Fatal("inactive EWMA state survived frozen-aging cleanup")
	}
	if _, ok := cm.behaviorLastSeverity[inactiveIdx][inactiveIdent]; ok {
		t.Fatal("inactive severity state survived frozen-aging cleanup")
	}
	if _, ok := cm.outboundPrev[inactiveIdx][inactiveKey]; ok {
		t.Fatal("inactive remote baseline survived frozen-aging cleanup")
	}
	if _, ok := cm.outboundPrevDstPorts[inactiveIdx][inactiveKey]; ok {
		t.Fatal("inactive port baseline survived frozen-aging cleanup")
	}
	if cm.behaviorPersist[inactiveAlert] != nil || cm.behaviorEmit[inactiveEmit] != nil || cm.miningAlerts[inactiveIdent] != nil {
		t.Fatal("inactive alert state survived frozen-aging cleanup")
	}
}

func TestFrozenBehaviorMetricsReuseLastFreshIntervalDeltas(t *testing.T) {
	cm := newBehaviorStateTestManager()
	const instanceUUID = "vm-retained-deltas"
	addrKey := IPStrToKey("10.0.0.50")
	descs := metricDescGroup{
		newRemotes:         cm.instanceOutboundNewRemotesDesc,
		newDstPorts:        cm.instanceOutboundNewDstPortsDesc,
		thresholdConfigKey: "outbound",
	}
	analyze := func(stats *behaviorStats, freeze bool) []prometheus.Metric {
		metrics := make([]prometheus.Metric, 0, 2)
		cm.analyzeBehavior(
			stats,
			addrKey,
			"10.0.0.50", "ipv4",
			"domain", "server", instanceUUID, "project", "project-name", "user",
			&metrics,
			descs,
			BehaviorContext{FreezeState: freeze},
		)
		return metrics
	}

	baseline := newBehaviorStats(false)
	baseline.updateDetailedWithCoverage(IPStrToKey("198.51.100.10"), 443, 6, IPS_SEEN_REPLY, 1, 0, 0, false, false)
	analyze(baseline, false)

	lastGood := newBehaviorStats(false)
	lastGood.updateDetailedWithCoverage(IPStrToKey("198.51.100.10"), 443, 6, IPS_SEEN_REPLY, 1, 0, 0, false, false)
	lastGood.updateDetailedWithCoverage(IPStrToKey("198.51.100.11"), 8443, 6, IPS_SEEN_REPLY, 1, 0, 0, false, false)
	freshValues := behaviorIntervalMetricValues(t, analyze(lastGood, false))
	frozenValues := behaviorIntervalMetricValues(t, analyze(lastGood, true))

	for _, name := range []string{
		"oie_instance_outbound_new_remotes",
		"oie_instance_outbound_new_dst_ports",
	} {
		if freshValues[name] != 1 {
			t.Fatalf("fresh %s=%v, want 1", name, freshValues[name])
		}
		if frozenValues[name] != freshValues[name] {
			t.Fatalf("frozen %s=%v, want retained fresh value %v", name, frozenValues[name], freshValues[name])
		}
	}
}

func behaviorIntervalMetricValues(t *testing.T, metrics []prometheus.Metric) map[string]float64 {
	t.Helper()
	values := make(map[string]float64, len(metrics))
	for _, metric := range metrics {
		desc := metric.Desc().String()
		var name string
		for _, candidate := range []string{
			"oie_instance_outbound_new_remotes",
			"oie_instance_outbound_new_dst_ports",
		} {
			if strings.Contains(desc, `fqName: "`+candidate+`"`) {
				name = candidate
				break
			}
		}
		if name == "" {
			continue
		}
		var encoded dto.Metric
		if err := metric.Write(&encoded); err != nil {
			t.Fatal(err)
		}
		values[name] = encoded.GetGauge().GetValue()
	}
	if len(values) != 2 {
		t.Fatalf("behavior interval metrics=%v, want both retained delta families", values)
	}
	return values
}
