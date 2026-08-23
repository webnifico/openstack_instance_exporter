package main

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func newBehaviorStateTestManager() *ConntrackManager {
	cm := &ConntrackManager{
		outboundBehaviorEnabled: true,
		behaviorSensitivity:     1,
		behaviorPersist:         make(map[behaviorAlertKey]*behaviorPersistState),
		behaviorEmit:            make(map[behaviorEmitKey]*behaviorEmitState),
		miningAlerts:            make(map[behaviorIdentityKey]*miningAlertState),
	}
	for i := 0; i < shardCount; i++ {
		cm.outboundPrev[i] = make(map[BehaviorKey]outboundPrev)
		cm.outboundPrevDstPorts[i] = make(map[BehaviorKey]outboundPrevDstPorts)
		cm.outboundPrevLastSeen[i] = make(map[BehaviorKey]int64)
		cm.inboundPrev[i] = make(map[BehaviorKey]outboundPrev)
		cm.inboundPrevDstPorts[i] = make(map[BehaviorKey]outboundPrevDstPorts)
		cm.inboundPrevLastSeen[i] = make(map[BehaviorKey]int64)
		cm.behaviorEWMA[i] = make(map[behaviorIdentityKey]*behaviorEWMAState)
		cm.behaviorLastSeverity[i] = make(map[behaviorIdentityKey]float64)
	}
	initConntrackMetrics(cm)
	return cm
}

func TestConntrackOutageFreezesBehaviorStateAndSeverity(t *testing.T) {
	cm := newBehaviorStateTestManager()
	ip := IPStrToKey("10.0.0.10")
	remote := IPStrToKey("198.51.100.20")
	ident := behaviorIdentityKey{InstanceUUID: "vm-1", IP: ip, Direction: "outbound"}
	idx := shardIndexBehavior(ident)
	cm.behaviorEWMA[idx][ident] = &behaviorEWMAState{LastSeenUnix: 123, Flows: axisEWMA{Fast: 10, Slow: 10, Initialized: true}}
	cm.behaviorLastSeverity[idx][ident] = 0.73

	stats := newBehaviorStats(false)
	stats.updateDetailedWithCoverage(remote, 443, 6, IPS_SEEN_REPLY, 1, 0, 0, false, false)
	severity := cm.analyzeBehavior(
		stats,
		ip,
		"10.0.0.10",
		"ipv4",
		"domain", "server", "vm-1", "project", "project-name", "user",
		nil,
		metricDescGroup{thresholdConfigKey: "outbound"},
		BehaviorContext{FreezeState: true},
	)

	if severity != 0.73 {
		t.Fatalf("stale collection changed behavior severity: got %v want 0.73", severity)
	}
	if got := cm.behaviorEWMA[idx][ident].LastSeenUnix; got != 123 {
		t.Fatalf("stale collection advanced EWMA state: got last_seen=%d", got)
	}
	if len(cm.outboundPrev[idx]) != 0 || len(cm.behaviorPersist) != 0 {
		t.Fatal("stale collection changed behavior diff or persistence state")
	}
}

func TestFreshZeroFlowPeriodDecaysBehaviorEWMA(t *testing.T) {
	cm := newBehaviorStateTestManager()
	ip := IPStrToKey("10.0.0.10")
	ident := behaviorIdentityKey{InstanceUUID: "vm-1", IP: ip, Direction: "outbound"}
	idx := shardIndexBehavior(ident)
	cm.behaviorEWMA[idx][ident] = &behaviorEWMAState{
		LastSeenUnix: time.Now().Add(-time.Minute).Unix(),
		Flows:        axisEWMA{Fast: 100, Slow: 100, Initialized: true},
	}
	agg := &ConntrackAgg{
		VMIndex:       map[VMIPIdentity]uint32{{InstanceUUID: "vm-1", IP: ip}: 0},
		FlowsIn:       []int{0},
		FlowsOut:      []int{0},
		OutboundStats: []*behaviorStats{nil},
		InboundStats:  []*behaviorStats{nil},
	}
	metrics := make([]prometheus.Metric, 0)
	cm.calculateConntrackMetrics(
		[]IP{{Address: "10.0.0.10", Family: "ipv4"}},
		agg,
		nil,
		nil,
		1000,
		true,
		"domain", "server", "vm-1", "project", "project-name", "user",
		&metrics,
	)
	if got := cm.behaviorEWMA[idx][ident].Flows.Fast; got >= 100 {
		t.Fatalf("zero-flow interval did not decay fast EWMA: got %v", got)
	}
}

func TestLongBehaviorGapResetsBaselineWithoutAnomaly(t *testing.T) {
	cm := newBehaviorStateTestManager()
	ident := behaviorIdentityKey{InstanceUUID: "vm-1", IP: IPStrToKey("10.0.0.10"), Direction: "outbound"}
	idx := shardIndexBehavior(ident)
	cm.behaviorEWMA[idx][ident] = &behaviorEWMAState{
		LastSeenUnix:  time.Now().Unix() - behaviorIdentityTTLSeconds - 1,
		Flows:         axisEWMA{Fast: 1000, Slow: 1000, Initialized: true},
		UniqueRemotes: axisEWMA{Fast: 1000, Slow: 1000, Initialized: true},
	}
	nowUnix := time.Now().Unix()
	signal, anomalies := cm.updateBehaviorEWMA(ident, BehaviorFeature{Flows: 5, UniqueRemotes: 2}, nowUnix)
	if signal != 0 || anomalies.Signal != 0 {
		t.Fatalf("long-gap sample was treated as an anomaly: signal=%v anomalies=%+v", signal, anomalies)
	}
	if got := cm.behaviorEWMA[idx][ident].Flows.Fast; got != 5 {
		t.Fatalf("long-gap baseline was not reset: got %v want 5", got)
	}
}
