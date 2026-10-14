package main

import (
	"fmt"
	"math"
	"testing"
)

func TestDistributedFanoutBaselineBoundaries(t *testing.T) {
	cm := &ConntrackManager{behaviorSensitivity: 1}
	for _, sensitivity := range []float64{0.1, 0.5, 1, 2, 10} {
		sc := newBehaviorScaler(sensitivity)
		for _, tc := range []struct {
			name                              string
			flowDelta, remoteDelta            int
			ratio, flowAnomaly, remoteAnomaly float64
			direction                         string
			want                              bool
		}{
			{"at boundaries", 0, 0, sc.ratioThresh(.60), sc.anomThresh(.80), sc.anomThresh(.80), "outbound", true},
			{"below flow floor", -1, 0, 1, 1, 1, "outbound", false},
			{"below remote floor", 0, -1, 1, 1, 1, "outbound", false},
			{"below unreplied floor", 0, 0, math.Nextafter(sc.ratioThresh(.60), 0), 1, 1, "outbound", false},
			{"flow baseline alone", 0, 0, 1, 1, 0, "outbound", false},
			{"remote baseline alone", 0, 0, 1, 0, 1, "outbound", false},
			{"steady known traffic", 0, 0, 1, 0, 0, "outbound", false},
			{"inbound", 0, 0, 1, 1, 1, "inbound", false},
		} {
			t.Run(fmt.Sprintf("sensitivity_%g/%s", sensitivity, tc.name), func(t *testing.T) {
				f := BehaviorFeature{Direction: tc.direction, Flows: sc.scaleIntHigh(20) + tc.flowDelta, UniqueRemotes: sc.scaleIntHigh(30) + tc.remoteDelta, UniqueDstPorts: 10, MaxSingleRemote: 1, MaxSingleDstPort: 1, UnrepliedRatio: tc.ratio}
				hit, signal, _ := cm.classifyOutboundScanning(f, behaviorAnomalies{Flows: tc.flowAnomaly, Remotes: tc.remoteAnomaly}, sc)
				if hit != tc.want || (hit && signal != "outbound_distributed_fanout_unreplied") {
					t.Fatalf("hit=%v signal=%q, want %v", hit, signal, tc.want)
				}
			})
		}
	}
}

func fanoutBaselineFixture(t *testing.T) (*ConntrackManager, behaviorIdentityKey, *[]capturedBehaviorSignal, func(int64, *behaviorStats, bool, bool)) {
	t.Helper()
	cm := newBehaviorStateTestManager()
	cm.behaviorOutboundPortNames = map[uint16]string{80: "http", 443: "https", 8080: "http-alt", 8443: "https-alt"}
	events := captureBehaviorSignals(cm)
	ip := IPStrToKey("10.0.0.10")
	ident := behaviorIdentityKey{InstanceUUID: "fanout-vm", IP: ip, Direction: "outbound"}
	observe := func(at int64, s *behaviorStats, freeze, recovery bool) {
		cm.analyzeBehavior(s, ip, "10.0.0.10", "ipv4", "domain", "server", ident.InstanceUUID, "project", "project-name", "user", nil, metricDescGroup{thresholdConfigKey: "outbound"}, BehaviorContext{ObservationUnix: at, FreezeState: freeze, Rebaseline: recovery})
	}
	return cm, ident, events, observe
}

func fanoutBaselineStats(flows, remotes int, replied bool) *behaviorStats {
	s := newBehaviorStats(false)
	ports := []uint16{80, 443, 8080, 8443}
	var status uint32
	if replied {
		status = IPS_SEEN_REPLY
	}
	for i := 0; i < flows; i++ {
		s.updateDetailedWithCoverage(IPStrToKey(fmt.Sprintf("198.51.%d.%d", (i%remotes)/250+100, (i%remotes)%250+1)), ports[i%len(ports)], 6, status, 1, 0, 0, false, false)
	}
	return s
}

func TestDistributedFanoutObservedStepSurvivesPersistence(t *testing.T) {
	for _, flows := range []int{80, 120} {
		t.Run(fmt.Sprintf("flows_%d", flows), func(t *testing.T) {
			_, _, events, observe := fanoutBaselineFixture(t)
			observe(100, fanoutBaselineStats(12, 4, true), false, false)
			high := fanoutBaselineStats(flows, 40, false)
			observe(115, high, false, false)
			observe(130, high, false, false)
			if len(*events) != 0 {
				t.Fatal("emitted before the persistence gate")
			}
			observe(145, high, false, false)
			if len(*events) != 1 || (*events)[0]["signal"] != "outbound_distributed_fanout_unreplied" {
				t.Fatalf("sustained measured baseline change did not qualify: %#v", *events)
			}
		})
	}
}

func TestDistributedFanoutBaselineLearningFreezeAndRecovery(t *testing.T) {
	cm, ident, events, observe := fanoutBaselineFixture(t)
	high := fanoutBaselineStats(120, 40, false)
	for _, at := range []int64{100, 115, 130, 145} {
		observe(at, high, false, false)
	}
	if len(*events) != 0 {
		t.Fatal("startup traffic manufactured a baseline deviation")
	}
	before := *cm.behaviorObservations[shardIndexBehavior(ident)][ident]
	observe(1000, fanoutBaselineStats(480, 160, false), true, false)
	if got := *cm.behaviorObservations[shardIndexBehavior(ident)][ident]; got != before {
		t.Fatal("incomplete observation advanced the baseline")
	}
	observe(160, fanoutBaselineStats(480, 160, false), false, true)
	for _, at := range []int64{175, 190, 205} {
		observe(at, fanoutBaselineStats(480, 160, false), false, false)
	}
	if len(*events) != 0 || len(cm.behaviorPersist) != 0 {
		t.Fatal("outage-time growth became a recovery anomaly")
	}
	observe(220, newBehaviorStats(false), false, false)
	if len(cm.behaviorPersist) != 0 {
		t.Fatal("clean observation retained fanout persistence")
	}
	if snapshot, ok := cm.behaviorIntervalSnapshot(ident); !ok || snapshot.NewRemotes != 0 || snapshot.NewDstPorts != 0 {
		t.Fatalf("zero-flow observation retained stale deltas: %+v", snapshot)
	}
}

func TestDistributedFanoutRepeatedSnapshotDoesNotTrainBaseline(t *testing.T) {
	cm, ident, events, observe := fanoutBaselineFixture(t)
	observe(100, fanoutBaselineStats(12, 4, true), false, false)
	high := fanoutBaselineStats(120, 40, false)
	observe(115, high, false, false)
	before := *cm.behaviorObservations[shardIndexBehavior(ident)][ident]
	for i := 0; i < 100; i++ {
		observe(115, high, false, false)
	}
	if got := *cm.behaviorObservations[shardIndexBehavior(ident)][ident]; got != before {
		t.Fatal("replaying one observation trained the baseline")
	}
	observe(130, high, false, false)
	observe(145, high, false, false)
	if len(*events) != 1 {
		t.Fatalf("repeated observations changed the later qualification: %d events", len(*events))
	}
}
