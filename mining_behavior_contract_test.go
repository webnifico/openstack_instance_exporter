package main

import (
	"strconv"
	"testing"
)

func TestBehaviorMiningBenignMiningPortCollisionCorpus(t *testing.T) {
	cases := []struct {
		name            string
		port            uint16
		sharedCollision bool
	}{
		{name: "VNC on 5900", port: 5900, sharedCollision: true},
		{name: "debug service on 6060", port: 6060, sharedCollision: true},
		{name: "alternate-port web service", port: 8008, sharedCollision: true},
		{name: "Nomad service traffic", port: 4646, sharedCollision: true},
		{name: "Kubernetes health endpoint", port: 10256, sharedCollision: true},
		{name: "monitoring agent", port: 9100},
		{name: "ordinary long-lived TCP session", port: 7777, sharedCollision: true},
		{name: "backup or replication traffic", port: 873},
		{name: "reverse proxy", port: 8080},
		{name: "database client", port: 5432},
		{name: "package download", port: 443},
	}

	for index, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			stats := newBehaviorStats(false)
			remote := IPStrToKey("198.51.100." + strconv.Itoa(index+100))
			stats.updateOutboundMining(remote, tt.port, 6, IPS_SEEN_REPLY|IPS_ASSURED, true)
			high, shared := stats.summarizeMining(nil)
			evidence := selectMiningDetectionEvidence(BehaviorFeature{
				Direction:    "outbound",
				MiningHigh:   high,
				MiningShared: shared,
			}, newBehaviorScaler(1))

			if !tt.sharedCollision {
				if evidence.Valid {
					t.Fatalf("ordinary service traffic became mining evidence: %+v", evidence)
				}
				return
			}
			if !evidence.Valid || evidence.Confidence != miningPortConfidenceSharedPersistent {
				t.Fatalf("shared-port collision tier=%+v, want observable shared_persistent only", evidence)
			}

			feature := miningAlertStateFeature(evidence.Confidence, IPKeyToString(evidence.TopRemote), evidence.Flows, evidence.RepliedFlows)
			feature.TopDstPort = tt.port
			feature.Mining = evidence
			cm := newBehaviorStateTestManager()
			ident := behaviorIdentityKey{InstanceUUID: "benign-" + strconv.Itoa(index), IP: IPStrToKey("10.0.0.10"), Direction: "outbound"}
			var outcome miningAlertOutcome
			for _, now := range []int64{100, 115, 130, 145, 160, 175} {
				outcome = cm.updateMiningAlertState(feature, ident, now)
			}
			if !outcome.Confirmed || outcome.ShouldEmit || outcome.SuppressReason != "corroboration_required" {
				t.Fatalf("shared collision escaped candidate-only lifecycle: %+v", outcome)
			}
			if got := applyConfirmedBehaviorPriorityFloor(0.1, outcome); got != 0.1 {
				t.Fatalf("shared collision raised behavior severity to %v", got)
			}
		})
	}
}

func TestBehaviorMiningMiningEvidenceTierPositiveCorpus(t *testing.T) {
	cases := []struct {
		name       string
		port       uint16
		flows      int
		want       miningPortConfidence
		structured bool
	}{
		{name: "dedicated pool port with multiple replied flows", port: 10128, flows: 2, want: miningPortConfidenceHigh, structured: true},
		{name: "dedicated pool port with one persistent replied flow", port: 10128, flows: 1, want: miningPortConfidenceHighPersistent},
		{name: "shared port with sustained CPU candidate", port: 7777, flows: 3, want: miningPortConfidenceShared},
		{name: "shared port without meaningful CPU candidate", port: 7777, flows: 3, want: miningPortConfidenceShared},
		{name: "shared persistent connection", port: 7777, flows: 1, want: miningPortConfidenceSharedPersistent},
		{name: "low-CPU or GPU-like dedicated evidence", port: 10128, flows: 2, want: miningPortConfidenceHigh, structured: true},
	}

	for index, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			stats := newBehaviorStats(false)
			remote := IPStrToKey("198.51.100." + strconv.Itoa(index+120))
			for flow := 0; flow < tt.flows; flow++ {
				stats.updateOutboundMining(remote, tt.port, 6, IPS_SEEN_REPLY|IPS_ASSURED, true)
			}
			high, shared := stats.summarizeMining(nil)
			evidence := selectMiningDetectionEvidence(BehaviorFeature{
				Direction:    "outbound",
				MiningHigh:   high,
				MiningShared: shared,
			}, newBehaviorScaler(1))
			if !evidence.Valid || evidence.Confidence != tt.want {
				t.Fatalf("evidence=%+v, want confidence %s", evidence, tt.want.String())
			}
			if (evidence.Confidence == miningPortConfidenceHigh) != tt.structured {
				t.Fatalf("standalone structured eligibility mismatch for %s", evidence.Confidence.String())
			}
		})
	}
}
