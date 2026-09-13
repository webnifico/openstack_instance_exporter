package main

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestCalculateConntrackMetricsSkipsIdentityAbsentFromSnapshot(t *testing.T) {
	cm := &ConntrackManager{outboundBehaviorEnabled: true}
	initConntrackMetrics(cm)

	const instanceUUID = "vm-current"
	oldIP := IPStrToKey("10.0.0.10")
	currentIP := IPStrToKey("10.0.0.20")
	currentIdentity := behaviorIdentityKey{InstanceUUID: instanceUUID, IP: currentIP, Direction: "outbound"}
	behaviorShard := shardIndexBehavior(currentIdentity)
	cm.outboundPrev[behaviorShard] = make(map[BehaviorKey]outboundPrev)
	cm.outboundPrevDstPorts[behaviorShard] = make(map[BehaviorKey]outboundPrevDstPorts)
	cm.outboundPrevLastSeen[behaviorShard] = make(map[BehaviorKey]int64)
	cm.behaviorEWMA[behaviorShard] = make(map[behaviorIdentityKey]*behaviorEWMAState)
	cm.behaviorLastSeverity[behaviorShard] = make(map[behaviorIdentityKey]float64)
	agg := &ConntrackAgg{
		VMIndex: map[VMIPIdentity]uint32{
			{InstanceUUID: instanceUUID, IP: oldIP}:   0,
			{InstanceUUID: "vm-other", IP: currentIP}: 1,
		},
		InstanceFlowTotals: map[string]int{instanceUUID: 7},
		FlowsIn:            []int{2, 3},
		FlowsOut:           []int{5, 6},
	}
	metrics := make([]prometheus.Metric, 0, 3)

	outbound, inbound, total := cm.calculateConntrackMetrics(
		[]IP{{Address: "10.0.0.20", Family: "ipv4"}},
		agg,
		nil,
		nil,
		1000,
		true,
		"domain", "server", instanceUUID, "project", "project-name", "user",
		&metrics,
	)

	if len(metrics) != 0 {
		t.Fatalf("snapshot emitted %d metrics for an absent {instance UUID, IP} identity", len(metrics))
	}
	if outbound != 0 || inbound != 0 {
		t.Fatalf("absent snapshot identity returned behavior signals: outbound=%v inbound=%v", outbound, inbound)
	}
	if len(cm.behaviorEWMA[behaviorShard]) != 0 || len(cm.outboundPrev[behaviorShard]) != 0 || len(cm.outboundPrevLastSeen[behaviorShard]) != 0 {
		t.Fatal("absent snapshot identity advanced behavior state")
	}
	if total != 7 {
		t.Fatalf("instance aggregate total changed: got %d want 7", total)
	}
}

func TestCalculateConntrackMetricsEmitsZeroesForIndexedIdentity(t *testing.T) {
	cm := &ConntrackManager{}
	initConntrackMetrics(cm)

	const (
		instanceUUID = "vm-indexed"
		address      = "10.0.0.30"
	)
	agg := &ConntrackAgg{
		VMIndex: map[VMIPIdentity]uint32{
			{InstanceUUID: instanceUUID, IP: IPStrToKey(address)}: 0,
		},
		FlowsIn:  []int{0},
		FlowsOut: []int{0},
	}
	metrics := make([]prometheus.Metric, 0, 3)

	cm.calculateConntrackMetrics(
		[]IP{{Address: address, Family: "ipv4"}},
		agg,
		nil,
		nil,
		1000,
		true,
		"domain", "server", instanceUUID, "project", "project-name", "user",
		&metrics,
	)

	if len(metrics) != 3 {
		t.Fatalf("indexed zero-flow identity emitted %d metrics, want 3", len(metrics))
	}
	seen := make(map[string]bool, 3)
	for _, metric := range metrics {
		var encoded dto.Metric
		if err := metric.Write(&encoded); err != nil {
			t.Fatal(err)
		}
		if encoded.GetGauge().GetValue() != 0 {
			t.Fatalf("indexed zero-flow metric was nonzero: %v", encoded.GetGauge().GetValue())
		}
		labels := make(map[string]string, len(encoded.Label))
		for _, pair := range encoded.Label {
			labels[pair.GetName()] = pair.GetValue()
		}
		if labels["instance_uuid"] != instanceUUID || labels["ip"] != address || labels["family"] != "ipv4" {
			t.Fatalf("indexed metric labels are incorrect: %v", labels)
		}
		seen[metric.Desc().String()] = true
	}
	if len(seen) != 3 {
		t.Fatalf("indexed identity emitted duplicate descriptors: %v", seen)
	}
}
