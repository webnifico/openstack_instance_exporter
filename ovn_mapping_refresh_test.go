package main

import (
	"testing"
	"time"
)

func TestOVNMappingMergesIPsAcrossPortsForSameZoneAndInstance(t *testing.T) {
	port1 := "11111111-1111-1111-1111-111111111111"
	port2 := "22222222-2222-2222-2222-222222222222"
	ip1 := IPStrToKey("10.0.0.10")
	ip2 := IPStrToKey("2001:db8::10")
	out := []byte(port1 + " 42\n" + port2 + " 42\n")

	zones, ips, _, err := parseOVNZoneList(out,
		map[string]string{port1: "vm-1", port2: "vm-1"},
		map[string][]IPKey{port1: {ip1}, port2: {ip2}},
	)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if zones[42] != "vm-1" || len(ips[42]) != 2 {
		t.Fatalf("mapping was not merged: zones=%v ips=%v", zones, ips)
	}
}

func TestOVNMappingSkipsNonPortZonesWithoutDiscardingPortMappings(t *testing.T) {
	port := "11111111-1111-1111-1111-111111111111"
	ip := IPStrToKey("10.0.0.10")
	out := []byte("neutron-router-a_dnat 17\n" + port + " 42\nneutron-router-a_snat 18\n")

	zones, ips, stats, err := parseOVNZoneList(out,
		map[string]string{port: "vm-1"},
		map[string][]IPKey{port: {ip}},
	)
	if err != nil {
		t.Fatalf("valid port mapping was discarded with non-port OVN zones present: %v", err)
	}
	if len(zones) != 1 || zones[42] != "vm-1" || len(ips[42]) != 1 {
		t.Fatalf("unexpected mapping after non-port zones: zones=%v ips=%v", zones, ips)
	}
	if stats.linesTotal != 3 || stats.linesParsed != 1 || stats.linesNoUUID != 2 {
		t.Fatalf("unexpected parser stats: %+v", stats)
	}
}

func TestOVNMappingWithOnlyNonPortZonesIsUnusable(t *testing.T) {
	_, _, stats, err := parseOVNZoneList([]byte("neutron-router-a_dnat 17\nneutron-router-a_snat 18\n"), nil, nil)
	if err == nil {
		t.Fatal("non-port-only OVN output was accepted as a usable instance mapping")
	}
	if stats.linesTotal != 2 || stats.linesNoUUID != 2 || stats.linesParsed != 0 {
		t.Fatalf("unexpected parser stats: %+v", stats)
	}
}

func TestOVNMappingRejectsAmbiguousDuplicateZone(t *testing.T) {
	port1 := "11111111-1111-1111-1111-111111111111"
	port2 := "22222222-2222-2222-2222-222222222222"
	out := []byte(port1 + " 42\n" + port2 + " 42\n")
	_, _, _, err := parseOVNZoneList(out,
		map[string]string{port1: "vm-1", port2: "vm-2"},
		map[string][]IPKey{port1: {IPStrToKey("10.0.0.1")}, port2: {IPStrToKey("10.0.0.2")}},
	)
	if err == nil {
		t.Fatal("expected ambiguous duplicate-zone error")
	}
}

func TestOVNMappingRejectsEmptyMalformedAndUnusableOutput(t *testing.T) {
	port := "11111111-1111-1111-1111-111111111111"
	tests := [][]byte{
		nil,
		[]byte("not-a-zone-list\n"),
		[]byte(port + " 7\n"),
	}
	for i, out := range tests {
		_, _, _, err := parseOVNZoneList(out, map[string]string{port: "vm-1"}, nil)
		if err == nil {
			t.Fatalf("case %d: expected unusable output error", i)
		}
	}
}

func TestOVNRefreshFailurePreservesLastGoodMappingsAndStaleness(t *testing.T) {
	m := NewOVNMapper()
	port := "11111111-1111-1111-1111-111111111111"
	good := []byte(port + " 9\n")
	if err := m.refreshFromOutput(good, map[string]string{port: "vm-1"}, map[string][]IPKey{port: {IPStrToKey("10.0.0.9")}}); err != nil {
		t.Fatalf("good refresh failed: %v", err)
	}
	last := m.LastRefresh()
	if err := m.refreshFromOutput([]byte("garbage\n"), map[string]string{port: "vm-1"}, nil); err == nil {
		t.Fatal("expected bad refresh to fail")
	}
	if got := m.GetInstance(9); got != "vm-1" {
		t.Fatalf("last-good mapping was lost: %q", got)
	}
	if !m.LastRefresh().Equal(last) {
		t.Fatal("failed refresh changed last-success time")
	}
	if !m.IsStale(last.Add(2*time.Minute), time.Minute) {
		t.Fatal("stale mapping was not detected")
	}
}

func TestOVNPortSnapshotMarksAmbiguousOwnershipUnusable(t *testing.T) {
	port := "11111111-1111-1111-1111-111111111111"
	im := &InstanceManager{domainMeta: map[string]*DomainStatic{
		"vm-1": {PortUUIDs: []string{port}},
		"vm-2": {PortUUIDs: []string{port}},
	}}
	got := im.snapshotOVNPortToInstance(map[string]struct{}{"vm-1": {}, "vm-2": {}})
	if owner, ok := got[port]; !ok || owner != "" {
		t.Fatalf("ambiguous port ownership silently chose %q", owner)
	}
	if _, _, _, err := parseOVNZoneList([]byte(port+" 12\n"), got, map[string][]IPKey{port: {IPStrToKey("10.0.0.12")}}); err == nil {
		t.Fatal("ambiguous port ownership produced a usable zone mapping")
	}
}
