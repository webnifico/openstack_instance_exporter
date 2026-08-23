package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLooksLikeUUID36Validation(t *testing.T) {
	for _, value := range []string{
		"00112233-4455-6677-8899-aabbccddeeff",
		"AABBCCDD-EEFF-0011-2233-445566778899",
	} {
		if !looksLikeUUID36(value) {
			t.Fatalf("valid UUID %q was rejected", value)
		}
	}
	for _, value := range []string{
		"",
		"00112233-4455-6677-8899-aabbccddee",
		"001122334455-6677-8899-aabbccddeeff",
		"00112233-4455-6677-8899-aabbccddee!f",
		"00112233_4455-6677-8899-aabbccddeeff",
	} {
		if looksLikeUUID36(value) {
			t.Fatalf("invalid UUID %q was accepted", value)
		}
	}
}

func TestOVNZoneParserStatsUnknownPortsAndValidation(t *testing.T) {
	knownPort := "11111111-1111-1111-1111-111111111111"
	unknownPort := "22222222-2222-2222-2222-222222222222"
	ip := IPStrToKey("192.0.2.10")
	zones, ips, stats, err := parseOVNZoneList(
		[]byte("header "+unknownPort+" 8\nzone "+knownPort+" 9 extra\n"),
		map[string]string{knownPort: "vm-1"},
		map[string][]IPKey{knownPort: {{}, ip, ip}},
	)
	if err != nil {
		t.Fatalf("OVN zone parse failed: %v", err)
	}
	if zones[9] != "vm-1" || len(ips[9]) != 1 {
		t.Fatalf("OVN parse result zones=%v ips=%v", zones, ips)
	}
	if stats.linesTotal != 2 || stats.linesParsed != 1 || stats.linesUnknownPort != 1 {
		t.Fatalf("OVN parse stats=%+v", stats)
	}

	tests := []struct {
		name     string
		out      string
		byPort   map[string]string
		byIP     map[string][]IPKey
		wantStat func(ovnRefreshStats) bool
	}{
		{
			name:   "too few fields",
			out:    "single",
			byPort: map[string]string{},
			byIP:   map[string][]IPKey{},
		},
		{
			name:     "missing uuid",
			out:      "zone 12",
			byPort:   map[string]string{},
			byIP:     map[string][]IPKey{},
			wantStat: func(s ovnRefreshStats) bool { return s.linesNoUUID == 1 },
		},
		{
			name:     "missing zone",
			out:      knownPort + " not-a-zone",
			byPort:   map[string]string{knownPort: "vm-1"},
			byIP:     map[string][]IPKey{knownPort: {ip}},
			wantStat: func(s ovnRefreshStats) bool { return s.linesNoZone == 1 },
		},
		{
			name:   "empty owner",
			out:    knownPort + " 12",
			byPort: map[string]string{knownPort: ""},
			byIP:   map[string][]IPKey{knownPort: {ip}},
		},
		{
			name:   "only zero IP",
			out:    knownPort + " 12",
			byPort: map[string]string{knownPort: "vm-1"},
			byIP:   map[string][]IPKey{knownPort: {{}}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, gotStats, err := parseOVNZoneList([]byte(tc.out+"\n"), tc.byPort, tc.byIP)
			if err == nil {
				t.Fatal("invalid OVN output unexpectedly succeeded")
			}
			if tc.wantStat != nil && !tc.wantStat(gotStats) {
				t.Fatalf("unexpected parser stats: %+v", gotStats)
			}
		})
	}
}

func TestOVNMapperAccessorsReturnExpectedIsolation(t *testing.T) {
	m := NewOVNMapper()
	if got := m.GetInstance(1); got != "" {
		t.Fatalf("missing instance=%q, want empty", got)
	}
	if got := m.GetIPs(1); got != nil {
		t.Fatalf("missing IP set=%v, want nil", got)
	}
	if !m.IsStale(time.Now(), time.Minute) {
		t.Fatal("never-refreshed mapper did not report stale")
	}
	if m.IsStale(time.Now(), 0) {
		t.Fatal("staleness check with disabled max age reported stale")
	}

	port := "11111111-1111-1111-1111-111111111111"
	ip := IPStrToKey("192.0.2.20")
	if err := m.refreshFromOutput([]byte(port+" 20\n"), map[string]string{port: "vm-20"}, map[string][]IPKey{port: {ip}}); err != nil {
		t.Fatal(err)
	}
	if m.GetInstance(20) != "vm-20" {
		t.Fatal("refreshed instance mapping was not returned")
	}
	copySet := m.GetIPs(20)
	delete(copySet, ip)
	if len(m.GetIPs(20)) != 1 {
		t.Fatal("GetIPs returned an alias of mapper state")
	}
	zones, ipSets := m.SnapshotRefs()
	if zones[20] != "vm-20" || len(ipSets[20]) != 1 {
		t.Fatalf("snapshot refs zones=%v ips=%v", zones, ipSets)
	}
	if m.IsStale(time.Now(), time.Hour) {
		t.Fatal("recently refreshed mapper reported stale")
	}
}

func TestOVNRefreshExecutesCommandPreservesOnFailureAndThrottles(t *testing.T) {
	binDir := t.TempDir()
	toolPath := filepath.Join(binDir, "ovs-appctl")
	port := "11111111-1111-1111-1111-111111111111"
	writeTool := func(body string) {
		t.Helper()
		if err := os.WriteFile(toolPath, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeTool("printf '%s\\n' '" + port + " 42'")
	t.Setenv("PATH", binDir)

	m := NewOVNMapper()
	m.socketPath = "/tmp/test-ovn-controller.ctl"
	ip := IPStrToKey("192.0.2.42")
	if err := m.Refresh(map[string]string{port: "vm-42"}, map[string][]IPKey{port: {ip}}); err != nil {
		t.Fatalf("command-backed OVN refresh failed: %v", err)
	}
	if m.GetInstance(42) != "vm-42" || m.LastRefresh().IsZero() {
		t.Fatal("command-backed refresh did not store mapping and timestamp")
	}

	// A recent success must suppress another expensive command invocation.
	writeTool("exit 1")
	if err := m.Refresh(nil, nil); err != nil {
		t.Fatalf("recent-success throttle returned an error: %v", err)
	}
	if m.GetInstance(42) != "vm-42" {
		t.Fatal("recent-success throttle changed mapping")
	}

	// Once both throttles expire, command failure must retain last-good data and
	// clear the cached socket so a later attempt can rediscover it.
	m.Lock()
	m.lastRefresh = time.Now().Add(-time.Minute)
	m.lastAttempt = time.Now().Add(-time.Minute)
	m.socketPath = "/tmp/test-ovn-controller.ctl"
	m.Unlock()
	if err := m.Refresh(nil, nil); err == nil || !strings.Contains(err.Error(), "zone refresh failed") {
		t.Fatalf("failing OVN command returned %v", err)
	}
	if m.GetInstance(42) != "vm-42" {
		t.Fatal("failed command refresh discarded last-good mapping")
	}
	m.RLock()
	gotSocket := m.socketPath
	m.RUnlock()
	if gotSocket != "" {
		t.Fatalf("failed command retained cached socket %q", gotSocket)
	}

	// A recent attempt is also throttled even when no successful refresh exists.
	m.Lock()
	m.lastRefresh = time.Time{}
	m.lastAttempt = time.Now()
	m.socketPath = "/tmp/test-ovn-controller.ctl"
	m.Unlock()
	if err := m.Refresh(nil, nil); err != nil {
		t.Fatalf("recent-attempt throttle returned an error: %v", err)
	}
}

func TestOVNSocketDetection(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.sock")
	if isSocket(missing) {
		t.Fatal("missing path reported as a socket")
	}
	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	if isSocket(regular) {
		t.Fatal("regular file reported as a socket")
	}
	socketPath := filepath.Join(dir, "ovn.sock")
	listener, err := net.Listen("unix", socketPath)
	if err == nil {
		defer listener.Close()
		if !isSocket(socketPath) {
			t.Fatal("Unix socket was not detected")
		}
	} else {
		t.Logf("Unix socket creation is unavailable in this sandbox: %v", err)
	}

	if path, err := pickOvnControllerCtlSocket(); err == nil {
		if !isSocket(path) {
			t.Fatalf("socket picker returned non-socket path %q", path)
		}
	}
}

func TestOVNPortIPSnapshotsFilterAndMerge(t *testing.T) {
	port1 := "11111111-1111-1111-1111-111111111111"
	port2 := "22222222-2222-2222-2222-222222222222"
	im := newInventoryStateTestManager()
	im.domainMeta["vm-1"] = &DomainStatic{
		PortUUIDs: []string{port1, "short"},
		PortIPsByUUID: map[string][]IP{
			port1: {{Address: "192.0.2.1"}, {Address: "bad"}},
			"bad": {{Address: "192.0.2.99"}},
		},
	}
	im.domainMeta["vm-2"] = &DomainStatic{
		PortUUIDs: []string{port2},
		PortIPsByUUID: map[string][]IP{
			port2: {{Address: "2001:db8::1"}},
		},
	}
	im.domainMeta["nil"] = nil
	active := map[string]struct{}{"vm-1": {}, "vm-2": {}, "nil": {}, "missing": {}}
	owners := im.snapshotOVNPortToInstance(active)
	if owners[port1] != "vm-1" || owners[port2] != "vm-2" || len(owners) != 2 {
		t.Fatalf("OVN owner snapshot=%v", owners)
	}
	ips := im.snapshotOVNPortToIPKeys(active)
	if len(ips[port1]) != 1 || len(ips[port2]) != 1 || len(ips) != 2 {
		t.Fatalf("OVN IP snapshot=%v", ips)
	}
}
