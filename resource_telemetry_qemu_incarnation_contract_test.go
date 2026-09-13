package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	libvirt "github.com/digitalocean/go-libvirt"
)

func writeResourceTelemetryFakeQEMUProcess(t *testing.T, procRoot string, pid int, instanceUUID string, startTime uint64) {
	t.Helper()
	processDir := filepath.Join(procRoot, strconv.Itoa(pid))
	if err := os.MkdirAll(processDir, 0o755); err != nil {
		t.Fatal(err)
	}
	argv := []byte("/usr/bin/qemu-system-x86_64\x00-name\x00guest=instance-test\x00-uuid\x00" + instanceUUID + "\x00")
	if err := os.WriteFile(filepath.Join(processDir, "cmdline"), argv, 0o600); err != nil {
		t.Fatal(err)
	}
	fields := make([]string, 20)
	for index := range fields {
		fields[index] = "0"
	}
	fields[0] = "S"
	fields[19] = strconv.FormatUint(startTime, 10)
	stat := fmt.Sprintf("%d (qemu worker) %s\n", pid, strings.Join(fields, " "))
	if err := os.WriteFile(filepath.Join(processDir, "stat"), []byte(stat), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestResourceTelemetryQEMUProcessSnapshotUsesBootPIDAndStartTime(t *testing.T) {
	root := t.TempDir()
	procRoot := filepath.Join(root, "proc")
	if err := os.MkdirAll(procRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	bootIDPath := filepath.Join(root, "boot_id")
	if err := os.WriteFile(bootIDPath, []byte("boot-a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const uuid = "00112233-4455-6677-8899-aabbccddeeff"
	writeResourceTelemetryFakeQEMUProcess(t, procRoot, 101, uuid, 4242)

	snapshot, err := scanQEMUProcessIncarnations(procRoot, bootIDPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := snapshot[uuid]; got != "boot-a:101:4242" {
		t.Fatalf("process incarnation token=%q want %q", got, "boot-a:101:4242")
	}

	writeResourceTelemetryFakeQEMUProcess(t, procRoot, 202, uuid, 5252)
	if _, err := scanQEMUProcessIncarnations(procRoot, bootIDPath); err == nil {
		t.Fatal("duplicate QEMU UUID was accepted as an unambiguous process incarnation")
	}
}

func TestResourceTelemetryQEMUProcessSnapshotMustBracketCompleteLibvirtCycle(t *testing.T) {
	records := []libvirt.DomainStatsRecord{{Dom: libvirt.Domain{
		UUID: libvirt.UUID{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
	}}}
	const uuid = "00112233-4455-6677-8899-aabbccddeeff"
	stable, err := stableQEMUProcessTokens(records, map[string]string{uuid: "boot-a:1:10"}, map[string]string{uuid: "boot-a:1:10"})
	if err != nil || stable[uuid] != "boot-a:1:10" {
		t.Fatalf("stable process incarnation rejected: tokens=%v err=%v", stable, err)
	}
	for name, after := range map[string]map[string]string{
		"changed": {uuid: "boot-a:1:20"},
		"missing": {},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := stableQEMUProcessTokens(records, map[string]string{uuid: "boot-a:1:10"}, after); err == nil {
				t.Fatal("unstable process incarnation was accepted")
			}
		})
	}
}

func TestResourceTelemetryChangedProcessTokenResetsSameIDWithHigherCounters(t *testing.T) {
	mc := newCollectorOrchestrationTestCollector(t)
	uuidBytes := libvirt.UUID{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	const uuid = "00112233-4455-6677-8899-aabbccddeeff"
	base := time.Unix(1_700_800_000, 0)
	if mc.im.observeInstanceResourceGenerationWithToken(uuid, 7, 100, true, "boot-a:101:1000", true) {
		t.Fatal("first process token was reported as a transition")
	}
	idx := shardIndex(uuid)
	mc.im.cpuSamples[idx][uuid] = cpuSample{total: 100, ts: base}
	mc.im.memSamples[idx][uuid] = memSample{swapIn: 100, ts: base}
	mc.im.diskSamples[idx][uuid+"|volume-a|vda"] = diskSample{rdReq: 100, ts: base}
	mc.im.netSamples[idx][uuid] = netSample{interfaces: map[string]netDeviceCounters{"tap-a": {rxPkts: 100}}, ts: base}
	mc.im.resourceDimensions[uuid] = resourceDimensions{vcpuCount: 2, memMB: 4096, vcpuKnown: true, memKnown: true}
	for cycle := 0; cycle < 3; cycle++ {
		out, state := mc.computeResourceV2(uuid, resourceTelemetryCPUInput(base.Add(time.Duration(cycle)*time.Second), 1))
		syncResourceV2EventState(out, state)
	}

	record := libvirt.DomainStatsRecord{
		Dom:    libvirt.Domain{UUID: uuidBytes, ID: 7},
		Params: []libvirt.TypedParam{typedParam("cpu.time", uint64(200))},
	}
	mc.applyPreparedRuntimeGenerations([]libvirt.DomainStatsRecord{record}, &preparedLibvirtCycle{
		runtimeTokens: map[string]string{uuid: "boot-a:101:2000"},
	})

	if len(mc.im.cpuSamples[idx])+len(mc.im.memSamples[idx])+len(mc.im.diskSamples[idx])+len(mc.im.netSamples[idx]) != 0 {
		t.Fatal("changed process token retained cross-QEMU rate baselines")
	}
	if _, exists := mc.im.resourceDimensions[uuid]; exists {
		t.Fatal("changed process token retained runtime dimensions")
	}
	state, ok := mc.lookupResourceV2State(uuid)
	if !ok || !state.NeedsRebaseline || state.Cpu.Initialized || state.Composite.Initialized ||
		state.OverallHi95Streak != 0 || state.LastBand != 0 || state.LastTopAxis != "" || state.LastCapActive {
		t.Fatalf("changed process token retained resource/persistence/event state: %+v", state)
	}
	if got := mc.im.resourceGenerationToken[uuid]; got != "boot-a:101:2000" {
		t.Fatalf("stored process token=%q", got)
	}
	if got := mc.im.resourceGenerationCPUTime[uuid]; got != 200 {
		t.Fatalf("stored new-process CPU time=%d want 200", got)
	}
}
