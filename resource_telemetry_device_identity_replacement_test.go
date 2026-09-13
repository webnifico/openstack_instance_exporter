package main

import (
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func resourceTelemetryDeviceIdentityDiskStat(name string, value uint64) *DiskStat {
	return &DiskStat{
		Name: name, NamePresent: true,
		RdReqs: value, RdReqsPresent: true,
		WrReqs: value, WrReqsPresent: true,
		RdBytes: value * 1024, RdBytesPresent: true,
		WrBytes: value * 1024, WrBytesPresent: true,
		RdTime: value * 1_000_000, RdTimePresent: true,
		WrTime: value * 1_000_000, WrTimePresent: true,
		FlReqs: value, FlReqsPresent: true,
		FlTime: value * 1_000_000, FlTimePresent: true,
	}
}

func resourceTelemetryDeviceIdentityDiskObservation(
	mc *MetricsCollector,
	meta *DomainStatic,
	instanceUUID string,
	now time.Time,
	value uint64,
) (bool, string, []string, bool) {
	metrics := make([]prometheus.Metric, 0)
	_, _, _, available, identity, sources, identityKnown := mc.collectDomainDiskMetricsWithSources(
		meta,
		&ParsedStats{
			BlockCount:        1,
			BlockCountPresent: true,
			Disks:             map[int]*DiskStat{0: resourceTelemetryDeviceIdentityDiskStat("vda", value)},
		},
		now,
		"domain", "server", instanceUUID, "project", "project-name", "user",
		true,
		&metrics,
	)
	return available, identity, sources, identityKnown
}

func resourceTelemetryDeviceIdentityNetStat(name string, packets uint64) *NetStat {
	return &NetStat{
		Name: name, NamePresent: true,
		RxPkts: packets, RxPktsPresent: true,
		TxPkts: packets, TxPktsPresent: true,
		RxDropPresent: true,
		TxDropPresent: true,
	}
}

func resourceTelemetryDeviceIdentityNetObservation(
	mc *MetricsCollector,
	meta *DomainStatic,
	instanceUUID string,
	now time.Time,
	packets uint64,
) (bool, string, []string) {
	metrics := make([]prometheus.Metric, 0)
	_, _, _, _, _, available, _, identity, sources := mc.collectDomainNetworkAndConntrackWithSources(
		meta,
		&ParsedStats{
			NetCount:        1,
			NetCountPresent: true,
			Nets:            map[int]*NetStat{0: resourceTelemetryDeviceIdentityNetStat("tap0", packets)},
		},
		now,
		"domain", "server", instanceUUID, "project", "project-name", "user",
		true,
		deduplicateIPs(meta.FixedIPs),
		nil,
		nil,
		nil,
		0,
		false,
		true,
		&metrics,
	)
	return available, identity, sources
}

func TestResourceTelemetryDomainXMLParsesStableBlockAndVolumeSourceIdentity(t *testing.T) {
	xmlDesc := `<domain><devices>
<disk device="disk" type="block"><source dev="/dev/mapper/cinder-volume-a"></source><target dev="vda"></target></disk>
<disk device="disk" type="volume"><source pool="cinder-pool" volume="volume-b"></source><target dev="vdb"></target></disk>
</devices></domain>`

	meta, err := parseDomainStaticFromXML("vm-disk-source-xml", "domain", xmlDesc)
	if err != nil {
		t.Fatalf("parseDomainStaticFromXML error: %v", err)
	}
	if len(meta.Disks) != 2 {
		t.Fatalf("parsed disks=%d, want 2: %+v", len(meta.Disks), meta.Disks)
	}
	block := meta.Disks[0]
	if block.TargetDev != "vda" || block.Type != "block" || block.SourceDev != "/dev/mapper/cinder-volume-a" {
		t.Fatalf("block source identity was not parsed: %+v", block)
	}
	volume := meta.Disks[1]
	if volume.TargetDev != "vdb" || volume.Type != "volume" ||
		volume.SourcePool != "cinder-pool" || volume.SourceVolume != "volume-b" {
		t.Fatalf("pool/volume source identity was not parsed: %+v", volume)
	}
}

func TestResourceTelemetryBlockDiskReplacementOnSameTargetDropsOldAxisAndEWMA(t *testing.T) {
	mc := newCollectorOrchestrationTestCollector(t)
	const instanceUUID = "vm-block-disk-replacement"
	base := time.Unix(1_700_620_000, 0)
	oldMeta := &DomainStatic{Disks: []DomainDisk{{
		Device: "disk", Type: "block", TargetDev: "vda", SourceDev: "/dev/mapper/cinder-old",
	}}}

	available, _, _, _ := resourceTelemetryDeviceIdentityDiskObservation(mc, oldMeta, instanceUUID, base, 10)
	if available {
		t.Fatal("first old-disk rate sample was available")
	}
	available, oldIdentity, oldSources, identityKnown := resourceTelemetryDeviceIdentityDiskObservation(mc, oldMeta, instanceUUID, base.Add(time.Second), 20)
	if !available || !identityKnown || len(oldSources) == 0 || !strings.Contains(oldIdentity, "/dev/mapper/cinder-old") {
		t.Fatalf("old block disk did not establish a complete identity: available=%v known=%v identity=%q sources=%v", available, identityKnown, oldIdentity, oldSources)
	}
	old, state := mc.computeResourceV2(instanceUUID, resourceV2Input{
		Now:               base.Add(time.Second),
		DiskAvailable:     true,
		DiskPRaw:          1,
		DiskConf:          1,
		DiskImpact:        1,
		DiskSources:       oldSources,
		DiskIdentity:      oldIdentity,
		DiskIdentityKnown: true,
	})
	if !old.DISK.Fresh || old.DISK.EWMA != 1 {
		t.Fatalf("old block disk did not establish the high-pressure axis: %+v", old.DISK)
	}
	state.OverallHi95Streak = 3

	newMeta := &DomainStatic{Disks: []DomainDisk{{
		Device: "disk", Type: "block", TargetDev: "vda", SourceDev: "/dev/mapper/cinder-new",
	}}}
	available, newIdentity, newSources, identityKnown := resourceTelemetryDeviceIdentityDiskObservation(mc, newMeta, instanceUUID, base.Add(2*time.Second), 1_000)
	if available || !identityKnown || len(newSources) != 0 || newIdentity == oldIdentity || !strings.Contains(newIdentity, "/dev/mapper/cinder-new") {
		t.Fatalf("replacement transition identity was not authoritative and rate-less: available=%v known=%v old=%q new=%q sources=%v", available, identityKnown, oldIdentity, newIdentity, newSources)
	}
	transition, state := mc.computeResourceV2(instanceUUID, resourceV2Input{
		Now:               base.Add(2 * time.Second),
		DiskAvailable:     available,
		DiskSources:       newSources,
		DiskIdentity:      newIdentity,
		DiskIdentityKnown: identityKnown,
	})
	if transition.DISK.Available || transition.DISK.Retained || !transition.DISK.StructuralChange || transition.DISK.AgeSeconds != -1 {
		t.Fatalf("same-target block replacement retained the old disk axis: %+v", transition.DISK)
	}
	if state.Disk.Initialized || state.Disk.EWMA != 0 || state.Disk.Identity != newIdentity || state.OverallHi95Streak != 0 {
		t.Fatalf("same-target block replacement retained old EWMA/persistence: %+v", state)
	}

	available, stableIdentity, newSources, identityKnown := resourceTelemetryDeviceIdentityDiskObservation(mc, newMeta, instanceUUID, base.Add(3*time.Second), 1_010)
	if !available || !identityKnown || stableIdentity != newIdentity || len(newSources) == 0 {
		t.Fatalf("replacement disk did not establish a new comparable rate: available=%v known=%v identity=%q/%q sources=%v", available, identityKnown, stableIdentity, newIdentity, newSources)
	}
	rebased, state := mc.computeResourceV2(instanceUUID, resourceV2Input{
		Now:               base.Add(3 * time.Second),
		DiskAvailable:     true,
		DiskPRaw:          0.2,
		DiskConf:          1,
		DiskImpact:        1,
		DiskSources:       newSources,
		DiskIdentity:      stableIdentity,
		DiskIdentityKnown: true,
	})
	if !rebased.DISK.Fresh || rebased.DISK.EWMA != 0.2 || rebased.DISK.Alpha != 1 || state.Disk.EWMA != 0.2 {
		t.Fatalf("replacement disk reused the old high-pressure EWMA: %+v state=%+v", rebased.DISK, state.Disk)
	}
}

func TestResourceTelemetryPortUUIDReplacementOnSameNICAndIPStructurallyRebaselines(t *testing.T) {
	mc := newCollectorOrchestrationTestCollector(t)
	const instanceUUID = "vm-port-uuid-replacement"
	base := time.Unix(1_700_621_000, 0)
	oldMeta := &DomainStatic{
		Interfaces: []string{"tap0"},
		FixedIPs:   []IP{{Address: "10.0.0.5", Family: "4"}},
		PortUUIDs:  []string{"port-old"},
	}

	available, _, _ := resourceTelemetryDeviceIdentityNetObservation(mc, oldMeta, instanceUUID, base, 100)
	if available {
		t.Fatal("first old-port rate sample was available")
	}
	available, oldIdentity, oldSources := resourceTelemetryDeviceIdentityNetObservation(mc, oldMeta, instanceUUID, base.Add(time.Second), 200)
	if !available || len(oldSources) != 1 || !strings.Contains(oldIdentity, "port:port-old") {
		t.Fatalf("old port did not establish a complete network identity: available=%v identity=%q sources=%v", available, oldIdentity, oldSources)
	}
	old, state := mc.computeResourceV2(instanceUUID, resourceV2Input{
		Now:              base.Add(time.Second),
		NetAvailable:     true,
		NetPRaw:          1,
		NetConf:          1,
		NetImpact:        1,
		NetSources:       oldSources,
		NetIdentity:      oldIdentity,
		NetIdentityKnown: true,
	})
	if !old.NET.Fresh || old.NET.EWMA != 1 {
		t.Fatalf("old port did not establish the high-pressure axis: %+v", old.NET)
	}
	state.OverallHi95Streak = 3

	newMeta := &DomainStatic{
		Interfaces: []string{"tap0"},
		FixedIPs:   []IP{{Address: "10.0.0.5", Family: "4"}},
		PortUUIDs:  []string{"port-new"},
	}
	available, newIdentity, newSources := resourceTelemetryDeviceIdentityNetObservation(mc, newMeta, instanceUUID, base.Add(2*time.Second), 210)
	if available || newIdentity == oldIdentity || !strings.Contains(newIdentity, "port:port-new") || len(newSources) != 0 {
		t.Fatalf("same-NIC/IP port replacement bridged the old rate baseline: available=%v old=%q new=%q sources=%v", available, oldIdentity, newIdentity, newSources)
	}
	transition, state := mc.computeResourceV2(instanceUUID, resourceV2Input{
		Now:              base.Add(2 * time.Second),
		NetAvailable:     available,
		NetSources:       newSources,
		NetIdentity:      newIdentity,
		NetIdentityKnown: true,
	})
	if transition.NET.Available || transition.NET.Retained || !transition.NET.StructuralChange || transition.NET.AgeSeconds != -1 {
		t.Fatalf("port UUID replacement retained the old network axis: %+v", transition.NET)
	}
	if state.Net.Initialized || state.Net.EWMA != 0 || state.Net.Identity != newIdentity || state.OverallHi95Streak != 0 {
		t.Fatalf("port UUID replacement retained old EWMA/persistence: %+v", state)
	}

	available, stableIdentity, newSources := resourceTelemetryDeviceIdentityNetObservation(mc, newMeta, instanceUUID, base.Add(3*time.Second), 220)
	if !available || stableIdentity != newIdentity || len(newSources) != 1 {
		t.Fatalf("replacement port did not establish a new comparable rate: available=%v identity=%q/%q sources=%v", available, stableIdentity, newIdentity, newSources)
	}
	rebased, state := mc.computeResourceV2(instanceUUID, resourceV2Input{
		Now:              base.Add(3 * time.Second),
		NetAvailable:     true,
		NetPRaw:          0.1,
		NetConf:          1,
		NetImpact:        1,
		NetSources:       newSources,
		NetIdentity:      stableIdentity,
		NetIdentityKnown: true,
	})
	if !rebased.NET.Fresh || rebased.NET.Recovery || rebased.NET.Alpha != 1 || rebased.NET.EWMA != 0.1 || state.Net.EWMA != 0.1 {
		t.Fatalf("replacement port reused the old high-pressure EWMA: axis=%+v state=%+v", rebased.NET, state.Net)
	}
}

func TestResourceTelemetryFixedIPReplacementCannotBridgeNetworkRateBaseline(t *testing.T) {
	mc := newCollectorOrchestrationTestCollector(t)
	const instanceUUID = "vm-fixed-ip-replacement"
	base := time.Unix(1_700_622_000, 0)
	oldMeta := &DomainStatic{
		Interfaces: []string{"tap0"},
		FixedIPs:   []IP{{Address: "10.0.0.5", Family: "4"}},
	}
	available, oldIdentity, _ := resourceTelemetryDeviceIdentityNetObservation(mc, oldMeta, instanceUUID, base, 100)
	if available {
		t.Fatal("first old-IP rate sample was available")
	}
	available, oldIdentity, oldSources := resourceTelemetryDeviceIdentityNetObservation(mc, oldMeta, instanceUUID, base.Add(time.Second), 200)
	if !available || len(oldSources) != 1 || !strings.Contains(oldIdentity, "ip:4:10.0.0.5") {
		t.Fatalf("old fixed IP did not establish a network rate identity: available=%v identity=%q sources=%v", available, oldIdentity, oldSources)
	}

	newMeta := &DomainStatic{
		Interfaces: []string{"tap0"},
		FixedIPs:   []IP{{Address: "10.0.0.6", Family: "4"}},
	}
	available, newIdentity, newSources := resourceTelemetryDeviceIdentityNetObservation(mc, newMeta, instanceUUID, base.Add(2*time.Second), 210)
	if available || len(newSources) != 0 || newIdentity == oldIdentity || !strings.Contains(newIdentity, "ip:4:10.0.0.6") {
		t.Fatalf("fixed-IP replacement bridged the old network baseline: available=%v old=%q new=%q sources=%v", available, oldIdentity, newIdentity, newSources)
	}
	available, stableIdentity, newSources := resourceTelemetryDeviceIdentityNetObservation(mc, newMeta, instanceUUID, base.Add(3*time.Second), 220)
	if !available || stableIdentity != newIdentity || len(newSources) != 1 {
		t.Fatalf("new fixed-IP identity did not recover from its own baseline: available=%v identity=%q/%q sources=%v", available, stableIdentity, newIdentity, newSources)
	}
}
