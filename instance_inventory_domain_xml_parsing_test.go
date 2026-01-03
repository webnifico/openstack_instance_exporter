package main

import (
	"reflect"
	"testing"
)

func TestParseDomainStaticFromXMLMultiNIC(t *testing.T) {
	xmlDesc := `<domain>
<uuid>11111111-1111-1111-1111-111111111111</uuid>
<metadata>
<instance>
<package version="1.0.0"></package>
<name>test-vm</name>
<creationTime>2026-01-01 00:00:00</creationTime>
<flavor name="m1.small">
<memory>1024</memory>
<vcpus>2</vcpus>
</flavor>
<owner>
<user uuid="user-uuid"><name>user</name></user>
<project uuid="proj-uuid">proj</project>
</owner>
<root type="image" uuid="root-uuid"></root>
<ports>
<port uuid="port-a"><ip address="10.0.0.5" ipVersion="4"></ip></port>
<port uuid="port-b"><ip address="fd00::1" ipVersion="6"></ip></port>
</ports>
</instance>
</metadata>
<devices>
<interface><target dev="tapabc"></target></interface>
<interface><target dev="tapdef"></target></interface>
<disk device="disk" type="file">
<source file="/var/lib/libvirt/images/disk.qcow2"></source>
<target dev="vda"></target>
</disk>
</devices>
</domain>`

	meta, err := parseDomainStaticFromXML("inst-uuid", "dom-name", xmlDesc)
	if err != nil {
		t.Fatalf("parseDomainStaticFromXML error: %v", err)
	}
	if meta.Name != "test-vm" {
		t.Fatalf("meta.Name=%q want %q", meta.Name, "test-vm")
	}
	if meta.InstanceUUID != "inst-uuid" {
		t.Fatalf("meta.InstanceUUID=%q want %q", meta.InstanceUUID, "inst-uuid")
	}
	if !reflect.DeepEqual(meta.PortUUIDs, []string{"port-a", "port-b"}) {
		t.Fatalf("meta.PortUUIDs=%v want %v", meta.PortUUIDs, []string{"port-a", "port-b"})
	}
	if got := meta.PortIPsByUUID["port-a"]; len(got) != 1 || got[0].Address != "10.0.0.5" || got[0].Family != "4" {
		t.Fatalf("meta.PortIPsByUUID[port-a]=%v want [{10.0.0.5 4 ...}]", got)
	}
	if got := meta.PortIPsByUUID["port-b"]; len(got) != 1 || got[0].Address != "fd00::1" || got[0].Family != "6" {
		t.Fatalf("meta.PortIPsByUUID[port-b]=%v want [{fd00::1 6 ...}]", got)
	}
	if len(meta.FixedIPs) != 2 {
		t.Fatalf("len(meta.FixedIPs)=%d want 2", len(meta.FixedIPs))
	}
	if !reflect.DeepEqual(meta.Interfaces, []string{"tapabc", "tapdef"}) {
		t.Fatalf("meta.Interfaces=%v want %v", meta.Interfaces, []string{"tapabc", "tapdef"})
	}
	if len(meta.Disks) != 1 || meta.Disks[0].TargetDev != "vda" || meta.Disks[0].SourceFile != "/var/lib/libvirt/images/disk.qcow2" || meta.Disks[0].Type != "file" {
		t.Fatalf("meta.Disks=%v want 1 disk with vda + qcow2 + type file", meta.Disks)
	}
}

func TestParseDomainStaticFromXMLNameFallback(t *testing.T) {
	xmlDesc := `<domain>
<uuid>11111111-1111-1111-1111-111111111111</uuid>
<metadata>
<instance>
<package version="1.0.0"></package>
<name></name>
<creationTime>2026-01-01 00:00:00</creationTime>
<flavor name="m1.small">
<memory>1024</memory>
<vcpus>1</vcpus>
</flavor>
<owner>
<user uuid="user-uuid"><name>user</name></user>
<project uuid="proj-uuid">proj</project>
</owner>
<root type="image" uuid="root-uuid"></root>
<ports></ports>
</instance>
</metadata>
<devices></devices>
</domain>`

	meta, err := parseDomainStaticFromXML("inst-uuid", "dom-fallback", xmlDesc)
	if err != nil {
		t.Fatalf("parseDomainStaticFromXML error: %v", err)
	}
	if meta.Name != "dom-fallback" {
		t.Fatalf("meta.Name=%q want %q", meta.Name, "dom-fallback")
	}
}
