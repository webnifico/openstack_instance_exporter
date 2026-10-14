package main

import "testing"

const specialDeviceUUID = "11111111-2222-4333-8444-555555555555"

func TestBlockDeviceRolesAndEligibility(t *testing.T) {
	for _, tc := range []struct {
		name     string
		disk     DomainDisk
		role     string
		resource bool
	}{
		{"rbd root", DomainDisk{Device: "disk", SourceProtocol: "rbd", SourceName: "vms/" + specialDeviceUUID + "_disk"}, "storage", true},
		{"rbd config cdrom", DomainDisk{Device: "cdrom", SourceProtocol: "rbd", SourceName: "vms/" + specialDeviceUUID + "_disk.config"}, "config_drive", false},
		{"rbd config disk", DomainDisk{Device: "disk", SourceProtocol: "rbd", SourceName: "vms/" + specialDeviceUUID + "_disk.config"}, "config_drive", false},
		{"local config cdrom", DomainDisk{Device: "cdrom", SourceFile: "/instances/vm/disk.config"}, "config_drive", false},
		{"local vfat config", DomainDisk{Device: "disk", SourceFile: "/instances/vm/disk.config"}, "config_drive", false},
		{"local swap", DomainDisk{Device: "disk", SourceFile: "/instances/vm/disk.swap"}, "swap", true},
		{"rbd swap", DomainDisk{Device: "disk", SourceProtocol: "rbd", SourceName: "vms/" + specialDeviceUUID + "_disk.swap"}, "swap", true},
		{"attached ISO", DomainDisk{Device: "cdrom", SourceFile: "/isos/ubuntu.iso"}, "other", false},
		{"empty cdrom", DomainDisk{Device: "cdrom"}, "other", false},
		{"floppy", DomainDisk{Device: "floppy", SourceFile: "/media/floppy.img"}, "other", false},
		{"lun", DomainDisk{Device: "lun", SourceDev: "/dev/mapper/data"}, "storage", true},
		{"default device is disk", DomainDisk{SourceFile: "/instances/vm/disk"}, "storage", true},
		{"arbitrary config-like filename", DomainDisk{Device: "disk", SourceFile: "/images/customer_disk.config"}, "storage", true},
		{"config backup", DomainDisk{Device: "disk", SourceFile: "/images/disk.config.bak"}, "storage", true},
		{"unrelated protocol", DomainDisk{Device: "disk", SourceProtocol: "nbd", SourceName: "exports/disk.config"}, "storage", true},
		{"arbitrary RBD image", DomainDisk{Device: "disk", SourceProtocol: "rbd", SourceName: "pool/customer_disk.swap"}, "storage", true},
		{"swap partition cannot be inferred", DomainDisk{Device: "disk", SourceDev: "/dev/mapper/swap"}, "storage", true},
		{"unknown XML device", DomainDisk{Device: "mystery"}, "other", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if role := blockDeviceRole(tc.disk); role != tc.role {
				t.Fatalf("role=%q want %q", role, tc.role)
			}
			if eligible := isResourceDisk(tc.disk); eligible != tc.resource {
				t.Fatalf("resource=%v want %v", eligible, tc.resource)
			}
		})
	}
}

func TestBlockDeviceReconciliationKeepsFailuresVisible(t *testing.T) {
	root := DomainDisk{Device: "disk", TargetDev: "vda", SourceProtocol: "rbd", SourceName: "vms/" + specialDeviceUUID + "_disk"}
	config := DomainDisk{Device: "cdrom", TargetDev: "hda", SourceProtocol: "rbd", SourceName: "vms/" + specialDeviceUUID + "_disk.config"}
	swap := DomainDisk{Device: "disk", TargetDev: "vdb", SourceFile: "/instances/vm/disk.swap"}
	for _, tc := range []struct {
		name               string
		xml                []DomainDisk
		targets            []string
		count              uint64
		countPresent, want bool
	}{
		{"root only", []DomainDisk{root}, []string{"vda"}, 1, true, true},
		{"root plus RBD config", []DomainDisk{root, config}, []string{"vda", "hda"}, 2, true, true},
		{"ignored config has no stats", []DomainDisk{root, config}, []string{"vda"}, 1, true, true},
		{"root missing while config present", []DomainDisk{root, config}, []string{"hda"}, 1, true, false},
		{"unknown extra runtime", []DomainDisk{root, config}, []string{"vda", "hda", "vdc"}, 3, true, false},
		{"missing swap", []DomainDisk{root, swap, config}, []string{"vda", "hda"}, 2, true, false},
		{"root swap config", []DomainDisk{root, swap, config}, []string{"vda", "vdb", "hda"}, 3, true, true},
		{"XML hotplug pending stats", []DomainDisk{root, swap}, []string{"vda"}, 1, true, false},
		{"runtime hotplug pending XML", []DomainDisk{root}, []string{"vda", "vdb"}, 2, true, false},
		{"detach complete", []DomainDisk{root}, []string{"vda"}, 1, true, true},
		{"duplicate runtime target", []DomainDisk{root, config}, []string{"vda", "vda", "hda"}, 3, true, false},
		{"duplicate XML target", []DomainDisk{root, root, config}, []string{"vda", "hda"}, 2, true, false},
		{"count exceeds parsed block stats", []DomainDisk{root, config}, []string{"vda"}, 2, true, false},
		{"count smaller than returned block stats", []DomainDisk{root, config}, []string{"vda", "hda"}, 1, true, false},
		{"unnamed runtime block", []DomainDisk{root, config}, []string{"vda", ""}, 2, true, false},
		{"unnamed XML block", []DomainDisk{root, {Device: "cdrom"}}, []string{"vda"}, 1, true, false},
		{"no block count available", []DomainDisk{root, config}, []string{"vda", "hda"}, 0, false, true},
		{"diskless confirmed", nil, nil, 0, true, true},
		{"unsupported XML device", []DomainDisk{root, {Device: "mystery", TargetDev: "hda"}}, []string{"vda", "hda"}, 2, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := resourceDiskTargetsComplete(tc.xml, tc.targets, tc.count, tc.countPresent); got != tc.want {
				t.Fatalf("complete=%v want %v", got, tc.want)
			}
		})
	}
}

func TestBlockDeviceSourceClassification(t *testing.T) {
	for _, tc := range []struct {
		disk     DomainDisk
		kind, id string
	}{
		{DomainDisk{SourceProtocol: "rbd", SourceName: "vms/image"}, "vms", "image"},
		{DomainDisk{SourceProtocol: "nbd", SourceName: "export/name"}, "nbd", "export/name"},
		{DomainDisk{SourceProtocol: "iscsi", SourceName: "iqn.2026.test/1"}, "iscsi", "iqn.2026.test/1"},
		{DomainDisk{SourceFile: "/images/disk"}, "local", "/images/disk"},
		{DomainDisk{SourceDev: "/dev/mapper/data"}, "block", "/dev/mapper/data"},
		{DomainDisk{SourcePool: "pool", SourceVolume: "vol"}, "volume", "pool/vol"},
		{DomainDisk{}, "unknown", "unknown"},
	} {
		kind, id := diskMetricSource(tc.disk)
		if kind != tc.kind || id != tc.id {
			t.Fatalf("%+v -> %q/%q want %q/%q", tc.disk, kind, id, tc.kind, tc.id)
		}
	}
}
