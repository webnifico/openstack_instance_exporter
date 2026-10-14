package main

import (
	"fmt"
	"strings"
	"testing"
	"time"

	libvirt "github.com/digitalocean/go-libvirt"
	"github.com/prometheus/client_golang/prometheus"
)

func TestConfigDriveDiskCollectionRecoversWithoutHidingUnknownDevices(t *testing.T) {
	for _, media := range []struct{ name, xml string }{
		{"rbd cdrom", `<disk type="network" device="cdrom"><source protocol="rbd" name="vms/` + specialDeviceUUID + `_disk.config"/><target dev="hda"/></disk>`},
		{"local cdrom", `<disk type="file" device="cdrom"><source file="/instances/vm/disk.config"/><target dev="hda"/></disk>`},
		{"vfat config disk", `<disk type="file" device="disk"><source file="/instances/vm/disk.config"/><target dev="hda"/></disk>`},
		{"ISO", `<disk type="file" device="cdrom"><source file="/images/ubuntu.iso"/><target dev="hda"/></disk>`},
		{"empty removable", `<disk type="file" device="cdrom"><target dev="hda"/></disk>`},
		{"floppy", `<disk type="file" device="floppy"><source file="/images/a.img"/><target dev="hda"/></disk>`},
	} {
		t.Run(media.name, func(t *testing.T) {
			mc := newCollectorOrchestrationTestCollector(t)
			xml := `<domain><devices><disk type="network" device="disk"><source protocol="rbd" name="vms/` + specialDeviceUUID + `_disk"/><target dev="vda"/></disk>` + media.xml + `</devices></domain>`
			meta, err := parseDomainStaticFromXML(specialDeviceUUID, "instance-fixture", xml)
			if err != nil {
				t.Fatal(err)
			}
			if len(meta.Disks) != 1 || len(meta.BlockDevices) != 2 {
				t.Fatalf("resource=%d inventory=%d", len(meta.Disks), len(meta.BlockDevices))
			}
			now := time.Unix(1700000000, 0)
			collect := func(v uint64, unknown bool) (bool, bool, []prometheus.Metric) {
				stats := &ParsedStats{BlockCount: 2, BlockCountPresent: true, Disks: map[int]*DiskStat{0: fullDiskStat("vda", v, v*4096, v*1000000, v, v*1000000), 1: {Name: "hda", NamePresent: true}}}
				if unknown {
					stats.Disks[2] = fullDiskStat("vdb", v, v, v, v, v)
					stats.BlockCount = 3
				}
				metrics := []prometheus.Metric{}
				count, fresh, identity, sources, known := mc.collectDomainDiskMetricsWithSources(meta, stats, now.Add(time.Duration(v)*time.Second), "domain", "nginx", specialDeviceUUID, "project", "project", "user", true, &metrics)
				if !unknown && count != 1 {
					t.Fatalf("CDROM counted as storage: %d", count)
				}
				if strings.Contains(identity, "hda") || strings.Contains(strings.Join(sources, " "), "hda") {
					t.Fatal("non-resource media entered performance identity")
				}
				for _, m := range metrics {
					if strings.Contains(dataIntegrityMetricLabels(metricDTO(t, m)), `disk_path="hda"`) {
						t.Fatal("non-resource device emitted disk performance metric")
					}
				}
				return fresh, known, metrics
			}
			if fresh, known, _ := collect(1, false); fresh || !known {
				t.Fatalf("first sample: fresh=%v known=%v", fresh, known)
			}
			if fresh, known, metrics := collect(2, false); !fresh || !known {
				t.Fatalf("second sample: fresh=%v known=%v", fresh, known)
			} else {
				reg := prometheus.NewPedanticRegistry()
				reg.MustRegister(staticMetricCollector{metrics: metrics})
				if _, err := reg.Gather(); err != nil {
					t.Fatal(err)
				}
			}
			if fresh, known, _ := collect(3, true); fresh || known {
				t.Fatal("unknown hotplug target was ignored")
			}
			if fresh, known, _ := collect(4, false); !fresh || !known {
				t.Fatal("resource collection did not recover after reconciliation")
			}
		})
	}
}

func TestSpecialBlockDeviceInventoryIncludesInactiveAndSwap(t *testing.T) {
	mc := newCollectorOrchestrationTestCollector(t)
	xml := `<domain><devices>
<disk type="network" device="disk"><source protocol="rbd" name="vms/` + specialDeviceUUID + `_disk"/><target dev="vda"/></disk>
<disk type="network" device="cdrom"><source protocol="rbd" name="vms/` + specialDeviceUUID + `_disk.config"/><target dev="hda"/></disk>
<disk type="file" device="disk"><source file="/instances/vm/disk.swap"/><target dev="vdb"/></disk>
</devices></domain>`
	meta, err := parseDomainStaticFromXML(inventoryTestUUID, "domain", xml)
	if err != nil {
		t.Fatal(err)
	}
	if len(meta.Disks) != 2 || len(meta.BlockDevices) != 3 {
		t.Fatalf("unexpected inventory: %+v", meta)
	}
	metrics := mc.inventoryMetricBatch([]libvirt.DomainStatsRecord{inventoryTestRecord()}, map[string]*DomainStatic{inventoryTestUUID: meta})
	roles := map[string]bool{}
	disks := 0
	for _, m := range metrics {
		if m.Desc() == mc.im.instanceInventoryBlockDeviceInfoDesc {
			encoded := metricDTO(t, m)
			ls := map[string]string{}
			for _, l := range encoded.Label {
				ls[l.GetName()] = l.GetValue()
			}
			roles[ls["device_role"]] = true
			if encoded.GetGauge().GetValue() != 1 {
				t.Fatal("inventory presence must be one")
			}
			if ls["device_role"] == "config_drive" && (ls["device_path"] != "hda" || ls["source_type"] != "vms") {
				t.Fatal(ls)
			}
		}
		if m.Desc() == mc.im.instanceInventoryDiskInfoDesc {
			disks++
		}
	}
	if len(roles) != 3 || !roles["config_drive"] || !roles["swap"] || !roles["storage"] || disks != 2 {
		t.Fatalf("roles=%v disks=%d", roles, disks)
	}
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(staticMetricCollector{metrics: metrics})
	if _, err := reg.Gather(); err != nil {
		t.Fatal(err)
	}
}

func TestSwapAndLUNDiskCounterCollection(t *testing.T) {
	for _, device := range []struct{ typ, source string }{
		{"disk", `<source file="/instances/vm/disk.swap"/>`},
		{"lun", `<source dev="/dev/mapper/data"/>`},
	} {
		mc := newCollectorOrchestrationTestCollector(t)
		xml := fmt.Sprintf(`<domain><devices><disk type="block" device="%s">%s<target dev="vda"/></disk></devices></domain>`, device.typ, device.source)
		meta, err := parseDomainStaticFromXML("vm", "domain", xml)
		if err != nil {
			t.Fatal(err)
		}
		for cycle := uint64(1); cycle <= 2; cycle++ {
			metrics := []prometheus.Metric{}
			stats := &ParsedStats{BlockCount: 1, BlockCountPresent: true, Disks: map[int]*DiskStat{0: fullDiskStat("vda", cycle, cycle, cycle, cycle, cycle)}}
			count, fresh := mc.collectDomainDiskMetrics(meta, stats, time.Unix(1700000000+int64(cycle), 0), "domain", "server", "vm", "project", "project", "user", true, &metrics)
			if count != 1 || fresh != (cycle == 2) {
				t.Fatalf("%s cycle=%d count=%d fresh=%v", device.typ, cycle, count, fresh)
			}
		}
	}
}
