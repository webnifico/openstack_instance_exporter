package main

import (
	"strings"
	"testing"

	libvirt "github.com/digitalocean/go-libvirt"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

const inventoryTestUUID = "00112233-4455-6677-8899-aabbccddeeff"

func inventoryTestRecord() libvirt.DomainStatsRecord {
	return libvirt.DomainStatsRecord{Dom: libvirt.Domain{Name: "stopped-vm", ID: -1, UUID: libvirt.UUID{0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}}, Params: []libvirt.TypedParam{typedParam("state.state", uint32(libvirt.DomainShutoff))}}
}

func TestInactiveInventoryConfigurationWithoutRuntime(t *testing.T) {
	mc := newCollectorOrchestrationTestCollector(t)
	xml := `<domain><memory unit="GiB">8</memory><currentMemory unit="MiB">2048</currentMemory><vcpu current="2">8</vcpu><devices><disk type="network" device="disk"><source protocol="rbd" name="premium/volume-test"/><target dev="vda"/></disk><interface type="bridge"><mac address="52:54:00:00:00:01"/><model type="virtio"/><source bridge="br-int"/></interface></devices></domain>`
	mc.im.domainXMLDescOverride = func(libvirt.Domain) (string, error) { return xml, nil }
	record := inventoryTestRecord()
	prepared, err := mc.prepareLibvirtCycle([]libvirt.DomainStatsRecord{record})
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.activeSet) != 0 || len(prepared.metadata) != 1 {
		t.Fatal("inactive domain polluted active inventory")
	}
	mc.commitPreparedLibvirtCycle(prepared)
	if len(mc.im.activeInstances) != 0 || len(mc.im.snapshotVMIPIdentities(prepared.activeSet)) != 0 {
		t.Fatal("inactive domain entered runtime/IP ownership maps")
	}
	metrics := mc.inventoryMetricBatch([]libvirt.DomainStatsRecord{record}, prepared.metadata)
	found := map[string]bool{}
	for _, m := range metrics {
		if !strings.Contains(m.Desc().String(), "oie_instance_inventory_") {
			t.Fatal("inactive inventory emitted a runtime metric")
		}
		var d dto.Metric
		if err := m.Write(&d); err != nil {
			t.Fatal(err)
		}
		labels := map[string]string{}
		for _, l := range d.Label {
			labels[l.GetName()] = l.GetValue()
		}
		if strings.Contains(m.Desc().String(), `fqName: "oie_instance_inventory_info"`) {
			found["info"] = true
			for key, want := range map[string]string{"libvirt_active": "0", "state_desc": "shutoff", "vcpus": "2", "mem_mb": "2048"} {
				if labels[key] != want {
					t.Fatalf("%s=%q want %q", key, labels[key], want)
				}
			}
		}
		if labels["disk_path"] == "vda" && labels["volume_uuid"] == "volume-test" {
			found["disk"] = true
		}
		if labels["mac"] == "52:54:00:00:00:01" && labels["ifname"] == "" {
			found["interface"] = true
		}
	}
	if len(found) != 3 {
		t.Fatalf("incomplete stopped configuration: %v", found)
	}
	active := activeDomainRecords([]libvirt.DomainStatsRecord{record})
	agg := mc.collectDomainStatsParallelPrepared(active, prepared.metadata, nil, nil, 0, false, false)
	if len(active) != 0 || agg.vcpus != 0 || agg.disks != 0 || agg.fixedIPs != 0 || len(agg.metrics) != 0 {
		t.Fatal("inactive domain contributed runtime resources")
	}
}

func TestInactiveInventoryRejectsPowerTransitionDuringSnapshot(t *testing.T) {
	record := inventoryTestRecord()
	if tokens, err := stableQEMUProcessTokens([]libvirt.DomainStatsRecord{record}, map[string]string{}, map[string]string{}); err != nil || len(tokens) != 0 {
		t.Fatalf("inactive definition requires a process: %v", err)
	}
	for _, state := range []struct{ before, after map[string]string }{
		{map[string]string{inventoryTestUUID: "boot:1:10"}, map[string]string{}},
		{map[string]string{}, map[string]string{inventoryTestUUID: "boot:1:20"}},
	} {
		if _, err := stableQEMUProcessTokens([]libvirt.DomainStatsRecord{record}, state.before, state.after); err == nil {
			t.Fatal("power transition accepted as stable inactive inventory")
		}
	}
}

func TestInventoryAllStatesAndUnknownTelemetry(t *testing.T) {
	for code, want := range []string{"nostate", "running", "blocked", "paused", "shutdown", "shutoff", "crashed", "pmsuspended"} {
		if got := inventoryStateDescription(&ParsedStats{State: code, StatePresent: true}); got != want {
			t.Fatalf("state %d=%s", code, got)
		}
	}
	if inventoryStateDescription(&ParsedStats{}) != "unavailable" || inventoryStateDescription(&ParsedStats{State: 99, StatePresent: true}) != "unrecognized(99)" {
		t.Fatal("unknown state was guessed")
	}
	// Register every newly advertised family, including an inactive inventory-only scrape.
	mc := newCollectorOrchestrationTestCollector(t)
	r := prometheus.NewPedanticRegistry()
	if err := r.Register(mc); err != nil {
		t.Fatal(err)
	}
}

const inventoryOIEFamilyCount = volumeRetypeOIEFamilyCount + 4

var inventoryMetricDescriptors = []string{
	"oie_instance_inventory_info|domain,server_name,instance_uuid,project_uuid,project_name,user_uuid,user_name,flavor,vcpus,mem_mb,root_type,created_at,metadata_version,libvirt_active,state_desc",
	"oie_instance_inventory_disk_info|domain,server_name,instance_uuid,project_uuid,project_name,user_uuid,volume_uuid,disk_type,disk_path",
	"oie_instance_inventory_interface_info|domain,server_name,instance_uuid,project_uuid,project_name,user_uuid,interface_index,ifname,mac,model,interface_type,attachment,port_uuid",
	"oie_instance_inventory_address_info|domain,server_name,instance_uuid,project_uuid,project_name,user_uuid,port_uuid,ip,family",
}

func laterMetricFamilyNames() map[string]struct{} {
	names := volumeRetypeMetricFamilyNames()
	for _, descriptor := range inventoryMetricDescriptors {
		name, _, _ := strings.Cut(descriptor, "|")
		names[name] = struct{}{}
	}
	return names
}

func TestInactiveInventoryFullCollectionTransitions(t *testing.T) {
	mc := newCollectorOrchestrationTestCollector(t)
	record := inventoryTestRecord()
	xmlReads := 0
	mc.im.domainXMLDescOverride = func(libvirt.Domain) (string, error) {
		xmlReads++
		return `<domain><vcpu>2</vcpu><memory unit="MiB">4096</memory></domain>`, nil
	}
	mc.fetchDomainStatsOverride = func() ([]libvirt.DomainStatsRecord, float64, error) {
		return []libvirt.DomainStatsRecord{record}, 0, nil
	}
	for _, active := range []bool{false, false, true, false} {
		if active {
			record.Dom.ID = 5
			record.Params = []libvirt.TypedParam{typedParam("state.state", uint32(libvirt.DomainRunning)), typedParam("vcpu.current", uint32(2)), typedParam("balloon.current", uint64(4194304)), typedParam("cpu.time", uint64(1000000000))}
		} else {
			record = inventoryTestRecord()
		}
		ch := make(chan prometheus.Metric, 1024)
		mc.collectHeavy(ch)
		close(ch)
		inventorySeen := false
		runtimeSeen := false
		for m := range ch {
			var d dto.Metric
			if err := m.Write(&d); err != nil {
				t.Fatal(err)
			}
			desc := m.Desc().String()
			if strings.Contains(desc, `fqName: "oie_instance_inventory_info"`) {
				inventorySeen = true
			}
			if strings.Contains(desc, `fqName: "oie_instance_info"`) {
				runtimeSeen = true
			}
			if !active && (strings.Contains(desc, `fqName: "oie_host_libvirt_active_vms"`) || strings.Contains(desc, `fqName: "oie_host_cpu_active_vcpus"`)) {
				if d.GetGauge().GetValue() != 0 {
					t.Fatal("inactive definition inflated active host totals")
				}
			}
			if !active && strings.Contains(desc, `fqName: "oie_instance_`) && !strings.Contains(desc, `fqName: "oie_instance_inventory_`) {
				t.Fatalf("inactive collection leaked runtime series %s", desc)
			}
		}
		if !inventorySeen || runtimeSeen != active {
			t.Fatalf("active=%v inventory=%v runtime=%v", active, inventorySeen, runtimeSeen)
		}
	}
	if xmlReads != 3 {
		t.Fatalf("XML reads=%d; inactive cache must avoid repeat reads but refresh across power transitions", xmlReads)
	}
	mc.fetchDomainStatsOverride = func() ([]libvirt.DomainStatsRecord, float64, error) { return nil, 0, nil }
	ch := make(chan prometheus.Metric, 1024)
	mc.collectHeavy(ch)
	close(ch)
	if len(mc.im.inactiveDomainMeta) != 0 {
		t.Fatal("undefined domain remained in inventory cache")
	}
	for m := range ch {
		if strings.Contains(m.Desc().String(), "oie_instance_inventory_") {
			t.Fatal("undefined domain remained in inventory output")
		}
	}
}
