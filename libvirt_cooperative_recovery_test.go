package main

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	libvirt "github.com/digitalocean/go-libvirt"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestLibvirtCooperativeBlockJobsPreserveOtherVMsAndRecoverMeasurements(t *testing.T) {
	for _, retypeEnabled := range []bool{false, true} {
		for _, marker := range []string{"public mirror", "saved ready job", "saved active flag"} {
			t.Run(fmt.Sprintf("%s/retype=%t", marker, retypeEnabled), func(t *testing.T) {
				busy, busyUUID := dataIntegrityDomain(0x71, "instance-retype-guard")
				healthy, healthyUUID := dataIntegrityDomain(0x72, "instance-retype-neighbour")
				busy.ID, healthy.ID = 7, 8
				domains := []libvirt.Domain{busy, healthy}
				var copying atomic.Bool
				var resourceReads [2]atomic.Int32
				var storageReads [2]atomic.Int32
				safety := &libvirtReadSafety{runtimeStateDir: t.TempDir()}
				statusPath := filepath.Join(safety.runtimeStateDir, busy.Name+".xml")
				writeStatus := func(job string) {
					t.Helper()
					status := fmt.Sprintf(`<domstatus>%s<domain><uuid>%s</uuid></domain></domstatus>`, job, busyUUID)
					if err := os.WriteFile(statusPath, []byte(status), 0600); err != nil {
						t.Fatal(err)
					}
				}
				writeStatus(`<blockjobs active="no"/>`)

				inventory := func(dom libvirt.Domain) libvirt.DomainStatsRecord {
					return libvirt.DomainStatsRecord{Dom: dom, Params: []libvirt.TypedParam{
						typedParam("state.state", int32(libvirt.DomainRunning)),
						typedParam("net.count", uint32(1)),
						typedParam("net.0.name", "tap0"),
						typedParam("net.0.rx.bytes", uint64(1<<30)),
						typedParam("net.0.tx.bytes", uint64(2<<30)),
						typedParam("net.0.rx.pkts", uint64(10)),
						typedParam("net.0.tx.pkts", uint64(20)),
						typedParam("net.0.rx.drop", uint64(0)),
						typedParam("net.0.tx.drop", uint64(0)),
					}}
				}
				c := &cooperativeTestClient{}
				c.xml = func(dom libvirt.Domain) (string, error) {
					mirror := ""
					if copying.Load() && dom == busy && marker == "public mirror" {
						mirror = `<mirror type="network" job="copy" ready="yes"/>`
					}
					// Only vdb is being copied. The guard must also exclude vda's
					// resource probes because libvirt inspects all storage nodes.
					return fmt.Sprintf(`<domain><name>%s</name><uuid>%s</uuid><memory unit="KiB">1048576</memory><vcpu>2</vcpu><devices>
				<disk type="network" device="disk"><source protocol="rbd" name="premium/volume-root"/><target dev="vda"/></disk>
				<disk type="network" device="disk"><source protocol="rbd" name="volumes/volume-data"/><target dev="vdb"/>%s</disk>
				<interface type="bridge"><target dev="tap0"/></interface></devices></domain>`, dom.Name, validLibvirtDomainUUID(dom.UUID), mirror), nil
				}
				c.stats = func(requested []libvirt.Domain, groups, flags uint32) ([]libvirt.DomainStatsRecord, error) {
					if flags != libvirtStatsNowait {
						return nil, fmt.Errorf("statistics lost NOWAIT: %#x", flags)
					}
					if len(requested) == 0 {
						if groups != uint32(_domainStatsState|_domainStatsInterface) {
							return nil, fmt.Errorf("inventory requested monitor statistics: %#x", groups)
						}
						return []libvirt.DomainStatsRecord{inventory(busy), inventory(healthy)}, nil
					}
					if len(requested) != 1 {
						return nil, fmt.Errorf("resource request spans %d VMs", len(requested))
					}
					dom := requested[0]
					index := 0
					if dom == healthy {
						index = 1
					} else if dom != busy {
						return nil, fmt.Errorf("unexpected domain %s", dom.Name)
					}
					resourceReads[index].Add(1)
					allGroups := uint32(_domainStatsState | _domainStatsCpuTotal | _domainStatsBalloon | _domainStatsVcpu | _domainStatsInterface | _domainStatsBlock)
					if copying.Load() && dom == busy {
						allGroups &^= uint32(_domainStatsBlock)
					}
					if groups != allGroups {
						return nil, fmt.Errorf("unsafe or incomplete collection for %s: groups=%#x want=%#x", dom.Name, groups, allGroups)
					}
					record := inventory(dom)
					record.Params = append(record.Params,
						typedParam("cpu.time", uint64(2_000_000_000)),
						typedParam("vcpu.current", uint32(2)),
						typedParam("balloon.maximum", uint64(1048576)),
						typedParam("balloon.current", uint64(1048576)),
						typedParam("balloon.usable", uint64(262144)))
					if groups&uint32(_domainStatsBlock) == 0 {
						return []libvirt.DomainStatsRecord{record}, nil
					}
					storageReads[index].Add(1)
					record.Params = append(record.Params, typedParam("block.count", uint32(2)))
					for i, disk := range []string{"vda", "vdb"} {
						prefix := fmt.Sprintf("block.%d.", i)
						record.Params = append(record.Params,
							typedParam(prefix+"name", disk),
							typedParam(prefix+"rd.reqs", uint64(20)),
							typedParam(prefix+"rd.bytes", uint64(4<<30)),
							typedParam(prefix+"rd.times", uint64(2_000_000_000)),
							typedParam(prefix+"wr.reqs", uint64(10)),
							typedParam(prefix+"wr.bytes", uint64(2<<30)),
							typedParam(prefix+"wr.times", uint64(1_000_000_000)),
							typedParam(prefix+"capacity", uint64(30<<30)),
							typedParam(prefix+"allocation", uint64(10<<30)))
					}
					return []libvirt.DomainStatsRecord{record}, nil
				}

				mc := newCollectorOrchestrationTestCollector(t)
				mc.volumeRetypeEnabled = retypeEnabled
				var latest []libvirt.DomainStatsRecord
				mc.fetchDomainStatsOverride = func() ([]libvirt.DomainStatsRecord, float64, error) {
					records, metadata, err := collectCooperativeDomainStats(c, safety, time.Now().Add(time.Second))
					latest, mc.pendingDomainMetadata = records, metadata
					return records, 0, err
				}
				collect := func() []*dto.MetricFamily {
					t.Helper()
					metrics := dataIntegrityRunHeavyCollection(t, mc)
					registry := prometheus.NewRegistry()
					registry.MustRegister(staticMetricCollector{metrics: metrics})
					families, err := registry.Gather()
					if err != nil {
						t.Fatal(err)
					}
					if got, ok := resourceTelemetryCachedResourceSample(t, families, "oie_host_libvirt_ok", nil); !ok || got != 1 {
						t.Fatalf("one copying VM invalidated the whole collection: %v %v", got, ok)
					}
					return families
				}
				assertMeasurements := func(families []*dto.MetricFamily, uuid string, diskPresent bool) {
					t.Helper()
					labels := map[string]string{"instance_uuid": uuid}
					for name, want := range map[string]float64{
						"oie_instance_mem_used_mb":         768,
						"oie_instance_net_rx_gbytes_total": 1,
						"oie_instance_net_tx_gbytes_total": 2,
					} {
						if got, ok := resourceTelemetryCachedResourceSample(t, families, name, labels); !ok || got != want {
							t.Fatalf("%s for %s: %v %v, want %v", name, uuid, got, ok, want)
						}
					}
					for _, disk := range []string{"vda", "vdb"} {
						labels["disk_path"] = disk
						for name, want := range map[string]float64{
							"oie_instance_disk_capacity_bytes":      30 << 30,
							"oie_instance_disk_allocation_bytes":    10 << 30,
							"oie_instance_disk_read_requests_total": 20,
							"oie_instance_disk_read_seconds_total":  2,
							"oie_instance_disk_read_gbytes_total":   4,
						} {
							if got, ok := resourceTelemetryCachedResourceSample(t, families, name, labels); ok != diskPresent || (ok && got != want) {
								t.Fatalf("%s/%s/%s: %v %v, want %v present=%v", uuid, disk, name, got, ok, want, diskPresent)
							}
						}
					}
				}

				baseline := collect()
				before := append([]libvirt.DomainStatsRecord(nil), latest...)
				assertMeasurements(baseline, busyUUID, true)
				assertMeasurements(baseline, healthyUUID, true)
				copying.Store(true)
				switch marker {
				case "saved ready job":
					writeStatus(`<blockjobs active="no"><blockjob type="copy" state="ready"/></blockjobs>`)
				case "saved active flag":
					writeStatus(`<blockjobs active="yes"/>`)
				}
				during := collect()
				assertMeasurements(during, busyUUID, false)
				assertMeasurements(during, healthyUUID, true)
				if resourceReads[0].Load() != 2 || resourceReads[1].Load() != 2 || storageReads[0].Load() != 1 || storageReads[1].Load() != 2 {
					t.Fatal("storage deferral affected other resource groups or the wrong VM")
				}
				deferred := parseLibvirtStats(latest[0].Params)
				if !deferred.CpuTimePresent || !deferred.MemCurPresent || len(deferred.Disks) != 2 || len(deferred.Nets) != 1 {
					t.Fatalf("storage deferral lost CPU, memory, network or inventory: %+v", deferred)
				}
				if got, ok := resourceTelemetryCachedResourceSample(t, during, "oie_instance_cpu_vcpu_percent", map[string]string{"instance_uuid": busyUUID}); !ok || got != 0 {
					t.Fatalf("CPU usage disappeared during storage deferral: %v %v", got, ok)
				}
				for axis, want := range map[string]float64{"cpu": 1, "mem": 1, "net": 1, "disk": 0} {
					labels := map[string]string{"instance_uuid": busyUUID, "axis": axis}
					if got, ok := resourceTelemetryCachedResourceSample(t, during, "oie_instance_resource_axis_fresh", labels); !ok || got != want {
						t.Fatalf("%s axis freshness: %v %v, want %v", axis, got, ok, want)
					}
				}
				c.block = func(libvirt.Domain, string) (int32, int32, uint64, uint64, uint64, error) {
					return 1, int32(libvirt.DomainBlockJobTypeCopy), 0, 25, 100, nil
				}
				if _, _, current, total, err := guardedBlockJobInfo(c, safety, busy, "vdb", time.Now().Add(time.Second)); err != nil || current != 25 || total != 100 {
					t.Fatalf("resource deferral disabled progress: %d/%d %v", current, total, err)
				}
				copying.Store(false)
				writeStatus(`<blockjobs active="no"/>`)
				after := collect()
				for i, dom := range domains {
					if !reflect.DeepEqual(latest[i], before[i]) {
						t.Fatalf("normal measurements did not recover unchanged for %s", dom.Name)
					}
					assertMeasurements(after, validLibvirtDomainUUID(dom.UUID), true)
				}
			})
		}
	}
}
