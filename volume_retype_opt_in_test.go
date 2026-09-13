package main

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	libvirt "github.com/digitalocean/go-libvirt"
	"github.com/prometheus/client_golang/prometheus"
)

func TestVolumeRetypeMonitoringRequiresExplicitOptIn(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		name := "disabled by default"
		if enabled {
			name = "explicitly enabled"
		}
		t.Run(name, func(t *testing.T) {
			cfg := CollectorConfig{LibvirtURI: "qemu:///system", CollectionInterval: 15 * time.Second}
			if enabled {
				cfg.VolumeRetypeEnable = true
			}
			mc, err := NewMetricsCollector(cfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { close(mc.shutdownChan) })
			uuid, instanceUUID := dataIntegrityE2EUUID()
			domain := libvirt.Domain{Name: "instance-retype-opt-in", UUID: uuid}
			meta := &DomainStatic{InstanceUUID: instanceUUID, Name: "retype-opt-in"}
			var xmlCalls, progressCalls atomic.Int32
			mc.im.domainXMLDescOverride = func(libvirt.Domain) (string, error) {
				xmlCalls.Add(1)
				return activeVolumeRetypeXML, nil
			}
			mc.libvirtBlockJobRPCOverride = func(_ *libvirt.Libvirt, _ libvirt.Domain, _ string, _ uint32) (int32, int32, uint64, uint64, uint64, error) {
				progressCalls.Add(1)
				return 1, int32(libvirt.DomainBlockJobTypeCopy), 0, 25, 100, nil
			}

			mc.refreshVolumeRetypes([]libvirt.DomainStatsRecord{{Dom: domain}}, map[string]*DomainStatic{instanceUUID: meta})
			if enabled {
				if xmlCalls.Load() == 0 || progressCalls.Load() != 1 || len(mc.volumeRetypeJobs) != 1 {
					t.Fatalf("enabled discovery/progress failed: XML=%d progress=%d jobs=%d", xmlCalls.Load(), progressCalls.Load(), len(mc.volumeRetypeJobs))
				}
			} else {
				if mc.volumeRetypeJobs != nil || mc.volumeRetypeCompleted != nil || mc.volumeRetypeRPCInflight != nil {
					t.Fatal("disabled monitoring allocated lifecycle state")
				}
				// Even a supplied old operation must not cause a disabled
				// collector to poll, emit counters or replay retype metrics.
				key := volumeRetypeKey{InstanceUUID: instanceUUID, DiskPath: "vde"}
				mc.volumeRetypeJobs = map[volumeRetypeKey]volumeRetypeJob{
					key: {Domain: domain, InstanceUUID: instanceUUID, DiskPath: "vde", ConfirmedAt: time.Now()},
				}
				mc.volumeRetypeResults.Success = 1
				mc.refreshActiveVolumeRetypes(time.Now())
				stopped := make(chan struct{})
				go func() {
					mc.runVolumeRetypePoller(time.Millisecond, mc.shutdownChan)
					close(stopped)
				}()
				select {
				case <-stopped:
				case <-time.After(time.Second):
					t.Fatal("disabled retype poller started a timer loop")
				}
				if xmlCalls.Load() != 0 || progressCalls.Load() != 0 {
					t.Fatalf("disabled monitoring queried libvirt: XML=%d progress=%d", xmlCalls.Load(), progressCalls.Load())
				}
				if len(mc.volumeRetypeMetrics(time.Now())) != 0 || len(mc.volumeRetypeResultMetrics()) != 0 {
					t.Fatal("disabled monitoring emitted lifecycle metrics")
				}
			}

			// Exercise the production scrape path using its initialized cache.
			// Retype series must come only from enabled live lifecycle state.
			mc.backgroundOnce.Do(func() {})
			mc.cacheInitialized = true
			mc.cachedLibvirtAvailable = true
			mc.cachedMetrics = []prometheus.Metric{
				prometheus.MustNewConstMetric(mc.hostLibvirtActiveVMsDesc, prometheus.GaugeValue, 1),
				prometheus.MustNewConstMetric(mc.hostVolumeRetypeResultsTotalDesc, prometheus.CounterValue, 99, "success"),
			}
			registry := prometheus.NewRegistry()
			registry.MustRegister(mc)
			families, err := registry.Gather()
			if err != nil {
				t.Fatal(err)
			}
			normalSeen, retypeSeen := false, false
			for _, family := range families {
				if strings.Contains(family.GetName(), "retype") {
					retypeSeen = true
				} else {
					normalSeen = true
					if family.Metric[0].GetGauge().GetValue() != 1 {
						t.Fatal("normal cached measurement changed")
					}
				}
			}
			if !normalSeen || retypeSeen != enabled {
				t.Fatalf("scrape normal=%v retype=%v, enabled=%v", normalSeen, retypeSeen, enabled)
			}
		})
	}
}
