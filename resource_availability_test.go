package main

import (
	libvirt "github.com/digitalocean/go-libvirt"
	"strings"
	"testing"
	"time"
)

func TestMissingResourceSamplePreservesPriorAxisInsteadOfHealthyZero(t *testing.T) {
	mc := &MetricsCollector{collectionInterval: 15 * time.Second, resourceV2: make(map[string]*resourceV2State)}
	first, _ := mc.computeResourceV2("vm-1", resourceV2Input{
		Now:          time.Unix(100, 0),
		CpuAvailable: true,
	})
	second, _ := mc.computeResourceV2("vm-1", resourceV2Input{Now: time.Unix(200, 0)})
	if !second.Available || !second.CPU.Available || second.CPU.Fresh || !second.CPU.LastSuccess.Equal(first.CPU.LastSuccess) {
		t.Fatalf("last-known CPU axis became unavailable: %+v", second)
	}

}

func TestResourceAxisRecoveryUsesItsOwnLastValidSampleGap(t *testing.T) {
	mc := &MetricsCollector{collectionInterval: 15 * time.Second, resourceV2: make(map[string]*resourceV2State)}
	start := time.Unix(100, 0)
	mc.computeResourceV2("vm-1", resourceV2Input{
		Now:          start,
		CpuAvailable: true,
	})

	// Keep another axis fresh near the end of a long CPU telemetry outage. That
	// unrelated sample must not shorten the CPU measurement recovery interval.
	mc.computeResourceV2("vm-1", resourceV2Input{
		Now:          start.Add(59*time.Minute + 50*time.Second),
		MemAvailable: true,
	})
	out, _ := mc.computeResourceV2("vm-1", resourceV2Input{
		Now:          start.Add(time.Hour),
		CpuAvailable: true,
	})

	if !out.CPU.Fresh || !out.CPU.Recovery || !out.CPU.LastSuccess.Equal(start.Add(time.Hour)) {
		t.Fatalf("CPU recovery borrowed another axis timestamp: %+v", out.CPU)
	}
}

func TestEntirelyMissingResourceTelemetryIsUnavailable(t *testing.T) {
	mc := &MetricsCollector{collectionInterval: 15 * time.Second, resourceV2: make(map[string]*resourceV2State)}
	out, _ := mc.computeResourceV2("vm-1", resourceV2Input{Now: time.Unix(100, 0)})
	if out.Available {
		t.Fatalf("missing resource telemetry was reported healthy: %+v", out)
	}
}

func TestPausedInstanceDoesNotEmitCachedResourcePressureAsHealthyZero(t *testing.T) {
	mc, err := NewMetricsCollector(CollectorConfig{
		LibvirtURI:         "qemu:///system",
		CollectionInterval: 15 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewMetricsCollector: %v", err)
	}

	var uuid libvirt.UUID
	for i := range uuid {
		uuid[i] = byte(i + 1)
	}
	instanceUUID := uuidBytesToString(uuid[:])
	mc.im.domainMeta[instanceUUID] = &DomainStatic{
		Name:         "paused-server",
		InstanceUUID: instanceUUID,
		ProjectUUID:  "project",
		ProjectName:  "project-name",
		UserUUID:     "user",
		VCPUCount:    1,
		MemMB:        1024,
		LastUpdated:  time.Now(),
	}
	mc.computeResourceV2(instanceUUID, resourceV2Input{
		Now:          time.Now().Add(-time.Minute),
		CpuAvailable: true,
	})

	agg := &hostAgg{projects: make(map[string]struct{})}
	mc.collectDomainMetrics(
		libvirt.DomainStatsRecord{
			Dom:    libvirt.Domain{Name: "paused-domain", UUID: uuid},
			Params: []libvirt.TypedParam{typedParam("state.state", int32(libvirt.DomainPaused))},
		},
		nil,
		nil,
		agg,
		0,
		false,
		false,
		true,
	)

	for _, metric := range agg.metrics {
		desc := metric.Desc().String()
		if strings.Contains(desc, `fqName: "oie_instance_resource_severity"`) ||
			strings.Contains(desc, `fqName: "oie_instance_resource_cpu_severity"`) ||
			strings.Contains(desc, `fqName: "oie_instance_resource_mem_severity"`) ||
			strings.Contains(desc, `fqName: "oie_instance_resource_disk_severity"`) ||
			strings.Contains(desc, `fqName: "oie_instance_resource_net_severity"`) {
			t.Fatalf("paused instance emitted stale resource metric: %s", desc)
		}
	}
}
