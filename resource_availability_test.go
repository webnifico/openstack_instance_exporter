package main

import (
	libvirt "github.com/digitalocean/go-libvirt"
	"strings"
	"testing"
	"time"
)

func TestResourceScoringDoesNotDiluteSingleAvailableSevereAxis(t *testing.T) {
	mc := &MetricsCollector{collectionInterval: 15 * time.Second, resourceV2: make(map[string]*resourceV2State)}
	out, _ := mc.computeResourceV2("vm-1", resourceV2Input{
		Now:     time.Unix(100, 0),
		CpuPRaw: 1, CpuConf: 1, CpuImpact: 1, CpuAvailable: true,
	})
	if !out.Available || !out.CPU.Available {
		t.Fatalf("available CPU axis was lost: %+v", out)
	}
	if out.OverallRaw < 99.9 {
		t.Fatalf("single severe available axis was diluted by missing axes: overall=%v", out.OverallRaw)
	}
}

func TestMissingResourceSamplePreservesPriorAxisInsteadOfHealthyZero(t *testing.T) {
	mc := &MetricsCollector{collectionInterval: 15 * time.Second, resourceV2: make(map[string]*resourceV2State)}
	first, _ := mc.computeResourceV2("vm-1", resourceV2Input{
		Now:     time.Unix(100, 0),
		CpuPRaw: 0.8, CpuConf: 1, CpuImpact: 1, CpuAvailable: true,
	})
	second, _ := mc.computeResourceV2("vm-1", resourceV2Input{Now: time.Unix(200, 0)})
	if !second.Available || !second.CPU.Available {
		t.Fatalf("last-known CPU axis became unavailable: %+v", second)
	}
	if second.CPU.Sev != first.CPU.Sev || second.OverallRaw != first.OverallRaw {
		t.Fatalf("missing sample changed prior severity: first=%+v second=%+v", first, second)
	}
}

func TestResourceAxisRecoveryUsesItsOwnLastValidSampleGap(t *testing.T) {
	mc := &MetricsCollector{collectionInterval: 15 * time.Second, resourceV2: make(map[string]*resourceV2State)}
	start := time.Unix(100, 0)
	mc.computeResourceV2("vm-1", resourceV2Input{
		Now:          start,
		CpuAvailable: true,
		CpuPRaw:      1,
		CpuConf:      1,
		CpuImpact:    1,
	})

	// Keep another axis fresh near the end of a long CPU telemetry outage. That
	// unrelated sample must not shorten the CPU EWMA's elapsed decay interval.
	mc.computeResourceV2("vm-1", resourceV2Input{
		Now:          start.Add(59*time.Minute + 50*time.Second),
		MemAvailable: true,
		MemConf:      1,
		MemImpact:    1,
	})
	out, _ := mc.computeResourceV2("vm-1", resourceV2Input{
		Now:          start.Add(time.Hour),
		CpuAvailable: true,
		CpuConf:      1,
		CpuImpact:    1,
	})

	if out.CPU.EWMA > 0.001 {
		t.Fatalf("CPU recovery used another axis's timestamp instead of its own hour-long gap: ewma=%v alpha=%v", out.CPU.EWMA, out.CPU.Alpha)
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
		CpuPRaw:      1,
		CpuConf:      1,
		CpuImpact:    1,
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
