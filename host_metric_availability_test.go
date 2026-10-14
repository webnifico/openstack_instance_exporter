package main

import (
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func TestUnavailableHostAggregatesAreNotExportedAsHealthyZeroes(t *testing.T) {
	mc, err := NewMetricsCollector(CollectorConfig{LibvirtURI: "qemu:///system", CollectionInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer close(mc.shutdownChan)

	ch := make(chan prometheus.Metric, 128)
	mc.emitHostAndAggMetrics(
		ch,
		nil,
		&hostAgg{projects: make(map[string]struct{})},
		0, 0, 0, 0, 0, 0, 0, 0,
		false, false, false,
	)
	close(ch)

	forbidden := []string{
		"oie_host_libvirt_active_vms",
		"oie_host_cpu_active_vcpus",
		"oie_host_active_disks",
		"oie_host_active_fixed_ips",
		"oie_host_active_projects",
		"oie_host_conntrack_entries",
		"oie_host_conntrack_utilization",
	}
	for metric := range ch {
		desc := metric.Desc().String()
		for _, name := range forbidden {
			if strings.Contains(desc, `fqName: "`+name+`"`) {
				t.Errorf("unavailable metric %s was exported as a healthy zero", name)
			}
		}
	}
}

func TestHostCPUFirstSampleAndCounterResetAreUnavailable(t *testing.T) {
	mc := &MetricsCollector{}
	if value, available := mc.hostCPUPercentFromTotals(100, 80); available || value != 0 {
		t.Fatalf("first sample = (%v, %v), want unavailable", value, available)
	}
	if value, available := mc.hostCPUPercentFromTotals(200, 140); !available || value != 40 {
		t.Fatalf("second sample = (%v, %v), want (40, true)", value, available)
	}
	if value, available := mc.hostCPUPercentFromTotals(50, 40); available || value != 0 {
		t.Fatalf("counter reset = (%v, %v), want unavailable", value, available)
	}
	if value, available := mc.hostCPUPercentFromTotals(100, 70); !available || value != 40 {
		t.Fatalf("post-reset sample = (%v, %v), want (40, true)", value, available)
	}
}

func TestHostMemoryFieldsHaveIndependentAvailability(t *testing.T) {
	free, available, freeOK, availableOK := parseHostMemInfo(strings.NewReader("MemFree: invalid kB\nMemAvailable: 2048 kB\n"))
	if free != 0 || freeOK {
		t.Fatalf("malformed MemFree = (%v, %v), want unavailable", free, freeOK)
	}
	if available != 2 || !availableOK {
		t.Fatalf("MemAvailable = (%v, %v), want (2, true)", available, availableOK)
	}
}

func TestAvailableEmptyHostAggregatesStillExportZeroes(t *testing.T) {
	mc, err := NewMetricsCollector(CollectorConfig{LibvirtURI: "qemu:///system", CollectionInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer close(mc.shutdownChan)

	ch := make(chan prometheus.Metric, 128)
	mc.emitHostAndAggMetrics(
		ch,
		nil,
		&hostAgg{projects: make(map[string]struct{})},
		0, 0, 0, 0, 0, 0, 0, 0,
		true, true, true,
	)
	close(ch)

	want := map[string]bool{
		"oie_host_libvirt_active_vms":    false,
		"oie_host_conntrack_entries":     false,
		"oie_host_conntrack_utilization": false,
	}
	for metric := range ch {
		desc := metric.Desc().String()
		for name := range want {
			if strings.Contains(desc, `fqName: "`+name+`"`) {
				want[name] = true
			}
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("available empty aggregate omitted %s", name)
		}
	}
}

func TestDisabledConntrackOmitsReaderHealthInsteadOfReportingFailure(t *testing.T) {
	mc, err := NewMetricsCollector(CollectorConfig{
		LibvirtURI:          "qemu:///system",
		CollectionInterval:  time.Hour,
		ConntrackIPv4Enable: false,
		ConntrackIPv6Enable: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer close(mc.shutdownChan)

	ch := make(chan prometheus.Metric, 128)
	mc.emitHostAndAggMetrics(
		ch,
		nil,
		&hostAgg{projects: make(map[string]struct{})},
		0, 0, 0, 0, 0, 0, 0, 0,
		true, false, false,
	)
	close(ch)

	forbidden := []string{
		"oie_host_conntrack_read_duration_seconds",
		"oie_host_conntrack_read_errors_total",
		"oie_host_conntrack_raw_ok",
		"oie_host_conntrack_raw_enobufs_total",
		"oie_host_conntrack_raw_parse_errors_total",
		"oie_host_conntrack_last_success_timestamp_seconds",
		"oie_host_conntrack_stale_seconds",
	}
	for metric := range ch {
		desc := metric.Desc().String()
		for _, name := range forbidden {
			if strings.Contains(desc, `fqName: "`+name+`"`) {
				t.Errorf("disabled conntrack emitted reader-health metric %s", name)
			}
		}
	}
}
