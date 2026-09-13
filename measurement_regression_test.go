package main

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

var measurementReplayNow = time.Unix(1700000015, 0)

func TestMeasurementReplayAgainstBaselines(t *testing.T) {
	im := &InstanceManager{}
	now := measurementReplayNow
	previous := now.Add(-15 * time.Second)
	uuid := "measurement-replay"
	idx := shardIndex(uuid)
	im.cpuSamples[idx] = map[string]cpuSample{uuid: {total: 1000000000, vcpuCount: 4, stealPresent: true, waitPresent: true, ts: previous}}
	cpu, steal, wait, cpuOK, _, _ := im.calculateCPUUsageWithDetailedAvailabilityAt(31000000000, 3000000000, 3000000000, true, true, uuid, 4, now)
	memory, memoryOK := guestMemoryUsedMB(&ParsedStats{MemCur: 1024 * 1024, MemCurPresent: true, MemUsable: 256 * 1024, MemUsablePresent: true}, true)
	im.calculateDiskIOWithAvailability(uuid+"|disk", 0, 0, 0, 0, 0, 0, 0, 0, true, true, previous)
	rd, wr, rdlat, wrlat, fl, fllat, iosize, rwdelta, fldelta, bw, rwOK, flOK := im.calculateDiskIOWithAvailability(uuid+"|disk", 150, 450, 614400, 1843200, 1500000000, 9000000000, 15, 75000000, true, true, now)
	im.calculateNetRatesForInterfaces(uuid, map[string]netDeviceCounters{"vnet0": {}}, previous)
	pps, drop, dropped, netOK := im.calculateNetRatesForInterfaces(uuid, map[string]netDeviceCounters{"vnet0": {rxPkts: 1500, txPkts: 3000, rxDrop: 15, txDrop: 30}}, now)
	mc := &MetricsCollector{}
	mc.hostCPUPercentFromTotals(100, 80)
	hostCPU, hostOK := mc.hostCPUPercentFromTotals(200, 130)
	if !cpuOK || !memoryOK || !rwOK || !flOK || !netOK || !hostOK {
		t.Fatal("complete replay sample became unavailable")
	}

	initInstanceMetrics(im)
	mc.im = im
	var metrics []prometheus.Metric
	mc.collectDomainDiskMetrics(&DomainStatic{Disks: []DomainDisk{{TargetDev: "vda", SourceFile: "/disk"}}},
		&ParsedStats{Disks: map[int]*DiskStat{0: {Name: "vda", NamePresent: true, RdBytes: 1, RdBytesPresent: true}}},
		now, "d", "s", "v", "p", "pn", "u", false, &metrics)
	rawByte := 0.0
	for _, metric := range metrics {
		var value dto.Metric
		if err := metric.Write(&value); err != nil {
			t.Fatal(err)
		}
		if value.Counter != nil {
			rawByte = value.GetCounter().GetValue()
		}
	}
	result := map[string]any{
		"cpu_usage_steal_wait_percent":        []float64{cpu, steal, wait},
		"guest_used_mib":                      memory,
		"host_cpu_percent":                    hostCPU,
		"read_write_flush_iops":               []float64{rd, wr, fl},
		"read_write_flush_latency_seconds":    []float64{rdlat, wrlat, fllat},
		"io_size_bytes":                       iosize,
		"read_write_and_flush_request_deltas": []float64{rwdelta, fldelta},
		"bandwidth_bytes_per_second":          bw,
		"network_pps_drop_ratio_dropped_pps":  []float64{pps, drop, dropped},
		"one_byte_gib_counter":                rawByte,
	}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"v1.2", "baseline"} {
		t.Run(version, func(t *testing.T) {
			baseline, err := os.ReadFile("testdata/measurement-" + version + ".json")
			if err != nil {
				t.Fatal(err)
			}
			var want, got map[string]any
			if err = json.Unmarshal(baseline, &want); err != nil {
				t.Fatal(err)
			}
			if err = json.Unmarshal(data, &got); err != nil {
				t.Fatal(err)
			}
			// Development corrected drops/packets to drops/(packets+drops). v2 retains
			// that observation ratio and fixes sub-GiB counter rounding. The
			// downloaded historical-source replay results remain unchanged.
			want["one_byte_gib_counter"] = float64(1) / float64(1<<30)
			if version == "v1.2" {
				want["network_pps_drop_ratio_dropped_pps"] = []any{float64(300), float64(3) / float64(303), float64(3)}
			}
			if !reflect.DeepEqual(want, got) {
				t.Fatalf("healthy %s measurements regressed\nwant=%v\ngot=%v", version, want, got)
			}
		})
	}
}
