package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"math"
	"strings"
	"time"
)

func parseDiskType(sourceName string) (string, string) {
	parts := strings.SplitN(sourceName, "/", 2)
	if len(parts) == 2 {
		if parts[0] != "" && parts[1] != "" {
			return parts[0], parts[1]
		}
	}
	return "unknown", "unknown"
}

func (mc *MetricsCollector) collectDomainDiskMetrics(
	meta *DomainStatic,
	stat *ParsedStats,
	now time.Time,
	domain, serverName, instanceUUID, projectUUID, projectName, userUUID string,
	dynamicMetrics *[]prometheus.Metric,
) (int, float64, float64) {

	seenDisks := make(map[string]struct{})
	diskCountDomain := 0
	diskMetaMap := make(map[string]DomainDisk)
	for _, d := range meta.Disks {
		if d.TargetDev != "" {
			diskMetaMap[d.TargetDev] = d
		}
	}

	maxDiskIOSignal := 0.0
	maxDiskActivity := 0.0

	for _, blk := range stat.Disks {
		if blk.Name == "" {
			continue
		}
		dMeta, ok := diskMetaMap[blk.Name]
		var diskType, volumeUUID string
		if ok {
			if dMeta.Type == "file" {
				diskType = "local"
				volumeUUID = dMeta.SourceFile
			} else {
				diskType, volumeUUID = parseDiskType(dMeta.SourceName)
			}
		} else {
			diskType = "unknown"
			volumeUUID = "unknown"
		}
		diskPath := blk.Name
		key := instanceUUID + "|" + volumeUUID + "|" + diskPath
		if _, exists := seenDisks[key]; exists {
			continue
		}
		seenDisks[key] = struct{}{}
		diskCountDomain++

		rdIOPS, wrIOPS, rdLat, wrLat, flIOPS, flLat, avgIOSize, rwReqDelta, flReqDelta, bwBytesPerSec := mc.im.calculateDiskIO(
			key,
			int64(blk.RdReqs), int64(blk.WrReqs),
			int64(blk.RdBytes), int64(blk.WrBytes),
			int64(blk.RdTime), int64(blk.WrTime),
			int64(blk.FlReqs), int64(blk.FlTime),
			now,
		)

		diskSignal := 0.0

		iops := rdIOPS + wrIOPS
		activity := math.Max(iops/100.0, bwBytesPerSec/(10.0*1024.0*1024.0))
		if activity > maxDiskActivity {
			maxDiskActivity = activity
		}

		const ioSmall = 64.0 * 1024.0
		const ioLarge = 1024.0 * 1024.0

		const rwFloor = 0.002
		const rwCeilSmall = 0.020
		const rwCeilLarge = 0.100

		rwCeil := rwCeilSmall
		if avgIOSize >= ioLarge {
			rwCeil = rwCeilLarge
		} else if avgIOSize > ioSmall {
			t := (avgIOSize - ioSmall) / (ioLarge - ioSmall)
			rwCeil = rwCeilSmall + t*(rwCeilLarge-rwCeilSmall)
		}

		sevFromLat := func(lat, floor, ceil float64) float64 {
			if lat <= floor || ceil <= floor {
				return 0
			}
			return clamp01((lat-floor)/(ceil-floor)) * 100.0
		}

		if rwReqDelta >= 5 {
			if rdLat > 0 {
				diskSignal = math.Max(diskSignal, sevFromLat(rdLat, rwFloor, rwCeil))
			}
			if wrLat > 0 {
				diskSignal = math.Max(diskSignal, sevFromLat(wrLat, rwFloor, rwCeil))
			}
		}

		if flReqDelta > 0 && flLat > 0 {
			const flFloor = 0.001
			const flCeil = 0.040
			diskSignal = math.Max(diskSignal, sevFromLat(flLat, flFloor, flCeil))
		}

		if diskSignal > maxDiskIOSignal {
			maxDiskIOSignal = diskSignal
		}

		diskMetrics := make([]prometheus.Metric, 0, 15)
		diskMetrics = append(diskMetrics, prometheus.MustNewConstMetric(mc.im.instanceDiskInfoDesc, prometheus.GaugeValue, 1.0, domain, serverName, instanceUUID, projectUUID, projectName, userUUID, volumeUUID, diskType, diskPath))

		counters := []struct {
			val  float64
			desc *prometheus.Desc
		}{
			{roundToFiveDecimals(float64(blk.RdBytes) * bytesToGigabytes), mc.im.instanceDiskReadGbytesTotalDesc},
			{roundToFiveDecimals(float64(blk.WrBytes) * bytesToGigabytes), mc.im.instanceDiskWriteGbytesTotalDesc},
			{float64(blk.RdReqs), mc.im.instanceDiskReadRequestsTotalDesc},
			{float64(blk.WrReqs), mc.im.instanceDiskWriteRequestsTotalDesc},
		}
		for _, c := range counters {
			diskMetrics = append(diskMetrics, prometheus.MustNewConstMetric(c.desc, prometheus.CounterValue, c.val, domain, serverName, instanceUUID, projectUUID, projectName, userUUID, volumeUUID, diskType, diskPath))
		}

		details := []struct {
			val  float64
			desc *prometheus.Desc
		}{
			{float64(blk.RdTime) / 1e9, mc.im.instanceDiskReadSecondsTotalDesc},
			{float64(blk.WrTime) / 1e9, mc.im.instanceDiskWriteSecondsTotalDesc},
			{float64(blk.FlReqs), mc.im.instanceDiskFlushRequestsTotalDesc},
			{float64(blk.FlTime) / 1e9, mc.im.instanceDiskFlushSecondsTotalDesc},
		}

		for _, d := range details {
			diskMetrics = append(diskMetrics, prometheus.MustNewConstMetric(d.desc, prometheus.CounterValue, d.val, domain, serverName, instanceUUID, projectUUID, projectName, userUUID, volumeUUID, diskType, diskPath))
		}

		alloc := blk.Allocation
		if alloc == 0 && blk.Physical > 0 {
			alloc = blk.Physical
		}

		diskMetrics = append(diskMetrics, prometheus.MustNewConstMetric(mc.im.instanceDiskAllocationBytesDesc, prometheus.GaugeValue, float64(alloc), domain, serverName, instanceUUID, projectUUID, projectName, userUUID, volumeUUID, diskType, diskPath))
		diskMetrics = append(diskMetrics, prometheus.MustNewConstMetric(mc.im.instanceDiskCapacityBytesDesc, prometheus.GaugeValue, float64(blk.Capacity), domain, serverName, instanceUUID, projectUUID, projectName, userUUID, volumeUUID, diskType, diskPath))
		diskMetrics = append(diskMetrics,
			prometheus.MustNewConstMetric(mc.im.instanceDiskReadIopsDesc, prometheus.GaugeValue, rdIOPS, domain, serverName, instanceUUID, projectUUID, projectName, userUUID, volumeUUID, diskType, diskPath),
			prometheus.MustNewConstMetric(mc.im.instanceDiskWriteIopsDesc, prometheus.GaugeValue, wrIOPS, domain, serverName, instanceUUID, projectUUID, projectName, userUUID, volumeUUID, diskType, diskPath),
			prometheus.MustNewConstMetric(mc.im.instanceDiskFlushIopsDesc, prometheus.GaugeValue, flIOPS, domain, serverName, instanceUUID, projectUUID, projectName, userUUID, volumeUUID, diskType, diskPath),
			prometheus.MustNewConstMetric(mc.im.instanceDiskReadLatencySecondsDesc, prometheus.GaugeValue, rdLat, domain, serverName, instanceUUID, projectUUID, projectName, userUUID, volumeUUID, diskType, diskPath),
			prometheus.MustNewConstMetric(mc.im.instanceDiskWriteLatencySecondsDesc, prometheus.GaugeValue, wrLat, domain, serverName, instanceUUID, projectUUID, projectName, userUUID, volumeUUID, diskType, diskPath),
			prometheus.MustNewConstMetric(mc.im.instanceDiskFlushLatencySecondsDesc, prometheus.GaugeValue, flLat, domain, serverName, instanceUUID, projectUUID, projectName, userUUID, volumeUUID, diskType, diskPath),
		)

		*dynamicMetrics = append(*dynamicMetrics, diskMetrics...)
	}

	return diskCountDomain, maxDiskIOSignal, maxDiskActivity
}
