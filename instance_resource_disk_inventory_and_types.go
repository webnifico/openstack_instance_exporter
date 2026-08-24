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
	telemetryFresh bool,
	dynamicMetrics *[]prometheus.Metric,
) (int, float64, float64, bool) {

	seenDisks := make(map[string]struct{})
	seenDiskPaths := make(map[string]struct{})
	diskMetaMap := make(map[string]DomainDisk)
	for _, d := range meta.Disks {
		if d.TargetDev != "" {
			diskMetaMap[d.TargetDev] = d
		}
	}

	maxDiskIOSignal := 0.0
	maxDiskActivity := 0.0
	maxDiskProjectedSeverity := -1.0
	derivedDiskPaths := make(map[string]struct{})

	for _, blk := range stat.Disks {
		if blk.Name == "" {
			continue
		}
		seenDiskPaths[blk.Name] = struct{}{}
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

		var rdIOPS, wrIOPS, rdLat, wrLat, flIOPS, flLat, avgIOSize, rwReqDelta, flReqDelta, bwBytesPerSec float64
		rwDerivedValid := false
		flushDerivedValid := false
		rwCountersPresent := blk.RdReqsPresent && blk.WrReqsPresent && blk.RdBytesPresent && blk.WrBytesPresent && blk.RdTimePresent && blk.WrTimePresent
		flushCountersPresent := blk.FlReqsPresent && blk.FlTimePresent
		if telemetryFresh && (rwCountersPresent || flushCountersPresent) {
			rdIOPS, wrIOPS, rdLat, wrLat, flIOPS, flLat, avgIOSize, rwReqDelta, flReqDelta, bwBytesPerSec, rwDerivedValid, flushDerivedValid = mc.im.calculateDiskIOWithAvailability(
				key,
				blk.RdReqs, blk.WrReqs,
				blk.RdBytes, blk.WrBytes,
				blk.RdTime, blk.WrTime,
				blk.FlReqs, blk.FlTime,
				rwCountersPresent, flushCountersPresent,
				now,
			)
		}
		if rwDerivedValid || flushDerivedValid {
			derivedDiskPaths[diskPath] = struct{}{}
		}

		diskSignal := 0.0
		diskActivity := 0.0

		if rwDerivedValid {
			iops := rdIOPS + wrIOPS
			diskActivity = math.Max(iops/100.0, bwBytesPerSec/(10.0*1024.0*1024.0))
		}
		if flushDerivedValid {
			diskActivity = math.Max(diskActivity, flIOPS/100.0)
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

		if rwDerivedValid && rwReqDelta >= 5 {
			if rdLat > 0 {
				diskSignal = math.Max(diskSignal, sevFromLat(rdLat, rwFloor, rwCeil))
			}
			if wrLat > 0 {
				diskSignal = math.Max(diskSignal, sevFromLat(wrLat, rwFloor, rwCeil))
			}
		}

		if flushDerivedValid && flReqDelta > 0 && flLat > 0 {
			const flFloor = 0.001
			const flCeil = 0.040
			diskSignal = math.Max(diskSignal, sevFromLat(flLat, flFloor, flCeil))
		}

		normalizedActivity := clamp01(diskActivity)
		projectedSeverity := math.Pow(clamp01(diskSignal/100.0)*normalizedActivity, 2) * normalizedActivity
		if projectedSeverity > maxDiskProjectedSeverity ||
			(projectedSeverity == maxDiskProjectedSeverity && (diskSignal > maxDiskIOSignal ||
				(diskSignal == maxDiskIOSignal && diskActivity > maxDiskActivity))) {
			maxDiskProjectedSeverity = projectedSeverity
			maxDiskIOSignal = diskSignal
			maxDiskActivity = diskActivity
		}

		diskMetrics := make([]prometheus.Metric, 0, 15)
		diskMetrics = append(diskMetrics, prometheus.MustNewConstMetric(mc.im.instanceDiskInfoDesc, prometheus.GaugeValue, 1.0, domain, serverName, instanceUUID, projectUUID, projectName, userUUID, volumeUUID, diskType, diskPath))

		counters := []struct {
			present bool
			val     float64
			desc    *prometheus.Desc
		}{
			{blk.RdBytesPresent, roundToFiveDecimals(float64(blk.RdBytes) * bytesToGigabytes), mc.im.instanceDiskReadGbytesTotalDesc},
			{blk.WrBytesPresent, roundToFiveDecimals(float64(blk.WrBytes) * bytesToGigabytes), mc.im.instanceDiskWriteGbytesTotalDesc},
			{blk.RdReqsPresent, float64(blk.RdReqs), mc.im.instanceDiskReadRequestsTotalDesc},
			{blk.WrReqsPresent, float64(blk.WrReqs), mc.im.instanceDiskWriteRequestsTotalDesc},
		}
		for _, c := range counters {
			if c.present {
				diskMetrics = append(diskMetrics, prometheus.MustNewConstMetric(c.desc, prometheus.CounterValue, c.val, domain, serverName, instanceUUID, projectUUID, projectName, userUUID, volumeUUID, diskType, diskPath))
			}
		}

		details := []struct {
			present bool
			val     float64
			desc    *prometheus.Desc
		}{
			{blk.RdTimePresent, float64(blk.RdTime) / 1e9, mc.im.instanceDiskReadSecondsTotalDesc},
			{blk.WrTimePresent, float64(blk.WrTime) / 1e9, mc.im.instanceDiskWriteSecondsTotalDesc},
			{blk.FlReqsPresent, float64(blk.FlReqs), mc.im.instanceDiskFlushRequestsTotalDesc},
			{blk.FlTimePresent, float64(blk.FlTime) / 1e9, mc.im.instanceDiskFlushSecondsTotalDesc},
		}

		for _, d := range details {
			if d.present {
				diskMetrics = append(diskMetrics, prometheus.MustNewConstMetric(d.desc, prometheus.CounterValue, d.val, domain, serverName, instanceUUID, projectUUID, projectName, userUUID, volumeUUID, diskType, diskPath))
			}
		}

		alloc := blk.Allocation
		allocPresent := blk.AllocationPresent
		if !allocPresent && blk.PhysicalPresent {
			alloc = blk.Physical
			allocPresent = true
		}

		if allocPresent {
			diskMetrics = append(diskMetrics, prometheus.MustNewConstMetric(mc.im.instanceDiskAllocationBytesDesc, prometheus.GaugeValue, float64(alloc), domain, serverName, instanceUUID, projectUUID, projectName, userUUID, volumeUUID, diskType, diskPath))
		}
		if blk.CapacityPresent {
			diskMetrics = append(diskMetrics, prometheus.MustNewConstMetric(mc.im.instanceDiskCapacityBytesDesc, prometheus.GaugeValue, float64(blk.Capacity), domain, serverName, instanceUUID, projectUUID, projectName, userUUID, volumeUUID, diskType, diskPath))
		}
		if rwDerivedValid {
			diskMetrics = append(diskMetrics,
				prometheus.MustNewConstMetric(mc.im.instanceDiskReadIopsDesc, prometheus.GaugeValue, rdIOPS, domain, serverName, instanceUUID, projectUUID, projectName, userUUID, volumeUUID, diskType, diskPath),
				prometheus.MustNewConstMetric(mc.im.instanceDiskWriteIopsDesc, prometheus.GaugeValue, wrIOPS, domain, serverName, instanceUUID, projectUUID, projectName, userUUID, volumeUUID, diskType, diskPath),
				prometheus.MustNewConstMetric(mc.im.instanceDiskReadLatencySecondsDesc, prometheus.GaugeValue, rdLat, domain, serverName, instanceUUID, projectUUID, projectName, userUUID, volumeUUID, diskType, diskPath),
				prometheus.MustNewConstMetric(mc.im.instanceDiskWriteLatencySecondsDesc, prometheus.GaugeValue, wrLat, domain, serverName, instanceUUID, projectUUID, projectName, userUUID, volumeUUID, diskType, diskPath),
			)
		}
		if flushDerivedValid {
			diskMetrics = append(diskMetrics,
				prometheus.MustNewConstMetric(mc.im.instanceDiskFlushIopsDesc, prometheus.GaugeValue, flIOPS, domain, serverName, instanceUUID, projectUUID, projectName, userUUID, volumeUUID, diskType, diskPath),
				prometheus.MustNewConstMetric(mc.im.instanceDiskFlushLatencySecondsDesc, prometheus.GaugeValue, flLat, domain, serverName, instanceUUID, projectUUID, projectName, userUUID, volumeUUID, diskType, diskPath),
			)
		}

		*dynamicMetrics = append(*dynamicMetrics, diskMetrics...)
	}

	relevantDisks := make(map[string]struct{}, len(diskMetaMap)+len(seenDiskPaths))
	for diskPath := range diskMetaMap {
		relevantDisks[diskPath] = struct{}{}
	}
	for diskPath := range seenDiskPaths {
		relevantDisks[diskPath] = struct{}{}
	}
	diskCountDomain := len(relevantDisks)
	if stat.BlockCountPresent && stat.BlockCount <= uint64(^uint(0)>>1) && int(stat.BlockCount) > diskCountDomain {
		diskCountDomain = int(stat.BlockCount)
	}

	completeSet := len(stat.Disks) == len(seenDiskPaths)
	if stat.BlockCountPresent {
		completeSet = completeSet && stat.BlockCount == uint64(len(stat.Disks)) && stat.BlockCount == uint64(len(seenDiskPaths))
	}
	if len(relevantDisks) == 0 {
		completeSet = false
	}
	for diskPath := range relevantDisks {
		if _, seen := seenDiskPaths[diskPath]; !seen {
			completeSet = false
		}
		if _, derived := derivedDiskPaths[diskPath]; !derived {
			completeSet = false
		}
	}

	return diskCountDomain, maxDiskIOSignal, maxDiskActivity, completeSet
}
