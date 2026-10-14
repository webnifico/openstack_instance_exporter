package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"sort"
	"strings"
	"time"
)

func (mc *MetricsCollector) collectDomainDiskMetricsWithSources(
	meta *DomainStatic,
	stat *ParsedStats,
	now time.Time,
	domain, serverName, instanceUUID, projectUUID, projectName, userUUID string,
	telemetryFresh bool,
	dynamicMetrics *[]prometheus.Metric,
) (int, bool, string, []string, bool) {

	seenDisks := make(map[string]struct{})
	seenDiskPaths := make(map[string]struct{})
	configured := meta.BlockDevices
	if configured == nil {
		configured = meta.Disks
	}
	allDevices := make(map[string]DomainDisk, len(configured))
	for _, d := range configured {
		allDevices[d.TargetDev] = d
	}
	diskMetaMap := make(map[string]DomainDisk)
	for _, d := range meta.Disks {
		if d.TargetDev != "" {
			diskMetaMap[d.TargetDev] = d
		}
	}

	derivedDiskPaths := make(map[string]struct{})
	resourceSources := make([]string, 0, len(stat.Disks)*2)

	runtimeTargets := make([]string, 0, len(stat.Disks))
	for _, blk := range stat.Disks {
		if blk == nil {
			runtimeTargets = append(runtimeTargets, "")
			continue
		}
		runtimeTargets = append(runtimeTargets, blk.Name)
		if blk.Name == "" {
			continue
		}
		// Ignore only devices positively identified by this XML snapshot.
		// An unknown runtime target still prevents authoritative collection.
		if device, known := allDevices[blk.Name]; known && isInventoryOnlyBlockDevice(device) {
			continue
		}
		seenDiskPaths[blk.Name] = struct{}{}
		dMeta, ok := diskMetaMap[blk.Name]
		var diskType, volumeUUID string
		if ok {
			diskType, volumeUUID = diskMetricSource(dMeta)
		} else {
			diskType, volumeUUID = "unknown", "unknown"
		}
		diskPath := blk.Name
		key := instanceUUID + "|" + volumeUUID + "|" + diskPath
		if _, exists := seenDisks[key]; exists {
			continue
		}
		seenDisks[key] = struct{}{}

		var rdIOPS, wrIOPS, rdLat, wrLat, flIOPS, flLat float64
		rwDerivedValid := false
		flushDerivedValid := false
		rwCountersPresent := blk.RdReqsPresent && blk.WrReqsPresent && blk.RdBytesPresent && blk.WrBytesPresent && blk.RdTimePresent && blk.WrTimePresent
		flushCountersPresent := blk.FlReqsPresent && blk.FlTimePresent
		if telemetryFresh && (rwCountersPresent || flushCountersPresent) {
			rdIOPS, wrIOPS, rdLat, wrLat, flIOPS, flLat, _, _, _, _, rwDerivedValid, flushDerivedValid = mc.im.calculateDiskIOWithAvailability(
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
		if rwDerivedValid {
			resourceSources = append(resourceSources, "rw:"+key)
		}
		if flushDerivedValid {
			resourceSources = append(resourceSources, "flush:"+key)
		}

		diskMetrics := make([]prometheus.Metric, 0, 15)
		diskMetrics = append(diskMetrics, prometheus.MustNewConstMetric(mc.im.instanceDiskInfoDesc, prometheus.GaugeValue, 1.0, domain, serverName, instanceUUID, projectUUID, projectName, userUUID, volumeUUID, diskType, diskPath))

		counters := []struct {
			present bool
			val     float64
			desc    *prometheus.Desc
		}{
			{blk.RdBytesPresent, float64(blk.RdBytes) * bytesToGigabytes, mc.im.instanceDiskReadGbytesTotalDesc},
			{blk.WrBytesPresent, float64(blk.WrBytes) * bytesToGigabytes, mc.im.instanceDiskWriteGbytesTotalDesc},
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

		if blk.AllocationPresent {
			diskMetrics = append(diskMetrics, prometheus.MustNewConstMetric(mc.im.instanceDiskAllocationBytesDesc, prometheus.GaugeValue, float64(blk.Allocation), domain, serverName, instanceUUID, projectUUID, projectName, userUUID, volumeUUID, diskType, diskPath))
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
	authoritativeDiskSet := telemetryFresh && resourceDiskTargetsComplete(
		configured, runtimeTargets, stat.BlockCount, stat.BlockCountPresent,
	)
	if authoritativeDiskSet {
		mc.im.pruneDiskSamples(instanceUUID, seenDisks)
	}
	// block.count includes CD-ROMs/config drives and must not inflate this
	// count of configured or runtime-observed resource disks.
	diskCountDomain := len(relevantDisks)
	completeSet := authoritativeDiskSet
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

	identityKeys := make([]string, 0, len(seenDisks))
	for key := range seenDisks {
		identityKeys = append(identityKeys, key)
	}
	sort.Strings(identityKeys)
	sort.Strings(resourceSources)
	return diskCountDomain, completeSet, strings.Join(identityKeys, "\x00"), resourceSources, authoritativeDiskSet
}
