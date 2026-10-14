package main

import (
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func guestMemoryUsedMB(stat *ParsedStats, instanceRunning bool) (float64, bool) {
	if stat == nil || !instanceRunning || !stat.MemCurPresent || !stat.MemUsablePresent || stat.MemCur < stat.MemUsable {
		return 0, false
	}
	return float64(stat.MemCur-stat.MemUsable) / 1024.0, true
}

func (mc *MetricsCollector) collectDomainMemoryMetricsWithSources(
	stat *ParsedStats,
	now time.Time,
	domain, serverName, instanceUUID, projectUUID, projectName, userUUID string,
	instanceRunning bool,
	memMB int,
	telemetryFresh bool,
	dynamicMetrics *[]prometheus.Metric,
) (float64, bool, bool, []string) {
	guestUsedMB, guestUsedAvailable := guestMemoryUsedMB(stat, instanceRunning)

	appendCounter := func(present bool, desc *prometheus.Desc, value float64) {
		if present {
			*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(desc, prometheus.CounterValue, value, domain, serverName, instanceUUID, projectUUID, projectName, userUUID))
		}
	}
	appendGauge := func(present bool, desc *prometheus.Desc, value float64) {
		if present {
			*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, value, domain, serverName, instanceUUID, projectUUID, projectName, userUUID))
		}
	}

	appendCounter(stat.SwapInPresent, mc.im.instanceMemSwapInBytesDesc, float64(stat.SwapIn)*1024.0)
	appendCounter(stat.SwapOutPresent, mc.im.instanceMemSwapOutBytesDesc, float64(stat.SwapOut)*1024.0)
	appendGauge(stat.MemRssPresent, mc.im.instanceMemRSSMBDesc, float64(stat.MemRss)/1024.0)
	appendCounter(stat.MajorFaultPresent, mc.im.instanceMemMajorFaultsTotalDesc, float64(stat.MajorFault))
	appendCounter(stat.MinorFaultPresent, mc.im.instanceMemMinorFaultsTotalDesc, float64(stat.MinorFault))
	appendCounter(stat.HugetlbPgAllocPresent, mc.im.instanceHugetlbPgAllocDesc, float64(stat.HugetlbPgAlloc))
	appendCounter(stat.HugetlbPgFailPresent, mc.im.instanceHugetlbPgFailDesc, float64(stat.HugetlbPgFail))

	swapInRateAvailable := false
	majorRateAvailable := false
	if instanceRunning && telemetryFresh && (stat.SwapInPresent || stat.SwapOutPresent || stat.MajorFaultPresent || stat.MinorFaultPresent) {
		_, _, _, siValid, _, mjValid := mc.im.calculateMemRatesWithAvailability(
			instanceUUID,
			stat.SwapIn, stat.SwapOut, stat.MajorFault, stat.MinorFault,
			stat.SwapInPresent, stat.SwapOutPresent, stat.MajorFaultPresent, stat.MinorFaultPresent,
			now,
		)
		swapInRateAvailable = siValid
		majorRateAvailable = mjValid
	}

	if guestUsedAvailable {
		*dynamicMetrics = append(*dynamicMetrics,
			prometheus.MustNewConstMetric(mc.im.instanceMemUsedMBDesc, prometheus.GaugeValue, guestUsedMB, domain, serverName, instanceUUID, projectUUID, projectName, userUUID),
		)
	}

	resourceSources := make([]string, 0, 3)
	if guestUsedAvailable {
		resourceSources = append(resourceSources, "guest_used")
	}
	if swapInRateAvailable {
		resourceSources = append(resourceSources, "swap_in")
	}
	if majorRateAvailable {
		resourceSources = append(resourceSources, "major_fault")
	}

	return guestUsedMB, guestUsedAvailable, len(resourceSources) > 0, resourceSources
}

func (mc *MetricsCollector) collectDomainCPUMetricsWithSources(
	stat *ParsedStats,
	now time.Time,
	domain, serverName, instanceUUID, projectUUID, projectName, userUUID string,
	vcpuCount int,
	telemetryFresh bool,
	dynamicMetrics *[]prometheus.Metric,
) (float64, bool, []string) {
	var stealTotal, waitTotal uint64
	perVCPUCoverageComplete := vcpuCount > 0 && len(stat.Vcpus) == vcpuCount
	stealAvailable := perVCPUCoverageComplete
	waitAvailable := perVCPUCoverageComplete
	for i, vcpu := range stat.Vcpus {
		if vcpu.DelayPresent {
			stealTotal += vcpu.Delay
			*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(mc.im.instanceCpuStealSecondsTotalDesc, prometheus.CounterValue, float64(vcpu.Delay)/1e9, domain, serverName, instanceUUID, projectUUID, projectName, userUUID, strconv.Itoa(i)))
		} else {
			stealAvailable = false
		}
		if vcpu.WaitPresent {
			waitTotal += vcpu.Wait
			*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(mc.im.instanceCpuWaitSecondsTotalDesc, prometheus.CounterValue, float64(vcpu.Wait)/1e9, domain, serverName, instanceUUID, projectUUID, projectName, userUUID, strconv.Itoa(i)))
		} else {
			waitAvailable = false
		}
	}

	if !telemetryFresh || !stat.CpuTimePresent {
		return 0, false, nil
	}
	cpuUsage, _, _, usageValid, stealValid, waitValid := mc.im.calculateCPUUsageWithDetailedAvailabilityAt(
		stat.CpuTime,
		stealTotal,
		waitTotal,
		stealAvailable,
		waitAvailable,
		instanceUUID,
		vcpuCount,
		now,
	)
	if !usageValid {
		return 0, false, nil
	}
	*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(mc.im.instanceCpuVcpuPercentDesc, prometheus.GaugeValue, roundToFiveDecimals(cpuUsage), domain, serverName, instanceUUID, projectUUID, projectName, userUUID))

	resourceSources := []string{"usage"}
	if stealValid {
		// Libvirt's delay and wait counters both describe time waiting in the
		// host scheduler runqueue. Prefer delay (the guest-visible steal-time
		// source) and use wait only as a compatibility fallback; adding the two
		// aliases would double-count scheduler contention.
		resourceSources = append(resourceSources, "steal")
	} else if waitValid {
		resourceSources = append(resourceSources, "wait")
	}
	return cpuUsage, true, resourceSources
}
