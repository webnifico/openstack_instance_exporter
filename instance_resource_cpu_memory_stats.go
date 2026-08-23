package main

import (
	"math"
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

func (mc *MetricsCollector) collectDomainMemoryMetrics(
	stat *ParsedStats,
	now time.Time,
	domain, serverName, instanceUUID, projectUUID, projectName, userUUID string,
	instanceRunning bool,
	memMB int,
	telemetryFresh bool,
	dynamicMetrics *[]prometheus.Metric,
) (float64, float64, bool, bool) {
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

	siRate := 0.0
	mjRate := 0.0
	swapInRateAvailable := false
	majorRateAvailable := false
	if instanceRunning && telemetryFresh && (stat.SwapInPresent || stat.SwapOutPresent || stat.MajorFaultPresent || stat.MinorFaultPresent) {
		si, _, mj, siValid, _, mjValid := mc.im.calculateMemRatesWithAvailability(
			instanceUUID,
			stat.SwapIn, stat.SwapOut, stat.MajorFault, stat.MinorFault,
			stat.SwapInPresent, stat.SwapOutPresent, stat.MajorFaultPresent, stat.MinorFaultPresent,
			now,
		)
		siRate = si
		mjRate = mj
		swapInRateAvailable = siValid
		majorRateAvailable = mjValid
	}

	if guestUsedAvailable {
		*dynamicMetrics = append(*dynamicMetrics,
			prometheus.MustNewConstMetric(mc.im.instanceMemUsedMBDesc, prometheus.GaugeValue, guestUsedMB, domain, serverName, instanceUUID, projectUUID, projectName, userUUID),
		)
	}

	memUsageSeverity := 0.0
	if guestUsedAvailable && memMB > 0 {
		usageRatio := guestUsedMB / float64(memMB)
		if usageRatio > 1.5 {
			usageRatio = 1.5
		}
		if usageRatio > 0.80 {
			memUsageSeverity = clamp01((usageRatio-0.80)/0.70) * 100.0
		}
	}

	swapSeverity := 0.0
	if swapInRateAvailable && siRate > 1024.0 {
		const swapHigh = 16384.0
		swapSeverity = clamp01((siRate-1024.0)/(swapHigh-1024.0)) * 100.0
	}

	majorSeverity := 0.0
	if majorRateAvailable && mjRate > 5.0 {
		const majorHigh = 200.0
		majorSeverity = clamp01((mjRate-5.0)/(majorHigh-5.0)) * 100.0
	}

	resourceMemSeverity := math.Max(memUsageSeverity, math.Max(swapSeverity, majorSeverity))
	return guestUsedMB, resourceMemSeverity, guestUsedAvailable, guestUsedAvailable || swapInRateAvailable || majorRateAvailable
}

func (mc *MetricsCollector) collectDomainCPUMetrics(
	stat *ParsedStats,
	domain, serverName, instanceUUID, projectUUID, projectName, userUUID string,
	vcpuCount int,
	telemetryFresh bool,
	dynamicMetrics *[]prometheus.Metric,
) (float64, bool) {
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
		return 0, false
	}
	cpuUsage, stealPercent, waitPercent, valid := mc.im.calculateCPUUsageWithAvailability(stat.CpuTime, stealTotal, waitTotal, stealAvailable, waitAvailable, instanceUUID, vcpuCount)
	if !valid {
		return 0, false
	}
	*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(mc.im.instanceCpuVcpuPercentDesc, prometheus.GaugeValue, roundToFiveDecimals(cpuUsage), domain, serverName, instanceUUID, projectUUID, projectName, userUUID))

	usage01 := clamp01(cpuUsage / 100.0)
	stall01 := 0.0
	if stealAvailable || waitAvailable {
		stall01 = clamp01((stealPercent + waitPercent) / 50.0)
	}
	return math.Max(stall01, usage01*0.3), true
}
