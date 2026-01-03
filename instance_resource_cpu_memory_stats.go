package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"math"
	"strconv"
	"time"
)

func (mc *MetricsCollector) collectDomainMemoryMetrics(
	stat *ParsedStats,
	now time.Time,
	domain, serverName, instanceUUID, projectUUID, projectName, userUUID string,
	instanceRunning bool,
	memMB int,
	dynamicMetrics *[]prometheus.Metric,
) (float64, float64) {

	var guestUsedMB float64
	if instanceRunning {
		if stat.MemUsable > 0 && stat.MemCur >= stat.MemUsable {
			guestUsedMB = float64(stat.MemCur-stat.MemUsable) / 1024.0
		} else if stat.MemRss > 0 {
			guestUsedMB = float64(stat.MemRss) / 1024.0
		} else if stat.MemCur > 0 {
			guestUsedMB = float64(stat.MemCur) / 1024.0
		}
	}

	*dynamicMetrics = append(*dynamicMetrics,
		prometheus.MustNewConstMetric(mc.im.instanceMemSwapInBytesDesc, prometheus.CounterValue, float64(stat.SwapIn)*1024.0, domain, serverName, instanceUUID, projectUUID, projectName, userUUID),
		prometheus.MustNewConstMetric(mc.im.instanceMemSwapOutBytesDesc, prometheus.CounterValue, float64(stat.SwapOut)*1024.0, domain, serverName, instanceUUID, projectUUID, projectName, userUUID),
		prometheus.MustNewConstMetric(mc.im.instanceMemRSSMBDesc, prometheus.GaugeValue, float64(stat.MemRss)/1024.0, domain, serverName, instanceUUID, projectUUID, projectName, userUUID),
		prometheus.MustNewConstMetric(mc.im.instanceMemMajorFaultsTotalDesc, prometheus.CounterValue, float64(stat.MajorFault), domain, serverName, instanceUUID, projectUUID, projectName, userUUID),
		prometheus.MustNewConstMetric(mc.im.instanceMemMinorFaultsTotalDesc, prometheus.CounterValue, float64(stat.MinorFault), domain, serverName, instanceUUID, projectUUID, projectName, userUUID),
	)

	siRate := 0.0
	mjRate := 0.0
	if instanceRunning {
		si, _, mj := mc.im.calculateMemRates(
			instanceUUID,
			stat.SwapIn,
			stat.SwapOut,
			stat.MajorFault,
			stat.MinorFault,
			now,
		)
		siRate = si
		mjRate = mj
	}

	if guestUsedMB > 0 {
		*dynamicMetrics = append(*dynamicMetrics,
			prometheus.MustNewConstMetric(mc.im.instanceMemUsedMBDesc, prometheus.GaugeValue, guestUsedMB, domain, serverName, instanceUUID, projectUUID, projectName, userUUID),
		)
	}

	memUsageSeverity := 0.0
	if guestUsedMB > 0 && memMB > 0 {
		usageRatio := guestUsedMB / float64(memMB)
		if usageRatio > 1.5 {
			usageRatio = 1.5
		}
		if usageRatio > 0.80 {
			u01 := clamp01((usageRatio - 0.80) / 0.70)
			memUsageSeverity = u01 * 100.0
		}
	}

	swapSeverity := 0.0
	if siRate > 0 {
		const swapLow = 1024.0
		const swapHigh = 16384.0
		if siRate > swapLow {
			s01 := clamp01((siRate - swapLow) / (swapHigh - swapLow))
			swapSeverity = s01 * 100.0
		}
	}

	majorSeverity := 0.0
	if mjRate > 0 {
		const majorLow = 5.0
		const majorHigh = 200.0
		if mjRate > majorLow {
			m01 := clamp01((mjRate - majorLow) / (majorHigh - majorLow))
			majorSeverity = m01 * 100.0
		}
	}

	resourceMemSeverity := math.Max(memUsageSeverity, math.Max(swapSeverity, majorSeverity))
	return guestUsedMB, resourceMemSeverity
}
func (mc *MetricsCollector) collectDomainCPUMetrics(
	stat *ParsedStats,
	domain, serverName, instanceUUID, projectUUID, projectName, userUUID string,
	vcpuCount int,
	dynamicMetrics *[]prometheus.Metric,
) float64 {

	var stealTotal, waitTotal uint64
	for i, vcpu := range stat.Vcpus {
		stealTotal += vcpu.Delay
		waitTotal += vcpu.Wait
		*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(mc.im.instanceCpuStealSecondsTotalDesc, prometheus.CounterValue, float64(vcpu.Delay)/1e9, domain, serverName, instanceUUID, projectUUID, projectName, userUUID, strconv.Itoa(i)))
		*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(mc.im.instanceCpuWaitSecondsTotalDesc, prometheus.CounterValue, float64(vcpu.Wait)/1e9, domain, serverName, instanceUUID, projectUUID, projectName, userUUID, strconv.Itoa(i)))
	}

	cpuUsage, stealPercent, waitPercent := mc.im.calculateCPUUsage(stat.CpuTime, stealTotal, waitTotal, instanceUUID, vcpuCount)
	*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(mc.im.instanceCpuVcpuPercentDesc, prometheus.GaugeValue, roundToFiveDecimals(cpuUsage), domain, serverName, instanceUUID, projectUUID, projectName, userUUID))

	usage01 := 0.0
	if cpuUsage > 0 {
		usage01 = clamp01(cpuUsage / 100.0)
	}

	stall01 := 0.0
	stallTotal := stealPercent + waitPercent
	if stallTotal > 0 {
		stall01 = clamp01(stallTotal / 50.0)
	}

	cpuPressure := math.Max(stall01, usage01*0.3)
	return cpuPressure
}
