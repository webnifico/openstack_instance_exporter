package main

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var resourceAxisNames = [...]string{"cpu", "mem", "disk", "net"}

func resourceAxisResults(out resourceV2Output) [4]resourceAxisResult {
	return [4]resourceAxisResult{out.CPU, out.MEM, out.DISK, out.NET}
}

func resourceAxisLastSuccessTimestamp(lastSuccess time.Time) float64 {
	if lastSuccess.IsZero() {
		return 0
	}
	return float64(lastSuccess.UnixNano()) / float64(time.Second)
}

func resourceAxisBoolValue(value bool) float64 {
	if value {
		return 1
	}
	return 0
}

func appendInstanceResourceAxisHealthMetrics(
	mc *MetricsCollector,
	metrics *[]prometheus.Metric,
	out resourceV2Output,
	domain, serverName, instanceUUID, projectUUID, projectName, userUUID string,
) {
	if mc == nil || metrics == nil {
		return
	}
	for index, axis := range resourceAxisResults(out) {
		axisName := resourceAxisNames[index]
		labels := []string{domain, serverName, instanceUUID, projectUUID, projectName, userUUID, axisName}
		staleSeconds := axis.AgeSeconds
		if axis.LastSuccess.IsZero() {
			staleSeconds = -1
		}
		*metrics = append(*metrics,
			prometheus.MustNewConstMetric(mc.instanceResourceAxisFreshDesc, prometheus.GaugeValue, resourceAxisBoolValue(axis.Fresh), labels...),
			prometheus.MustNewConstMetric(mc.instanceResourceAxisAvailableDesc, prometheus.GaugeValue, resourceAxisBoolValue(axis.Available), labels...),
			prometheus.MustNewConstMetric(mc.instanceResourceAxisLastSuccessTimestampDesc, prometheus.GaugeValue, resourceAxisLastSuccessTimestamp(axis.LastSuccess), labels...),
			prometheus.MustNewConstMetric(mc.instanceResourceAxisStaleSecondsDesc, prometheus.GaugeValue, staleSeconds, labels...),
		)
	}
}
