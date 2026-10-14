package main

import (
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func (mc *MetricsCollector) recordLibvirtCollectionResult(success bool, now time.Time) {
	if !success {
		atomic.StoreUint64(&mc.libvirtOK, 0)
		return
	}

	atomic.StoreInt64(&mc.libvirtLastSuccessUnix, now.Unix())
	atomic.StoreUint64(&mc.libvirtOK, 1)
}

func (mc *MetricsCollector) libvirtSourceAvailable() bool {
	return atomic.LoadUint64(&mc.libvirtOK) == 1
}

func (mc *MetricsCollector) libvirtSourceHealthSnapshot(now time.Time) (float64, float64, float64) {
	ok := float64(atomic.LoadUint64(&mc.libvirtOK))
	lastSuccess := atomic.LoadInt64(&mc.libvirtLastSuccessUnix)
	if lastSuccess <= 0 {
		return ok, 0, -1
	}

	staleSeconds := now.Sub(time.Unix(lastSuccess, 0)).Seconds()
	if staleSeconds < 0 {
		staleSeconds = 0
	}
	return ok, float64(lastSuccess), staleSeconds
}

func (mc *MetricsCollector) libvirtSourceHealthMetrics(now time.Time) []prometheus.Metric {
	ok, lastSuccess, staleSeconds := mc.libvirtSourceHealthSnapshot(now)
	return []prometheus.Metric{
		prometheus.MustNewConstMetric(mc.hostLibvirtOkDesc, prometheus.GaugeValue, ok),
		prometheus.MustNewConstMetric(mc.hostLibvirtLastSuccessTimestampDesc, prometheus.GaugeValue, lastSuccess),
		prometheus.MustNewConstMetric(mc.hostLibvirtStaleSecondsDesc, prometheus.GaugeValue, staleSeconds),
	}
}
