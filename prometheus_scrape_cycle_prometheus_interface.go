package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"sync"
	"time"
)

func (mc *MetricsCollector) Describe(ch chan<- *prometheus.Desc) {
	mc.im.describeInstanceMetrics(ch)
	mc.tm.describeThreatMetrics(ch)
	mc.cm.describeConntrackMetrics(ch)

	ch <- mc.instanceResourceSeverityDesc

	ch <- mc.instanceResourceCpuSeverityDesc
	ch <- mc.instanceResourceMemSeverityDesc
	ch <- mc.instanceResourceDiskSeverityDesc
	ch <- mc.instanceResourceNetSeverityDesc
	ch <- mc.instanceThreatListSeverityDesc
	ch <- mc.instanceAttentionSeverityDesc
	ch <- mc.instanceBehaviorSeverityDesc

	mc.describeHostMetrics(ch)
}

func (mc *MetricsCollector) describeHostMetrics(ch chan<- *prometheus.Desc) {
	ch <- mc.hostMemTotalMBDesc
	ch <- mc.hostLibvirtActiveVMsDesc
	ch <- mc.hostCpuActiveVcpusDesc
	ch <- mc.hostActiveDisksDesc
	ch <- mc.hostActiveFixedIPsDesc
	ch <- mc.hostActiveProjectsDesc
	ch <- mc.hostCpuThreadsDesc
	ch <- mc.hostCollectionErrorsTotalDesc
	ch <- mc.hostCollectionCycleDurationSecondsDesc
	ch <- mc.hostCollectionCycleLagSecondsDesc
	ch <- mc.hostLibvirtListDurationSecondsDesc
	ch <- mc.hostConntrackReadDurationSecondsDesc
	ch <- mc.hostConntrackEntriesDesc
	ch <- mc.hostGoHeapAllocBytesDesc
	ch <- mc.hostConntrackReadErrorsTotalDesc
	ch <- mc.hostConntrackRawOkDesc
	ch <- mc.hostConntrackRawENOBUFSTotalDesc
	ch <- mc.hostConntrackRawParseErrorsTotalDesc
	ch <- mc.hostConntrackLastSuccessTimestampDesc
	ch <- mc.hostConntrackStaleSecondsDesc
	ch <- mc.hostConntrackMaxDesc
	ch <- mc.hostConntrackUtilizationDesc
	ch <- mc.hostCacheCleanupDurationSecondsDesc

	ch <- mc.hostCpuUsagePercentDesc
	ch <- mc.hostMemFreeMBDesc
	ch <- mc.hostMemAvailableMBDesc

	mc.tm.describeHostMetrics(ch)
}

func (mc *MetricsCollector) runCollectionCycle() []prometheus.Metric {
	mc.collectionMu.Lock()
	defer mc.collectionMu.Unlock()
	if mc.collectionRunner != nil {
		return mc.collectionRunner()
	}

	ch := make(chan prometheus.Metric, 1024)
	metrics := make([]prometheus.Metric, 0, 1024)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for m := range ch {
			metrics = append(metrics, m)
		}
	}()
	mc.collectHeavy(ch)
	close(ch)
	wg.Wait()
	return metrics
}

func (mc *MetricsCollector) startBackgroundCollector() {
	interval := mc.collectionInterval
	if interval <= 0 {
		interval = 15 * time.Second
	}
	nextCollection := time.Now().Add(interval)

	for {
		if !waitForBackgroundCollectionDeadline(nextCollection, mc.shutdownChan) {
			logCollectorMetric.Info("background_collector_shutdown")
			return
		}

		metrics := mc.runCollectionCycle()
		mc.cacheMu.Lock()
		mc.cachedMetrics = metrics
		mc.cacheInitialized = true
		mc.cacheMu.Unlock()

		nextCollection = advanceBackgroundCollectionDeadline(nextCollection, interval, time.Now())
	}
}

func waitForBackgroundCollectionDeadline(deadline time.Time, shutdown <-chan struct{}) bool {
	wait := time.Until(deadline)
	if wait < 0 {
		wait = 0
	}
	t := time.NewTimer(wait)
	select {
	case <-shutdown:
		t.Stop()
		return false
	case <-t.C:
	}

	// If shutdown became ready with the timer, do not let select's random choice
	// start another expensive collection after termination was requested.
	select {
	case <-shutdown:
		return false
	default:
		return true
	}
}

func advanceBackgroundCollectionDeadline(previous time.Time, interval time.Duration, now time.Time) time.Time {
	next := previous.Add(interval)
	if next.After(now) {
		return next
	}
	missed := now.Sub(next)/interval + 1
	return next.Add(missed * interval)
}

func (mc *MetricsCollector) cachedOrCollect() []prometheus.Metric {
	mc.cacheMu.RLock()
	cached := mc.cachedMetrics
	initialized := mc.cacheInitialized
	mc.cacheMu.RUnlock()
	if initialized {
		return cached
	}

	mc.initialCollectionMu.Lock()
	defer mc.initialCollectionMu.Unlock()

	mc.cacheMu.RLock()
	cached = mc.cachedMetrics
	initialized = mc.cacheInitialized
	mc.cacheMu.RUnlock()
	if initialized {
		return cached
	}

	cached = mc.runCollectionCycle()
	mc.cacheMu.Lock()
	mc.cachedMetrics = cached
	mc.cacheInitialized = true
	mc.cacheMu.Unlock()
	return cached
}

func (mc *MetricsCollector) Collect(ch chan<- prometheus.Metric) {
	cached := mc.cachedOrCollect()
	mc.backgroundOnce.Do(func() {
		go mc.startBackgroundCollector()
	})
	for _, m := range cached {
		ch <- m
	}
}
