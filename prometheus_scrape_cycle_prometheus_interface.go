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

	for {
		t := time.NewTimer(interval)
		select {
		case <-mc.shutdownChan:
			t.Stop()
			logCollectorMetric.Info("background_collector_shutdown")
			return
		case <-t.C:
		}

		metrics := mc.runCollectionCycle()
		mc.cacheMu.Lock()
		mc.cachedMetrics = metrics
		mc.cacheMu.Unlock()
	}
}

func (mc *MetricsCollector) Collect(ch chan<- prometheus.Metric) {
	mc.backgroundOnce.Do(func() {
		go mc.startBackgroundCollector()
	})
	mc.cacheMu.RLock()
	cached := mc.cachedMetrics
	mc.cacheMu.RUnlock()
	if len(cached) == 0 {
		cached = mc.runCollectionCycle()
		mc.cacheMu.Lock()
		mc.cachedMetrics = cached
		mc.cacheMu.Unlock()
	}
	for _, m := range cached {
		ch <- m
	}
}
