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
	ch <- mc.instanceResourceAxisFreshDesc
	ch <- mc.instanceResourceAxisAvailableDesc
	ch <- mc.instanceResourceAxisLastSuccessTimestampDesc
	ch <- mc.instanceResourceAxisStaleSecondsDesc
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
	ch <- mc.hostCollectionIntervalSecondsDesc
	ch <- mc.hostCollectionCycleLagSecondsDesc
	ch <- mc.hostLibvirtListDurationSecondsDesc
	ch <- mc.hostLibvirtOkDesc
	ch <- mc.hostLibvirtLastSuccessTimestampDesc
	ch <- mc.hostLibvirtStaleSecondsDesc
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
	ch <- mc.hostVolumeRetypeResultsTotalDesc

	ch <- mc.hostCpuUsagePercentDesc
	ch <- mc.hostMemFreeMBDesc
	ch <- mc.hostMemAvailableMBDesc

	mc.tm.describeHostMetrics(ch)
}

func (mc *MetricsCollector) runCollectionCycle() []prometheus.Metric {
	metrics, _ := mc.runCollectionCycleWithLibvirtHealth()
	return metrics
}

func (mc *MetricsCollector) runCollectionCycleWithLibvirtHealth() ([]prometheus.Metric, bool) {
	mc.collectionMu.Lock()
	defer mc.collectionMu.Unlock()
	if mc.collectionRunner != nil {
		metrics := mc.collectionRunner()
		return metrics, mc.libvirtSourceAvailable()
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
	return metrics, mc.libvirtSourceAvailable()
}

func (mc *MetricsCollector) startBackgroundCollector() {
	interval := mc.effectiveCollectionInterval()
	nextCollection := time.Now().Add(interval)

	for {
		if !waitForBackgroundCollectionDeadline(nextCollection, mc.shutdownChan) {
			logCollectorMetric.Info("background_collector_shutdown")
			return
		}

		metrics, libvirtAvailable := mc.runCollectionCycleWithLibvirtHealth()
		mc.cacheMu.Lock()
		mc.cachedMetrics = metrics
		mc.cachedLibvirtAvailable = libvirtAvailable
		mc.cacheInitialized = true
		mc.cacheMu.Unlock()

		nextCollection = advanceBackgroundCollectionDeadline(nextCollection, interval, time.Now())
	}
}

func (mc *MetricsCollector) isVolumeRetypeDescriptor(desc *prometheus.Desc) bool {
	if desc == nil {
		return false
	}
	descriptors := []*prometheus.Desc{mc.hostVolumeRetypeResultsTotalDesc}
	if mc.im != nil {
		descriptors = append(descriptors,
			mc.im.instanceDiskRetypeActiveDesc,
			mc.im.instanceDiskRetypeProgressDesc,
			mc.im.instanceDiskRetypeStatusCodeDesc,
			mc.im.instanceDiskRetypeObservationHealthyDesc,
			mc.im.instanceDiskRetypeStartTimestampDesc,
			mc.im.instanceDiskRetypeReadyTimestampDesc,
			mc.im.instanceDiskRetypeEndTimestampDesc,
		)
	}
	for _, retypeDesc := range descriptors {
		if desc == retypeDesc {
			return true
		}
	}
	return false
}

func (mc *MetricsCollector) effectiveCollectionInterval() time.Duration {
	if mc == nil || mc.collectionInterval <= 0 {
		return 15 * time.Second
	}
	return mc.collectionInterval
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

func (mc *MetricsCollector) cachedOrCollect() ([]prometheus.Metric, bool) {
	mc.cacheMu.RLock()
	cached := mc.cachedMetrics
	libvirtAvailable := mc.cachedLibvirtAvailable
	initialized := mc.cacheInitialized
	mc.cacheMu.RUnlock()
	if initialized {
		return cached, libvirtAvailable
	}

	mc.initialCollectionMu.Lock()
	defer mc.initialCollectionMu.Unlock()

	mc.cacheMu.RLock()
	cached = mc.cachedMetrics
	libvirtAvailable = mc.cachedLibvirtAvailable
	initialized = mc.cacheInitialized
	mc.cacheMu.RUnlock()
	if initialized {
		return cached, libvirtAvailable
	}

	cached, libvirtAvailable = mc.runCollectionCycleWithLibvirtHealth()
	mc.cacheMu.Lock()
	mc.cachedMetrics = cached
	mc.cachedLibvirtAvailable = libvirtAvailable
	mc.cacheInitialized = true
	mc.cacheMu.Unlock()
	return cached, libvirtAvailable
}

func (mc *MetricsCollector) Collect(ch chan<- prometheus.Metric) {
	cached, progressTrusted := mc.cachedOrCollect()
	mc.backgroundOnce.Do(func() {
		go mc.startBackgroundCollector()
		if mc.volumeRetypeEnabled {
			go mc.startVolumeRetypePoller()
		}
	})
	for _, m := range cached {
		// Retype lifecycle state is refreshed independently every five seconds.
		// Never replay the slower full-collection snapshot for these families.
		if mc.isVolumeRetypeDescriptor(m.Desc()) {
			continue
		}
		ch <- m
	}
	// The last full Libvirt cycle owns source-health authority. If it failed,
	// retain only recent operation identity and lifecycle timestamps; a cached
	// byte cursor must not be exposed as live progress. Counters and operation
	// rows are rendered from one locked state snapshot.
	for _, metric := range mc.volumeRetypeMetricBatch(time.Now(), progressTrusted) {
		ch <- metric
	}
}
