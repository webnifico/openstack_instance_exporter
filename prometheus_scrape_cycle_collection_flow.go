package main

import (
	"errors"
	"fmt"
	libvirt "github.com/digitalocean/go-libvirt"
	"github.com/prometheus/client_golang/prometheus"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	_domainStatsState                   = 1
	_domainStatsCpuTotal                = 2
	_domainStatsBalloon                 = 4
	_domainStatsVcpu                    = 8
	_domainStatsInterface               = 16
	_domainStatsBlock                   = 32
	_connectGetAllDomainStatsActiveOnly = 1
	_connectGetAllDomainStatsInactive   = 2
)

func (mc *MetricsCollector) collectHeavy(ch chan<- prometheus.Metric) {
	cycleStart := time.Now()
	cycleID := atomic.AddUint64(&mc.cycleSeq, 1)
	lagSeconds := mc.collectionLagSeconds()
	conntrackConfigured := mc.cm.conntrackIPv4Enable || mc.cm.conntrackIPv6Enable

	logCollectorMetric.Debug("scrapetime_collection_start", "cycle_id", cycleID, "lag_seconds", lagSeconds)

	// The fast retype poller shares this Libvirt connection. Keep the complete
	// stats, metadata, and retype RPC phase exclusive so a bounded retype
	// timeout cannot close the connection underneath unrelated collection work.
	mc.volumeRetypeLibvirtWorkMu.Lock()
	domainStats, libvirtSeconds, errLibvirt := mc.fetchDomainStatsForCycle()
	var prepared *preparedLibvirtCycle
	if errLibvirt == nil {
		prepared, errLibvirt = mc.prepareLibvirtCycle(domainStats)
		if errLibvirt != nil {
			errLibvirt = fmt.Errorf("complete Libvirt cycle preflight: %w", errLibvirt)
			mc.discardLibvirtConnection()
		}
	}
	if errLibvirt == nil {
		mc.applyPreparedRuntimeGenerations(domainStats, prepared)
		mc.commitPreparedLibvirtCycle(prepared)
		mc.refreshVolumeRetypes(activeDomainRecords(domainStats), prepared.metadata)
	}
	mc.volumeRetypeLibvirtWorkMu.Unlock()

	if errLibvirt != nil {
		atomic.AddUint64(&mc.hostCollectionErrors, 1)
		logCollectorMetric.Error("domain_stats_failed", "cycle_id", cycleID, "err", errLibvirt)
		if conntrackConfigured {
			mc.cm.beginBehaviorStateFreeze(cycleStart)
		}
		cycleEnd := time.Now()
		if mc.emitCachedMetricsWithLiveHealth(ch, cycleEnd.Sub(cycleStart).Seconds(), lagSeconds, libvirtSeconds) {
			atomic.StoreInt64(&mc.lastCycleEndUnixNano, cycleEnd.UnixNano())
			logCollectorMetric.Notice("collection_degraded", "cycle_id", cycleID, "stage", "libvirt", "fallback", "last_good_metric_cycle", "impact", "all previously valid metrics preserved", "err", errLibvirt)
			logCollectorMetric.Debug("scrapetime_collection_end", "cycle_id", cycleID, "duration_seconds", cycleEnd.Sub(cycleStart).Seconds())
			return
		}
		mc.emitHostAndAggMetrics(
			ch,
			nil,
			&hostAgg{projects: make(map[string]struct{})},
			lagSeconds,
			libvirtSeconds,
			0,
			0,
			0,
			0,
			0,
			cycleEnd.Sub(cycleStart).Seconds(),
			false,
			false,
			false,
		)
		atomic.StoreInt64(&mc.lastCycleEndUnixNano, cycleEnd.UnixNano())
		logCollectorMetric.Notice("collection_degraded", "cycle_id", cycleID, "stage", "libvirt", "fallback", "unavailable", "impact", "Libvirt-dependent metrics omitted", "err", errLibvirt)
		logCollectorMetric.Debug("scrapetime_collection_end", "cycle_id", cycleID, "duration_seconds", cycleEnd.Sub(cycleStart).Seconds())
		return
	}
	inventoryMetrics := mc.inventoryMetricBatch(domainStats, prepared.metadata)
	domainStats = activeDomainRecords(domainStats)
	logCollectorMetric.Debug("domain_stats_success", "cycle_id", cycleID, "active_domains", len(domainStats))

	activeSet := prepared.activeSet
	mc.cm.beginBehaviorLifecycleFreezesForMissingStates(domainStats, cycleStart)

	vmIPs := mc.im.snapshotVMIPIdentities(activeSet)
	mc.cm.pruneBehaviorStateToVMIPIdentities(activeSet, vmIPs)
	ovnPortToInstance := mc.im.snapshotOVNPortToInstance(activeSet)
	ovnPortToIPs := mc.im.snapshotOVNPortToIPKeys(activeSet)

	hostIPMap := mc.buildHostIPMap()

	var (
		cacheCleanupSeconds float64
		conntrackSeconds    float64
		ctCount             int
		errConntrack        error
		connAgg             *ConntrackAgg
		wg                  sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		cStart := time.Now()
		if conntrackConfigured && mc.cm.ovnMapper != nil && len(ovnPortToInstance) > 0 {
			if err := mc.cm.ovnMapper.Refresh(ovnPortToInstance, ovnPortToIPs); err != nil {
				logConntrackMetric.Error("ovn_refresh_failed", "err", err)
			}
			staleAfter := 2 * mc.collectionInterval
			if staleAfter < time.Minute {
				staleAfter = time.Minute
			}
			if mc.cm.ovnMapper.IsStale(time.Now(), staleAfter) {
				logConntrackMetric.Notice("ovn_mapping_stale", "last_success", mc.cm.ovnMapper.LastRefresh(), "stale_after", staleAfter)
			}
		}
		connAgg, ctCount, errConntrack = mc.cm.readAndAggregateConntrack(vmIPs, mc.tm)
		conntrackSeconds = time.Since(cStart).Seconds()
	}()
	wg.Wait()

	conntrackDisabled := errors.Is(errConntrack, errConntrackFamiliesDisabled)
	if errConntrack != nil && !conntrackDisabled {
		atomic.AddUint64(&mc.hostCollectionErrors, 1)
		atomic.AddUint64(&mc.cm.conntrackReadErrors, 1)
		logConntrackMetric.Error("conntrack_read_failed", "cycle_id", cycleID, "ct_entries", ctCount, "err", errConntrack)

		var aggErr *conntrackAggregateError
		if lastGood, lastCount, ok := mc.cm.snapshotLastGoodConntrack(); ok {
			connAgg = lastGood
			ctCount = lastCount
			logConntrackMetric.Notice("collection_degraded", "cycle_id", cycleID, "stage", "conntrack", "fallback", "last_good_conntrack_agg", "impact", "conntrack metrics retained from the last complete dump", "partial", errors.As(errConntrack, &aggErr) && aggErr.Partial, "err", errConntrack)
		} else {
			logConntrackMetric.Notice("collection_degraded", "cycle_id", cycleID, "stage", "conntrack", "fallback", "unavailable", "impact", "per-vm network attribution unavailable", "err", errConntrack)
			connAgg = nil
			ctCount = 0
		}
	}
	conntrackFresh := errConntrack == nil && !conntrackDisabled
	conntrackAvailable := conntrackFresh || connAgg != nil
	freezeConntrackAging := conntrackConfigured && !conntrackFresh
	if conntrackConfigured {
		if conntrackFresh {
			recoveryNow := conntrackObservationTime(connAgg, time.Now())
			outageDelta := mc.cm.resumeBehaviorStateClock(recoveryNow)
			mc.tm.shiftThreatEventClock(outageDelta)
			mc.shiftIntelHistoryClock(outageDelta)
		} else {
			mc.cm.beginBehaviorStateFreeze(cycleStart)
		}
	}
	cacheCleanupSeconds = mc.cleanupCachesWithConntrackAging(activeSet, freezeConntrackAging)

	ctMax, ctMaxAvailable := hostConntrackMaxWithAvailability()
	var ctUtil float64
	if ctMaxAvailable {
		ctUtil = float64(ctCount) / float64(ctMax)
	}

	agg := mc.collectDomainStatsParallelPrepared(domainStats, prepared.metadata, connAgg, hostIPMap, ctMax, ctMaxAvailable, conntrackFresh)
	agg.metrics = append(agg.metrics, inventoryMetrics...)
	mc.cm.finishBehaviorRecoveryRebaseline()

	cycleEnd := time.Now()
	cycleSeconds := cycleEnd.Sub(cycleStart).Seconds()

	mc.emitHostAndAggMetrics(
		ch,
		domainStats,
		agg,
		lagSeconds,
		libvirtSeconds,
		conntrackSeconds,
		cacheCleanupSeconds,
		ctCount,
		ctMax,
		ctUtil,
		cycleSeconds,
		true,
		conntrackAvailable,
		ctMaxAvailable,
	)

	summaryArgs := []interface{}{
		"cycle_id", cycleID,
		"duration_seconds", cycleSeconds,
		"lag_seconds", lagSeconds,
		"libvirt_ok", true,
		"libvirt_duration_seconds", libvirtSeconds,
		"active_domains", len(domainStats),
		"active_instances", len(activeSet),
		"vm_ip_identities", len(vmIPs),
		"conntrack_ok", conntrackFresh,
		"conntrack_duration_seconds", conntrackSeconds,
		"conntrack_entries", ctCount,
		"conntrack_max", ctMax,
		"conntrack_max_available", ctMaxAvailable,
		"conntrack_utilization", ctUtil,
		"cache_cleanup_seconds", cacheCleanupSeconds,
		"degraded", errConntrack != nil && !conntrackDisabled,
	}
	degradedStages := make([]string, 0, 1)
	if errConntrack != nil && !conntrackDisabled {
		degradedStages = append(degradedStages, "conntrack")
		summaryArgs = append(summaryArgs, "conntrack_err", errConntrack)
	}
	if len(degradedStages) > 0 {
		summaryArgs = append(summaryArgs, "degraded_stages", strings.Join(degradedStages, ","))
	}
	logCollectorMetric.Debug("collection_cycle_summary", summaryArgs...)

	atomic.StoreInt64(&mc.lastCycleEndUnixNano, cycleEnd.UnixNano())
	logCollectorMetric.Debug("scrapetime_collection_end", "cycle_id", cycleID, "duration_seconds", cycleSeconds)
}

func (mc *MetricsCollector) collectionLagSeconds() float64 {
	prevEnd := atomic.LoadInt64(&mc.lastCycleEndUnixNano)
	if prevEnd <= 0 {
		return 0
	}
	lagDur := time.Since(time.Unix(0, prevEnd)).Seconds()
	if lagDur <= 0 {
		return 0
	}
	return lagDur
}

func (mc *MetricsCollector) fetchDomainStats() ([]libvirt.DomainStatsRecord, float64, error) {
	lStart := time.Now()
	mc.pendingRuntimeTokens = nil
	mc.pendingDomainMetadata = nil

	conn, err := mc.getLibvirtConn()
	if err != nil {
		return nil, time.Since(lStart).Seconds(), err
	}
	// Synthetic RPC overrides intentionally bypass host-process validation.
	// Production collection brackets the complete Libvirt stats+metadata
	// snapshot with a collision-resistant local QEMU process incarnation map.
	if mc.libvirtStatsRPCOverride == nil || mc.qemuProcessSnapshotOverride != nil {
		before, snapshotErr := mc.snapshotQEMUProcessIncarnations()
		if snapshotErr != nil {
			return nil, time.Since(lStart).Seconds(), fmt.Errorf("QEMU process incarnation preflight: %w", snapshotErr)
		}
		mc.pendingRuntimeTokens = before
	}

	type statsResult struct {
		records  []libvirt.DomainStatsRecord
		metadata map[string]*DomainStatic
		err      error
	}
	resultCh := make(chan statsResult, 1)
	go func() {
		if mc.libvirtStatsRPCOverride != nil {
			records, rpcErr := mc.libvirtStatsRPCOverride(conn)
			resultCh <- statsResult{records: records, err: rpcErr}
			return
		}
		records, metadata, rpcErr := collectCooperativeDomainStats(conn, mc.libvirtSafety, time.Now().Add(mc.effectiveLibvirtRPCTimeout()))
		resultCh <- statsResult{records: records, metadata: metadata, err: rpcErr}
	}()
	timeout := mc.effectiveLibvirtRPCTimeout()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	var result statsResult
	select {
	case result = <-resultCh:
	case <-timer.C:
		mc.libvirtSafety.pause(time.Now())
		mc.abortLibvirtConnection(conn)
		return nil, time.Since(lStart).Seconds(), fmt.Errorf("Libvirt domain stats RPC timed out after %s", timeout)
	}
	domainStats, errLibvirt := result.records, result.err
	if errLibvirt == nil {
		mc.pendingDomainMetadata = result.metadata
	}

	if errLibvirt != nil {
		mc.abortLibvirtConnection(conn)
	}

	libvirtSeconds := time.Since(lStart).Seconds()
	return domainStats, libvirtSeconds, errLibvirt
}

func (mc *MetricsCollector) fetchDomainStatsForCycle() ([]libvirt.DomainStatsRecord, float64, error) {
	mc.pendingRuntimeTokens = nil
	mc.pendingDomainMetadata = nil
	if mc.fetchDomainStatsOverride != nil {
		return mc.fetchDomainStatsOverride()
	}
	return mc.fetchDomainStats()
}

func (mc *MetricsCollector) discardLibvirtConnection() {
	mc.libvirtMu.Lock()
	conn := mc.libvirtConn
	mc.libvirtMu.Unlock()
	mc.abortLibvirtConnection(conn)
}

func (mc *MetricsCollector) abortLibvirtConnection(conn *libvirt.Libvirt) {
	if mc == nil || conn == nil {
		return
	}
	mc.libvirtMu.Lock()
	if mc.libvirtConn != conn {
		mc.libvirtMu.Unlock()
		return
	}
	dialer := mc.libvirtDialer
	mc.libvirtConn = nil
	mc.libvirtDialer = nil
	mc.libvirtMu.Unlock()
	if dialer != nil {
		_ = dialer.Close()
	}
}

func (mc *MetricsCollector) buildActiveAndVMIPSets(domainStats []libvirt.DomainStatsRecord) (map[string]struct{}, map[IPKey]struct{}, map[IPKey]string) {
	activeSet := make(map[string]struct{}, len(domainStats))

	mc.libvirtMu.Lock()
	preScanConn := mc.libvirtConn
	mc.libvirtMu.Unlock()

	if preScanConn != nil && len(domainStats) > 0 {
		numWorkers := effectiveDomainWorkerCount(mc.im.workerCount)

		jobs := make(chan libvirt.Domain, len(domainStats))
		var wg sync.WaitGroup
		for i := 0; i < numWorkers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for dom := range jobs {
					_, _ = mc.im.getDomainMeta(dom, preScanConn)
				}
			}()
		}

		for _, stat := range domainStats {
			uuidBytes := stat.Dom.UUID
			uuid := uuidBytesToString(uuidBytes[:])
			if uuid == "" {
				continue
			}

			activeSet[uuid] = struct{}{}
			jobs <- stat.Dom
		}

		close(jobs)
		wg.Wait()
	} else {
		for _, stat := range domainStats {
			uuidBytes := stat.Dom.UUID
			uuid := uuidBytesToString(uuidBytes[:])
			if uuid == "" {
				continue
			}

			activeSet[uuid] = struct{}{}
		}
	}

	vmIPSet, vmIPToInstance := mc.im.getVMIPIndexSnapshot()
	return activeSet, vmIPSet, vmIPToInstance
}

func (mc *MetricsCollector) buildHostIPMap() map[string]struct{} {
	if mc.tm == nil {
		return map[string]struct{}{}
	}
	hostIPs := mc.tm.getBehaviorHostIPs()
	hostIPMap := make(map[string]struct{}, len(hostIPs))
	for _, hip := range hostIPs {
		hostIPMap[hip.Address] = struct{}{}
	}
	return hostIPMap
}

func (mc *MetricsCollector) cleanupCaches(activeSet map[string]struct{}) float64 {
	return mc.cleanupCachesWithConntrackAging(activeSet, false)
}

func (mc *MetricsCollector) cleanupCachesWithConntrackAging(activeSet map[string]struct{}, freezeConntrackAging bool) float64 {
	cleanupStart := time.Now()
	mc.im.cleanupDomainMeta()
	mc.im.cleanupResourceSamples()
	mc.cleanupResourceV2(activeSet)
	mc.cm.cleanupBehaviorMapsWithAging(activeSet, freezeConntrackAging)
	mc.cm.cleanupBehaviorStateWithAging(activeSet, freezeConntrackAging)
	mc.tm.cleanupThreatCounts(activeSet)
	mc.tm.cleanupThreatLastHitWithFrozenInstances(freezeConntrackAging, mc.cm.snapshotBehaviorFrozenInstances())
	mc.cleanupIntelHistory(activeSet)
	return time.Since(cleanupStart).Seconds()
}

func (mc *MetricsCollector) cleanupIntelHistory(activeSet map[string]struct{}) {
	mc.intelMu.Lock()
	for instanceUUID := range mc.intelHistory {
		if _, ok := activeSet[instanceUUID]; !ok {
			delete(mc.intelHistory, instanceUUID)
		}
	}
	mc.intelMu.Unlock()
}

func (mc *MetricsCollector) collectDomainStatsParallel(domainStats []libvirt.DomainStatsRecord, connAgg *ConntrackAgg, hostIPMap map[string]struct{}, ctMax uint64, ctMaxAvailable bool, conntrackFresh bool, libvirtFresh bool) *hostAgg {
	return mc.collectDomainStatsParallelInternal(domainStats, nil, connAgg, hostIPMap, ctMax, ctMaxAvailable, conntrackFresh, libvirtFresh)
}

func (mc *MetricsCollector) collectDomainStatsParallelPrepared(domainStats []libvirt.DomainStatsRecord, metadata map[string]*DomainStatic, connAgg *ConntrackAgg, hostIPMap map[string]struct{}, ctMax uint64, ctMaxAvailable bool, conntrackFresh bool) *hostAgg {
	return mc.collectDomainStatsParallelInternal(domainStats, metadata, connAgg, hostIPMap, ctMax, ctMaxAvailable, conntrackFresh, true)
}

func (mc *MetricsCollector) collectDomainStatsParallelInternal(domainStats []libvirt.DomainStatsRecord, metadata map[string]*DomainStatic, connAgg *ConntrackAgg, hostIPMap map[string]struct{}, ctMax uint64, ctMaxAvailable bool, conntrackFresh bool, libvirtFresh bool) *hostAgg {
	agg := &hostAgg{projects: make(map[string]struct{})}

	if len(domainStats) == 0 {
		return agg
	}

	numWorkers := effectiveDomainWorkerCount(mc.im.workerCount)

	jobs := make(chan libvirt.DomainStatsRecord, len(domainStats))
	aggCh := make(chan *hostAgg, numWorkers)
	var wgWorkers sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		wgWorkers.Add(1)
		go func() {
			defer wgWorkers.Done()
			localAgg := &hostAgg{projects: make(map[string]struct{})}
			for stat := range jobs {
				if metadata == nil {
					mc.collectDomainMetrics(stat, connAgg, hostIPMap, localAgg, ctMax, ctMaxAvailable, conntrackFresh, libvirtFresh)
					continue
				}
				uuidBytes := stat.Dom.UUID
				instanceUUID := uuidBytesToString(uuidBytes[:])
				mc.collectDomainMetricsWithMetadata(stat, metadata[instanceUUID], connAgg, hostIPMap, localAgg, ctMax, ctMaxAvailable, conntrackFresh)
			}
			aggCh <- localAgg
		}()
	}

	for _, s := range domainStats {
		jobs <- s
	}
	close(jobs)
	wgWorkers.Wait()
	close(aggCh)

	var allAggs []*hostAgg
	metricsCap := 0
	for a := range aggCh {
		allAggs = append(allAggs, a)
		metricsCap += len(a.metrics)
	}

	agg.metrics = make([]prometheus.Metric, 0, metricsCap)

	for _, a := range allAggs {
		agg.vcpus += a.vcpus
		agg.disks += a.disks
		agg.fixedIPs += a.fixedIPs
		for p := range a.projects {
			agg.projects[p] = struct{}{}
		}
		agg.metrics = append(agg.metrics, a.metrics...)
	}

	return agg
}

func (mc *MetricsCollector) emitCachedMetrics(ch chan<- prometheus.Metric) bool {
	mc.cacheMu.RLock()
	cached := append([]prometheus.Metric(nil), mc.cachedMetrics...)
	mc.cacheMu.RUnlock()
	if len(cached) == 0 {
		return false
	}
	for _, metric := range cached {
		ch <- metric
	}
	return true
}

func (mc *MetricsCollector) emitCachedMetricsWithLiveHealth(ch chan<- prometheus.Metric, cycleSeconds, lagSeconds, libvirtSeconds float64) bool {
	healthNow := time.Now()
	mc.recordLibvirtCollectionResult(false, healthNow)
	if atomic.LoadInt64(&mc.libvirtLastSuccessUnix) <= 0 {
		return false
	}

	mc.cacheMu.RLock()
	cached := append([]prometheus.Metric(nil), mc.cachedMetrics...)
	mc.cacheMu.RUnlock()
	if len(cached) == 0 {
		return false
	}
	cached, resourceOverlay := mc.overlayCachedResourceMetrics(cached, healthNow)

	liveMetrics := make([]prometheus.Metric, 0, 32)
	liveDescs := make(map[*prometheus.Desc]struct{}, 32)
	appendLive := func(metric prometheus.Metric) {
		liveMetrics = append(liveMetrics, metric)
		liveDescs[metric.Desc()] = struct{}{}
	}
	markLive := func(desc *prometheus.Desc) {
		if desc != nil {
			liveDescs[desc] = struct{}{}
		}
	}
	for _, metric := range resourceOverlay {
		appendLive(metric)
	}

	appendLive(prometheus.MustNewConstMetric(
		mc.hostCollectionErrorsTotalDesc,
		prometheus.CounterValue,
		float64(atomic.LoadUint64(&mc.hostCollectionErrors)),
	))
	appendLive(prometheus.MustNewConstMetric(
		mc.hostCollectionCycleDurationSecondsDesc,
		prometheus.GaugeValue,
		cycleSeconds,
	))
	appendLive(prometheus.MustNewConstMetric(
		mc.hostCollectionIntervalSecondsDesc,
		prometheus.GaugeValue,
		mc.effectiveCollectionInterval().Seconds(),
	))
	appendLive(prometheus.MustNewConstMetric(
		mc.hostCollectionCycleLagSecondsDesc,
		prometheus.GaugeValue,
		lagSeconds,
	))
	appendLive(prometheus.MustNewConstMetric(
		mc.hostLibvirtListDurationSecondsDesc,
		prometheus.GaugeValue,
		libvirtSeconds,
	))
	for _, metric := range mc.libvirtSourceHealthMetrics(healthNow) {
		appendLive(metric)
	}
	if mc.im != nil {
		// Active retype state has a shorter validity window than general last-good
		// inventory. Never replay a stale progress cursor during a Libvirt outage.
		markLive(mc.im.instanceDiskRetypeActiveDesc)
		markLive(mc.im.instanceDiskRetypeProgressDesc)
		markLive(mc.im.instanceDiskRetypeStatusCodeDesc)
		markLive(mc.im.instanceDiskRetypeObservationHealthyDesc)
		markLive(mc.im.instanceDiskRetypeStartTimestampDesc)
		markLive(mc.im.instanceDiskRetypeReadyTimestampDesc)
		markLive(mc.im.instanceDiskRetypeEndTimestampDesc)
	}
	for _, metric := range mc.volumeRetypeMetricBatch(healthNow, false) {
		appendLive(metric)
	}
	appendLive(prometheus.MustNewConstMetric(
		mc.hostCacheCleanupDurationSecondsDesc,
		prometheus.GaugeValue,
		0,
	))
	conntrackHealthDescs := []*prometheus.Desc{
		mc.hostConntrackReadDurationSecondsDesc,
		mc.hostConntrackRawOkDesc,
		mc.hostConntrackRawENOBUFSTotalDesc,
		mc.hostConntrackRawParseErrorsTotalDesc,
		mc.hostConntrackReadErrorsTotalDesc,
		mc.hostConntrackLastSuccessTimestampDesc,
		mc.hostConntrackStaleSecondsDesc,
	}
	// A Libvirt failure ends the cycle before a new conntrack snapshot is read.
	// Never re-expose prior conntrack data gauges as if they belonged to this
	// degraded cycle; the independently maintained health metrics below remain
	// available to explain the source state.
	for _, desc := range []*prometheus.Desc{
		mc.hostConntrackEntriesDesc,
		mc.hostConntrackMaxDesc,
		mc.hostConntrackUtilizationDesc,
	} {
		markLive(desc)
	}
	if mc.cm.conntrackIPv4Enable || mc.cm.conntrackIPv6Enable {
		appendLive(prometheus.MustNewConstMetric(mc.hostConntrackReadDurationSecondsDesc, prometheus.GaugeValue, 0))
		appendLive(prometheus.MustNewConstMetric(mc.hostConntrackRawOkDesc, prometheus.GaugeValue, float64(atomic.LoadUint64(&mc.cm.conntrackRawOK))))
		appendLive(prometheus.MustNewConstMetric(mc.hostConntrackRawENOBUFSTotalDesc, prometheus.CounterValue, float64(atomic.LoadUint64(&mc.cm.conntrackRawENOBUFSTotal))))
		appendLive(prometheus.MustNewConstMetric(mc.hostConntrackRawParseErrorsTotalDesc, prometheus.CounterValue, float64(atomic.LoadUint64(&mc.cm.conntrackRawParseErrorsTotal))))
		appendLive(prometheus.MustNewConstMetric(mc.hostConntrackReadErrorsTotalDesc, prometheus.CounterValue, float64(atomic.LoadUint64(&mc.cm.conntrackReadErrors))))
		appendLive(prometheus.MustNewConstMetric(mc.hostConntrackLastSuccessTimestampDesc, prometheus.GaugeValue, float64(atomic.LoadInt64(&mc.cm.conntrackLastSuccessUnix))))
		appendLive(prometheus.MustNewConstMetric(mc.hostConntrackStaleSecondsDesc, prometheus.GaugeValue, mc.cm.conntrackStaleSeconds()))
	} else {
		for _, desc := range conntrackHealthDescs {
			markLive(desc)
		}
	}

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	appendLive(prometheus.MustNewConstMetric(
		mc.hostGoHeapAllocBytesDesc,
		prometheus.GaugeValue,
		float64(memStats.HeapAlloc),
	))
	hostResources := mc.readHostResourceSnapshot()
	// These optional /proc and sysinfo probes are live overlay data. Mark every
	// descriptor even when its current probe is unavailable so an old cached
	// value cannot acquire a new scrape timestamp and drive a host alert.
	for _, desc := range []*prometheus.Desc{
		mc.hostMemTotalMBDesc,
		mc.hostCpuUsagePercentDesc,
		mc.hostMemFreeMBDesc,
		mc.hostMemAvailableMBDesc,
	} {
		markLive(desc)
	}
	if hostResources.totalMemAvailable {
		appendLive(prometheus.MustNewConstMetric(
			mc.hostMemTotalMBDesc,
			prometheus.GaugeValue,
			float64(hostResources.totalMemBytes)*bytesToMegabytes,
		))
	}
	if hostResources.cpuAvailable {
		appendLive(prometheus.MustNewConstMetric(mc.hostCpuUsagePercentDesc, prometheus.GaugeValue, hostResources.cpuPercent))
	}
	if hostResources.memFreeAvailable {
		appendLive(prometheus.MustNewConstMetric(mc.hostMemFreeMBDesc, prometheus.GaugeValue, hostResources.memFreeMB))
	}
	if hostResources.memAvailAvailable {
		appendLive(prometheus.MustNewConstMetric(mc.hostMemAvailableMBDesc, prometheus.GaugeValue, hostResources.memAvailableMB))
	}

	if mc.tm != nil {
		for _, provider := range mc.tm.Providers {
			if provider == nil {
				continue
			}
			markLive(provider.HostRefreshLastSuccessDesc)
			markLive(provider.HostRefreshDurationDesc)
			markLive(provider.HostRefreshErrorsDesc)
			markLive(provider.HostEntriesDesc)
		}
		markLive(mc.tm.hostSpamhausRefreshLastSuccessTimestampDesc)
		markLive(mc.tm.hostSpamhausRefreshDurationSecondsDesc)
		markLive(mc.tm.hostSpamhausRefreshErrorsTotalDesc)
		markLive(mc.tm.hostSpamhausEntriesDesc)
		markLive(mc.tm.hostThreatFeedFreshDesc)
		markLive(mc.tm.hostThreatListedDesc)

		threatMetrics := make([]prometheus.Metric, 0, 24)
		mc.tm.collectHostThreatMetrics(&threatMetrics)
		for _, metric := range threatMetrics {
			appendLive(metric)
		}
	}

	for _, metric := range cached {
		if _, replace := liveDescs[metric.Desc()]; replace {
			continue
		}
		ch <- metric
	}
	for _, metric := range liveMetrics {
		ch <- metric
	}
	return true
}

func (mc *MetricsCollector) emitHostAndAggMetrics(
	ch chan<- prometheus.Metric,
	domainStats []libvirt.DomainStatsRecord,
	agg *hostAgg,
	lagSeconds float64,
	libvirtSeconds float64,
	conntrackSeconds float64,
	cacheCleanupSeconds float64,
	ctCount int,
	ctMax uint64,
	ctUtil float64,
	cycleSeconds float64,
	libvirtAvailable bool,
	conntrackAvailable bool,
	conntrackMaxAvailable bool,
) {
	healthNow := time.Now()
	mc.recordLibvirtCollectionResult(libvirtAvailable, healthNow)

	hostResources := mc.readHostResourceSnapshot()
	totalMemMB := float64(hostResources.totalMemBytes) * bytesToMegabytes

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	heapAllocBytes := float64(ms.HeapAlloc)

	errorsTotal := atomic.LoadUint64(&mc.hostCollectionErrors)
	conntrackErrors := atomic.LoadUint64(&mc.cm.conntrackReadErrors)

	hostMetrics := []prometheus.Metric{
		prometheus.MustNewConstMetric(mc.hostCpuThreadsDesc, prometheus.GaugeValue, float64(runtime.NumCPU())),
		prometheus.MustNewConstMetric(mc.hostCollectionErrorsTotalDesc, prometheus.CounterValue, float64(errorsTotal)),
		prometheus.MustNewConstMetric(mc.hostCollectionCycleDurationSecondsDesc, prometheus.GaugeValue, cycleSeconds),
		prometheus.MustNewConstMetric(mc.hostCollectionIntervalSecondsDesc, prometheus.GaugeValue, mc.effectiveCollectionInterval().Seconds()),
		prometheus.MustNewConstMetric(mc.hostCollectionCycleLagSecondsDesc, prometheus.GaugeValue, lagSeconds),
		prometheus.MustNewConstMetric(mc.hostLibvirtListDurationSecondsDesc, prometheus.GaugeValue, libvirtSeconds),
		prometheus.MustNewConstMetric(mc.hostGoHeapAllocBytesDesc, prometheus.GaugeValue, heapAllocBytes),
		prometheus.MustNewConstMetric(mc.hostCacheCleanupDurationSecondsDesc, prometheus.GaugeValue, cacheCleanupSeconds),
	}
	hostMetrics = append(hostMetrics, mc.libvirtSourceHealthMetrics(healthNow)...)
	if mc.cm.conntrackIPv4Enable || mc.cm.conntrackIPv6Enable {
		hostMetrics = append(hostMetrics,
			prometheus.MustNewConstMetric(mc.hostConntrackReadDurationSecondsDesc, prometheus.GaugeValue, conntrackSeconds),
			prometheus.MustNewConstMetric(mc.hostConntrackRawOkDesc, prometheus.GaugeValue, float64(atomic.LoadUint64(&mc.cm.conntrackRawOK))),
			prometheus.MustNewConstMetric(mc.hostConntrackRawENOBUFSTotalDesc, prometheus.CounterValue, float64(atomic.LoadUint64(&mc.cm.conntrackRawENOBUFSTotal))),
			prometheus.MustNewConstMetric(mc.hostConntrackRawParseErrorsTotalDesc, prometheus.CounterValue, float64(atomic.LoadUint64(&mc.cm.conntrackRawParseErrorsTotal))),
			prometheus.MustNewConstMetric(mc.hostConntrackLastSuccessTimestampDesc, prometheus.GaugeValue, float64(atomic.LoadInt64(&mc.cm.conntrackLastSuccessUnix))),
			prometheus.MustNewConstMetric(mc.hostConntrackStaleSecondsDesc, prometheus.GaugeValue, mc.cm.conntrackStaleSeconds()),
			prometheus.MustNewConstMetric(mc.hostConntrackReadErrorsTotalDesc, prometheus.CounterValue, float64(conntrackErrors)),
		)
	}
	if hostResources.totalMemAvailable {
		hostMetrics = append(hostMetrics, prometheus.MustNewConstMetric(mc.hostMemTotalMBDesc, prometheus.GaugeValue, totalMemMB))
	}
	if hostResources.cpuAvailable {
		hostMetrics = append(hostMetrics, prometheus.MustNewConstMetric(mc.hostCpuUsagePercentDesc, prometheus.GaugeValue, hostResources.cpuPercent))
	}
	if hostResources.memFreeAvailable {
		hostMetrics = append(hostMetrics, prometheus.MustNewConstMetric(mc.hostMemFreeMBDesc, prometheus.GaugeValue, hostResources.memFreeMB))
	}
	if hostResources.memAvailAvailable {
		hostMetrics = append(hostMetrics, prometheus.MustNewConstMetric(mc.hostMemAvailableMBDesc, prometheus.GaugeValue, hostResources.memAvailableMB))
	}
	if conntrackMaxAvailable {
		hostMetrics = append(hostMetrics, prometheus.MustNewConstMetric(mc.hostConntrackMaxDesc, prometheus.GaugeValue, float64(ctMax)))
	}
	if libvirtAvailable {
		hostMetrics = append(hostMetrics,
			prometheus.MustNewConstMetric(mc.hostLibvirtActiveVMsDesc, prometheus.GaugeValue, float64(len(domainStats))),
			prometheus.MustNewConstMetric(mc.hostCpuActiveVcpusDesc, prometheus.GaugeValue, float64(agg.vcpus)),
			prometheus.MustNewConstMetric(mc.hostActiveDisksDesc, prometheus.GaugeValue, float64(agg.disks)),
			prometheus.MustNewConstMetric(mc.hostActiveFixedIPsDesc, prometheus.GaugeValue, float64(agg.fixedIPs)),
			prometheus.MustNewConstMetric(mc.hostActiveProjectsDesc, prometheus.GaugeValue, float64(len(agg.projects))),
		)
	}
	if conntrackAvailable {
		hostMetrics = append(hostMetrics,
			prometheus.MustNewConstMetric(mc.hostConntrackEntriesDesc, prometheus.GaugeValue, float64(ctCount)),
		)
	}
	if conntrackAvailable && conntrackMaxAvailable {
		hostMetrics = append(hostMetrics, prometheus.MustNewConstMetric(mc.hostConntrackUtilizationDesc, prometheus.GaugeValue, ctUtil))
	}

	mc.tm.collectHostThreatMetrics(&hostMetrics)

	for _, metric := range hostMetrics {
		ch <- metric
	}

	for _, metric := range agg.metrics {
		ch <- metric
	}
	for _, metric := range mc.volumeRetypeMetricBatch(healthNow, libvirtAvailable) {
		ch <- metric
	}
}
