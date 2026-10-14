package main

// Test-only adapters for internal wrappers removed from the production build.
// These connect focused regression tests to the implementation
// without carrying test seams in the exporter binary.

import (
	"bytes"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/digitalocean/go-libvirt"
	"github.com/prometheus/client_golang/prometheus"
)

func (cm *ConntrackManager) aggregateConntrackOnePassFamilies(
	flowsV4 []ConntrackFlowLite,
	flowsV6 []ConntrackFlowLite,
	vmIPs []VMIPIdentity,
	tm *ThreatManager,
) *ConntrackAgg {
	agg, consumeOne := cm.newConntrackAggregator(vmIPs, tm)
	for _, flow := range flowsV4 {
		consumeOne(flow)
	}
	for _, flow := range flowsV6 {
		consumeOne(flow)
	}
	agg.ObservationUnix = cm.conntrackNow().Unix()
	agg.ObservationTimeSet = true
	return agg
}

func appendConstMetric(metrics *[]prometheus.Metric, desc *prometheus.Desc, valueType prometheus.ValueType, value float64, labels ...string) {
	*metrics = append(*metrics, prometheus.MustNewConstMetric(desc, valueType, value, labels...))
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

func (im *InstanceManager) calculateCPUUsage(totalCPUTime, stealTime, waitTime uint64, uuid string, vcpuCount int) (float64, float64, float64, bool) {
	return im.calculateCPUUsageWithAvailability(totalCPUTime, stealTime, waitTime, true, true, uuid, vcpuCount)
}

func (im *InstanceManager) calculateCPUUsageWithAvailability(totalCPUTime, stealTime, waitTime uint64, stealPresent, waitPresent bool, uuid string, vcpuCount int) (float64, float64, float64, bool) {
	usage, steal, wait, usageValid, _, _ := im.calculateCPUUsageWithDetailedAvailabilityAt(
		totalCPUTime, stealTime, waitTime,
		stealPresent, waitPresent,
		uuid, vcpuCount,
		time.Now(),
	)
	return usage, steal, wait, usageValid
}

func (im *InstanceManager) calculateDiskIO(key string, rdReq, wrReq uint64, rdBytes, wrBytes uint64, rdTime, wrTime uint64, flReq, flTime uint64, now time.Time) (float64, float64, float64, float64, float64, float64, float64, float64, float64, float64, bool) {
	rdIOPS, wrIOPS, rdLat, wrLat, flIOPS, flLat, avgIOSize, rwReqDelta, flReqDelta, bwBytesPerSec, rwValid, flushValid := im.calculateDiskIOWithAvailability(
		key, rdReq, wrReq, rdBytes, wrBytes, rdTime, wrTime, flReq, flTime, true, true, now,
	)
	return rdIOPS, wrIOPS, rdLat, wrLat, flIOPS, flLat, avgIOSize, rwReqDelta, flReqDelta, bwBytesPerSec, rwValid && flushValid
}

func (im *InstanceManager) calculateMemRates(uuid string, swapIn, swapOut, majorFault, minorFault uint64, now time.Time) (swapInRate, swapOutRate, majorFaultRate float64, valid bool) {
	swapInRate, swapOutRate, majorFaultRate, swapInValid, swapOutValid, majorValid := im.calculateMemRatesWithAvailability(
		uuid, swapIn, swapOut, majorFault, minorFault, true, true, true, true, now,
	)
	return swapInRate, swapOutRate, majorFaultRate, swapInValid && swapOutValid && majorValid
}

func (im *InstanceManager) calculateNetRates(uuid string, rxPkts, txPkts, rxDrop, txDrop uint64, now time.Time) (pps float64, dropRate float64, dropsPerSec float64, valid bool) {
	return im.calculateNetRatesForInterfaceSet(uuid, "", rxPkts, txPkts, rxDrop, txDrop, now)
}

func (im *InstanceManager) calculateNetRatesForInterfaceSet(uuid, interfaceSet string, rxPkts, txPkts, rxDrop, txDrop uint64, now time.Time) (pps float64, dropRate float64, dropsPerSec float64, valid bool) {
	idx := shardIndex(uuid)
	im.netMu[idx].Lock()
	if im.netSamples[idx] == nil {
		im.netSamples[idx] = make(map[string]netSample)
	}
	prev, ok := im.netSamples[idx][uuid]
	im.netSamples[idx][uuid] = netSample{
		rxPkts:       rxPkts,
		txPkts:       txPkts,
		rxDrop:       rxDrop,
		txDrop:       txDrop,
		interfaceSet: interfaceSet,
		ts:           now,
	}
	im.netMu[idx].Unlock()

	if !ok {
		return 0, 0, 0, false
	}
	if prev.interfaceSet != interfaceSet {
		return 0, 0, 0, false
	}

	_, elapsed, intervalValid := im.validResourceSampleInterval(prev.ts, now)
	if !intervalValid {
		return 0, 0, 0, false
	}
	if rxPkts < prev.rxPkts || txPkts < prev.txPkts || rxDrop < prev.rxDrop || txDrop < prev.txDrop {
		return 0, 0, 0, false
	}

	delta := func(curr, prev uint64) float64 {
		return float64(curr - prev)
	}

	dPkts := delta(rxPkts, prev.rxPkts) + delta(txPkts, prev.txPkts)
	dDrops := delta(rxDrop, prev.rxDrop) + delta(txDrop, prev.txDrop)

	pps = dPkts / elapsed
	dropsPerSec = dDrops / elapsed
	if dPkts+dDrops > 0 {
		dropRate = dDrops / (dPkts + dDrops)
	}
	return pps, dropRate, dropsPerSec, true
}

func (im *InstanceManager) calculateNetRatesForInterfaces(uuid string, interfaces map[string]netDeviceCounters, now time.Time) (pps float64, dropRate float64, dropsPerSec float64, valid bool) {
	interfaceNames := make([]string, 0, len(interfaces))
	for name := range interfaces {
		interfaceNames = append(interfaceNames, name)
	}
	sort.Strings(interfaceNames)
	return im.calculateNetRatesForInterfacesWithIdentity(uuid, strings.Join(interfaceNames, "\x00"), interfaces, now)
}

func checkLibvirtRuntimeJobXML(data []byte, dom libvirt.Domain) error {
	return checkLibvirtRuntimeJobXMLMode(data, dom, false)
}

func clampInt01To100(value int) int {
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	return value
}

func (cm *ConntrackManager) classifyBehavior(feature BehaviorFeature, hostImpact float64, anoms behaviorAnomalies, dstPortCounts map[uint16]int) behaviorClassification {
	return cm.classifyBehaviorWithRuleContext(feature, hostImpact, anoms, &RuleCtx{DstPortCounts: dstPortCounts})
}

func (cm *ConntrackManager) cleanupBehaviorMaps(activeSet map[string]struct{}) {
	cm.cleanupBehaviorMapsWithAging(activeSet, false)
}

func (cm *ConntrackManager) cleanupBehaviorState(activeSet map[string]struct{}) {
	cm.cleanupBehaviorStateWithAging(activeSet, false)
}

func (mc *MetricsCollector) cleanupCaches(activeSet map[string]struct{}) float64 {
	return mc.cleanupCachesWithConntrackAging(activeSet, false)
}

func (tm *ThreatManager) cleanupThreatLastHitWithConntrackFreeze(freezeConntrack bool) {
	tm.cleanupThreatLastHitWithFrozenInstances(freezeConntrack, nil)
}

func clearBehaviorRuleLogStateForIdentity(identity behaviorIdentityKey) int {
	if identity.InstanceUUID == "" {
		return 0
	}
	key := behaviorEmitKey(identity)
	behaviorRuleLogMu.Lock()
	defer behaviorRuleLogMu.Unlock()
	if _, exists := behaviorRuleLogStateMap[key]; !exists {
		return 0
	}
	delete(behaviorRuleLogStateMap, key)
	return 1
}

func (mc *MetricsCollector) collectDomainCPUMetrics(
	stat *ParsedStats,
	domain, serverName, instanceUUID, projectUUID, projectName, userUUID string,
	vcpuCount int,
	telemetryFresh bool,
	dynamicMetrics *[]prometheus.Metric,
) (float64, bool) {
	usage, available, _ := mc.collectDomainCPUMetricsWithSources(
		stat,
		time.Now(),
		domain, serverName, instanceUUID, projectUUID, projectName, userUUID,
		vcpuCount,
		telemetryFresh,
		dynamicMetrics,
	)
	return usage, available
}

func (mc *MetricsCollector) collectDomainDiskMetrics(
	meta *DomainStatic,
	stat *ParsedStats,
	now time.Time,
	domain, serverName, instanceUUID, projectUUID, projectName, userUUID string,
	telemetryFresh bool,
	dynamicMetrics *[]prometheus.Metric,
) (int, bool) {
	diskCount, available, _, _, _ := mc.collectDomainDiskMetricsWithSources(
		meta,
		stat,
		now,
		domain, serverName, instanceUUID, projectUUID, projectName, userUUID,
		telemetryFresh,
		dynamicMetrics,
	)
	return diskCount, available
}

func (mc *MetricsCollector) collectDomainMemoryMetrics(
	stat *ParsedStats,
	now time.Time,
	domain, serverName, instanceUUID, projectUUID, projectName, userUUID string,
	instanceRunning bool,
	memMB int,
	telemetryFresh bool,
	dynamicMetrics *[]prometheus.Metric,
) (float64, bool, bool) {
	guestUsedMB, guestUsedAvailable, memAvailable, _ := mc.collectDomainMemoryMetricsWithSources(
		stat,
		now,
		domain, serverName, instanceUUID, projectUUID, projectName, userUUID,
		instanceRunning,
		memMB,
		telemetryFresh,
		dynamicMetrics,
	)
	return guestUsedMB, guestUsedAvailable, memAvailable
}

func (mc *MetricsCollector) collectDomainNetworkAndConntrack(
	meta *DomainStatic,
	stat *ParsedStats,
	now time.Time,
	domain, serverName, instanceUUID, projectUUID, projectName, userUUID string,
	instanceRunning bool,
	fixedIPs []IP,
	connAgg *ConntrackAgg,
	ipSet map[string]struct{},
	hostIPs map[string]struct{},
	hostConntrackMax uint64,
	conntrackFresh bool,
	libvirtFresh bool,
	dynamicMetrics *[]prometheus.Metric,
) (float64, float64, int, bool, bool) {
	netPPS, netDropRate, maxConntrackFlows, netRatesAvailable, conntrackAvailable, _, _ := mc.collectDomainNetworkAndConntrackWithSources(
		meta,
		stat,
		now,
		domain, serverName, instanceUUID, projectUUID, projectName, userUUID,
		instanceRunning,
		fixedIPs,
		connAgg,
		ipSet,
		hostIPs,
		hostConntrackMax,
		conntrackFresh,
		libvirtFresh,
		dynamicMetrics,
	)
	return netPPS, netDropRate, maxConntrackFlows, netRatesAvailable, conntrackAvailable
}

func (mc *MetricsCollector) collectDomainStatsParallel(domainStats []libvirt.DomainStatsRecord, connAgg *ConntrackAgg, hostIPMap map[string]struct{}, ctMax uint64, ctMaxAvailable bool, conntrackFresh bool, libvirtFresh bool) *hostAgg {
	return mc.collectDomainStatsParallelInternal(domainStats, nil, connAgg, hostIPMap, ctMax, ctMaxAvailable, conntrackFresh, libvirtFresh)
}

func copyPortNameMap(in map[uint16]string) map[uint16]string {
	out := make(map[uint16]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func effectiveDomainVCPUCount(configured int, stat *ParsedStats) int {
	if stat != nil && stat.VcpuCurrentPresent && stat.VcpuCurrent > 0 && stat.VcpuCurrent <= uint64(^uint(0)>>1) {
		return int(stat.VcpuCurrent)
	}
	if configured > 0 {
		return configured
	}
	if stat != nil {
		return len(stat.Vcpus)
	}
	return 0
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

func (im *InstanceManager) ensureInstanceResourceGeneration(instanceUUID string, domainID int32) bool {
	return im.observeInstanceResourceGenerationWithToken(instanceUUID, domainID, 0, false, "", false)
}

func (mc *MetricsCollector) getHostCPUPercent() float64 {
	value, _ := mc.getHostCPUPercentWithAvailability()
	return value
}

func (mc *MetricsCollector) getHostMemInfo() (freeMB, availMB float64) {
	freeMB, availMB, _, _ = mc.getHostMemInfoWithAvailability()
	return freeMB, availMB
}

func (im *InstanceManager) getVMIPIndexSnapshot() (map[IPKey]struct{}, map[IPKey]string) {
	im.vmIPIndexMu.RLock()

	setCopy := make(map[IPKey]struct{}, len(im.vmIPSet))
	for k := range im.vmIPSet {
		setCopy[k] = struct{}{}
	}

	mapCopy := make(map[IPKey]string, len(im.vmIPToInstance))
	for k, v := range im.vmIPToInstance {
		mapCopy[k] = v
	}

	im.vmIPIndexMu.RUnlock()
	return setCopy, mapCopy
}

func hostTotalMemBytes() uint64 {
	value, _ := hostTotalMemBytesWithAvailability()
	return value
}

func isInfrastructureKey(k IPKey, hostIPKeys map[IPKey]struct{}) bool {
	if hostIPKeys != nil {
		if _, ok := hostIPKeys[k]; ok {
			return true
		}
	}
	if isIPv4MappedKey(k) {
		if k[12] == 169 && k[13] == 254 {
			return true
		}
		return false
	}
	if k[0] == 0xfe && (k[1]&0xc0) == 0x80 {
		return true
	}
	return false
}

func isPrivateOrLocalStr(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	return isPrivateOrLocal(ip)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func minRemoteCountEntry(in map[IPKey]int) (IPKey, int, bool) {
	var victim IPKey
	victimCount := 0
	set := false
	for k, count := range in {
		if !set || count < victimCount || (count == victimCount && bytes.Compare(k[:], victim[:]) < 0) {
			victim = k
			victimCount = count
			set = true
		}
	}
	return victim, victimCount, set
}

func (cm *ConntrackManager) readConntrack() ([]ConntrackFlowLite, []ConntrackFlowLite, error) {
	if !cm.conntrackIPv4Enable && !cm.conntrackIPv6Enable {
		atomic.StoreUint64(&cm.conntrackRawOK, 0)
		return nil, nil, errConntrackFamiliesDisabled
	}

	var (
		v4    []ConntrackFlowLite
		v6    []ConntrackFlowLite
		errV4 error
		errV6 error
		wg    sync.WaitGroup
	)

	dump := func(enabled bool, family int, out *[]ConntrackFlowLite, errp *error) {
		if !enabled {
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			var parseErrs, enobufs uint64
			_, parseErrs, enobufs, *errp = conntrackDumpFamilyLiteConsume(family, cm.conntrackRawRcvBufBytes, cm.conntrackNetlinkRecvTimeout, func(flow ConntrackFlowLite) {
				*out = append(*out, flow)
			})
			if parseErrs > 0 {
				atomic.AddUint64(&cm.conntrackRawParseErrorsTotal, parseErrs)
			}
			if enobufs > 0 {
				atomic.AddUint64(&cm.conntrackRawENOBUFSTotal, enobufs)
			}
		}()
	}

	dump(cm.conntrackIPv4Enable, syscall.AF_INET, &v4, &errV4)
	dump(cm.conntrackIPv6Enable, syscall.AF_INET6, &v6, &errV6)
	wg.Wait()

	readErr := newConntrackAggregateError(cm.conntrackIPv4Enable, cm.conntrackIPv6Enable, errV4, errV6)
	if readErr != nil {
		atomic.StoreUint64(&cm.conntrackRawOK, 0)
		if readErr.Partial {
			if cm.conntrackIPv4Enable && errV4 != nil {
				logKV(LogLevelNotice, "metric", "conntrack", "conntrack_raw_partial_failure", "family", "v4", "err", errV4)
			}
			if cm.conntrackIPv6Enable && errV6 != nil {
				logKV(LogLevelNotice, "metric", "conntrack", "conntrack_raw_partial_failure", "family", "v6", "err", errV6)
			}
		}
		return nil, nil, readErr
	}

	atomic.StoreUint64(&cm.conntrackRawOK, 1)
	atomic.StoreInt64(&cm.conntrackLastSuccessUnix, cm.conntrackNow().Unix())
	return v4, v6, nil
}

func (mc *MetricsCollector) resetResourceV2(instanceUUID string) {
	mc.resourceV2Mu.Lock()
	if mc.resourceV2 != nil {
		delete(mc.resourceV2, instanceUUID)
	}
	mc.resourceV2Mu.Unlock()
}

func (mc *MetricsCollector) runCollectionCycle() []prometheus.Metric {
	metrics, _ := mc.runCollectionCycleWithLibvirtHealth()
	return metrics
}

func (im *InstanceManager) setActiveInstances(activeSet map[string]struct{}) {
	im.activeInstancesMu.Lock()
	im.activeInstances = activeSet
	im.activeInstancesMu.Unlock()
}

func shiftBehaviorRuleLogStateForIdentity(identity behaviorIdentityKey, delta int64) int {
	if identity.InstanceUUID == "" || delta <= 0 {
		return 0
	}
	behaviorRuleLogMu.Lock()
	defer behaviorRuleLogMu.Unlock()
	return shiftBehaviorRuleLogStateLocked(func(key behaviorEmitKey) bool {
		return key.InstanceUUID == identity.InstanceUUID && key.IP == identity.IP && key.Direction == identity.Direction
	}, delta)
}

func (im *InstanceManager) snapshotActiveInstances() map[string]struct{} {
	im.activeInstancesMu.RLock()
	defer im.activeInstancesMu.RUnlock()
	out := make(map[string]struct{}, len(im.activeInstances))
	for k := range im.activeInstances {
		out[k] = struct{}{}
	}
	return out
}

func topPortIs(feature BehaviorFeature, ports ...uint16) bool {
	p := feature.TopDstPort
	for _, x := range ports {
		if p == x {
			return true
		}
	}
	return false
}

func (b *behaviorStats) updateDetailed(remote IPKey, port uint16, proto uint8, status uint32, zone uint16, bytes uint64, packets uint64) {
	b.updateDetailedWithCoverage(remote, port, proto, status, zone, bytes, packets, b.trackAcct, b.trackAcct)
}

func (mc *MetricsCollector) volumeRetypeCachedFallbackMetrics(now time.Time) []prometheus.Metric {
	// A failed Libvirt cycle cannot validate a prior byte cursor. Preserve only
	// recently confirmed active-job identity and lifecycle timestamps, omit
	// per-job progress and query-health observations that are not currently
	// trustworthy, then let the normal freshness bound remove the identity.
	return mc.volumeRetypeMetricsForMetricState(now, false, mc.volumeRetypeMetricStateSnapshot())
}

func (mc *MetricsCollector) volumeRetypeMetrics(now time.Time) []prometheus.Metric {
	return mc.volumeRetypeMetricsForMetricState(now, true, mc.volumeRetypeMetricStateSnapshot())
}

func (mc *MetricsCollector) volumeRetypeResultMetrics() []prometheus.Metric {
	return mc.volumeRetypeResultMetricsForState(mc.volumeRetypeMetricStateSnapshot())
}
