package main

import (
	"math"
	"sort"
	"strings"
	"time"
)

func (im *InstanceManager) resolveResourceDimensions(instanceUUID string, configuredVCPU, configuredMemMB int, stat *ParsedStats) (int, bool, bool, int, bool, bool) {
	im.resourceDimensionsMu.Lock()
	defer im.resourceDimensionsMu.Unlock()
	if im.resourceDimensions == nil {
		im.resourceDimensions = make(map[string]resourceDimensions)
	}
	dimensions := im.resourceDimensions[instanceUUID]
	maxInt := uint64(^uint(0) >> 1)
	vcpuCurrent := false
	if stat != nil && stat.VcpuCurrentPresent {
		dimensions.vcpuLiveObserved = true
		if stat.VcpuCurrent > 0 && stat.VcpuCurrent <= maxInt {
			dimensions.vcpuCount = int(stat.VcpuCurrent)
			dimensions.vcpuKnown = true
			vcpuCurrent = true
		}
	} else if !dimensions.vcpuLiveObserved && configuredVCPU > 0 {
		dimensions.vcpuCount = configuredVCPU
		dimensions.vcpuKnown = true
		vcpuCurrent = true
	}
	memCurrent := false
	if stat != nil && stat.MemMaxPresent {
		dimensions.memLiveObserved = true
		if stat.MemMax >= 1024 && stat.MemMax/1024 <= maxInt {
			dimensions.memMB = int(stat.MemMax / 1024)
			dimensions.memKnown = dimensions.memMB > 0
			memCurrent = dimensions.memKnown
		}
	} else if !dimensions.memLiveObserved && configuredMemMB > 0 {
		dimensions.memMB = configuredMemMB
		dimensions.memKnown = true
		memCurrent = true
	}
	if instanceUUID != "" {
		im.resourceDimensions[instanceUUID] = dimensions
	}
	return dimensions.vcpuCount, dimensions.vcpuKnown, dimensions.vcpuKnown && vcpuCurrent,
		dimensions.memMB, dimensions.memKnown, dimensions.memKnown && memCurrent
}

func (im *InstanceManager) validResourceSampleInterval(previous, current time.Time) (time.Duration, float64, bool) {
	elapsed := current.Sub(previous)
	elapsedSeconds := elapsed.Seconds()
	if elapsed <= 0 || math.IsNaN(elapsedSeconds) || math.IsInf(elapsedSeconds, 0) {
		return 0, 0, false
	}
	maxAge := im.resourceSampleMaxAge
	if maxAge <= 0 {
		maxAge = resourceAxisMaxRetainedAge(15 * time.Second)
	}
	if maxAge > 0 && elapsed > maxAge {
		return 0, 0, false
	}
	return elapsed, elapsedSeconds, true
}

func (im *InstanceManager) calculateCPUUsage(totalCPUTime, stealTime, waitTime uint64, uuid string, vcpuCount int) (float64, float64, float64, bool) {
	return im.calculateCPUUsageWithAvailability(totalCPUTime, stealTime, waitTime, true, true, uuid, vcpuCount)
}

func (im *InstanceManager) calculateCPUUsageWithAvailability(totalCPUTime, stealTime, waitTime uint64, stealPresent, waitPresent bool, uuid string, vcpuCount int) (float64, float64, float64, bool) {
	usage, steal, wait, usageValid, _, _ := im.calculateCPUUsageWithDetailedAvailability(
		totalCPUTime, stealTime, waitTime,
		stealPresent, waitPresent,
		uuid, vcpuCount,
	)
	return usage, steal, wait, usageValid
}

func (im *InstanceManager) calculateCPUUsageWithDetailedAvailability(totalCPUTime, stealTime, waitTime uint64, stealPresent, waitPresent bool, uuid string, vcpuCount int) (usage, steal, wait float64, usageValid, stealValid, waitValid bool) {
	return im.calculateCPUUsageWithDetailedAvailabilityAt(
		totalCPUTime, stealTime, waitTime,
		stealPresent, waitPresent,
		uuid, vcpuCount,
		time.Now(),
	)
}

func (im *InstanceManager) calculateCPUUsageWithDetailedAvailabilityAt(totalCPUTime, stealTime, waitTime uint64, stealPresent, waitPresent bool, uuid string, vcpuCount int, now time.Time) (usage, steal, wait float64, usageValid, stealValid, waitValid bool) {
	if vcpuCount <= 0 {
		return 0, 0, 0, false, false, false
	}

	idx := shardIndex(uuid)
	im.cpuMu[idx].Lock()

	if im.cpuSamples[idx] == nil {
		im.cpuSamples[idx] = make(map[string]cpuSample)
	}

	prev, ok := im.cpuSamples[idx][uuid]
	im.cpuSamples[idx][uuid] = cpuSample{total: totalCPUTime, steal: stealTime, wait: waitTime, vcpuCount: vcpuCount, stealPresent: stealPresent, waitPresent: waitPresent, ts: now}
	im.cpuMu[idx].Unlock()

	if !ok {
		return 0, 0, 0, false, false, false
	}
	if prev.vcpuCount != vcpuCount {
		return 0, 0, 0, false, false, false
	}

	elapsed, _, intervalValid := im.validResourceSampleInterval(prev.ts, now)
	if !intervalValid {
		return 0, 0, 0, false, false, false
	}
	if totalCPUTime < prev.total {
		return 0, 0, 0, false, false, false
	}
	ns := float64(elapsed.Nanoseconds())
	if ns <= 0 || math.IsNaN(ns) || math.IsInf(ns, 0) {
		return 0, 0, 0, false, false, false
	}

	calc := func(curr, prev uint64) float64 {
		delta := curr - prev
		val := (float64(delta) / ns) * 100 / float64(vcpuCount)
		if val > 100 {
			return 100
		}
		return val
	}

	usage = calc(totalCPUTime, prev.total)
	if math.IsNaN(usage) || math.IsInf(usage, 0) {
		return 0, 0, 0, false, false, false
	}
	usageValid = true
	stealValid = stealPresent && prev.stealPresent && stealTime >= prev.steal
	if stealValid {
		steal = calc(stealTime, prev.steal)
		if math.IsNaN(steal) || math.IsInf(steal, 0) {
			steal = 0
			stealValid = false
		}
	}
	waitValid = waitPresent && prev.waitPresent && waitTime >= prev.wait
	if waitValid {
		wait = calc(waitTime, prev.wait)
		if math.IsNaN(wait) || math.IsInf(wait, 0) {
			wait = 0
			waitValid = false
		}
	}

	return usage, steal, wait, usageValid, stealValid, waitValid
}
func (im *InstanceManager) calculateDiskIO(key string, rdReq, wrReq uint64, rdBytes, wrBytes uint64, rdTime, wrTime uint64, flReq, flTime uint64, now time.Time) (float64, float64, float64, float64, float64, float64, float64, float64, float64, float64, bool) {
	rdIOPS, wrIOPS, rdLat, wrLat, flIOPS, flLat, avgIOSize, rwReqDelta, flReqDelta, bwBytesPerSec, rwValid, flushValid := im.calculateDiskIOWithAvailability(
		key, rdReq, wrReq, rdBytes, wrBytes, rdTime, wrTime, flReq, flTime, true, true, now,
	)
	return rdIOPS, wrIOPS, rdLat, wrLat, flIOPS, flLat, avgIOSize, rwReqDelta, flReqDelta, bwBytesPerSec, rwValid && flushValid
}

func (im *InstanceManager) calculateDiskIOWithAvailability(key string, rdReq, wrReq uint64, rdBytes, wrBytes uint64, rdTime, wrTime uint64, flReq, flTime uint64, rwPresent, flushPresent bool, now time.Time) (float64, float64, float64, float64, float64, float64, float64, float64, float64, float64, bool, bool) {
	parts := strings.SplitN(key, "|", 2)
	uuid := key
	if len(parts) > 0 {
		uuid = parts[0]
	}

	idx := shardIndex(uuid)
	im.diskMu[idx].Lock()

	if im.diskSamples[idx] == nil {
		im.diskSamples[idx] = make(map[string]diskSample)
	}

	prev, ok := im.diskSamples[idx][key]
	im.diskSamples[idx][key] = diskSample{
		rdReq: rdReq, wrReq: wrReq,
		rdBytes: rdBytes, wrBytes: wrBytes,
		rdTime: rdTime, wrTime: wrTime,
		flReq: flReq, flTime: flTime,
		rwPresent: rwPresent, flushPresent: flushPresent,
		ts: now,
	}
	im.diskMu[idx].Unlock()

	if !ok {
		return 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, false, false
	}

	_, elapsed, intervalValid := im.validResourceSampleInterval(prev.ts, now)
	if !intervalValid {
		return 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, false, false
	}

	delta := func(curr, prev uint64) float64 {
		return float64(curr - prev)
	}

	var rdIOPS, wrIOPS, rdLat, wrLat, avgIOSize, rwReqDelta, bwBytesPerSec float64
	rwValid := rwPresent && prev.rwPresent &&
		rdReq >= prev.rdReq && wrReq >= prev.wrReq &&
		rdBytes >= prev.rdBytes && wrBytes >= prev.wrBytes &&
		rdTime >= prev.rdTime && wrTime >= prev.wrTime
	if rwValid {
		dRdReq := delta(rdReq, prev.rdReq)
		dWrReq := delta(wrReq, prev.wrReq)
		dRdBytes := delta(rdBytes, prev.rdBytes)
		dWrBytes := delta(wrBytes, prev.wrBytes)
		rwReqDelta = dRdReq + dWrReq
		bwBytesPerSec = (dRdBytes + dWrBytes) / elapsed
		if rwReqDelta > 0 {
			avgIOSize = (dRdBytes + dWrBytes) / rwReqDelta
		}
		rdIOPS = dRdReq / elapsed
		wrIOPS = dWrReq / elapsed
		if dRdReq > 0 {
			rdLat = (delta(rdTime, prev.rdTime) / dRdReq) / 1e9
		}
		if dWrReq > 0 {
			wrLat = (delta(wrTime, prev.wrTime) / dWrReq) / 1e9
		}
	}

	var flIOPS, flLat, flReqDelta float64
	flushValid := flushPresent && prev.flushPresent && flReq >= prev.flReq && flTime >= prev.flTime
	if flushValid {
		flReqDelta = delta(flReq, prev.flReq)
		flIOPS = flReqDelta / elapsed
		if flReqDelta > 0 {
			flLat = (delta(flTime, prev.flTime) / flReqDelta) / 1e9
		}
	}

	return rdIOPS, wrIOPS, rdLat, wrLat, flIOPS, flLat, avgIOSize, rwReqDelta, flReqDelta, bwBytesPerSec, rwValid, flushValid
}
func (im *InstanceManager) calculateMemRates(uuid string, swapIn, swapOut, majorFault, minorFault uint64, now time.Time) (swapInRate, swapOutRate, majorFaultRate float64, valid bool) {
	swapInRate, swapOutRate, majorFaultRate, swapInValid, swapOutValid, majorValid := im.calculateMemRatesWithAvailability(
		uuid, swapIn, swapOut, majorFault, minorFault, true, true, true, true, now,
	)
	return swapInRate, swapOutRate, majorFaultRate, swapInValid && swapOutValid && majorValid
}

func (im *InstanceManager) calculateMemRatesWithAvailability(uuid string, swapIn, swapOut, majorFault, minorFault uint64, swapInPresent, swapOutPresent, majorFaultPresent, minorFaultPresent bool, now time.Time) (swapInRate, swapOutRate, majorFaultRate float64, swapInValid, swapOutValid, majorFaultValid bool) {
	idx := shardIndex(uuid)
	im.memMu[idx].Lock()

	if im.memSamples[idx] == nil {
		im.memSamples[idx] = make(map[string]memSample)
	}

	prev, ok := im.memSamples[idx][uuid]
	im.memSamples[idx][uuid] = memSample{
		swapIn:            swapIn,
		swapOut:           swapOut,
		majorFault:        majorFault,
		minorFault:        minorFault,
		swapInPresent:     swapInPresent,
		swapOutPresent:    swapOutPresent,
		majorFaultPresent: majorFaultPresent,
		minorFaultPresent: minorFaultPresent,
		ts:                now,
	}
	im.memMu[idx].Unlock()

	if !ok {
		return 0, 0, 0, false, false, false
	}

	_, elapsed, intervalValid := im.validResourceSampleInterval(prev.ts, now)
	if !intervalValid {
		return 0, 0, 0, false, false, false
	}

	delta := func(curr, prev uint64) float64 {
		if curr <= prev {
			return 0
		}
		return float64(curr-prev) / elapsed
	}

	swapInValid = swapInPresent && prev.swapInPresent && swapIn >= prev.swapIn
	if swapInValid {
		swapInRate = delta(swapIn, prev.swapIn)
	}
	swapOutValid = swapOutPresent && prev.swapOutPresent && swapOut >= prev.swapOut
	if swapOutValid {
		swapOutRate = delta(swapOut, prev.swapOut)
	}
	majorFaultValid = majorFaultPresent && prev.majorFaultPresent && majorFault >= prev.majorFault
	if majorFaultValid {
		majorFaultRate = delta(majorFault, prev.majorFault)
	}

	return swapInRate, swapOutRate, majorFaultRate, swapInValid, swapOutValid, majorFaultValid
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

func cloneNetDeviceCounters(in map[string]netDeviceCounters) map[string]netDeviceCounters {
	out := make(map[string]netDeviceCounters, len(in))
	for name, counters := range in {
		out[name] = counters
	}
	return out
}

func netDeviceCounterAggregatesFitUint64(interfaces map[string]netDeviceCounters) bool {
	var rxPkts, txPkts, rxDrop, txDrop uint64
	safeAdd := func(total *uint64, value uint64) bool {
		if ^uint64(0)-*total < value {
			return false
		}
		*total += value
		return true
	}
	for _, counters := range interfaces {
		if !safeAdd(&rxPkts, counters.rxPkts) ||
			!safeAdd(&txPkts, counters.txPkts) ||
			!safeAdd(&rxDrop, counters.rxDrop) ||
			!safeAdd(&txDrop, counters.txDrop) {
			return false
		}
	}
	return true
}

func (im *InstanceManager) calculateNetRatesForInterfaces(uuid string, interfaces map[string]netDeviceCounters, now time.Time) (pps float64, dropRate float64, dropsPerSec float64, valid bool) {
	interfaceNames := make([]string, 0, len(interfaces))
	for name := range interfaces {
		interfaceNames = append(interfaceNames, name)
	}
	sort.Strings(interfaceNames)
	return im.calculateNetRatesForInterfacesWithIdentity(uuid, strings.Join(interfaceNames, "\x00"), interfaces, now)
}

func (im *InstanceManager) calculateNetRatesForInterfacesWithIdentity(uuid, interfaceIdentity string, interfaces map[string]netDeviceCounters, now time.Time) (pps float64, dropRate float64, dropsPerSec float64, valid bool) {
	if uuid == "" {
		return 0, 0, 0, false
	}
	idx := shardIndex(uuid)
	if len(interfaces) == 0 {
		im.netMu[idx].Lock()
		if im.netSamples[idx] != nil {
			delete(im.netSamples[idx], uuid)
		}
		im.netMu[idx].Unlock()
		return 0, 0, 0, false
	}
	for name := range interfaces {
		if strings.TrimSpace(name) == "" {
			return 0, 0, 0, false
		}
	}
	if !netDeviceCounterAggregatesFitUint64(interfaces) {
		return 0, 0, 0, false
	}

	current := netSample{interfaceSet: interfaceIdentity, interfaces: cloneNetDeviceCounters(interfaces), ts: now}
	im.netMu[idx].Lock()
	if im.netSamples[idx] == nil {
		im.netSamples[idx] = make(map[string]netSample)
	}
	prev, ok := im.netSamples[idx][uuid]
	im.netSamples[idx][uuid] = current
	im.netMu[idx].Unlock()

	if !ok || prev.interfaceSet != current.interfaceSet || len(prev.interfaces) != len(current.interfaces) {
		return 0, 0, 0, false
	}
	_, elapsed, intervalValid := im.validResourceSampleInterval(prev.ts, now)
	if !intervalValid {
		return 0, 0, 0, false
	}

	var packetDelta, dropDelta float64
	for name, counters := range current.interfaces {
		previous, exists := prev.interfaces[name]
		if !exists || counters.rxPkts < previous.rxPkts || counters.txPkts < previous.txPkts ||
			counters.rxDrop < previous.rxDrop || counters.txDrop < previous.txDrop {
			return 0, 0, 0, false
		}
		packetDelta += float64(counters.rxPkts-previous.rxPkts) + float64(counters.txPkts-previous.txPkts)
		dropDelta += float64(counters.rxDrop-previous.rxDrop) + float64(counters.txDrop-previous.txDrop)
	}

	pps = packetDelta / elapsed
	dropsPerSec = dropDelta / elapsed
	if packetDelta+dropDelta > 0 {
		dropRate = dropDelta / (packetDelta + dropDelta)
	}
	if math.IsNaN(pps) || math.IsInf(pps, 0) || math.IsNaN(dropRate) || math.IsInf(dropRate, 0) ||
		math.IsNaN(dropsPerSec) || math.IsInf(dropsPerSec, 0) {
		return 0, 0, 0, false
	}
	return pps, dropRate, dropsPerSec, true
}

func (im *InstanceManager) resetInstanceResourceSamples(instanceUUID string) {
	if instanceUUID == "" {
		return
	}
	idx := shardIndex(instanceUUID)
	im.cpuMu[idx].Lock()
	delete(im.cpuSamples[idx], instanceUUID)
	im.cpuMu[idx].Unlock()

	im.memMu[idx].Lock()
	delete(im.memSamples[idx], instanceUUID)
	im.memMu[idx].Unlock()

	im.netMu[idx].Lock()
	delete(im.netSamples[idx], instanceUUID)
	im.netMu[idx].Unlock()

	im.diskMu[idx].Lock()
	for key := range im.diskSamples[idx] {
		if strings.SplitN(key, "|", 2)[0] == instanceUUID {
			delete(im.diskSamples[idx], key)
		}
	}
	im.diskMu[idx].Unlock()

	im.resourceDimensionsMu.Lock()
	delete(im.resourceDimensions, instanceUUID)
	im.resourceDimensionsMu.Unlock()
}

func (im *InstanceManager) ensureInstanceResourceGeneration(instanceUUID string, domainID int32) bool {
	return im.observeInstanceResourceGenerationWithToken(instanceUUID, domainID, 0, false, "", false)
}

// observeInstanceResourceGeneration treats both a numeric Libvirt domain-ID
// change and a rollback of the domain-lifetime CPU counter as a new QEMU
// incarnation. Domain IDs are reusable, so the monotonic lifetime witness is
// required to catch a stop/start that reuses the same numeric ID between
// collection cycles.
func (im *InstanceManager) observeInstanceResourceGeneration(instanceUUID string, domainID int32, cpuTime uint64, cpuTimePresent bool) bool {
	return im.observeInstanceResourceGenerationWithToken(instanceUUID, domainID, cpuTime, cpuTimePresent, "", false)
}

func (im *InstanceManager) observeInstanceResourceGenerationWithToken(instanceUUID string, domainID int32, cpuTime uint64, cpuTimePresent bool, processToken string, processTokenPresent bool) bool {
	if instanceUUID == "" {
		return false
	}
	im.resourceGenerationMu.Lock()
	previous, exists := im.resourceGeneration[instanceUUID]
	previousCPUTime, previousCPUTimePresent := im.resourceGenerationCPUTime[instanceUUID]
	previousProcessToken, previousProcessTokenPresent := im.resourceGenerationToken[instanceUUID]
	changed := exists && (previous != domainID ||
		(cpuTimePresent && previousCPUTimePresent && cpuTime < previousCPUTime) ||
		(processTokenPresent && (!previousProcessTokenPresent || processToken != previousProcessToken)))
	if im.resourceGeneration == nil {
		im.resourceGeneration = make(map[string]int32)
	}
	if im.resourceGenerationCPUTime == nil {
		im.resourceGenerationCPUTime = make(map[string]uint64)
	}
	if im.resourceGenerationToken == nil {
		im.resourceGenerationToken = make(map[string]string)
	}
	im.resourceGeneration[instanceUUID] = domainID
	if cpuTimePresent {
		im.resourceGenerationCPUTime[instanceUUID] = cpuTime
	} else if changed {
		delete(im.resourceGenerationCPUTime, instanceUUID)
	}
	if processTokenPresent {
		im.resourceGenerationToken[instanceUUID] = processToken
	} else if changed {
		delete(im.resourceGenerationToken, instanceUUID)
	}
	im.resourceGenerationMu.Unlock()
	if !changed {
		return false
	}

	im.resetInstanceResourceSamples(instanceUUID)
	return true
}

func (im *InstanceManager) pruneDiskSamples(instanceUUID string, activeKeys map[string]struct{}) {
	if instanceUUID == "" {
		return
	}
	idx := shardIndex(instanceUUID)
	im.diskMu[idx].Lock()
	for key := range im.diskSamples[idx] {
		if strings.SplitN(key, "|", 2)[0] != instanceUUID {
			continue
		}
		if _, active := activeKeys[key]; !active {
			delete(im.diskSamples[idx], key)
		}
	}
	im.diskMu[idx].Unlock()
}
