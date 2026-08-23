package main

import (
	"strings"
	"time"
)

func (im *InstanceManager) calculateCPUUsage(totalCPUTime, stealTime, waitTime uint64, uuid string, vcpuCount int) (float64, float64, float64, bool) {
	return im.calculateCPUUsageWithAvailability(totalCPUTime, stealTime, waitTime, true, true, uuid, vcpuCount)
}

func (im *InstanceManager) calculateCPUUsageWithAvailability(totalCPUTime, stealTime, waitTime uint64, stealPresent, waitPresent bool, uuid string, vcpuCount int) (float64, float64, float64, bool) {
	if vcpuCount <= 0 {
		return 0, 0, 0, false
	}
	now := time.Now()

	idx := shardIndex(uuid)
	im.cpuMu[idx].Lock()

	if im.cpuSamples[idx] == nil {
		im.cpuSamples[idx] = make(map[string]cpuSample)
	}

	prev, ok := im.cpuSamples[idx][uuid]
	im.cpuSamples[idx][uuid] = cpuSample{total: totalCPUTime, steal: stealTime, wait: waitTime, vcpuCount: vcpuCount, stealPresent: stealPresent, waitPresent: waitPresent, ts: now}
	im.cpuMu[idx].Unlock()

	if !ok {
		return 0, 0, 0, false
	}
	if prev.vcpuCount != vcpuCount {
		return 0, 0, 0, false
	}

	elapsed := now.Sub(prev.ts)
	if elapsed <= 0 {
		return 0, 0, 0, false
	}
	if totalCPUTime < prev.total {
		return 0, 0, 0, false
	}
	ns := float64(elapsed.Nanoseconds())

	calc := func(curr, prev uint64) float64 {
		delta := curr - prev
		val := (float64(delta) / ns) * 100 / float64(vcpuCount)
		if val > 100 {
			return 100
		}
		return val
	}

	usage := calc(totalCPUTime, prev.total)
	steal := 0.0
	if stealPresent && prev.stealPresent && stealTime >= prev.steal {
		steal = calc(stealTime, prev.steal)
	}
	wait := 0.0
	if waitPresent && prev.waitPresent && waitTime >= prev.wait {
		wait = calc(waitTime, prev.wait)
	}

	return usage, steal, wait, true
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

	elapsed := now.Sub(prev.ts).Seconds()
	if elapsed <= 0 {
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

	elapsed := now.Sub(prev.ts).Seconds()
	if elapsed <= 0 {
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

	elapsed := now.Sub(prev.ts).Seconds()
	if elapsed <= 0 {
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
