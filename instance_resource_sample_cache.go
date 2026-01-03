package main

import (
	"strings"
	"time"
)

func (im *InstanceManager) calculateCPUUsage(totalCPUTime, stealTime, waitTime uint64, uuid string, vcpuCount int) (float64, float64, float64) {
	if vcpuCount <= 0 {
		return 0, 0, 0
	}
	now := time.Now()

	idx := shardIndex(uuid)
	im.cpuMu[idx].Lock()

	if im.cpuSamples[idx] == nil {
		im.cpuSamples[idx] = make(map[string]cpuSample)
	}

	prev, ok := im.cpuSamples[idx][uuid]
	im.cpuSamples[idx][uuid] = cpuSample{total: totalCPUTime, steal: stealTime, wait: waitTime, ts: now}
	im.cpuMu[idx].Unlock()

	if !ok {
		return 0, 0, 0
	}

	elapsed := now.Sub(prev.ts)
	if elapsed <= 0 {
		return 0, 0, 0
	}
	ns := float64(elapsed.Nanoseconds())

	calc := func(curr, prev uint64) float64 {
		if curr < prev {
			return 0
		}
		delta := curr - prev
		val := (float64(delta) / ns) * 100 / float64(vcpuCount)
		if val > 100 {
			return 100
		}
		return val
	}

	usage := calc(totalCPUTime, prev.total)
	steal := calc(stealTime, prev.steal)
	wait := calc(waitTime, prev.wait)

	return usage, steal, wait
}
func (im *InstanceManager) calculateDiskIO(key string, rdReq, wrReq int64, rdBytes, wrBytes int64, rdTime, wrTime int64, flReq, flTime int64, now time.Time) (float64, float64, float64, float64, float64, float64, float64, float64, float64, float64) {
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
		ts: now,
	}
	im.diskMu[idx].Unlock()

	if !ok {
		return 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	}

	elapsed := now.Sub(prev.ts).Seconds()
	if elapsed <= 0 {
		return 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	}

	delta := func(curr, prev int64) float64 {
		if curr < prev {
			return 0
		}
		return float64(curr - prev)
	}

	dRdReq := delta(rdReq, prev.rdReq)
	dWrReq := delta(wrReq, prev.wrReq)
	dFlReq := delta(flReq, prev.flReq)

	dRdBytes := delta(rdBytes, prev.rdBytes)
	dWrBytes := delta(wrBytes, prev.wrBytes)

	bwBytesPerSec := (dRdBytes + dWrBytes) / elapsed

	rwReqDelta := dRdReq + dWrReq
	flReqDelta := dFlReq

	avgIOSize := float64(0)
	if rwReqDelta > 0 {
		avgIOSize = (dRdBytes + dWrBytes) / rwReqDelta
	}

	rdIOPS := dRdReq / elapsed
	wrIOPS := dWrReq / elapsed
	flIOPS := dFlReq / elapsed

	rdTimeDelta := delta(rdTime, prev.rdTime)
	wrTimeDelta := delta(wrTime, prev.wrTime)
	flTimeDelta := delta(flTime, prev.flTime)

	var rdLat, wrLat, flLat float64
	if dRdReq > 0 {
		rdLat = (rdTimeDelta / dRdReq) / 1e9
	}
	if dWrReq > 0 {
		wrLat = (wrTimeDelta / dWrReq) / 1e9
	}
	if dFlReq > 0 {
		flLat = (flTimeDelta / dFlReq) / 1e9
	}

	return rdIOPS, wrIOPS, rdLat, wrLat, flIOPS, flLat, avgIOSize, rwReqDelta, flReqDelta, bwBytesPerSec
}
func (im *InstanceManager) calculateMemRates(uuid string, swapIn, swapOut, majorFault, minorFault uint64, now time.Time) (swapInRate, swapOutRate, majorFaultRate float64) {
	idx := shardIndex(uuid)
	im.memMu[idx].Lock()

	if im.memSamples[idx] == nil {
		im.memSamples[idx] = make(map[string]memSample)
	}

	prev, ok := im.memSamples[idx][uuid]
	im.memSamples[idx][uuid] = memSample{
		swapIn:     swapIn,
		swapOut:    swapOut,
		majorFault: majorFault,
		minorFault: minorFault,
		ts:         now,
	}
	im.memMu[idx].Unlock()

	if !ok {
		return 0, 0, 0
	}

	elapsed := now.Sub(prev.ts).Seconds()
	if elapsed <= 0 {
		return 0, 0, 0
	}

	delta := func(curr, prev uint64) float64 {
		if curr <= prev {
			return 0
		}
		return float64(curr-prev) / elapsed
	}

	swapInRate = delta(swapIn, prev.swapIn)
	swapOutRate = delta(swapOut, prev.swapOut)
	majorFaultRate = delta(majorFault, prev.majorFault)

	return
}
func (im *InstanceManager) calculateNetRates(uuid string, rxPkts, txPkts, rxDrop, txDrop uint64, now time.Time) (pps float64, dropRate float64, dropsPerSec float64) {
	idx := shardIndex(uuid)
	im.netMu[idx].Lock()
	if im.netSamples[idx] == nil {
		im.netSamples[idx] = make(map[string]netSample)
	}
	prev, ok := im.netSamples[idx][uuid]
	im.netSamples[idx][uuid] = netSample{
		rxPkts: rxPkts,
		txPkts: txPkts,
		rxDrop: rxDrop,
		txDrop: txDrop,
		ts:     now,
	}
	im.netMu[idx].Unlock()

	if !ok {
		return 0, 0, 0
	}

	elapsed := now.Sub(prev.ts).Seconds()
	if elapsed <= 0 {
		return 0, 0, 0
	}

	delta := func(curr, prev uint64) float64 {
		if curr < prev {
			return 0
		}
		return float64(curr - prev)
	}

	dPkts := delta(rxPkts, prev.rxPkts) + delta(txPkts, prev.txPkts)
	dDrops := delta(rxDrop, prev.rxDrop) + delta(txDrop, prev.txDrop)

	pps = dPkts / elapsed
	dropsPerSec = dDrops / elapsed
	if dPkts > 0 {
		dropRate = dDrops / dPkts
	}
	return pps, dropRate, dropsPerSec
}
