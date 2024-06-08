package main

import (
	"math"
	"time"
)

type resourceAxisV2 struct {
	EWMA        float64
	Initialized bool
}

type resourceV2State struct {
	LastUpdate        time.Time
	Cpu               resourceAxisV2
	Mem               resourceAxisV2
	Disk              resourceAxisV2
	Net               resourceAxisV2
	OverallHi95Streak int
	LastBand          int
	LastTopAxis       string
	LastCapActive     bool
}

type resourceAxisResult struct {
	PRaw   float64
	Conf   float64
	Impact float64
	PEff   float64
	EWMA   float64
	Sev    float64
	Alpha  float64
	Tau    float64
}

type resourceV2Input struct {
	Now time.Time

	CpuPRaw   float64
	CpuConf   float64
	CpuImpact float64

	MemPRaw   float64
	MemConf   float64
	MemImpact float64

	DiskPRaw   float64
	DiskConf   float64
	DiskImpact float64

	NetPRaw   float64
	NetConf   float64
	NetImpact float64
}

type resourceV2Output struct {
	DtSeconds            float64
	OverallRaw           float64
	OverallFinal         float64
	CapActive            bool
	PersistenceTriggered bool
	AxesGE90             int
	TopAxis              string

	CPU  resourceAxisResult
	MEM  resourceAxisResult
	DISK resourceAxisResult
	NET  resourceAxisResult
}

func updateAxisV2(a *resourceAxisV2, pEff, dtSeconds, riseTau, fallTau float64) (ewmaOut, alphaOut, tauUsed float64) {
	if !a.Initialized {
		a.EWMA = clamp01(pEff)
		a.Initialized = true
		return a.EWMA, 1, 0
	}
	tauUsed = fallTau
	if pEff > a.EWMA {
		tauUsed = riseTau
	}
	alphaOut = ewmaAlpha(dtSeconds, tauUsed)
	a.EWMA = clamp01(a.EWMA + alphaOut*(pEff-a.EWMA))
	return a.EWMA, alphaOut, tauUsed
}

func axisSeverityV2(ewma, scale, power, impact float64) float64 {
	x := clamp01(ewma * scale)
	if power > 0 {
		x = math.Pow(x, power)
	}
	return clamp01(x) * 100.0 * clamp01(impact)
}

func lpBlend(p float64, cpu, mem, disk, net float64, wCPU, wMem, wDisk, wNet float64) float64 {
	if p <= 0 {
		p = 3
	}
	sumW := wCPU + wMem + wDisk + wNet
	if sumW <= 0 {
		return 0
	}
	f := func(x float64) float64 {
		return math.Pow(clamp01(x/100.0), p)
	}
	s := wCPU*f(cpu) + wMem*f(mem) + wDisk*f(disk) + wNet*f(net)
	s = s / sumW
	return clamp01(math.Pow(s, 1.0/p)) * 100.0
}

func band30_60_85(overall float64) int {
	if overall >= 85 {
		return 85
	}
	if overall >= 60 {
		return 60
	}
	if overall >= 30 {
		return 30
	}
	return 0
}

func countAxesAbove90(cpu, mem, disk, net float64) int {
	n := 0
	if cpu >= 90 {
		n++
	}
	if mem >= 90 {
		n++
	}
	if disk >= 90 {
		n++
	}
	if net >= 90 {
		n++
	}
	return n
}

func topAxisName(cpu, mem, disk, net float64) string {
	top := "cpu"
	val := cpu
	if mem > val {
		top = "mem"
		val = mem
	}
	if disk > val {
		top = "disk"
		val = disk
	}
	if net > val {
		top = "net"
	}
	return top
}

func (mc *MetricsCollector) getResourceV2State(instanceUUID string) *resourceV2State {
	mc.resourceV2Mu.Lock()
	defer mc.resourceV2Mu.Unlock()
	if mc.resourceV2 == nil {
		mc.resourceV2 = make(map[string]*resourceV2State)
	}
	s, ok := mc.resourceV2[instanceUUID]
	if !ok {
		s = &resourceV2State{}
		mc.resourceV2[instanceUUID] = s
	}
	return s
}

func (mc *MetricsCollector) cleanupResourceV2(activeSet map[string]struct{}) {
	mc.resourceV2Mu.Lock()
	defer mc.resourceV2Mu.Unlock()
	if mc.resourceV2 == nil {
		return
	}
	for uuid := range mc.resourceV2 {
		if _, ok := activeSet[uuid]; !ok {
			delete(mc.resourceV2, uuid)
		}
	}
}

func (mc *MetricsCollector) computeResourceV2(instanceUUID string, in resourceV2Input) (resourceV2Output, *resourceV2State) {
	out := resourceV2Output{}
	s := mc.getResourceV2State(instanceUUID)

	now := in.Now
	dt := mc.collectionInterval.Seconds()
	if !s.LastUpdate.IsZero() {
		d := now.Sub(s.LastUpdate).Seconds()
		if d > 0 && d < 300 {
			dt = d
		}
	}
	s.LastUpdate = now
	out.DtSeconds = dt

	const power = 2.0
	const scale = 1.0

	const cpuRiseTau = 30.0
	const cpuFallTau = 120.0
	const memRiseTau = 45.0
	const memFallTau = 180.0
	const diskRiseTau = 30.0
	const diskFallTau = 180.0
	const netRiseTau = 30.0
	const netFallTau = 120.0

	pEffCPU := clamp01(in.CpuPRaw * clamp01(in.CpuConf))
	pEffMEM := clamp01(in.MemPRaw * clamp01(in.MemConf))
	pEffDISK := clamp01(in.DiskPRaw * clamp01(in.DiskConf))
	pEffNET := clamp01(in.NetPRaw * clamp01(in.NetConf))

	out.CPU = resourceAxisResult{PRaw: clamp01(in.CpuPRaw), Conf: clamp01(in.CpuConf), Impact: clamp01(in.CpuImpact), PEff: pEffCPU}
	out.MEM = resourceAxisResult{PRaw: clamp01(in.MemPRaw), Conf: clamp01(in.MemConf), Impact: clamp01(in.MemImpact), PEff: pEffMEM}
	out.DISK = resourceAxisResult{PRaw: clamp01(in.DiskPRaw), Conf: clamp01(in.DiskConf), Impact: clamp01(in.DiskImpact), PEff: pEffDISK}
	out.NET = resourceAxisResult{PRaw: clamp01(in.NetPRaw), Conf: clamp01(in.NetConf), Impact: clamp01(in.NetImpact), PEff: pEffNET}

	ew, a, tau := updateAxisV2(&s.Cpu, pEffCPU, dt, cpuRiseTau, cpuFallTau)
	out.CPU.EWMA, out.CPU.Alpha, out.CPU.Tau = ew, a, tau
	out.CPU.Sev = axisSeverityV2(ew, scale, power, out.CPU.Impact)

	ew, a, tau = updateAxisV2(&s.Mem, pEffMEM, dt, memRiseTau, memFallTau)
	out.MEM.EWMA, out.MEM.Alpha, out.MEM.Tau = ew, a, tau
	out.MEM.Sev = axisSeverityV2(ew, scale, power, out.MEM.Impact)

	ew, a, tau = updateAxisV2(&s.Disk, pEffDISK, dt, diskRiseTau, diskFallTau)
	out.DISK.EWMA, out.DISK.Alpha, out.DISK.Tau = ew, a, tau
	out.DISK.Sev = axisSeverityV2(ew, scale, power, out.DISK.Impact)

	ew, a, tau = updateAxisV2(&s.Net, pEffNET, dt, netRiseTau, netFallTau)
	out.NET.EWMA, out.NET.Alpha, out.NET.Tau = ew, a, tau
	out.NET.Sev = axisSeverityV2(ew, scale, power, out.NET.Impact)

	const lpP = 3.0
	const wCPU = 0.25
	const wMEM = 0.25
	const wDISK = 0.30
	const wNET = 0.20

	overallRaw := lpBlend(lpP, out.CPU.Sev, out.MEM.Sev, out.DISK.Sev, out.NET.Sev, wCPU, wMEM, wDISK, wNET)
	out.OverallRaw = overallRaw

	if overallRaw >= 95 {
		s.OverallHi95Streak++
	} else {
		s.OverallHi95Streak = 0
	}

	axes90 := countAxesAbove90(out.CPU.Sev, out.MEM.Sev, out.DISK.Sev, out.NET.Sev)
	out.AxesGE90 = axes90

	allowOver95 := axes90 >= 2
	if !allowOver95 && s.OverallHi95Streak >= 3 {
		allowOver95 = true
		out.PersistenceTriggered = true
	}

	overallFinal := overallRaw
	if overallRaw > 95 && !allowOver95 {
		overallFinal = 95
		out.CapActive = true
	}
	out.OverallFinal = overallFinal
	out.TopAxis = topAxisName(out.CPU.Sev, out.MEM.Sev, out.DISK.Sev, out.NET.Sev)

	return out, s
}

func appendAxisFieldsV2(kv *[]any, prefix string, r resourceAxisResult) {
	*kv = append(*kv,
		prefix+"_p_raw", roundToFiveDecimals(r.PRaw),
		prefix+"_conf", roundToFiveDecimals(r.Conf),
		prefix+"_impact", roundToFiveDecimals(r.Impact),
		prefix+"_p_eff", roundToFiveDecimals(r.PEff),
		prefix+"_ewma", roundToFiveDecimals(r.EWMA),
		prefix+"_sev", roundToFiveDecimals(r.Sev),
		prefix+"_alpha", roundToFiveDecimals(r.Alpha),
		prefix+"_tau", roundToFiveDecimals(r.Tau),
	)
}

func (mc *MetricsCollector) maybeLogResourceV2Event(domain, instanceUUID, projectUUID, projectName, userUUID string, out resourceV2Output, s *resourceV2State) {
	if s == nil {
		return
	}
	band := band30_60_85(out.OverallFinal)
	top := out.TopAxis

	bandChanged := (s.LastBand != band)
	topChanged := (s.LastTopAxis != "" && s.LastTopAxis != top)
	capChanged := (s.LastCapActive != out.CapActive)

	shouldLog := false
	if bandChanged {
		if band >= 30 || s.LastBand >= 30 {
			shouldLog = true
		}
	}
	if topChanged {
		if band >= 30 || s.LastBand >= 30 {
			shouldLog = true
		}
	}
	if capChanged {
		if band >= 30 || s.LastBand >= 30 || out.OverallFinal >= 95 {
			shouldLog = true
		}
	}
	if out.PersistenceTriggered {
		shouldLog = true
	}

	if !shouldLog {
		s.LastBand = band
		s.LastTopAxis = top
		s.LastCapActive = out.CapActive
		return
	}
	if out.OverallFinal >= 30 {
		kv := make([]any, 0, 128)
		kv = append(kv,
			"domain", domain,
			"instance_uuid", instanceUUID,
			"project_uuid", projectUUID,
			"project_name", projectName,
			"user_uuid", userUUID,
			"overall_raw", roundToFiveDecimals(out.OverallRaw),
			"overall", roundToFiveDecimals(out.OverallFinal),
			"band", band,
			"cap_active", out.CapActive,
			"hi95_streak", s.OverallHi95Streak,
			"axes_ge90", out.AxesGE90,
			"top_axis", top,
			"dt_seconds", roundToFiveDecimals(out.DtSeconds),
		)
		appendAxisFieldsV2(&kv, "cpu", out.CPU)
		appendAxisFieldsV2(&kv, "mem", out.MEM)
		appendAxisFieldsV2(&kv, "disk", out.DISK)
		appendAxisFieldsV2(&kv, "net", out.NET)
		logKV(LogLevelInfo, "severity", "resource_v2_event", kv...)
	}
	s.LastBand = band
	s.LastTopAxis = top
	s.LastCapActive = out.CapActive
}
