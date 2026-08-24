package main

import (
	libvirt "github.com/digitalocean/go-libvirt"
	"github.com/prometheus/client_golang/prometheus"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

func combineBehaviorSignals(outbound, inbound float64, outboundEnabled, inboundEnabled bool) (float64, bool) {
	signal := 0.0
	available := false
	if outboundEnabled {
		signal = outbound
		available = true
	}
	if inboundEnabled && (!available || inbound > signal) {
		signal = inbound
		available = true
	}
	return signal, available
}

func typedParamUint64(value interface{}) (uint64, bool) {
	switch v := value.(type) {
	case uint64:
		return v, true
	case uint32:
		return uint64(v), true
	case uint:
		return uint64(v), true
	case int64:
		if v >= 0 {
			return uint64(v), true
		}
	case int32:
		if v >= 0 {
			return uint64(v), true
		}
	case int:
		if v >= 0 {
			return uint64(v), true
		}
	case bool:
		if v {
			return 1, true
		}
		return 0, true
	}
	return 0, false
}

func typedParamInt(value interface{}) (int, bool) {
	u, ok := typedParamUint64(value)
	if !ok || u > uint64(^uint(0)>>1) {
		return 0, false
	}
	return int(u), true
}

func parseLibvirtStats(params []libvirt.TypedParam) *ParsedStats {
	s := &ParsedStats{
		Vcpus: make(map[int]*VcpuStat),
		Disks: make(map[int]*DiskStat),
		Nets:  make(map[int]*NetStat),
	}

	for _, p := range params {
		field := p.Field
		uVal, uOK := typedParamUint64(p.Value.I)
		strVal, strOK := p.Value.I.(string)
		uOK = uOK && (p.Value.D == 0 || p.Value.D >= uint32(libvirt.TypedParamInt) && p.Value.D <= uint32(libvirt.TypedParamUllong))
		strOK = strOK && (p.Value.D == 0 || p.Value.D == uint32(libvirt.TypedParamString))

		if field == "state.state" && uOK {
			if i, ok := typedParamInt(p.Value.I); ok {
				s.State = i
				s.StatePresent = true
			}
		}

		if field == "cpu.time" && uOK {
			s.CpuTime = uVal
			s.CpuTimePresent = true
		}
		if field == "cpu.user" && uOK {
			s.CpuUser = uVal
			s.CpuUserPresent = true
		}
		if field == "cpu.system" && uOK {
			s.CpuSystem = uVal
			s.CpuSystemPresent = true
		}
		if field == "vcpu.current" && uOK {
			s.VcpuCurrent = uVal
			s.VcpuCurrentPresent = true
		}

		if field == "balloon.maximum" && uOK {
			s.MemMax = uVal
			s.MemMaxPresent = true
		}
		if field == "balloon.current" && uOK {
			s.MemCur = uVal
			s.MemCurPresent = true
		}
		if field == "balloon.usable" && uOK {
			s.MemUsable = uVal
			s.MemUsablePresent = true
		}
		if field == "balloon.rss" && uOK {
			s.MemRss = uVal
			s.MemRssPresent = true
		}
		if field == "balloon.swap_in" && uOK {
			s.SwapIn = uVal
			s.SwapInPresent = true
		}
		if field == "balloon.swap_out" && uOK {
			s.SwapOut = uVal
			s.SwapOutPresent = true
		}
		if field == "balloon.major_fault" && uOK {
			s.MajorFault = uVal
			s.MajorFaultPresent = true
		}
		if field == "balloon.minor_fault" && uOK {
			s.MinorFault = uVal
			s.MinorFaultPresent = true
		}
		if field == "balloon.hugetlb_pgalloc" && uOK {
			s.HugetlbPgAlloc = uVal
			s.HugetlbPgAllocPresent = true
		}
		if field == "balloon.hugetlb_pgfail" && uOK {
			s.HugetlbPgFail = uVal
			s.HugetlbPgFailPresent = true
		}
		if field == "net.count" && uOK {
			s.NetCount = uVal
			s.NetCountPresent = true
		}
		if field == "block.count" && uOK {
			s.BlockCount = uVal
			s.BlockCountPresent = true
		}

		if strings.HasPrefix(field, "vcpu.") {
			parts := strings.Split(field, ".")
			if len(parts) == 3 {
				idx, err := strconv.Atoi(parts[1])
				if err != nil || idx < 0 {
					continue
				}
				key := parts[2]
				if !uOK || key != "state" && key != "time" && key != "wait" && key != "delay" {
					continue
				}
				if _, ok := s.Vcpus[idx]; !ok {
					s.Vcpus[idx] = &VcpuStat{}
				}
				v := s.Vcpus[idx]
				switch key {
				case "state":
					v.State = uVal
					v.StatePresent = true
				case "time":
					v.Time = uVal
					v.TimePresent = true
				case "wait":
					v.Wait = uVal
					v.WaitPresent = true
				case "delay":
					v.Delay = uVal
					v.DelayPresent = true
				}
			}
		}

		if strings.HasPrefix(field, "block.") {
			parts := strings.Split(field, ".")
			if len(parts) >= 3 {
				idx, err := strconv.Atoi(parts[1])
				if err != nil || idx < 0 {
					continue
				}
				key := parts[2]
				validField := len(parts) == 3 && key == "name" && strOK
				if len(parts) == 4 && uOK {
					subKey := parts[3]
					validField = ((key == "rd" || key == "wr") && (subKey == "reqs" || subKey == "bytes" || subKey == "times")) ||
						(key == "fl" && (subKey == "reqs" || subKey == "times"))
				} else if len(parts) == 3 && uOK {
					validField = key == "capacity" || key == "allocation" || key == "physical"
				}
				if !validField {
					continue
				}
				if _, ok := s.Disks[idx]; !ok {
					s.Disks[idx] = &DiskStat{}
				}
				d := s.Disks[idx]

				if key == "name" && strOK {
					d.Name = strVal
					d.NamePresent = true
					continue
				}

				if len(parts) == 4 {
					if !uOK {
						continue
					}
					subKey := parts[3]
					switch key {
					case "rd":
						if subKey == "reqs" {
							d.RdReqs = uVal
							d.RdReqsPresent = true
						}
						if subKey == "bytes" {
							d.RdBytes = uVal
							d.RdBytesPresent = true
						}
						if subKey == "times" {
							d.RdTime = uVal
							d.RdTimePresent = true
						}
					case "wr":
						if subKey == "reqs" {
							d.WrReqs = uVal
							d.WrReqsPresent = true
						}
						if subKey == "bytes" {
							d.WrBytes = uVal
							d.WrBytesPresent = true
						}
						if subKey == "times" {
							d.WrTime = uVal
							d.WrTimePresent = true
						}
					case "fl":
						if subKey == "reqs" {
							d.FlReqs = uVal
							d.FlReqsPresent = true
						}
						if subKey == "times" {
							d.FlTime = uVal
							d.FlTimePresent = true
						}
					}
				} else if uOK {
					if key == "capacity" {
						d.Capacity = uVal
						d.CapacityPresent = true
					}
					if key == "allocation" {
						d.Allocation = uVal
						d.AllocationPresent = true
					}
					if key == "physical" {
						d.Physical = uVal
						d.PhysicalPresent = true
					}
				}
			}
		}

		if strings.HasPrefix(field, "net.") {
			parts := strings.Split(field, ".")
			if len(parts) >= 3 {
				idx, err := strconv.Atoi(parts[1])
				if err != nil || idx < 0 {
					continue
				}
				key := parts[2]
				validField := len(parts) == 3 && key == "name" && strOK
				if len(parts) == 4 && uOK {
					subKey := parts[3]
					validField = (key == "rx" || key == "tx") && (subKey == "bytes" || subKey == "pkts" || subKey == "errs" || subKey == "drop")
				}
				if !validField {
					continue
				}
				if _, ok := s.Nets[idx]; !ok {
					s.Nets[idx] = &NetStat{}
				}
				n := s.Nets[idx]

				if key == "name" && strOK {
					n.Name = strVal
					n.NamePresent = true
					continue
				}

				if len(parts) == 4 {
					if !uOK {
						continue
					}
					subKey := parts[3]
					switch key {
					case "rx":
						if subKey == "bytes" {
							n.RxBytes = uVal
							n.RxBytesPresent = true
						}
						if subKey == "pkts" {
							n.RxPkts = uVal
							n.RxPktsPresent = true
						}
						if subKey == "errs" {
							n.RxErrs = uVal
							n.RxErrsPresent = true
						}
						if subKey == "drop" {
							n.RxDrop = uVal
							n.RxDropPresent = true
						}
					case "tx":
						if subKey == "bytes" {
							n.TxBytes = uVal
							n.TxBytesPresent = true
						}
						if subKey == "pkts" {
							n.TxPkts = uVal
							n.TxPktsPresent = true
						}
						if subKey == "errs" {
							n.TxErrs = uVal
							n.TxErrsPresent = true
						}
						if subKey == "drop" {
							n.TxDrop = uVal
							n.TxDropPresent = true
						}
					}
				}
			}
		}
	}
	return s
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

func (mc *MetricsCollector) collectDomainMetrics(
	record libvirt.DomainStatsRecord,
	connAgg *ConntrackAgg,
	hostIPs map[string]struct{},
	agg *hostAgg,
	hostConntrackMax uint64,
	hostConntrackMaxAvailable bool,
	conntrackFresh bool,
	libvirtFresh bool,
) {
	mc.libvirtMu.Lock()
	conn := mc.libvirtConn
	mc.libvirtMu.Unlock()
	meta, err := mc.im.getDomainMeta(record.Dom, conn)
	if err != nil {
		logCollectorMetric.Error("domain_meta_failed", "err", err)
		return
	}
	stat := parseLibvirtStats(record.Params)
	domain := strings.TrimSpace(record.Dom.Name)
	serverName := strings.TrimSpace(meta.Name)
	instanceUUID := meta.InstanceUUID
	userUUID := meta.UserUUID
	projectUUID := meta.ProjectUUID
	projectName := meta.ProjectName
	userName := meta.UserName
	flavorName := meta.FlavorName
	vcpuCount := effectiveDomainVCPUCount(meta.VCPUCount, stat)
	memMB := meta.MemMB
	if stat.MemMaxPresent && stat.MemMax > 0 {
		memMB = int(stat.MemMax / 1024)
	}
	rootType := meta.RootType
	createdAt := meta.CreatedAt
	metadataVersion := meta.MetadataVersion
	now := time.Now()
	var (
		resourceMemSeverity float64
		maxDiskIOSignal     float64
		maxDiskActivity     float64
		maxConntrackFlows   int
		netPPS              float64
		netDropRate         float64
		outboundSignal      float64
		inboundSignal       float64
	)
	fixedIPs := deduplicateIPs(meta.FixedIPs)
	ipSet := make(map[string]struct{}, len(fixedIPs))
	for _, ip := range fixedIPs {
		ipSet[ip.Address] = struct{}{}
	}
	if agg != nil {
		agg.fixedIPs += len(ipSet)
		if projectName == "" {
			projectName = "unknown"
		}
		projectIdentity := "name:" + projectName
		if projectUUID != "" {
			projectIdentity = "uuid:" + projectUUID
		}
		agg.projects[projectIdentity] = struct{}{}
		if vcpuCount > 0 {
			agg.vcpus += vcpuCount
		}
	}
	dynamicMetrics := make([]prometheus.Metric, 0, 80)
	stateCode := stat.State
	stateDesc := strings.ToLower(libvirt.DomainState(stateCode).String())
	stateDesc = strings.TrimPrefix(stateDesc, "vir_domain_")
	stateDesc = strings.TrimPrefix(stateDesc, "domain")
	stateDesc = strings.Trim(stateDesc, "_")
	instanceRunning := stat.StatePresent && stateCode == int(libvirt.DomainRunning)
	if stat.StatePresent {
		dynamicMetrics = append(dynamicMetrics, prometheus.MustNewConstMetric(
			mc.im.instanceStateDesc,
			prometheus.GaugeValue,
			float64(stateCode),
			domain,
			serverName,
			instanceUUID,
			projectUUID,
			projectName,
			userUUID,
			stateDesc,
		))
	}
	dynamicMetrics = append(dynamicMetrics, prometheus.MustNewConstMetric(
		mc.im.instanceInfoDesc,
		prometheus.GaugeValue,
		1.0,
		domain,
		serverName,
		instanceUUID,
		projectUUID,
		projectName,
		userUUID,
		userName,
		flavorName,
		strconv.Itoa(vcpuCount),
		strconv.Itoa(memMB),
		rootType,
		createdAt,
		metadataVersion,
	))
	if vcpuCount > 0 {
		dynamicMetrics = append(dynamicMetrics,
			prometheus.MustNewConstMetric(
				mc.im.instanceCpuVcpuCountDesc,
				prometheus.GaugeValue,
				float64(vcpuCount),
				domain,
				serverName,
				instanceUUID,
				projectUUID,
				projectName,
				userUUID,
			),
		)
	}
	if memMB > 0 {
		dynamicMetrics = append(dynamicMetrics,
			prometheus.MustNewConstMetric(
				mc.im.instanceMemAllocatedMBDesc,
				prometheus.GaugeValue,
				float64(memMB),
				domain,
				serverName,
				instanceUUID,
				projectUUID,
				projectName,
				userUUID,
			),
		)
	}
	var guestUsedMB float64
	var guestUsedAvailable, memPressureAvailable bool
	guestUsedMB, resourceMemSeverity, guestUsedAvailable, memPressureAvailable = mc.collectDomainMemoryMetrics(
		stat,
		now,
		domain,
		serverName,
		instanceUUID,
		projectUUID,
		projectName,
		userUUID,
		instanceRunning,
		memMB,
		libvirtFresh && instanceRunning,
		&dynamicMetrics,
	)
	_ = guestUsedMB
	diskCountDomain := 0
	var diskAvailable bool
	diskCountDomain, maxDiskIOSignal, maxDiskActivity, diskAvailable = mc.collectDomainDiskMetrics(
		meta,
		stat,
		now,
		domain,
		serverName,
		instanceUUID,
		projectUUID,
		projectName,
		userUUID,
		libvirtFresh && instanceRunning,
		&dynamicMetrics,
	)
	if agg != nil && diskCountDomain > 0 {
		agg.disks += diskCountDomain
	}
	cpuPressure, cpuAvailable := mc.collectDomainCPUMetrics(
		stat,
		domain,
		serverName,
		instanceUUID,
		projectUUID,
		projectName,
		userUUID,
		vcpuCount,
		libvirtFresh && instanceRunning,
		&dynamicMetrics,
	)
	var netRatesAvailable, conntrackAvailable bool
	netPPS, netDropRate, outboundSignal, inboundSignal, maxConntrackFlows, netRatesAvailable, conntrackAvailable = mc.collectDomainNetworkAndConntrack(
		meta,
		stat,
		now,
		domain,
		serverName,
		instanceUUID,
		projectUUID,
		projectName,
		userUUID,
		instanceRunning,
		fixedIPs,
		connAgg,
		ipSet,
		hostIPs,
		hostConntrackMax,
		conntrackFresh,
		libvirtFresh,
		&dynamicMetrics,
	)
	intelCombined, threatAvailable := mc.collectDomainThreatSignals(
		connAgg,
		ipSet,
		domain,
		serverName,
		instanceUUID,
		projectUUID,
		projectName,
		userUUID,
		conntrackFresh,
		&dynamicMetrics,
	)
	cpuPRaw := clamp01(cpuPressure)
	cpuConf := 1.0
	cpuImpact := clamp01(math.Log1p(float64(vcpuCount)) / math.Log1p(16.0))
	memPRaw := clamp01(resourceMemSeverity / 100.0)
	memConf := 0.0
	if memMB > 0 && guestUsedAvailable {
		memConf = 1.0
	} else if memMB > 0 && memPressureAvailable {
		memConf = 0.5
	}
	memImpact := clamp01(math.Log1p(float64(memMB)) / math.Log1p(32768.0))
	diskPRaw := clamp01(maxDiskIOSignal / 100.0)
	diskConf := clamp01(maxDiskActivity)
	diskImpact := diskConf
	const basePPS = 1000.0
	dropConf := clamp01(netPPS / basePPS)
	ctRatio := 0.0
	ctPressure := 0.0
	ctSourceAvailable := conntrackAvailable && hostConntrackMaxAvailable && hostConntrackMax > 0
	if ctSourceAvailable {
		ctRatio = float64(maxConntrackFlows) / float64(hostConntrackMax)
		if ctRatio > 0.01 {
			ctPressure = clamp01((ctRatio - 0.01) / (0.10 - 0.01))
		}
	}
	dropPressure := 0.0
	if netDropRate > 0.0001 {
		dropPressure = clamp01(math.Log10(netDropRate/0.0001) / math.Log10(0.01/0.0001))
	}
	dropImpact := clamp01(math.Log1p(netPPS) / math.Log1p(20000.0))
	ctImpact := clamp01(ctRatio / 0.10)
	netPRaw := dropPressure
	netConf := dropConf
	netImpact := dropImpact
	projectedSeverity := func(pressure, confidence, impact float64) float64 {
		return math.Pow(clamp01(pressure)*clamp01(confidence), 2) * clamp01(impact)
	}
	dropProjected := projectedSeverity(dropPressure, dropConf, dropImpact)
	ctProjected := projectedSeverity(ctPressure, 1.0, ctImpact)
	if ctSourceAvailable && (ctProjected > dropProjected ||
		(ctProjected == dropProjected && ctPressure > dropPressure)) {
		netPRaw = ctPressure
		netConf = 1.0
		netImpact = ctImpact
	}
	var resOut resourceV2Output
	var resState *resourceV2State
	if instanceRunning {
		resOut, resState = mc.computeResourceV2(instanceUUID, resourceV2Input{
			Now:          now,
			CpuAvailable: cpuAvailable, CpuPRaw: cpuPRaw, CpuConf: cpuConf, CpuImpact: cpuImpact,
			MemAvailable: memPressureAvailable && memMB > 0, MemPRaw: memPRaw, MemConf: memConf, MemImpact: memImpact,
			DiskAvailable: diskAvailable, DiskPRaw: diskPRaw, DiskConf: diskConf, DiskImpact: diskImpact,
			NetAvailable: netRatesAvailable || ctSourceAvailable, NetPRaw: netPRaw, NetConf: netConf, NetImpact: netImpact,
		})
		mc.maybeLogResourceV2Event(domain, serverName, instanceUUID, projectUUID, projectName, userUUID, resOut, resState)
	}
	resourceSeverity := 0.0
	if instanceRunning && resOut.Available {
		resourceSeverity = resOut.OverallFinal
	}
	behaviorDataAvailable := instanceRunning && connAgg != nil && len(fixedIPs) > 0
	behaviorSignal, behaviorAvailable := combineBehaviorSignals(
		outboundSignal,
		inboundSignal,
		mc.cm.outboundBehaviorEnabled && behaviorDataAvailable,
		mc.cm.inboundBehaviorEnabled && behaviorDataAvailable,
	)
	behavior01 := clamp01(behaviorSignal)
	behaviorScore := behavior01 * 100.0
	threatListSeverity := intelCombined * 100.0
	attentionSeverity := attentionSeverityWeighted(
		mc.scoring,
		resourceSeverity,
		instanceRunning && resOut.Available,
		behaviorScore,
		behaviorAvailable,
		threatListSeverity,
		threatAvailable,
	)
	attentionAvailable := attentionInputsAvailable(mc.scoring, instanceRunning && resOut.Available, behaviorAvailable, threatAvailable)
	if resOut.Available {
		dynamicMetrics = append(dynamicMetrics, prometheus.MustNewConstMetric(mc.instanceResourceSeverityDesc, prometheus.GaugeValue, resourceSeverity, domain, serverName, instanceUUID, projectUUID, projectName, userUUID))
	}
	if resOut.CPU.Available {
		dynamicMetrics = append(dynamicMetrics, prometheus.MustNewConstMetric(mc.instanceResourceCpuSeverityDesc, prometheus.GaugeValue, resOut.CPU.Sev, domain, serverName, instanceUUID, projectUUID, projectName, userUUID))
	}
	if resOut.MEM.Available {
		dynamicMetrics = append(dynamicMetrics, prometheus.MustNewConstMetric(mc.instanceResourceMemSeverityDesc, prometheus.GaugeValue, resOut.MEM.Sev, domain, serverName, instanceUUID, projectUUID, projectName, userUUID))
	}
	if resOut.DISK.Available {
		dynamicMetrics = append(dynamicMetrics, prometheus.MustNewConstMetric(mc.instanceResourceDiskSeverityDesc, prometheus.GaugeValue, resOut.DISK.Sev, domain, serverName, instanceUUID, projectUUID, projectName, userUUID))
	}
	if resOut.NET.Available {
		dynamicMetrics = append(dynamicMetrics, prometheus.MustNewConstMetric(mc.instanceResourceNetSeverityDesc, prometheus.GaugeValue, resOut.NET.Sev, domain, serverName, instanceUUID, projectUUID, projectName, userUUID))
	}
	if threatAvailable {
		dynamicMetrics = append(dynamicMetrics, prometheus.MustNewConstMetric(mc.instanceThreatListSeverityDesc, prometheus.GaugeValue, threatListSeverity, domain, serverName, instanceUUID, projectUUID, projectName, userUUID))
	}
	if attentionAvailable {
		dynamicMetrics = append(dynamicMetrics, prometheus.MustNewConstMetric(mc.instanceAttentionSeverityDesc, prometheus.GaugeValue, attentionSeverity, domain, serverName, instanceUUID, projectUUID, projectName, userUUID))
	}
	if behaviorAvailable {
		dynamicMetrics = append(dynamicMetrics, prometheus.MustNewConstMetric(mc.instanceBehaviorSeverityDesc, prometheus.GaugeValue, behaviorScore, domain, serverName, instanceUUID, projectUUID, projectName, userUUID))
	}
	if agg != nil {
		agg.metrics = append(agg.metrics, dynamicMetrics...)
	}
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
) (float64, float64, float64, float64, int, bool, bool) {

	var rxPktsTotal, txPktsTotal, rxDropTotal, txDropTotal uint64
	knownIfaces := make(map[string]struct{}, len(meta.Interfaces))
	for _, kn := range meta.Interfaces {
		knownIfaces[kn] = struct{}{}
	}

	matchedIfaces := 0
	netCountersComplete := true
	addAggregateCounter := func(total *uint64, value uint64) {
		if ^uint64(0)-*total < value {
			*total = ^uint64(0)
			netCountersComplete = false
			return
		}
		*total += value
	}
	seenIfaces := make(map[string]struct{}, len(stat.Nets))
	for _, iface := range stat.Nets {
		if _, ok := knownIfaces[iface.Name]; !ok {
			continue
		}
		if _, duplicate := seenIfaces[iface.Name]; duplicate {
			continue
		}
		seenIfaces[iface.Name] = struct{}{}
		matchedIfaces++

		if iface.RxPktsPresent {
			addAggregateCounter(&rxPktsTotal, iface.RxPkts)
		} else {
			netCountersComplete = false
		}
		if iface.TxPktsPresent {
			addAggregateCounter(&txPktsTotal, iface.TxPkts)
		} else {
			netCountersComplete = false
		}
		if iface.RxDropPresent {
			addAggregateCounter(&rxDropTotal, iface.RxDrop)
		} else {
			netCountersComplete = false
		}
		if iface.TxDropPresent {
			addAggregateCounter(&txDropTotal, iface.TxDrop)
		} else {
			netCountersComplete = false
		}

		netStats := []struct {
			present bool
			val     float64
			desc    *prometheus.Desc
		}{
			{iface.RxBytesPresent, roundToFiveDecimals(float64(iface.RxBytes) * bytesToGigabytes), mc.im.instanceNetRxGbytesTotalDesc},
			{iface.TxBytesPresent, roundToFiveDecimals(float64(iface.TxBytes) * bytesToGigabytes), mc.im.instanceNetTxGbytesTotalDesc},
			{iface.RxPktsPresent, float64(iface.RxPkts), mc.im.instanceNetRxPacketsTotalDesc},
			{iface.TxPktsPresent, float64(iface.TxPkts), mc.im.instanceNetTxPacketsTotalDesc},
			{iface.RxErrsPresent, float64(iface.RxErrs), mc.im.instanceNetRxErrorsTotalDesc},
			{iface.TxErrsPresent, float64(iface.TxErrs), mc.im.instanceNetTxErrorsTotalDesc},
			{iface.RxDropPresent, float64(iface.RxDrop), mc.im.instanceNetRxDroppedTotalDesc},
			{iface.TxDropPresent, float64(iface.TxDrop), mc.im.instanceNetTxDroppedTotalDesc},
		}

		for _, s := range netStats {
			if s.present {
				*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(s.desc, prometheus.CounterValue, s.val, domain, serverName, instanceUUID, projectUUID, projectName, userUUID, iface.Name))
			}
		}
	}

	netPPS := 0.0
	netDropRate := 0.0
	netRatesAvailable := false
	completeInterfaceSet := matchedIfaces > 0 &&
		matchedIfaces == len(knownIfaces) &&
		matchedIfaces == len(stat.Nets) &&
		(!stat.NetCountPresent || stat.NetCount == uint64(matchedIfaces))
	if instanceRunning && libvirtFresh && completeInterfaceSet && netCountersComplete {
		interfaceNames := make([]string, 0, len(seenIfaces))
		for name := range seenIfaces {
			interfaceNames = append(interfaceNames, name)
		}
		sort.Strings(interfaceNames)
		interfaceSet := strings.Join(interfaceNames, "\x00")
		pp, dr, droppedPPS, valid := mc.im.calculateNetRatesForInterfaceSet(instanceUUID, interfaceSet, rxPktsTotal, txPktsTotal, rxDropTotal, txDropTotal, now)
		netPPS = pp + droppedPPS
		netDropRate = dr
		netRatesAvailable = valid
	}

	outboundSignal := 0.0
	inboundSignal := 0.0
	maxConntrackFlows := 0

	conntrackAvailable := instanceRunning && conntrackFresh && connAgg != nil && len(fixedIPs) > 0
	if instanceRunning && connAgg != nil && len(fixedIPs) > 0 {
		outboundSignal, inboundSignal, maxConntrackFlows = mc.cm.calculateConntrackMetrics(fixedIPs, connAgg, ipSet, hostIPs, hostConntrackMax, conntrackFresh, domain, serverName, instanceUUID, projectUUID, projectName, userUUID, dynamicMetrics)
	}

	return netPPS, netDropRate, outboundSignal, inboundSignal, maxConntrackFlows, netRatesAvailable, conntrackAvailable
}
