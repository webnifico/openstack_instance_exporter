package main

import (
	libvirt "github.com/digitalocean/go-libvirt"
	"github.com/prometheus/client_golang/prometheus"
	"math"
	"strconv"
	"strings"
	"time"
)

func parseLibvirtStats(params []libvirt.TypedParam) *ParsedStats {
	s := &ParsedStats{
		Vcpus: make(map[int]*VcpuStat),
		Disks: make(map[int]*DiskStat),
		Nets:  make(map[int]*NetStat),
	}

	for _, p := range params {
		field := p.Field
		var uVal uint64
		var strVal string

		switch v := p.Value.I.(type) {
		case uint64:
			uVal = v
		case int64:
			uVal = uint64(v)
		case uint32:
			uVal = uint64(v)
		case int32:
			uVal = uint64(v)
		case int:
			uVal = uint64(v)
		case string:
			strVal = v
		case bool:
			if v {
				uVal = 1
			}
		}

		if field == "state.state" {
			if i, ok := p.Value.I.(int32); ok {
				s.State = int(i)
			} else if i, ok := p.Value.I.(int); ok {
				s.State = i
			}
		}

		if field == "cpu.time" {
			s.CpuTime = uVal
		}
		if field == "cpu.user" {
			s.CpuUser = uVal
		}
		if field == "cpu.system" {
			s.CpuSystem = uVal
		}

		if field == "balloon.maximum" {
			s.MemMax = uVal
		}
		if field == "balloon.current" {
			s.MemCur = uVal
		}
		if field == "balloon.usable" {
			s.MemUsable = uVal
		}
		if field == "balloon.rss" {
			s.MemRss = uVal
		}
		if field == "balloon.swap_in" {
			s.SwapIn = uVal
		}
		if field == "balloon.swap_out" {
			s.SwapOut = uVal
		}
		if field == "balloon.major_fault" {
			s.MajorFault = uVal
		}
		if field == "balloon.minor_fault" {
			s.MinorFault = uVal
		}

		if strings.HasPrefix(field, "vcpu.") {
			parts := strings.Split(field, ".")
			if len(parts) >= 3 {
				idx, err := strconv.Atoi(parts[1])
				if err != nil || idx < 0 {
					continue
				}
				if _, ok := s.Vcpus[idx]; !ok {
					s.Vcpus[idx] = &VcpuStat{}
				}
				v := s.Vcpus[idx]
				key := parts[2]
				switch key {
				case "state":
					v.State = uVal
				case "time":
					v.Time = uVal
				case "wait":
					v.Wait = uVal
				case "delay":
					v.Delay = uVal
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
				if _, ok := s.Disks[idx]; !ok {
					s.Disks[idx] = &DiskStat{}
				}
				d := s.Disks[idx]
				key := parts[2]

				if key == "name" {
					d.Name = strVal
					continue
				}

				if len(parts) >= 4 {
					subKey := parts[3]
					switch key {
					case "rd":
						if subKey == "reqs" {
							d.RdReqs = uVal
						}
						if subKey == "bytes" {
							d.RdBytes = uVal
						}
						if subKey == "times" {
							d.RdTime = uVal
						}
					case "wr":
						if subKey == "reqs" {
							d.WrReqs = uVal
						}
						if subKey == "bytes" {
							d.WrBytes = uVal
						}
						if subKey == "times" {
							d.WrTime = uVal
						}
					case "fl":
						if subKey == "reqs" {
							d.FlReqs = uVal
						}
						if subKey == "times" {
							d.FlTime = uVal
						}
					}
				} else {
					if key == "capacity" {
						d.Capacity = uVal
					}
					if key == "allocation" {
						d.Allocation = uVal
					}
					if key == "physical" {
						d.Physical = uVal
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
				if _, ok := s.Nets[idx]; !ok {
					s.Nets[idx] = &NetStat{}
				}
				n := s.Nets[idx]
				key := parts[2]

				if key == "name" {
					n.Name = strVal
					continue
				}

				if len(parts) >= 4 {
					subKey := parts[3]
					switch key {
					case "rx":
						if subKey == "bytes" {
							n.RxBytes = uVal
						}
						if subKey == "pkts" {
							n.RxPkts = uVal
						}
						if subKey == "errs" {
							n.RxErrs = uVal
						}
						if subKey == "drop" {
							n.RxDrop = uVal
						}
					case "tx":
						if subKey == "bytes" {
							n.TxBytes = uVal
						}
						if subKey == "pkts" {
							n.TxPkts = uVal
						}
						if subKey == "errs" {
							n.TxErrs = uVal
						}
						if subKey == "drop" {
							n.TxDrop = uVal
						}
					}
				}
			}
		}
	}
	return s
}
func (mc *MetricsCollector) collectDomainMetrics(
	record libvirt.DomainStatsRecord,
	connAgg *ConntrackAgg,
	hostIPs map[string]struct{},
	agg *hostAgg,
	hostConntrackMax uint64,
) {
	mc.libvirtMu.Lock()
	conn := mc.libvirtConn
	mc.libvirtMu.Unlock()
	if conn == nil {
		return
	}
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
	vcpuCount := meta.VCPUCount
	if len(stat.Vcpus) > 0 {
		vcpuCount = len(stat.Vcpus)
	}
	memMB := meta.MemMB
	if stat.MemMax > 0 {
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
	fixedIPs := meta.FixedIPs
	ipSet := make(map[string]struct{}, len(fixedIPs))
	for _, ip := range fixedIPs {
		ipSet[ip.Address] = struct{}{}
	}
	if agg != nil {
		agg.fixedIPs += len(ipSet)
		if projectName == "" {
			projectName = "unknown"
		}
		agg.projects[projectName] = struct{}{}
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
	instanceRunning := stateCode == int(libvirt.DomainRunning)
	dynamicMetrics = append(dynamicMetrics,
		prometheus.MustNewConstMetric(
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
		),
		prometheus.MustNewConstMetric(
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
		),
	)
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
	guestUsedMB, resourceMemSeverity = mc.collectDomainMemoryMetrics(
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
		&dynamicMetrics,
	)
	diskCountDomain := 0
	diskCountDomain, maxDiskIOSignal, maxDiskActivity = mc.collectDomainDiskMetrics(
		meta,
		stat,
		now,
		domain,
		serverName,
		instanceUUID,
		projectUUID,
		projectName,
		userUUID,
		&dynamicMetrics,
	)
	if agg != nil && diskCountDomain > 0 {
		agg.disks += diskCountDomain
	}
	cpuPressure := mc.collectDomainCPUMetrics(
		stat,
		domain,
		serverName,
		instanceUUID,
		projectUUID,
		projectName,
		userUUID,
		vcpuCount,
		&dynamicMetrics,
	)
	netPPS, netDropRate, outboundSignal, inboundSignal, maxConntrackFlows = mc.collectDomainNetworkAndConntrack(
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
		&dynamicMetrics,
	)
	intelCombined := mc.collectDomainThreatSignals(
		connAgg,
		ipSet,
		domain,
		serverName,
		instanceUUID,
		projectUUID,
		projectName,
		userUUID,
		&dynamicMetrics,
	)
	cpuPRaw := clamp01(cpuPressure)
	cpuConf := 1.0
	cpuImpact := clamp01(math.Log1p(float64(vcpuCount)) / math.Log1p(16.0))
	memPRaw := clamp01(resourceMemSeverity / 100.0)
	memConf := 0.0
	if memMB > 0 && guestUsedMB > 0 {
		memConf = 1.0
	} else if memMB > 0 {
		memConf = 0.5
	}
	memImpact := clamp01(math.Log1p(float64(memMB)) / math.Log1p(32768.0))
	diskPRaw := clamp01(maxDiskIOSignal / 100.0)
	diskConf := clamp01(maxDiskActivity)
	diskImpact := diskConf
	const basePPS = 1000.0
	dropConf := clamp01(netPPS / basePPS)
	ctConf := 0.0
	ctRatio := 0.0
	ctPressure := 0.0
	ctMax := hostConntrackMax
	if ctMax == 0 {
		ctMax = 200000
	}
	if maxConntrackFlows > 0 {
		ctRatio = float64(maxConntrackFlows) / float64(ctMax)
		ctConf = 1.0
		if ctRatio > 0.01 {
			ctPressure = clamp01((ctRatio - 0.01) / (0.10 - 0.01))
		}
	}
	dropPressure := 0.0
	if netDropRate > 0.0001 {
		dropPressure = clamp01(math.Log10(netDropRate/0.0001) / math.Log10(0.01/0.0001))
	}
	netPRaw := math.Max(dropPressure, ctPressure)
	netConf := math.Max(dropConf, ctConf)
	netImpact := clamp01(math.Log1p(netPPS) / math.Log1p(20000.0))
	if ctRatio > 0 {
		netImpact = math.Max(netImpact, clamp01(ctRatio/0.10))
	}
	var resOut resourceV2Output
	var resState *resourceV2State
	if instanceRunning {
		resOut, resState = mc.computeResourceV2(instanceUUID, resourceV2Input{
			Now:     now,
			CpuPRaw: cpuPRaw, CpuConf: cpuConf, CpuImpact: cpuImpact,
			MemPRaw: memPRaw, MemConf: memConf, MemImpact: memImpact,
			DiskPRaw: diskPRaw, DiskConf: diskConf, DiskImpact: diskImpact,
			NetPRaw: netPRaw, NetConf: netConf, NetImpact: netImpact,
		})
		mc.maybeLogResourceV2Event(domain, serverName, instanceUUID, projectUUID, projectName, userUUID, resOut, resState)
	} else {
		resOut, _ = mc.computeResourceV2(instanceUUID, resourceV2Input{Now: now})
	}
	resourceSeverity := 0.0
	if instanceRunning {
		resourceSeverity = resOut.OverallFinal
	}
	behaviorSignal := 0.0
	behaviorWeightOutbound := 0.0
	behaviorWeightInbound := 0.0
	if mc.cm.outboundBehaviorEnabled {
		behaviorWeightOutbound = 1.0
	}
	if mc.cm.inboundBehaviorEnabled {
		behaviorWeightInbound = 1.0
	}
	totalBehaviorWeight := behaviorWeightOutbound + behaviorWeightInbound
	if totalBehaviorWeight > 0 {
		behaviorSignal = (outboundSignal*behaviorWeightOutbound + inboundSignal*behaviorWeightInbound) / totalBehaviorWeight
	}
	behavior01 := clamp01(behaviorSignal)
	behaviorScore := behavior01 * 100.0
	threatListSeverity := intelCombined * 100.0
	wRes := mc.scoring.ResourceWeight
	wBeh := mc.scoring.BehaviorWeight
	wList := mc.scoring.ThreatWeight
	attentionSeverity := 0.0
	totalW := wRes + wBeh + wList
	if totalW > 0 {
		attentionSeverity = (resourceSeverity*wRes + behaviorScore*wBeh + threatListSeverity*wList) / totalW
	}
	dynamicMetrics = append(dynamicMetrics,
		prometheus.MustNewConstMetric(mc.instanceResourceSeverityDesc, prometheus.GaugeValue, resourceSeverity, domain, serverName, instanceUUID, projectUUID, projectName, userUUID),
		prometheus.MustNewConstMetric(mc.instanceResourceCpuSeverityDesc, prometheus.GaugeValue, resOut.CPU.Sev, domain, serverName, instanceUUID, projectUUID, projectName, userUUID),
		prometheus.MustNewConstMetric(mc.instanceResourceMemSeverityDesc, prometheus.GaugeValue, resOut.MEM.Sev, domain, serverName, instanceUUID, projectUUID, projectName, userUUID),
		prometheus.MustNewConstMetric(mc.instanceResourceDiskSeverityDesc, prometheus.GaugeValue, resOut.DISK.Sev, domain, serverName, instanceUUID, projectUUID, projectName, userUUID),
		prometheus.MustNewConstMetric(mc.instanceResourceNetSeverityDesc, prometheus.GaugeValue, resOut.NET.Sev, domain, serverName, instanceUUID, projectUUID, projectName, userUUID),
		prometheus.MustNewConstMetric(mc.instanceThreatListSeverityDesc, prometheus.GaugeValue, threatListSeverity, domain, serverName, instanceUUID, projectUUID, projectName, userUUID),
		prometheus.MustNewConstMetric(mc.instanceAttentionSeverityDesc, prometheus.GaugeValue, attentionSeverity, domain, serverName, instanceUUID, projectUUID, projectName, userUUID),
		prometheus.MustNewConstMetric(mc.instanceBehaviorSeverityDesc, prometheus.GaugeValue, behaviorScore, domain, serverName, instanceUUID, projectUUID, projectName, userUUID),
	)
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
	dynamicMetrics *[]prometheus.Metric,
) (float64, float64, float64, float64, int) {

	var rxPktsTotal, txPktsTotal, rxDropTotal, txDropTotal uint64
	knownIfaces := make(map[string]struct{}, len(meta.Interfaces))
	for _, kn := range meta.Interfaces {
		knownIfaces[kn] = struct{}{}
	}

	for _, iface := range stat.Nets {
		if _, ok := knownIfaces[iface.Name]; !ok {
			continue
		}

		rxPktsTotal += iface.RxPkts
		txPktsTotal += iface.TxPkts
		rxDropTotal += iface.RxDrop
		txDropTotal += iface.TxDrop

		netStats := []struct {
			val  float64
			desc *prometheus.Desc
		}{
			{roundToFiveDecimals(float64(iface.RxBytes) * bytesToGigabytes), mc.im.instanceNetRxGbytesTotalDesc},
			{roundToFiveDecimals(float64(iface.TxBytes) * bytesToGigabytes), mc.im.instanceNetTxGbytesTotalDesc},
			{float64(iface.RxPkts), mc.im.instanceNetRxPacketsTotalDesc},
			{float64(iface.TxPkts), mc.im.instanceNetTxPacketsTotalDesc},
			{float64(iface.RxErrs), mc.im.instanceNetRxErrorsTotalDesc},
			{float64(iface.TxErrs), mc.im.instanceNetTxErrorsTotalDesc},
			{float64(iface.RxDrop), mc.im.instanceNetRxDroppedTotalDesc},
			{float64(iface.TxDrop), mc.im.instanceNetTxDroppedTotalDesc},
		}

		for _, s := range netStats {
			*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(s.desc, prometheus.CounterValue, s.val, domain, serverName, instanceUUID, projectUUID, projectName, userUUID, iface.Name))
		}
	}

	netPPS := 0.0
	netDropRate := 0.0
	if instanceRunning {
		pp, dr, _ := mc.im.calculateNetRates(instanceUUID, rxPktsTotal, txPktsTotal, rxDropTotal, txDropTotal, now)
		netPPS = pp
		netDropRate = dr
	}

	outboundSignal := 0.0
	inboundSignal := 0.0
	maxConntrackFlows := 0

	if instanceRunning && connAgg != nil && len(fixedIPs) > 0 {
		outboundSignal, inboundSignal, maxConntrackFlows = mc.cm.calculateConntrackMetrics(fixedIPs, connAgg, ipSet, hostIPs, hostConntrackMax, domain, serverName, instanceUUID, projectUUID, projectName, userUUID, dynamicMetrics)
	}

	return netPPS, netDropRate, outboundSignal, inboundSignal, maxConntrackFlows
}
