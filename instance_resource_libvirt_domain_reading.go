package main

import (
	libvirt "github.com/digitalocean/go-libvirt"
	"github.com/prometheus/client_golang/prometheus"
	"sort"
	"strconv"
	"strings"
	"time"
)

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
	if !libvirtFresh {
		return
	}
	mc.libvirtMu.Lock()
	conn := mc.libvirtConn
	mc.libvirtMu.Unlock()
	meta, err := mc.im.getDomainMeta(record.Dom, conn)
	if err != nil {
		logCollectorMetric.Error("domain_meta_failed", "err", err)
		return
	}
	mc.collectDomainMetricsWithMetadata(
		record,
		meta,
		connAgg,
		hostIPs,
		agg,
		hostConntrackMax,
		hostConntrackMaxAvailable,
		conntrackFresh,
	)
}

func (mc *MetricsCollector) collectDomainMetricsWithMetadata(
	record libvirt.DomainStatsRecord,
	meta *DomainStatic,
	connAgg *ConntrackAgg,
	hostIPs map[string]struct{},
	agg *hostAgg,
	hostConntrackMax uint64,
	hostConntrackMaxAvailable bool,
	conntrackFresh bool,
) {
	if meta == nil {
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
	stateCode := stat.State
	stateDesc := strings.ToLower(libvirt.DomainState(stateCode).String())
	stateDesc = strings.TrimPrefix(stateDesc, "vir_domain_")
	stateDesc = strings.TrimPrefix(stateDesc, "domain")
	stateDesc = strings.Trim(stateDesc, "_")
	instanceStateKnown := stat.StatePresent
	instanceRunning := instanceStateKnown && stateCode == int(libvirt.DomainRunning)
	if instanceRunning {
		if mc.im.observeInstanceResourceGeneration(instanceUUID, record.Dom.ID, stat.CpuTime, stat.CpuTimePresent) {
			mc.resetResourceV2ForTransition(instanceUUID)
			mc.cm.resetBehaviorStateForInstance(instanceUUID)
			mc.resetThreatStateForInstance(instanceUUID)
		}
	} else if instanceStateKnown {
		// A known stopped/paused state is an authoritative lifecycle boundary.
		// A missing state field is only missing telemetry and must retain/age the
		// last complete axes under the normal bounded policy.
		mc.im.resetInstanceResourceSamples(instanceUUID)
		mc.resetResourceV2ForTransition(instanceUUID)
		mc.resetThreatStateForInstance(instanceUUID)
	}
	behaviorLifecycleNow := mc.cm.conntrackNow()
	if conntrackFresh {
		behaviorLifecycleNow = conntrackObservationTime(connAgg, behaviorLifecycleNow)
	}
	behaviorLifecycleRecovered := mc.cm.observeBehaviorInstanceLifecycle(instanceUUID, instanceStateKnown, instanceRunning, behaviorLifecycleNow)
	recoveryShift := mc.cm.takeBehaviorInstanceRecoveryShiftSeconds(instanceUUID)
	mc.tm.shiftThreatEventClockForInstance(instanceUUID, recoveryShift)
	dimensionStats := stat
	if !instanceRunning {
		// Do not let terminal-state telemetry select the authority mode for the
		// next runtime generation. Its dimension cache was just reset above.
		dimensionStats = nil
	}
	vcpuCount, vcpuDimensionKnown, vcpuDimensionFresh, memMB, memDimensionKnown, memDimensionFresh := mc.im.resolveResourceDimensions(instanceUUID, meta.VCPUCount, meta.MemMB, dimensionStats)
	rootType := meta.RootType
	createdAt := meta.CreatedAt
	metadataVersion := meta.MetadataVersion
	now := time.Now()
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
	var memAvailable bool
	var memSources []string
	guestUsedMB, _, memAvailable, memSources = mc.collectDomainMemoryMetricsWithSources(
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
		instanceRunning && memDimensionFresh,
		&dynamicMetrics,
	)
	_ = guestUsedMB
	diskCountDomain := 0
	var diskAvailable bool
	var diskIdentityKnown bool
	var diskIdentity string
	var diskSources []string
	diskCountDomain, diskAvailable, diskIdentity, diskSources, diskIdentityKnown = mc.collectDomainDiskMetricsWithSources(
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
		&dynamicMetrics,
	)
	if agg != nil && diskCountDomain > 0 {
		agg.disks += diskCountDomain
	}
	_, cpuAvailable, cpuSources := mc.collectDomainCPUMetricsWithSources(
		stat,
		now,
		domain,
		serverName,
		instanceUUID,
		projectUUID,
		projectName,
		userUUID,
		vcpuCount,
		instanceRunning && vcpuDimensionFresh,
		&dynamicMetrics,
	)
	var netRatesAvailable, conntrackAvailable bool
	var netIdentity string
	var netSources []string
	_, _, _, netRatesAvailable, conntrackAvailable, netIdentity, netSources = mc.collectDomainNetworkAndConntrackWithSources(
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
		true,
		&dynamicMetrics,
	)
	mc.collectDomainThreatSignals(
		connAgg,
		ipSet,
		domain,
		serverName,
		instanceUUID,
		projectUUID,
		projectName,
		userUUID,
		conntrackFresh,
		conntrackFresh && instanceRunning,
		instanceRunning || !instanceStateKnown,
		&dynamicMetrics,
	)
	if behaviorLifecycleRecovered && conntrackFresh && connAgg != nil && len(fixedIPs) > 0 {
		mc.cm.finishBehaviorInstanceRecovery(instanceUUID)
	}
	ctSourceAvailable := conntrackAvailable && hostConntrackMaxAvailable && hostConntrackMax > 0
	if ctSourceAvailable {
		netSources = append(netSources, "conntrack")
		sort.Strings(netSources)
	}
	resOut, _ := mc.computeResourceV2(instanceUUID, resourceV2Input{
		Now:          now,
		CpuAvailable: instanceRunning && vcpuDimensionFresh && cpuAvailable,
		CpuSources:   cpuSources, CpuIdentity: "vcpu:" + strconv.Itoa(vcpuCount), CpuIdentityKnown: instanceRunning && vcpuDimensionKnown,
		MemAvailable: instanceRunning && memDimensionFresh && memAvailable && memMB > 0,
		MemSources:   memSources, MemIdentity: "memory:" + strconv.Itoa(memMB), MemIdentityKnown: instanceRunning && memDimensionKnown,
		DiskAvailable: instanceRunning && diskAvailable,
		DiskSources:   diskSources, DiskIdentity: diskIdentity, DiskIdentityKnown: instanceRunning && diskIdentityKnown,
		NetAvailable: instanceRunning && (netRatesAvailable || ctSourceAvailable),
		NetSources:   netSources, NetIdentity: netIdentity, NetIdentityKnown: instanceRunning,
	})
	appendInstanceResourceAxisHealthMetrics(mc, &dynamicMetrics, resOut, domain, serverName, instanceUUID, projectUUID, projectName, userUUID)

	if agg != nil {
		agg.metrics = append(agg.metrics, dynamicMetrics...)
	}
}

func (mc *MetricsCollector) collectDomainNetworkAndConntrackWithSources(
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
) (float64, float64, int, bool, bool, string, []string) {

	knownIfaces := make(map[string]struct{}, len(meta.Interfaces))
	for _, kn := range meta.Interfaces {
		knownIfaces[kn] = struct{}{}
	}
	networkIdentity := resourceNetworkIdentity(meta, fixedIPs)

	matchedIfaces := 0
	netCountersComplete := true
	seenIfaces := make(map[string]struct{}, len(stat.Nets))
	interfaceCounters := make(map[string]netDeviceCounters, len(stat.Nets))
	for _, iface := range stat.Nets {
		if _, ok := knownIfaces[iface.Name]; !ok {
			continue
		}
		if _, duplicate := seenIfaces[iface.Name]; duplicate {
			continue
		}
		seenIfaces[iface.Name] = struct{}{}
		matchedIfaces++

		if !iface.RxPktsPresent || !iface.TxPktsPresent || !iface.RxDropPresent || !iface.TxDropPresent {
			netCountersComplete = false
		} else {
			interfaceCounters[iface.Name] = netDeviceCounters{
				rxPkts: iface.RxPkts,
				txPkts: iface.TxPkts,
				rxDrop: iface.RxDrop,
				txDrop: iface.TxDrop,
			}
		}

		netStats := []struct {
			present bool
			val     float64
			desc    *prometheus.Desc
		}{
			{iface.RxBytesPresent, float64(iface.RxBytes) * bytesToGigabytes, mc.im.instanceNetRxGbytesTotalDesc},
			{iface.TxBytesPresent, float64(iface.TxBytes) * bytesToGigabytes, mc.im.instanceNetTxGbytesTotalDesc},
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
	completeInterfaceSet := matchedIfaces == len(knownIfaces) &&
		matchedIfaces == len(stat.Nets) &&
		(!stat.NetCountPresent || stat.NetCount == uint64(matchedIfaces))
	if instanceRunning && libvirtFresh && completeInterfaceSet && netCountersComplete {
		pp, dr, droppedPPS, valid := mc.im.calculateNetRatesForInterfacesWithIdentity(instanceUUID, networkIdentity, interfaceCounters, now)
		netPPS = pp + droppedPPS
		netDropRate = dr
		netRatesAvailable = valid
	}

	maxConntrackFlows := 0

	conntrackAvailable := instanceRunning && conntrackFresh && connAgg != nil && len(fixedIPs) > 0
	behaviorCollectable := instanceRunning || mc.cm.behaviorInstanceStateFrozen(instanceUUID)
	if behaviorCollectable && connAgg != nil && len(fixedIPs) > 0 {
		maxConntrackFlows = mc.cm.calculateConntrackMetrics(fixedIPs, connAgg, ipSet, hostIPs, hostConntrackMax, conntrackFresh, domain, serverName, instanceUUID, projectUUID, projectName, userUUID, dynamicMetrics)
	}

	resourceSources := make([]string, 0, 1)
	if netRatesAvailable {
		resourceSources = append(resourceSources, "nic_drop")
	}
	return netPPS, netDropRate, maxConntrackFlows, netRatesAvailable, conntrackAvailable, networkIdentity, resourceSources
}

// resourceNetworkIdentity comes only from authoritative metadata. The same
// identity keys the rate baseline and the resource axis so a NIC, Neutron port,
// or fixed-IP replacement cannot bridge counters from two ownership epochs.
func resourceNetworkIdentity(meta *DomainStatic, fixedIPs []IP) string {
	parts := make(map[string]struct{}, len(meta.Interfaces)+len(fixedIPs)+len(meta.PortUUIDs))
	for _, name := range meta.Interfaces {
		if name = strings.TrimSpace(name); name != "" {
			parts["if:"+name] = struct{}{}
		}
	}
	for _, ip := range fixedIPs {
		family := strings.TrimSpace(ip.Family)
		address := strings.TrimSpace(ip.Address)
		if address != "" {
			parts["ip:"+family+":"+address] = struct{}{}
		}
	}
	for _, portUUID := range meta.PortUUIDs {
		if portUUID = strings.TrimSpace(portUUID); portUUID != "" {
			parts["port:"+portUUID] = struct{}{}
		}
	}
	identityParts := make([]string, 0, len(parts))
	for part := range parts {
		identityParts = append(identityParts, part)
	}
	sort.Strings(identityParts)
	return strings.Join(identityParts, "\x00")
}
