package main

import (
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"libvirt.org/go/libvirt"
)

// -----------------------------------------------------------------------------
// Prometheus Metric Initializers
// -----------------------------------------------------------------------------

func initHostMetrics(mc *MetricsCollector) {
	mc.hostMemTotalMBDesc = prometheus.NewDesc("oie_host_mem_mb_total", "Total physical memory on this hypervisor (MB)", nil, nil)
	mc.hostLibvirtActiveVMsDesc = prometheus.NewDesc("oie_host_libvirt_active_vms", "Active libvirt domains on this hypervisor", nil, nil)
	mc.hostCpuActiveVcpusDesc = prometheus.NewDesc("oie_host_cpu_active_vcpus", "Sum of vCPUs allocated to active domains on this hypervisor", nil, nil)
	mc.hostActiveDisksDesc = prometheus.NewDesc("oie_host_active_disks", "Count of disks across active domains on this hypervisor", nil, nil)
	mc.hostActiveFixedIPsDesc = prometheus.NewDesc("oie_host_active_fixed_ips", "Count of fixed IPs across active domains on this hypervisor", nil, nil)
	mc.hostActiveProjectsDesc = prometheus.NewDesc("oie_host_active_projects", "Unique project names seen in active domains on this hypervisor", nil, nil)
	mc.hostCpuThreadsDesc = prometheus.NewDesc("oie_host_cpu_threads", "Logical CPU thread count on this hypervisor", nil, nil)
	mc.hostCollectionErrorsTotalDesc = prometheus.NewDesc("oie_host_collection_errors_total", "Total background collection errors on this host", nil, nil)
	mc.hostCollectionCycleDurationSecondsDesc = prometheus.NewDesc("oie_host_collection_cycle_duration_seconds", "Duration of last background collection cycle on this host (seconds)", nil, nil)
	mc.hostCollectionCycleLagSecondsDesc = prometheus.NewDesc("oie_host_collection_cycle_lag_seconds", "Seconds since prior background collection cycle ended on this host", nil, nil)
	mc.hostLibvirtListDurationSecondsDesc = prometheus.NewDesc("oie_host_libvirt_list_duration_seconds", "Seconds spent listing active libvirt domains on this host", nil, nil)
	mc.hostConntrackReadDurationSecondsDesc = prometheus.NewDesc("oie_host_conntrack_read_duration_seconds", "Seconds spent reading conntrack tables on this host", nil, nil)
	mc.hostGoHeapAllocBytesDesc = prometheus.NewDesc("oie_host_go_heap_alloc_bytes", "Go heap allocation of the exporter process in bytes on this host", nil, nil)
	mc.hostConntrackEntriesDesc = prometheus.NewDesc("oie_host_conntrack_entries", "Conntrack entries observed in last snapshot on this host", nil, nil)
	mc.hostConntrackReadErrorsTotalDesc = prometheus.NewDesc("oie_host_conntrack_read_errors_total", "Conntrack read errors on this host", nil, nil)
	mc.hostConntrackMaxDesc = prometheus.NewDesc("oie_host_conntrack_max", "Configured maximum conntrack entries on this host", nil, nil)
	mc.hostConntrackUtilizationDesc = prometheus.NewDesc("oie_host_conntrack_utilization", "Conntrack table utilization (entries / max)", nil, nil)
	mc.hostCacheCleanupDurationSecondsDesc = prometheus.NewDesc("oie_host_cache_cleanup_duration_seconds", "Duration of last cache cleanup cycle on this host (seconds)", nil, nil)
}

func initInstanceMetrics(im *InstanceManager) {
	im.instanceInfoDesc = prometheus.NewDesc("oie_instance_info", "Static instance metadata (one series per active instance)", []string{"domain", "instance_uuid", "project_uuid", "project_name", "user_uuid", "user_name", "flavor", "vcpus", "mem_mb", "root_type", "created_at", "metadata_version"}, nil)
	im.instanceDiskReadAlertThresholdDesc = prometheus.NewDesc("oie_instance_disk_read_alert_threshold", "Disk read alert threshold", []string{"domain", "instance_uuid", "user_uuid", "project_uuid", "project_name", "disk_uuid", "disk_type", "disk_path"}, nil)
	im.instanceDiskWriteAlertThresholdDesc = prometheus.NewDesc("oie_instance_disk_write_alert_threshold", "Disk write alert threshold", []string{"domain", "instance_uuid", "user_uuid", "project_uuid", "project_name", "disk_uuid", "disk_type", "disk_path"}, nil)
	im.instanceDiskReadGbytesTotalDesc = prometheus.NewDesc("oie_instance_disk_read_gbytes_total", "Disk read gigabytes", []string{"domain", "instance_uuid", "user_uuid", "project_uuid", "project_name", "disk_uuid", "disk_type", "disk_path"}, nil)
	im.instanceDiskWriteGbytesTotalDesc = prometheus.NewDesc("oie_instance_disk_write_gbytes_total", "Disk write gigabytes", []string{"domain", "instance_uuid", "user_uuid", "project_uuid", "project_name", "disk_uuid", "disk_type", "disk_path"}, nil)
	im.instanceDiskReadRequestsTotalDesc = prometheus.NewDesc("oie_instance_disk_read_requests_total", "Disk read requests", []string{"domain", "instance_uuid", "user_uuid", "project_uuid", "project_name", "disk_uuid", "disk_type", "disk_path"}, nil)
	im.instanceDiskWriteRequestsTotalDesc = prometheus.NewDesc("oie_instance_disk_write_requests_total", "Disk write requests", []string{"domain", "instance_uuid", "user_uuid", "project_uuid", "project_name", "disk_uuid", "disk_type", "disk_path"}, nil)
	im.instanceDiskInfoDesc = prometheus.NewDesc("oie_instance_disk_info", "Static disk metadata (one series per disk per active instance)", []string{"domain", "instance_uuid", "project_uuid", "project_name", "user_uuid", "disk_uuid", "disk_type", "disk_path"}, nil)
	im.instanceCpuVcpuPercentDesc = prometheus.NewDesc("oie_instance_cpu_vcpu_percent", "CPU usage percentage per vCPU", []string{"domain", "instance_uuid", "user_uuid", "project_uuid", "project_name"}, nil)
	im.instanceCpuVcpuCountDesc = prometheus.NewDesc("oie_instance_cpu_vcpu_count", "Allocated vCPU count for this instance", []string{"domain", "instance_uuid", "user_uuid", "project_uuid", "project_name"}, nil)
	im.instanceMemAllocatedMBDesc = prometheus.NewDesc("oie_instance_mem_allocated_mb", "Allocated memory for this instance (MB)", []string{"domain", "instance_uuid", "user_uuid", "project_uuid", "project_name"}, nil)
	im.instanceMemUsedMBDesc = prometheus.NewDesc("oie_instance_mem_used_mb", "Guest-view used memory for this instance (MB) from balloon/unused stats", []string{"domain", "instance_uuid", "user_uuid", "project_uuid", "project_name"}, nil)
	im.instanceNetRxGbytesTotalDesc = prometheus.NewDesc("oie_instance_net_rx_gbytes_total", "Network receive gigabytes", []string{"domain", "interface", "instance_uuid", "user_uuid", "project_uuid", "project_name"}, nil)
	im.instanceNetTxGbytesTotalDesc = prometheus.NewDesc("oie_instance_net_tx_gbytes_total", "Network transmit gigabytes", []string{"domain", "interface", "instance_uuid", "user_uuid", "project_uuid", "project_name"}, nil)
	im.instanceNetRxPacketsTotalDesc = prometheus.NewDesc("oie_instance_net_rx_packets_total", "Network receive packets", []string{"domain", "interface", "instance_uuid", "user_uuid", "project_uuid", "project_name"}, nil)
	im.instanceNetTxPacketsTotalDesc = prometheus.NewDesc("oie_instance_net_tx_packets_total", "Network transmit packets", []string{"domain", "interface", "instance_uuid", "user_uuid", "project_uuid", "project_name"}, nil)
	im.instanceNetRxErrorsTotalDesc = prometheus.NewDesc("oie_instance_net_rx_errors_total", "Network receive errors", []string{"domain", "interface", "instance_uuid", "user_uuid", "project_uuid", "project_name"}, nil)
	im.instanceNetTxErrorsTotalDesc = prometheus.NewDesc("oie_instance_net_tx_errors_total", "Network transmit errors", []string{"domain", "interface", "instance_uuid", "user_uuid", "project_uuid", "project_name"}, nil)
	im.instanceNetRxDroppedTotalDesc = prometheus.NewDesc("oie_instance_net_rx_dropped_total", "Network receive dropped packets", []string{"domain", "interface", "instance_uuid", "user_uuid", "project_uuid", "project_name"}, nil)
	im.instanceNetTxDroppedTotalDesc = prometheus.NewDesc("oie_instance_net_tx_dropped_total", "Network transmit dropped packets", []string{"domain", "interface", "instance_uuid", "user_uuid", "project_uuid", "project_name"}, nil)
}

func initInstanceScoreMetrics(mc *MetricsCollector) {
	mc.instanceResourceScoreDesc = prometheus.NewDesc("oie_instance_resource_score", "Resource pressure score (0-100) combining CPU, memory, disk and network/conntrack", []string{"domain", "instance_uuid", "project_uuid", "project_name", "user_uuid"}, nil)
	mc.instanceThreatScoreDesc = prometheus.NewDesc("oie_instance_threat_score", "Threat/behavior score (0-100) combining outbound behavior and threat intel contacts", []string{"domain", "instance_uuid", "project_uuid", "project_name", "user_uuid"}, nil)
	mc.instanceAttentionScoreDesc = prometheus.NewDesc("oie_instance_attention_score", "Combined attention score (0-100) based on resource pressure and threat signals", []string{"domain", "instance_uuid", "project_uuid", "project_name", "user_uuid"}, nil)
}

func initConntrackMetrics(cm *ConntrackManager) {
	cm.instanceConntrackIPFlowsDesc = prometheus.NewDesc("oie_instance_conntrack_ip_flows", "Conntrack flow entries matched to this fixed IP (inbound + outbound)", []string{"domain", "instance_uuid", "ip", "family", "project_uuid", "project_name", "user_uuid"}, nil)
	cm.instanceConntrackIPFlowsInboundDesc = prometheus.NewDesc("oie_instance_conntrack_ip_flows_inbound", "Inbound conntrack flow entries matched to this fixed IP (VM as destination)", []string{"domain", "instance_uuid", "ip", "family", "project_uuid", "project_name", "user_uuid"}, nil)
	cm.instanceConntrackIPFlowsOutboundDesc = prometheus.NewDesc("oie_instance_conntrack_ip_flows_outbound", "Outbound conntrack flow entries matched to this fixed IP (VM as source)", []string{"domain", "instance_uuid", "ip", "family", "project_uuid", "project_name", "user_uuid"}, nil)
	cm.instanceOutboundUniqueRemotesDesc = prometheus.NewDesc("oie_instance_outbound_unique_remotes", "Outbound unique remote IPs for this fixed IP in the current interval", []string{"domain", "instance_uuid", "ip", "family", "project_uuid", "project_name", "user_uuid"}, nil)
	cm.instanceOutboundNewRemotesDesc = prometheus.NewDesc("oie_instance_outbound_new_remotes", "Outbound new remote IPs discovered since previous interval", []string{"domain", "instance_uuid", "ip", "family", "project_uuid", "project_name", "user_uuid"}, nil)
	cm.instanceOutboundFlowsDesc = prometheus.NewDesc("oie_instance_outbound_flows", "Outbound conntrack flows initiated by this fixed IP in the current interval", []string{"domain", "instance_uuid", "ip", "family", "project_uuid", "project_name", "user_uuid"}, nil)
	cm.instanceOutboundMaxFlowsSingleRemoteDesc = prometheus.NewDesc("oie_instance_outbound_max_flows_single_remote", "Maximum outbound flows to a single remote IP in the current interval", []string{"domain", "instance_uuid", "ip", "family", "project_uuid", "project_name", "user_uuid"}, nil)
	cm.instanceOutboundUniqueDstPortsDesc = prometheus.NewDesc("oie_instance_outbound_unique_dst_ports", "Outbound unique destination ports in the current interval", []string{"domain", "instance_uuid", "ip", "family", "project_uuid", "project_name", "user_uuid"}, nil)
	cm.instanceOutboundNewDstPortsDesc = prometheus.NewDesc("oie_instance_outbound_new_dst_ports", "Outbound new destination ports discovered since previous interval", []string{"domain", "instance_uuid", "ip", "family", "project_uuid", "project_name", "user_uuid"}, nil)
	cm.instanceOutboundMaxFlowsSingleDstPortDesc = prometheus.NewDesc("oie_instance_outbound_max_flows_single_dst_port", "Maximum outbound flows to a single destination port in the current interval", []string{"domain", "instance_uuid", "ip", "family", "project_uuid", "project_name", "user_uuid"}, nil)
	cm.instanceInboundUniqueRemotesDesc = prometheus.NewDesc("oie_instance_inbound_unique_remotes", "Inbound unique remote IPs for this fixed IP in the current interval", []string{"domain", "instance_uuid", "ip", "family", "project_uuid", "project_name", "user_uuid"}, nil)
	cm.instanceInboundNewRemotesDesc = prometheus.NewDesc("oie_instance_inbound_new_remotes", "Inbound new remote IPs discovered since previous interval", []string{"domain", "instance_uuid", "ip", "family", "project_uuid", "project_name", "user_uuid"}, nil)
	cm.instanceInboundFlowsDesc = prometheus.NewDesc("oie_instance_inbound_flows", "Inbound conntrack flows targeting this fixed IP in the current interval", []string{"domain", "instance_uuid", "ip", "family", "project_uuid", "project_name", "user_uuid"}, nil)
	cm.instanceInboundMaxFlowsSingleRemoteDesc = prometheus.NewDesc("oie_instance_inbound_max_flows_single_remote", "Maximum inbound flows from a single remote IP in the current interval", []string{"domain", "instance_uuid", "ip", "family", "project_uuid", "project_name", "user_uuid"}, nil)
	cm.instanceInboundUniqueDstPortsDesc = prometheus.NewDesc("oie_instance_inbound_unique_dst_ports", "Inbound unique destination ports on this fixed IP in the current interval", []string{"domain", "instance_uuid", "ip", "family", "project_uuid", "project_name", "user_uuid"}, nil)
	cm.instanceInboundNewDstPortsDesc = prometheus.NewDesc("oie_instance_inbound_new_dst_ports", "Inbound new remote IPs discovered since previous interval", []string{"domain", "instance_uuid", "ip", "family", "project_uuid", "project_name", "user_uuid"}, nil)
	cm.instanceInboundMaxFlowsSingleDstPortDesc = prometheus.NewDesc("oie_instance_inbound_max_flows_single_dst_port", "Maximum inbound flows to a single destination port in the current interval", []string{"domain", "instance_uuid", "ip", "family", "project_uuid", "project_name", "user_uuid"}, nil)
}

// -----------------------------------------------------------------------------
// Core Metric Calculation Logic
// -----------------------------------------------------------------------------

func (im *InstanceManager) getDomainMeta(domain *libvirt.Domain) (*DomainStatic, error) {
	instanceUUID, err := domain.GetUUIDString()
	if err != nil {
		return nil, fmt.Errorf("failed to get domain UUID: %v", err)
	}

	im.domainMetaMu.RLock()
	meta, ok := im.domainMeta[instanceUUID]
	im.domainMetaMu.RUnlock()
	if ok && meta != nil {
		return meta, nil
	}

	im.domainMetaMu.Lock()
	if meta, ok := im.domainMeta[instanceUUID]; ok && meta != nil {
		im.domainMetaMu.Unlock()
		return meta, nil
	}

	name, err := domain.GetName()
	if err != nil {
		im.domainMetaMu.Unlock()
		return nil, fmt.Errorf("failed to get domain name: %v", err)
	}

	xmlDesc, err := domain.GetXMLDesc(libvirt.DOMAIN_XML_SECURE)
	if err != nil {
		im.domainMetaMu.Unlock()
		return nil, fmt.Errorf("failed to get domain XML description: %v", err)
	}
	var domainXML DomainXML
	if err := xml.Unmarshal([]byte(xmlDesc), &domainXML); err != nil {
		im.domainMetaMu.Unlock()
		return nil, fmt.Errorf("failed to parse domain XML: %v", err)
	}

	meta = &DomainStatic{
		Name:            name,
		InstanceUUID:    instanceUUID,
		UserUUID:        domainXML.Metadata.NovaInstance.NovaOwner.NovaUser.UserUUID,
		UserName:        strings.TrimSpace(domainXML.Metadata.NovaInstance.NovaOwner.NovaUser.UserName),
		ProjectUUID:     domainXML.Metadata.NovaInstance.NovaOwner.NovaProject.ProjectUUID,
		ProjectName:     strings.TrimSpace(domainXML.Metadata.NovaInstance.NovaOwner.NovaProject.ProjectName),
		FlavorName:      strings.TrimSpace(domainXML.Metadata.NovaInstance.NovaFlavor.FlavorName),
		VCPUCount:       domainXML.Metadata.NovaInstance.NovaFlavor.VCPUs,
		MemMB:           domainXML.Metadata.NovaInstance.NovaFlavor.MemoryMB,
		RootType:        strings.TrimSpace(domainXML.Metadata.NovaInstance.NovaRoot.RootType),
		CreatedAt:       strings.TrimSpace(domainXML.Metadata.NovaInstance.CreationTime),
		MetadataVersion: strings.TrimSpace(domainXML.Metadata.NovaInstance.NovaPackage.Version),
	}

	if meta.ProjectName == "" {
		meta.ProjectName = "unknown"
	}
	if meta.UserName == "" {
		meta.UserName = "unknown"
	}
	if meta.FlavorName == "" {
		meta.FlavorName = "unknown"
	}
	if meta.RootType == "" {
		meta.RootType = "unknown"
	}
	if meta.CreatedAt == "" {
		meta.CreatedAt = "unknown"
	}
	if meta.MetadataVersion == "" {
		meta.MetadataVersion = "unknown"
	}

	if meta.MemMB <= 0 {
		if info, err := domain.GetInfo(); err == nil && info.Memory > 0 {
			meta.MemMB = int(info.Memory / 1024)
		}
	}

	var fixedIPs []IP
	for _, p := range domainXML.Metadata.NovaInstance.NovaPorts.Ports {
		for _, ip := range p.IPs {
			fixedIPs = append(fixedIPs, IP{
				Address: ip.Address,
				Family:  "ipv" + ip.IPVersion,
				Prefix:  "",
			})
		}
	}
	meta.FixedIPs = fixedIPs

	if len(domainXML.Devices.Disks) > 0 {
		meta.Disks = make([]DomainDisk, 0, len(domainXML.Devices.Disks))
		for _, d := range domainXML.Devices.Disks {
			meta.Disks = append(meta.Disks, DomainDisk{
				Device:     d.Device,
				Type:       d.Type,
				SourceName: d.Source.Name,
				SourceFile: d.Source.File,
				TargetDev:  d.Target.Dev,
			})
		}
	}

	if len(domainXML.Devices.Interfaces) > 0 {
		meta.Interfaces = make([]string, 0, len(domainXML.Devices.Interfaces))
		for _, iface := range domainXML.Devices.Interfaces {
			ifaceName := iface.Target.Dev
			if ifaceName == "" {
				continue
			}
			meta.Interfaces = append(meta.Interfaces, ifaceName)
		}
	}

	im.domainMeta[instanceUUID] = meta
	im.domainMetaMu.Unlock()

	return meta, nil
}

func (im *InstanceManager) calculateCPUUsage(totalCPUTime uint64, uuid string, vcpuCount int) float64 {
	if vcpuCount <= 0 {
		return 0
	}
	now := time.Now()

	im.cpuMu.Lock()
	prev, ok := im.cpuSamples[uuid]
	im.cpuSamples[uuid] = cpuSample{total: totalCPUTime, ts: now}
	im.cpuMu.Unlock()

	if !ok {
		return 0
	}

	elapsed := now.Sub(prev.ts)
	if elapsed <= 0 {
		return 0
	}
	var delta uint64
	if totalCPUTime >= prev.total {
		delta = totalCPUTime - prev.total
	} else {
		delta = 0
	}
	usage := (float64(delta) / float64(elapsed.Nanoseconds())) * 100 / float64(vcpuCount)
	if usage < 0 {
		usage = 0
	} else if usage > 100 {
		usage = 100
	}
	return usage
}

func (im *InstanceManager) calculateDiskIO(key string, rdReq, wrReq int64, now time.Time) (float64, float64) {
	im.diskMu.Lock()
	defer im.diskMu.Unlock()

	prev, ok := im.diskSamples[key]
	im.diskSamples[key] = diskSample{
		rdReq: rdReq,
		wrReq: wrReq,
		ts:    now,
	}
	if !ok {
		return 0, 0
	}

	elapsed := now.Sub(prev.ts).Seconds()
	if elapsed <= 0 {
		return 0, 0
	}

	var rdDelta, wrDelta int64
	if rdReq >= prev.rdReq {
		rdDelta = rdReq - prev.rdReq
	}
	if wrReq >= prev.wrReq {
		wrDelta = wrReq - prev.wrReq
	}
	if rdDelta < 0 {
		rdDelta = 0
	}
	if wrDelta < 0 {
		wrDelta = 0
	}

	return float64(rdDelta) / elapsed, float64(wrDelta) / elapsed
}

func (mc *MetricsCollector) collectDomainMetrics(stat libvirt.DomainStats, ipFlows map[string][]ConntrackEntry, hostIPs []string, agg *hostAgg) {
	if stat.Domain == nil {
		return
	}
	meta, err := mc.im.getDomainMeta(stat.Domain)
	if err != nil {
		logCollectorMetric.Error("domain_meta_failed", "err", err)
		return
	}

	name := meta.Name
	instanceUUID := meta.InstanceUUID
	userUUID := meta.UserUUID
	projectUUID := meta.ProjectUUID
	projectName := meta.ProjectName
	userName := meta.UserName
	flavorName := meta.FlavorName
	vcpuCount := meta.VCPUCount
	if len(stat.Vcpu) > 0 {
		vcpuCount = len(stat.Vcpu)
	}

	memMB := meta.MemMB
	if stat.Balloon != nil && stat.Balloon.Maximum > 0 {
		memMB = int(stat.Balloon.Maximum / 1024)
	}

	rootType := meta.RootType
	createdAt := meta.CreatedAt
	metadataVersion := meta.MetadataVersion

	now := time.Now()

	var (
		resourceCpuScore  float64
		resourceMemScore  float64
		resourceDiskScore float64
		resourceNetScore  float64
		maxDiskIOSignal   float64
		maxConntrackFlows int

		torSignal      float64
		relaySignal    float64
		spamSignal     float64
		emSignal       float64
		clSignal       float64
		outboundSignal float64
		inboundSignal  float64
	)

	fixedIPs := meta.FixedIPs
	ipSet := make(map[string]struct{}, len(fixedIPs))
	for _, ip := range fixedIPs {
		ipSet[ip.Address] = struct{}{}
	}

	if agg != nil {
		agg.mu.Lock()
		agg.fixedIPs += len(ipSet)
		if projectName == "" {
			projectName = "unknown"
		}
		agg.projects[projectName] = struct{}{}
		if vcpuCount > 0 {
			agg.vcpus += vcpuCount
		}
		agg.mu.Unlock()
	}

	dynamicMetrics := make([]prometheus.Metric, 0, 80)

	dynamicMetrics = append(dynamicMetrics,
		prometheus.MustNewConstMetric(
			mc.im.instanceInfoDesc,
			prometheus.GaugeValue,
			1.0,
			name,
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
			prometheus.MustNewConstMetric(mc.im.instanceCpuVcpuCountDesc, prometheus.GaugeValue, float64(vcpuCount), name, instanceUUID, userUUID, projectUUID, projectName),
		)
	}

	if memMB > 0 {
		dynamicMetrics = append(dynamicMetrics,
			prometheus.MustNewConstMetric(mc.im.instanceMemAllocatedMBDesc, prometheus.GaugeValue, float64(memMB), name, instanceUUID, userUUID, projectUUID, projectName),
		)
	}

	var guestUsedMB float64
	if stat.Balloon != nil {
		if stat.Balloon.Usable > 0 && stat.Balloon.Current >= stat.Balloon.Usable {
			guestUsedMB = float64(stat.Balloon.Current-stat.Balloon.Usable) / 1024.0
		} else if stat.Balloon.Rss > 0 {
			guestUsedMB = float64(stat.Balloon.Rss) / 1024.0
		} else if stat.Balloon.Current > 0 {
			guestUsedMB = float64(stat.Balloon.Current) / 1024.0
		}
	}

	if guestUsedMB > 0 {
		dynamicMetrics = append(dynamicMetrics,
			prometheus.MustNewConstMetric(mc.im.instanceMemUsedMBDesc, prometheus.GaugeValue, guestUsedMB, name, instanceUUID, userUUID, projectUUID, projectName),
		)
	}

	if guestUsedMB > 0 && memMB > 0 {
		usageRatio := guestUsedMB / float64(memMB)
		if usageRatio > 1.5 {
			usageRatio = 1.5
		}
		pressureNorm := (usageRatio - 0.8) / 0.2
		resourceMemScore = clamp01(pressureNorm) * 25.0
	}

	seenDisks := make(map[string]struct{})
	diskCountDomain := 0
	diskMetaMap := make(map[string]DomainDisk)
	for _, d := range meta.Disks {
		if d.TargetDev != "" {
			diskMetaMap[d.TargetDev] = d
		}
	}

	if stat.Block != nil {
		for _, blk := range stat.Block {
			if blk.Name == "" {
				continue
			}
			dMeta, ok := diskMetaMap[blk.Name]
			var diskType, volumeUUID string
			if ok {
				if dMeta.Type == "file" {
					diskType = "local"
					volumeUUID = dMeta.SourceFile
				} else {
					diskType, volumeUUID = parseDiskType(dMeta.SourceName)
				}
			} else {
				diskType = "unknown"
				volumeUUID = "unknown"
			}
			diskPath := blk.Name
			key := instanceUUID + "|" + volumeUUID + "|" + diskPath
			if _, exists := seenDisks[key]; exists {
				continue
			}
			seenDisks[key] = struct{}{}
			diskCountDomain++

			readThreshold := mc.im.defaultReadThreshold
			if v, ok := mc.im.readThreshold["default"]; ok {
				readThreshold = v
			}
			if v, ok := mc.im.readThreshold[diskType]; ok {
				readThreshold = v
			}
			writeThreshold := mc.im.defaultWriteThreshold
			if v, ok := mc.im.writeThreshold["default"]; ok {
				writeThreshold = v
			}
			if v, ok := mc.im.writeThreshold[diskType]; ok {
				writeThreshold = v
			}

			readIOPS, writeIOPS := mc.im.calculateDiskIO(instanceUUID+"|"+volumeUUID+"|"+diskPath, int64(blk.RdReqs), int64(blk.WrReqs), now)
			iopsTotal := readIOPS + writeIOPS
			if readThreshold > 0 || writeThreshold > 0 {
				baseline := float64(readThreshold + writeThreshold)
				if baseline > 0 {
					diskSignal := clamp01(iopsTotal / baseline)
					if diskSignal > maxDiskIOSignal {
						maxDiskIOSignal = diskSignal
					}
				}
			}

			diskMetrics := make([]prometheus.Metric, 0, 7)
			diskMetrics = append(diskMetrics, prometheus.MustNewConstMetric(mc.im.instanceDiskInfoDesc, prometheus.GaugeValue, 1.0, name, instanceUUID, projectUUID, projectName, userUUID, volumeUUID, diskType, diskPath))
			diskMetrics = append(diskMetrics, prometheus.MustNewConstMetric(mc.im.instanceDiskReadAlertThresholdDesc, prometheus.GaugeValue, float64(readThreshold), name, instanceUUID, userUUID, projectUUID, projectName, volumeUUID, diskType, diskPath), prometheus.MustNewConstMetric(mc.im.instanceDiskWriteAlertThresholdDesc, prometheus.GaugeValue, float64(writeThreshold), name, instanceUUID, userUUID, projectUUID, projectName, volumeUUID, diskType, diskPath))

			if blk.RdBytes != 0 || blk.WrBytes != 0 || blk.RdReqs != 0 || blk.WrReqs != 0 {
				diskMetrics = append(diskMetrics,
					prometheus.MustNewConstMetric(mc.im.instanceDiskReadGbytesTotalDesc, prometheus.CounterValue, roundToFiveDecimals(float64(blk.RdBytes)*bytesToGigabytes), name, instanceUUID, userUUID, projectUUID, projectName, volumeUUID, diskType, diskPath),
					prometheus.MustNewConstMetric(mc.im.instanceDiskWriteGbytesTotalDesc, prometheus.CounterValue, roundToFiveDecimals(float64(blk.WrBytes)*bytesToGigabytes), name, instanceUUID, userUUID, projectUUID, projectName, volumeUUID, diskType, diskPath),
					prometheus.MustNewConstMetric(mc.im.instanceDiskReadRequestsTotalDesc, prometheus.CounterValue, float64(blk.RdReqs), name, instanceUUID, userUUID, projectUUID, projectName, volumeUUID, diskType, diskPath),
					prometheus.MustNewConstMetric(mc.im.instanceDiskWriteRequestsTotalDesc, prometheus.CounterValue, float64(blk.WrReqs), name, instanceUUID, userUUID, projectUUID, projectName, volumeUUID, diskType, diskPath),
				)
			}
			dynamicMetrics = append(dynamicMetrics, diskMetrics...)
		}
	}

	if agg != nil && diskCountDomain > 0 {
		agg.mu.Lock()
		agg.disks += diskCountDomain
		agg.mu.Unlock()
	}
	if maxDiskIOSignal > 0 {
		resourceDiskScore = maxDiskIOSignal * 25.0
	}

	var cpuTimeTotal uint64
	if stat.Cpu != nil {
		cpuTimeTotal = stat.Cpu.Time
	}
	cpuUsage := mc.im.calculateCPUUsage(cpuTimeTotal, instanceUUID, vcpuCount)
	dynamicMetrics = append(dynamicMetrics, prometheus.MustNewConstMetric(mc.im.instanceCpuVcpuPercentDesc, prometheus.GaugeValue, roundToFiveDecimals(cpuUsage), name, instanceUUID, userUUID, projectUUID, projectName))

	if cpuUsage > 0 {
		usageNorm := (cpuUsage - 70.0) / 30.0
		resourceCpuScore = clamp01(usageNorm) * 25.0
	}

	if stat.Net != nil {
		for _, iface := range stat.Net {
			isKnown := false
			for _, kn := range meta.Interfaces {
				if kn == iface.Name {
					isKnown = true
					break
				}
			}
			if !isKnown {
				continue
			}
			if iface.RxBytes != 0 {
				dynamicMetrics = append(dynamicMetrics, prometheus.MustNewConstMetric(mc.im.instanceNetRxGbytesTotalDesc, prometheus.CounterValue, roundToFiveDecimals(float64(iface.RxBytes)*bytesToGigabytes), name, iface.Name, instanceUUID, userUUID, projectUUID, projectName))
			}
			if iface.TxBytes != 0 {
				dynamicMetrics = append(dynamicMetrics, prometheus.MustNewConstMetric(mc.im.instanceNetTxGbytesTotalDesc, prometheus.CounterValue, roundToFiveDecimals(float64(iface.TxBytes)*bytesToGigabytes), name, iface.Name, instanceUUID, userUUID, projectUUID, projectName))
			}
			if iface.RxPkts != 0 {
				dynamicMetrics = append(dynamicMetrics, prometheus.MustNewConstMetric(mc.im.instanceNetRxPacketsTotalDesc, prometheus.CounterValue, float64(iface.RxPkts), name, iface.Name, instanceUUID, userUUID, projectUUID, projectName))
			}
			if iface.TxPkts != 0 {
				dynamicMetrics = append(dynamicMetrics, prometheus.MustNewConstMetric(mc.im.instanceNetTxPacketsTotalDesc, prometheus.CounterValue, float64(iface.TxPkts), name, iface.Name, instanceUUID, userUUID, projectUUID, projectName))
			}
			if iface.RxErrs != 0 {
				dynamicMetrics = append(dynamicMetrics, prometheus.MustNewConstMetric(mc.im.instanceNetRxErrorsTotalDesc, prometheus.CounterValue, float64(iface.RxErrs), name, iface.Name, instanceUUID, userUUID, projectUUID, projectName))
			}
			if iface.TxErrs != 0 {
				dynamicMetrics = append(dynamicMetrics, prometheus.MustNewConstMetric(mc.im.instanceNetTxErrorsTotalDesc, prometheus.CounterValue, float64(iface.TxErrs), name, iface.Name, instanceUUID, userUUID, projectUUID, projectName))
			}
			if iface.RxDrop != 0 {
				dynamicMetrics = append(dynamicMetrics, prometheus.MustNewConstMetric(mc.im.instanceNetRxDroppedTotalDesc, prometheus.CounterValue, float64(iface.RxDrop), name, iface.Name, instanceUUID, userUUID, projectUUID, projectName))
			}
			if iface.TxDrop != 0 {
				dynamicMetrics = append(dynamicMetrics, prometheus.MustNewConstMetric(mc.im.instanceNetTxDroppedTotalDesc, prometheus.CounterValue, float64(iface.TxDrop), name, iface.Name, instanceUUID, userUUID, projectUUID, projectName))
			}
		}
	}

	if len(ipFlows) > 0 && len(fixedIPs) > 0 {
		outboundSignal, inboundSignal, maxConntrackFlows = mc.cm.calculateConntrackMetrics(fixedIPs, ipFlows, ipSet, hostIPs, name, instanceUUID, projectUUID, projectName, userUUID, &dynamicMetrics)

		if maxConntrackFlows > 0 {
			base := 20
			ratio := float64(maxConntrackFlows) / float64(base*10)
			resourceNetScore = clamp01(ratio) * 25.0
		}
	}

	mc.tm.checkTorExit(fixedIPs, ipSet, ipFlows, name, instanceUUID, projectUUID, projectName, userUUID, &dynamicMetrics, &torSignal)
	mc.tm.checkTorRelay(fixedIPs, ipSet, ipFlows, name, instanceUUID, projectUUID, projectName, userUUID, &dynamicMetrics, &relaySignal)
	mc.tm.checkSpamhaus(fixedIPs, ipSet, ipFlows, name, instanceUUID, projectUUID, projectName, userUUID, &dynamicMetrics, &spamSignal)
	mc.tm.checkEmergingThreats(fixedIPs, ipSet, ipFlows, name, instanceUUID, projectUUID, projectName, userUUID, &dynamicMetrics, &emSignal)
	mc.tm.checkCustomList(fixedIPs, ipSet, ipFlows, name, instanceUUID, projectUUID, projectName, userUUID, &dynamicMetrics, &clSignal)

	resourceScore := resourceCpuScore + resourceMemScore + resourceDiskScore + resourceNetScore
	resourceScore = clamp01(resourceScore/100.0) * 100.0

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

	// Use configurable weights
	threatScore := torSignal*mc.scoring.TorSignal +
		relaySignal*mc.scoring.RelaySignal +
		spamSignal*mc.scoring.SpamSignal +
		emSignal*mc.scoring.EmergingSignal +
		clSignal*mc.scoring.CustomSignal +
		behaviorSignal*mc.scoring.BehaviorSignal

	threatScore = clamp01(threatScore/100.0) * 100.0

	resourceWeight := mc.scoring.ResourceWeight
	threatWeight := mc.scoring.ThreatWeight

	attentionScore := (resourceScore*resourceWeight + threatScore*threatWeight) / (resourceWeight + threatWeight)

	if attentionScore >= mc.minAttentionScore {
		logKV(LogLevelNotice, "score", "instance_scores", "domain", name, "instance_uuid", instanceUUID, "project_uuid", projectUUID, "attention_score", attentionScore, "threat_score", threatScore, "behavior", behaviorSignal)
		dynamicMetrics = append(dynamicMetrics,
			prometheus.MustNewConstMetric(mc.instanceResourceScoreDesc, prometheus.GaugeValue, resourceScore, name, instanceUUID, projectUUID, projectName, userUUID),
			prometheus.MustNewConstMetric(mc.instanceThreatScoreDesc, prometheus.GaugeValue, threatScore, name, instanceUUID, projectUUID, projectName, userUUID),
			prometheus.MustNewConstMetric(mc.instanceAttentionScoreDesc, prometheus.GaugeValue, attentionScore, name, instanceUUID, projectUUID, projectName, userUUID),
		)
	}

	if agg != nil {
		agg.mu.Lock()
		agg.metrics = append(agg.metrics, dynamicMetrics...)
		agg.mu.Unlock()
	}
}

// Instance Manager Cleanup Methods
func (im *InstanceManager) setActiveInstances(activeSet map[string]struct{}) {
	im.activeInstancesMu.Lock()
	im.activeInstances = activeSet
	im.activeInstancesMu.Unlock()
}

func (im *InstanceManager) isInstanceActive(instanceUUID string) bool {
	im.activeInstancesMu.RLock()
	defer im.activeInstancesMu.RUnlock()
	_, ok := im.activeInstances[instanceUUID]
	return ok
}

func (im *InstanceManager) cleanupDomainMeta() {
	im.domainMetaMu.Lock()
	for uuid := range im.domainMeta {
		if !im.isInstanceActive(uuid) {
			delete(im.domainMeta, uuid)
		}
	}
	im.domainMetaMu.Unlock()
}

func (im *InstanceManager) cleanupResourceSamples() {
	im.cpuMu.Lock()
	for uuid := range im.cpuSamples {
		if !im.isInstanceActive(uuid) {
			delete(im.cpuSamples, uuid)
		}
	}
	im.cpuMu.Unlock()

	im.diskMu.Lock()
	for key := range im.diskSamples {
		parts := strings.SplitN(key, "|", 2)
		if len(parts) > 0 && !im.isInstanceActive(parts[0]) {
			delete(im.diskSamples, key)
		}
	}
	im.diskMu.Unlock()
}

func (im *InstanceManager) describeInstanceMetrics(ch chan<- *prometheus.Desc) {
	ch <- im.instanceDiskReadAlertThresholdDesc
	ch <- im.instanceDiskWriteAlertThresholdDesc
	ch <- im.instanceDiskReadGbytesTotalDesc
	ch <- im.instanceDiskWriteGbytesTotalDesc
	ch <- im.instanceDiskReadRequestsTotalDesc
	ch <- im.instanceDiskWriteRequestsTotalDesc
	ch <- im.instanceDiskInfoDesc
	ch <- im.instanceCpuVcpuPercentDesc
	ch <- im.instanceCpuVcpuCountDesc
	ch <- im.instanceMemAllocatedMBDesc
	ch <- im.instanceMemUsedMBDesc
	ch <- im.instanceNetRxGbytesTotalDesc
	ch <- im.instanceNetTxGbytesTotalDesc
	ch <- im.instanceNetRxPacketsTotalDesc
	ch <- im.instanceNetTxPacketsTotalDesc
	ch <- im.instanceNetRxErrorsTotalDesc
	ch <- im.instanceNetTxErrorsTotalDesc
	ch <- im.instanceNetRxDroppedTotalDesc
	ch <- im.instanceNetTxDroppedTotalDesc
	ch <- im.instanceInfoDesc
}
