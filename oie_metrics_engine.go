package main

import (
	"bufio"
	"encoding/xml"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/digitalocean/go-libvirt"
	"github.com/prometheus/client_golang/prometheus"
)

// -----------------------------------------------------------------------------
// Prometheus Metric Initializers
// -----------------------------------------------------------------------------

func initHostMetrics(mc *MetricsCollector) {
	type d struct {
		dst  **prometheus.Desc
		name string
		help string
	}

	descs := []d{
		{dst: &mc.hostMemTotalMBDesc, name: "oie_host_mem_mb_total", help: "Total physical memory on this hypervisor (MB)"},
		{dst: &mc.hostLibvirtActiveVMsDesc, name: "oie_host_libvirt_active_vms", help: "Active libvirt domains on this hypervisor"},
		{dst: &mc.hostCpuActiveVcpusDesc, name: "oie_host_cpu_active_vcpus", help: "Sum of vCPUs allocated to active domains on this hypervisor"},
		{dst: &mc.hostActiveDisksDesc, name: "oie_host_active_disks", help: "Count of disks across active domains on this hypervisor"},
		{dst: &mc.hostActiveFixedIPsDesc, name: "oie_host_active_fixed_ips", help: "Count of fixed IPs across active domains on this hypervisor"},
		{dst: &mc.hostActiveProjectsDesc, name: "oie_host_active_projects", help: "Unique project names seen in active domains on this hypervisor"},
		{dst: &mc.hostCpuThreadsDesc, name: "oie_host_cpu_threads", help: "Logical CPU thread count on this hypervisor"},
		{dst: &mc.hostCollectionErrorsTotalDesc, name: "oie_host_collection_errors_total", help: "Total background collection errors on this host"},
		{dst: &mc.hostCollectionCycleDurationSecondsDesc, name: "oie_host_collection_cycle_duration_seconds", help: "Duration of last background collection cycle on this host (seconds)"},
		{dst: &mc.hostCollectionCycleLagSecondsDesc, name: "oie_host_collection_cycle_lag_seconds", help: "Seconds since prior background collection cycle ended on this host"},
		{dst: &mc.hostLibvirtListDurationSecondsDesc, name: "oie_host_libvirt_list_duration_seconds", help: "Seconds spent listing active libvirt domains on this host"},
		{dst: &mc.hostConntrackReadDurationSecondsDesc, name: "oie_host_conntrack_read_duration_seconds", help: "Seconds spent reading conntrack tables on this host"},
		{dst: &mc.hostGoHeapAllocBytesDesc, name: "oie_host_go_heap_alloc_bytes", help: "Go heap allocation of the exporter process in bytes on this host"},
		{dst: &mc.hostConntrackEntriesDesc, name: "oie_host_conntrack_entries", help: "Conntrack entries observed in last snapshot on this host"},
		{dst: &mc.hostConntrackReadErrorsTotalDesc, name: "oie_host_conntrack_read_errors_total", help: "Conntrack read errors on this host"},
		{dst: &mc.hostConntrackRawOkDesc, name: "oie_host_conntrack_raw_ok", help: "1 if the raw conntrack reader succeeded on the last run, else 0"},
		{dst: &mc.hostConntrackRawENOBUFSTotalDesc, name: "oie_host_conntrack_raw_enobufs_total", help: "Total ENOBUFS errors encountered by the raw conntrack reader"},
		{dst: &mc.hostConntrackRawParseErrorsTotalDesc, name: "oie_host_conntrack_raw_parse_errors_total", help: "Total parse errors encountered by the raw conntrack reader"},
		{dst: &mc.hostConntrackLastSuccessTimestampDesc, name: "oie_host_conntrack_last_success_timestamp_seconds", help: "Unix timestamp of last successful conntrack read (seconds)"},
		{dst: &mc.hostConntrackStaleSecondsDesc, name: "oie_host_conntrack_stale_seconds", help: "Seconds since last successful conntrack read"},
		{dst: &mc.hostConntrackMaxDesc, name: "oie_host_conntrack_max", help: "Configured maximum conntrack entries on this host"},
		{dst: &mc.hostConntrackUtilizationDesc, name: "oie_host_conntrack_utilization", help: "Conntrack table utilization (entries / max)"},
		{dst: &mc.hostCacheCleanupDurationSecondsDesc, name: "oie_host_cache_cleanup_duration_seconds", help: "Duration of last cache cleanup cycle on this host (seconds)"},
		{dst: &mc.hostCpuUsagePercentDesc, name: "oie_host_cpu_usage_percent", help: "Live host CPU usage percentage (0-100) from /proc/stat delta"},
		{dst: &mc.hostMemFreeMBDesc, name: "oie_host_mem_free_mb", help: "Free host memory (MemFree) in MB"},
		{dst: &mc.hostMemAvailableMBDesc, name: "oie_host_mem_available_mb", help: "Available host memory (MemAvailable) in MB"},
	}
	for _, d := range descs {
		*d.dst = newHostMetricDesc(d.name, d.help)
	}
}

func initInstanceMetrics(im *InstanceManager) {
	im.instanceInfoDesc = prometheus.NewDesc("oie_instance_info", "Static instance metadata", []string{"domain", "instance_uuid", "project_uuid", "project_name", "user_uuid", "user_name", "flavor", "vcpus", "mem_mb", "root_type", "created_at", "metadata_version"}, nil)
	im.instanceStateDesc = prometheus.NewDesc("oie_instance_state_code", "Libvirt state code", []string{"domain", "instance_uuid", "user_uuid", "project_uuid", "project_name", "state_desc"}, nil)

	diskLabels := []string{"domain", "instance_uuid", "user_uuid", "project_uuid", "project_name", "volume_uuid", "disk_type", "disk_path"}
	netLabels := []string{"domain", "interface", "instance_uuid", "user_uuid", "project_uuid", "project_name"}

	type d struct {
		dst   **prometheus.Desc
		build func() *prometheus.Desc
	}
	descs := []d{
		{dst: &im.instanceDiskReadGbytesTotalDesc, build: func() *prometheus.Desc {
			return prometheus.NewDesc("oie_instance_disk_read_gbytes_total", "Disk read gigabytes", diskLabels, nil)
		}},
		{dst: &im.instanceDiskWriteGbytesTotalDesc, build: func() *prometheus.Desc {
			return prometheus.NewDesc("oie_instance_disk_write_gbytes_total", "Disk write gigabytes", diskLabels, nil)
		}},
		{dst: &im.instanceDiskReadRequestsTotalDesc, build: func() *prometheus.Desc {
			return prometheus.NewDesc("oie_instance_disk_read_requests_total", "Disk read requests", diskLabels, nil)
		}},
		{dst: &im.instanceDiskWriteRequestsTotalDesc, build: func() *prometheus.Desc {
			return prometheus.NewDesc("oie_instance_disk_write_requests_total", "Disk write requests", diskLabels, nil)
		}},
		{dst: &im.instanceDiskReadSecondsTotalDesc, build: func() *prometheus.Desc {
			return prometheus.NewDesc("oie_instance_disk_read_seconds_total", "Total seconds spent reading from disk", diskLabels, nil)
		}},
		{dst: &im.instanceDiskWriteSecondsTotalDesc, build: func() *prometheus.Desc {
			return prometheus.NewDesc("oie_instance_disk_write_seconds_total", "Total seconds spent writing to disk", diskLabels, nil)
		}},
		{dst: &im.instanceDiskFlushRequestsTotalDesc, build: func() *prometheus.Desc {
			return prometheus.NewDesc("oie_instance_disk_flush_requests_total", "Total flush requests", diskLabels, nil)
		}},
		{dst: &im.instanceDiskFlushSecondsTotalDesc, build: func() *prometheus.Desc {
			return prometheus.NewDesc("oie_instance_disk_flush_seconds_total", "Total seconds spent flushing to disk", diskLabels, nil)
		}},
		{dst: &im.instanceDiskCapacityBytesDesc, build: func() *prometheus.Desc {
			return prometheus.NewDesc("oie_instance_disk_capacity_bytes", "Logical size of the disk", diskLabels, nil)
		}},
		{dst: &im.instanceDiskAllocationBytesDesc, build: func() *prometheus.Desc {
			return prometheus.NewDesc("oie_instance_disk_allocation_bytes", "Physical space used on storage", diskLabels, nil)
		}},
		{dst: &im.instanceDiskInfoDesc, build: func() *prometheus.Desc {
			return prometheus.NewDesc("oie_instance_disk_info", "Static disk metadata", diskLabels, nil)
		}},

		{dst: &im.instanceDiskReadIopsDesc, build: func() *prometheus.Desc {
			return prometheus.NewDesc("oie_instance_disk_read_iops", "Disk read IOPS (per-second rate computed from libvirt counters)", diskLabels, nil)
		}},
		{dst: &im.instanceDiskWriteIopsDesc, build: func() *prometheus.Desc {
			return prometheus.NewDesc("oie_instance_disk_write_iops", "Disk write IOPS (per-second rate computed from libvirt counters)", diskLabels, nil)
		}},
		{dst: &im.instanceDiskFlushIopsDesc, build: func() *prometheus.Desc {
			return prometheus.NewDesc("oie_instance_disk_flush_iops", "Disk flush IOPS (per-second rate computed from libvirt counters)", diskLabels, nil)
		}},
		{dst: &im.instanceDiskReadLatencySecondsDesc, build: func() *prometheus.Desc {
			return prometheus.NewDesc("oie_instance_disk_read_latency_seconds", "Average disk read latency in seconds over the interval", diskLabels, nil)
		}},
		{dst: &im.instanceDiskWriteLatencySecondsDesc, build: func() *prometheus.Desc {
			return prometheus.NewDesc("oie_instance_disk_write_latency_seconds", "Average disk write latency in seconds over the interval", diskLabels, nil)
		}},
		{dst: &im.instanceDiskFlushLatencySecondsDesc, build: func() *prometheus.Desc {
			return prometheus.NewDesc("oie_instance_disk_flush_latency_seconds", "Average disk flush latency in seconds over the interval", diskLabels, nil)
		}},

		{dst: &im.instanceCpuVcpuPercentDesc, build: func() *prometheus.Desc {
			return newInstanceMetricDesc("oie_instance_cpu_vcpu_percent", "CPU usage percentage per vCPU")
		}},
		{dst: &im.instanceCpuVcpuCountDesc, build: func() *prometheus.Desc {
			return newInstanceMetricDesc("oie_instance_cpu_vcpu_count", "Allocated vCPU count for this instance")
		}},
		{dst: &im.instanceCpuStealSecondsTotalDesc, build: func() *prometheus.Desc {
			return prometheus.NewDesc("oie_instance_cpu_steal_seconds_total", "Total time vCPU spent waiting on Host Scheduler", []string{"domain", "instance_uuid", "user_uuid", "project_uuid", "project_name", "vcpu"}, nil)
		}},
		{dst: &im.instanceCpuWaitSecondsTotalDesc, build: func() *prometheus.Desc {
			return prometheus.NewDesc("oie_instance_cpu_wait_seconds_total", "Total time vCPU spent waiting on I/O", []string{"domain", "instance_uuid", "user_uuid", "project_uuid", "project_name", "vcpu"}, nil)
		}},

		{dst: &im.instanceMemAllocatedMBDesc, build: func() *prometheus.Desc {
			return newInstanceMetricDesc("oie_instance_mem_allocated_mb", "Allocated memory for this instance (MB)")
		}},
		{dst: &im.instanceMemUsedMBDesc, build: func() *prometheus.Desc {
			return newInstanceMetricDesc("oie_instance_mem_used_mb", "Guest-view used memory for this instance (MB)")
		}},
		{dst: &im.instanceMemSwapInBytesDesc, build: func() *prometheus.Desc {
			return prometheus.NewDesc("oie_instance_mem_swap_in_bytes_total", "Memory swapped in", []string{"domain", "instance_uuid", "user_uuid", "project_uuid", "project_name"}, nil)
		}},
		{dst: &im.instanceMemSwapOutBytesDesc, build: func() *prometheus.Desc {
			return prometheus.NewDesc("oie_instance_mem_swap_out_bytes_total", "Memory swapped out", []string{"domain", "instance_uuid", "user_uuid", "project_uuid", "project_name"}, nil)
		}},
		{dst: &im.instanceMemMajorFaultsTotalDesc, build: func() *prometheus.Desc {
			return newInstanceMetricDesc("oie_instance_mem_major_faults_total", "Major memory page faults")
		}},
		{dst: &im.instanceMemMinorFaultsTotalDesc, build: func() *prometheus.Desc {
			return newInstanceMetricDesc("oie_instance_mem_minor_faults_total", "Minor memory page faults")
		}},
		{dst: &im.instanceMemRSSMBDesc, build: func() *prometheus.Desc {
			return newInstanceMetricDesc("oie_instance_mem_rss_mb", "Resident Set Size (Actual Host RAM used) (MB)")
		}},

		{dst: &im.instanceHugetlbPgAllocDesc, build: func() *prometheus.Desc {
			return prometheus.NewDesc("oie_instance_hugetlb_pgalloc_total", "HugePage allocations successful", []string{"domain", "instance_uuid", "user_uuid", "project_uuid", "project_name"}, nil)
		}},
		{dst: &im.instanceHugetlbPgFailDesc, build: func() *prometheus.Desc {
			return prometheus.NewDesc("oie_instance_hugetlb_pgfail_total", "HugePage allocations failed", []string{"domain", "instance_uuid", "user_uuid", "project_uuid", "project_name"}, nil)
		}},

		{dst: &im.instanceNetRxGbytesTotalDesc, build: func() *prometheus.Desc {
			return prometheus.NewDesc("oie_instance_net_rx_gbytes_total", "Network receive gigabytes", netLabels, nil)
		}},
		{dst: &im.instanceNetTxGbytesTotalDesc, build: func() *prometheus.Desc {
			return prometheus.NewDesc("oie_instance_net_tx_gbytes_total", "Network transmit gigabytes", netLabels, nil)
		}},
		{dst: &im.instanceNetRxPacketsTotalDesc, build: func() *prometheus.Desc {
			return prometheus.NewDesc("oie_instance_net_rx_packets_total", "Network receive packets", netLabels, nil)
		}},
		{dst: &im.instanceNetTxPacketsTotalDesc, build: func() *prometheus.Desc {
			return prometheus.NewDesc("oie_instance_net_tx_packets_total", "Network transmit packets", netLabels, nil)
		}},
		{dst: &im.instanceNetRxErrorsTotalDesc, build: func() *prometheus.Desc {
			return prometheus.NewDesc("oie_instance_net_rx_errors_total", "Network receive errors", netLabels, nil)
		}},
		{dst: &im.instanceNetTxErrorsTotalDesc, build: func() *prometheus.Desc {
			return prometheus.NewDesc("oie_instance_net_tx_errors_total", "Network transmit errors", netLabels, nil)
		}},
		{dst: &im.instanceNetRxDroppedTotalDesc, build: func() *prometheus.Desc {
			return prometheus.NewDesc("oie_instance_net_rx_dropped_total", "Network receive dropped packets", netLabels, nil)
		}},
		{dst: &im.instanceNetTxDroppedTotalDesc, build: func() *prometheus.Desc {
			return prometheus.NewDesc("oie_instance_net_tx_dropped_total", "Network transmit dropped packets", netLabels, nil)
		}},
	}
	for _, d := range descs {
		*d.dst = d.build()
	}
}

func initInstanceSeverityMetrics(mc *MetricsCollector) {
	mc.instanceResourceSeverityDesc = newInstanceSeverityMetricDesc("oie_instance_resource_severity", "Resource pressure severity (0-100) combining CPU, memory, disk and network/conntrack")
	mc.instanceThreatListSeverityDesc = newInstanceSeverityMetricDesc("oie_instance_threat_list_severity", "Threat list severity (0-100) derived strictly from Threat Intel (Spamhaus, Tor, etc) matches")
	mc.instanceAttentionSeverityDesc = newInstanceSeverityMetricDesc("oie_instance_attention_severity", "Combined attention severity (0-100) based on resource pressure and threat signals")
	mc.instanceBehaviorSeverityDesc = newInstanceSeverityMetricDesc("oie_instance_behavior_severity", "Pure behavior severity (0-100) derived from conntrack behavior signals (no intel)")

	mc.instanceResourceCpuSeverityDesc = newInstanceSeverityMetricDesc("oie_instance_resource_cpu_severity", "Resource CPU axis severity (0-100) based on pressure EWMA")
	mc.instanceResourceMemSeverityDesc = newInstanceSeverityMetricDesc("oie_instance_resource_mem_severity", "Resource memory axis severity (0-100) based on pressure EWMA")
	mc.instanceResourceDiskSeverityDesc = newInstanceSeverityMetricDesc("oie_instance_resource_disk_severity", "Resource disk axis severity (0-100) based on latency/flush pressure EWMA")
	mc.instanceResourceNetSeverityDesc = newInstanceSeverityMetricDesc("oie_instance_resource_net_severity", "Resource network axis severity (0-100) based on drop/capacity pressure EWMA")
}

func initConntrackMetrics(cm *ConntrackManager) {
	cm.instanceConntrackIPFlowsDesc = newInstanceConntrackMetricDesc("oie_instance_conntrack_ip_flows", "Conntrack flow entries matched to this fixed IP (inbound + outbound)")
	cm.instanceConntrackIPFlowsInboundDesc = newInstanceConntrackMetricDesc("oie_instance_conntrack_ip_flows_inbound", "Inbound conntrack flow entries matched to this fixed IP (VM as destination)")
	cm.instanceConntrackIPFlowsOutboundDesc = newInstanceConntrackMetricDesc("oie_instance_conntrack_ip_flows_outbound", "Outbound conntrack flow entries matched to this fixed IP (VM as source)")
	cm.instanceOutboundUniqueRemotesDesc = newInstanceConntrackMetricDesc("oie_instance_outbound_unique_remotes", "Outbound unique remote IPs for this fixed IP in the current interval")
	cm.instanceOutboundNewRemotesDesc = newInstanceConntrackMetricDesc("oie_instance_outbound_new_remotes", "Outbound new remote IPs discovered since previous interval")
	cm.instanceOutboundFlowsDesc = newInstanceConntrackMetricDesc("oie_instance_outbound_flows", "Outbound conntrack flows initiated by this fixed IP in the current interval")
	cm.instanceOutboundMaxFlowsSingleRemoteDesc = newInstanceConntrackMetricDesc("oie_instance_outbound_max_flows_single_remote", "Maximum outbound flows to a single remote IP in the current interval")
	cm.instanceOutboundUniqueDstPortsDesc = newInstanceConntrackMetricDesc("oie_instance_outbound_unique_dst_ports", "Outbound unique destination ports in the current interval")
	cm.instanceOutboundNewDstPortsDesc = newInstanceConntrackMetricDesc("oie_instance_outbound_new_dst_ports", "Outbound new destination ports discovered since previous interval")
	cm.instanceOutboundMaxFlowsSingleDstPortDesc = newInstanceConntrackMetricDesc("oie_instance_outbound_max_flows_single_dst_port", "Maximum outbound flows to a single destination port in the current interval")
	cm.instanceOutboundBytesPerFlowDesc = newInstanceConntrackMetricDesc("oie_instance_outbound_bytes_per_flow", "Outbound average bytes per conntrack flow for this fixed IP (requires nf_conntrack_acct=1)")
	cm.instanceOutboundPacketsPerFlowDesc = newInstanceConntrackMetricDesc("oie_instance_outbound_packets_per_flow", "Outbound average packets per conntrack flow for this fixed IP (requires nf_conntrack_acct=1)")

	cm.instanceInboundUniqueRemotesDesc = newInstanceConntrackMetricDesc("oie_instance_inbound_unique_remotes", "Inbound unique remote IPs for this fixed IP in the current interval")
	cm.instanceInboundNewRemotesDesc = newInstanceConntrackMetricDesc("oie_instance_inbound_new_remotes", "Inbound new remote IPs discovered since previous interval")
	cm.instanceInboundFlowsDesc = newInstanceConntrackMetricDesc("oie_instance_inbound_flows", "Inbound conntrack flows targeting this fixed IP in the current interval")
	cm.instanceInboundMaxFlowsSingleRemoteDesc = newInstanceConntrackMetricDesc("oie_instance_inbound_max_flows_single_remote", "Maximum inbound flows from a single remote IP in the current interval")
	cm.instanceInboundUniqueDstPortsDesc = newInstanceConntrackMetricDesc("oie_instance_inbound_unique_dst_ports", "Inbound unique destination ports on this fixed IP in the current interval")
	cm.instanceInboundNewDstPortsDesc = newInstanceConntrackMetricDesc("oie_instance_inbound_new_dst_ports", "Inbound new destination ports discovered since previous interval")
	cm.instanceInboundMaxFlowsSingleDstPortDesc = newInstanceConntrackMetricDesc("oie_instance_inbound_max_flows_single_dst_port", "Maximum inbound flows to a single destination port in the current interval")
	cm.instanceInboundBytesPerFlowDesc = newInstanceConntrackMetricDesc("oie_instance_inbound_bytes_per_flow", "Inbound average bytes per conntrack flow for this fixed IP (requires nf_conntrack_acct=1)")
	cm.instanceInboundPacketsPerFlowDesc = newInstanceConntrackMetricDesc("oie_instance_inbound_packets_per_flow", "Inbound average packets per conntrack flow for this fixed IP (requires nf_conntrack_acct=1)")
}

// -----------------------------------------------------------------------------
// Core Metric Calculation Logic
// -----------------------------------------------------------------------------

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

func (im *InstanceManager) getDomainMeta(dom libvirt.Domain, conn *libvirt.Libvirt) (*DomainStatic, error) {
	uuidBytes := dom.UUID
	instanceUUID := fmt.Sprintf("%x-%x-%x-%x-%x", uuidBytes[0:4], uuidBytes[4:6], uuidBytes[6:8], uuidBytes[8:10], uuidBytes[10:])

	im.domainMetaMu.RLock()
	meta, ok := im.domainMeta[instanceUUID]
	im.domainMetaMu.RUnlock()

	if ok && meta != nil && time.Since(meta.LastUpdated) < 5*time.Minute {
		return meta, nil
	}

	im.xmlInflightMu.Lock()
	if c, ok := im.xmlInflight[instanceUUID]; ok && c != nil {
		im.xmlInflightMu.Unlock()
		c.wg.Wait()
		if c.err != nil {
			return c.meta, c.err
		}
		if c.meta != nil {
			return c.meta, nil
		}
		im.domainMetaMu.RLock()
		meta3, ok3 := im.domainMeta[instanceUUID]
		im.domainMetaMu.RUnlock()
		if ok3 && meta3 != nil {
			return meta3, nil
		}
		return nil, fmt.Errorf("domain meta singleflight returned no result for %s", instanceUUID)
	}

	c := &domainXMLInflight{}
	c.wg.Add(1)
	if im.xmlInflight == nil {
		im.xmlInflight = make(map[string]*domainXMLInflight, 256)
	}
	im.xmlInflight[instanceUUID] = c
	im.xmlInflightMu.Unlock()

	defer func() {
		im.xmlInflightMu.Lock()
		delete(im.xmlInflight, instanceUUID)
		im.xmlInflightMu.Unlock()
		c.wg.Done()
	}()

	im.domainMetaMu.RLock()
	meta2, ok2 := im.domainMeta[instanceUUID]
	im.domainMetaMu.RUnlock()
	if ok2 && meta2 != nil && time.Since(meta2.LastUpdated) < 5*time.Minute {
		c.meta = meta2
		return meta2, nil
	}

	var xmlDesc string
	var err error
	if im.xmlRPCSem != nil {
		im.xmlRPCSem <- struct{}{}
		xmlDesc, err = conn.DomainGetXMLDesc(dom, 0)
		<-im.xmlRPCSem
	} else {
		xmlDesc, err = conn.DomainGetXMLDesc(dom, 0)
	}
	if err != nil {
		c.err = fmt.Errorf("failed to get domain XML description: %v", err)
		return nil, c.err
	}

	var domainXML DomainXML
	if err := xml.Unmarshal([]byte(xmlDesc), &domainXML); err != nil {
		c.err = fmt.Errorf("failed to parse domain XML: %v", err)
		return nil, c.err
	}

	meta = &DomainStatic{
		Name:            strings.TrimSpace(domainXML.Metadata.NovaInstance.NovaName),
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
		LastUpdated:     time.Now(),
	}

	if meta.Name == "" {
		meta.Name = dom.Name
	}

	for _, p := range domainXML.Metadata.NovaInstance.NovaPorts.Ports {
		uuid := strings.TrimSpace(p.PortUUID)
		if uuid == "" {
			continue
		}
		meta.PortUUIDs = append(meta.PortUUIDs, uuid)
		if meta.PortIPsByUUID == nil {
			meta.PortIPsByUUID = make(map[string][]IP, 4)
		}
		for _, ip := range p.IPs {
			addr := strings.TrimSpace(ip.Address)
			if addr == "" {
				continue
			}

			v := strings.TrimSpace(ip.IPVersion)
			if v == "" {
				v = "4"
			}

			meta.PortIPsByUUID[uuid] = append(meta.PortIPsByUUID[uuid], IP{
				Address: addr,
				Family:  v,
			})
			meta.FixedIPs = append(meta.FixedIPs, IP{
				Address: addr,
				Family:  v,
			})
		}

	}

	for _, disk := range domainXML.Devices.Disks {
		if disk.Device != "disk" {
			continue
		}
		d := DomainDisk{
			Device: disk.Device,
			Type:   disk.Type,
		}
		d.TargetDev = strings.TrimSpace(disk.Target.Dev)
		d.SourceFile = strings.TrimSpace(disk.Source.File)
		d.SourceName = strings.TrimSpace(disk.Source.Name)
		meta.Disks = append(meta.Disks, d)
	}

	for _, iface := range domainXML.Devices.Interfaces {
		ifaceName := strings.TrimSpace(iface.Target.Dev)
		if ifaceName == "" {
			continue
		}
		meta.Interfaces = append(meta.Interfaces, ifaceName)
	}

	im.domainMetaMu.Lock()
	im.domainMeta[instanceUUID] = meta
	im.domainMetaMu.Unlock()

	im.updateVMIPIndex(instanceUUID, meta.FixedIPs)

	c.meta = meta
	return meta, nil
}

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

	name := meta.Name
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

		netPPS      float64
		netDropRate float64

		outboundSignal float64
		inboundSignal  float64
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
		prometheus.MustNewConstMetric(mc.im.instanceStateDesc, prometheus.GaugeValue, float64(stateCode), name, instanceUUID, userUUID, projectUUID, projectName, stateDesc),
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
	guestUsedMB, resourceMemSeverity = mc.collectDomainMemoryMetrics(
		stat,
		now,
		name,
		instanceUUID,
		userUUID,
		projectUUID,
		projectName,
		instanceRunning,
		memMB,
		&dynamicMetrics,
	)

	diskCountDomain := 0
	diskCountDomain, maxDiskIOSignal, maxDiskActivity = mc.collectDomainDiskMetrics(
		meta,
		stat,
		now,
		name,
		instanceUUID,
		userUUID,
		projectUUID,
		projectName,
		&dynamicMetrics,
	)

	if agg != nil && diskCountDomain > 0 {
		agg.disks += diskCountDomain
	}

	cpuPressure := mc.collectDomainCPUMetrics(
		stat,
		name,
		instanceUUID,
		userUUID,
		projectUUID,
		projectName,
		vcpuCount,
		&dynamicMetrics,
	)

	netPPS, netDropRate, outboundSignal, inboundSignal, maxConntrackFlows = mc.collectDomainNetworkAndConntrack(
		meta,
		stat,
		now,
		name,
		instanceUUID,
		userUUID,
		projectUUID,
		projectName,
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
		name,
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
		mc.maybeLogResourceV2Event(name, instanceUUID, projectUUID, projectName, userUUID, resOut, resState)
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
		prometheus.MustNewConstMetric(mc.instanceResourceSeverityDesc, prometheus.GaugeValue, resourceSeverity, name, instanceUUID, projectUUID, projectName, userUUID),
		prometheus.MustNewConstMetric(mc.instanceResourceCpuSeverityDesc, prometheus.GaugeValue, resOut.CPU.Sev, name, instanceUUID, projectUUID, projectName, userUUID),
		prometheus.MustNewConstMetric(mc.instanceResourceMemSeverityDesc, prometheus.GaugeValue, resOut.MEM.Sev, name, instanceUUID, projectUUID, projectName, userUUID),
		prometheus.MustNewConstMetric(mc.instanceResourceDiskSeverityDesc, prometheus.GaugeValue, resOut.DISK.Sev, name, instanceUUID, projectUUID, projectName, userUUID),
		prometheus.MustNewConstMetric(mc.instanceResourceNetSeverityDesc, prometheus.GaugeValue, resOut.NET.Sev, name, instanceUUID, projectUUID, projectName, userUUID),
		prometheus.MustNewConstMetric(mc.instanceThreatListSeverityDesc, prometheus.GaugeValue, threatListSeverity, name, instanceUUID, projectUUID, projectName, userUUID),
		prometheus.MustNewConstMetric(mc.instanceAttentionSeverityDesc, prometheus.GaugeValue, attentionSeverity, name, instanceUUID, projectUUID, projectName, userUUID),
		prometheus.MustNewConstMetric(mc.instanceBehaviorSeverityDesc, prometheus.GaugeValue, behaviorScore, name, instanceUUID, projectUUID, projectName, userUUID),
	)

	if agg != nil {
		agg.metrics = append(agg.metrics, dynamicMetrics...)
	}
}

func (mc *MetricsCollector) collectDomainMemoryMetrics(
	stat *ParsedStats,
	now time.Time,
	name, instanceUUID, userUUID, projectUUID, projectName string,
	instanceRunning bool,
	memMB int,
	dynamicMetrics *[]prometheus.Metric,
) (float64, float64) {

	var guestUsedMB float64
	if instanceRunning {
		if stat.MemUsable > 0 && stat.MemCur >= stat.MemUsable {
			guestUsedMB = float64(stat.MemCur-stat.MemUsable) / 1024.0
		} else if stat.MemRss > 0 {
			guestUsedMB = float64(stat.MemRss) / 1024.0
		} else if stat.MemCur > 0 {
			guestUsedMB = float64(stat.MemCur) / 1024.0
		}
	}

	*dynamicMetrics = append(*dynamicMetrics,
		prometheus.MustNewConstMetric(mc.im.instanceMemSwapInBytesDesc, prometheus.CounterValue, float64(stat.SwapIn), name, instanceUUID, userUUID, projectUUID, projectName),
		prometheus.MustNewConstMetric(mc.im.instanceMemSwapOutBytesDesc, prometheus.CounterValue, float64(stat.SwapOut), name, instanceUUID, userUUID, projectUUID, projectName),
		prometheus.MustNewConstMetric(mc.im.instanceMemRSSMBDesc, prometheus.GaugeValue, float64(stat.MemRss)/1024.0, name, instanceUUID, userUUID, projectUUID, projectName),
		prometheus.MustNewConstMetric(mc.im.instanceMemMajorFaultsTotalDesc, prometheus.CounterValue, float64(stat.MajorFault), name, instanceUUID, userUUID, projectUUID, projectName),
		prometheus.MustNewConstMetric(mc.im.instanceMemMinorFaultsTotalDesc, prometheus.CounterValue, float64(stat.MinorFault), name, instanceUUID, userUUID, projectUUID, projectName),
	)

	siRate := 0.0
	mjRate := 0.0
	if instanceRunning {
		si, _, mj := mc.im.calculateMemRates(
			instanceUUID,
			stat.SwapIn,
			stat.SwapOut,
			stat.MajorFault,
			stat.MinorFault,
			now,
		)
		siRate = si
		mjRate = mj
	}

	if guestUsedMB > 0 {
		*dynamicMetrics = append(*dynamicMetrics,
			prometheus.MustNewConstMetric(mc.im.instanceMemUsedMBDesc, prometheus.GaugeValue, guestUsedMB, name, instanceUUID, userUUID, projectUUID, projectName),
		)
	}

	memUsageSeverity := 0.0
	if guestUsedMB > 0 && memMB > 0 {
		usageRatio := guestUsedMB / float64(memMB)
		if usageRatio > 1.5 {
			usageRatio = 1.5
		}
		if usageRatio > 0.80 {
			u01 := clamp01((usageRatio - 0.80) / 0.70)
			memUsageSeverity = u01 * 100.0
		}
	}

	swapSeverity := 0.0
	if siRate > 0 {
		const swapLow = 1024.0
		const swapHigh = 16384.0
		if siRate > swapLow {
			s01 := clamp01((siRate - swapLow) / (swapHigh - swapLow))
			swapSeverity = s01 * 100.0
		}
	}

	majorSeverity := 0.0
	if mjRate > 0 {
		const majorLow = 5.0
		const majorHigh = 200.0
		if mjRate > majorLow {
			m01 := clamp01((mjRate - majorLow) / (majorHigh - majorLow))
			majorSeverity = m01 * 100.0
		}
	}

	resourceMemSeverity := math.Max(memUsageSeverity, math.Max(swapSeverity, majorSeverity))
	return guestUsedMB, resourceMemSeverity
}

func (mc *MetricsCollector) collectDomainDiskMetrics(
	meta *DomainStatic,
	stat *ParsedStats,
	now time.Time,
	name, instanceUUID, userUUID, projectUUID, projectName string,
	dynamicMetrics *[]prometheus.Metric,
) (int, float64, float64) {

	seenDisks := make(map[string]struct{})
	diskCountDomain := 0
	diskMetaMap := make(map[string]DomainDisk)
	for _, d := range meta.Disks {
		if d.TargetDev != "" {
			diskMetaMap[d.TargetDev] = d
		}
	}

	maxDiskIOSignal := 0.0
	maxDiskActivity := 0.0

	for _, blk := range stat.Disks {
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

		rdIOPS, wrIOPS, rdLat, wrLat, flIOPS, flLat, avgIOSize, rwReqDelta, flReqDelta, bwBytesPerSec := mc.im.calculateDiskIO(
			key,
			int64(blk.RdReqs), int64(blk.WrReqs),
			int64(blk.RdBytes), int64(blk.WrBytes),
			int64(blk.RdTime), int64(blk.WrTime),
			int64(blk.FlReqs), int64(blk.FlTime),
			now,
		)

		diskSignal := 0.0

		iops := rdIOPS + wrIOPS
		activity := math.Max(iops/100.0, bwBytesPerSec/(10.0*1024.0*1024.0))
		if activity > maxDiskActivity {
			maxDiskActivity = activity
		}

		const ioSmall = 64.0 * 1024.0
		const ioLarge = 1024.0 * 1024.0

		const rwFloor = 0.002
		const rwCeilSmall = 0.020
		const rwCeilLarge = 0.100

		rwCeil := rwCeilSmall
		if avgIOSize >= ioLarge {
			rwCeil = rwCeilLarge
		} else if avgIOSize > ioSmall {
			t := (avgIOSize - ioSmall) / (ioLarge - ioSmall)
			rwCeil = rwCeilSmall + t*(rwCeilLarge-rwCeilSmall)
		}

		sevFromLat := func(lat, floor, ceil float64) float64 {
			if lat <= floor || ceil <= floor {
				return 0
			}
			return clamp01((lat-floor)/(ceil-floor)) * 100.0
		}

		if rwReqDelta >= 5 {
			if rdLat > 0 {
				diskSignal = math.Max(diskSignal, sevFromLat(rdLat, rwFloor, rwCeil))
			}
			if wrLat > 0 {
				diskSignal = math.Max(diskSignal, sevFromLat(wrLat, rwFloor, rwCeil))
			}
		}

		if flReqDelta > 0 && flLat > 0 {
			const flFloor = 0.001
			const flCeil = 0.040
			diskSignal = math.Max(diskSignal, sevFromLat(flLat, flFloor, flCeil))
		}

		if diskSignal > maxDiskIOSignal {
			maxDiskIOSignal = diskSignal
		}

		diskMetrics := make([]prometheus.Metric, 0, 15)
		diskMetrics = append(diskMetrics, prometheus.MustNewConstMetric(mc.im.instanceDiskInfoDesc, prometheus.GaugeValue, 1.0, name, instanceUUID, userUUID, projectUUID, projectName, volumeUUID, diskType, diskPath))

		counters := []struct {
			val  float64
			desc *prometheus.Desc
		}{
			{roundToFiveDecimals(float64(blk.RdBytes) * bytesToGigabytes), mc.im.instanceDiskReadGbytesTotalDesc},
			{roundToFiveDecimals(float64(blk.WrBytes) * bytesToGigabytes), mc.im.instanceDiskWriteGbytesTotalDesc},
			{float64(blk.RdReqs), mc.im.instanceDiskReadRequestsTotalDesc},
			{float64(blk.WrReqs), mc.im.instanceDiskWriteRequestsTotalDesc},
		}
		for _, c := range counters {
			diskMetrics = append(diskMetrics, prometheus.MustNewConstMetric(c.desc, prometheus.CounterValue, c.val, name, instanceUUID, userUUID, projectUUID, projectName, volumeUUID, diskType, diskPath))
		}

		details := []struct {
			val  float64
			desc *prometheus.Desc
		}{
			{float64(blk.RdTime) / 1e9, mc.im.instanceDiskReadSecondsTotalDesc},
			{float64(blk.WrTime) / 1e9, mc.im.instanceDiskWriteSecondsTotalDesc},
			{float64(blk.FlReqs), mc.im.instanceDiskFlushRequestsTotalDesc},
			{float64(blk.FlTime) / 1e9, mc.im.instanceDiskFlushSecondsTotalDesc},
		}

		for _, d := range details {
			diskMetrics = append(diskMetrics, prometheus.MustNewConstMetric(d.desc, prometheus.CounterValue, d.val, name, instanceUUID, userUUID, projectUUID, projectName, volumeUUID, diskType, diskPath))
		}

		alloc := blk.Allocation
		if alloc == 0 && blk.Physical > 0 {
			alloc = blk.Physical
		}

		diskMetrics = append(diskMetrics, prometheus.MustNewConstMetric(mc.im.instanceDiskAllocationBytesDesc, prometheus.GaugeValue, float64(alloc), name, instanceUUID, userUUID, projectUUID, projectName, volumeUUID, diskType, diskPath))
		diskMetrics = append(diskMetrics, prometheus.MustNewConstMetric(mc.im.instanceDiskCapacityBytesDesc, prometheus.GaugeValue, float64(blk.Capacity), name, instanceUUID, userUUID, projectUUID, projectName, volumeUUID, diskType, diskPath))
		diskMetrics = append(diskMetrics,
			prometheus.MustNewConstMetric(mc.im.instanceDiskReadIopsDesc, prometheus.GaugeValue, rdIOPS, name, instanceUUID, userUUID, projectUUID, projectName, volumeUUID, diskType, diskPath),
			prometheus.MustNewConstMetric(mc.im.instanceDiskWriteIopsDesc, prometheus.GaugeValue, wrIOPS, name, instanceUUID, userUUID, projectUUID, projectName, volumeUUID, diskType, diskPath),
			prometheus.MustNewConstMetric(mc.im.instanceDiskFlushIopsDesc, prometheus.GaugeValue, flIOPS, name, instanceUUID, userUUID, projectUUID, projectName, volumeUUID, diskType, diskPath),
			prometheus.MustNewConstMetric(mc.im.instanceDiskReadLatencySecondsDesc, prometheus.GaugeValue, rdLat, name, instanceUUID, userUUID, projectUUID, projectName, volumeUUID, diskType, diskPath),
			prometheus.MustNewConstMetric(mc.im.instanceDiskWriteLatencySecondsDesc, prometheus.GaugeValue, wrLat, name, instanceUUID, userUUID, projectUUID, projectName, volumeUUID, diskType, diskPath),
			prometheus.MustNewConstMetric(mc.im.instanceDiskFlushLatencySecondsDesc, prometheus.GaugeValue, flLat, name, instanceUUID, userUUID, projectUUID, projectName, volumeUUID, diskType, diskPath),
		)

		*dynamicMetrics = append(*dynamicMetrics, diskMetrics...)
	}

	return diskCountDomain, maxDiskIOSignal, maxDiskActivity
}

func (mc *MetricsCollector) collectDomainCPUMetrics(
	stat *ParsedStats,
	name, instanceUUID, userUUID, projectUUID, projectName string,
	vcpuCount int,
	dynamicMetrics *[]prometheus.Metric,
) float64 {

	var stealTotal, waitTotal uint64
	for i, vcpu := range stat.Vcpus {
		stealTotal += vcpu.Delay
		waitTotal += vcpu.Wait
		*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(mc.im.instanceCpuStealSecondsTotalDesc, prometheus.CounterValue, float64(vcpu.Delay)/1e9, name, instanceUUID, userUUID, projectUUID, projectName, strconv.Itoa(i)))
		*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(mc.im.instanceCpuWaitSecondsTotalDesc, prometheus.CounterValue, float64(vcpu.Wait)/1e9, name, instanceUUID, userUUID, projectUUID, projectName, strconv.Itoa(i)))
	}

	cpuUsage, stealPercent, waitPercent := mc.im.calculateCPUUsage(stat.CpuTime, stealTotal, waitTotal, instanceUUID, vcpuCount)
	*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(mc.im.instanceCpuVcpuPercentDesc, prometheus.GaugeValue, roundToFiveDecimals(cpuUsage), name, instanceUUID, userUUID, projectUUID, projectName))

	usage01 := 0.0
	if cpuUsage > 0 {
		usage01 = clamp01(cpuUsage / 100.0)
	}

	stall01 := 0.0
	stallTotal := stealPercent + waitPercent
	if stallTotal > 0 {
		stall01 = clamp01(stallTotal / 50.0)
	}

	cpuPressure := math.Max(stall01, usage01*0.3)
	return cpuPressure
}

func (mc *MetricsCollector) collectDomainNetworkAndConntrack(
	meta *DomainStatic,
	stat *ParsedStats,
	now time.Time,
	name, instanceUUID, userUUID, projectUUID, projectName string,
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
			*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(s.desc, prometheus.CounterValue, s.val, name, iface.Name, instanceUUID, userUUID, projectUUID, projectName))
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
		outboundSignal, inboundSignal, maxConntrackFlows = mc.cm.calculateConntrackMetrics(fixedIPs, connAgg, ipSet, hostIPs, hostConntrackMax, name, instanceUUID, projectUUID, projectName, userUUID, dynamicMetrics)
	}

	return netPPS, netDropRate, outboundSignal, inboundSignal, maxConntrackFlows
}

func (mc *MetricsCollector) collectDomainThreatSignals(
	connAgg *ConntrackAgg,
	ipSet map[string]struct{},
	name, instanceUUID, projectUUID, projectName, userUUID string,
	dynamicMetrics *[]prometheus.Metric,
) float64 {

	if mc.tm == nil {
		return 0.0
	}

	intelSum := 0.0
	intelCount := 0.0

	if mc.tm.spamEnabled {
		spamSignal := 0.0
		var hits map[PairKey]ConntrackEntry
		if connAgg != nil {
			hits = connAgg.SpamhausHits[instanceUUID]
		}
		mc.tm.exportSpamhausHits(hits, ipSet, name, instanceUUID, projectUUID, projectName, userUUID, dynamicMetrics, &spamSignal)
		intelSum += spamSignal
		intelCount++
	}

	for _, p := range mc.tm.Providers {
		if !p.Enabled {
			continue
		}

		providerSignal := 0.0
		var hits map[PairKey]ConntrackEntry
		if connAgg != nil {
			if pm, ok := connAgg.ProviderHits[p.Name]; ok {
				hits = pm[instanceUUID]
			}
		}
		mc.tm.exportProviderHits(p, hits, ipSet, name, instanceUUID, projectUUID, projectName, userUUID, dynamicMetrics, &providerSignal)
		intelSum += providerSignal
		intelCount++
	}

	intel01 := 0.0
	if intelCount > 0 {
		intel01 = clamp01(intelSum / intelCount)
	}

	intelBurst := intel01
	intelLong := mc.updateIntelHistory(instanceUUID, intelBurst)
	intelCombined := clamp01(0.5*intelBurst + 0.5*intelLong)
	return intelCombined
}

func (mc *MetricsCollector) updateIntelHistory(instanceUUID string, instant float64) float64 {
	const alphaIntel = 0.1

	mc.intelMu.Lock()
	defer mc.intelMu.Unlock()

	if mc.intelHistory == nil {
		mc.intelHistory = make(map[string]*IntelHistory)
	}

	s, ok := mc.intelHistory[instanceUUID]
	if !ok {
		s = &IntelHistory{
			EWMA:        instant,
			Initialized: true,
		}
		mc.intelHistory[instanceUUID] = s
		return s.EWMA
	}

	s.EWMA = s.EWMA + alphaIntel*(instant-s.EWMA)
	return s.EWMA
}

func (im *InstanceManager) setActiveInstances(activeSet map[string]struct{}) {
	im.activeInstancesMu.Lock()
	im.activeInstances = activeSet
	im.activeInstancesMu.Unlock()
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

func (im *InstanceManager) updateVMIPIndex(instanceUUID string, fixedIPs []IP) {
	if instanceUUID == "" {
		return
	}
	keys := make([]IPKey, 0, len(fixedIPs))
	for _, ip := range fixedIPs {
		if ip.Address == "" {
			continue
		}
		k := IPStrToKey(ip.Address)
		if k == (IPKey{}) {
			continue
		}
		keys = append(keys, k)
	}

	im.vmIPIndexMu.Lock()
	old := im.vmIPKeysByInstance[instanceUUID]
	for _, k := range old {
		delete(im.vmIPSet, k)
		delete(im.vmIPToInstance, k)
	}
	for _, k := range keys {
		im.vmIPSet[k] = struct{}{}
		im.vmIPToInstance[k] = instanceUUID
	}
	im.vmIPKeysByInstance[instanceUUID] = keys
	im.vmIPIndexMu.Unlock()
}

func (im *InstanceManager) removeVMIPIndex(instanceUUID string) {
	if instanceUUID == "" {
		return
	}
	im.vmIPIndexMu.Lock()
	old := im.vmIPKeysByInstance[instanceUUID]
	for _, k := range old {
		delete(im.vmIPSet, k)
		delete(im.vmIPToInstance, k)
	}
	delete(im.vmIPKeysByInstance, instanceUUID)
	im.vmIPIndexMu.Unlock()
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
			im.removeVMIPIndex(uuid)
		}
	}
	im.domainMetaMu.Unlock()
}

func (im *InstanceManager) cleanupResourceSamples() {
	for i := 0; i < shardCount; i++ {
		im.cpuMu[i].Lock()
		for uuid := range im.cpuSamples[i] {
			if !im.isInstanceActive(uuid) {
				delete(im.cpuSamples[i], uuid)
			}
		}
		im.cpuMu[i].Unlock()

		im.diskMu[i].Lock()
		for key := range im.diskSamples[i] {
			parts := strings.SplitN(key, "|", 2)
			if len(parts) > 0 && !im.isInstanceActive(parts[0]) {
				delete(im.diskSamples[i], key)
			}
		}
		im.diskMu[i].Unlock()

		im.memMu[i].Lock()
		for uuid := range im.memSamples[i] {
			if !im.isInstanceActive(uuid) {
				delete(im.memSamples[i], uuid)
			}
		}
		im.memMu[i].Unlock()

		im.netMu[i].Lock()
		for uuid := range im.netSamples[i] {
			if !im.isInstanceActive(uuid) {
				delete(im.netSamples[i], uuid)
			}
		}
		im.netMu[i].Unlock()
	}
}

func (im *InstanceManager) describeInstanceMetrics(ch chan<- *prometheus.Desc) {
	ch <- im.instanceStateDesc
	ch <- im.instanceDiskReadGbytesTotalDesc
	ch <- im.instanceDiskWriteGbytesTotalDesc
	ch <- im.instanceDiskReadRequestsTotalDesc
	ch <- im.instanceDiskWriteRequestsTotalDesc
	ch <- im.instanceDiskReadSecondsTotalDesc
	ch <- im.instanceDiskWriteSecondsTotalDesc
	ch <- im.instanceDiskFlushRequestsTotalDesc
	ch <- im.instanceDiskFlushSecondsTotalDesc
	ch <- im.instanceDiskCapacityBytesDesc
	ch <- im.instanceDiskAllocationBytesDesc
	ch <- im.instanceDiskReadIopsDesc
	ch <- im.instanceDiskWriteIopsDesc
	ch <- im.instanceDiskFlushIopsDesc
	ch <- im.instanceDiskReadLatencySecondsDesc
	ch <- im.instanceDiskWriteLatencySecondsDesc
	ch <- im.instanceDiskFlushLatencySecondsDesc
	ch <- im.instanceDiskInfoDesc

	ch <- im.instanceCpuVcpuPercentDesc
	ch <- im.instanceCpuVcpuCountDesc
	ch <- im.instanceCpuStealSecondsTotalDesc
	ch <- im.instanceCpuWaitSecondsTotalDesc

	ch <- im.instanceMemAllocatedMBDesc
	ch <- im.instanceMemUsedMBDesc
	ch <- im.instanceMemSwapInBytesDesc
	ch <- im.instanceMemSwapOutBytesDesc
	ch <- im.instanceHugetlbPgAllocDesc
	ch <- im.instanceHugetlbPgFailDesc

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

// -----------------------------------------------------------------------------
// Host Resource Parsing Helpers
// -----------------------------------------------------------------------------

func (mc *MetricsCollector) getHostMemInfo() (freeMB, availMB float64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	found := 0
	for scanner.Scan() && found < 2 {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemFree:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				v, _ := strconv.ParseFloat(parts[1], 64)
				freeMB = v / 1024.0
				found++
			}
		} else if strings.HasPrefix(line, "MemAvailable:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				v, _ := strconv.ParseFloat(parts[1], 64)
				availMB = v / 1024.0
				found++
			}
		}
	}
	return
}

func (mc *MetricsCollector) getHostCPUPercent() float64 {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		return 0
	}
	line := scanner.Text()
	parts := strings.Fields(line)
	if len(parts) < 8 {
		return 0
	}

	user, _ := strconv.ParseFloat(parts[1], 64)
	nice, _ := strconv.ParseFloat(parts[2], 64)
	system, _ := strconv.ParseFloat(parts[3], 64)
	idle, _ := strconv.ParseFloat(parts[4], 64)
	iowait, _ := strconv.ParseFloat(parts[5], 64)
	irq, _ := strconv.ParseFloat(parts[6], 64)
	softirq, _ := strconv.ParseFloat(parts[7], 64)
	steal := 0.0
	if len(parts) > 8 {
		steal, _ = strconv.ParseFloat(parts[8], 64)
	}

	currentIdle := idle + iowait
	currentTotal := user + nice + system + idle + iowait + irq + softirq + steal

	mc.hostCpuState.mu.Lock()
	defer mc.hostCpuState.mu.Unlock()

	usagePercent := 0.0

	if mc.hostCpuState.initialized {
		deltaTotal := currentTotal - mc.hostCpuState.prevTotal
		deltaIdle := currentIdle - mc.hostCpuState.prevIdle

		if deltaTotal > 0 {
			usagePercent = ((deltaTotal - deltaIdle) / deltaTotal) * 100.0
		}
	} else {
		mc.hostCpuState.initialized = true
	}

	mc.hostCpuState.prevTotal = currentTotal
	mc.hostCpuState.prevIdle = currentIdle

	return clamp01(usagePercent/100.0) * 100.0
}

func (im *InstanceManager) snapshotOVNPortToInstance(activeSet map[string]struct{}) map[string]string {
	m := make(map[string]string, 64)
	im.domainMetaMu.RLock()
	defer im.domainMetaMu.RUnlock()
	for uuid := range activeSet {
		meta := im.domainMeta[uuid]
		if meta == nil {
			continue
		}
		for _, p := range meta.PortUUIDs {
			if len(p) == 36 {
				m[p] = uuid
			}
		}
	}
	return m
}

func (im *InstanceManager) snapshotOVNPortToIPKeys(activeSet map[string]struct{}) map[string][]IPKey {
	m := make(map[string][]IPKey, 64)
	im.domainMetaMu.RLock()
	defer im.domainMetaMu.RUnlock()
	for uuid := range activeSet {
		meta := im.domainMeta[uuid]
		if meta == nil || len(meta.PortIPsByUUID) == 0 {
			continue
		}
		for port, ips := range meta.PortIPsByUUID {
			if len(port) != 36 {
				continue
			}
			keys := m[port]
			for _, ip := range ips {
				k := IPStrToKey(ip.Address)
				if k == (IPKey{}) {
					continue
				}
				keys = append(keys, k)
			}
			if len(keys) > 0 {
				m[port] = keys
			}
		}
	}
	return m
}

func (im *InstanceManager) snapshotVMIPIdentities(activeSet map[string]struct{}) []VMIPIdentity {
	out := make([]VMIPIdentity, 0, 256)
	seen := make(map[VMIPIdentity]struct{}, 256)
	im.domainMetaMu.RLock()
	defer im.domainMetaMu.RUnlock()
	for uuid := range activeSet {
		meta := im.domainMeta[uuid]
		if meta == nil {
			continue
		}
		for _, ip := range meta.FixedIPs {
			k := IPStrToKey(ip.Address)
			if k == (IPKey{}) {
				continue
			}
			id := VMIPIdentity{InstanceUUID: uuid, IP: k}
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			out = append(out, id)
		}
	}
	return out
}
