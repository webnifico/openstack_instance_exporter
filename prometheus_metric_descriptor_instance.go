package main

import (
	"github.com/prometheus/client_golang/prometheus"
)

func initInstanceMetrics(im *InstanceManager) {
	im.instanceInventoryInfoDesc = newInstanceMetricDescExtra("oie_instance_inventory_info", "Configured Libvirt inventory including inactive definitions; configuration is not runtime usage; libvirt_active is 1 for an active domain and 0 for an inactive definition", "user_name", "flavor", "vcpus", "mem_mb", "root_type", "created_at", "metadata_version", "libvirt_active", "state_desc")
	im.instanceInventoryDiskInfoDesc = newInstanceMetricDescExtra("oie_instance_inventory_disk_info", "Disk configuration from Libvirt XML, including inactive definitions; no runtime or physical storage usage is implied", "volume_uuid", "disk_type", "disk_path")
	im.instanceInventoryInterfaceInfoDesc = newInstanceMetricDescExtra("oie_instance_inventory_interface_info", "Interface configuration from Libvirt XML, including inactive definitions; an absent runtime interface name is empty", "interface_index", "ifname", "mac", "model", "interface_type", "attachment", "port_uuid")
	im.instanceInventoryAddressInfoDesc = newInstanceMetricDescExtra("oie_instance_inventory_address_info", "Fixed address and port configuration retained in Libvirt metadata; not proof of live network ownership or current Neutron state", "port_uuid", "ip", "family")
	im.instanceInfoDesc = newInstanceMetricDescExtra(
		"oie_instance_info",
		"Static instance metadata",
		"user_name",
		"flavor",
		"vcpus",
		"mem_mb",
		"root_type",
		"created_at",
		"metadata_version",
	)
	im.instanceStateDesc = newInstanceMetricDescExtra("oie_instance_state_code", "Libvirt state code", "state_desc")

	diskLabels := labelsInstance("volume_uuid", "disk_type", "disk_path")
	netLabels := labelsInstance("ifname")

	im.instanceDiskReadGbytesTotalDesc = prometheus.NewDesc("oie_instance_disk_read_gbytes_total", "Disk read gibibytes; metric name retained for compatibility", diskLabels, nil)
	im.instanceDiskWriteGbytesTotalDesc = prometheus.NewDesc("oie_instance_disk_write_gbytes_total", "Disk write gibibytes; metric name retained for compatibility", diskLabels, nil)
	im.instanceDiskReadRequestsTotalDesc = prometheus.NewDesc("oie_instance_disk_read_requests_total", "Disk read requests", diskLabels, nil)
	im.instanceDiskWriteRequestsTotalDesc = prometheus.NewDesc("oie_instance_disk_write_requests_total", "Disk write requests", diskLabels, nil)
	im.instanceDiskReadSecondsTotalDesc = prometheus.NewDesc("oie_instance_disk_read_seconds_total", "Total seconds spent reading from disk", diskLabels, nil)
	im.instanceDiskWriteSecondsTotalDesc = prometheus.NewDesc("oie_instance_disk_write_seconds_total", "Total seconds spent writing to disk", diskLabels, nil)
	im.instanceDiskFlushRequestsTotalDesc = prometheus.NewDesc("oie_instance_disk_flush_requests_total", "Total flush requests", diskLabels, nil)
	im.instanceDiskFlushSecondsTotalDesc = prometheus.NewDesc("oie_instance_disk_flush_seconds_total", "Total seconds spent flushing to disk", diskLabels, nil)
	im.instanceDiskCapacityBytesDesc = prometheus.NewDesc("oie_instance_disk_capacity_bytes", "Logical size of the disk", diskLabels, nil)
	im.instanceDiskAllocationBytesDesc = prometheus.NewDesc("oie_instance_disk_allocation_bytes", "Libvirt block allocation boundary in bytes (offset of the highest written sector); not backend physical usage", diskLabels, nil)
	im.instanceDiskInfoDesc = prometheus.NewDesc("oie_instance_disk_info", "Static disk metadata", diskLabels, nil)

	im.instanceDiskReadIopsDesc = prometheus.NewDesc("oie_instance_disk_read_iops", "Disk read IOPS (per-second rate computed from libvirt counters)", diskLabels, nil)
	im.instanceDiskWriteIopsDesc = prometheus.NewDesc("oie_instance_disk_write_iops", "Disk write IOPS (per-second rate computed from libvirt counters)", diskLabels, nil)
	im.instanceDiskFlushIopsDesc = prometheus.NewDesc("oie_instance_disk_flush_iops", "Disk flush IOPS (per-second rate computed from libvirt counters)", diskLabels, nil)
	im.instanceDiskReadLatencySecondsDesc = prometheus.NewDesc("oie_instance_disk_read_latency_seconds", "Average disk read latency in seconds over the interval", diskLabels, nil)
	im.instanceDiskWriteLatencySecondsDesc = prometheus.NewDesc("oie_instance_disk_write_latency_seconds", "Average disk write latency in seconds over the interval", diskLabels, nil)
	im.instanceDiskFlushLatencySecondsDesc = prometheus.NewDesc("oie_instance_disk_flush_latency_seconds", "Average disk flush latency in seconds over the interval", diskLabels, nil)

	retypeLabels := labelsInstance("volume_uuid", "disk_type", "disk_path", "destination_volume_uuid", "destination_disk_type")
	im.instanceDiskRetypeActiveDesc = prometheus.NewDesc("oie_instance_disk_retype_active", "Observed Libvirt block-copy presence for a Cinder RBD volume retype: 1 while the copy job was recently confirmed present, including copy-ready jobs awaiting pivot, and 0 after a successful XML inspection finds the mirror gone; emitted only for active or recently observed terminal operations", retypeLabels, nil)
	im.instanceDiskRetypeProgressDesc = prometheus.NewDesc("oie_instance_disk_retype_progress_percent", "Approximate Libvirt block-job progress for an active Cinder volume retype (0-100 percent); logical work position, not Ceph allocation, transferred bytes, or ETA; omitted when no usable total is available unless mirror XML confirms copy-ready", retypeLabels, nil)
	im.instanceDiskRetypeStatusCodeDesc = prometheus.NewDesc("oie_instance_disk_retype_status_code", "Observed Libvirt-side RBD block-copy state: 1 copying or finalizing, 2 mirror gone and live source matches the saved destination, 3 mirror gone and live source matches the original source, 4 mirror gone with an unmatched final source, 5 copy ready and awaiting pivot, 6 copy ready and awaiting pivot for at least 10 minutes; not authoritative Cinder status", retypeLabels, nil)
	im.instanceDiskRetypeObservationHealthyDesc = prometheus.NewDesc("oie_instance_disk_retype_observation_healthy", "Whether the latest Libvirt block-job query for this active retype succeeded: 1 healthy, 0 timed out or failed; omitted while the main Libvirt source is unavailable and emitted only for observed active operations", retypeLabels, nil)
	im.instanceDiskRetypeStartTimestampDesc = prometheus.NewDesc("oie_instance_disk_retype_start_timestamp_seconds", "Unix timestamp when this exporter first observed the Libvirt block-copy job; not the authoritative Cinder operation start time", retypeLabels, nil)
	im.instanceDiskRetypeReadyTimestampDesc = prometheus.NewDesc("oie_instance_disk_retype_ready_timestamp_seconds", "Unix timestamp when this exporter first observed the Libvirt block copy ready and awaiting pivot; omitted until ready and not an authoritative Cinder lifecycle timestamp", retypeLabels, nil)
	im.instanceDiskRetypeEndTimestampDesc = prometheus.NewDesc("oie_instance_disk_retype_end_timestamp_seconds", "Unix timestamp when a successful Libvirt XML inspection first found the saved block-copy mirror gone; not an authoritative Cinder operation end time and emitted only for recent observations", retypeLabels, nil)

	im.instanceCpuVcpuPercentDesc = newInstanceMetricDesc("oie_instance_cpu_vcpu_percent", "CPU usage percentage per vCPU")
	im.instanceCpuVcpuCountDesc = newInstanceMetricDesc("oie_instance_cpu_vcpu_count", "Allocated vCPU count for this instance")
	im.instanceCpuStealSecondsTotalDesc = newInstanceMetricDescExtra("oie_instance_cpu_steal_seconds_total", "Total vCPU host-scheduler runqueue delay exposed to the guest as steal time", "vcpu")
	im.instanceCpuWaitSecondsTotalDesc = newInstanceMetricDescExtra("oie_instance_cpu_wait_seconds_total", "Compatibility counter for total vCPU host-scheduler runqueue wait; an alternative to delay/steal, not guest I/O wait", "vcpu")

	im.instanceMemAllocatedMBDesc = newInstanceMetricDesc("oie_instance_mem_allocated_mb", "Allocated memory for this instance in mebibytes; metric name retained for compatibility")
	im.instanceMemUsedMBDesc = newInstanceMetricDesc("oie_instance_mem_used_mb", "Guest-view used memory for this instance in mebibytes; metric name retained for compatibility")
	im.instanceMemSwapInBytesDesc = newInstanceMetricDesc("oie_instance_mem_swap_in_bytes_total", "Memory swapped in")
	im.instanceMemSwapOutBytesDesc = newInstanceMetricDesc("oie_instance_mem_swap_out_bytes_total", "Memory swapped out")
	im.instanceMemMajorFaultsTotalDesc = newInstanceMetricDesc("oie_instance_mem_major_faults_total", "Major memory page faults")
	im.instanceMemMinorFaultsTotalDesc = newInstanceMetricDesc("oie_instance_mem_minor_faults_total", "Minor memory page faults")
	im.instanceMemRSSMBDesc = newInstanceMetricDesc("oie_instance_mem_rss_mb", "Libvirt-reported resident set size of the process running this instance in mebibytes; includes resident process mappings and is not unique physical host RAM consumption; metric name retained for compatibility")

	im.instanceHugetlbPgAllocDesc = newInstanceMetricDesc("oie_instance_hugetlb_pgalloc_total", "HugePage allocations successful")
	im.instanceHugetlbPgFailDesc = newInstanceMetricDesc("oie_instance_hugetlb_pgfail_total", "HugePage allocations failed")

	im.instanceNetRxGbytesTotalDesc = prometheus.NewDesc("oie_instance_net_rx_gbytes_total", "Network receive gibibytes; metric name retained for compatibility", netLabels, nil)
	im.instanceNetTxGbytesTotalDesc = prometheus.NewDesc("oie_instance_net_tx_gbytes_total", "Network transmit gibibytes; metric name retained for compatibility", netLabels, nil)
	im.instanceNetRxPacketsTotalDesc = prometheus.NewDesc("oie_instance_net_rx_packets_total", "Network receive packets", netLabels, nil)
	im.instanceNetTxPacketsTotalDesc = prometheus.NewDesc("oie_instance_net_tx_packets_total", "Network transmit packets", netLabels, nil)
	im.instanceNetRxErrorsTotalDesc = prometheus.NewDesc("oie_instance_net_rx_errors_total", "Network receive errors", netLabels, nil)
	im.instanceNetTxErrorsTotalDesc = prometheus.NewDesc("oie_instance_net_tx_errors_total", "Network transmit errors", netLabels, nil)
	im.instanceNetRxDroppedTotalDesc = prometheus.NewDesc("oie_instance_net_rx_dropped_total", "Network receive dropped packets", netLabels, nil)
	im.instanceNetTxDroppedTotalDesc = prometheus.NewDesc("oie_instance_net_tx_dropped_total", "Network transmit dropped packets", netLabels, nil)
}
func initInstanceSeverityMetrics(mc *MetricsCollector) {
	mc.instanceResourceSeverityDesc = newInstanceSeverityMetricDesc("oie_instance_resource_severity", "Resource pressure severity (0-100) combining CPU, memory, disk and network/conntrack")
	mc.instanceThreatListSeverityDesc = newInstanceSeverityMetricDesc("oie_instance_threat_list_severity", "Threat list severity (0-100) derived strictly from Threat Intel (Spamhaus, Tor, etc) matches")
	mc.instanceAttentionSeverityDesc = newInstanceSeverityMetricDesc("oie_instance_attention_severity", "Combined attention severity (0-100) based on resource pressure, behavior anomalies, and threat-list signals")
	mc.instanceBehaviorSeverityDesc = newInstanceSeverityMetricDesc("oie_instance_behavior_severity", "Pure behavior severity (0-100) derived from conntrack behavior signals (no intel)")

	mc.instanceResourceCpuSeverityDesc = newInstanceSeverityMetricDesc("oie_instance_resource_cpu_severity", "Resource CPU axis severity (0-100) based on pressure EWMA")
	mc.instanceResourceMemSeverityDesc = newInstanceSeverityMetricDesc("oie_instance_resource_mem_severity", "Resource memory axis severity (0-100) based on pressure EWMA")
	mc.instanceResourceDiskSeverityDesc = newInstanceSeverityMetricDesc("oie_instance_resource_disk_severity", "Resource disk axis severity (0-100) based on latency/flush pressure EWMA")
	mc.instanceResourceNetSeverityDesc = newInstanceSeverityMetricDesc("oie_instance_resource_net_severity", "Resource network axis severity (0-100) based on drop/capacity pressure EWMA")
	mc.instanceResourceAxisFreshDesc = newInstanceMetricDescExtra("oie_instance_resource_axis_fresh", "1 if the resource axis received a complete valid sample in the current collection cycle, else 0", "axis")
	mc.instanceResourceAxisAvailableDesc = newInstanceMetricDescExtra("oie_instance_resource_axis_available", "1 if the resource axis has a fresh or retained severity value within the maximum retention age, else 0", "axis")
	mc.instanceResourceAxisLastSuccessTimestampDesc = newInstanceMetricDescExtra("oie_instance_resource_axis_last_success_timestamp_seconds", "Unix timestamp of the last complete valid resource-axis sample; 0 before the first success", "axis")
	mc.instanceResourceAxisStaleSecondsDesc = newInstanceMetricDescExtra("oie_instance_resource_axis_stale_seconds", "Seconds since the last complete valid resource-axis sample; -1 before the first success", "axis")
}
func (im *InstanceManager) describeInstanceMetrics(ch chan<- *prometheus.Desc) {
	ch <- im.instanceInventoryInfoDesc
	ch <- im.instanceInventoryDiskInfoDesc
	ch <- im.instanceInventoryInterfaceInfoDesc
	ch <- im.instanceInventoryAddressInfoDesc
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
	ch <- im.instanceDiskRetypeActiveDesc
	ch <- im.instanceDiskRetypeProgressDesc
	ch <- im.instanceDiskRetypeStatusCodeDesc
	ch <- im.instanceDiskRetypeObservationHealthyDesc
	ch <- im.instanceDiskRetypeStartTimestampDesc
	ch <- im.instanceDiskRetypeReadyTimestampDesc
	ch <- im.instanceDiskRetypeEndTimestampDesc

	ch <- im.instanceCpuVcpuPercentDesc
	ch <- im.instanceCpuVcpuCountDesc
	ch <- im.instanceCpuStealSecondsTotalDesc
	ch <- im.instanceCpuWaitSecondsTotalDesc

	ch <- im.instanceMemAllocatedMBDesc
	ch <- im.instanceMemUsedMBDesc
	ch <- im.instanceMemSwapInBytesDesc
	ch <- im.instanceMemSwapOutBytesDesc
	ch <- im.instanceMemRSSMBDesc
	ch <- im.instanceMemMajorFaultsTotalDesc
	ch <- im.instanceMemMinorFaultsTotalDesc
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
