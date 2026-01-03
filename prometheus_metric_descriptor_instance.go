package main

import (
	"github.com/prometheus/client_golang/prometheus"
)

func initInstanceMetrics(im *InstanceManager) {
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

	im.instanceDiskReadGbytesTotalDesc = prometheus.NewDesc("oie_instance_disk_read_gbytes_total", "Disk read gigabytes", diskLabels, nil)
	im.instanceDiskWriteGbytesTotalDesc = prometheus.NewDesc("oie_instance_disk_write_gbytes_total", "Disk write gigabytes", diskLabels, nil)
	im.instanceDiskReadRequestsTotalDesc = prometheus.NewDesc("oie_instance_disk_read_requests_total", "Disk read requests", diskLabels, nil)
	im.instanceDiskWriteRequestsTotalDesc = prometheus.NewDesc("oie_instance_disk_write_requests_total", "Disk write requests", diskLabels, nil)
	im.instanceDiskReadSecondsTotalDesc = prometheus.NewDesc("oie_instance_disk_read_seconds_total", "Total seconds spent reading from disk", diskLabels, nil)
	im.instanceDiskWriteSecondsTotalDesc = prometheus.NewDesc("oie_instance_disk_write_seconds_total", "Total seconds spent writing to disk", diskLabels, nil)
	im.instanceDiskFlushRequestsTotalDesc = prometheus.NewDesc("oie_instance_disk_flush_requests_total", "Total flush requests", diskLabels, nil)
	im.instanceDiskFlushSecondsTotalDesc = prometheus.NewDesc("oie_instance_disk_flush_seconds_total", "Total seconds spent flushing to disk", diskLabels, nil)
	im.instanceDiskCapacityBytesDesc = prometheus.NewDesc("oie_instance_disk_capacity_bytes", "Logical size of the disk", diskLabels, nil)
	im.instanceDiskAllocationBytesDesc = prometheus.NewDesc("oie_instance_disk_allocation_bytes", "Physical space used on storage", diskLabels, nil)
	im.instanceDiskInfoDesc = prometheus.NewDesc("oie_instance_disk_info", "Static disk metadata", diskLabels, nil)

	im.instanceDiskReadIopsDesc = prometheus.NewDesc("oie_instance_disk_read_iops", "Disk read IOPS (per-second rate computed from libvirt counters)", diskLabels, nil)
	im.instanceDiskWriteIopsDesc = prometheus.NewDesc("oie_instance_disk_write_iops", "Disk write IOPS (per-second rate computed from libvirt counters)", diskLabels, nil)
	im.instanceDiskFlushIopsDesc = prometheus.NewDesc("oie_instance_disk_flush_iops", "Disk flush IOPS (per-second rate computed from libvirt counters)", diskLabels, nil)
	im.instanceDiskReadLatencySecondsDesc = prometheus.NewDesc("oie_instance_disk_read_latency_seconds", "Average disk read latency in seconds over the interval", diskLabels, nil)
	im.instanceDiskWriteLatencySecondsDesc = prometheus.NewDesc("oie_instance_disk_write_latency_seconds", "Average disk write latency in seconds over the interval", diskLabels, nil)
	im.instanceDiskFlushLatencySecondsDesc = prometheus.NewDesc("oie_instance_disk_flush_latency_seconds", "Average disk flush latency in seconds over the interval", diskLabels, nil)

	im.instanceCpuVcpuPercentDesc = newInstanceMetricDesc("oie_instance_cpu_vcpu_percent", "CPU usage percentage per vCPU")
	im.instanceCpuVcpuCountDesc = newInstanceMetricDesc("oie_instance_cpu_vcpu_count", "Allocated vCPU count for this instance")
	im.instanceCpuStealSecondsTotalDesc = newInstanceMetricDescExtra("oie_instance_cpu_steal_seconds_total", "Total time vCPU spent waiting on Host Scheduler", "vcpu")
	im.instanceCpuWaitSecondsTotalDesc = newInstanceMetricDescExtra("oie_instance_cpu_wait_seconds_total", "Total time vCPU spent waiting on I/O", "vcpu")

	im.instanceMemAllocatedMBDesc = newInstanceMetricDesc("oie_instance_mem_allocated_mb", "Allocated memory for this instance (MB)")
	im.instanceMemUsedMBDesc = newInstanceMetricDesc("oie_instance_mem_used_mb", "Guest-view used memory for this instance (MB)")
	im.instanceMemSwapInBytesDesc = newInstanceMetricDesc("oie_instance_mem_swap_in_bytes_total", "Memory swapped in")
	im.instanceMemSwapOutBytesDesc = newInstanceMetricDesc("oie_instance_mem_swap_out_bytes_total", "Memory swapped out")
	im.instanceMemMajorFaultsTotalDesc = newInstanceMetricDesc("oie_instance_mem_major_faults_total", "Major memory page faults")
	im.instanceMemMinorFaultsTotalDesc = newInstanceMetricDesc("oie_instance_mem_minor_faults_total", "Minor memory page faults")
	im.instanceMemRSSMBDesc = newInstanceMetricDesc("oie_instance_mem_rss_mb", "Resident Set Size (Actual Host RAM used) (MB)")

	im.instanceHugetlbPgAllocDesc = newInstanceMetricDesc("oie_instance_hugetlb_pgalloc_total", "HugePage allocations successful")
	im.instanceHugetlbPgFailDesc = newInstanceMetricDesc("oie_instance_hugetlb_pgfail_total", "HugePage allocations failed")

	im.instanceNetRxGbytesTotalDesc = prometheus.NewDesc("oie_instance_net_rx_gbytes_total", "Network receive gigabytes", netLabels, nil)
	im.instanceNetTxGbytesTotalDesc = prometheus.NewDesc("oie_instance_net_tx_gbytes_total", "Network transmit gigabytes", netLabels, nil)
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
	mc.instanceAttentionSeverityDesc = newInstanceSeverityMetricDesc("oie_instance_attention_severity", "Combined attention severity (0-100) based on resource pressure and threat signals")
	mc.instanceBehaviorSeverityDesc = newInstanceSeverityMetricDesc("oie_instance_behavior_severity", "Pure behavior severity (0-100) derived from conntrack behavior signals (no intel)")

	mc.instanceResourceCpuSeverityDesc = newInstanceSeverityMetricDesc("oie_instance_resource_cpu_severity", "Resource CPU axis severity (0-100) based on pressure EWMA")
	mc.instanceResourceMemSeverityDesc = newInstanceSeverityMetricDesc("oie_instance_resource_mem_severity", "Resource memory axis severity (0-100) based on pressure EWMA")
	mc.instanceResourceDiskSeverityDesc = newInstanceSeverityMetricDesc("oie_instance_resource_disk_severity", "Resource disk axis severity (0-100) based on latency/flush pressure EWMA")
	mc.instanceResourceNetSeverityDesc = newInstanceSeverityMetricDesc("oie_instance_resource_net_severity", "Resource network axis severity (0-100) based on drop/capacity pressure EWMA")
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
