package main

import (
	"github.com/prometheus/client_golang/prometheus"
)

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
