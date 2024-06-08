# OpenStack Instance Exporter Metrics Collector

## Overview

This project provides a metrics collector for OpenStack instances using libvirt and Prometheus. The collector gathers various metrics from the instances and exposes them for Prometheus to scrape. These metrics include CPU usage, disk I/O, and network statistics, which are crucial for monitoring and ensuring optimal performance and resource usage.

While similar to libvirt exporter, it associates OpenStack related UUIDs to metrics so that alerting/monitoring can be provided as it relates to hypervisor > project > instance in that order of precedence. It also collects less and limited metrics compared to libvirt exporter to ensure efficiency. 

Currently tested with the following stack:

- Ubuntu 22.04
- OpenStack Bobcat
- Libvirt 8.0.0
- Prometheus 2.47.2
- Grafana 11.0.0

## Build Requirements

Go 1.22

To build clone and: `go build`

## Features

- Collects CPU usage metrics, considering the number of vCPUs.
- Gathers disk read/write statistics for both Ceph-based and local file-based disks.
- Monitors network traffic, including packets and errors.
- Exposes metrics in a Prometheus-compatible format.
- Utilizes caching for efficient metric collection and serving.
- Metrics are ran and stored on compute nodes in advance so that API queries are highly performant and efficient.
- Configurable logging for detailed metric data collection.

## Metrics

The metrics collected by this collector are prefixed with `oie` and include:

### CPU Metrics

- **oie_cpu_usage_percent**: CPU usage percentage, adjusted for the number of vCPUs.

### Disk Metrics

- **oie_disk_read_gbytes**: Disk read in gigabytes.
- **oie_disk_write_gbytes**: Disk write in gigabytes.
- **oie_disk_read_requests**: Total number of disk read requests.
- **oie_disk_write_requests**: Total number of disk write requests.

### Network Metrics

- **oie_net_tx_gbytes**: Network transmit in gigabytes.
- **oie_net_rx_gbytes**: Network receive in gigabytes.
- **oie_net_tx_packets_total**: Total number of transmitted packets.
- **oie_net_rx_packets_total**: Total number of received packets.
- **oie_net_tx_errors_total**: Total number of transmission errors.
- **oie_net_rx_errors_total**: Total number of receive errors.
- **oie_net_tx_dropped_total**: Total number of dropped transmitted packets.
- **oie_net_rx_dropped_total**: Total number of dropped received packets.

### Dynamic Disk Metrics

The collector dynamically gathers metrics for different types of disks, including both Ceph-based and local file-based disks. The metrics are labeled with dynamic labels to differentiate between disk types and individual disks. For example:

- **disk_type**: Indicates the type of the disk (e.g., `premium`, `ultra`, `local`).
- **disk_uuid**: The unique identifier for the disk. For Ceph-based disks, this is the volume UUID. For local file-based disks, this is the file path.
- **disk_path**: The device path (e.g., `vda`, `vdb`).
- **disk_read_alert_threshold**: The read threshold value defined for the disk type, or the default value if not defined.
- **disk_write_alert_threshold**: The write threshold value defined for the disk type, or the default value if not defined.

This allows the metrics to reflect the performance of different storage backends and track the usage of individual disks.

## Caching Mechanism

To optimize performance, the metrics collector uses an in-memory caching mechanism. The cache stores both static and dynamic metrics with defined expiration times. Static metrics are cached for a longer duration (e.g., 1 hour), while dynamic metrics are cached for a shorter duration (e.g., 10 seconds).

### Cache Configuration

- **Static Cache**: Stores metrics that do not change frequently (e.g., disk thresholds).
- **Dynamic Cache**: Stores metrics that change frequently (e.g., disk I/O, network traffic).

The cache ensures that metrics are pre-collected and updated periodically, so they are always available when queried via the API.

## Optional User Flags

The collector provides several configurable options that can be set via flags:

```go
flag.StringVar(&listenAddress, "web.listen-address", "0.0.0.0:9120", "Address to listen on for web interface and telemetry.")
flag.StringVar(&metricsPath, "web.telemetry-path", "/metrics", "Path under which to expose metrics.")
flag.StringVar(&libvirtURI, "libvirt.uri", "qemu:///system", "Libvirt URI from which to extract metrics.")
flag.StringVar(&readThresholds, "read.thresholds", "", "Comma-separated list of read thresholds. eg -read.thresholds='default:500'")
flag.StringVar(&writeThresholds, "write.thresholds", "", "Comma-separated list of write thresholds. eg -write.thresholds='default:500'")
flag.DurationVar(&staticCacheExpiration, "static.cache.expiration", 1*time.Hour, "Expiration duration for the cache of static values")
flag.DurationVar(&dynamicCacheExpiration, "dynamic.cache.expiration", 10*time.Second, "Expiration duration for the cache of dynamic values")
flag.DurationVar(&collectionInterval, "collection.interval", 10*time.Second, "Interval at which to collect metrics in the background")
flag.BoolVar(&enableLogging, "enable_logging", false, "Enable detailed logging of metrics data")
flag.IntVar(&defaultReadThreshold, "default.read.threshold", 100, "Default read threshold if none provided")
flag.IntVar(&defaultWriteThreshold, "default.write.threshold", 100, "Default write threshold if none provided")
flag.Parse()
