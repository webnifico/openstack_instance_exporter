## Overview

Example Grafana Dashboard. Please feel free to adjust values - they are set high to be a bit more relevant for abuse cases.

## Grafana Dashboard Panels

### Panel Summaries

Note that no panel will display metrics unless thresholds are met to ensure there is no clutter.

### Instance CPU Usage

- **Description:** Displays CPU usage above 75% for more than 5 consecutive minutes.
- **Query:** Average CPU usage over a 5-minute interval for instances, filtered by project UUID, instance UUID, and hypervisor.

### Disk Write Requests (IOPS)

- **Description:** Displays disk write request IOPS above the defined threshold for more than 5 consecutive minutes.
- **Query:** Minimum rate of disk write requests over a 5-minute interval for instances, filtered by project UUID, instance UUID, and hypervisor.

### Disk Read Requests (IOPS)

- **Description:** Displays disk read request IOPS above the defined threshold for more than 5 consecutive minutes.
- **Query:** Minimum rate of disk read requests over a 5-minute interval for instances, filtered by project UUID, instance UUID, and hypervisor.

### Disk Write Throughput

- **Description:** Displays disk write throughput above the defined threshold for more than 5 consecutive minutes.
- **Query:** Minimum rate of disk write throughput over a 5-minute interval for instances, filtered by project UUID, instance UUID, and hypervisor.

### Disk Read Throughput

- **Description:** Displays disk read throughput above the defined threshold for more than 5 consecutive minutes.
- **Query:** Minimum rate of disk read throughput over a 5-minute interval for instances, filtered by project UUID, instance UUID, and hypervisor.

### Disk Write Usage (GB)

- **Description:** Displays disk write usage if greater than the defined threshold in an hour span.
- **Query:** Increase in disk write usage over an hour for instances, filtered by project UUID, instance UUID, and hypervisor.

### Disk Read Usage (GB)

- **Description:** Displays disk read usage if greater than the defined threshold in an hour span.
- **Query:** Increase in disk read usage over an hour for instances, filtered by project UUID, instance UUID, and hypervisor.

### Network RX Usage (GB)

- **Description:** Displays network receive usage in gigabytes if greater than the defined threshold in a 30-minute consecutive period.
- **Query:** Increase in network receive usage over 30 minutes for instances, filtered by project UUID, instance UUID, and hypervisor.

### Network TX Usage (GB)

- **Description:** Displays network transmit usage in gigabytes if greater than the defined threshold in a 30-minute consecutive period.
- **Query:** Increase in network transmit usage over 30 minutes for instances, filtered by project UUID, instance UUID, and hypervisor.

### Network RX Throughput

- **Description:** Displays network receive throughput if greater than the defined threshold and transfer total is greater than the defined threshold in 10 consecutive minutes.
- **Query:** Rate of network receive throughput over 10 minutes for instances, filtered by project UUID, instance UUID, and hypervisor.

### Network TX Throughput

- **Description:** Displays network transmit throughput if greater than the defined threshold and transfer total is greater than the defined threshold in 10 consecutive minutes.
- **Query:** Rate of network transmit throughput over 10 minutes for instances, filtered by project UUID, instance UUID, and hypervisor.

### Network RX Packets PPS

- **Description:** Displays network receive packets per second above the defined threshold if consecutive for more than 10 minutes.
- **Query:** Minimum rate of network receive packets over a minute for instances, filtered by project UUID, instance UUID, and hypervisor.

### Network TX Packets PPS

- **Description:** Displays network transmit packets per second above the defined threshold if consecutive for more than 10 minutes.
- **Query:** Minimum rate of network transmit packets over a minute for instances, filtered by project UUID, instance UUID, and hypervisor.

### Network RX Dropped Packets

- **Description:** Displays network receive dropped packets if greater than 0.
- **Query:** Rate of network receive dropped packets over a minute for instances, filtered by project UUID, instance UUID, and hypervisor.

### Network TX Dropped Packets

- **Description:** Displays network transmit dropped packets if greater than 0.
- **Query:** Rate of network transmit dropped packets over a minute for instances, filtered by project UUID, instance UUID, and hypervisor.

### Network RX Packet Errors

- **Description:** Displays network receive packet errors if greater than 0.
- **Query:** Rate of network receive packet errors over a minute for instances, filtered by project UUID, instance UUID, and hypervisor.

### Network TX Packet Errors

- **Description:** Displays network transmit packet errors if greater than 0.
- **Query:** Rate of network transmit packet errors over a minute for instances, filtered by project UUID, instance UUID, and hypervisor.
