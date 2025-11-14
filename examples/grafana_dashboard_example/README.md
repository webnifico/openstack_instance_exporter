## Overview

Example Grafana dashboard for the OpenStack Instance Exporter. Thresholds are intentionally set high and focused on abuse / “hot path” cases so that panels stay quiet during normal usage.

All panels are filtered by:

- **Hypervisor** (`gvar_oie_hypervisor` → `instance` label)
- **Project UUID** (`gvar_oie_project_uuid`)
- **Instance UUID** (`gvar_oie_instance_uuid`)

and pull from a Prometheus datasource (`${datasource}`).

---

## Grafana Dashboard Panels

### Panel Summaries

- Most panels **only render data when thresholds are exceeded**.
- The goal is to highlight abusive or noisy workloads and keep the dashboard readable.

---

## Conntrack & Threat-Intel Metrics

### Conntrack Flows per IP (Hot Only)

- **Description:** Shows fixed IPs that currently have a high conntrack entry count for the selected instances/projects.
- **Query:**  
  `sum by (instance_uuid, project_uuid, ip) (oie_conntrack_ip_total{...}) > 1000`  
  Only IPs with more than **1,000** conntrack entries are shown. Legend includes IP, instance UUID, and project UUID.

### Conntrack Flows per Instance (Hot Only)

- **Description:** Shows instances with a high total conntrack footprint (sum of all fixed IPs).
- **Query:**  
  `sum by (instance_uuid, project_uuid) (oie_conntrack_ip_total{...}) > 3000`  
  Only instances with more than **3,000** total conntrack entries are shown.

### Threat-Intel Contacts Timeline (Tor / Spamhaus / ET / Custom)

- **Description:** Timeline of threat-intel hits per instance, broken out by list (Tor, Spamhaus, EmergingThreats, Custom list). Values approximate **hits per 5-minute window**.
- **Query:**  
  Four series using `sum_over_time(...[5m])`:
  - `oie_tor_contact{...}`
  - `oie_spamhaus_contact{...}`
  - `oie_emergingthreats_contact{...}`
  - `oie_customlist_contact{...}`  
  Each series is grouped by `instance_uuid` and `project_uuid`.

### Conntrack Top IPs (Time Series)

- **Description:** Shows the **top 100 IPs** by current conntrack flow count, useful to see which IPs are dominating conntrack on the selected hypervisors/projects/instances.
- **Query:**  
  `topk(100, oie_conntrack_ip_total{...})`  
  Legend includes IP, instance UUID, and project UUID.

### Threat-Intel Hit Summary (Total per Instance)

- **Description:** Summarizes total threat-intel hits **per instance** over the current dashboard time range.
- **Query:**  
  Combined `sum_over_time(...[$__range])` across:
  - `oie_tor_contact{...}`
  - `oie_spamhaus_contact{...}`
  - `oie_emergingthreats_contact{...}`
  - `oie_customlist_contact{...}`  
  Aggregated as:  
  `sum by (instance_uuid) ( ... ) > 3`  
  Only instances with more than **3 total hits** in the selected time range are shown.

---

## Instance CPU Usage

### Instance CPU Usage

- **Description:** Displays instances with sustained high CPU usage.
- **Query:**  
  `avg_over_time(oie_cpu_percent{...}[5m]) > 75`  
  Shows instances whose **average CPU usage over 5 minutes** is greater than **75%**.

---

## Disk Usage Metrics

### Disk Read/Write Requests (IOPS)

- **Description:** Displays disks where read or write IOPS exceed their per-tier alert thresholds.
- **Query:**  
  Two series, both over a **1-minute** `irate`:
  - `irate(oie_disk_w_requests{...}[1m]) > oie_disk_w_alert_threshold`
  - `irate(oie_disk_r_requests{...}[1m]) > oie_disk_r_alert_threshold`  
  If a series appears, it is above its configured **IOPS alert threshold**.

### Disk Read/Write Throughput

- **Description:** Displays disks with sustained high read/write throughput.
- **Query:**  
  Uses a **5-minute** rate and **5-minute** `min_over_time` window:
  - `min_over_time(rate(oie_disk_w_gbytes{...}[5m])[5m:]) > 0.05`
  - `min_over_time(rate(oie_disk_r_gbytes{...}[5m])[5m:]) > 0.05`  
  Threshold is **0.05 GB/s (~50 MB/s)** sustained over at least 5 minutes.

### Disk Read/Write High Usage (GB in 30m)

- **Description:** Displays disks that move a large amount of data over a 30-minute window.
- **Query:**  
  - `increase(oie_disk_w_gbytes{...}[30m]) > 20`
  - `increase(oie_disk_r_gbytes{...}[30m]) > 20`  
  Shows periods where **more than 20 GB** is read or written in **30 minutes**.

---

## Network Usage Metrics

### Network RX/TX Usage (GB in 30m)

- **Description:** Displays instances with high total network usage (GB transferred) over a 30-minute period.
- **Query:**  
  - `increase(oie_net_rx_gbytes{...}[30m]) > 20`
  - `increase(oie_net_tx_gbytes{...}[30m]) > 20`  
  Shows instances with **more than 20 GB** received or transmitted in **30 minutes**.

### Network RX/TX Throughput

- **Description:** Displays instances with both high throughput and high volume over 30 minutes.
- **Query:**  
  Conditions for each direction:
  - `(rate(oie_net_rx_gbytes{...}[5m]) / 8) > 0.125` **and** `increase(oie_net_rx_gbytes{...}[30m]) > 20`
  - `(rate(oie_net_tx_gbytes{...}[5m]) / 8) > 0.125` **and** `increase(oie_net_tx_gbytes{...}[30m]) > 20`  
  Threshold is **> 0.125 Gbit/s (~125 Mbit/s)** sustained plus **> 20 GB** moved in **30 minutes**.

### Network RX/TX Packets PPS

- **Description:** Displays instances with very high packet rates.
- **Query:**  
  Uses a **5-minute** rate with **1-minute** `min_over_time`:
  - `min_over_time(rate(oie_net_rx_pkt_total{...}[5m])[1m:]) > 10000`
  - `min_over_time(rate(oie_net_tx_pkt_total{...}[5m])[1m:]) > 10000`  
  Shows instances with **> 10,000 packets per second** sustained.

### Network RX/TX Dropped Packets

- **Description:** Displays instances that are dropping packets (RX or TX) at a non-zero rate.
- **Query:**  
  - `rate(oie_net_rx_drp_total{...}[5m]) > 0`
  - `rate(oie_net_tx_drp_total{...}[5m]) > 0`  
  Any non-zero 5-minute drop rate will appear.

### Network RX/TX Packet Errors

- **Description:** Displays instances with packet errors (RX or TX) at a non-zero rate.
- **Query:**  
  - `rate(oie_net_rx_er_total{...}[5m]) > 0`
  - `rate(oie_net_tx_er_total{...}[5m]) > 0`  
  Any non-zero 5-minute error rate will appear.
