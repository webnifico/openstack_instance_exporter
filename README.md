# OpenStack Instance Exporter (OIE)

**Version:** `v1.0.0` (Dynamic Risk Engine)  
**Maintained by:** xneelo Cloud Engineering Team  
**License:** Apache 2.0

## 📖 Introduction

**OpenStack Instance Exporter (OIE)** is a specialized, high-performance Prometheus exporter designed for multi-tenant OpenStack compute nodes.

Zero-Allocation Data Structures: Uses struct-based map keys and raw netlink dumping to eliminate string concatenation overhead and minimize Garbage Collector (GC) pressure during high-traffic intervals.

Unlike generic exporters (like `node_exporter` or `libvirt_exporter`), OIE is built specifically to:

- Expose **per-instance** resource usage (CPU, memory, disk, network, conntrack).
- Enrich those metrics with **OpenStack context** (instance UUID, project UUID, user UUID, flavor, etc.).
- Apply **dynamic risk scoring** that blends:
  - Resource pressure (CPU saturation, memory pressure, disk IO, packet drops).
  - Conntrack behavior and statistical anomaly detection.
  - Threat intelligence hits (Tor, Spamhaus, Emerging Threats, Custom Lists).
- Emit a single **attention score** (0–100) per VM, telling you “where to look first”.
- Keep Prometheus cardinality **predictable** and safe, even at large scale.

OIE closes the “observability gap” between:

- Raw host-level metrics (`node_exporter`),
- Control-plane metrics (Nova/Neutron APIs),
- And what’s actually happening **inside** tenant VMs — without agents.

### Core Value Proposition: The Monitoring Gap Closer 🌉

OIE is positioned to solve critical, high-impact operational problems that traditional tools fail to address:

- “Which VM is attacking our infrastructure / other tenants / the internet right now?”
- “Why is this hypervisor hitting conntrack limits or dropping packets?”
- “Which project is burning CPU in a noisy-neighbor pattern?”
- “Which VM should we investigate first when there’s a suspected abuse event?”

By merging resource usage, conntrack behavior, and threat intelligence into a **single attention score**, OIE helps operators:

- Detect infrastructure abuse (DoS, port scans, brute-force, exfiltration).
- Keep noisy neighbors under control.
- Make better decisions about throttling, blocking, or contacting customers.
- Build direct integrations with:
  - Alerting and ticketing (PagerDuty, OpsGenie, email).
  - Security tooling and SIEM.
  - Automated responses (OpenStack QoS, firewall rules) or operational alerts.

OIE is designed to detect **abuse**, **noisy neighbors**, and **risky behavior** in near real time, using **behavior-based scoring** (flows and patterns) rather than only static thresholds.

-----

# 📑 Table of Contents

1.  [Architecture & Design](#-architecture--design)  
      * [The Background Collection Loop](#the-background-collection-loop)  
      * [The Worker Pool Model](#the-worker-pool-model)  
      * [Concurrency & Safety](#concurrency--safety)
2.  [The Dynamic Risk Engine (Deep Dive)](#-the-dynamic-risk-engine-deep-dive)  
      * [Priority Logic Table](#priority-logic-table)  
      * [Significance vs. Impact](#significance-vs-impact)
3.  [Scoring Calculus](#-scoring-calculus)  
      * [Resource Score](#resource-score)  
      * [Threat Score](#threat-score)  
      * [Attention Score](#attention-score)
4.  [Metrics Reference (Full Catalog)](#-metrics-reference-full-catalog)  
      * [Instance Metrics](#instance-metrics)  
      * [Conntrack & Behavior Metrics](#conntrack--behavior-metrics)  
      * [Threat Intel Metrics](#threat-intel-metrics)  
      * [Instance Score Metrics](#instance-score-metrics)  
      * [Host Metrics](#host-metrics)  
      * [Host Threat Metrics](#host-threat-metrics)
5.  [Configuration Guide](#-configuration-guide)  
      * [Behavior Tuning](#behavior-tuning)  
      * [Threat Intelligence Feeds](#threat-intelligence-feeds)  
      * [Host Threats](#host-threats)  
      * [System & Threshold Tuning](#system--threshold-tuning)
6.  [Logging & Forensics](#-logging--forensics)
7.  [Alert Diagnosis Reference](#-alert-diagnosis-reference)
8.  [Build & Deployment](#-build--deployment)
9.  [Compatibility](#-compatibility)
10. [License](#-license)

-----

# 🏗 Architecture & Design

OIE is designed to run as a **systemd service** or DaemonSet (one instance per compute node). It connects directly to the local libvirt socket and reads the local conntrack table.

Design goal:

> “OIE should never be the reason a hypervisor is slow or unstable.”

## The Background Collection Loop

To keep Prometheus scrapes fast, OIE decouples collection from scraping:

```text
      +----------------------+
      |     Ticker (15s)     |  -collection.interval
      +----------+-----------+
                 |
                 v
      +----------+-----------+
      |  Background Collector |  (host + instances + flows + scores)
      +----------+-----------+
                 |
                 v
      +----------+-----------+
      |  RAM Metrics Cache   |  (static + dynamic metrics)
      +----------+-----------+
                 |
                 v
      +----------+-----------+
      | Prometheus Collect   |  HTTP GET /metrics
      +----------------------+
````

The **Background Collector** runs every `-collection.interval` (default: `15s`) and:

*Phase 1 (Parallel I/O): Simultaneously fetches Libvirt domain stats and dumps the Kernel conntrack table in parallel goroutines to minimize cycle latency.

*Phase 2 (Processing):

   - Rebuilds InstanceMeta (UUIDs, project/user info, IPs, disks).

   - Maps raw conntrack entries to fixed IPs in memory (Zero-allocation filtering).

   - Runs behavior analysis and threat intel matching.

The **Prometheus scrape path** simply:

* Reads the snapshot under a mutex.
* Emits metrics from the cached slices.
* Does **no heavy work** (no libvirt, no conntrack walks, no scoring).

## The Worker Pool Model

Inside a collection cycle, per-instance work is parallelized:

* A bounded channel of “jobs” (per active domain).
* A pool of workers (size configured via `-worker.count`; `0` = `NumCPU()`):

Each worker:

* Pulls one domain from the job queue.
* Collects libvirt stats for that domain.
* Maps tap devices to instance IPs.
* Aggregates conntrack flows per fixed IP.
  -  Note that this is an effective alternative to mapping floating ips, given that a private fixed ip would always be required for a floating - thus this is how we can trace back.
* Contributes metrics into a shared aggregate struct.

Workers are bounded and conservative; when the node is highly loaded, the exporter prefers to **do less work**, not overwhelm libvirt or conntrack.

## Concurrency & Safety

Key properties:

* Persistent Libvirt Connection: The collector maintains a persistent connection to the libvirt daemon, reusing it across cycles to minimize socket overhead, with automatic reconnection logic on failure.
* Shared maps (metadata, previous behavior state, threat counts) are guarded by mutexes.
* The scrape path reads from immutable slices prepared by the collector.
* Background threat refreshers run independently but only update their own state (protected by mutexes).

Collection cycle:

1. Refresh host metrics.
2. Enumerate active instances and rebuild metadata.
3. Scan conntrack and aggregate flows per IP (once per cycle).
4. Apply behavior analysis and threat intel.
5. Compute scores and prepare metric slices.
6. Swap snapshot.
7. Scrapes read and expose.

---

# 🛡 The Dynamic Risk Engine (Deep Dive)

The Dynamic Risk Engine is the “brain” of OIE. It fuses:

* **Resource pressure** (CPU, memory, disk IO, conntrack load).
* **Outbound and inbound behavior** (unique remotes, new remotes, fan-out).
* **Threat intel hits** (Tor, Spamhaus, Emerging Threats, custom lists).

Into three metrics:

* `oie_instance_resource_score`
* `oie_instance_threat_score`
* `oie_instance_attention_score`

The goal is **interpretability**: you should be able to look at the metrics and the logs and understand *why* a VM is hot.

## Priority Logic Table

Internally, detections conceptually map into priorities (expressed in logs, not as separate metrics):

| Priority | Label                            | Description                                                                         |
| -------- | -------------------------------- | ----------------------------------------------------------------------------------- |
| P0       | `infrastructure_abuse_critical`  | Our infra is being attacked; host/control-plane targeted; collateral damage likely. |
| P1       | `shared_tenant_abuse_high`       | Tenant is harming other tenants (noisy neighbor, scanning, lateral movement).       |
| P2       | `public_network_scan_unreplied`  | Wide internet scanning / brute-forcing.                                             |
| P3       | `capacity_limit_exceeded_200pct` | Hard breach of safety limits (e.g. >200% of documented limit).                      |
| P4       | `traffic_anomaly_volume`         | Strong statistical anomaly (volume/shape), within safety limits.                    |
| P5       | `application_connection_leak`    | Active connections accumulating without matching throughput.                        |

The exporter does **not** expose these as their own metrics to avoid cardinality explosions. Instead:

* Metrics indicate **pressure and hits** (scores, flows, contact counters).
* Logs in the threatfile capture **what** and **why** for forensic review.

## Significance vs. Impact

The engine balances two axes:

1. **Significance (per-VM view)**
   “Is this a lot of activity for this VM?”

   Examples:

   * New high-fan-out scanning behavior to many remotes.
   * Sudden spikes in unique remotes and destination ports.
   * Outbound connection patterns that diverge from prior cycles.

2. **Impact (host view)**
   “How much does this hurt the hypervisor?”

   Examples:

   * Conntrack flows from this VM vs the host’s conntrack capacity.
   * Disk IO vs thresholds for the disk tier.
   * Contribution to host-level saturation.

The threat / behavior signal (`behaviorSignal`) is higher when:

* The VM’s behavior is unusual **for itself** (significance), **and**
* The host is under meaningful pressure (impact).

This keeps noise low on quiet hosts, and makes the engine stricter when the host is in trouble.

---

# 🧮 Scoring Calculus

The exporter compresses all of this into three 0–100 scores per instance.

> Exact math is implemented in `engine.go`. Below is the conceptual model, kept aligned with the current code.

## Resource Score

Inputs:

* CPU utilization (`cpuUsage`).
* Memory pressure (fraction of used vs allocated; penalties mainly above ~80%).
* Disk IO signal (per-disk IO vs configured thresholds).
* Conntrack / network signal (max flows vs a base).

Each component is normalized into `0.0–1.0` and then scaled:

* CPU: normalized from ~70–100% usage.
* Memory: normalized from ~80–100% usage.
* Disk: based on the maximum disk IO signal across disks (vs thresholds).
* Net: based on maximum conntrack flows relative to a baseline.

In code:

* Each component yields up to **25 points**:

  * `resourceCpuScore`
  * `resourceMemScore`
  * `resourceDiskScore`
  * `resourceNetScore`
* They are summed and then clamped to `0–100`:

```go
resourceScore := resourceCpuScore + resourceMemScore + resourceDiskScore + resourceNetScore
resourceScore = clamp01(resourceScore/100.0) * 100.0
```

Exported as:

* `oie_instance_resource_score` (0–100).

## Threat Score

Threat score aggregates:

* Behavior anomalies (outbound/inbound behavior signals).
* Threat intel hits per list.

Threat intel weighting comes from CLI:

* `-score.weight.behavior`
* `-score.weight.tor`
* `-score.weight.relay`
* `-score.weight.spam`
* `-score.weight.emerging`
* `-score.weight.custom`

Conceptually:

```go
threatScore := behaviorSignal * mc.scoring.BehaviorSignal +
               torSignal      * mc.scoring.TorSignal      +
               relaySignal    * mc.scoring.RelaySignal    +
               spamSignal     * mc.scoring.SpamSignal     +
               emSignal       * mc.scoring.EmergingSignal +
               clSignal       * mc.scoring.CustomSignal

threatScore = clamp01(threatScore/100.0) * 100.0
```

Exported as:

* `oie_instance_threat_score` (0–100).

## Attention Score

Attention score blends resource and threat scores with configurable weights:

* `-score.weight.resource`
* `-score.weight.threat`

In code:

```go
attentionScore := (resourceScore*resourceWeight + threatScore*threatWeight) /
                  (resourceWeight + threatWeight)
```

Exported as:

* `oie_instance_attention_score` (0–100).

Minimum score cutoff:

* `-attention.min_score`
  If `attentionScore` is below this value, score metrics and some logs are suppressed to reduce cardinality and noise.

---

# 📊 Metrics Reference (Full Catalog)

## Notes on Labels

Unless otherwise specified:

* **Instance metrics** are labeled with:

  * `domain`, `instance_uuid`, `project_uuid`, `project_name`, `user_uuid`
* **Per-IP metrics** add:

  * `ip`, `family` (`ipv4` / `ipv6`), sometimes `direction`
* **Disk metrics** add:

  * `disk_uuid`, `disk_type`, `disk_path`
* **Host metrics** are typically labeled with:

  * `hostname` and where relevant, `libvirt_uri` or list name.

Prometheus types:

* Metrics ending in `_total` are Counters.
* Scores, flows, utilization, entries, durations are Gauges.

---

## Instance Metrics

**Static / identity**

* `oie_instance_info`
  Static metadata for an active instance (1 = present). Includes flavor, root type, created-at, networking context in labels.

**CPU**

* `oie_instance_cpu_vcpu_count`
  vCPU count for this instance (from metadata or libvirt stats).
* `oie_instance_cpu_vcpu_percent`
  Average vCPU utilization percentage.

**Memory**

* `oie_instance_mem_allocated_mb`
  Allocated memory (MB) for this instance.
* `oie_instance_mem_used_mb`
  Guest-view memory used (MB), derived from balloon/unused stats when available.

**Disk (per disk)**

* `oie_instance_disk_info`
  Static disk metadata per instance disk (tier, type, path, etc.).
* `oie_instance_disk_read_gbytes_total`
  Total disk read volume in GiB.
* `oie_instance_disk_read_requests_total`
  Total disk read operations.
* `oie_instance_disk_write_gbytes_total`
  Total disk write volume in GiB.
* `oie_instance_disk_write_requests_total`
  Total disk write operations.
* `oie_instance_disk_read_alert_threshold`
  Alert threshold (GiB) for reads for this disk’s tier.
* `oie_instance_disk_write_alert_threshold`
  Alert threshold (GiB) for writes for this disk’s tier.

**Network (per instance)**

* `oie_instance_net_rx_gbytes_total`
  Total network receive volume in GiB.
* `oie_instance_net_rx_packets_total`
  Total packets received.
* `oie_instance_net_rx_errors_total`
  Total RX errors.
* `oie_instance_net_rx_dropped_total`
  Total RX drops.
* `oie_instance_net_tx_gbytes_total`
  Total network transmit volume in GiB.
* `oie_instance_net_tx_packets_total`
  Total packets transmitted.
* `oie_instance_net_tx_errors_total`
  Total TX errors.
* `oie_instance_net_tx_dropped_total`
  Total TX drops.

---

## Conntrack & Behavior Metrics

**Per fixed IP, per instance**

* `oie_instance_conntrack_ip_flows`
  Total conntrack flows involving this fixed IP (inbound + outbound).
* `oie_instance_conntrack_ip_flows_inbound`
  Flows where the VM is the destination (inbound).
* `oie_instance_conntrack_ip_flows_outbound`
  Flows where the VM is the source (outbound).

**Inbound behavior (`inbound.behavior.enable`)**

* `oie_instance_inbound_flows`
  Inbound flows to this fixed IP.
* `oie_instance_inbound_unique_remotes`
  Unique remote IPs sending to this IP.
* `oie_instance_inbound_unique_dst_ports`
  Unique destination ports targeted.
* `oie_instance_inbound_new_remotes`
  Remotes not seen in the previous interval.
* `oie_instance_inbound_new_dst_ports`
  Destination ports not seen in the previous interval.
* `oie_instance_inbound_max_flows_single_remote`
  Maximum flows from a single remote IP.
* `oie_instance_inbound_max_flows_single_dst_port`
  Maximum flows to a single destination port.

**Outbound behavior (`outbound.behavior.enable`)**

* `oie_instance_outbound_flows`
  Outbound flows from this fixed IP.
* `oie_instance_outbound_unique_remotes`
  Unique remote IPs contacted.
* `oie_instance_outbound_unique_dst_ports`
  Unique destination ports contacted.
* `oie_instance_outbound_new_remotes`
  Remotes not seen in the previous interval.
* `oie_instance_outbound_new_dst_ports`
  Destination ports not seen in the previous interval.
* `oie_instance_outbound_max_flows_single_remote`
  Maximum flows to a single remote IP.
* `oie_instance_outbound_max_flows_single_dst_port`
  Maximum flows to a single destination port.

---

## Threat Intel Metrics

All threat metrics are per-instance and labeled with `direction` (`in`, `out`, or `any`) reflecting configured contact direction.

**Tor Exit Nodes**

* `oie_instance_threat_tor_exit_active_flows`
  Active flows involving Tor Exit IPs.
* `oie_instance_threat_tor_exit_contacts_total`
  Total distinct Tor Exit contacts over time.

**Tor Relay Nodes**

* `oie_instance_threat_tor_relay_active_flows`
  Active flows involving Tor Relay IPs.
* `oie_instance_threat_tor_relay_contacts_total`
  Total distinct Tor Relay contacts over time.

**Spamhaus DROP (IPv4 + IPv6)**

* `oie_instance_threat_spamhaus_active_flows`
  Active flows where remote IP is in Spamhaus DROP ranges.
* `oie_instance_threat_spamhaus_contacts_total`
  Total distinct Spamhaus contacts over time.

**EmergingThreats compromised IPs**

* `oie_instance_threat_emergingthreats_active_flows`
  Active flows involving EmergingThreats IPs.
* `oie_instance_threat_emergingthreats_contacts_total`
  Total distinct EmergingThreats contacts over time.

**Custom List**

* `oie_instance_threat_customlist_active_flows`
  Active flows involving IPs from the custom list.
* `oie_instance_threat_customlist_contacts_total`
  Total distinct custom-list contacts over time.

---

## Instance Score Metrics

Per instance:

* `oie_instance_resource_score`
  Resource pressure score (0–100) based on CPU, memory, disk IO, and conntrack usage.
* `oie_instance_threat_score`
  Threat / behavior score (0–100) combining behavior anomalies and threat intel hits.
* `oie_instance_attention_score`
  Blended attention score (0–100) combining resource and threat scores via configured weights.

---

## Host Metrics

Host-level metrics (hypervisor / exporter process):

* `oie_host_cpu_threads`
  Total logical CPU threads on the host.

* `oie_host_cpu_active_vcpus`
  Sum of vCPUs allocated to active domains on this host.

* `oie_host_mem_mb_total`
  Total host memory (MB).

* `oie_host_libvirt_active_vms`
  Active libvirt domains on this host.

* `oie_host_active_disks`
  Approximate number of disks in use by active domains.

* `oie_host_active_fixed_ips`
  Fixed IPs associated with active instances.

* `oie_host_active_projects`
  Number of distinct projects with active instances.

* `oie_host_conntrack_entries`
  Conntrack entries observed in last snapshot.

* `oie_host_conntrack_max`
  Kernel conntrack maximum.

* `oie_host_conntrack_utilization`
  Utilization ratio (entries / max).

* `oie_host_conntrack_read_duration_seconds`
  Duration spent reading conntrack.

* `oie_host_conntrack_read_errors_total`
  Conntrack read errors encountered.

* `oie_host_collection_cycle_duration_seconds`
  Duration of the last background collection cycle.

* `oie_host_collection_cycle_lag_seconds`
  Time since the previous collection cycle completed.

* `oie_host_collection_errors_total`
  Total collection cycle errors.

* `oie_host_cache_cleanup_duration_seconds`
  Time spent cleaning old cache entries.

* `oie_host_go_heap_alloc_bytes`
  Go heap usage of the exporter.

---

## Host Threat Metrics

Threat-list status per host (only when list is enabled):

**Tor Exit**

* `oie_host_threat_tor_exit_entries`
  Number of Tor Exit IPs loaded.
* `oie_host_threat_tor_exit_refresh_last_success_timestamp_seconds`
  Unix timestamp of last successful refresh.
* `oie_host_threat_tor_exit_refresh_duration_seconds`
  Duration of last refresh.
* `oie_host_threat_tor_exit_refresh_errors_total`
  Total refresh errors.

**Tor Relay**

* `oie_host_threat_tor_relay_entries`
  Number of Tor Relay IPs loaded.
* `oie_host_threat_tor_relay_refresh_last_success_timestamp_seconds`
  Unix timestamp of last successful refresh.
* `oie_host_threat_tor_relay_refresh_duration_seconds`
  Duration of last refresh.
* `oie_host_threat_tor_relay_refresh_errors_total`
  Total refresh errors.

**Spamhaus**

* `oie_host_threat_spamhaus_entries`
  Number of Spamhaus CIDRs loaded (v4 + v6).
* `oie_host_threat_spamhaus_refresh_last_success_timestamp_seconds`
  Unix timestamp of last successful refresh.
* `oie_host_threat_spamhaus_refresh_duration_seconds`
  Duration of last refresh.
* `oie_host_threat_spamhaus_refresh_errors_total`
  Total refresh errors.

**EmergingThreats**

* `oie_host_threat_emergingthreats_entries`
  Number of EmergingThreats IPs loaded.
* `oie_host_threat_emergingthreats_refresh_last_success_timestamp_seconds`
  Unix timestamp of last successful refresh.
* `oie_host_threat_emergingthreats_refresh_duration_seconds`
  Duration of last refresh.
* `oie_host_threat_emergingthreats_refresh_errors_total`
  Total refresh errors.

**Custom List**

* `oie_host_threat_customlist_entries`
  Number of custom-list IPs loaded.
* `oie_host_threat_customlist_refresh_last_success_timestamp_seconds`
  Unix timestamp of last successful refresh.
* `oie_host_threat_customlist_refresh_duration_seconds`
  Duration of last refresh.
* `oie_host_threat_customlist_refresh_errors_total`
  Total refresh errors.

**Provider-owned host IP membership**

* `oie_host_threat_provider_ip_listed`
  Gauge `0/1`.
  Labeled with `list`, `ip`, `family`. Indicates that a **provider-owned host IP** (from selected host interfaces) currently appears in a threat list (Tor, Spamhaus, ET, custom list).

---

# ⚙️ Configuration Guide

OIE is configured through CLI flags (or systemd `ExecStart` arguments).

## Behavior Tuning

Flags:

* `-inbound.behavior.enable`
  Enable inbound behavior analysis.
* `-outbound.behavior.enable`
  Enable outbound behavior analysis.
* `-behavior.sensitivity`
  Scaling factor on behavior thresholds; `< 1` = more sensitive, `> 1` = less sensitive.
* `-contacts.direction`
  Default contact direction for threat matching: `out`, `in`, or `any`.

Score weights:

* `-score.weight.resource`
  Weight for resource score in attention score.
* `-score.weight.threat`
  Weight for threat score in attention score.
* `-score.weight.behavior`
  Weight of behavior signal inside threat score.
* `-score.weight.tor`
  Weight of Tor Exit signal.
* `-score.weight.relay`
  Weight of Tor Relay signal.
* `-score.weight.spam`
  Weight of Spamhaus signal.
* `-score.weight.emerging`
  Weight of EmergingThreats signal.
* `-score.weight.custom`
  Weight of custom-list signal.

Minimum attention score:

* `-attention.min_score`
  Minimum attention score for emitting score metrics and certain logs.

## Threat Intelligence Feeds

Each list has:

* `*.enable` – on/off.
* `*.url` / `*.path` – data source.
* `*.refresh` – refresh interval.
* `*.direction` – direction override (`out`, `in`, `any`).

**Tor Exit**

* `-tor.exit.enable`
* `-tor.exit.url`
* `-tor.exit.refresh`
* `-tor.exit.direction`

**Tor Relay**

* `-tor.relay.enable`
* `-tor.relay.url`
* `-tor.relay.refresh`
* `-tor.relay.direction`

**Spamhaus DROP**

* `-spamhaus.enable`
* `-spamhaus.url` (IPv4)
* `-spamhaus.ipv6.url` (IPv6)
* `-spamhaus.refresh`
* `-spamhaus.direction`

**EmergingThreats**

* `-emergingthreats.enable`
* `-emergingthreats.url`
* `-emergingthreats.refresh`
* `-emergingthreats.direction`

**Custom List**

* `-customlist.enable`
* `-customlist.path`
* `-customlist.refresh`
* `-customlist.direction`

## Host Threats

Host-level threat inspection:
* Note: this is intended to be used with ovn-bgp-agent and has been ran in a collapsed compute architecture. Default interface is bgp-nic.

* `-host.threats.enable`
  Enable host NIC threat checks and host threat metrics.
* `-host.ips.allow-private`
  If true, includes private and loopback host IPs; otherwise, only public/global addresses.
* `-host.interfaces`
  Optional comma-separated list of interfaces to consider (e.g. `br-external,br-provider`).

If host threats are enabled:

* OIE gathers host IPs from the selected interfaces.
* On each threat list refresh, it checks whether any host IP is in that list.
* It updates:

  * list status metrics (`oie_host_threat_*`),
  * `oie_host_threat_provider_ip_listed{list,ip,family}`.

## System & Threshold Tuning

Collection and thresholds:

* `-web.listen-address` (default `0.0.0.0:9120`)
* `-web.telemetry-path` (default `/metrics`)
* `-libvirt.uri` (default `qemu:///system`)
* `-collection.interval` (default `15s`)
* `-worker.count` (`0` = `NumCPU()`)

Disk thresholds:

* `-read.thresholds`
  Comma-separated thresholds by tier, e.g.
  `volumes:500,premium:1500,ultra:2500,local:5000`
* `-write.thresholds`
  Comma-separated thresholds by tier, e.g.
  `volumes:500,premium:1000,ultra:1500,local:1500`
* `-default.read.threshold`
  Default read threshold when no tier match.
* `-default.write.threshold`
  Default write threshold when no tier match.

Logging:

* `-log.file.enable`
  Enable logging to a file.
* `-log.file.path`
  Main log file path.
* `-log.level`
  `error`, `notice`, `info`, `debug`.
* `-threatfile.enable`
  Enable threat hit logging file.
* `-threatfile.path`
  Path to threat log file.
* `-threatfile.min_interval`
  Minimum interval before repeating the same threat hit key (sampling).

---

# 🕵️ Logging & Forensics

OIE writes **single-line, key=value** logs designed for Loki/SIEM.

Typical files:

* Main log: `/var/log/openstack_instance_exporter.log`
* Threat log: `/var/log/openstack_instance_exporter.threat.log` (if enabled)

Examples (illustrative):

**Behavior / score log**

```text
ts=2025-12-06T12:00:00Z level=notice component=score event=instance_scores \
domain=prod-api-01 instance_uuid=aee9... project_uuid=... user_uuid=... \
resource_score=45.2 threat_score=82.7 attention_score=68.9 \
behavior=0.76 tor_signal=0.40 spam_signal=0.90 em_signal=0.00 custom_signal=0.10
```

**Threat-list hit per flow**

```text
ts=2025-12-06T12:01:02Z level=notice component=threat event=threat_list_hit \
tag=SPAMHAUS list=spamhaus domain=prod-api-01 instance_uuid=... \
project_uuid=... project_name=customer-prod user_uuid=... \
src=203.0.113.10 dst=10.0.0.12 direction=in
```

**Host provider IP listed**

```text
ts=2025-12-06T12:05:00Z level=notice component=threat event=host_threat \
tag=HOST_THREAT list=tor_exit ip=198.51.100.20 family=ipv4
```

Workflow:

1. Use metrics dashboards (scores, flows, threat contacts) to find hot instances.
2. Pivot into threat logs for those instances / projects.
3. Inspect event tags (`event`, `tag`, `list`, `direction`, `priority-kind`) to understand behavior.
4. Decide on response (rate-limit, security actions, customer communication).

---

# 🚨 Alert Diagnosis Reference

Some quick heuristics for interpreting scores:

* **High attention, high threat, moderate resource**
  Likely abuse (scanning, brute-force, exfiltration). Threat intel hits and behavior anomalies drive this.

* **High attention, high resource, low threat**
  Noisy neighbor or capacity issue; resource-heavy but not obviously malicious. Consider customer contact, migration, or QoS.

* **High host conntrack utilization, multiple moderate scores**
  Host under pressure from several tenants at once. Check `oie_host_conntrack_*` and per-instance `*_flows` metrics.

* **Provider IP listed in threat lists (`oie_host_threat_provider_ip_listed`)**
  Provider infrastructure appearing in external threat feeds. Investigate urgently.

Use `oie_instance_attention_score` for top-k queries and dashboards; use resource / threat subscores and the behavior metrics to understand *why*.

---

# 📦 Build & Deployment

## Build

From the repository root:

```bash
go mod tidy
go build -o openstack_instance_exporter
```

Create tarball and checksums:

```bash
tar -cJf openstack_instance_exporter.tar.xz openstack_instance_exporter
cp openstack_instance_exporter.tar.xz openstack_instance_exporter-v1.0.0-linux-amd64.tar.xz
sha256sum openstack_instance_exporter-v1.0.0-linux-amd64.tar.xz > sha256sums.txt
```

## Systemd Deployment (example)

Install:

* Binary to `/opt/openstack_instance_exporter/openstack_instance_exporter`
* Configured systemd unit, for example:

```ini
[Unit]
Description=OpenStack Instance Exporter
After=network.target

[Service]
User=root
Group=root
ExecStart=/opt/openstack_instance_exporter/openstack_instance_exporter \
  -libvirt.uri=qemu:///system \
  -collection.interval=15s \
  -outbound.behavior.enable \
  -inbound.behavior.enable \
  -attention.min_score=0 \
  -behavior.sensitivity=0.25 \
  -tor.exit.enable \
  -tor.exit.direction=any \
  -tor.relay.enable \
  -tor.relay.direction=any \
  -spamhaus.enable \
  -spamhaus.direction=any \
  -emergingthreats.enable \
  -emergingthreats.direction=any \
  -customlist.enable \
  -customlist.direction=any \
  -customlist.path=/opt/openstack_instance_exporter/custom-ips.txt \
  -read.thresholds=volumes:500,premium:1500,ultra:2500,local:5000 \
  -write.thresholds=volumes:500,premium:1000,ultra:1500,local:1500 \
  -host.threats.enable

Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Activate:

```bash
systemctl daemon-reload
systemctl enable --now openstack_instance_exporter
```

Prometheus scrape config example:

```yaml
scrape_configs:
  - job_name: 'openstack-instance-exporter'
    static_configs:
      - targets:
          - compute1:9120
          - compute2:9120
          - compute3:9120
```

---

# ✅ Compatibility

Tested with:

* **OS:** Ubuntu 22.04 / 24.04
* **Hypervisor:** Libvirt 8.x–10.x, QEMU/KVM
* **Cloud:** OpenStack (OVN/OVS networking; compatible with Linux Bridge)
* **Monitoring:** Prometheus 2.x/3.x, Grafana /12+

Intended deployment: one exporter per compute node.

---

# 📄 License

**Apache License 2.0**

Copyright (c) 2025
**xneelo Cloud Engineering Team**

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this exporter except in compliance with the License. You may obtain a copy of the License at:

[http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an **"AS IS" BASIS**, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.


