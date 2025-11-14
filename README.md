# **OpenStack Instance Exporter – Metrics Collector**

A high-performance, zero-waste Prometheus exporter for **OpenStack compute nodes**, providing **per-instance metrics** with deep cloud-aware context and built-in threat-intelligence checks.

This exporter exposes:

* CPU usage
* Disk I/O metrics
* Disk I/O thresholds
* Network traffic and error counters
* Conntrack flows per fixed IP
* Tor exit-node contact detection
* Spamhaus DROP (IPv4 + IPv6) contact detection
* EmergingThreats compromised-IP contact detection (IPv4)
* Custom user-provided IP list contact detection (IPv4 + IPv6)

Every metric includes full OpenStack UUID metadata so activity can be traced precisely:

> `hypervisor → project → instance → disk/interface/IP`

The exporter is intentionally lean and optimized for large compute clusters. It eliminates unnecessary time series, avoids libvirt calls during scrapes, and performs threat-intel matching with minimal overhead.

---

# **Overview**

The exporter:

* Connects to libvirt
* Parses Nova metadata from domain XML
* Collects CPU, disk, network, and conntrack metrics
* Identifies Tor exit-node traffic (IPv4 + IPv6)
* Identifies Spamhaus DROP-listed traffic (IPv4 + IPv6)
* Identifies EmergingThreats compromised-host traffic (IPv4)
* Identifies traffic to a custom operator-defined IP list (IPv4 + IPv6)
* Stores all metrics in in-memory caches
* Serves only cached metrics to Prometheus

It differs from generic libvirt exporters by being fully OpenStack-aware, applying extensive zero-suppression, and enriching metrics with security-relevant signals.

---

# **Tested Stack**

* Ubuntu 22.04 and 24.04
* Libvirt 8.x–10.x
* OpenStack Bobcat–Epoxy
* Prometheus 2.47+
* Grafana 11+

---

# **Build Requirements**

* Go 1.22+

```bash
git clone <repo>
cd openstack_instance_exporter
go build
./openstack_instance_exporter
````

---

# **High-Level Architecture**

## Background Collection Loop (expensive path)

Runs every `-collection.interval`:

1. Lists all active libvirt domains
2. Calls `conntrack -L -o extended` once per cycle
3. Parses libvirt XML + Nova metadata
4. Collects:

   * CPU usage
   * Disk I/O and thresholds
   * Network counters
   * Conntrack flows per fixed IP
5. Performs threat-intel checks:

   * Tor exit-node matches (IPv4 + IPv6)
   * Spamhaus DROP (IPv4 + IPv6) CIDR matches
   * EmergingThreats compromised-IP matches (IPv4)
   * Custom user IP list matches (IPv4 + IPv6)
6. Applies zero-suppression rules
7. Stores per-instance metrics in the dynamic cache

## Prometheus Scrape (cheap path)

1. Prometheus hits `/metrics`
2. Exporter’s `Collect()`:

   * Reads static cache
   * Reads dynamic cache
3. Streams the last collected metrics

There are **no** libvirt calls, conntrack invocations, or XML parsing in the scrape path. Scrapes have predictable latency.

## Cache Cleanup

A separate goroutine:

* Runs every minute
* Removes expired static entries
* Removes expired dynamic entries
* Drops metrics for instances that no longer exist

This keeps memory usage stable even on busy compute nodes.

---

# **Features**

* Per-instance CPU usage with smart suppression
* Disk I/O metrics and disk-type thresholds
* Network counters with per-interface suppression
* Conntrack flow counts per fixed IP
* Tor exit-node contact detection (**IPv4 + IPv6**)
* Spamhaus DROP CIDR detection (**IPv4 + IPv6**)
* EmergingThreats compromised-IP detection (**IPv4**)
* Custom operator IP list detection (**IPv4 + IPv6**)
* Per-disk threshold maps (`default`, `local`, `ultra`, etc.)
* Static + dynamic TTL caches
* Low cardinality by design
* Full OpenStack metadata baked into all labels

---

# **Metric Naming**

All metrics are prefixed with:

`oie_`

and carry OpenStack metadata labels.

---

# **CPU Metrics**

### `oie_cpu_percent`

* Per-instance CPU usage in percent.
* Computed from deltas between samples and scaled by vCPU count.
* Uses background sampling (no per-scrape sleeps).

Zero-suppression rules:

* If this is the **first** value for the instance → export.
* If previous export was `0` and current is `0` → suppress.
* If previous export equals current value → suppress.
* If `usage < cpu.min` → suppress.

Only meaningful CPU changes above the configured minimum get exported.

---

# **Disk Metrics**

Threshold metrics (configuration) are **always exported**:

* `oie_disk_r_alert_threshold`
* `oie_disk_w_alert_threshold`

These encode disk-type thresholds and rarely change.

I/O metrics are only exported if any I/O has occurred for that disk:

* `oie_disk_r_gbytes`
* `oie_disk_w_gbytes`
* `oie_disk_r_requests`
* `oie_disk_w_requests`

Zero-suppression for disks:

* If **all** of `RdBytes`, `WrBytes`, `RdReq`, `WrReq` are `0`, only thresholds are exported.
* I/O counters are emitted only when there is some activity.

---

# **Network Metrics**

Per-interface network metrics:

* `oie_net_rx_gbytes`
* `oie_net_tx_gbytes`
* `oie_net_rx_pkt_total`
* `oie_net_tx_pkt_total`
* `oie_net_rx_er_total`
* `oie_net_tx_er_total`
* `oie_net_rx_drp_total`
* `oie_net_tx_drp_total`

Zero-suppression for interfaces:

* If **all** eight counters are `0` for a NIC, no metrics are exported for that interface for that cycle.

This prevents “eternal zero” series on idle NICs.

---

# **Conntrack Metrics**

### `oie_conntrack_ip_total`

* Number of conntrack flows matched to a fixed IP of the instance during the collection cycle.

Why fixed IPs?

* OpenStack floating IPs are implemented via NAT.
* OVN/OVS rewrites packets to the fixed IP before conntrack.
* Conntrack sees the **internal** fixed IP, not the floating IP.

Zero-suppression:

* Metric exported only if `count >= conntrack.min`.
* IPs with flow counts below the threshold do not emit a metric.

---

# **Threat-Intel Metrics**

All threat-intel checks run against the same conntrack data used for `oie_conntrack_ip_total`. No extra packet capture is required.

Common label set:

* `domain`
* `instance_uuid`
* `project_uuid`
* `user_uuid`

All threat-intel metrics are **only** exported on positive contact (hit). They never emit zero values.

IPv4 / IPv6 support summary:

| Metric                        | Source                                     | IPv4 | IPv6 |
| ----------------------------- | ------------------------------------------ | :--: | :--: |
| `oie_tor_contact`             | Tor Onionoo `details` API (`or_addresses`) |   ✅  |   ✅  |
| `oie_spamhaus_contact`        | Spamhaus DROP / DROPv6 CIDR lists          |   ✅  |   ✅  |
| `oie_emergingthreats_contact` | EmergingThreats `compromised-ips.txt`      |   ✅  |   ⛔  |
| `oie_customlist_contact`      | Operator-provided plaintext IP list        |   ✅  |   ✅  |

---

## Tor Exit Node Contact Detection

### `oie_tor_contact`

Emitted if an instance talks to any IP in the Tor exit-node list during the collection interval.

* Data source (default flag): Onionoo `details` API
  `https://onionoo.torproject.org/details?search=flag:exit&fields=or_addresses`
* Handles both IPv4 and IPv6 exit addresses.
* Exit-node IPs loaded into an in-memory set.

Zero-suppression:

* Only emitted as `1.0` when a hit is detected.
* No metric at all when no Tor exits are contacted.

---

## Spamhaus DROP CIDR Detection (IPv4 + IPv6)

### `oie_spamhaus_contact`

Emitted if an instance talks to any IP contained in the Spamhaus DROP CIDR lists.

Data sources (defaults):

* IPv4: `https://www.spamhaus.org/drop/drop.txt`
* IPv6: `https://www.spamhaus.org/drop/dropv6.txt`

Implementation details:

* Both lists parsed into `net.IPNet` CIDRs.
* IPv4 CIDRs bucketed by `/16` (first two octets).
* IPv6 CIDRs bucketed by a 3-hextet-style prefix.
* Matching is done per conntrack endpoint (src/dst).

Zero-suppression:

* Only emits `1.0` when any matched CIDR is hit.
* No metric when no DROP-listed target is contacted.

---

## EmergingThreats Compromised-IP Detection (IPv4)

### `oie_emergingthreats_contact`

Emitted if an instance talks to any EmergingThreats compromised IP.

Data source (default):

* `https://rules.emergingthreats.net/blockrules/compromised-ips.txt`

Implementation details:

* Plain list of IP addresses, one per line.
* As provided, this feed is IPv4-only.
* Loaded into a `map[string]struct{}` for O(1) lookups by string IP.

Zero-suppression:

* Only emits `1.0` when a compromised IP is contacted.
* No metric when there is no contact.

---

## Custom User-Provided IP List Detection (IPv4 + IPv6)

### `oie_customlist_contact`

Emitted if an instance talks to any IP from a custom operator-maintained list.

File format:

```text
# comments allowed
1.2.3.4
2001:db8::1
203.0.113.10
```

* One IPv4 or IPv6 address per line.
* Empty lines and comment lines (`#...`) ignored.
* Non-parsable entries are skipped.
* Parsed and stored as a `map[string]struct{}`.

Zero-suppression:

* Only emits `1.0` when a conntrack flow involving an IP from this list is detected.
* No metric when no custom-list IP is contacted.

---

# **Dynamic Disk Threshold Maps**

Read/write thresholds can be defined per disk type:

Examples:

```bash
-read.thresholds="default:500,local:200,ultra:2500"
-write.thresholds="default:500,premium:1000"
```

Resolution order:

1. specific disk type (e.g. `ultra`)
2. `"default"` entry (if present)
3. built-in default thresholds (`-default.read.threshold`, `-default.write.threshold`)

Threshold metrics are always exported, even if the disk has never seen any I/O.

---

# **Cache System**

The exporter uses a simple in-memory cache abstraction with TTL.

## Static Cache

* Stores rarely-changing metrics (reserved for future expansion).
* TTL controlled by `-static.cache.expiration`.

## Dynamic Cache

* Stores all per-instance metrics from the last background collection.
* TTL controlled by `-dynamic.cache.expiration`.

## Cleanup Loop

* Runs once per minute.
* Removes entries whose age exceeds their cache TTL.
* Calls back into libvirt to check if an instance UUID still exists.
* Drops metrics for deleted or migrated instances.

---

# **Logging**

Logging is controlled by a log level flag and a runtime HTTP endpoint.

CLI flag:

```text
-log.level="error"    # one of: error, info, debug
```

* `error` – only errors
* `info` – errors + high-level events (downloads, hits, cleanup)
* `debug` – verbose per-VM/per-flow details, useful for tuning

Runtime control endpoint:

* `GET  /debug/log-level`
  Returns the current numeric log level.
* `POST /debug/log-level?level=debug`
  or `GET /debug/log-level?level=debug` (for simplicity)

  * `level` can be `error`, `info`, or `debug`.

This allows turning detailed logging on/off without restarting the exporter.

---

# **Exporter Workflow**

## 1. Startup

* Parse CLI flags
* Connect to libvirt
* Initialize caches
* Initialize metric descriptors
* Start:

  * background collection goroutine
  * cache cleanup goroutine
  * Tor refresher goroutine (if enabled)
  * Spamhaus refresher goroutine (if enabled)
  * EmergingThreats refresher goroutine (if enabled)
  * Custom IP list refresher goroutine (if enabled)
* Start HTTP server and register Prometheus collector

## 2. Background Collection

For each interval:

1. List active domains (`CONNECT_LIST_DOMAINS_ACTIVE`)
2. Run `conntrack -L -o extended`
3. For each domain:

   * Parse XML (Nova metadata, disks, interfaces)
   * Resolve OpenStack user/project/instance UUIDs
   * Collect:

     * Disk I/O + thresholds
     * CPU usage (delta-based)
     * Network counters
     * Conntrack counts per fixed IP
   * Perform threat-intel matching:

     * Tor exit-node IPs (IPv4 + IPv6)
     * Spamhaus CIDRs (IPv4 + IPv6)
     * EmergingThreats IPs (IPv4)
     * Custom user list IPs (IPv4 + IPv6)
   * Apply zero-suppression
   * Write metrics slice into dynamic cache under instance UUID

## 3. Cleanup

* Periodically flush expired cache entries.
* Drop metrics for instances no longer present in libvirt.

## 4. Prometheus Scrape

* `/metrics` handler uses a dedicated Prometheus registry.
* Collector’s `Collect()` loads metrics from both caches.
* No expensive operations executed during the scrape.

---

# **CLI Flags**

### Web Server

```text
-web.listen-address="0.0.0.0:9120"
-web.telemetry-path="/metrics"
```

### Libvirt

```text
-libvirt.uri="qemu:///system"
```

### Disk Thresholds

```text
-read.thresholds=""
-write.thresholds=""
-default.read.threshold=100
-default.write.threshold=100
```

### Cache Durations

```text
-static.cache.expiration=1h
-dynamic.cache.expiration=10s
```

### Collection Interval

```text
-collection.interval=10s
```

### Logging

```text
-log.level="error"    # error, info, debug
```

### Minimum Export Conditions

```text
-conntrack.min=20     # minimum flows for oie_conntrack_ip_total
-cpu.min=10.0         # minimum CPU percent for oie_cpu_percent
```

### Tor Detection

```text
-tor.enable=false
-tor.url="https://onionoo.torproject.org/details?search=flag:exit&fields=or_addresses"
-tor.refresh=1h
```

### Spamhaus Detection (IPv4 + IPv6)

```text
-spamhaus.enable=false
-spamhaus.url="https://www.spamhaus.org/drop/drop.txt"
-spamhaus.ipv6.url="https://www.spamhaus.org/drop/dropv6.txt"
-spamhaus.refresh=6h
```

### EmergingThreats Detection (IPv4)

```text
-emergingthreats.enable=false
-emergingthreats.url="https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
-emergingthreats.refresh=6h
```

### Custom User IP List Detection (IPv4 + IPv6)

```text
-customlist.enable=false
-customlist.path=""          # path to file with one IP per line
-customlist.refresh=10m
```

---

# **Example ExecStart**

```bash
/openstack_instance_exporter \
  -web.listen-address="0.0.0.0:9120" \
  -web.telemetry-path="/metrics" \
  -libvirt.uri="qemu:///system" \
  -read.thresholds="default:500,local:200,ultra:2500" \
  -write.thresholds="default:500,local:200,ultra:2500" \
  -default.read.threshold=100 \
  -default.write.threshold=100 \
  -collection.interval=10s \
  -dynamic.cache.expiration=10s \
  -conntrack.min=20 \
  -cpu.min=10 \
  -tor.enable \
  -tor.refresh=1h \
  -spamhaus.enable \
  -spamhaus.refresh=6h \
  -emergingthreats.enable \
  -emergingthreats.refresh=6h \
  -customlist.enable \
  -customlist.path="/opt/openstack_instance_exporter/custom-ips.txt" \
  -customlist.refresh=10m \
  -log.level="info"
```

---

# **Efficiency Summary**

* Scrapes never hit libvirt or conntrack.
* Background sampling isolates heavy operations.
* Tor, Spamhaus, EmergingThreats, and custom IP matching all piggyback on conntrack scanning.
* Zero-suppression eliminates meaningless or repetitive time series.
* Cache cleanup prevents unbounded growth from dead instances.
* Stable and efficient on large compute nodes with many VMs.

---

**End of README**