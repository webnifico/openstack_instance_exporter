# OpenStack Instance Exporter (OIE)

A high-performance Prometheus exporter for **OpenStack compute nodes** (and optionally L3 / OVN-BGP nodes if running collapsed compute architecture).

OIE collects **per-instance** CPU, disk, network, and conntrack summaries, enriches them with **OpenStack UUID context**, applies **zero-suppression**, and (optionally) flags contacts with common threat-intel lists — while keeping Prometheus cardinality boring and predictable.

---

**Bounded series only:**

* per instance
* per disk
* per vNIC
* per fixed IP (when activity passes a threshold)

**Never exported:**

* per remote IP series
* per destination port series
* any unbounded “one series per X on the internet” label

---

## TL;DR behavior

* Heavy work runs **in the background** on a fixed interval.
* `/metrics` scrapes are **cache reads only**.
* Zero-suppression avoids eternal-zero noise.
* Threat feeds are **optional**, refreshed async with last-good retained.
* `conntrack.min` gates:

  * conntrack per-fixed-IP flow export
  * outbound behavior export (when enabled)
* Host-level health/telemetry is always exported.

---

## Architecture

```text
Optional threat feeds ──refresh──▶ in-memory sets/buckets (last-good retained)
                                    │
                                    ▼
Background loop (every -collection.interval)
  1) list ACTIVE domains once
  2) read conntrack once (v4+v6)
  3) per-domain goroutines:
     - parse Nova XML → UUIDs, fixed IPs, disks, vNICs
     - instance + disk static info (always)
     - CPU percent (delta) + suppression
     - disk I/O + thresholds
     - vNIC counters + suppression
     - conntrack flows per fixed IP (thresholded)
     - outbound behavior counts (optional, thresholded)
     - threat matching (optional)
     - write slice → dynamic cache
                                    │
                                    ▼
/metrics scrape
  - stream static cache + dynamic cache
  - NO libvirt / conntrack / XML here
                                    │
                                    ▼
Cleanup loop (every minute)
  - TTL expiry
  - drop dead instance state
  - prune CPU/outbound/threat history
```

---

## What OIE collects

Per **instance**:

* **Static instance info (always emitted)**

  * flavor, vcpus, mem, root type, created_at, project/user UUIDs
* CPU utilisation % (suppressed)
* Disk I/O counters per disk (suppressed)
* Disk read/write thresholds per disk (always emitted)
* **Static disk info (always emitted)**

  * disk_uuid, disk_type, disk_path
* Network counters per vNIC (suppressed)
* Conntrack flow summaries per fixed IP (thresholded)
* Outbound behavior summaries (optional, thresholded)
* Threat-intel contacts (optional)
* Host IP threat matching (optional)
* Host-level collector health (always)

All exported series include OpenStack UUIDs so you can pivot:
`hypervisor → project → instance → disk/interface/IP`

---

## Tested stack

* Ubuntu 22.04 / 24.04
* libvirt 8.x–10.x
* OpenStack Bobcat → Epoxy era
* Prometheus 2.47+
* Grafana 11+

---

## Build & run

Go 1.22+.

```bash
git clone <repo>
cd openstack_instance_exporter
go mod tidy
go build -o openstack_instance_exporter
sudo ./openstack_instance_exporter
```

---

## How the code works

### Startup (`main`)

1. Parse CLI flags.
2. Configure logging (stdout, optional file) + runtime log level.
3. Parse:

   * disk thresholds
   * contact direction defaults
   * host interface allow-list
4. Create collector with `NewMetricsCollector(...)`.
5. Register collector in a dedicated Prometheus registry.
6. Serve HTTP:

   * `/metrics`
   * `/debug/log-level`

`NewMetricsCollector` also:

* opens threat file if enabled
* creates HTTP client with **15s timeout**
* starts enabled feed refreshers
* starts background collector loop
* starts cache cleanup loop

---

### Background collection (`startBackgroundCollection`)

Runs forever:

1. `ListAllDomains(ACTIVE)` once per interval.
2. `readConntrack()` once per interval:

   * netlink conntrack snapshot for IPv4 + IPv6
3. Fan-out per-domain goroutines:

   * `collectDomainMetrics(domain, ctEntries)`
4. Emit host telemetry into static cache.
5. Sleep for `-collection.interval`.

Heavy operations never happen on scrape.

---

### Per-domain collection (`collectDomainMetrics`)

**1) Metadata + fixed IPs**

* Get domain name + UUID.
* Pull XML.
* Unmarshal `DomainXML`.
* From Nova ports metadata, build:

  * `fixedIPs []IP` with `Family = ipv4|ipv6`
  * `ipSet map[string]struct{}` for membership checks.
* Extract:

  * `project_uuid`, `project_name`
  * `user_uuid`, `user_name`
  * `flavor`, `vcpus`, `mem_mb`
  * `root_type`, `created_at`, `metadata_version`

Always emit:

* `oie_instance_info{...}=1`

**2) Disk I/O + thresholds**

For each XML disk:

* skip non-`device="disk"`.
* `BlockStats(dev)` for counters.
* Determine disk tier:

  * `type="file"` → `local`
  * otherwise parse `tier/uuid` from `source.name`
* Threshold resolution:

  1. tier override
  2. `"default"` override
  3. built-in defaults

Always emit:

* `oie_disk_info{...}=1`
* `oie_disk_r_alert_threshold`
* `oie_disk_w_alert_threshold`

Emit I/O counters **only if any activity**:

* `oie_disk_*_gbytes`
* `oie_disk_*_requests`

**3) CPU percent**

* `calculateCPUUsage()`:

  * reads libvirt CPU time
  * stores last sample in `cpuSamples[uuid]`
  * delta / elapsed / vcpus → percent
  * clamp to `[0..100]`
* `shouldExportCPU()`:

  * export if usage ≥ `cpu.min`
  * allow one trailing sample after dropping under min
  * suppress repeated idle zeros

**4) Network per vNIC**

For each interface:

* `InterfaceStats(iface)`
* suppress if all 8 counters zero
* otherwise emit only non-zero counters:

  * `oie_net_{rx,tx}_gbytes`
  * `oie_net_{rx,tx}_pkt_total`
  * `oie_net_{rx,tx}_er_total`
  * `oie_net_{rx,tx}_drp_total`

**5) Conntrack summaries per fixed IP**

* Scan interval conntrack snapshot once.
* For each entry:

  * if `Src` or `Dst` matches a fixed IP:

    * bump flow count for that fixed IP
  * if fixed IP is source and dest is not another fixed IP:

    * populate outbound maps (if enabled)

After scan, per fixed IP:

* emit only if flows ≥ `conntrack.min`:

  * `oie_conntrack_ip_flows_total`

Why fixed IPs work under NAT:

* OVN/OVS conntrack on the host tracks VM endpoints using fixed IPs through the pipeline. Floating IPs don’t appear as the VM endpoint in host conntrack.

**6) Outbound behavior (optional)**
Enabled by `-outbound.behavior.enable`.

Outbound is:

* fixed IP is **source**
* dest is **not** another fixed IP of the instance.

Per fixed IP per interval:

* unique remotes
* new remotes vs previous interval
* total outbound flows
* max flows to one remote
* unique dst ports (count only)
* new dst ports vs previous interval
* max flows to one dst port

Counts only. No per-remote / per-port series.

**Export gate:** outbound metrics are exported per fixed IP only when **either** of these meets `conntrack.min` in the current interval:

* unique outbound remotes, **or**
* outbound flows

Dst-port counts do **not** gate export; they’re included only when outbound export is already triggered.

**7) Threat-intel matching (optional)**

For each enabled list:

* Scan conntrack snapshot.
* Consider flows involving VM fixed IPs.
* Apply direction filter:

  * default from `-contacts.direction`
  * per-list override allows `out|in|any`
* Dedup by unordered endpoint pair per interval.
* Emit:

  * `*_contact_active` (gauge): interval hits
  * `*_contact` (counter): accumulated hits since process start

Counters reset on exporter restart by design.

**8) Cache write**

* Store the per-instance metric slice in dynamic cache:

  * key = instance UUID
  * TTL = `-dynamic.cache.expiration`

---

### Scrape path (`Collect`)

* Reads:

  * static cache (host/list metrics)
  * dynamic cache (per instance slices)
* Streams everything to Prometheus.

No expensive work.

---

### Cleanup loop (`startCacheCleanup`)

Every minute:

* expire static + dynamic TTL entries (host_* entries are retained)
* remove cache entries for inactive instances
* prune:

  * `cpuSamples`, `cpuLastExport`
  * outbound previous-interval state
  * threat counter maps

Keeps memory flat under VM churn.

---

### Host threat matching (optional)

Enabled by `-host.threats.enable`.

* Enumerates host NIC IPs (optionally allow private)
* Filters interfaces by `-host.interfaces` list

  * default interface if empty: `bgp-nic`
* Matches host IPs against enabled lists.
* Emits into static cache:

  * `oie_host_threat_listed{list,ip,family}=1`

Useful for L3/BGP nodes with public addresses.

---

## Metrics

### Instance info (always)

* `oie_instance_info` (gauge)

  * One series per active domain.
  * Labels:
    `domain, instance_uuid, project_uuid, project_name, user_uuid, user_name, flavor, vcpus, mem_mb, root_type, created_at, metadata_version`

### CPU (suppressed)

* `oie_cpu_percent` (gauge)

  * Labels: `domain, instance_uuid, user_uuid, project_uuid`

### Disk

Always:

* `oie_disk_info` (gauge)
* `oie_disk_r_alert_threshold` (gauge)
* `oie_disk_w_alert_threshold` (gauge)

On I/O activity:

* `oie_disk_r_gbytes` (counter)
* `oie_disk_w_gbytes` (counter)
* `oie_disk_r_requests` (counter)
* `oie_disk_w_requests` (counter)

Labels:
`domain, instance_uuid, user_uuid, project_uuid, disk_uuid, disk_type, disk_path`

### Network (per vNIC, on activity)

* `oie_net_rx_gbytes`
* `oie_net_tx_gbytes`
* `oie_net_rx_pkt_total`
* `oie_net_tx_pkt_total`
* `oie_net_rx_er_total`
* `oie_net_tx_er_total`
* `oie_net_rx_drp_total`
* `oie_net_tx_drp_total`

Labels:
`domain, interface, instance_uuid, user_uuid, project_uuid`

### Conntrack summaries (per fixed IP, on threshold)

* `oie_conntrack_ip_flows_total` (gauge)

Labels:
`domain, instance_uuid, ip, family, project_uuid, user_uuid`

### Outbound behavior (optional, per fixed IP)

* `oie_outbound_unique_remotes`
* `oie_outbound_new_remotes`
* `oie_outbound_flows`
* `oie_outbound_max_flows_single_remote`
* `oie_outbound_unique_dst_ports`
* `oie_outbound_new_dst_ports`
* `oie_outbound_max_flows_single_dst_port`

Labels: same as conntrack per fixed IP.
Exported only when outbound meets the `conntrack.min` gate (unique remotes **or** outbound flows).

### Threat-intel (optional, per instance)

Each list exports:

* `oie_<list>_contact_active` (gauge)
* `oie_<list>_contact` (counter)

Lists:

* `tor_exit`
* `tor_relay`
* `spamhaus`
* `emergingthreats`
* `customlist`

Labels:
`domain, instance_uuid, project_uuid, user_uuid, direction`

### Threat feed refresh telemetry (host-level)

Per list:

* `<list>_refresh_last_success_timestamp_seconds` (gauge)
* `<list>_refresh_duration_seconds` (gauge)
* `<list>_refresh_errors_total` (counter)
* `<list>_entries` (gauge)

Concrete names:

* `oie_tor_exit_refresh_last_success_timestamp_seconds`
* `oie_tor_exit_refresh_duration_seconds`
* `oie_tor_exit_refresh_errors_total`
* `oie_tor_exit_entries`

…and the same pattern for:

* `tor_relay`
* `spamhaus`
* `emergingthreats`
* `customlist`

### Host threats (optional)

* `oie_host_threat_listed` (gauge)

Labels: `list, ip, family`

### Host collector health (always)

* `oie_host_active_vms` (gauge)
* `oie_host_active_vcpus` (gauge)
* `oie_host_active_mem_gbytes` (gauge)
* `oie_host_collection_errors_total` (counter)
* `oie_host_collection_duration_seconds` (gauge)
* `oie_host_collection_lag_seconds` (gauge)
* `oie_host_libvirt_list_duration_seconds` (gauge)
* `oie_host_conntrack_read_duration_seconds` (gauge)
* `oie_host_conntrack_entries_total` (gauge)
* `oie_host_dynamic_cache_series_total` (gauge)
* `oie_host_go_heap_alloc_bytes` (gauge)
* `oie_conntrack_read_errors_total` (counter)
* `oie_host_conntrack_read_errors_total` (counter)
* `oie_static_cache_entries` (gauge)
* `oie_dynamic_cache_entries` (gauge)
* `oie_cache_cleanup_duration_seconds` (gauge)
* `oie_cache_evictions_total` (counter)

---

## Flags

### Web / libvirt

* `-web.listen-address="0.0.0.0:9120"`
* `-web.telemetry-path="/metrics"`
* `-libvirt.uri="qemu:///system"`

### Collection + caches

* `-collection.interval=10s`
* `-dynamic.cache.expiration=10s`
* `-static.cache.expiration=1h`

### Suppression thresholds

* `-cpu.min=10.0`
* `-conntrack.min=20` — minimum per-interval activity before exporting:

  * `oie_conntrack_ip_flows_total`
  * outbound behavior metrics (when enabled)

### Disk thresholds

* `-default.read.threshold=100`
* `-default.write.threshold=100`
* `-read.thresholds="default:500,local:200,ultra:2500"`
* `-write.thresholds="default:500,local:200,ultra:2500"`

### Contact direction default

* `-contacts.direction="out|in|any"`

### Outbound behavior

* `-outbound.behavior.enable`

### Tor exit

* `-tor.exit.enable`
* `-tor.exit.url="https://onionoo.torproject.org/details?search=flag:exit&fields=or_addresses"`
* `-tor.exit.refresh=1h`
* `-tor.exit.direction="out|in|any"`

### Tor relay

* `-tor.relay.enable`
* `-tor.relay.url="https://onionoo.torproject.org/details?search=flag:running&fields=or_addresses"`
* `-tor.relay.refresh=1h`
* `-tor.relay.direction="out|in|any"`

### Spamhaus

* `-spamhaus.enable`
* `-spamhaus.url="https://www.spamhaus.org/drop/drop.txt"`
* `-spamhaus.ipv6.url="https://www.spamhaus.org/drop/dropv6.txt"`
* `-spamhaus.refresh=6h`
* `-spamhaus.direction="out|in|any"`

### EmergingThreats

* `-emergingthreats.enable`
* `-emergingthreats.url="https://rules.emergingthreats.net/blockrules/compromised-ips.txt"`
* `-emergingthreats.refresh=6h`
* `-emergingthreats.direction="out|in|any"`

### Custom list

* `-customlist.enable`
* `-customlist.path="/path/to/ips.txt"`
* `-customlist.refresh=10m`
* `-customlist.direction="out|in|any"`

### Threat file logging

* `-threatfile.enable`
* `-threatfile.path="/var/log/openstack_instance_exporter.threat.log"`

### Host threats

* `-host.threats.enable`
* `-host.ips.allow-private`
* `-host.interfaces="bgp-nic,eth1"`

### Logging

* `-log.level="error|notice|info|debug"`
* `-log.file.enable`
* `-log.file.path="/var/log/openstack_instance_exporter.log"`

Runtime log level change:

* `GET  /debug/log-level`
* `POST /debug/log-level?level=debug`

---

## Example

Compute node with outbound summaries + Spamhaus + EmergingThreats:

```bash
./openstack_instance_exporter \
  -collection.interval=10s \
  -dynamic.cache.expiration=10s \
  -static.cache.expiration=1h \
  -cpu.min=10 \
  -conntrack.min=20 \
  -outbound.behavior.enable \
  -spamhaus.enable \
  -spamhaus.refresh=6h \
  -emergingthreats.enable \
  -emergingthreats.refresh=6h \
  -log.level=info
```

---

## License

Apache 2.0

## Author

xneelo cloud engineering team
