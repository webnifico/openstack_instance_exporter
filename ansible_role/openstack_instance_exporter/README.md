# **OpenStack Instance Exporter — Ansible Role**

This role installs and manages the **OpenStack Instance Exporter** on OpenStack compute nodes.
The exporter collects **per-instance CPU, disk, network, conntrack, threat-intel**, and other VM-level signals directly from libvirt and conntrack, and exposes them to Prometheus.

The exporter is optimized for large clouds with:

* zero-suppression
* stable cardinality
* safe caching
* predictable scrape latency
* threat-intel feeds (Tor, Spamhaus DROP/DROPv6, EmergingThreats, custom IP lists)

---

## **Requirements**

* libvirt (for per-VM stats + XML metadata)
* conntrack-tools (`conntrack -L -o extended` support)
* systemd (for service management)

---

## **Role Variables**

Below are the current variables matching your exporter flags and internal defaults.

```yaml
# Enable installation
openstack_instance_exporter_enabled: false

# Exporter version + download location
openstack_instance_exporter_version: "v1.1.0"
openstack_instance_exporter_sha256: "https://github.com/webnifico/openstack_instance_exporter/releases/download/{{ openstack_instance_exporter_version }}/sha256sums.txt"

# Install directory
openstack_instance_exporter_install_dir: "/opt/openstack_instance_exporter"

# HTTP listener
openstack_instance_exporter_bind_port: 9120
openstack_instance_exporter_web_telemetry_path: "/metrics"

# If defined, exporter binds to this interface IP:PORT.
# If undefined/empty, exporter binds to 0.0.0.0:PORT.
openstack_instance_exporter_network_interface: br-monitoring

# -----------------------------------------------------------------------------
# LOGGING
# -----------------------------------------------------------------------------
# Logging level (controls -log.level).
# Valid values: debug, info, error
# If unset, the systemd template defaults to "error".
#
# NOTE:
#   - Threat-intel HIT log lines (TOR-HIT / SPAMHAUS-HIT / EMTHREATS-HIT /
#     CUSTOMLIST-HIT) are ALWAYS logged when their feature is enabled,
#     regardless of log.level.
#   - log.level only controls general debug/info noise (collection summaries,
#     zero-suppression chatter, cache cleanup logs, etc.).
#
# Example:
#   openstack_instance_exporter_log_level: "debug"
#
# openstack_instance_exporter_log_level: "error"

# Collection interval (background polling from libvirt + conntrack)
openstack_instance_exporter_collection_interval: 10s

# Cache expirations (match exporter defaults)
openstack_instance_exporter_static_cache_expiration: 1h
openstack_instance_exporter_dynamic_cache_expiration: 10s

# Conntrack suppression
# Minimum number of flows required before exporting oie_conntrack_ip_total for an IP
openstack_instance_exporter_conntrack_min: 20

# CPU suppression
# Minimum CPU % required before exporting; below this, CPU metrics are suppressed
openstack_instance_exporter_cpu_min: 10

# Disk threshold defaults
openstack_instance_exporter_default_read_threshold: 100
openstack_instance_exporter_default_write_threshold: 100

# Per-disk-type thresholds (optional)
# Example:
# openstack_instance_exporter_read_thresholds:
#   - disk_tier: volumes
#     threshold: 500
#   - disk_tier: ultra
#     threshold: 2500
#
# openstack_instance_exporter_write_thresholds:
#   - disk_tier: volumes
#     threshold: 500
openstack_instance_exporter_read_thresholds: []
openstack_instance_exporter_write_thresholds: []

# -----------------------------------------------------------------------------
# THREAT-INTELLIGENCE MASTER SWITCH
# -----------------------------------------------------------------------------
# When enabled, this overrides individual Tor/Spamhaus/EmergingThreats flags
# and forces ALL threat-intel detection on (Tor, Spamhaus v4/v6, EmergingThreats).
# Threat hits will still be logged even if log.level=error.
# -----------------------------------------------------------------------------
openstack_instance_exporter_threats_enable: false

# -----------------------------------------------------------------------------
# TOR EXIT NODE DETECTION (IPv4 + IPv6 via Onionoo)
# -----------------------------------------------------------------------------
openstack_instance_exporter_tor_enable: true
openstack_instance_exporter_tor_url: "https://onionoo.torproject.org/details?search=flag:exit&fields=or_addresses"
openstack_instance_exporter_tor_refresh: 1h

# -----------------------------------------------------------------------------
# SPAMHAUS DROP CIDR DETECTION (IPv4 + IPv6)
# -----------------------------------------------------------------------------
openstack_instance_exporter_spamhaus_enable: true

# IPv4 DROP list
openstack_instance_exporter_spamhaus_url: "https://www.spamhaus.org/drop/drop.txt"

# IPv6 DROPv6 list (optional override; exporter handles v6 in same engine)
openstack_instance_exporter_spamhaus_ipv6_url: "https://www.spamhaus.org/drop/dropv6.txt"

# Unified refresh interval for Spamhaus CIDRs (applies to both v4 and v6)
openstack_instance_exporter_spamhaus_refresh: 6h

# -----------------------------------------------------------------------------
# EMERGINGTHREATS COMPROMISED IP DETECTION
# -----------------------------------------------------------------------------
# This list contains IPs of actively compromised servers observed attacking.
# -----------------------------------------------------------------------------
openstack_instance_exporter_emergingthreats_enable: true
openstack_instance_exporter_emergingthreats_url: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
openstack_instance_exporter_emergingthreats_refresh: 6h

# -----------------------------------------------------------------------------
# CUSTOM USER IP LIST (PER-LINE IPv4 / IPv6)
# -----------------------------------------------------------------------------
# When enabled, exporter will load a local file of IPs (one per line)
# and raise a boolean contact metric when any instance talks to them.
# Threat hits from this list are always logged when detected.
# -----------------------------------------------------------------------------
openstack_instance_exporter_customlist_enable: false

# Path on the target host to custom IP list file (one IP per line, IPv4 or IPv6)
# This is where the role will write/copy the file to.
# Example:
# openstack_instance_exporter_customlist_path: "/opt/openstack_instance_exporter/custom-ips.txt"

# Refresh interval for re-reading the custom IP list (defaults to 6h)
# openstack_instance_exporter_customlist_refresh: 6h

# Option A: provide IPs inline (one per element). If set and non-empty, the role
# will render these into the customlist_path on the target host.
# Example:
# openstack_instance_exporter_custom_ip_list:
#   - "1.2.3.4"
#   - "2001:db8::1"

# Option B: copy from a static file shipped with this role (roles/<role>/files/).
# For example, put files/custom-ips.txt in the role and set:
# openstack_instance_exporter_customlist_src: "custom-ips.txt"
```

---

## **What the Exporter Suppresses (Zero-Suppression)**

The exporter intentionally eliminates useless time series.
This dramatically reduces Prometheus TSDB size and cardinality.

### **CPU**

Suppressed when:

* usage < `openstack_instance_exporter_cpu_min`
* repeated 0 %
* identical to last export for that instance

Only changed, meaningful CPU values are exported.

---

### **Disk**

For each disk:

* Threshold metrics (`oie_disk_r_alert_threshold`, `oie_disk_w_alert_threshold`)
  are **always exported** (they represent configuration).
* I/O counters (`oie_disk_r_gbytes`, `oie_disk_w_gbytes`, `oie_disk_r_requests`, `oie_disk_w_requests`)
  are exported **only if there is activity**:

  * `RdBytes > 0` OR `WrBytes > 0` OR `RdReq > 0` OR `WrReq > 0`

If a disk has never seen I/O, only thresholds appear; counters are suppressed.

---

### **Network**

Per-interface metrics are suppressed when *all* counters are zero:

* bytes: `RxBytes`, `TxBytes`
* packets: `RxPackets`, `TxPackets`
* errors: `RxErrs`, `TxErrs`
* drops: `RxDrop`, `TxDrop`

If all are 0, **no network metrics are exported for that interface**.

---

### **Conntrack**

For each fixed IP of an instance, the exporter counts conntrack flows and emits:

* `oie_conntrack_ip_total{ip=...,instance_uuid=...}`

…but **only if**:

* `flow_count >= openstack_instance_exporter_conntrack_min`

Below that threshold, the metric is suppressed.

---

### **Threat Intel**

All threat-intel contact metrics are **boolean hits only**:

* `oie_tor_contact`
* `oie_spamhaus_contact`
* `oie_emergingthreats_contact`
* `oie_customlist_contact` (custom IP list)

They are emitted **only when a hit occurs during the collection interval**.
There are no continuously-streamed `0` samples for “no contact”.

Threat HIT log lines are **always** written when hits occur (for any enabled
threat feed), regardless of `openstack_instance_exporter_log_level`.

---

## **Threat Intelligence Support**

Exporter natively supports:

| Feed                            | Match Type         | Metric                        |
| ------------------------------- | ------------------ | ----------------------------- |
| Tor Exit List (Onionoo, v4/v6)  | IP match           | `oie_tor_contact`             |
| Spamhaus DROP/DROPv6            | CIDR match (v4/v6) | `oie_spamhaus_contact`        |
| EmergingThreats Compromised IPs | IP match           | `oie_emergingthreats_contact` |
| Custom IP List (local file)     | IP match           | `oie_customlist_contact`      |

Zero-suppression applies — metrics only appear when hits occur.
Each threat hit also produces a log line (TOR-HIT / SPAMHAUS-HIT / EMTHREATS-HIT / CUSTOMLIST-HIT) regardless of log level.

---

## **Service File Template Example**

The role generates a systemd service like:

```ini
[Unit]
Description=OpenStack Instance Exporter
After=network.target

[Service]
User=root
Group=root
ExecStart=/opt/openstack_instance_exporter/openstack_instance_exporter \
  -web.listen-address=IP:PORT \
  -web.telemetry-path=/metrics \
  -collection.interval=10s \
  -static.cache.expiration=1h \
  -dynamic.cache.expiration=10s \
  -conntrack.min=20 \
  -cpu.min=10 \
  -default.read.threshold=100 \
  -default.write.threshold=100 \
  -log.level=error \
  ... (per-tier thresholds) ...
  ... (Tor/Spamhaus/ET/custom-list flags if enabled) ...

Restart=always
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

The actual `ExecStart` flags are rendered from the role variables shown above, with `-log.level` coming from `openstack_instance_exporter_log_level` and defaulting to `error` when unset.

---

## **Dependencies**

* `libvirt-daemon` / `libvirtd` on compute nodes
* `conntrack-tools`
* `systemd`
* (optional) `python3-libvirt` if you use Ansible libvirt modules elsewhere

---

## **Example Playbook**

```yaml
- hosts: compute
  become: true
  roles:
    - role: openstack_instance_exporter
```

---

## **License**

Apache 2.0

---

## **Author**

xneelo cloud engineering team
