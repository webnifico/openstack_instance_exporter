# OpenStack Instance Exporter — Ansible Role

Deploys and manages the **OpenStack Instance Exporter (OIE)** on:

* OpenStack **compute nodes**, and
* Optional **L3 / OVN-BGP nodes** in collapsed compute deployments.

The exporter provides **low-cardinality**, **zero-suppressed** Prometheus metrics describing per-VM CPU, memory, disk, network, conntrack activity, behavior analytics, and optional threat-intel signals.

This role handles installation, configuration, logging, and systemd lifecycle — no manual service management required.

Please see exporter repo readme for full set of configuration options.

---

## 🚀 Features

* Installs any tagged OIE release (`v1.x.x`)
* Autodetects bind address via interface or explicit override
* Fully configurable thresholds (disk tiers, attention score)
* Optional behavior analytics (outbound/inbound) with **sensitivity scaling**
* Optional threat-intel feed matching (Tor, Spamhaus, EmergingThreats, custom)
* Optional host-IP threat matching for nodes with public IPs
* Optional main log + threat log file with logrotate
* Predictable Prometheus scraping — exporter uses a background collection/caching loop

For exporter internals, scoring models, and metric definitions, see the main exporter README.

---

## 📦 Requirements

**Target hosts:**

* Linux, systemd
* `libvirt` (`qemu:///system`)
* Kernel conntrack (`nf_conntrack_netlink`)
* Root privileges (for netlink + libvirt)

**Controller host:**

* Ansible 2.12+ recommended

---

## ⚙️ Key Variables (Quick Reference)

Below are the **primary** variables operators typically touch.  
Full list remains in `defaults/main.yml`.

### Enable / version / install

```yaml
openstack_instance_exporter_enabled: true
openstack_instance_exporter_version: "v1.0.0"
openstack_instance_exporter_install_dir: "/opt/openstack_instance_exporter"
openstack_instance_exporter_sha256: "https://github.com/webnifico/openstack_instance_exporter/releases/download/v1.0.0/sha256sums.txt"
````

---

### Web binding

Use either a **hard-coded address**:

```yaml
openstack_instance_exporter_web_listen_address: "192.168.10.5:9120"
```

Or bind to an interface IP:

```yaml
openstack_instance_exporter_network_interface: br-monitoring
openstack_instance_exporter_bind_port: 9120
```

Optional:

```yaml
openstack_instance_exporter_web_telemetry_path: "/metrics"
```

---

### Collection

```yaml
# Libvirt URI (exporter flag: -libvirt.uri)
openstack_instance_exporter_libvirt_uri: "qemu:///system"

# Background collection cadence (exporter flag: -collection.interval)
openstack_instance_exporter_collection_interval: 15s

# Worker pool size for collection (exporter flag: -worker.count, 0 = NumCPU)
openstack_instance_exporter_worker_count: 0

# Direction used for threat contact classification (exporter flag: -contacts.direction)
openstack_instance_exporter_contacts_direction: out   # "out", "in", or "any"
```

The exporter runs a background collection loop and internally caches state to avoid hammering libvirt and conntrack every scrape; Prometheus can scrape more frequently than the collection interval if desired.

---

### Disk tier thresholds

Example:

```yaml
openstack_instance_exporter_read_thresholds:
  - { disk_tier: local, threshold: 400 }

openstack_instance_exporter_write_thresholds:
  - { disk_tier: local, threshold: 200 }
```

Defaults:

```yaml
openstack_instance_exporter_default_read_threshold: 100
openstack_instance_exporter_default_write_threshold: 100
```

These thresholds are used for **per-disk “busy” classification** inside the exporter’s resource scoring.

---

### Minimum attention score & scoring weights

Controls when **resource / threat / attention** metrics/logs are emitted:

```yaml
openstack_instance_exporter_minimum_attention_score: 10
```

VMs with an attention score below this stay silent — no per-instance metrics/logs, which keeps noise and cardinality down.

You can also tweak the **score blending weights** used by the exporter if needed:

```yaml
openstack_instance_exporter_score_weight_resource: 0.5
openstack_instance_exporter_score_weight_threat: 0.5
openstack_instance_exporter_score_weight_behavior: 100

openstack_instance_exporter_score_weight_tor: 25.0
openstack_instance_exporter_score_weight_relay: 5.0
openstack_instance_exporter_score_weight_spam: 40.0
openstack_instance_exporter_score_weight_emerging: 40.0
openstack_instance_exporter_score_weight_custom: 5.0
```

If these are not set, the exporter’s compiled-in defaults are used.

---

### Behavior analytics (fan-out / fan-in / spikes)

Behavior logic summarizes **outbound** and **inbound** conntrack activity per VM IP:

```yaml
openstack_instance_exporter_outbound_behavior_enable: true
openstack_instance_exporter_inbound_behavior_enable: false
```

Outbound covers:

* Fan-out to many remotes
* Spikes in new remotes
* Spikes in destination ports
* Heavy focus on a single remote/port

Inbound covers:

* Fan-in from many remotes
* Scanning / brute-force patterns
* Heavy focus on a single service

---

### Behavior sensitivity (single knob)

Behavior thresholds can be **scaled** globally with a single knob:

```yaml
openstack_instance_exporter_behavior_sensitivity: 1.0
```

This maps to the `-behavior.sensitivity` flag and is used to multiply all internal behavior thresholds.

Rough guide:

```text
< 1.0  → more sensitive (fires on smaller spikes)
= 1.0  → baseline
> 1.0  → less sensitive (requires bigger spikes)
```

Typical range:

```text
0.25  very sensitive
0.50  high sensitivity
0.75  moderately sensitive
1.00  balanced (default)
1.50  less sensitive
2.00  quite relaxed
```

You can set this directly, or let **profiles** drive it (see below).

---

### Threat-intel feeds

```yaml
openstack_instance_exporter_spamhaus_enable: true
openstack_instance_exporter_emergingthreats_enable: true
openstack_instance_exporter_contacts_direction: out   # "out", "in", or "any"
```

Supported lists (each independently toggleable):

* Tor exit nodes
* Tor relays
* Spamhaus DROP / DROPv6
* EmergingThreats compromised IPs
* Custom user list

Lists refresh in the background; stale lists fall back to the last known-good copy.

---

### Host IP threat detection

```yaml
openstack_instance_exporter_host_threats_enable: true
openstack_instance_exporter_host_interfaces:
  - "bgp-nic"
openstack_instance_exporter_host_ips_allow_private: false
```

This checks **host NIC IPs** (not VMs) against the enabled IP lists.
Useful for nodes with public BGP / router roles.

---

### Logging & logrotate

Main log:

```yaml
openstack_instance_exporter_log_level: info     # error | notice | info | debug
openstack_instance_exporter_log_file_enable: true
openstack_instance_exporter_log_file_path: /var/log/openstack_instance_exporter.log
```

Threat log:

```yaml
openstack_instance_exporter_threat_log_file_enable: true
openstack_instance_exporter_threat_log_file_path: /var/log/openstack_instance_exporter.threat.log
openstack_instance_exporter_threat_log_min_interval: 5m
```

Logrotate:

* Generated automatically when file logging is enabled
* Daily rotate, 14 copies, compress, copytruncate

---

## 🎚 Profiles (attention / threats / behavior)

The role exposes a **profile** mechanism that sets sane defaults for:

* Minimum attention score
* Behavior enablement
* Threat-intel enablement
* Behavior sensitivity

Top-level var:

```yaml
openstack_instance_exporter_profile: outbound-standard   # disabled | outbound-standard | outbound-observant | outbound-max | bidir-standard | bidir-observant | bidir-max
```

Profile defaults (can still be overridden per-variable):

```yaml
openstack_instance_exporter_profile_defaults:

  ################################
  # OUTBOUND-ONLY (Standard/Observant/Max)
  ################################

  outbound-standard:
    attention_min_score: 40
    outbound_behavior_enable: true
    spamhaus_enable: true
    emergingthreats_enable: true
    behavior_sensitivity: 1.25

  outbound-observant:
    attention_min_score: 25
    outbound_behavior_enable: true
    spamhaus_enable: true
    emergingthreats_enable: true
    customlist_enable: true
    tor_exit_enable: true
    tor_relay_enable: true
    behavior_sensitivity: 1.0

  outbound-max:
    attention_min_score: 0
    outbound_behavior_enable: true
    spamhaus_enable: true
    emergingthreats_enable: true
    customlist_enable: true
    tor_exit_enable: true
    tor_relay_enable: true
    behavior_sensitivity: 0.75


  ################################
  # BIDIRECTIONAL (Standard/Observant/Max)
  ################################

  bidir-standard:
    attention_min_score: 25
    inbound_behavior_enable: true
    outbound_behavior_enable: true
    spamhaus_enable: true
    spamhaus_direction: "any"
    emergingthreats_enable: true
    emergingthreats_direction: "any"
    behavior_sensitivity: 1.25

  bidir-observant:
    attention_min_score: 10
    inbound_behavior_enable: true
    outbound_behavior_enable: true
    spamhaus_enable: true
    spamhaus_direction: "any"
    emergingthreats_enable: true
    emergingthreats_direction: "any"
    customlist_enable: true
    customlist_direction: "any"
    tor_exit_enable: true
    tor_exit_direction: "any"
    tor_relay_enable: true
    tor_relay_direction: "any"
    behavior_sensitivity: 1.0

  bidir-max:
    attention_min_score: 0
    inbound_behavior_enable: true
    outbound_behavior_enable: true
    spamhaus_enable: true
    spamhaus_direction: "any"
    emergingthreats_enable: true
    emergingthreats_direction: "any"
    customlist_enable: true
    customlist_direction: "any"
    tor_exit_enable: true
    tor_exit_direction: "any"
    tor_relay_enable: true
    tor_relay_direction: "any"
    behavior_sensitivity: 0.75
```

Resolution order per setting:

1. Explicit Ansible var override (e.g. `openstack_instance_exporter_behavior_sensitivity`)
2. Profile key (e.g. `profile.behavior_sensitivity`)
3. Role default (e.g. `1.0` for behavior sensitivity if nothing else set)

---

## 🧩 Example Playbooks

### Simple outbound-only profile with behavior + threat log

```yaml
- hosts: openstack_compute
  become: true
  roles:
    - role: openstack_instance_exporter
  vars:
    openstack_instance_exporter_enabled: true
    openstack_instance_exporter_profile: outbound-standard
    openstack_instance_exporter_log_level: info
    openstack_instance_exporter_threat_log_file_enable: true
```

### More aggressive bidirectional behavior / threat posture

```yaml
- hosts: openstack_compute
  become: true
  roles:
    - role: openstack_instance_exporter
  vars:
    openstack_instance_exporter_enabled: true
    openstack_instance_exporter_profile: bidir-observant

    # Optional override: make behavior slightly *less* sensitive than profile
    openstack_instance_exporter_behavior_sensitivity: 1.25

    openstack_instance_exporter_log_level: notice
    openstack_instance_exporter_threat_log_file_enable: true
    openstack_instance_exporter_log_file_enable: true
```

---

## 🛠 Troubleshooting

**Exporter not starting**

* Check libvirt: `virsh -c qemu:///system list`
* Check service logs:

  * `journalctl -u openstack_instance_exporter -f`
  * Or the configured log file if `openstack_instance_exporter_log_file_enable: true`

**No conntrack / behavior metrics**

* Confirm conntrack is present: `lsmod | grep nf_conntrack`
* Ensure role is enabled: `openstack_instance_exporter_enabled: true`
* Check that behavior is enabled:

  * `openstack_instance_exporter_outbound_behavior_enable: true`
  * or a profile that enables it (outbound-standard/outbound-observant/outbound-max/bidir-standard/bidir-observant/bidir-max)
* If too noisy or too quiet, adjust `openstack_instance_exporter_behavior_sensitivity`.

**Threat feeds quiet**

* Verify outbound network and DNS from the node
* Check threat log file if enabled
* For testing, set list `direction: any` and use a profile that enables the list

---

## 📜 License

Apache 2.0

## 👥 Author

xneelo cloud engineering team
