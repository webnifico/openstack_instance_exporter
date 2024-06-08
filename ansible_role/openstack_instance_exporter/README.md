# OpenStack Instance Exporter — Ansible Role

This role installs and manages the **OpenStack Instance Exporter (OIE)** as a **systemd service** on:

* OpenStack **compute nodes**
* Optional **L3 / OVN-BGP nodes** in collapsed compute deployments (for host-IP threat matching)

OIE is a **hypervisor-side Prometheus exporter** that provides **low-cardinality, attribution-safe metrics** for:

* Per-VM **resource severity** (CPU / memory / disk / network)
* Host and per-VM **conntrack state** (shared blast-radius ownership)
* Optional **behavior anomaly signals** derived from conntrack feature summaries
* Optional **threat-intel list** matching (Spamhaus, Tor, EmergingThreats, Custom)

This role handles:

* Installation of tagged releases
* Configuration via exporter flags
* systemd lifecycle management
* Optional log + evidence file handling
* Optional rendering of behavior ports / rules YAML from inline variables

> **Scope note**
> This README documents **Ansible variables → exporter flags** only.
> For internals, metrics, scoring, and detection logic, see the exporter **whitepaper README**.

---

## Features

* Installs tagged OIE releases (`v1.x.x`)
* Binds exporter to an interface IP or explicit listen address
* Predictable background collection loop
* Optional **behavior analytics** (inbound / outbound)
* Optional **threat-intel feeds**, each independently toggleable
* Optional **host public-IP threat matching**
* Optional **file logging** (JSON)
* Inline YAML support for **behavior ports** and **behavior rules**

---

## Requirements

### Target hosts

* Linux with `systemd`
* libvirt (`qemu:///system`)
* kernel `nf_conntrack`
* Privileges to read libvirt + conntrack (typically root)

### Controller

* Ansible **2.12+** recommended

---

## Key Variables (Quick Reference)

### Enable / version / install

```yaml
openstack_instance_exporter_enabled: true
openstack_instance_exporter_version: "v1.0.0"
openstack_instance_exporter_install_dir: "/opt/openstack_instance_exporter"
openstack_instance_exporter_sha256: "https://github.com/webnifico/openstack_instance_exporter/releases/download/{{ openstack_instance_exporter_version }}/sha256sums.txt"
```

---

## Web binding

### Explicit bind address

```yaml
openstack_instance_exporter_web_listen_address: "192.168.10.5:9120"
```

### Bind to interface address

```yaml
openstack_instance_exporter_network_interface: br-monitoring
openstack_instance_exporter_bind_port: 9120
```

Optional:

```yaml
openstack_instance_exporter_web_telemetry_path: "/metrics"
```

---

## Collection

```yaml
openstack_instance_exporter_libvirt_uri: "qemu:///system"
openstack_instance_exporter_collection_interval: "15s"
openstack_instance_exporter_worker_count: 0   # 0 = NumCPU
```

---

## Conntrack reader (performance)

All conntrack reading uses the **raw reader**.

Optional overrides (exporter defaults apply if unset):

```yaml
# openstack_instance_exporter_conntrack_raw_rcvbuf_bytes: 33554432
# openstack_instance_exporter_conntrack_ipv4_enable: true
# openstack_instance_exporter_conntrack_ipv6_enable: true
```

### Suggested SO_RCVBUF sizing

| Approx conntrack size | rcvbuf  |
| --------------------- | ------- |
| < 250k                | 32 MiB  |
| 250k–1M               | 64 MiB  |
| 1M–2M                 | 128 MiB |
| ENOBUFS observed      | 256 MiB |

Kernel cap:

* Controlled by `net.core.rmem_max`
* Must be raised if using large buffers

Monitoring metrics:

* `oie_host_conntrack_raw_ok`
* `oie_host_conntrack_raw_enobufs_total`
* `oie_host_conntrack_raw_parse_errors_total`
* `oie_host_conntrack_stale_seconds`

---

## Severity blending (Attention score)

OIE emits:

* `oie_instance_resource_severity`
* `oie_instance_behavior_severity`
* `oie_instance_threat_list_severity`
* `oie_instance_attention_severity` (combined)

Weights:

```yaml
openstack_instance_exporter_severity_weight_resource: 0.45
openstack_instance_exporter_severity_weight_behavior: 0.45
openstack_instance_exporter_severity_weight_threat_list: 0.10
```

---

## Behavior analytics

Enable summaries (no per-remote / per-port labels):

```yaml
openstack_instance_exporter_outbound_behavior_enable: true
openstack_instance_exporter_inbound_behavior_enable: false
```

Sensitivity (single knob):

```yaml
openstack_instance_exporter_behavior_sensitivity: 1.0
```

Meaning:

* `> 1.0` → more sensitive
* `= 1.0` → baseline
* `< 1.0` → less sensitive

EWMA tuning (optional):

```yaml
openstack_instance_exporter_behavior_ewma_fast_tau: "3m"
openstack_instance_exporter_behavior_ewma_slow_tau: "2h"
```

---

## Behavior ports configuration (inline YAML)

The exporter ships with **built-in port → name mappings** and monitored port sets.
You may **extend or override** them via an inline YAML variable.

### Variables

```yaml
openstack_instance_exporter_behavior_ports_config_path: "/opt/openstack_instance_exporter/behavior-ports.yaml"

openstack_instance_exporter_behavior_ports_config_yaml: |

  inbound:
    - port: 22
      name: ssh
    - port: 3389
      name: rdp
    - port: 5900
      name: vnc
    - port: 6443
      name: kube-api

  outbound:
    - port: 25
      name: smtp
    - port: 465
      name: smtps
    - port: 587
      name: smtp-submission
    - port: 3333
      name: stratum
```

### Semantics

* Built-in ports load **first**
* Inline YAML **extends or overrides**
* Ports listed here are considered **monitored**
* Traffic to ports **not listed** is eligible for **dark-space detection**
* `name` is for readability only
* Restart required

If `*_config_yaml` is unset or empty, **no file is written** and built-ins are used.

---

## Behavior rules configuration (inline YAML)

Optional **table-driven heuristics** that run **after built-in rules**.

### Variables

```yaml
openstack_instance_exporter_behavior_rules_config_path: "/opt/openstack_instance_exporter/behavior-rules.yaml"

openstack_instance_exporter_behavior_rules_config_yaml: |

  port_sets:
    admin:
      - 22
      - 3389
      - 5900
      - 2375
      - 6443

    mail:
      - 25
      - 465
      - 587

    mining:
      - 3333
      - 4444
      - 8333

  rules:
    - id: inbound_admin_exposure
      direction: inbound
      dst_port_set: admin
      kind: inbound_admin
      severity: high
      flows_min: 50
      unique_remotes_min: 10

    - id: outbound_smtp_spam
      direction: outbound
      dst_port_set: mail
      kind: smtp_spam
      severity: high
      flows_min: 200
      unique_remotes_min: 50
      ratios:
        unreplied: 0.80

    - id: outbound_mining_fanout
      direction: outbound
      dst_port_set: mining
      kind: crypto_mining
      severity: medium
      flows_min: 100
      unique_remotes_min: 20
```

### Rule evaluation order (important)

Rules use **first-match-wins** semantics:

1. **Built-in internal rules**
2. **User-provided rules** (this YAML)

Within each group, rules are evaluated **top-to-bottom**.

Once a rule matches:

* No further rules are evaluated
* Severity and kind are taken from the matching rule
* There is **no priority or best-match logic**

External rules are best used to **add detections**, not replace built-ins.

---

## Threat-intel feeds

```yaml
openstack_instance_exporter_spamhaus_enable: true
openstack_instance_exporter_emergingthreats_enable: true
openstack_instance_exporter_tor_exit_enable: false
openstack_instance_exporter_tor_relay_enable: false
openstack_instance_exporter_customlist_enable: false
openstack_instance_exporter_customlist_path: "/opt/openstack_instance_exporter/custom-ips.txt"
openstack_instance_exporter_contacts_direction: "out"   # out | in | any
```

Optional per-list direction override:

```yaml
openstack_instance_exporter_spamhaus_direction: "out"
openstack_instance_exporter_emergingthreats_direction: "out"
openstack_instance_exporter_tor_exit_direction: "out"
openstack_instance_exporter_tor_relay_direction: "out"
openstack_instance_exporter_customlist_direction: "out"
```

---

## Host IP threat detection (optional)

```yaml
openstack_instance_exporter_host_threats_enable: true
openstack_instance_exporter_host_interfaces:
  - "bgp-nic"
openstack_instance_exporter_host_ips_allow_private: false
```

---

## Conntrack accounting (bytes / packets per flow)

Some behavior features require:

```text
net.netfilter.nf_conntrack_acct=1
```

Role support:

```yaml
openstack_instance_exporter_nf_conntrack_acct_enable: true
openstack_instance_exporter_nf_conntrack_acct_value: 1
```

If disabled, the exporter still runs; those features are omitted.

---

## Logging

Main log:

```yaml
openstack_instance_exporter_log_level: "error"   # error | notice | info | debug - recommended info
openstack_instance_exporter_log_file_enable: true
openstack_instance_exporter_log_file_path: "/var/log/openstack_instance_exporter.log"
```

Threat log throttling:

```yaml
openstack_instance_exporter_threat_log_min_interval: "5m"
```

> Threat hits are logged to the **same log stream** as other events.

---

## Profiles

Profiles are **role-side presets**.

```yaml
openstack_instance_exporter_profile: "outbound-standard"
```

Resolution order:

1. Explicit Ansible variable
2. Profile value
3. Exporter default

Profiles do **not** control ports or rules files.

---

## Example playbooks

### Resource-only posture

```yaml
- hosts: openstack_compute
  become: true
  roles:
    - role: openstack_instance_exporter
  vars:
    openstack_instance_exporter_enabled: true
    openstack_instance_exporter_profile: "resource-only"
    openstack_instance_exporter_log_level: "info"
```

### Outbound behavior + custom rules

```yaml
- hosts: openstack_compute
  become: true
  roles:
    - role: openstack_instance_exporter
  vars:
    openstack_instance_exporter_enabled: true
    openstack_instance_exporter_outbound_behavior_enable: true

    openstack_instance_exporter_behavior_ports_config_yaml: |
      outbound:
        - port: 443
          name: https

    openstack_instance_exporter_behavior_rules_config_yaml: |
      port_sets:
        admin: [22, 3389]
      rules:
        - id: inbound_admin_exposure
          direction: inbound
          dst_port_set: admin
          severity: high
```

---

## Troubleshooting

* `journalctl -u openstack_instance_exporter -f`
* Confirm libvirt access: `virsh -c qemu:///system list`
* Confirm conntrack privileges
* For acct features: confirm `nf_conntrack_acct=1`

---

## License

Apache 2.0

## Author

xneelo cloud engineering team
