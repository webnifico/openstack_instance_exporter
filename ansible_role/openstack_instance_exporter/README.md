# OpenStack Instance Exporter Ansible role

[Documentation index](../../DOCUMENTATION.md) · [Project README](../../README.md)

This role installs and manages the **OpenStack Instance Exporter (OIE)** as a **systemd service** on:

* OpenStack **compute nodes**
* Collapsed compute/network nodes with local QEMU/Libvirt, including optional host-IP threat matching

OIE is a **hypervisor-side Prometheus exporter** that provides **host and instance metrics** for:

* Per-VM **resource severity** (CPU / memory / disk / network)
* Host and per-VM **conntrack state** and instance attribution
* Attached-volume RBD **retype lifecycle** observed through local Libvirt block jobs
* Optional **behavior anomaly signals** derived from conntrack feature summaries
* Optional **threat-intel list** matching (Spamhaus, Tor, EmergingThreats, Custom)

This role handles:

* Installation from the pinned GitHub release or a verified local controller archive
* Configuration via exporter flags
* systemd lifecycle management
* Optional file logging (JSON)
* Optional rendering of behavior ports / rules YAML from inline variables

> **Scope note**
> This README documents **Ansible variables → exporter flags** only.
> For internals, metrics, scoring, and detection logic, see the [project README](../../README.md).

**On this page**

- [Deployment sequence](#deployment-sequence)
- [Requirements](#requirements)
- [Installation variables](#installation-variables)
- [Web binding](#web-binding)
- [Collection](#collection)
- [Profiles](#profiles)
- [Example playbooks](#example-playbooks)
- [Troubleshooting](#troubleshooting)

## Features

* Installs a verified OIE release archive
* Binds exporter to an interface IP or explicit listen address
* Predictable background collection loop
* Optional **behavior analytics** (inbound / outbound)
* Optional **threat-intel feeds**, each independently toggleable
* Optional **host public-IP threat matching**
* Optional **file logging** (JSON)
* Inline YAML support for **behavior ports** and **behavior rules**

## Deployment sequence

1. Check the [target and controller requirements](#requirements).
2. Review the [version, URL and checksum](#version-url-and-checksum), or select a [local archive](#install-from-a-local-archive).
3. Set the [web binding](#web-binding), [collection options](#collection) and any optional behavior or threat inputs.
4. Apply an [example playbook](#example-playbooks) with your target inventory and verify the service using [troubleshooting](#troubleshooting).
5. Install the [Prometheus rules](../../examples/prometheus_alerts_example/README.md) and [Grafana dashboards](../../examples/grafana_dashboard_example/README.md).

## Requirements

### Target hosts

* x86_64/amd64 architecture
* Linux with `systemd`
* libvirt (`qemu:///system`)
* kernel `nf_conntrack`
* Root service access to local Libvirt and raw conntrack

### Controller

* ansible-core **2.12+** required
* `ansible.posix` collection (for `ansible.posix.sysctl`)

Install the required collection from the repository root:

```bash
ansible-galaxy collection install -r ansible_role/openstack_instance_exporter/requirements.yml
```

## Installation variables

### Version, URL and checksum

```yaml
openstack_instance_exporter_enabled: true
openstack_instance_exporter_version: "v2.0.0"
openstack_instance_exporter_install_dir: "/opt/openstack_instance_exporter"
openstack_instance_exporter_download_url: "https://github.com/webnifico/openstack_instance_exporter/releases/download/{{ openstack_instance_exporter_version }}/openstack_instance_exporter-{{ openstack_instance_exporter_version }}-linux-{{ openstack_instance_exporter_architecture }}.tar.xz"
openstack_instance_exporter_sha256: "f5275d93087512bf58f6ba590954d5d56aeda089e948b29ac1e171c605d1b2d1"
```

The role defaults to this versioned GitHub URL and pins the SHA-256 of the bundled Linux amd64 archive. The release asset must be published at that URL before a remote installation can download it.

### Install from a local archive

For a local installation, set the controller archive path:

```yaml
openstack_instance_exporter_archive_src: "/path/on/ansible/controller/openstack_instance_exporter-v2.0.0-linux-amd64.tar.xz"
```

A local archive takes precedence over the download URL; no URL override is needed. The default checksum also verifies the bundled local archive. Override the checksum when using a different archive, and update it together with the version or download URL when selecting another release. Both installation paths verify the staged archive before extraction.

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

## Collection

```yaml
openstack_instance_exporter_libvirt_uri: "qemu:///system"
openstack_instance_exporter_collection_interval: "15s"
openstack_instance_exporter_worker_count: 0   # 0 = NumCPU, capped at 64
```

### Optional volume-retype monitoring

Retype monitoring is **disabled by default**. Enable it explicitly:

```yaml
openstack_instance_exporter_volume_retype_enable: true
```

You can also pass `-e openstack_instance_exporter_volume_retype_enable=true` to the playbook. The role then adds `-volume.retype.enable` to the exporter service. No profile enables it automatically. Setting the variable to `false` removes the flag and the existing service handler applies the change.

With monitoring disabled, OIE performs no dedicated retype discovery or progress polling and emits no retype lifecycle or result-counter samples. Normal inventory, CPU, memory, disk and network collection keeps its existing safety checks. Retype tables and alerts have no new operation data from that exporter while disabled; previously stored Prometheus history remains available.

When enabled, OIE observes only RBD retype block jobs for volumes attached to active local Libvirt domains; detached or available-volume retypes are outside this compute-local view. OIE does not query Cinder, so Cinder remains authoritative for migration status and lifecycle timestamps.

Copy-ready XML can prove logical progress of 100% even when block-info has no usable total. The first observed ready timestamp survives pivot/abort finalization; a terminal result still requires the mirror to disappear.

### Libvirt collection safeguards

All OIE Libvirt readers share busy-job checks and timeout backoff. An observed mirror or saved block job excludes block statistics for every disk on that VM, including jobs without a public mirror. CPU, memory and network statistics continue when the control/async-job checks permit; busy or unreadable control state can still defer monitor-dependent measurements. Disk identity remains available, and guarded retype progress is available when monitoring is enabled. Other VMs retain normal collection unless a timeout triggers the shared host-wide Libvirt backoff.

This behavior applies with retype monitoring off or on; no additional flag is required. Missing observations retain the existing freshness/availability semantics. This role updates OIE only. Review the host QEMU build and other Libvirt clients separately; see [Libvirt collection safeguards](../../LIBVIRT_COLLECTION_SAFETY.md).

## Conntrack reader (performance)

All conntrack reading uses the **raw reader**.

Optional overrides (exporter defaults apply if unset):

```yaml
# openstack_instance_exporter_conntrack_raw_rcvbuf_bytes: 33554432
# openstack_instance_exporter_conntrack_raw_rcv_timeout: "15s"
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

## Behavior ports configuration (inline YAML)

The exporter ships with **built-in named monitored port maps**.
You may replace them **per direction** via an inline YAML variable.

### Port-map variables

```yaml
openstack_instance_exporter_behavior_ports_config_path: "/opt/openstack_instance_exporter/behavior-ports.yaml"

openstack_instance_exporter_behavior_ports_config_yaml: |
  behavior:
    ports:
      inbound_monitored:
        22: ssh
        3389: rdp
        5900: vnc
        6443: kube-api
      outbound_monitored:
        25: smtp
        465: smtps
        587: smtp-submission
        3333: stratum
```

### Semantics

* `behavior.ports.inbound_monitored` replaces the built-in inbound monitored map when present
* `behavior.ports.outbound_monitored` replaces the built-in outbound monitored map when present
* If only one direction is provided, the other direction stays on built-ins
* Ports listed here are considered **monitored**
* Traffic to ports **not listed** is eligible for **dark-space detection**
* This map does not replace or extend the separate built-in mining-pool classifier
* Restart required

If `*_config_yaml` is unset or empty and `*_config_path` is defined, the role removes the rendered file and omits the matching exporter flag, so the built-ins remain active.

### Built-in mining detection

When outbound behavior collection is enabled, the exporter evaluates more than 100 built-in mining-pool ports. Coverage includes common Monero/RandomX ports, MoneroOcean difficulty/TLS endpoints, and active pool endpoints for multiple GPU/ASIC/CPU-mined networks.

Only outbound TCP connections to public, non-VM destinations are eligible. High-confidence pool ports require kernel reply evidence and persistence. Shared ports such as `3333`, `4444`, `5555`, `7777`, `8888`, and `9000` require stronger matching-flow, reply, concentration, remote-count, and persistence evidence. Bitcoin P2P `8333`, Monero P2P/RPC `18080`/`18081`, and generic `80`/`443`/`8080`/`9200` are excluded from port-only classification.

Mining persistence is independent of the first-match generic behavior classifier. Once its evidence gate passes, the exporter publishes `oie_instance_mining_suspected`. The `high` tier can emit a direct structured exporter event. The example Prometheus warning requires fresh CPU telemetry for every tier and two further minutes of persistence. The `high_persistent`, `shared` and `shared_persistent` tiers also require their configured CPU-utilization thresholds. A separate informational alert reports an uncorroborated `high_persistent` candidate after 15 minutes. Incomplete conntrack collections preserve the last-good persisted mining-suspicion metric without advancing the mining state.

## Behavior rules configuration (inline YAML)

Optional **table-driven heuristics** that run **after built-in rules**.

### Rule variables

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

  rules:
    - id: inbound_admin_exposure
      direction: inbound
      port_set: admin
      kind: inbound_admin
      flows_min: 50
      unique_remotes_min: 10

    - id: outbound_smtp_spam
      direction: outbound
      port_set: mail
      kind: smtp_spam
      flows_min: 200
      unique_remotes_min: 50
      ratios:
        unreplied: 0.80

    - id: outbound_mining_fanout
      direction: outbound
      port_set: mining
      kind: crypto_mining
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
* Kind is taken from the matching rule; severity is calculated from the matched behavior evidence
* There is **no priority or best-match logic**

External rules are best used to **add detections**, not replace built-ins.

For compatibility with v1.2.0 configurations, the legacy `severity` values `low`, `medium`, `high`, and `critical` are accepted but do not control scoring; severity remains evidence-derived.

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

## Host IP threat detection (optional)

```yaml
openstack_instance_exporter_host_threats_enable: true
openstack_instance_exporter_host_interfaces:
  - "bgp-nic"
openstack_instance_exporter_host_ips_allow_private: false
```

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

## Logging

Main log:

```yaml
openstack_instance_exporter_log_level: "error"   # debug | info | warn | notice | error
openstack_instance_exporter_log_file_enable: true
openstack_instance_exporter_log_file_path: "/var/log/openstack_instance_exporter.log"
```

Threat / behavior notice throttling:

```yaml
openstack_instance_exporter_threat_log_min_interval: "5m"
```

> Threat hits are logged to the **same log stream** as other events.

## Profiles

Profiles are **role-side presets**.

```yaml
openstack_instance_exporter_profile: "outbound-standard"
```

Resolution order:

1. Explicit Ansible variable
2. Profile value
3. Exporter default

This applies to the profile-controlled role knobs such as severity weights, behavior enablement, threat-feed enablement, per-list directions, and behavior sensitivity.

Profiles do **not** control ports or rules files.

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
      behavior:
        ports:
          outbound_monitored:
            443: https

    openstack_instance_exporter_behavior_rules_config_yaml: |
      port_sets:
        admin: [22, 3389]
      rules:
        - id: inbound_admin_exposure
          direction: inbound
          port_set: admin
          kind: inbound_admin
```

## Troubleshooting

* `journalctl -u openstack_instance_exporter -f`
* Confirm libvirt access: `virsh -c qemu:///system list`
* Confirm conntrack privileges
* For acct features: confirm `nf_conntrack_acct=1`

## License

Apache 2.0

## Author

xneelo cloud engineering team
