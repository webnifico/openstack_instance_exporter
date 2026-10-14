# OpenStack Instance Exporter Ansible role

Installs OIE v2.0.0 on OpenStack compute hosts and manages its configuration and systemd service. OIE collects per-instance resource measurements, inventory and conntrack ownership, with optional behavior signals, threat-list matching and attached RBD retype monitoring. This role handles deployment; the [exporter README](https://github.com/webnifico/openstack_instance_exporter) covers the metrics and detection logic.

The service runs as root to access Libvirt and conntrack. Prometheus, Grafana, Alertmanager and log shipping are configured separately.

## Requirements

- Controller: ansible-core 2.12+ and the collections in [requirements.yml](requirements.yml).
- Compute: Linux x86_64/amd64, systemd, QEMU/KVM and Libvirt.

Resource collection works without conntrack. Connection-state collection needs access to the kernel's `nf_conntrack` data. Conntrack accounting is optional and recommended for bytes/packets-per-flow evidence.

Tested on Ubuntu 22.04 and Ubuntu 24.04 with OpenStack Dalmatian through Gazpacho.

## Installation

Place this role at `roles/openstack_instance_exporter` beside your playbook. From that playbook directory:

```sh
ansible-galaxy collection install -r roles/openstack_instance_exporter/requirements.yml
```

Save as `deploy-oie.yml`:

```yaml
- hosts: openstack_compute
  become: true
  roles:
    - role: openstack_instance_exporter
  vars:
    openstack_instance_exporter_enabled: true
    openstack_instance_exporter_web_listen_address: "192.0.2.10:9120"
    openstack_instance_exporter_profile: resource-only
```

Add your computes to an `openstack_compute` group in `inventory`. Replace the listen address with the compute's monitoring address; for multiple hosts, set it in each host's variables. Then run:

```sh
ansible-playbook -i inventory deploy-oie.yml
```

An explicit listen address takes precedence. If omitted, the role uses the IPv4 address of `openstack_instance_exporter_network_interface` (default `br-monitoring`) on port `9120`. Protect the listener with network access controls.

The role downloads the published release archive and verifies its pinned SHA-256. Installation defaults to `/opt/openstack_instance_exporter`. Binary, unit and managed configuration changes restart the service.

For a controller-side archive, set `openstack_instance_exporter_archive_src` to its path and `openstack_instance_exporter_sha256` to its 64-character digest. A nonempty archive source takes precedence over `openstack_instance_exporter_download_url`. If you change the version or archive, supply its matching checksum.

## Configuration

The [commented defaults](defaults/main.yml) contain the role options, profiles and custom-file examples. The [service template](templates/openstack_instance_exporter.service.j2) shows their runtime flag mappings.

Explicit variables override profiles. `resource-only` and the default `disabled` profile supply no behavior/feed settings; neither clears explicit overrides or disables the service. `openstack_instance_exporter_enabled` defaults to `false`; set it to `true` to deploy, or `false` to stop and disable an existing installation.

Profiles choose behavior directions, enabled feeds and sensitivity:

| Profile | Behavior | Feeds | Sensitivity |
| --- | --- | --- | --- |
| `disabled`, `resource-only` | No preset | No preset | Exporter default |
| `outbound-standard` | Outbound | Spamhaus, Emerging Threats | `1.0` |
| `outbound-observant` | Outbound | Spamhaus, Emerging Threats, Tor exit and relay | `1.25` |
| `outbound-max` | Outbound | Spamhaus, Emerging Threats, Tor exit and relay | `1.5` |
| `bidir-standard` | Inbound and outbound | Spamhaus, Emerging Threats; both directions | `1.0` |
| `bidir-observant` | Inbound and outbound | All four feeds; both directions | `1.25` |
| `bidir-max` | Inbound and outbound | All four feeds; both directions | `1.5` |

Outbound profiles inherit `openstack_instance_exporter_contacts_direction`, whose exporter default is `out`. Bidirectional profiles set their enabled feeds to `any`. An explicit per-feed direction overrides that preset; an explicit empty string makes that feed inherit the global direction. Custom lists are configured separately. Profiles never enable retype monitoring.

```yaml
openstack_instance_exporter_profile: outbound-standard
openstack_instance_exporter_collection_interval: 15s
# Optional attached RBD volume-retype monitoring:
openstack_instance_exporter_volume_retype_enable: true
# Optional kernel accounting for bytes/packets-per-flow features:
openstack_instance_exporter_nf_conntrack_acct_enable: true
```

Collection supports **5s through 1m**. Retype monitoring observes Libvirt block-copy jobs on attached RBD volumes; it does not initiate or manage Cinder operations.

Enabling conntrack accounting through the role configures `net.netfilter.nf_conntrack_acct` and restarts OIE. OIE detects accounting at startup; existing flows may still lack counters until replaced. Accounting adds bytes/packets-per-flow evidence and is optional for the remaining conntrack features.

To collect resources without conntrack reads, set:

```yaml
openstack_instance_exporter_conntrack_ipv4_enable: false
openstack_instance_exporter_conntrack_ipv6_enable: false
```

The `resource-only` profile alone does not disable conntrack reads. Receive-buffer size and timeout overrides are documented in the defaults; watch conntrack source-health metrics when tuning them.

## Behavior configuration

Enable each direction through a profile or its explicit `*_behavior_enable` variable. `openstack_instance_exporter_behavior_sensitivity` adjusts built-in heuristic thresholds; external-rule thresholds remain as written. The fast and slow EWMA variables apply to behavior flow/remote baselines.

Inline YAML is written to the installation directory by default:

```yaml
openstack_instance_exporter_outbound_behavior_enable: true
openstack_instance_exporter_behavior_ports_config_yaml: |
  behavior:
    ports:
      outbound_monitored:
        25: smtp
        465: smtps
        587: submission
        443: https

openstack_instance_exporter_behavior_rules_config_yaml: |
  port_sets:
    mail: [25, 465, 587]
  rules:
    - id: outbound_mail_fanout
      direction: outbound
      port_set: mail
      signal: outbound_mail_fanout
      flows_min: 200
      unique_remotes_min: 50
      ratios:
        unreplied: 0.8
```

A supplied monitored-port map replaces the built-in map for that direction; an omitted direction keeps its built-ins. These maps affect monitored-port summaries and dark-space detection. They do not replace the separate mining-port catalog.

External rules run when no built-in generic behavior classifier matches. Within the external YAML, the first matching rule wins. Rules require `id`, `signal` and a nonempty port selection; the built-in mining signal is reserved. Mining detection has its own evidence and persistence lifecycle.

To use operator-managed YAML, set `openstack_instance_exporter_behavior_ports_config_path` or `openstack_instance_exporter_behavior_rules_config_path` without inline content. Nonempty inline content writes to the selected path; empty content leaves existing files untouched. With no explicit path and no content, the role omits the flag and OIE uses built-ins. Configured files are loaded at startup: a missing, empty or invalid file stops startup. Restart after editing an operator-managed file.

## Threat-list configuration

Feeds can be enabled independently of profiles. Their `*_direction` variables accept `out`, `in`, `any` or an empty string to inherit `openstack_instance_exporter_contacts_direction`.

For a managed custom list:

```yaml
openstack_instance_exporter_customlist_enable: true
openstack_instance_exporter_customlist_path: /opt/openstack_instance_exporter/custom-ips.txt
openstack_instance_exporter_custom_ip_list:
  - "192.0.2.25"
  - "2001:db8::25"
```

Alternatively, set `openstack_instance_exporter_customlist_src` to a controller-side file. Custom lists contain individual IPv4 or IPv6 addresses, one per line; CIDR ranges are not supported. A nonempty `openstack_instance_exporter_custom_ip_list` takes precedence. You can also provide a path to an operator-managed list.

Host NIC address checks are independent of per-instance remote-contact matching. To check addresses assigned to selected host interfaces:

```yaml
openstack_instance_exporter_host_threats_enable: true
openstack_instance_exporter_host_interfaces:
  - bgp-nic
```

The host check defaults to `bgp-nic` when its interface list is empty and excludes private addresses unless `openstack_instance_exporter_host_ips_allow_private` is enabled.

## Logging and verification

Logs go to the systemd journal by default. For a managed file and log rotation:

```yaml
openstack_instance_exporter_log_file_enable: true
openstack_instance_exporter_log_file_path: /var/log/openstack_instance_exporter.log
```

Rotation defaults to daily, 14 compressed rotations using `copytruncate`; override `openstack_instance_exporter_logrotate_content` to change it. File logging replaces the normal stdout destination; stderr remains in the journal. `openstack_instance_exporter_log_level` defaults to `info` and accepts `debug`, `info`, `warn` or `error` (`notice` is an alias for `warn`). Repeated threat-list/policy notices use `openstack_instance_exporter_threat_log_min_interval`; behavior notices have their own lifecycle.

Check the deployed service and endpoint:

```sh
systemctl status openstack_instance_exporter
journalctl -u openstack_instance_exporter -n 100 --no-pager
curl --fail http://192.0.2.10:9120/metrics
```

Confirm expected instance identity and healthy Libvirt source metrics. Check conntrack health when using connection-state collection.

## Disable or remove

Set `openstack_instance_exporter_enabled: false` and rerun the playbook to stop and disable the service while retaining its installation.

To remove the installation, run the cleanup tag:

```sh
ansible-playbook -i inventory deploy-oie.yml --tags cleanup_oie
```

Cleanup removes the service, installation directory, logrotate configuration, selected log file and currently managed custom configuration. Keep the same installation and configuration variables when invoking cleanup. Operator-managed configuration outside the installation directory is preserved; the installation directory itself is removed in full. Rotated log files are retained.
