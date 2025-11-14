# OpenStack Instance Exporter — Ansible Role

Installs and manages **OpenStack Instance Exporter (OIE)** on OpenStack compute nodes (and optionally L3 / ovn-bgp-agent nodes w/ collapsed compute architecture).

OIE collects per-VM stats from **libvirt domain XML + libvirt stats + kernel conntrack**, applies **zero-suppression**, and exports **stable, low-cardinality Prometheus metrics**.

---

## What the exporter collects

Per **instance** (domain):

- CPU utilisation (percent)
- Disk I/O (bytes + requests) per disk + tier thresholds
- Network I/O per vNIC (bytes/packets/errors/drops)
- Conntrack summaries per fixed IP (unique remote peers + total flows)
- Optional outbound fan-out / scanning heuristics (summary only, never per-port or per-remote series)
- Optional threat-intel contact detection (Tor exit/relay, Spamhaus DROP/DROPv6, EmergingThreats, custom IP list)
- Optional host-IP threat matching for nodes that carry public IPs on the host NIC

---

## Design goals

- **Stable cardinality**
  - Only per-instance, per-disk, per-vNIC, per-fixed-IP series.
  - No dynamic labels like remote IP per-series.
  - No per-destination-port series.
- **Zero-suppression**
  - Suppresses idle CPU, disks with never-seen I/O, silent vNICs, and low conntrack noise.
- **Predictable scrape cost**
  - Background collection caches results; `/metrics` only serves cache.
- **Threat feeds optional**
  - Each feed is independently enable/disable and direction-filterable.
- **Outbound behavior without explosions**
  - You still get “many remotes / many ports” detection via counts, without ever producing one series per remote or port.

---

## Requirements

Target host needs:

- `libvirt` / `libvirtd` with access to `qemu:///system`
- kernel conntrack table enabled (typical on compute/L3 nodes)
- systemd
- netlink conntrack support on the host (exporter runs as root)
  - `nf_conntrack_netlink` kernel module enabled

Controller host (Ansible runner) needs:

- standard Ansible + ssh

---

## Role behavior

When `openstack_instance_exporter_enabled: true` the role:

1. Downloads the exporter release matching `openstack_instance_exporter_version`.
2. Verifies against `openstack_instance_exporter_sha256`.
3. Installs into `openstack_instance_exporter_install_dir`.
4. Renders a systemd unit with flags derived from variables.
5. Starts/enables the service.

If disabled, install/service tasks are skipped.

---

## Variable reference

### Core enable / install

- `openstack_instance_exporter_enabled`
  Master switch for the role.

- `openstack_instance_exporter_version`
  GitHub release tag (e.g. `v1.1.0`).

- `openstack_instance_exporter_sha256`
  URL to sha256 sums file for that release.

- `openstack_instance_exporter_install_dir`
  Directory containing the binary and support files.

---

### Web listener binding

Binding logic:

1. If `openstack_instance_exporter_web_listen_address` is non-empty, use it verbatim.
2. Else, if `openstack_instance_exporter_network_interface` is set and has an IPv4 address, bind to that IP.
3. Else bind to `0.0.0.0`.

- `openstack_instance_exporter_network_interface`
  Interface name to bind on (e.g. `br-monitoring`). Only used if no hard listen address is provided.

- `openstack_instance_exporter_web_listen_address`
  Hard override, e.g. `"172.29.232.10:9120"`.

- `openstack_instance_exporter_web_telemetry_path`
  If set, passes `-web.telemetry-path`. Default `/metrics`.

- `openstack_instance_exporter_bind_port`
  Only used by the systemd template when building `-web.listen-address`. Exporter default port 9120.

---

### Collection + cache

- `openstack_instance_exporter_libvirt_uri`
  `-libvirt.uri`. Default `qemu:///system`.

- `openstack_instance_exporter_collection_interval`
  `-collection.interval`. Default `10s`.

- `openstack_instance_exporter_static_cache_expiration`
  `-static.cache.expiration`. Default `1h`.
  Used for threat lists + host threat metrics.

- `openstack_instance_exporter_dynamic_cache_expiration`
  `-dynamic.cache.expiration`. Default `10s`.
  Used for per-instance metrics.

---

### Zero-suppression thresholds

- `openstack_instance_exporter_cpu_min`
  `-cpu.min`. Default `10.0`.

  CPU is exported only when:
  - usage >= cpu.min, OR
  - previous export was >= cpu.min (one trailing sample), OR
  - usage changed from a previous non-zero state.
    Repeated 0% stays suppressed.

- `openstack_instance_exporter_conntrack_min`
  `-conntrack.min`. Default `20`.

  Conntrack-derived per-fixed-IP metrics are emitted only when the fixed IP meets/exceeds this activity floor in the interval, using either:
  - unique remotes >= conntrack.min, OR
  - total flows >= conntrack.min.

  The same gate applies to outbound behavior, so quiet IPs don’t produce outbound series at all.

---

### Disk IOPS thresholds

Tiered thresholds are rendered to CLI strings like:
`default:500,local:200,ceph_pool_standard:1000,ceph_pool_premium:2000`

- `openstack_instance_exporter_default_read_threshold`
  `-default.read.threshold`, default `100`.

- `openstack_instance_exporter_default_write_threshold`
  `-default.write.threshold`, default `100`.

- `openstack_instance_exporter_read_thresholds`
  List used to build `-read.thresholds`. Empty means “use defaults”.

- `openstack_instance_exporter_write_thresholds`
  List used to build `-write.thresholds`.

Example:

```yaml
openstack_instance_exporter_default_read_threshold: 100
openstack_instance_exporter_default_write_threshold: 100
openstack_instance_exporter_read_thresholds:
  - disk_tier: default
    threshold: 100
  - disk_tier: local
    threshold: 400
  - disk_tier: ceph_pool_standard
    threshold: 1500
  - disk_tier: ceph_pool_premium
    threshold: 3000
openstack_instance_exporter_write_thresholds:
  - disk_tier: default
    threshold: 100
  - disk_tier: local
    threshold: 200
  - disk_tier: ceph_pool_standard
    threshold: 1000
  - disk_tier: ceph_pool_premium
    threshold: 2000
````

Tier matching rules:

* `disk.Type == "file"` ⇒ tier = `local`
* Ceph/RBD ⇒ tier comes from `protocol/name` parsed into `<tier>/<uuid>`
* If no tier matches, exporter uses:

  * `read.thresholds["default"]` if present, otherwise `default.read.threshold`
  * same for write

---

### Contacts direction defaults

Controls direction semantics for threat feeds and can be overridden per feed.

* `openstack_instance_exporter_contacts_direction`
  `-contacts.direction`. Default `out`.

Values:

* `out`: only VM-initiated contacts count
* `in`: only inbound contacts count
* `any`: either direction counts

Using `out` is recommended for noise control.

---

### Outbound behavior / abuse heuristics

* `openstack_instance_exporter_outbound_behavior_enable`
  `-outbound.behavior.enable`. Default `false`.

What it does:

* For each fixed IP on the instance, looks at conntrack entries where that IP is the **source** and the remote is **not another fixed IP**.
* Floating IP traffic is still attributed to the VM’s fixed IP (so NAT doesn’t hide outbound behavior).
* Builds interval summaries and exports them only if outbound activity is present.

Conntrack min gate:

* Outbound summaries are only computed/emitted for a fixed IP **after** it passes `conntrack.min` for that interval (unique remotes or total flows >= conntrack.min).
* If an IP stays below `conntrack.min`, you will not see `oie_outbound_*` for it.

Emitted metrics per fixed IP per interval:

* `oie_outbound_unique_remotes`
* `oie_outbound_new_remotes`
* `oie_outbound_flows`
* `oie_outbound_max_flows_single_remote`
* `oie_outbound_unique_dst_ports`
* `oie_outbound_new_dst_ports`
* `oie_outbound_max_flows_single_dst_port`

---

### Threat feeds (per-instance)

Each feed has:

* enable
* url (or path)
* refresh interval
* direction override

Matching rules:

* Conntrack entries are deduplicated by unordered pair `min(src,dst)|max(src,dst)` per interval.
* `*_active` gauges count unique hit pairs this interval.
* `*_contact` counters accumulate interval hits over time.

HTTP behavior:

* Remote feeds fetched with a shared HTTP client with hard **15s timeout**.
* On refresh failure, exporter keeps using the last successfully loaded list.

#### Tor exit nodes

* `openstack_instance_exporter_tor_exit_enable` ⇒ `-tor.exit.enable`
* `openstack_instance_exporter_tor_exit_url` ⇒ `-tor.exit.url`
* `openstack_instance_exporter_tor_exit_refresh` ⇒ `-tor.exit.refresh`
* `openstack_instance_exporter_tor_exit_direction` ⇒ `-tor.exit.direction` (empty inherits contacts.direction)

Metrics:

* `oie_tor_exit_contact`
* `oie_tor_exit_contact_active`

#### Tor relays

* `openstack_instance_exporter_tor_relay_enable` ⇒ `-tor.relay.enable`
* `openstack_instance_exporter_tor_relay_url` ⇒ `-tor.relay.url`
* `openstack_instance_exporter_tor_relay_refresh` ⇒ `-tor.relay.refresh`
* `openstack_instance_exporter_tor_relay_direction` ⇒ `-tor.relay.direction`

Metrics:

* `oie_tor_relay_contact`
* `oie_tor_relay_contact_active`

#### Spamhaus DROP / DROPv6

* `openstack_instance_exporter_spamhaus_enable` ⇒ `-spamhaus.enable`
* `openstack_instance_exporter_spamhaus_url` ⇒ `-spamhaus.url`
* `openstack_instance_exporter_spamhaus_ipv6_url` ⇒ `-spamhaus.ipv6.url`
* `openstack_instance_exporter_spamhaus_refresh` ⇒ `-spamhaus.refresh`
* `openstack_instance_exporter_spamhaus_direction` ⇒ `-spamhaus.direction`

Matching:

* CIDR containment lookup using /16 (v4) and /48 (v6) buckets.

Metrics:

* `oie_spamhaus_contact`
* `oie_spamhaus_contact_active`

#### EmergingThreats compromised IP list

* `openstack_instance_exporter_emergingthreats_enable` ⇒ `-emergingthreats.enable`
* `openstack_instance_exporter_emergingthreats_url` ⇒ `-emergingthreats.url`
* `openstack_instance_exporter_emergingthreats_refresh` ⇒ `-emergingthreats.refresh`
* `openstack_instance_exporter_emergingthreats_direction` ⇒ `-emergingthreats.direction`

Metrics:

* `oie_emergingthreats_contact`
* `oie_emergingthreats_contact_active`

#### Custom IP list

Enable requires both:

* `openstack_instance_exporter_customlist_enable: true`
* `openstack_instance_exporter_customlist_path` non-empty

Variables:

* `openstack_instance_exporter_customlist_enable` ⇒ `-customlist.enable`
* `openstack_instance_exporter_customlist_path` ⇒ `-customlist.path`
* `openstack_instance_exporter_customlist_refresh` ⇒ `-customlist.refresh`
* `openstack_instance_exporter_customlist_direction` ⇒ `-customlist.direction`

Metrics:

* `oie_customlist_contact`
* `oie_customlist_contact_active`

---

### Threat hit log file

Threat hits (and outbound summaries) can be logged to a dedicated file.

* `openstack_instance_exporter_threat_log_file_enable` ⇒ `-threatfile.enable`
* `openstack_instance_exporter_threat_log_file_path` ⇒ `-threatfile.path`

Behavior:

* When enabled, threat events are written to the threat file.
* Threat events may also emit `[THREAT] ...` lines to stdout/journal at notice level.

Format:

```
<rfc3339nano> tag=<LIST> domain=<DOMAIN> uuid=<INSTANCE_UUID> project=<PROJECT_UUID> user=<USER_UUID> src=<SRC_IP> dst=<DST_IP> direction=<in|out|any>
```

---

### Host IP listed detection (for L3 / BGP nodes)

Checks host NIC addresses against enabled threat lists.

* `openstack_instance_exporter_host_threats_enable` ⇒ `-host.threats.enable`
* `openstack_instance_exporter_host_ips_allow_private` ⇒ `-host.ips.allow-private`
* `openstack_instance_exporter_host_interfaces` ⇒ `-host.interfaces`

Rules:

* If enabled and interfaces list empty, exporter scans only `bgp-nic`.
* If list non-empty, scans only those interfaces.
* Private / link-local / loopback skipped unless allow-private true.

Metric:

* `oie_host_threat_listed{list,ip,family}=1`

---

### Logging

Main logging always goes to stdout → systemd journal.

* `openstack_instance_exporter_log_level` ⇒ `-log.level`
  Values: `error`, `notice`, `info`, `debug`.
  Empty means omit flag and use exporter default `error`.

Optional duplicate main log file:

* `openstack_instance_exporter_log_file_enable` ⇒ `-log.file.enable`
* `openstack_instance_exporter_log_file_path` ⇒ `-log.file.path`

Behavior:

* If `log.file.enable=true`, logs go to stdout+journal and to file.
* If `false`, stdout+journal only.

Runtime log level endpoint:

* `GET /debug/log-level` shows current level.
* `POST /debug/log-level?level=debug` sets level live.

---

### Log rotation (optional)

If either main log file or threat log file is enabled, install logrotate rules.

Rules path:

* `/etc/logrotate.d/openstack_instance_exporter`

Role variable:

```yaml
openstack_instance_exporter_logrotate_content: |
  {% if openstack_instance_exporter_log_file_enable|default(false)|bool and (openstack_instance_exporter_log_file_path is defined and openstack_instance_exporter_log_file_path|length > 0) %}
  {{ openstack_instance_exporter_log_file_path }} {
    daily
    rotate 14
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
    create 0640 root root
  }
  {% endif %}
  {% if openstack_instance_exporter_threat_log_file_enable|default(false)|bool and (openstack_instance_exporter_threat_log_file_path is defined and openstack_instance_exporter_threat_log_file_path|length > 0) %}
  {{ openstack_instance_exporter_threat_log_file_path }} {
    daily
    rotate 14
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
    create 0640 root root
  }
  {% endif %}
```

Task:

```yaml
- name: install openstack_instance_exporter logrotate rules
  become: true
  copy:
    dest: /etc/logrotate.d/openstack_instance_exporter
    owner: root
    group: root
    mode: "0644"
    content: "{{ openstack_instance_exporter_logrotate_content }}"
  when:
    - openstack_instance_exporter_enabled|default(false)|bool
    - (openstack_instance_exporter_log_file_enable|default(false)|bool and (openstack_instance_exporter_log_file_path|default('')|length > 0)) or (openstack_instance_exporter_threat_log_file_enable|default(false)|bool and (openstack_instance_exporter_threat_log_file_path|default('')|length > 0))
```

---

## Metrics catalog

### Emission rules

The exporter produces three classes of series:

**Always emitted (workload-independent):**

* Per-instance static metadata:

  * `oie_instance_info`
* Per-disk static metadata:

  * `oie_disk_info`
* Per-disk threshold gauges:

  * `oie_disk_r_alert_threshold`
  * `oie_disk_w_alert_threshold`
* Host / exporter health:

  * `oie_host_active_vms`
  * `oie_host_active_vcpus`
  * `oie_host_active_mem_gbytes`
  * `oie_host_collection_errors_total`
  * `oie_host_collection_duration_seconds`
  * `oie_host_collection_lag_seconds`
  * `oie_host_libvirt_list_duration_seconds`
  * `oie_host_conntrack_read_duration_seconds`
  * `oie_host_conntrack_entries_total`
  * `oie_host_dynamic_cache_series_total`
  * `oie_host_go_heap_alloc_bytes`
  * `oie_conntrack_read_errors_total`
  * `oie_host_conntrack_read_errors_total`
  * `oie_static_cache_entries`
  * `oie_dynamic_cache_entries`
  * `oie_cache_cleanup_duration_seconds`
  * `oie_cache_evictions_total`
* Go / process / build runtime:

  * `go_*`
  * `process_*`
  * `prometheus_build_info`

**Always emitted when a threat feed is enabled (host-level list telemetry):**
These are emitted continuously while the list is enabled, regardless of VM activity:

* Tor exit:

  * `oie_tor_exit_refresh_last_success_timestamp_seconds`
  * `oie_tor_exit_refresh_duration_seconds`
  * `oie_tor_exit_refresh_errors_total`
  * `oie_tor_exit_entries`
* Tor relay:

  * `oie_tor_relay_refresh_last_success_timestamp_seconds`
  * `oie_tor_relay_refresh_duration_seconds`
  * `oie_tor_relay_refresh_errors_total`
  * `oie_tor_relay_entries`
* Spamhaus:

  * `oie_spamhaus_refresh_last_success_timestamp_seconds`
  * `oie_spamhaus_refresh_duration_seconds`
  * `oie_spamhaus_refresh_errors_total`
  * `oie_spamhaus_entries`
* EmergingThreats:

  * `oie_emergingthreats_refresh_last_success_timestamp_seconds`
  * `oie_emergingthreats_refresh_duration_seconds`
  * `oie_emergingthreats_refresh_errors_total`
  * `oie_emergingthreats_entries`
* Custom list:

  * `oie_customlist_refresh_last_success_timestamp_seconds`
  * `oie_customlist_refresh_duration_seconds`
  * `oie_customlist_refresh_errors_total`
  * `oie_customlist_entries`

**Activity-gated (zero-suppressed):**
All counters/behaviors below emit only after activity is seen and are further suppressed by `cpu.min` / `conntrack.min`.

---

### Disk

Always emitted per disk:

* `oie_disk_info`
* `oie_disk_r_alert_threshold`
* `oie_disk_w_alert_threshold`

Emitted only on activity:

* `oie_disk_r_gbytes` (counter)
* `oie_disk_w_gbytes` (counter)
* `oie_disk_r_requests` (counter)
* `oie_disk_w_requests` (counter)

Labels:

* `domain`
* `instance_uuid`
* `user_uuid`
* `project_uuid`
* `disk_uuid`
* `disk_type`
* `disk_path`

---

### CPU

* `oie_cpu_percent` (gauge)

Labels:

* `domain`
* `instance_uuid`
* `user_uuid`
* `project_uuid`

Suppression:

* exported only when `shouldExportCPU()` passes per `cpu.min` rules.

---

### Network

Only emitted per vNIC when any counter non-zero:

* `oie_net_rx_gbytes`
* `oie_net_tx_gbytes`
* `oie_net_rx_pkt_total`
* `oie_net_tx_pkt_total`
* `oie_net_rx_er_total`
* `oie_net_tx_er_total`
* `oie_net_rx_drp_total`
* `oie_net_tx_drp_total`

Labels:

* `domain`
* `interface`
* `instance_uuid`
* `user_uuid`
* `project_uuid`

---

### Conntrack summaries (per fixed IP)

Suppressed unless count >= `conntrack.min`:

* `oie_conntrack_ip_flows_total` (gauge)

Labels:

* `domain`
* `instance_uuid`
* `ip`
* `family`
* `project_uuid`
* `user_uuid`

---

### Outbound behavior (when enabled)

Emitted only when outbound activity exists **and fixed IP passes `conntrack.min`**:

* `oie_outbound_unique_remotes`
* `oie_outbound_new_remotes`
* `oie_outbound_flows`
* `oie_outbound_max_flows_single_remote`
* `oie_outbound_unique_dst_ports`
* `oie_outbound_new_dst_ports`
* `oie_outbound_max_flows_single_dst_port`

Labels:

* same as conntrack per fixed IP.

---

### Threat intel contacts (when enabled)

Activity-gated per instance:

* `oie_tor_exit_contact` / `oie_tor_exit_contact_active`
* `oie_tor_relay_contact` / `oie_tor_relay_contact_active`
* `oie_spamhaus_contact` / `oie_spamhaus_contact_active`
* `oie_emergingthreats_contact` / `oie_emergingthreats_contact_active`
* `oie_customlist_contact` / `oie_customlist_contact_active`

Labels:

* `domain`
* `instance_uuid`
* `project_uuid`
* `user_uuid`
* `direction`

---

### Host threats (when enabled)

Always emitted while listed:

* `oie_host_threat_listed`

Labels:

* `list`
* `ip`
* `family`

---

## Example playbook

Typical compute install with outbound summaries and two threat feeds:

```yaml
- hosts: openstack_compute
  become: true
  roles:
    - role: openstack_instance_exporter
  vars:
    openstack_instance_exporter_enabled: true
    openstack_instance_exporter_outbound_behavior_enable: true
    openstack_instance_exporter_spamhaus_enable: true
    openstack_instance_exporter_emergingthreats_enable: true
    openstack_instance_exporter_log_file_enable: true
    openstack_instance_exporter_log_file_path: /var/log/openstack_instance_exporter.log
    openstack_instance_exporter_threat_log_file_enable: true
    openstack_instance_exporter_threat_log_file_path: /var/log/openstack_instance_exporter.threat.log
```

---

## Troubleshooting

* **No metrics / exporter won’t start**

  * Check libvirt URI works:
    `virsh -c qemu:///system list`
  * Ensure exporter runs as root (needs netlink + libvirt socket)
  * Look at journal:
    `journalctl -u openstack_instance_exporter -f`
  * Or tail log files if enabled.

* **Conntrack metrics missing**

  * Ensure conntrack is enabled on the host
  * Ensure `nf_conntrack_netlink` is available
  * If counts are low, you may be under `conntrack.min` (also suppresses outbound).

* **Threat feeds not matching**

  * Confirm feed enabled and refreshed
  * Direction filters can exclude hits; try `any` to validate
  * Slow/unreachable endpoints keep last good list due to 15s timeout

* **Cardinality concerns**

  * No series per remote IP
  * No series per port
  * Only bounded per-instance series are produced

---

## License

Apache 2.0

---

## Author

xneelo cloud engineering team
