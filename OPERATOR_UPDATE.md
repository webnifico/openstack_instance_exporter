# OIE v2.0.0 operator guide

[Documentation index](DOCUMENTATION.md) · [Project README](README.md)

Use this guide when deploying v2.0.0 or upgrading from the previous published release, v1.2.0. Apply the exporter, dashboard and rendered rule configuration together.

**On this page**

- [Build and deployment](#build-and-deployment)
- [Threat-feed retries](#threat-feed-retries)
- [Active and inactive inventory](#active-and-inactive-inventory)
- [Dashboard navigation and scope](#dashboard-navigation-and-scope)
- [Default alert policy](#default-alert-policy)

## Build and deployment

The bundled linux/amd64 release is built with Go **1.27.1** and updated compatible Go dependencies. Source builds require Go 1.27.1 or newer; compute nodes do not need Go installed. `make vuln` checks known reachable vulnerabilities using a pinned scanner, and the supplied source workflows run it on changes and weekly. The workflow files inside the source ZIP must be installed at a repository root to run in GitHub. The role's binary archive, default checksum and matching source bundle are updated together.

## Threat-feed retries

Enabled Tor exit, Tor relay, Emerging Threats, custom-file and Spamhaus feeds share one refresh scheduler. With a positive refresh interval, a failed initial load or later refresh retries after 30 seconds, then 1, 2, 4 and 5 minutes, capped at 5 minutes; a shorter configured interval remains the upper bound. Each delay starts after the previous attempt completes. Success resets the retry delay and resumes the configured normal interval. Explicit startup-only configurations (`refresh <= 0`) retain their single-attempt behavior. Pending retry waits stop promptly on exporter shutdown. No additional flags or Ansible variables are required.

HTTP failures identify known timeout, DNS, TLS certificate, connection-refusal/reset, unreachable-host and truncated-response causes without printing configured URLs, query tokens or proxy credentials. HTTP status errors retain their numeric status. Unclassified transport failures keep the generic request-failed message. Custom-file failures retain their existing file/parser diagnostics. Failed loads never advance the last-success timestamp or extend snapshot freshness; Spamhaus publishes only after every configured address family succeeds.

## Active and inactive inventory

Libvirt inventory includes active domains and retained inactive definitions. `oie_instance_inventory_info`, `oie_instance_inventory_disk_info`, `oie_instance_inventory_interface_info` and `oie_instance_inventory_address_info` expose observed identity, configured vCPUs/RAM, disk backing, interfaces and metadata fixed addresses. XML metadata uses the existing five-minute cache; state and active/inactive presence come from the current complete Libvirt listing. A power transition invalidates the relevant cached runtime identity. Inactive XML is cached separately and never populates active IP-ownership maps.

Inactive definitions do not contribute CPU/RAM utilization, runtime counters, active vCPUs, active disk/IP counts, conntrack attribution or mining findings. Configured memory is a boot/current-configuration value, not resident usage or Nova quota. A retained disk definition does not report backend physical allocation. Deleted/undefined domains and transient domains that disappear on shutdown are outside this Libvirt inventory. Nova, Cinder and Neutron remain authoritative for their own state.

All standard Libvirt states are named: `nostate`, `running`, `blocked`, `paused`, `shutdown`, `shutoff`, `crashed`, `pmsuspended`. Missing state is `unavailable`; an unexpected future numeric state is `unrecognized(n)` rather than guessed. The state pie uses an instant snapshot, so a former state cannot persist through a last-non-null reducer.

## Dashboard navigation and scope

Five dashboards retain their UIDs and datasource variables. A visible scope/time strip exposes inherited filters and provides Reset scope. Current tables, stats and the state pie evaluate at the selected range end; time-series graphs use the selected range. Top N defaults to **10** and remains selectable as **1, 3, 5, 10, 20, 50, 100 or 0 (All)**. UUID-based instance choices and links preserve identity even when server names repeat. Hypervisor and volume variables use the Prometheus datasource's native escaping, including dotted hosts, IPs and multi-selects.

Threat List Overview includes score summaries, per-feed active flows, contact counters and contact increases, feed health, provider-IP matches, and the 24-hour, 7-day and 30-day behavior/resource views. The scope strip, navigation, Top N controls and annotation switches remain. Mining evidence remains on the Cluster and Instance dashboards, with destination port, fixed IP, evidence tier, priority and five-minute CPU context; remote destination IP and exact first-seen time are not exported.

On Cluster, the filterable **Instance inventory** table sits directly beneath the state and resource summary in **Cluster CPU/Memory Usage & Instance Stats**. It includes both active domains and retained inactive definitions; use the Libvirt state column filter to narrow the rows. Configured vCPUs/RAM remain separate from measured resource consumption. There is no separate Cluster inventory section.

### Read evidence with coverage

Mining counts and rows retain observations from usable hosts when another selected target is down. Compact neutral coverage stats identify incomplete observation. Zero means no observed candidate among usable hosts; absent telemetry is unavailable, never a green Clear. Evidence and coverage must be read together. Alert tables query `ALERTS`; an empty result alone does not prove the rules are installed.

### Timeline annotations

Four visible annotation switches are **off by default**: observed volume-retype events, exporter starts/restarts, telemetry interruptions and telemetry recovery observations. They only add/remove timeline markers and shaded regions; they do not turn collection or alerts on/off. Retype/start markers use exported timestamps. Recovery marks the first sampled healthy observation, not an exact recovery timestamp.

### Apply the monitoring assets

Provision or re-import all five JSON files and reload the Prometheus rule configuration alongside the exporter update. Saved URL variable values may retain an old Top N selection; choose 10 or reset the dashboard. No live lab Grafana session or notification delivery was exercised by these source and fixture tests.

## Default alert policy

The v2.0.0 operator policy contains 82 alert definitions, including two corroborated host-impact criticals. By default it enables 33 alerts: 30 warnings, one informational persistent mining candidate and two criticals. The remaining 49 workload/heuristic diagnostics are `enabled: false`; operators may enable individual definitions after reviewing local workload baselines. Ten shared recording rules gate current source health, five-minute observation windows, running instances and resource freshness. The Ansible alert template emits the recording rules and honors each definition's `enabled` flag.

### Host impact

High utilization, raw traffic volume, Tor membership and a high heuristic score alone are diagnostics. Host CPU critical requires >95% CPU usage excluding idle and I/O wait together with aggregate guest scheduler delay >5% of allocated vCPU time for ten minutes. Host memory critical requires <2% available RAM together with >1 MiB/s aggregate guest swap-in for ten minutes. These indicate coincident host and guest symptoms, not the identity of the responsible workload. Corresponding host warning predicates are disjoint from the critical predicates.

### Workload warning qualification

Read/write/flush latency warnings preserve I/O-weighted service-time/operation ratios, require at least 60 measured operations per five minutes and five minutes of persistence. Drop warnings require >2%, at least 1,000 packet/drop observations and 20 drops per five minutes, sustained for fifteen minutes. Per-feed repeated-contact warnings require outbound matches, current matching flows, a usable feed and five minutes of persistence. Mining warning candidates require current CPU evidence, their existing tier-specific qualification and two additional minutes of persistence; multiple ports on one VM form one incident.

The uncorroborated dedicated-port candidate remains informational after fifteen minutes. Source outages interrupt pending workload alerts. Retype warnings retain their focused observation/ready-stalled semantics.

### Links, routing and local validation

Every alert includes an identity-specific dashboard path with an evaluation-time window. The deployment Prometheus template converts it to `dashboard_url` and `documentation`, using the configured Grafana root URL or the monitoring host address. The default policy was tested against the rendered deployment template. Scoped baseline fixtures provide additional regression coverage alongside the deployed-rule tests. These defaults reduce avoidable noise but require local observation before notification routing is treated as calibrated.
