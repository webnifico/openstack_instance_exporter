# Grafana dashboard examples

[Documentation index](../../DOCUMENTATION.md) · [Project README](../../README.md)

This directory contains **five dashboards** audited for Grafana 12 and the v2.0.0 metric schema:

| File | Scope |
| --- | --- |
| [openstack_instance_exporter_cluster.json](openstack_instance_exporter_cluster.json) | Fleet health, source freshness, resource-axis state, identity, active/recent volume retypes, top instances, and mining evidence |
| [openstack_instance_exporter_hypervisor.json](openstack_instance_exporter_hypervisor.json) | One compute node's host pressure, capacity, and contributing instances |
| [openstack_instance_exporter_project.json](openstack_instance_exporter_project.json) | Project-level allocation, usage, pressure, active/recent volume retypes, and evidence |
| [openstack_instance_exporter_instance.json](openstack_instance_exporter_instance.json) | Instance identity, resource, traffic, threat-list, and mining evidence |
| [openstack_instance_exporter_threats.json](openstack_instance_exporter_threats.json) | Feed health, configured-list contacts, behavior evidence, and long-window trends |

**On this page**

- [Requirements](#requirements)
- [Import](#import)
- [Current operator layout](#current-operator-layout)
- [Reading source state](#reading-source-state)
- [Attached-volume retype tables](#attached-volume-retype-tables)
- [Disk capacity and allocation](#disk-capacity-and-allocation)
- [Units and aggregation](#units-and-aggregation)
- [Current status and incomplete measurements](#current-status-and-incomplete-measurements)
- [Validate local edits](#validate-local-edits)

## Requirements

- Grafana 12 or later.
- A Prometheus data source containing OIE targets with `job="openstack-instance-exporter"`.
- Hostname-based `instance` target labels across OIE and related exporters. The Hypervisor variable extracts the hostname and every panel anchors that regex-safe hostname plus an optional numeric port, so standard `host:9120` OIE and `host:9100` node-exporter targets line up without prefix-matching similarly named hosts. Relabel non-hostname target identities consistently before using the dashboards.
- Node exporter metrics for the physical CPU, memory, load, root-filesystem, network-error, and OOM panels in the hypervisor dashboard. OIE-only panels still work without node exporter.

The JSON uses one selectable Prometheus data source variable named `datasource`. It assumes the exporter job name above; change the JSON or relabel the scrape job consistently if your deployment uses another name.

## Import

1. Export any local dashboard edits you want to keep. Importing the same UID updates the existing dashboard.
2. In Grafana, choose **Dashboards → New → Import** and upload one JSON file.
3. Select the intended Prometheus data source and save.
4. Repeat for all five files to install the full workflow.

The dashboard variables narrow hypervisor, project UUID/name, instance UUID, and Top N views. Multi-value host selections use Grafana's regex-safe interpolation and an anchored optional-port matcher; a blank or `.*` selection intentionally includes all matching values. The displayed ownership labels originate in Libvirt/OpenStack instance metadata and are reliable only when OIE's identity mapping is unambiguous.

## Current operator layout

Five dashboards retain their UIDs and datasource variables. A visible scope/time strip exposes inherited filters and provides Reset scope. Current tables, stats and the state pie evaluate at the selected range end; time-series graphs use the selected range. Top N defaults to **10** and remains selectable as **1, 3, 5, 10, 20, 50, 100 or 0 (All)**. UUID-based instance choices and links preserve identity even when server names repeat. Hypervisor and volume variables use the Prometheus datasource's native escaping, including dotted hosts, IPs and multi-selects.

### Investigation views

Threat List Overview includes score summaries, per-feed active flows, contact counters and contact increases, feed health, provider-IP matches, and the 24-hour, 7-day and 30-day behavior/resource views. The scope strip, navigation, Top N controls and annotation switches remain. Mining evidence remains on the Cluster and Instance dashboards, with destination port, fixed IP, evidence tier, priority and five-minute CPU context; remote destination IP and exact first-seen time are not exported.

### Instance inventory table

On Cluster, the filterable **Instance inventory** table sits directly beneath the state and resource summary in **Cluster CPU/Memory Usage & Instance Stats**. It includes both active domains and retained inactive definitions; use the Libvirt state column filter to narrow the rows. Configured vCPUs/RAM remain separate from measured resource consumption. There is no separate Cluster inventory section.

### Coverage indicators

Mining counts and rows retain observations from usable hosts when another selected target is down. Compact neutral coverage stats identify incomplete observation. Zero means no observed candidate among usable hosts; absent telemetry is unavailable, never a green Clear. Evidence and coverage must be read together. Alert tables query `ALERTS`; an empty result alone does not prove the rules are installed.

### Timeline annotations

Four visible annotation switches are **off by default**: observed volume-retype events, exporter starts/restarts, telemetry interruptions and telemetry recovery observations. They only add/remove timeline markers and shaded regions; they do not turn collection or alerts on/off. Retype/start markers use exported timestamps. Recovery marks the first sampled healthy observation, not an exact recovery timestamp.

Provision or re-import all five JSON files and reload the Prometheus rule configuration alongside the exporter update. Saved URL variable values may retain an old Top N selection; choose 10 or reset the dashboard. No live lab Grafana session or notification delivery was exercised by these source and fixture tests.

### Inventory scope and state

Libvirt inventory now includes active domains and retained inactive definitions. `oie_instance_inventory_info`, `oie_instance_inventory_disk_info`, `oie_instance_inventory_interface_info` and `oie_instance_inventory_address_info` expose observed identity, configured vCPUs/RAM, disk backing, interfaces and metadata fixed addresses. XML metadata uses the existing five-minute cache; state and active/inactive presence come from the current complete Libvirt listing. A power transition invalidates the relevant cached runtime identity. Inactive XML is cached separately and never populates active IP-ownership maps.

Inactive definitions do not contribute CPU/RAM utilization, runtime counters, active vCPUs, active disk/IP counts, conntrack attribution or mining findings. Configured memory is a boot/current-configuration value, not resident usage or Nova quota. A retained disk definition does not report backend physical allocation. Deleted/undefined domains and transient domains that disappear on shutdown are outside this Libvirt inventory. Nova, Cinder and Neutron remain authoritative for their own state.

All standard Libvirt states are named: `nostate`, `running`, `blocked`, `paused`, `shutdown`, `shutoff`, `crashed`, `pmsuspended`. Missing state is `unavailable`; an unexpected future numeric state is `unrecognized(n)` rather than guessed. The state pie uses an instant snapshot, so a former state cannot persist through a last-non-null reducer.

## Reading source state

Prometheus `up` reports scrape reachability. OIE separately reports Libvirt and conntrack health. A source can be unhealthy while its last-good dependent values remain **retained** for diagnosis. Use the cluster source-health and last-success-age panels before treating a workload value as **fresh**.

Resource axes have separate `fresh` and `available` state. An available axis with `fresh=0` is retained. An unavailable axis is omitted from severity output rather than rendered as a healthy zero. Threat feed state is tri-state: `1` enabled and usable, `0` enabled but unusable, and `-1` disabled.

## Attached-volume retype tables

The cluster and project dashboards each contain a full-width **Attached-Volume Retypes Only — Active and Recent** table. This is a compute-local Libvirt view: it covers only Cinder RBD volumes attached to active Libvirt domains on OIE-scraped hosts. Detached or available-volume retypes run in Cinder or the storage backend without a compute-side Libvirt block job and therefore are not visible. OIE does not query Cinder, so Cinder remains authoritative for migration status and lifecycle timestamps.

Root/boot volumes are visible when Libvirt exposes a matching job, but support and outcome still depend on the OpenStack and storage path.

### Read RBD identities

**Source RBD Pool** and **Destination RBD Pool** are parsed from the RBD image identities and are not Cinder volume-type names. **Source RBD Image** and **Destination RBD Image** are the RBD image basenames and retain the `volume-` prefix; strip the prefix before passing either value to `openstack volume show`.

### Observation cadence

For known operations, the completion-paced fast poller inspects mirror XML no more often than every five seconds after the preceding attempt completes. Block-job progress is queried no more often than every fifteen seconds after the preceding query completes and waits thirty seconds after a failed query completes before retrying. Bounded discovery XML inspection continues with normal collections even while no operation is known.

### Current rows and lifecycle states

Raw Prometheus queries return one series per lifecycle metric family; the bundled instant-query table transforms those fields into one row per retained operation. An exact repeated source/destination identity on one instance disk retains only its newest row. The tables distinguish copying, copy-ready/awaiting-pivot, ready-stalled/awaiting-pivot, completed, unsuccessful-or-cancelled, and unknown states, and show whether the latest block-job observation succeeded. Copy-ready is non-terminal: it means Libvirt finished the copy but has not pivoted the live disk, so the Libvirt job remains present and it does not prove Cinder success.

A job becomes ready-stalled after ten minutes in that exporter-observed state. Unknown is emitted only after a successful terminal XML inspection finds the mirror gone but cannot match the final live source to the saved source or destination; a job that merely becomes too old to reconfirm expires without a terminal result.

### Timestamps and retention

The tables also show exporter-observed first, copy-ready, and terminal timestamps, source and destination identity, and Libvirt/QEMU's approximate `cur/end` logical progress. Observation timestamps, recent rows, and result counters are in-memory exporter-process state rather than authoritative Cinder lifecycle data and reset on exporter restart. Terminal rows remain for one hour and are capped at 256 per exporter; idle volumes create no rows.

That expiry ends current exporter emission but does not delete historical samples already retained by Prometheus; because the bundled table uses an instant query, an omitted row clears from the current view after Prometheus processes the subsequent scrape.

### Interpret progress

Progress is not Ceph physical allocation, transferred bytes, or an ETA. Thin-provisioned or sparse regions and regions discarded by guest fstrim/TRIM (when discard propagated to RBD) can be processed with little or no transfer, so a retype can finish sooner than a linear percentage estimate suggests. The two bundled retype warnings cover a ready job stalled awaiting pivot and a persistent block-job observation failure; they are source-health gated and deduplicated.

These per-job intervals are minimum spacing. Shared Libvirt timeout backoff can defer every observation path for at least one minute, and active control/job checks can defer it longer. Dynamic disk statistics are omitted for every disk on a VM with a live disk mirror or saved Libvirt block job. CPU, memory and network statistics can continue when the control/async-job checks permit; missing observations are represented by the existing freshness and availability metrics.

## Disk capacity and allocation

The cluster and project dashboards show **attached disk logical capacity by source type/pool**. Capacity does not depend on the optional allocation-boundary field. The existing paired view is preserved in a collapsed **Disk address-space diagnostics (not storage usage)** row with neutral colors and an explicit warning in the title and offset legend. The existing `disk_type` label is a source type or pool name, not a reliable RBD/backend classification; a file source labeled `local` can still reside on shared storage.

Libvirt's `block.<n>.allocation` field is the offset of the highest written sector; it is not guest-filesystem usage or authoritative Ceph consumption. Both plotted lines use only disks that expose both capacity and allocation, preventing unmatched populations from being compared. For RBD, obtain actual backend allocation from Ceph-native telemetry that understands objects, snapshots/clones, pool durability overhead, compression, and reclamation. OIE omits the allocation series when Libvirt does not provide that field instead of substituting `block.<n>.physical`.

## Units and aggregation

The legacy metric names ending in `_mb` and `_gbytes` use binary scaling. Dashboards therefore render them as MiB and GiB, derived byte-volume rates as GiB/s, and the corresponding network bit rates as Gibit/s. VM scheduler-delay panels prefer Libvirt delay/steal and use wait only when delay is unavailable; those two host-runqueue counters are alternatives and are never added. Every time-series panel explicitly sets Grafana stacking mode to `none` so imports cannot inherit a stacked presentation.

The project conntrack endpoint-load ratios sum observations attributed to fixed-IP endpoints. One east-west flow can be represented at both endpoints, including twice within one project, so these panels are diagnostic endpoint-load ratios rather than unique-flow shares and may exceed 100%.

Behavior, threat-list, attention, and mining panels show observed or internally qualified evidence. They are **not proof** of compromise, malicious intent, or mining. Long-window new-remote panels show the largest observed fixed-IP/address-family burst; they are not distinct-IP counts across the whole window.

## Current status and incomplete measurements

Mining and threat summary stats evaluate the selected range end. `None observed` or a zero count requires usable telemetry; `Unavailable` identifies missing, stale, failed, disabled or incomplete monitoring. A previous positive result is not reused as a current count. Current threat summaries collapse duplicate host series for the same instance before aggregation.

Guest-memory ratios retain their configured allocation denominator. Incomplete aggregates produce gaps instead of treating missing usage as zero. Disk latency remains I/O-weighted and uses the same observed disks and sample counts in both sums; idle or unavailable telemetry produces a gap. CPU composition remains an approximation that includes VM-associated virtualization overhead. Host non-idle CPU includes I/O wait, and host-interface error totals include virtual interfaces.

See [measurement accuracy and validation scope](../../ACCURACY_VALIDATION.md) for the definitions and executable regression cases.

Dashboard Top N ranking uses the PromQL `@` modifier, stable since [Prometheus 2.33](https://github.com/prometheus/prometheus/releases/tag/v2.33.0). The exporter scrape format is separate from this dashboard query requirement. Ubuntu 22.04 ships Prometheus 2.31 with that feature disabled by default; it is not the unconfigured dashboard baseline. CI installs the same checksum-verified `promtool` 2.45.3 on both runner operating systems, independent of their Ansible versions. This is an offline compatibility test tool, not a Prometheus server upgrade.

## Validate local edits

From the repository root, run:

```bash
make docs PROMTOOL=/path/to/promtool
```

The gate parses every dashboard PromQL expression, requires every OIE selector (including dashboard-variable queries) to use `job="openstack-instance-exporter"`, checks every OIE metric and selector label against the final schema, requires explicit display units and non-stacked time-series panels, verifies the dashboard inventory, and audits the accompanying documentation.
