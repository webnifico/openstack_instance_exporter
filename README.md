# OpenStack Instance Exporter (OIE)
**Whitepaper README (generated from current code snapshot on 2025-12-20).**

OIE is a hypervisor-side Prometheus exporter for KVM/OpenStack that turns host- and instance-level reality into metrics: **libvirt + kernel conntrack + threat intel + behavioral anomaly scoring**.

It answers the questions OpenStack’s control-plane metrics can’t:

- *What a VM is doing to shared host resources* (CPU, memory, disk, and the kernel’s conntrack budget).
- *What a VM is doing on the network* (fan-out, scanning patterns, anomalous behavior).

It does this **without an agent inside the tenant** and **without packet capture**.

---

## Table of contents

1. [What problem this solves](#what-problem-this-solves)
2. [What gaps it fills](#what-gaps-it-fills)
3. [Why it’s free and what that means](#why-its-free-and-what-that-means)
4. [Executive value table](#executive-value-table)
5. [Architecture](#architecture)
6. [Data sources and why they matter](#data-sources-and-why-they-matter)
7. [Zero agents, zero packet capture](#zero-agents-zero-packet-capture)
8. [Identity model and label strategy](#identity-model-and-label-strategy)
9. [Scoring model](#scoring-model)
10. [Attention score: how the severities combine](#attention-score-how-the-severities-combine)
11. [Noisy neighbors: host pressure to per-instance attribution](#noisy-neighbors-host-pressure-to-per-instance-attribution)
12. [Resource engine (Resource v2)](#resource-engine-resource-v2)
13. [Conntrack engine: shared blast radius](#conntrack-engine-shared-blast-radius)  
    13.1 [OVN, conntrack zones, and dataplane compatibility](#ovn-conntrack-zones-and-dataplane-compatibility)  
    13.2 [Raw conntrack reader](#raw-conntrack-reader)  
    13.3 [Raw conntrack reader health metrics](#raw-conntrack-reader-health-metrics)  
    13.4 [Raw reader socket buffer sizing](#raw-reader-socket-buffer-sizing)
14. [Behavior engine: EWMA anomaly IDS + heuristics](#behavior-engine-ewma-anomaly-ids--heuristics)
15. [Threat intelligence engine](#threat-intelligence-engine)
16. [Logging and evidence](#logging-and-evidence)
17. [Tuning and configuration](#tuning-and-configuration)
18. [nf_conntrack_acct: bytes/packets per flow](#nf_conntrack_acct-bytespackets-per-flow)
19. [Cardinality, scaling, and TSDB safety](#cardinality-scaling-and-tsdb-safety)
20. [Performance and overhead](#performance-and-overhead)
21. [Operational workflows (runbooks)](#operational-workflows-runbooks)
22. [Deployment](#deployment)
23. [Compatibility](#compatibility)
24. [Permissions and security model](#permissions-and-security-model)
25. [Troubleshooting](#troubleshooting)
26. [FAQ (blunt answers)](#faq-blunt-answers)
27. [Appendix A: Metric reference](#appendix-a-metric-reference)
28. [Appendix B: Log schema and examples](#appendix-b-log-schema-and-examples)
29. [Appendix C: Glossary](#appendix-c-glossary)
30. [License](#license)


## Logging

### Unified logging (single file)

All engines (resource, conntrack, behavior, threat) emit **JSON lines** into the same log stream/file.

* There is **no separate threat log file**.
* Threat hits (when threat lists are enabled) are emitted as normal log events into the main log (with the same cadence controls: min-interval / de-dup).
* This makes Loki/Grafana, grep, and incident timelines simpler: one source of truth.

---

## What problem this solves

OpenStack gives you scheduling, quotas, and API-level telemetry.
It does **not** give you hypervisor-grade answers to questions like:

- Which tenant VM is about to blow up the host conntrack table?
- Which VM is quietly scanning the internet across 40k ports?
- Which project is reserving 1 TB of RAM but using 80 GB?
- Why is “the cloud slow” on this host right now (CPU steal vs disk service time vs flow pressure)?

OIE fills that gap with **per-VM attribution** from the compute node’s own truth.

## What gaps it fills

Think of OIE as the missing middle layer between:

- **Control-plane telemetry** (Nova/Neutron/Cinder events, quotas, API counters).
- **Host-only telemetry** (node exporter / process exporter).
- **Packet capture IDS** (Suricata/Zeek), which is powerful but expensive.

OIE’s niche is:

- **Attribution:** turn host and kernel reality into *per-instance* metrics (instance UUID + project/user ownership).
- **Lightweight IDS signals:** anomaly + heuristic detection from conntrack state (not payload).
- **Operational triage:** provide a single “attention” signal that blends resource + behavior + threat-list signals.
- **TSDB safety:** stay low-cardinality (no remote-IP labels) and bounded state.

OIE is for providers and operators who need *actionable answers* without deploying an agent or standing up a capture pipeline.

## Why it’s free and what that means

OIE is Apache-2.0 licensed.
That matters operationally:

- You can deploy it **one-per-compute** across a fleet without per-core licensing pressure.
- You can embed it into your OpenStack deployment tooling (Ansible roles, OSA, Terraform, golden images).
- You can inspect, audit, and tailor the scoring and thresholds to your environment.
- You can keep the output formats stable for dashboards, alerts, and automation.

In short: **it is designed to be a default-on visibility layer**, not an optional premium feature.

## Executive value table

| Domain | Administrative Challenge | Exporter Solution & Key Features | Value to the Company & Administrator |
|---|---|---|---|
| Security & Threat Detection | Detecting low-level network abuses (scanning, botnet behavior, outbound fan-out) originating from tenant VMs that are often invisible to perimeter firewalls. | **Behavioral Engine (EWMA + heuristics):** fast/slow EWMAs per *(VM, fixed IP, direction)* score deviations in flows, unique remotes, unique ports, concentration, unreplied ratio + “should-never-happen” heuristics → **`oie_instance_behavior_severity`**. **Threat Intelligence:** list matching (Spamhaus, Tor Exit/Relay, EmergingThreats, Custom) → **`oie_instance_threat_list_severity`**. | **Proactive threat hunting:** consolidate to a single triage/automation signal via **`oie_instance_attention_severity`** with clear handoff labels (instance UUID + project/user). |
| Operational Stability | Preventing host-wide outages caused by a single VM exhausting shared kernel resources (especially conntrack). | **Conntrack visibility + attribution:** exports host conntrack utilization and attributes per-IP flow pressure to instances (total + inbound/outbound splits). | **Outage prevention:** identifies the one VM becoming shared blast radius before the host starts dropping connections for everyone. |
| Performance & Troubleshooting | Pinpointing the root cause of “the cloud is slow” when multiple VMs share a host (CPU contention vs disk service time vs flow pressure). | **Hypervisor truth:** CPU usage and contention (steal/wait), disk service time and request rates, and network/flow pressure — all per-instance, with ownership labels. | **Reduced MTTR:** correlate user symptoms to host-level causes quickly and defensibly; isolate bad actors without guessing. |
| Resource Waste & FinOps | Identifying over-allocation (reserved vs used) and tying that waste to the owning project/team. | **Allocated vs used:** allocated memory vs guest-used memory plus host RSS realities; vCPU count vs actual usage. **Ownership labels:** every per-instance series carries project/user identifiers. | **Right-sizing & accountability:** quantify waste in hard numbers and drive chargeback/showback or right-sizing policy from metrics. |
| Efficiency & Scalability | Ensuring monitoring does not become workload on the compute node. | **Bounded state + concurrency:** sharded maps, capped histories, TTL cleanup, and worker pools across heavy collection paths. | **Low overhead:** designed to scale linearly within a compute node at practical scrape intervals. |

---

## Architecture

OIE runs on the **compute node** and collects:

- **Libvirt domain inventory + stats** (CPU, memory, disks, NICs, state).
- **Kernel conntrack table** to attribute flow pressure to instances (by fixed IP; and by conntrack zone when available).
- **Threat list matchers** (Spamhaus CIDRs + IP lists like Tor Exit/Relay, EmergingThreats, Custom).
- **Behavior engine** (fast/slow EWMA + heuristics) per *(instance, fixed IP, direction)* for anomaly/abuse detection.

### Dataflow diagram

```text
 ┌────────────────────────────────────────────────────────────────────────┐
 │                           Compute Node                                 │
 │                                                                        │
 │   ┌───────────────┐     ┌───────────────────┐     ┌───────────────┐    │
 │   │ Libvirt/QEMU  │     │ Kernel Conntrack  │     │ Threat Lists  │    │
 │   │ domain stats  │     │ (IPv4 + IPv6)     │     │ (HTTP/File)   │    │
 │   └───────┬───────┘     └─────────┬─────────┘     └───────┬───────┘    │
 │           │                       │                       │            │
 │           v                       v                       v            │
 │   ┌────────────────────────────────────────────────────────────────┐   │
 │   │                     Metrics + Scoring Engine                   │   │
 │   │  - identity mapping (domain + UUID + project/user + fixed IPs) │   │
 │   │  - resource engine (v2)                                        │   │
 │   │  - conntrack attribution (zone-first when available)           │   │
 │   │  - behavior engine (EWMA + heuristics + persistence)           │   │
 │   │  - threat list engine (pressure + contacts)                    │   │
 │   │  - attention aggregation (weights)                             │   │
 │   └────────────────────────────────────────────────────────────────┘   │
 │                               │                                        │
 │                               v                                        │
 │                       /metrics Prometheus                              │
 └────────────────────────────────────────────────────────────────────────┘
```

OIE is intentionally **not** a packet capture IDS.
It is a *hypervisor-truth telemetry and IDS-signal layer*.

## Data sources and why they matter

### Libvirt: the VM’s resource truth

Libvirt tells you:

- Which domains exist and are active.
- CPU time and vCPU allocation.
- Guest memory usage signals (where available).
- Disk service time and request counters.
- NIC byte/packet counters and errors/drops.

This is what lets OIE attribute **host-side resource consumption** to **tenant instances**.

### Conntrack: the VM’s network state truth

Conntrack tells you:

- How many flows exist.
- Direction (VM as source vs VM as destination).
- Reply-seen / assured signals (useful for unreplied ratio).
- Optional bytes/packets per flow if `nf_conntrack_acct=1`.
- (When available) the conntrack **zone**, which is the key to safe attribution in a multi-tenant overlay world.

This is what lets OIE attribute:

- **Host conntrack budget consumption** (shared blast radius).
- **Scanning and fan-out** patterns without packet capture.
- **Overlapping IP** environments safely (zone-first attribution).

### Threat intel: the “known bad” touchpoints

Threat intel lists tell you:

- Whether remote IPs involved in flows are on curated lists.
- How often an instance touches those lists (contacts).
- Whether it is actively touching them right now (active flows pressure).

### EWMA: deviation from self-baseline

Fast/slow EWMA tells you:

- What “normal” looks like for *this exact identity*.
- Whether the current interval is a burst, drift, or stable.

This avoids a classic operator trap:
global static thresholds that page constantly in busy environments and miss quiet-but-weird behavior.

## Zero agents, zero packet capture

OIE’s principle is simple:

- If the compute node already knows the truth, don’t duplicate it inside the tenant.
- If the kernel already tracks state, don’t mirror packets and parse payload unless you truly need DPI.

### What OIE does not do (by design)

- No packet capture.
- No TCP stream reassembly.
- No signature scanning over payload.
- No per-flow time series.
- No remote-IP labels in Prometheus.

### Why this matters (Suricata/Zeek comparison)

Suricata class tooling is powerful, but expensive:

- Packet copy from kernel to userland at scale is heavy.
- DPI engines can consume significant CPU per Gbps.
- Storing pcap/events can be large and sensitive.
- Per-flow event streams can become operationally noisy.

OIE is designed to be:

- **Default-on** across your entire compute fleet.
- **Predictable** in overhead (bounded state + low cardinality).
- **Actionable** for infra operators (conntrack blast radius + ownership labels).

## Identity model and label strategy

OIE uses identity labels because you cannot operate a cloud without ownership.
Metrics without identity create endless “who owns this?” churn.

### Standard label sets (practical)

- **Instance metrics:** `domain, instance_uuid, user_uuid, project_uuid, project_name`
- **Instance conntrack IP metrics:** `domain, instance_uuid, ip, family, project_uuid, project_name, user_uuid`
- **Instance severity metrics:** `domain, instance_uuid, project_uuid, project_name, user_uuid`
- **Threat metrics (direction-aware):** `domain, instance_uuid, project_uuid, project_name, user_uuid, direction`

### Why IDs and names together

- UUIDs are stable keys for automation and incident response.
- Names are human-friendly for dashboards and triage.
- You need both for operators to move quickly without copying/pasting from a separate lookup system.

### Why fixed IP mapping is the right bridge

Conntrack is keyed by IPs and ports.
By attributing flows to fixed IPs owned by a VM:

- You can identify the exact instance causing conntrack pressure.
- You can split inbound vs outbound behavior.
- You can keep cardinality bounded (fixed IP count is bounded by your inventory).

When conntrack **zones** are available, OIE uses **zone-first attribution** to make this safe even when multiple tenant networks reuse the same RFC1918 address space.

### Cardinality rules (non-negotiable)

- Host metrics: single series per host.
- Instance metrics: linear with instance count.
- Conntrack IP metrics: linear with fixed IP count.
- Behavior features: per *(instance, fixed IP, direction)* identity and bounded by caps.
- `*_info` series: metadata fan-out by design; treat as metadata, not alert triggers.

## Scoring model

### Behavior IDS: human-readable evidence (always present)

When a behavior alert is emitted, the log line always includes stable evidence keys so you can answer **what happened** in one glance:

* `top_remote_ip` (string): the dominant remote IP (inbound) or remote destination (outbound). Empty if none.
* `top_dst_port` (int): dominant destination port (inbound: local port, outbound: remote port). 0 if none.
* `top_dst_port_name` (string): friendly name for `top_dst_port` (e.g., `ssh`, `rdp`). Empty if unknown.
* `top_remote_share` (0..1): `max_single_remote / flows_current`.
* `top_port_share` (0..1): `max_single_port / flows_current`.
* `evidence_mode` (string): `dominant_remote | dominant_port | distributed | mixed`.

These keys are **never omitted** (unknown values are empty/0) so dashboards and parsers stay stable.

### Port naming (built-in map + optional override file)
The exporter ships with a **built-in port → name** map for common services (ssh/http/https/rdp/mysql/redis/etc) so alerts and dashboards are readable out of the box.

If you want to **extend/override names** and define additional “known good” ports for **dark-space detection**, provide a YAML file via:

- `-behavior.ports_config=/etc/oie/behavior_ports.yaml`

YAML schema (ports are numeric keys; values are human-readable names):

```yaml
behavior:
  ports:
    inbound_monitored:
      22: ssh
      3389: rdp
      6443: kube-api
    outbound_monitored:
      25: smtp
      465: smtps
      587: smtp-submission
      8333: bitcoin
```

**Notes**

- The built-in map still applies; the YAML file **overrides existing values/extends** it.
- If a port is present with an empty name, it is still treated as “monitored” for dark-space, but has no friendly label.
- This file is read at startup (restart the exporter to apply changes).

### Rule evaluation order and precedence

Behavior rules are evaluated using **first-match-wins semantics**.

Rules are checked **sequentially** and the **first rule whose conditions match is applied**.
Once a rule matches, **no further rules are evaluated** for that event.

Evaluation order is fixed:

1. **Built-in (internal) behavior rules**
2. **User-provided external rules** (from `behavior.rules_config`)

Within each group, rules are evaluated **top-to-bottom** in their defined order.

**Important implications**

- External rules **compete with** internal rules, but **do not override them**.
- If a built-in rule matches, external rules are **never evaluated** for that event.
- YAML rule order **matters** within the external rules file.
- There is **no best-match, priority, or specificity ranking**.
- Severity does **not** influence rule selection; it is only an output attribute.

External rules are therefore best used to **add new detections** or cover gaps not already handled by the built-in heuristics, rather than to replace existing behavior.


### External behavior rules (optional)

Built-in heuristics are intentionally conservative. If you need a small amount of **environment-specific tuning** (without turning OIE into a sprawling rule engine), you can provide an optional YAML file of **table-driven rules**.

- `-behavior.rules_config=/etc/oie/behavior_rules.yaml`

Schema (minimal):

```yaml
port_sets:
  mining: [3333, 4444, 8333]
  admin: [22, 3389, 2375, 6443]

rules:
  - id: outbound_mining_fanout
    direction: outbound
    port_set: mining
    flows_min: 200
    unique_remotes_min: 50
    ratios:
      unreplied: 0.80

  - id: inbound_admin_exposure
    direction: inbound
    port_set: admin
    flows_min: 50
    unique_remotes_min: 10
```

**Notes**

- Rules are evaluated alongside the built-in heuristics (they are additive).
- A restart is required to apply extended rules if changed.
- Parse/validation errors are logged; the last valid rule set remains in effect.
### Priority (P1–P4) derived from severity × confidence

Behavior alerts separate **severity** (impact) from **confidence** (how sure we are), then derive a human-friendly priority:

* **Severity**: volume, unreplied ratio, distinct remotes/ports, host saturation indicators.
* **Confidence**: persistence across scrapes, consistency of the shape (scan vs blast vs brute), and “should-never-happen” signals like dark-space.
* **Priority**: `P1` (urgent) → `P4` (low).

This makes tuning safer: you can adjust weights without rewriting detection logic.

### Persistence gate + cooldown

To reduce false positives and log spam:

* Detections are gated on persistence (e.g., must appear across 2–3 scrapes) before emitting as an alert kind.
* Alerts are cooldowned and/or change-only so repeated identical behavior doesn’t spam logs.


OIE emits four headline severities (normalized 0..1; commonly displayed as 0..100):

- **`oie_instance_resource_severity`** — how hard the VM leans on shared host resources (CPU/memory/disk/net/conntrack).
- **`oie_instance_behavior_severity`** — how strongly the VM’s network behavior deviates from its own baseline (EWMA + heuristics).
- **`oie_instance_threat_list_severity`** — how strongly the VM is touching known-bad infrastructure/lists.
- **`oie_instance_attention_severity`** — combined score intended for triage and automation.

These severities are designed to be:

- Stable enough for alerting (not flapping constantly).
- Explainable enough for operators.
- Tunable with minimal knobs.

## Attention score: how the severities combine

Attention is a weighted blend of:

- Resource severity
- Behavior severity
- Threat-list severity

Weights are tunable:

- `-severity.weight.resource` (default 0.45)
- `-severity.weight.behavior` (default 0.45)
- `-severity.weight.threat_list` (default 0.10)

Operator intent:

- Raise resource weight if you want a pure stability/FinOps orientation.
- Raise behavior weight if you want a stronger IDS orientation.
- Raise threat-list weight if you trust lists and want faster list-driven automation.

A recommended philosophy:

- Keep threat-list weight lower (lists can be noisy).
- Use behavior and resource as the stable “truth” signals.

---

## Noisy neighbors: host pressure to per-instance attribution

“The cloud is slow” almost always begins with a **host-level symptom** and an operator question:

**Which VM is actually causing it?**

OIE is designed to answer that question by exporting **both sides of the equation** in the same scrape window:

- **Host pressure signals** — what the compute node is experiencing.
- **Per-instance contribution signals** — which VM(s) are consuming shared resources in a way that matters.

This turns vague telemetry (“CPU is at 50%”) into actionable attribution (“this one VM is dominating active vCPU time, and other instances are now seeing contention”).

---

### Why host utilization alone is misleading

Host metrics by themselves are blunt instruments:

- CPU at 40–60% can still produce **scheduler contention** for latency-sensitive workloads.
- Disk throughput can appear normal while **service time rises**, causing queueing.
- Network bandwidth can look quiet while **conntrack state explodes**, leading to timeouts for unrelated tenants.

OIE bridges this gap by correlating host pressure with **ownership-labeled per-instance metrics**, allowing operators to move from symptom to cause without guesswork.

---

### Resource severity breakdown: diagnosing the *kind* of contention

OIE does not emit a single opaque “resource score.”
It emits **separate severities per resource axis**, each answering a different diagnostic question:

- **`oie_instance_resource_cpu_severity`**  
  Is this VM causing or experiencing CPU contention?

- **`oie_instance_resource_mem_severity`**  
  Is this VM creating memory pressure that impacts others?

- **`oie_instance_resource_disk_severity`**  
  Is this VM introducing storage latency or queueing?

- **`oie_instance_resource_net_severity`**  
  Is this VM stressing shared network or conntrack resources?

These axis severities are intentionally independent.
A VM can be severe in one dimension and benign in others.

---

### Why per-axis severities matter

A single blended score hides root cause.
Per-axis severities allow immediate classification of the problem:

- High CPU severity, low disk severity → scheduler contention, not storage.
- High disk severity, low CPU severity → I/O bottleneck, not compute exhaustion.
- High network severity with low bandwidth → conntrack or kernel state pressure, not throughput.
- High memory severity without swap → pressure building before failure.

This prevents misdiagnosis and avoids unnecessary or ineffective mitigation.

---

### Practical noisy-neighbor workflows

#### CPU contention (“the host feels slow”)

Start with host pressure:

- **`oie_host_cpu_usage_percent`**
- **`oie_host_cpu_active_vcpus`**

Confirm contention symptoms on instances:

- **`oie_instance_cpu_steal_seconds_total`**
- **`oie_instance_cpu_wait_seconds_total`**

Attribute dominant consumers:

- **`oie_instance_cpu_vcpu_percent`**
- **`oie_instance_cpu_vcpu_count`**
- **`oie_instance_resource_cpu_severity`**

A single VM consuming a disproportionate share of active vCPU time can degrade others even when the host is not saturated.

---

#### Memory pressure (quiet until it isn’t)

Compare allocation vs reality:

- **`oie_instance_mem_allocated_mb`**
- **`oie_instance_mem_used_mb`**
- **`oie_instance_mem_rss_mb`**

Watch for stress signals:

- **`oie_instance_mem_minor_faults_total`**
- **`oie_instance_mem_major_faults_total`**
- **`oie_instance_mem_swap_in_bytes_total`**
- **`oie_instance_mem_swap_out_bytes_total`**

Confirm escalation via:

- **`oie_instance_resource_mem_severity`**

Diagnostic patterns:

- High allocation + low usage → waste / over-reservation
- Rising RSS + rising faults → real host memory pressure
- Any swap activity → shared-host impact is already occurring

---

#### Disk contention (latency and I/O wait)

Look for I/O volume and pain separately:

- **Volume**
  - **`oie_instance_disk_read_requests_total`**
  - **`oie_instance_disk_write_requests_total`**

- **Pain**
  - **`oie_instance_disk_read_seconds_total`**
  - **`oie_instance_disk_write_seconds_total`**

Identify sustained elevation in:

- **`oie_instance_resource_disk_severity`**

A noisy neighbor here is often **latency-dominant**, not throughput-dominant.

---

#### Network and conntrack contention (timeouts, flaky connections)

Start with shared blast-radius pressure:

- **`oie_host_conntrack_entries`**
- **`oie_host_conntrack_max`**
- **`oie_host_conntrack_utilization`**

Attribute flow pressure to instances:

- **`oie_instance_conntrack_ip_flows`**
- **`oie_instance_conntrack_ip_flows_inbound`**
- **`oie_instance_conntrack_ip_flows_outbound`**

Confirm escalation via:

- **`oie_instance_resource_net_severity`**

Explain *why* using behavior features:

- **Scanning / wide fan-out**
  - **`oie_instance_outbound_unique_dst_ports`**
  - **`oie_instance_outbound_new_dst_ports`**
  - **`oie_instance_outbound_unique_remotes`**
  - **`oie_instance_outbound_new_remotes`**

- **Inbound spray / probing**
  - **`oie_instance_inbound_unique_remotes`**
  - **`oie_instance_inbound_new_remotes`**
  - **`oie_instance_inbound_unique_dst_ports`**
  - **`oie_instance_inbound_new_dst_ports`**

- **Concentration on a single target**
  - **`oie_instance_outbound_max_flows_single_remote`**
  - **`oie_instance_outbound_max_flows_single_dst_port`**

Conntrack exhaustion often presents as “random networking issues” long before the host is fully saturated.

---

### From axis severities to overall resource severity

The overall resource severity:

- **`oie_instance_resource_severity`**

is not a simple max.
It reflects:

- Multiple axes elevated simultaneously, or
- Sustained elevation on a single axis over time.

This ensures that:

- Brief spikes are visible but not immediately critical.
- Persistent or multi-axis pressure escalates appropriately.
- Operators retain nuance instead of everything becoming “100”.

---

### What “noisy neighbor” means in OIE terms

In OIE, a noisy neighbor is:

- An instance with elevated **per-axis resource severities**
- On a host exhibiting **measurable pressure**
- Whose consumption is large enough to plausibly impact other tenants

Because all metrics carry instance, project, and user identity, remediation is direct and defensible:

- migrate or isolate the instance
- apply Neutron security-group restrictions
- rate-limit or throttle abusive patterns
- engage the owning project with concrete evidence

OIE’s goal is not to label tenants as “bad.”
It is to make shared-resource impact **visible, attributable, and actionable**.

---

## Resource engine (Resource v2)

Resource v2 answers:

- “Which VM is consuming shared host resources *in a way that matters*?”
- “Which VM is likely impacting other tenants on the same host?”

Resource v2 produces:

- `oie_instance_resource_severity`
- `oie_instance_resource_cpu_severity`
- `oie_instance_resource_mem_severity`
- `oie_instance_resource_disk_severity`
- `oie_instance_resource_net_severity`

### Resource v2 core idea: Pressure × Confidence × Impact

Each axis computes:

- **Pressure (P):** the current push (0..1).
- **Confidence (C):** how trustworthy the pressure sample is (0..1).
- **Impact (I):** how much this VM matters (0..1), scaled by “size” (vCPU count, memory allocation, etc.).

The axis severity is derived from these components and smoothed over time.

### Smoothing: rise vs fall time constants (anti-flap)

Resource v2 uses different time constants for:

- Rising pressure (react quickly).
- Falling pressure (cool down slowly).

This reduces:

- Alert flapping.
- Dashboard noise.
- “Everything is always in crisis” syndrome.

### Persistence: guarding the top of the scale

A common failure mode is:

- Everything “bad” instantly becomes 100.
- Operators lose nuance.

Resource v2 uses persistence and multi-axis checks to allow “very high” only when justified:

- If multiple axes are severe simultaneously, very high is justified.
- If one axis stays severe for multiple cycles, very high becomes justified.
- Otherwise, a single spike is visible but not automatically “100”.

### Axis notes (operator-level meaning)

CPU axis:

- High CPU usage is not automatically “bad” if the host is healthy.
- CPU becomes “bad” when it correlates with contention signals and host pressure.

Memory axis:

- Allocated vs used reveals waste and overcommit risk.
- RSS reveals actual host RAM consumed.
- Swap and faults can indicate memory stress.

Disk axis:

- Service time is the “pain” metric.
- Requests/IOPS explain volume.
- High service time + high requests indicates I/O bottleneck.

Network axis:

- Bytes/packets show volume.
- Drops/errors show pain.
- Conntrack flows show kernel state pressure (blast radius).

### What resource v2 is not

- It is not a micro-benchmark tool.
- It is not a per-device storage profiler.
- It is not a replacement for deep host tuning.

It is a “who is causing pressure?” attribution engine.

## Conntrack engine: shared blast radius

Conntrack is a host-wide table.
One tenant can exhaust it and break networking for everyone.

Host conntrack metrics:

- `oie_host_conntrack_entries`

- `oie_host_conntrack_raw_ok` (gauge): `1` if the raw conntrack reader succeeded on the last run, else `0`
- `oie_host_conntrack_raw_enobufs_total` (counter): total ENOBUFS errors encountered by the raw conntrack reader
- `oie_host_conntrack_raw_parse_errors_total` (counter): total parse errors encountered by the raw conntrack reader
- `oie_host_conntrack_last_success_timestamp_seconds` (gauge): unix timestamp of last successful conntrack read (seconds)
- `oie_host_conntrack_stale_seconds` (gauge): seconds since last successful conntrack read
- `oie_host_conntrack_max`
- `oie_host_conntrack_utilization`

Per-instance flow attribution:

- `oie_instance_conntrack_ip_flows`
- `oie_instance_conntrack_ip_flows_inbound`
- `oie_instance_conntrack_ip_flows_outbound`

### Why conntrack is the right “blast radius” signal

- It reflects kernel state consumption, not just bandwidth.
- Low bandwidth scans can still explode conntrack.
- When conntrack fails, symptoms look like “random timeouts” and “cloud outage”.

### How to operate with conntrack

- Watch host utilization.
- When it rises, pivot to per-instance IP flows.
- Determine whether inbound pressure (attack) or outbound pressure (tenant abuse).
- Mitigate accordingly.

### Mitigation levers (real cloud ops)

- Neutron security groups (block egress, restrict ports, lock down).
- Quarantine network (move VM / detach / isolate).
- Edge ACLs and rate limits (stop abuse fast).
- Increase conntrack max only with careful memory planning.

### OVN, conntrack zones, and dataplane compatibility

OIE’s conntrack attribution is designed around a hard reality: **tenant IP overlap is normal**.

In OVN deployments, overlapping RFC1918 spaces are separated in the dataplane using conntrack zones (and related logical pipeline metadata). When those zones are visible in the conntrack snapshot, OIE uses a **zone-first** attribution path:

- Zone → identify the tenant context
- Then fixed-IP → map to instance identity

**Result:** precise per-instance attribution even when ten different networks all have a `10.0.0.5`.

#### OVN / OVN+OVS

- **Best case for attribution.**
- Conntrack zones exist and are meaningful.
- OIE can disambiguate overlap cleanly.
- “One VM is melting conntrack” becomes immediately attributable even in dense multi-tenant overlays.

#### Linux Bridge / legacy OVS without usable zones

OIE still works and still exports:

- Host conntrack utilization and health metrics.
- Per-instance fixed-IP flow attribution **when IPs are unique on-host**.
- Behavior features and severities off observed flows.

However:

- If the host sees **overlapping tenant IPs** (common in large fleets), and there is **no reliable zone context**, attribution can become ambiguous.
- In ambiguous cases, OIE intentionally prefers *not lying*:
  - it may under-attribute per-instance flows, or
  - it may collapse some attribution when identities cannot be uniquely resolved.

**Bottom line:** Linux Bridge/OVS is supported, but the **zone model is what makes attribution perfect at scale**. This was decided as OVN is typically the default SDN implementation now.

### Raw conntrack reader

OIE uses a purpose-built **raw conntrack reader** that talks to the kernel via Netlink and parses into a compact in-memory representation (minimizing per-flow allocations and string conversions).

Important operational facts:

- **Raw is the only conntrack backend**.
- There is **no fallback** to a different reader.
- If the raw reader fails for a run, conntrack-derived attribution/behavior signals for that run are degraded or absent, and the health metrics below tell you that immediately.

This is controlled by:

- `-conntrack.raw.rcvbuf_bytes=<bytes>` (default: `33554432` / 32 MiB)  
  Sets the socket **SO_RCVBUF** for the raw reader. Too small can cause **ENOBUFS** under heavy tables.
- `-conntrack.ipv4.enable` (default: `true`)
- `-conntrack.ipv6.enable` (default: `true`)

> Note: raw is an implementation choice for performance and determinism. The semantics are “conntrack snapshot → attribution → features” regardless of dataplane.

### Raw conntrack reader health metrics

The raw reader exposes host-level “health” telemetry so you can detect when you’re dropping/losing visibility:

- `oie_host_conntrack_raw_ok` (gauge): `1` if the last raw read succeeded, else `0`
- `oie_host_conntrack_raw_enobufs_total` (counter): ENOBUFS occurrences encountered by the raw reader
- `oie_host_conntrack_raw_parse_errors_total` (counter): parse errors encountered by the raw reader
- `oie_host_conntrack_last_success_timestamp_seconds` (gauge): unix timestamp of the last successful conntrack read
- `oie_host_conntrack_stale_seconds` (gauge): seconds since the last successful conntrack read

These are intentionally **host-level** only (no extra labels) so they remain low-cardinality.

### Raw reader socket buffer sizing

The single biggest tuning knob for the raw reader is **SO_RCVBUF** (`-conntrack.raw.rcvbuf_bytes`). If it’s too small, the kernel can drop Netlink messages under load and you’ll see ENOBUFS.

Pragmatic starting points:

| Conntrack table size (rough) | Suggested `conntrack.raw.rcvbuf_bytes` |
|---:|---:|
| < 250k entries | 33554432 (32 MiB) |
| 250k – 1M entries | 67108864 (64 MiB) |
| 1M – 2M entries | 134217728 (128 MiB) |
| 2M+ entries | 268435456 (256 MiB) |

If you increase SO_RCVBUF, you may also need to raise host limits:

- `net.core.rmem_max`
- `net.core.rmem_default`

OIE does **not** change these sysctls for you; set them in your node baseline if you want larger buffers. Likely will not need to change.


## Behavior engine: EWMA anomaly IDS + heuristics

Behavior engine answers:

- “Is this VM’s network behavior normal for itself?”
- “Is it suddenly scanning, fanning out, or receiving a spray of inbound probes?”
- “Is it doing high-ROI abusive things that are obvious from state alone?” (mail spam patterns, mining ports, public admin exposure, etc.)

### Key properties

- Identity: *(instance UUID, fixed IP, direction)*.
- Inputs: conntrack snapshot-derived features (flows, ports, remotes, unreplied, optional acct bytes/packets).
- Method: fast/slow EWMA + heuristic classification.
- Output: metrics + severity + structured logs with evidence.

### What this is (and what it is not)

**What it is:**

- A hypervisor-side **behavior IDS signal layer**.
- It detects deviations from self-baseline (EWMA) and flags high-confidence abuse patterns.
- It produces explainable alerts with stable evidence keys.

**What it is not:**

- Not DPI.
- Not Suricata rules.
- Not payload inspection.
- Not a signature feed that needs constant tuning.

### New behavior system: EWMA + heuristic “kinds”

The behavior engine emits an alert `kind` (category) when detection gates pass. Kinds are designed to be:

- few and operator-readable (not hundreds of signatures)
- evidence-first (you can explain the alert from the log line)
- conservative (persistence + cooldown to reduce noise)

Examples of kinds (direction-aware):

- **Vertical port scan**: many destination ports, concentrated remotes low, high unreplied.
- **Horizontal scan / fan-out**: many remotes, smaller port spread, high unreplied.
- **Dark-space**: traffic to ports outside the monitored port list (“should never happen” signal).
- **Public admin exposure** (inbound): inbound to high-risk admin ports with meaningful remote breadth.
- **SMTP spam behavior** (outbound): sustained outbound to mail ports with high remote fan-out.
- **Mining/Stratum behavior** (outbound): persistent outbound to common mining ports.
- **DNS tunneling-ish** (outbound): UDP/53 with abnormal bytes-per-flow and low reply ratio (acct required).
- **Control-plane abuse signals**: patterns consistent with BGP/Geneve probing and metadata service abuse (when enabled by the build/config).

(Exact kind names are implementation-defined; the goal is stable semantics rather than a giant ruleset.)


### Why fast+slow EWMA matters

- Fast EWMA detects bursts.
- Slow EWMA models baseline.
- The gap between them expresses “how weird is this right now?”

### Behavior feature metrics (exported)

Inbound:

- `oie_instance_inbound_flows`
- `oie_instance_inbound_unique_remotes`
- `oie_instance_inbound_new_remotes`
- `oie_instance_inbound_unique_dst_ports`
- `oie_instance_inbound_new_dst_ports`
- `oie_instance_inbound_max_flows_single_remote`
- `oie_instance_inbound_max_flows_single_dst_port`
- `oie_instance_inbound_bytes_per_flow` (acct required)
- `oie_instance_inbound_packets_per_flow` (acct required)

Outbound:

- `oie_instance_outbound_flows`
- `oie_instance_outbound_unique_remotes`
- `oie_instance_outbound_new_remotes`
- `oie_instance_outbound_unique_dst_ports`
- `oie_instance_outbound_new_dst_ports`
- `oie_instance_outbound_max_flows_single_remote`
- `oie_instance_outbound_max_flows_single_dst_port`
- `oie_instance_outbound_bytes_per_flow` (acct required)
- `oie_instance_outbound_packets_per_flow` (acct required)

### What these features mean (operator translation)

- Flows: state pressure and activity level.
- Unique remotes: spread/fan-out.
- New remotes: “newness” and discovery rate (scan/botnet spread indicator).
- Unique destination ports: breadth of target surface.
- New destination ports: scan ramp indicator.
- Max flows single remote: concentration on one target (targeted attack vs spread).
- Max flows single port: pressure on one service (hot port).
- Unreplied ratio: scan/UDP spray/one-way traffic proxy.
- Bytes/packets per flow: throughput vs state (leak detection).

### Behavior sensitivity (one knob to move the whole engine)

`-behavior.sensitivity` scales:

- Integer thresholds (flows, unique ports, unique remotes).
- Ratio thresholds (unreplied ratio, new remote ratio, etc.).
- EWMA anomaly bands.

Higher sensitivity:

- Finds more things.
- Finds them sooner.
- Requires less anomaly intensity.

## Threat intelligence engine

Threat intelligence answers:

- “Is this instance interacting with known-bad infrastructure?”
- “Is the interaction ongoing (pressure) or historical (presence)?”

Supported lists:

- Spamhaus DROP/EDROP (CIDR)
- Tor Exit list (IP)
- Tor Relay list (IP)
- EmergingThreats compromised IP list (IP)
- Custom list (IP file)

Threat metrics per list:

- `*_active_flows` (pressure now)
- `*_contacts_total` (presence over time)

### Direction-aware tracking

Threat contacts are direction-aware:

- Outbound: VM contacts known-bad remote.
- Inbound: known-bad remote contacts VM.
- Any: either direction counts.

## Logging and evidence

Metrics drive dashboards and alerts.
Logs provide evidence and incident context.

OIE logs:

- Structured JSON for easy parsing.
- Log level controlled by `-log.level`.
- Optional file logging controlled by `-log.file.enable`.
- Threat hits and behavior alerts are **log events in the same stream** (unified logging).
- Ideally set log level info, this will provide all insight for behavior and resources.

### Threat hit throttling (still exists)

Threat list hits can be bursty during sustained abuse. OIE throttles/de-dups threat-hit events so you get evidence without disk-filling storms.

### Loki compatibility

OIE’s logs are designed to be Loki-friendly out of the box:

- JSON per line.
- Consistent keys (`msg`, `level`, `time`, plus identity keys like `instance_uuid`, `project_uuid`, `user_uuid`, `direction`, etc.).
- High-cardinality stays in log *fields*, not log *labels*.

## Tuning and configuration

OIE is designed so tuning maps to operator intent.

### Core flags (common)

| Flag | Default | What it controls |
|---|---:|---|
| `behavior.sensitivity` | `1.0` | Behavior sensitivity (>1 more sensitive). |
| `behavior.ewma_fast_tau` | `3m` | Behavior EWMA **fast** time constant (baseline reacts quickly). |
| `behavior.ewma_slow_tau` | `2h` | Behavior EWMA **slow** time constant (baseline reflects long-term normal). |
| `behavior.ports_config` | `""` | Optional YAML: extend/override port names + inbound/outbound “monitored ports” sets. |
| `behavior.rules_config` | `""` | Optional YAML: external behavior rules (table-driven heuristics + port sets). |
| `collection.interval` | `15s` | Background collection interval. |
| `contacts.direction` | `"out"` | Default direction for threat/contacts: `out`, `in`, `any`. |
| `host.threats.enable` | `false` | Enable host NIC/provider IP threat list checks if using ovn-bgp-agent.  |
| `host.interfaces` | `"bgp-nic"` | Which NIC IPs are checked used with host.threats.enable. |
| `host.ips.allow-private` | `false` | Include private IPs (provider/host threat checks). Useful for development/labs. |
| `inbound.behavior.enable` | `false` | Enable inbound behavior metrics. |
| `libvirt.uri` | `"qemu:///system"` | Libvirt URI. |
| `log.file.enable` | `false` | Enable file logging. |
| `log.file.path` | `"/var/log/openstack_instance_exporter.log"` | Log file path. |
| `log.level` | `"error"` | Log level. |
| `outbound.behavior.enable` | `false` | Enable outbound behavior metrics. |
| `severity.weight.behavior` | `0.45` | Weight: behavior anomalies. |
| `severity.weight.resource` | `0.45` | Weight: resource pressure. |
| `severity.weight.threat_list` | `0.10` | Weight: threat list matches. |
| `web.listen-address` | `"0.0.0.0:9120"` | Address to listen on. |
| `web.telemetry-path` | `"/metrics"` | Path under which to expose metrics. |
| `worker.count` | `0` | Concurrent workers (0 = NumCPU). |
| `conntrack.raw.rcvbuf_bytes` | `33554432` | SO_RCVBUF bytes for the raw conntrack reader |
| `conntrack.ipv4.enable` | `true` | Enable IPv4 conntrack reads |
| `conntrack.ipv6.enable` | `true` | Enable IPv6 conntrack reads |

### Threat list flags (common)

| Flag | Default | Purpose |
|---|---:|---|
| `spamhaus.enable` | `false` | Enable the Spamhaus DROP list provider. |
| `spamhaus.url` | `"<built-in>"` | Spamhaus IPv4 DROP source URL. |
| `spamhaus.ipv6.url` | `"<built-in>"` | Spamhaus IPv6 DROP source URL. |
| `spamhaus.refresh` | `10m` | Refresh interval for Spamhaus. |
| `spamhaus.direction` | `both` | Apply Spamhaus to `inbound|outbound|both`. |
| `tor.exit.enable` | `false` | Enable the Tor **exit** list provider. |
| `tor.exit.url` | `"<built-in>"` | Tor exit source URL (Onionoo). |
| `tor.exit.refresh` | `10m` | Refresh interval for Tor exit. |
| `tor.exit.direction` | `both` | Apply Tor exit to `inbound|outbound|both`. |
| `tor.relay.enable` | `false` | Enable the Tor **relay** list provider. |
| `tor.relay.url` | `"<built-in>"` | Tor relay source URL (Onionoo). |
| `tor.relay.refresh` | `10m` | Refresh interval for Tor relay. |
| `tor.relay.direction` | `both` | Apply Tor relay to `inbound|outbound|both`. |
| `emergingthreats.enable` | `false` | Enable the Emerging Threats list provider. |
| `emergingthreats.url` | `"<built-in>"` | Emerging Threats source URL. |
| `emergingthreats.refresh` | `10m` | Refresh interval for Emerging Threats. |
| `emergingthreats.direction` | `both` | Apply Emerging Threats to `inbound|outbound|both`. |
| `customlist.enable` | `false` | Enable the local custom list provider. |
| `customlist.path` | `""` | Path to a newline-delimited list of IPs/CIDRs. |
| `customlist.refresh` | `10m` | Reload interval for the custom list file. |
| `customlist.direction` | `both` | Apply custom list to `inbound|outbound|both`. |

### Practical tuning strategy

- Start with outbound behavior enabled and sensitivity 1.0.
- Add inbound behavior if you run public services and want inbound spray visibility.
- Start with Spamhaus first for high confidence.
- Add Tor lists if policy requires it.
- Add EmergingThreats if you accept higher false positive risk.
- Keep threat weight lower until you have tuned noise.

## nf_conntrack_acct: bytes/packets per flow

Some behavior features require conntrack accounting (`nf_conntrack_acct=1`):

- `*_bytes_per_flow`
- `*_packets_per_flow`

If accounting is disabled:

- OIE still exports flows/ports/remotes and scores behavior.
- Bytes/packets features are omitted.
- Accounting-based detections do not activate.

How to enable (common):

- `sysctl -w net.netfilter.nf_conntrack_acct=1` (temporary)
- Add `net.netfilter.nf_conntrack_acct=1` to `/etc/sysctl.conf` or `/etc/sysctl.d/*.conf` (persistent)

Note:
- Accounting adds extra work in kernel per flow.
- Validate overhead on your busiest compute nodes.

## Cardinality, scaling, and TSDB safety

OIE is designed for Prometheus.
That means avoiding cardinality traps.

### Cardinality rules

- Host metrics: O(1) per host.
- Instance metrics: O(N instances).
- Conntrack IP metrics: O(N fixed IPs).
- Behavior features: O(N identities) where identity = (instance, fixed IP, direction).

### Explicitly avoided

- No remote IP labels.
- No per-flow labels.
- No per-connection event streams in Prometheus.

### Where to put high-cardinality evidence

- In your SIEM / log pipeline.
- In ad-hoc tooling when needed.

Prometheus is for metrics; logs are for evidence.

## Performance and overhead

OIE is a lightweight IDS-style signal system because it avoids packet parsing.

### Why it’s lighter than Suricata/pcap IDS

- No packet mirroring.
- No payload scanning.
- No stream reassembly.
- No per-packet processing loop.

### What it does instead

- Reads libvirt stats (bounded by VM count).
- Reads conntrack table (bounded by host conntrack size).
- Computes features and EWMAs (bounded state).
- Exposes metrics (low cardinality).

### Practical overhead expectations

- Overhead scales with: active VMs + fixed IPs + conntrack size.
- Threat list matching cost scales with: flows seen + enabled lists.
- Behavior engine cost scales with: identities tracked (bounded by caps and TTL).

### Operational knobs for overhead

- Increase `collection.interval`.
- Disable inbound behavior if not needed.
- Limit enabled threat lists.
- Tune `worker.count` for your host CPU capacity.

## Operational workflows (runbooks)

### Conntrack saturation before it becomes an outage

- Watch `oie_host_conntrack_utilization` per compute node.
- When it climbs, pivot to top per-instance fixed-IP flow pressure:
  - `oie_instance_conntrack_ip_flows`
  - inbound/outbound splits.
- Correlate with behavior features:
  - `*_unique_dst_ports` spikes → scanning / wide fan-out.
  - `*_unique_remotes` spikes → spread / botnet-ish behavior.
  - `*_max_flows_single_dst_port` spikes → pressure on a specific service port.
- Remediate at the cloud edge:
  - isolate, rate-limit, quarantine via Neutron policy/security groups.

### “The cloud is slow on this host”

- Check host pressure: `oie_host_cpu_usage_percent` and host memory metrics.
- Find contention:
  - high `oie_instance_cpu_steal_seconds_total` → scheduler contention.
  - high `oie_instance_cpu_wait_seconds_total` → I/O wait.
- Confirm I/O pressure:
  - rising disk service time + rising requests.
- Confirm network pressure:
  - rising packets + elevated `oie_instance_conntrack_ip_flows`.

### Threat intel hits you can automate

- Enable lists you trust (Spamhaus first).
- Use active-flow pressure and contact presence:
  - active flows = now
  - contact rate = repeated touches
- Drive automation off severities with instance UUID as handoff key.

### FinOps right-sizing (“reserved vs used”)

- Use allocated vs used memory to identify chronic over-reservation.
- Aggregate by project/user labels to generate showback/chargeback.

## Deployment

### Enable behavior + threat lists (example)

```bash
./openstack_instance_exporter   -collection.interval=15s   -outbound.behavior.enable=true   -inbound.behavior.enable=true   -behavior.sensitivity=2.0   -spamhaus.enable=true   -tor.exit.enable=true   -tor.relay.enable=true   -emergingthreats.enable=true
```

### Notes

- Intended deployment: **one exporter per compute node**.
- The repo includes an Ansible role for installation/configuration and systemd management — see the Ansible README in the repo for role variables and examples.
- Prometheus example alert rules and Grafana dashboards live in the repo also (kept out of this whitepaper README).

## Compatibility

Designed with:

- **OS:** Ubuntu 22.04 / 24.04
- **Hypervisor:** Libvirt 8.x–10.x, QEMU/KVM
- **Cloud:** OpenStack (OVN/OVS networking; **also works on Linux Bridge and OVS** — see conntrack zone notes)
- **Monitoring:** Prometheus 2.x/3.x, Grafana 12+

Dataplane notes:

- OVN gives the best attribution story because conntrack zones exist and allow safe disambiguation of overlapping tenant IPs.
- Linux Bridge/OVS is supported; without reliable zone context, overlapping IP environments can reduce uniqueness of per-instance attribution.

Intended deployment: one exporter per compute node.

## Permissions and security model

You need:

- Libvirt read access (qemu system socket).
- Conntrack read capability (often requires elevated privileges).
- Optional outbound HTTPS for threat list fetching.
- Ability to bind on the listen address/port.

Security model:

- OIE runs outside tenants.
- OIE does not capture payload; it avoids sensitive content storage by design.
- OIE produces triage signals; treat high scores as “investigate and mitigate”, not proof of compromise.
- OIE lets you keep telemetry and evidence in-house instead of relying on a paid service with opaque detection logic, forced data egress, or vendor lock-in.
- OIE is open source, so you can audit, modify, and self-host the full pipeline end-to-end.


## Troubleshooting

### No conntrack metrics?

- Check `oie_host_conntrack_read_errors_total`.
- Check exporter logs for conntrack read failures.
- Ensure required privileges are present.
- Check raw reader health: `oie_host_conntrack_raw_ok` and `oie_host_conntrack_stale_seconds`.

### Some instances missing fixed-IP attribution?

- OIE attributes by fixed IP (and zone when available).
- Instances without discoverable fixed IPs won’t get conntrack attribution.
- Check `oie_host_active_fixed_ips` and `oie_instance_info`.

### Some per-instance conntrack attribution looks “too low” on Linux Bridge / OVS?

- If you have overlapping tenant IPs and no usable zone context, OIE may not be able to uniquely map every flow to a single instance identity.
- Host conntrack utilization remains correct; per-instance splits can be degraded by ambiguity.

### High label cardinality concerns?

- Treat `oie_instance_info` as metadata; do not alert on `*_info`.
- Use `max by (...)` in dashboards/alerts when collapsing fan-out labels (if you add rules in your repo).

### Threat lists failing to refresh?

- Watch refresh error counters and last-success timestamps.
- Confirm HTTPS egress and DNS.
- Confirm customlist path permissions if using `customlist.path`.

## FAQ (blunt answers)

- **Is this a replacement for Suricata/Zeek?** No. It is not DPI. It is a hypervisor-truth IDS-signal layer.
- **Will this explode Prometheus cardinality?** Not if you keep defaults. It avoids remote-IP labels and bounds state.
- **Can tenants hide from it?** They can hide payload, but they cannot hide host resource use or conntrack state.
- **What’s the biggest stability win?** Conntrack attribution: finding the single VM creating the blast radius.
- **Does it work with OVN/OVS and Linux Bridge?** Yes. OVN is best. Linux Bridge/OVS works but zone-less overlap can reduce uniqueness of per-instance attribution.

## Appendix A: Metric reference

This appendix is intentionally verbose for dashboard authors.

### Host metrics

- **oie_host_active_disks**
  - Type: Gauge
  - Description: Count of disks across active domains on this hypervisor.
  - labels: none
  - unit: count

- **oie_host_active_fixed_ips**
  - Type: Gauge
  - Description: Count of fixed IPs across active domains on this hypervisor.
  - labels: none
  - unit: count

- **oie_host_active_projects**
  - Type: Gauge
  - Description: Unique projects seen in active domains on this hypervisor.
  - labels: none
  - unit: count

- **oie_host_cache_cleanup_duration_seconds**
  - Type: Gauge
  - Description: Duration of the last cache cleanup cycle on this host.
  - labels: none
  - unit: seconds

- **oie_host_collection_cycle_duration_seconds**
  - Type: Gauge
  - Description: Duration of the last background collection cycle on this host.
  - labels: none
  - unit: seconds

- **oie_host_collection_cycle_lag_seconds**
  - Type: Gauge
  - Description: Seconds since the prior background collection cycle ended on this host.
  - labels: none
  - unit: seconds

- **oie_host_collection_errors_total**
  - Type: Counter
  - Description: Total background collection errors on this host.
  - labels: none
  - unit: errors

- **oie_host_conntrack_entries**
  - Type: Gauge
  - Description: Conntrack entries observed in the last snapshot.
  - labels: none
  - unit: entries

- **oie_host_conntrack_max**
  - Type: Gauge
  - Description: Configured maximum conntrack entries.
  - labels: none
  - unit: entries

- **oie_host_conntrack_read_duration_seconds**
  - Type: Gauge
  - Description: Seconds spent reading conntrack tables.
  - labels: none
  - unit: seconds

- **oie_host_conntrack_read_errors_total**
  - Type: Counter
  - Description: Conntrack read errors.
  - labels: none
  - unit: errors

- **oie_host_conntrack_raw_ok**
  - Type: Gauge
  - Description: 1 if the raw conntrack reader succeeded on the last run, else 0.
  - labels: none
  - unit: boolean (0/1)

- **oie_host_conntrack_raw_enobufs_total**
  - Type: Counter
  - Description: Total ENOBUFS errors encountered by the raw conntrack reader.
  - labels: none
  - unit: errors

- **oie_host_conntrack_raw_parse_errors_total**
  - Type: Counter
  - Description: Total parse errors encountered by the raw conntrack reader.
  - labels: none
  - unit: errors

- **oie_host_conntrack_last_success_timestamp_seconds**
  - Type: Gauge
  - Description: Unix timestamp of last successful conntrack read (seconds).
  - labels: none
  - unit: seconds

- **oie_host_conntrack_stale_seconds**
  - Type: Gauge
  - Description: Seconds since last successful conntrack read.
  - labels: none
  - unit: seconds

- **oie_host_conntrack_utilization**
  - Type: Gauge
  - Description: Conntrack table utilization (entries/max).
  - labels: none
  - unit: ratio

- **oie_host_cpu_active_vcpus**
  - Type: Gauge
  - Description: Sum of vCPUs allocated to active domains.
  - labels: none
  - unit: vCPUs

- **oie_host_cpu_threads**
  - Type: Gauge
  - Description: Logical CPU thread count.
  - labels: none
  - unit: threads

- **oie_host_cpu_usage_percent**
  - Type: Gauge
  - Description: Live host CPU usage percentage (0–100).
  - labels: none
  - unit: percent

- **oie_host_go_heap_alloc_bytes**
  - Type: Gauge
  - Description: Go heap allocation of the exporter process.
  - labels: none
  - unit: bytes

- **oie_host_libvirt_active_vms**
  - Type: Gauge
  - Description: Active libvirt domains on this hypervisor.
  - labels: none
  - unit: VMs

- **oie_host_libvirt_list_duration_seconds**
  - Type: Gauge
  - Description: Seconds spent listing active libvirt domains.
  - labels: none
  - unit: seconds

- **oie_host_mem_mb_total**
  - Type: Gauge
  - Description: Total physical memory on this hypervisor.
  - labels: none
  - unit: MB

- **oie_host_mem_available_mb**
  - Type: Gauge
  - Description: Host memory available to the OS (MemAvailable).
  - labels: none
  - unit: MB

- **oie_host_mem_free_mb**
  - Type: Gauge
  - Description: Host free memory (MemFree).
  - labels: none
  - unit: MB

### Host threat list health

- **oie_host_threat_customlist_entries**
  - Type: Gauge
  - Description: Number of Customlist IPs currently loaded.
  - labels: none
  - unit: entries

- **oie_host_threat_customlist_refresh_duration_seconds**
  - Type: Gauge
  - Description: Duration of last Customlist refresh.
  - labels: none
  - unit: seconds

- **oie_host_threat_customlist_refresh_errors_total**
  - Type: Counter
  - Description: Total Customlist refresh errors.
  - labels: none
  - unit: errors

- **oie_host_threat_customlist_refresh_last_success_timestamp_seconds**
  - Type: Gauge
  - Description: Unix timestamp of last successful Customlist refresh.
  - labels: none
  - unit: unix_ts

- **oie_host_threat_emergingthreats_entries**
  - Type: Gauge
  - Description: Number of EmergingThreats IPs currently loaded.
  - labels: none
  - unit: entries

- **oie_host_threat_emergingthreats_refresh_duration_seconds**
  - Type: Gauge
  - Description: Duration of last EmergingThreats refresh.
  - labels: none
  - unit: seconds

- **oie_host_threat_emergingthreats_refresh_errors_total**
  - Type: Counter
  - Description: Total EmergingThreats refresh errors.
  - labels: none
  - unit: errors

- **oie_host_threat_emergingthreats_refresh_last_success_timestamp_seconds**
  - Type: Gauge
  - Description: Unix timestamp of last successful EmergingThreats refresh.
  - labels: none
  - unit: unix_ts

- **oie_host_threat_provider_ip_listed**
  - Type: Gauge
  - Description: Provider-owned host IP is present in a threat list (1=member).
  - labels: list, ip, family
  - unit: boolean

- **oie_host_threat_spamhaus_entries**
  - Type: Gauge
  - Description: Number of Spamhaus CIDRs currently loaded.
  - labels: none
  - unit: entries

- **oie_host_threat_spamhaus_refresh_duration_seconds**
  - Type: Gauge
  - Description: Duration of last Spamhaus refresh.
  - labels: none
  - unit: seconds

- **oie_host_threat_spamhaus_refresh_errors_total**
  - Type: Counter
  - Description: Total Spamhaus refresh errors.
  - labels: none
  - unit: errors

- **oie_host_threat_spamhaus_refresh_last_success_timestamp_seconds**
  - Type: Gauge
  - Description: Unix timestamp of last successful Spamhaus refresh.
  - labels: none
  - unit: unix_ts

- **oie_host_threat_tor_exit_entries**
  - Type: Gauge
  - Description: Number of Tor Exit IPs currently loaded.
  - labels: none
  - unit: entries

- **oie_host_threat_tor_exit_refresh_duration_seconds**
  - Type: Gauge
  - Description: Duration of last Tor Exit refresh.
  - labels: none
  - unit: seconds

- **oie_host_threat_tor_exit_refresh_errors_total**
  - Type: Counter
  - Description: Total Tor Exit refresh errors.
  - labels: none
  - unit: errors

- **oie_host_threat_tor_exit_refresh_last_success_timestamp_seconds**
  - Type: Gauge
  - Description: Unix timestamp of last successful Tor Exit refresh.
  - labels: none
  - unit: unix_ts

- **oie_host_threat_tor_relay_entries**
  - Type: Gauge
  - Description: Number of Tor Relay IPs currently loaded.
  - labels: none
  - unit: entries

- **oie_host_threat_tor_relay_refresh_duration_seconds**
  - Type: Gauge
  - Description: Duration of last Tor Relay refresh.
  - labels: none
  - unit: seconds

- **oie_host_threat_tor_relay_refresh_errors_total**
  - Type: Counter
  - Description: Total Tor Relay refresh errors.
  - labels: none
  - unit: errors

- **oie_host_threat_tor_relay_refresh_last_success_timestamp_seconds**
  - Type: Gauge
  - Description: Unix timestamp of last successful Tor Relay refresh.
  - labels: none
  - unit: unix_ts

### Instance metadata & core

- **oie_instance_info**
  - Type: Gauge
  - Description: Static instance metadata (treat as metadata).
  - labels: domain, instance_uuid, user_uuid, project_uuid, project_name
  - unit: 1

- **oie_instance_state_code**
  - Type: Gauge
  - Description: Current libvirt state code (description via label).
  - labels: domain, instance_uuid, project_uuid, user_uuid
  - unit: code

- **oie_instance_cpu_vcpu_count**
  - Type: Gauge
  - Description: Allocated vCPU count.
  - labels: domain, instance_uuid, project_uuid, user_uuid
  - unit: vCPUs

- **oie_instance_cpu_vcpu_percent**
  - Type: Gauge
  - Description: CPU usage percent per vCPU.
  - labels: domain, instance_uuid, project_uuid, user_uuid
  - unit: percent

- **oie_instance_cpu_steal_seconds_total**
  - Type: Counter
  - Description: Total steal time.
  - labels: domain, instance_uuid, project_uuid, user_uuid
  - unit: seconds

- **oie_instance_cpu_wait_seconds_total**
  - Type: Counter
  - Description: Total CPU wait time.
  - labels: domain, instance_uuid, project_uuid, user_uuid
  - unit: seconds

- **oie_instance_mem_allocated_mb**
  - Type: Gauge
  - Description: Allocated memory (MB).
  - labels: domain, instance_uuid, project_uuid, user_uuid
  - unit: MB

- **oie_instance_mem_used_mb**
  - Type: Gauge
  - Description: Guest-view used memory (MB).
  - labels: domain, instance_uuid, project_uuid, user_uuid
  - unit: MB

- **oie_instance_mem_rss_mb**
  - Type: Gauge
  - Description: Host RSS attributed to instance (MB).
  - labels: domain, instance_uuid, project_uuid, user_uuid
  - unit: MB

- **oie_instance_mem_major_faults_total**
  - Type: Counter
  - Description: Total major page faults attributed to this instance.
  - labels: domain, instance_uuid, project_uuid, user_uuid
  - unit: count

- **oie_instance_mem_minor_faults_total**
  - Type: Counter
  - Description: Total minor page faults attributed to this instance.
  - labels: domain, instance_uuid, project_uuid, user_uuid
  - unit: count

- **oie_instance_mem_swap_in_bytes_total**
  - Type: Counter
  - Description: Total bytes swapped in for this instance.
  - labels: domain, instance_uuid, project_uuid, user_uuid
  - unit: count

- **oie_instance_mem_swap_out_bytes_total**
  - Type: Counter
  - Description: Total bytes swapped out for this instance.
  - labels: domain, instance_uuid, project_uuid, user_uuid
  - unit: count

- **oie_instance_hugetlb_pgalloc_total**
  - Type: Counter
  - Description: Total hugetlb page allocations attributed to this instance.
  - labels: domain, instance_uuid, project_uuid, user_uuid
  - unit: count

- **oie_instance_hugetlb_pgfail_total**
  - Type: Counter
  - Description: Total hugetlb page allocation failures attributed to this instance.
  - labels: domain, instance_uuid, project_uuid, user_uuid
  - unit: count

- **oie_instance_net_rx_gbytes_total**
  - Type: Counter
  - Description: Total received data attributed to this instance (GB).
  - labels: domain, instance_uuid, project_uuid, user_uuid
  - unit: GB

- **oie_instance_net_tx_gbytes_total**
  - Type: Counter
  - Description: Total transmitted data attributed to this instance (GB).
  - labels: domain, instance_uuid, project_uuid, user_uuid
  - unit: GB

- **oie_instance_net_rx_packets_total**
  - Type: Counter
  - Description: Total received packets attributed to this instance.
  - labels: domain, instance_uuid, project_uuid, user_uuid
  - unit: packets

- **oie_instance_net_tx_packets_total**
  - Type: Counter
  - Description: Total transmitted packets attributed to this instance.
  - labels: domain, instance_uuid, project_uuid, user_uuid
  - unit: packets

- **oie_instance_net_rx_errors_total**
  - Type: Counter
  - Description: Total receive errors attributed to this instance.
  - labels: domain, instance_uuid, project_uuid, user_uuid
  - unit: errors

- **oie_instance_net_tx_errors_total**
  - Type: Counter
  - Description: Total transmit errors attributed to this instance.
  - labels: domain, instance_uuid, project_uuid, user_uuid
  - unit: errors

- **oie_instance_net_rx_dropped_total**
  - Type: Counter
  - Description: Total received packets dropped attributed to this instance.
  - labels: domain, instance_uuid, project_uuid, user_uuid
  - unit: packets

- **oie_instance_net_tx_dropped_total**
  - Type: Counter
  - Description: Total transmitted packets dropped attributed to this instance.
  - labels: domain, instance_uuid, project_uuid, user_uuid
  - unit: packets

- **oie_instance_disk_info**
  - Type: Gauge
  - Description: Static disk metadata for an instance disk (treat as metadata).
  - labels: domain, instance_uuid, user_uuid, project_uuid, project_name, volume_uuid, disk_type, disk_path
  - unit: count

- **oie_instance_disk_capacity_bytes**
  - Type: Gauge
  - Description: Virtual disk capacity (bytes).
  - labels: domain, instance_uuid, user_uuid, project_uuid, project_name, volume_uuid, disk_type, disk_path
  - unit: bytes

- **oie_instance_disk_allocation_bytes**
  - Type: Gauge
  - Description: Allocated disk space on the host backing store (bytes).
  - labels: domain, instance_uuid, user_uuid, project_uuid, project_name, volume_uuid, disk_type, disk_path
  - unit: bytes

- **oie_instance_disk_read_requests_total**
  - Type: Counter
  - Description: Total disk read requests serviced.
  - labels: domain, instance_uuid, user_uuid, project_uuid, project_name, volume_uuid, disk_type, disk_path
  - unit: requests

- **oie_instance_disk_write_requests_total**
  - Type: Counter
  - Description: Total disk write requests serviced.
  - labels: domain, instance_uuid, user_uuid, project_uuid, project_name, volume_uuid, disk_type, disk_path
  - unit: requests

- **oie_instance_disk_read_seconds_total**
  - Type: Counter
  - Description: Total time spent servicing disk reads (seconds).
  - labels: domain, instance_uuid, user_uuid, project_uuid, project_name, volume_uuid, disk_type, disk_path
  - unit: seconds

- **oie_instance_disk_write_seconds_total**
  - Type: Counter
  - Description: Total time spent servicing disk writes (seconds).
  - labels: domain, instance_uuid, user_uuid, project_uuid, project_name, volume_uuid, disk_type, disk_path
  - unit: seconds

- **oie_instance_disk_read_gbytes_total**
  - Type: Counter
  - Description: Total data read from disk (GB).
  - labels: domain, instance_uuid, user_uuid, project_uuid, project_name, volume_uuid, disk_type, disk_path
  - unit: GB

- **oie_instance_disk_write_gbytes_total**
  - Type: Counter
  - Description: Total data written to disk (GB).
  - labels: domain, instance_uuid, user_uuid, project_uuid, project_name, volume_uuid, disk_type, disk_path
  - unit: GB

- **oie_instance_disk_flush_requests_total**
  - Type: Counter
  - Description: Total disk flush requests serviced.
  - labels: domain, instance_uuid, user_uuid, project_uuid, project_name, volume_uuid, disk_type, disk_path
  - unit: requests

- **oie_instance_disk_flush_seconds_total**
  - Type: Counter
  - Description: Total time spent servicing disk flushes (seconds).
  - labels: domain, instance_uuid, user_uuid, project_uuid, project_name, volume_uuid, disk_type, disk_path
  - unit: seconds

- **oie_instance_disk_read_iops**
  - Type: Gauge
  - Description: Read IOPS over the last scrape interval (`Δread_requests_total / Δt`).
  - labels: domain, instance_uuid, user_uuid, project_uuid, project_name, volume_uuid, disk_type, disk_path
  - unit: iops

- **oie_instance_disk_write_iops**
  - Type: Gauge
  - Description: Write IOPS over the last scrape interval (`Δwrite_requests_total / Δt`).
  - labels: domain, instance_uuid, user_uuid, project_uuid, project_name, volume_uuid, disk_type, disk_path
  - unit: iops

- **oie_instance_disk_flush_iops**
  - Type: Gauge
  - Description: Flush IOPS over the last scrape interval (`Δflush_requests_total / Δt`).
  - labels: domain, instance_uuid, user_uuid, project_uuid, project_name, volume_uuid, disk_type, disk_path
  - unit: iops

- **oie_instance_disk_read_latency_seconds**
  - Type: Gauge
  - Description: Average per-read service time over the last scrape interval (`Δread_seconds_total / max(Δread_requests_total,1)`).
  - labels: domain, instance_uuid, user_uuid, project_uuid, project_name, volume_uuid, disk_type, disk_path
  - unit: seconds

- **oie_instance_disk_write_latency_seconds**
  - Type: Gauge
  - Description: Average per-write service time over the last scrape interval (`Δwrite_seconds_total / max(Δwrite_requests_total,1)`).
  - labels: domain, instance_uuid, user_uuid, project_uuid, project_name, volume_uuid, disk_type, disk_path
  - unit: seconds

- **oie_instance_disk_flush_latency_seconds**
  - Type: Gauge
  - Description: Average per-flush service time over the last scrape interval (`Δflush_seconds_total / max(Δflush_requests_total,1)`).
  - labels: domain, instance_uuid, user_uuid, project_uuid, project_name, volume_uuid, disk_type, disk_path
  - unit: seconds

- **oie_instance_conntrack_ip_flows**
  - Type: Gauge
  - Description: Conntrack flows currently attributed to this instance fixed IP (inbound + outbound).
  - labels: domain, instance_uuid, ip, family, project_uuid, project_name, user_uuid
  - unit: flows

- **oie_instance_conntrack_ip_flows_inbound**
  - Type: Gauge
  - Description: Conntrack flows currently attributed to this instance fixed IP (inbound).
  - labels: domain, instance_uuid, ip, family, project_uuid, project_name, user_uuid
  - unit: flows

- **oie_instance_conntrack_ip_flows_outbound**
  - Type: Gauge
  - Description: Conntrack flows currently attributed to this instance fixed IP (outbound).
  - labels: domain, instance_uuid, ip, family, project_uuid, project_name, user_uuid
  - unit: flows

- **oie_instance_inbound_flows**
  - Type: Gauge
  - Description: Conntrack flows observed for this behavior identity (inbound) in the last analysis window.
  - labels: domain, instance_uuid, ip, family, project_uuid, project_name, user_uuid
  - unit: flows

- **oie_instance_inbound_unique_remotes**
  - Type: Gauge
  - Description: Unique remote IPs observed for this behavior identity (inbound) in the last analysis window.
  - labels: domain, instance_uuid, ip, family, project_uuid, project_name, user_uuid
  - unit: count

- **oie_instance_inbound_new_remotes**
  - Type: Gauge
  - Description: Remote IPs newly observed (vs recent history) for this behavior identity (inbound) in the last analysis window.
  - labels: domain, instance_uuid, ip, family, project_uuid, project_name, user_uuid
  - unit: count

- **oie_instance_inbound_unique_dst_ports**
  - Type: Gauge
  - Description: Unique destination ports observed for this behavior identity (inbound) in the last analysis window.
  - labels: domain, instance_uuid, ip, family, project_uuid, project_name, user_uuid
  - unit: count

- **oie_instance_inbound_new_dst_ports**
  - Type: Gauge
  - Description: Destination ports newly observed (vs recent history) for this behavior identity (inbound) in the last analysis window.
  - labels: domain, instance_uuid, ip, family, project_uuid, project_name, user_uuid
  - unit: count

- **oie_instance_inbound_max_flows_single_remote**
  - Type: Gauge
  - Description: Maximum flows concentrated to/from a single remote IP for this behavior identity (inbound) in the last analysis window.
  - labels: domain, instance_uuid, ip, family, project_uuid, project_name, user_uuid
  - unit: flows

- **oie_instance_inbound_max_flows_single_dst_port**
  - Type: Gauge
  - Description: Maximum flows concentrated to a single destination port for this behavior identity (inbound) in the last analysis window.
  - labels: domain, instance_uuid, ip, family, project_uuid, project_name, user_uuid
  - unit: flows

- **oie_instance_inbound_bytes_per_flow**
  - Type: Gauge
  - Description: Average bytes per flow for this behavior identity (inbound) in the last analysis window (requires nf_conntrack_acct=1).
  - labels: domain, instance_uuid, ip, family, project_uuid, project_name, user_uuid
  - unit: bytes/flow

- **oie_instance_inbound_packets_per_flow**
  - Type: Gauge
  - Description: Average packets per flow for this behavior identity (inbound) in the last analysis window (requires nf_conntrack_acct=1).
  - labels: domain, instance_uuid, ip, family, project_uuid, project_name, user_uuid
  - unit: packets/flow

- **oie_instance_outbound_flows**
  - Type: Gauge
  - Description: Conntrack flows observed for this behavior identity (outbound) in the last analysis window.
  - labels: domain, instance_uuid, ip, family, project_uuid, project_name, user_uuid
  - unit: flows

- **oie_instance_outbound_unique_remotes**
  - Type: Gauge
  - Description: Unique remote IPs observed for this behavior identity (outbound) in the last analysis window.
  - labels: domain, instance_uuid, ip, family, project_uuid, project_name, user_uuid
  - unit: count

- **oie_instance_outbound_new_remotes**
  - Type: Gauge
  - Description: Remote IPs newly observed (vs recent history) for this behavior identity (outbound) in the last analysis window.
  - labels: domain, instance_uuid, ip, family, project_uuid, project_name, user_uuid
  - unit: count

- **oie_instance_outbound_unique_dst_ports**
  - Type: Gauge
  - Description: Unique destination ports observed for this behavior identity (outbound) in the last analysis window.
  - labels: domain, instance_uuid, ip, family, project_uuid, project_name, user_uuid
  - unit: count

- **oie_instance_outbound_new_dst_ports**
  - Type: Gauge
  - Description: Destination ports newly observed (vs recent history) for this behavior identity (outbound) in the last analysis window.
  - labels: domain, instance_uuid, ip, family, project_uuid, project_name, user_uuid
  - unit: count

- **oie_instance_outbound_max_flows_single_remote**
  - Type: Gauge
  - Description: Maximum flows concentrated to/from a single remote IP for this behavior identity (outbound) in the last analysis window.
  - labels: domain, instance_uuid, ip, family, project_uuid, project_name, user_uuid
  - unit: flows

- **oie_instance_outbound_max_flows_single_dst_port**
  - Type: Gauge
  - Description: Maximum flows concentrated to a single destination port for this behavior identity (outbound) in the last analysis window.
  - labels: domain, instance_uuid, ip, family, project_uuid, project_name, user_uuid
  - unit: flows

- **oie_instance_outbound_bytes_per_flow**
  - Type: Gauge
  - Description: Average bytes per flow for this behavior identity (outbound) in the last analysis window (requires nf_conntrack_acct=1).
  - labels: domain, instance_uuid, ip, family, project_uuid, project_name, user_uuid
  - unit: bytes/flow

- **oie_instance_outbound_packets_per_flow**
  - Type: Gauge
  - Description: Average packets per flow for this behavior identity (outbound) in the last analysis window (requires nf_conntrack_acct=1).
  - labels: domain, instance_uuid, ip, family, project_uuid, project_name, user_uuid
  - unit: packets/flow

- **oie_instance_threat_spamhaus_active_flows**
  - Type: Gauge
  - Description: Active conntrack flows involving a remote IP present in the spamhaus threat list.
  - labels: domain, instance_uuid, project_uuid, project_name, user_uuid, direction
  - unit: flows

- **oie_instance_threat_spamhaus_contacts_total**
  - Type: Counter
  - Description: Total threat-list contact events for the spamhaus threat list (direction-aware).
  - labels: domain, instance_uuid, project_uuid, project_name, user_uuid, direction
  - unit: count

- **oie_instance_threat_tor_exit_active_flows**
  - Type: Gauge
  - Description: Active conntrack flows involving a remote IP present in the tor_exit threat list.
  - labels: domain, instance_uuid, project_uuid, project_name, user_uuid, direction
  - unit: flows

- **oie_instance_threat_tor_exit_contacts_total**
  - Type: Counter
  - Description: Total threat-list contact events for the tor_exit threat list (direction-aware).
  - labels: domain, instance_uuid, project_uuid, project_name, user_uuid, direction
  - unit: count

- **oie_instance_threat_tor_relay_active_flows**
  - Type: Gauge
  - Description: Active conntrack flows involving a remote IP present in the tor_relay threat list.
  - labels: domain, instance_uuid, project_uuid, project_name, user_uuid, direction
  - unit: flows

- **oie_instance_threat_tor_relay_contacts_total**
  - Type: Counter
  - Description: Total threat-list contact events for the tor_relay threat list (direction-aware).
  - labels: domain, instance_uuid, project_uuid, project_name, user_uuid, direction
  - unit: count

- **oie_instance_threat_emergingthreats_active_flows**
  - Type: Gauge
  - Description: Active conntrack flows involving a remote IP present in the emergingthreats threat list.
  - labels: domain, instance_uuid, project_uuid, project_name, user_uuid, direction
  - unit: flows

- **oie_instance_threat_emergingthreats_contacts_total**
  - Type: Counter
  - Description: Total threat-list contact events for the emergingthreats threat list (direction-aware).
  - labels: domain, instance_uuid, project_uuid, project_name, user_uuid, direction
  - unit: count

- **oie_instance_threat_customlist_active_flows**
  - Type: Gauge
  - Description: Active conntrack flows involving a remote IP present in the customlist threat list.
  - labels: domain, instance_uuid, project_uuid, project_name, user_uuid, direction
  - unit: flows

- **oie_instance_threat_customlist_contacts_total**
  - Type: Counter
  - Description: Total threat-list contact events for the customlist threat list (direction-aware).
  - labels: domain, instance_uuid, project_uuid, project_name, user_uuid, direction
  - unit: count

- **oie_instance_resource_severity**
  - Type: Gauge
  - Description: Overall resource severity (0..1) for this instance.
  - labels: domain, instance_uuid, project_uuid, project_name, user_uuid
  - unit: ratio

- **oie_instance_resource_cpu_severity**
  - Type: Gauge
  - Description: Resource severity (0..1) for the cpu axis.
  - labels: domain, instance_uuid, project_uuid, project_name, user_uuid
  - unit: ratio

- **oie_instance_resource_mem_severity**
  - Type: Gauge
  - Description: Resource severity (0..1) for the mem axis.
  - labels: domain, instance_uuid, project_uuid, project_name, user_uuid
  - unit: ratio

- **oie_instance_resource_disk_severity**
  - Type: Gauge
  - Description: Resource severity (0..1) for the disk axis.
  - labels: domain, instance_uuid, project_uuid, project_name, user_uuid
  - unit: ratio

- **oie_instance_resource_net_severity**
  - Type: Gauge
  - Description: Resource severity (0..1) for the net axis.
  - labels: domain, instance_uuid, project_uuid, project_name, user_uuid
  - unit: ratio

- **oie_instance_behavior_severity**
  - Type: Gauge
  - Description: Overall behavior anomaly severity (0..1) for this instance.
  - labels: domain, instance_uuid, project_uuid, project_name, user_uuid
  - unit: ratio

- **oie_instance_threat_list_severity**
  - Type: Gauge
  - Description: Overall threat-list severity (0..1) for this instance.
  - labels: domain, instance_uuid, project_uuid, project_name, user_uuid, direction
  - unit: ratio

- **oie_instance_attention_severity**
  - Type: Gauge
  - Description: Overall attention severity (0..1) combining resource + behavior + threat-list signals.
  - labels: domain, instance_uuid, project_uuid, project_name, user_uuid
  - unit: ratio

## Appendix B: Log schema and examples

### Behavior alert fields (additions)

In addition to the common fields, `behavior_alert` events include:

* `priority` (`P1`..`P4`)
* `severity_score`, `confidence_score` (numeric; logged separately so you can tune)
* `kind` (category label)
* `top_remote_ip`, `top_dst_port`, `top_dst_port_name`
* `top_remote_share`, `top_port_share`, `evidence_mode`

### Example: behavior alert (illustrative)

```json
{
  "time": "2025-12-20T12:01:00Z",
  "level": "NOTICE",
  "msg": "behavior_alert",
  "domain": "instance-00000001",
  "instance_uuid": "…",
  "project_uuid": "…",
  "user_uuid": "…",
  "direction": "outbound",
  "kind": "vertical_port_scan",
  "priority": "P2",
  "severity_score": 0.78,
  "confidence_score": 0.72,
  "top_remote_ip": "203.0.113.55",
  "top_dst_port": 22,
  "top_dst_port_name": "ssh",
  "top_remote_share": 0.08,
  "top_port_share": 0.14,
  "evidence_mode": "distributed",
  "flows": 1200,
  "unique_dst_ports": 400,
  "unique_remotes": 2,
  "unreplied_ratio": 0.92
}
```

### Example: threat hit (illustrative, unified log)

```json
{
  "time": "2025-12-20T12:02:11Z",
  "level": "NOTICE",
  "msg": "threat_hit",
  "domain": "instance-00000001",
  "instance_uuid": "…",
  "project_uuid": "…",
  "user_uuid": "…",
  "direction": "outbound",
  "list": "spamhaus",
  "remote_ip": "198.51.100.77",
  "active_flows": 12,
  "contacts_total": 1
}
```

## Appendix C: Glossary

- **Conntrack:** Kernel connection tracking state table (shared host resource).
- **Conntrack zone:** Kernel zone identifier used by overlays/virtualization to separate tenant contexts.
- **EWMA:** Exponentially weighted moving average (fast baseline and slow baseline).
- **Behavior identity:** (instance UUID, fixed IP, direction) — the key for behavior state.
- **Fixed IP:** The tenant IP OIE uses for attribution (not remote IP).
- **Pressure:** “how hard right now” (0..1).
- **Impact:** “how much it matters” (0..1).
- **Confidence:** “how reliable this measurement is” (0..1).
- **Severity:** normalized signal intended for dashboards/alerts (0..1, often displayed as 0..100).
- **Attention:** weighted blend severity intended for triage and automation.

## License

Apache License 2.0

Copyright (c) 2025 xneelo Cloud Engineering Team

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this exporter except in compliance with the License.
You may obtain a copy of the License at:

http://www.apache.org/licenses/LICENSE-2.0