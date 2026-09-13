# Prometheus alert policy

[Documentation index](DOCUMENTATION.md) · [Project README](README.md)

The v2.0.0 example contains **82 alert definitions** in one group named `OpenStack Instance Exporter`, with ten shared recording rules. Every alert name appears exactly once. All alert names from the published v1.2.0 baseline remain available.

**On this page**

- [Policy at a glance](#policy-at-a-glance)
- [Rendering and installation](#rendering-and-installation)
- [Source and freshness requirements](#source-and-freshness-requirements)
- [Default operational thresholds](#default-operational-thresholds)
- [Attached-volume retype warnings](#attached-volume-retype-warnings)
- [Validation and tuning](#validation-and-tuning)

## Policy at a glance

| Policy | Count | Purpose |
| --- | ---: | --- |
| Enabled warnings | 30 | Exporter/source failures and persistent, qualified operational symptoms |
| Enabled informational | 1 | Persistent mining-port candidate without warning-level CPU corroboration |
| Enabled criticals | 2 | Corroborated host CPU or memory impact |
| Opt-in informational diagnostics | 49 | Workload volume, heuristic scores and environment-dependent signals |

The default policy enables 33 alerts. Definitions marked `enabled: false` are omitted by the deployment template until an operator enables them. A generic high CPU, IOPS, bandwidth, connection-count, fan-out, or aggregate anomaly score is not proof of abuse. Legacy alert names containing words such as `Critical`, `Flood` or `Mining` preserve interface compatibility; the configured severity and annotations describe their current meaning.

## Rendering and installation

`examples/prometheus_alerts_example/openstack_instance_exporter_alerts.yml` is an Ansible/Jinja variable file, not a native Prometheus rule file. Render it with support for both `group_recording_rules` and each alert's `enabled` flag. Preserve the triple-backslash label-quote escaping in the source template. The [example README](examples/prometheus_alerts_example/README.md) describes installation and validation.

```bash
promtool check rules /path/to/rendered-openstack-instance-exporter.rules.yml
make operator-test PROMTOOL=/path/to/promtool
```

Every alert includes an identity-specific `dashboard_path` with an evaluation-time window. The deployment template converts it to a dashboard URL using the configured Grafana root URL or monitoring host address. Reload the rendered rules and import all five dashboards together. An empty `ALERTS` query does not establish that the rules were installed successfully.

## Source and freshness requirements

Rules use the `openstack-instance-exporter` scrape job and target-local matching. Libvirt-dependent workload rules require current Libvirt health; conntrack-dependent rules require current conntrack health; mixed rules require both. Shared five-minute recording rules require healthy source and `up` observations throughout the measured window. Running-instance and resource-axis gates prevent retained or inactive workload data from qualifying current alerts. A failed source interrupts pending workload alerts.

Observed-window checks cannot establish that every wall-clock scrape happened. If Prometheus stores neither a primary sample nor an `up` sample for an interval, their sample counts share that gap. Evaluate rules against raw scrape series with the same target labels; transformed or independently resampled series need separate validation.

Current host CPU, memory and conntrack-capacity readings are omitted when unavailable rather than replayed as live host observations. Retained workload data can remain visible for diagnosis; source and resource freshness must be read alongside it.

### Collection cadence and feed health

`oie_host_collection_interval_seconds` reports the effective configured interval and uses exactly `15s` when an internal caller omits it. `oie_host_threat_feed_fresh` emits exactly five series on every scrape. Its exact `list` values are `TOREXIT`, `TORRELAY`, `EMERGING`, `CUSTOMLIST`, and `spamhaus`. A value of `1` means enabled with a usable non-empty snapshot, `0` means enabled but unusable, and `-1` means disabled. A failed feed refresh never extends snapshot freshness.

## Default operational thresholds

- Exporter unavailability requires five minutes of failed scrapes.
- Host CPU critical requires usage above 95%, excluding idle and I/O wait, together with aggregate guest scheduler delay above 5% of allocated vCPU time for ten minutes. Host memory critical requires available RAM below 2% together with aggregate guest swap-in above 1 MiB/s for ten minutes. The corresponding warning predicates are disjoint from the critical predicates.
- Disk read, write and flush latency warnings use I/O-weighted service-time/operation ratios. Their respective thresholds are 150 ms, 100 ms and 40 ms, with at least 60 measured operations over five minutes and five minutes of persistence. Disk identity is preserved, so separate affected devices are separate incidents.
- Network drop warnings require a ratio above 2%, at least 1,000 packet/drop observations and 20 drops per five-minute window, sustained for fifteen minutes.
- Enabled repeated-contact warnings cover Spamhaus, Emerging Threats and the custom list. They require outbound evidence, current matching flows, a usable selected feed and five minutes of persistence. Tor contact diagnostics are opt-in.
- Mining warnings require current CPU evidence, tier-specific qualification and two additional minutes of persistence. Multiple ports on one VM form one incident. The uncorroborated dedicated-port candidate remains informational after fifteen minutes. The pack does not claim that an instance is definitely mining or compromised.

## Attached-volume retype warnings

### Conditions that can warn

Retype monitoring is disabled by default. When enabled, `OpenStackInstanceVolumeRetypeReadyStalled` qualifies only for status `6`: copy ready and awaiting pivot for at least ten exporter-observed minutes, followed by one minute of alert persistence. `OpenStackInstanceVolumeRetypeObservationUnhealthy` requires two continuous minutes of failed block-job observation while the main Libvirt source remains healthy. It is suppressed when the same operation is already ready-stalled. Both rules use warning severity.

### Conditions that do not warn

Ordinary copying and copy-ready status `5` do not alert. These observations do not declare the authoritative Nova or Cinder outcome, and detached-volume retypes are outside the compute-local view.

## Validation and tuning

Every bundled rule has executable Prometheus lifecycle coverage. The operator tests exercise the rendered deployment template, enabled/disabled policy, recording rules, pending durations, source interruptions and recovery. Scoped baseline alert fixtures remain additional regression coverage; they do not define the installed policy.

Review thresholds and notification routing against local workload observations. Optional diagnostics may co-fire with a direct symptom because they describe different signal classes. Use instance, project, host and affected-disk identity when investigating; a score or list match is evidence for review, not a causal diagnosis.
