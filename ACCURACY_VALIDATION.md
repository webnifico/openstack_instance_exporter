# Measurement accuracy

[Documentation index](DOCUMENTATION.md) · [Project README](README.md)

The exporter reports host-observed measurements and evidence. Its severity scores are heuristics for ranking and alerting, not physical measurements or proof of abusive activity.

**On this page**

- [Measurement definitions](#measurement-definitions)
- [Current status and source coverage](#current-status-and-source-coverage)
- [Comparison with v1.2.0](#comparison-with-v120)
- [Validation scope](#validation-scope)

## Measurement definitions

| Measurement | Meaning preserved |
| --- | --- |
| Instance CPU | Libvirt domain CPU-time delta divided by elapsed time and allocated vCPUs, capped at 100%. Includes virtualization overhead. |
| CPU composition | Approximate VM-associated CPU versus remaining host CPU. The cap and non-atomic sampling prevent exact attribution of overhead. |
| Scheduler delay | Prefer Libvirt vCPU delay/steal; use wait as a fallback. Both describe host scheduler delay and are not added or described as guest I/O wait. |
| Guest memory | Balloon current minus balloon usable, in MiB. Used/allocation retains the configured allocation denominator; missing usage produces gaps in affected aggregates. It is not unique physical host RAM consumption. |
| Disk latency | Summed service time divided by summed operation counts, separately for reads, writes and flushes. Numerator and denominator use matched observed disks and sample counts. No operations produces no latency value. |
| Disk/network throughput | Counter deltas per second; legacy `gbytes` counters contain GiB. Unrounded counter precision is retained. |
| Drops/errors | Interface events per second. Host-interface panels include virtual interfaces and do not claim unique affected packets. |
| Mining | Persisted network evidence with the existing CPU corroboration thresholds. No evidence observed requires healthy, sufficiently recent telemetry and observed selected-instance coverage. Otherwise current status is Unavailable. |
| Threat counts/scores | Current instant observations, with duplicate instance series reduced before aggregation. Zero matches return zero; unavailable sources do not reuse an earlier positive value. |
| Retypes | Compute-local Libvirt observations and approximate logical progress. Cinder outcomes and Ceph physical allocation remain outside this measurement. |

## Current status and source coverage

Current status considers a source stale after three configured collection intervals, with a minimum allowance of 60 seconds. Threat status requires every enabled feed to have a usable snapshot; disabled feeds are excluded. These checks cover the selected Prometheus targets and the instance inventory visible to the exporter, not undiscovered or unconfigured targets.

## Comparison with v1.2.0

The numerical regression tests compare identical healthy inputs with v1.2.0 source at commit `4b428db7f0355b74b0251f63123835cc19d10516` and a preserved development checkpoint. The measured baselines are `testdata/measurement-v1.2.json` and `testdata/measurement-baseline.json`. Only the replay clock and host CPU input path were substituted when collecting those reference results.

CPU, guest memory, host CPU, IOPS, latency, mean I/O size, throughput and packet/drop rates match the published baseline for these inputs. Two named numerical corrections are allowed: v2.0.0 uses drops/(packets+drops) for the drop ratio, and preserves one-byte precision in GiB counters instead of rounding it to zero. This finite replay does not establish equivalence for every input or environment. Interface compatibility is checked separately; see [COMPATIBILITY_BASELINE.md](COMPATIBILITY_BASELINE.md).

OIE's `oie_host_cpu_usage_percent` excludes idle and I/O wait. The node_exporter dashboard's `100 - idle` panel includes I/O wait. Their distinct calculations are preserved and documented.

## Validation scope

Executable dashboard fixtures evaluate the shipped PromQL for healthy and missing observations, zero-match recovery, disabled monitoring, stale/failed sources, partial coverage, duplicate instance series, CPU corroboration, allocation denominators and I/O-weighted disk cohorts. Existing exporter tests cover the retained numerical formulas, optional counters, resets, hotplug, identity changes, retained source state, metric names and labels, alert behavior, and retype lifecycle.

Current package validation results are recorded in [integration_tests/validation.json](integration_tests/validation.json).

This is source and synthetic validation. Live Libvirt, Prometheus and Grafana behavior still requires deployment testing.

Definitions: [Libvirt domain statistics](https://libvirt.org/manpages/virsh.html#domstats), [Prometheus comparison and set operators](https://prometheus.io/docs/prometheus/latest/querying/operators/), [Grafana calculation types](https://grafana.com/docs/grafana/latest/panels-visualizations/query-transform-data/calculation-types/).
