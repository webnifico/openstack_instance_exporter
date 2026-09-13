# Source health and retained data

[Documentation index](DOCUMENTATION.md) · [Project README](README.md)

Data integrity defines how OIE reports source data when Libvirt or conntrack succeeds, fails temporarily, or has never succeeded. It adds explicit Libvirt health telemetry and makes source failure behavior atomic. A collection failure must be visible as a collection failure; it must never be converted into a healthy workload zero.

**On this page**

- [States](#states)
- [Libvirt atomicity](#libvirt-atomicity)
- [Libvirt health metrics](#libvirt-health-metrics)
- [Conntrack completeness and retention](#conntrack-completeness-and-retention)
- [Cross-source rules](#cross-source-rules)
- [Compatibility boundary](#compatibility-boundary)

## States

| State | Meaning | Dependent metrics | Derived state |
| --- | --- | --- | --- |
| Fresh | The complete source cycle succeeded. | Publish the new cycle. | Advance once from the new observations. |
| Retained | The source failed after at least one complete success. | Preserve the last-good values and publish live unhealthy/stale source health. | Freeze; do not learn from or age through the outage. |
| Unavailable | The source failed before its first complete success. | Omit dependent workload metrics. Publish source health with the initial sentinel values. | Do not initialize or advance. |

Retained and unavailable are not zero-valued observations. Zero is a valid workload value only when it came from a complete fresh collection.

## Libvirt atomicity

A Libvirt cycle is complete only when all of the following are true:

- the domain-stats request completes without error;
- every returned domain has a valid, unique UUID;
- metadata required for every returned domain is fresh or successfully refreshed; and
- every returned record can be staged before the active-instance snapshot is committed.

An error returned with a partial domain list still rejects the whole list. A stale metadata fallback can remain available to callers for compatibility, but it cannot make the collection cycle fresh. One failed domain or metadata lookup rejects the complete cycle, so active-instance identity, aggregate counts, resource samples, and derived state cannot become a mixture of old and new domains.

### Empty inventory and failed cycles

A successful empty domain list is fresh. It atomically replaces the previous domain set, removes the old instance series, and publishes valid zero host aggregates such as active VM count.

On an initial Libvirt failure, Libvirt-dependent instance and aggregate metrics are unavailable and omitted. On a later failure, OIE preserves the complete last-good Libvirt metric cycle. The current health metrics are overlaid on retained data so an operator can always distinguish it from fresh output.

## Libvirt health metrics

The three Data integrity additions are unlabeled gauges:

| Metric | Initial failure | Successful cycle at `T` | Failure after `T` |
| --- | ---: | ---: | ---: |
| `oie_host_libvirt_ok` | `0` | `1` | `0` |
| `oie_host_libvirt_last_success_timestamp_seconds` | `0` | Unix timestamp `T` | unchanged at `T` |
| `oie_host_libvirt_stale_seconds` | `-1` | `max(0, now - T)` | continues increasing from `T` |

Recovery records the recovery cycle as the new last success and returns `oie_host_libvirt_ok` to `1`. Backward wall-clock movement clamps stale age to zero.

## Conntrack completeness and retention

A conntrack snapshot is fresh only when every enabled address-family dump completes. Timeout, `ENOBUFS`, interrupted or overrun Netlink dumps, malformed messages, sequence/family mismatches, parse failures, and any other partial-read condition reject the complete snapshot.

After a previous success, a rejected snapshot retains conntrack-derived values only for the exact `(instance UUID, fixed IP)` identities present in that last-good snapshot. Reusing an old aggregate for a new or changed fixed IP is forbidden. Before the first complete snapshot, conntrack-dependent attribution and behavior metrics are unavailable and omitted.

### State frozen during failure

During a retained interval OIE freezes:

- behavior fast and slow EWMA state;
- generic behavior and mining persistence;
- previous-interval feature baselines, including new remotes and destination ports;
- state TTL aging and cleanup;
- emission cooldowns and episode state; and
- threat/behavior/mining evidence events and counters driven by the snapshot.

### Recovery and health reporting

Recovery resumes the paused logical clock, then accepts the first complete behavior observation as a silent statistical baseline. Its raw observation is exported, but behavior/mining persistence and composite attention resume only after a complete post-recovery interval. The outage duration therefore cannot reset persistence, manufacture an EWMA burst, or emit a recovery-only workload event.

Conntrack health remains live while values are retained: `oie_host_conntrack_raw_ok` is `0`, the last-success timestamp is unchanged, and stale seconds increases. Its pre-first-success stale sentinel is `-1`. When conntrack collection is disabled by configuration, its dependent and health series follow the disabled configuration path rather than reporting a failed read.

## Cross-source rules

- Libvirt identity is authoritative for the current domain set; a failed Libvirt cycle cannot partially rewrite that identity.
- A retained conntrack snapshot must match the exact current instance/IP identity before any retained per-IP value can be emitted.
- Retained behavior or threat values may remain observable, but an unavailable or stale source cannot be treated as a fresh zero or fresh input to a composite score.
- Source failures do not advance workload state or generate new exporter workload evidence. The bundled rules require healthy source gauges from the same `instance`/`job` scrape target, so retained values cannot continue or newly satisfy an alert `for` interval. Range expressions additionally require every necessary source to have remained healthy for the complete data lookback; this blocks pre-failure history and recovery movement until the range is continuously fresh.
- With conntrack collection disabled, no healthy conntrack gate is available. Conntrack-dependent composite/workload rules and the host conntrack-utilization rule are intentionally suppressed, while Libvirt-only workload rules remain eligible.

## Compatibility boundary

The source-health contract preserves existing metric identities and adds explicit Libvirt availability, last-success and stale-age gauges. Layered fixtures cover the baseline schema, source-health additions and later resource, alert-health, inventory and retype families. The complete v2.0.0 catalog is in [README.md](README.md); [COMPATIBILITY_BASELINE.md](COMPATIBILITY_BASELINE.md) records the published v1.2.0 compatibility boundary.
