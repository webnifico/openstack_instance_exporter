# Resource telemetry and freshness

[Documentation index](DOCUMENTATION.md) · [Project README](README.md)

Resource telemetry makes the existing CPU, memory, disk, and network resource axes bounded and explicit. It does not add a fifth axis or change the exporter identity labels.

**On this page**

- [Timing policy](#timing-policy)
- [Axis lifecycle](#axis-lifecycle)
- [Complete observations](#complete-observations)
- [Composite contract](#composite-contract)
- [Prometheus surface](#prometheus-surface)

## Timing policy

Let `I` be the configured collection interval. When the interval is unavailable to an internal caller, `I` is 15 seconds.

- Missing-sample grace: `2I`.
- Maximum retained age: `8I`.
- The exact `8I` boundary remains retained; an age greater than `8I` is unavailable.
- A backward wall-clock adjustment clamps the reported age to zero.

## Axis lifecycle

| State | Fresh | Available | Last success | Stale seconds | Severity |
| --- | ---: | ---: | --- | ---: | --- |
| Never successfully sampled | `0` | `0` | `0` | `-1` | Omitted |
| Complete valid sample | `1` | `1` | Updated | `0` | Current |
| Missing, age at most `8I` | `0` | `1` | Unchanged | Increasing | Last good |
| Missing, age greater than `8I` | `0` | `0` | Unchanged | Increasing | Omitted |

A missing or non-finite observation never becomes zero. While retained, the axis EWMA, pressure, confidence, impact, persistence, cap state, and workload-event state do not advance. Recovery within `2I` advances over one normal interval. Recovery after `2I`, after expiry, or after an identity/source-set change establishes a silent baseline so outage time cannot create a spike or event.

## Complete observations

Each axis records the source set and runtime identity that produced its last complete observation.

- CPU: usage and the available steal/wait contributors, bound to the live vCPU count and QEMU runtime generation.
- Memory: guest-used, swap-in, and major-fault contributors that are actually available.
- Disk: read/write and flush contributors per authoritative volume/path identity.
- Network: per-interface drop counters and, when available, conntrack pressure, bound to the authoritative NIC/fixed-IP identity.

If a previously observed contributor disappears, the last complete axis is retained rather than scoring an implicit zero. A newly added contributor or changed device identity is a structural transition and is silently rebaselined. Rate samples cannot bridge a gap longer than `8I`.

### Live dimensions and runtime identity

Once live `vcpu.current` or `balloon.maximum` has been observed for a runtime generation, disappearance of that field is missing telemetry: the cached dimension remains the stable identity/label value, but the affected axis is not fresh and its rate baseline does not advance. Nova metadata remains authoritative only for a legacy runtime generation that has never exposed the corresponding live dimension.

Production Libvirt collection brackets the complete stats-and-metadata snapshot with the local QEMU process identity `(host boot ID, PID, /proc start-time ticks)`, mapped by the QEMU `-uuid` argument. Missing, duplicate, or changing bracket tokens reject the cycle without mutating resource state. This distinguishes QEMU incarnations even when an instance UUID and numeric Libvirt domain ID are reused and every new counter already exceeds the previous value. CPU-time rollback remains an additional restart witness.

### Reset and cleanup boundaries

Counter rollback, vCPU-count change, QEMU process-incarnation change, stopped/paused domains, device replacement, and confirmed instance deletion clear the affected baselines. Disk and NIC differencing is device-specific, so one device reset cannot be hidden by another device increasing. Confirmed cleanup removes axis, sample, generation, persistence, cap, and event state before a UUID can be reused.

## Composite contract

Only available axes participate. Axis weights are CPU `0.25`, memory `0.25`, disk `0.30`, and network `0.20`. For every available baseline axis `i`, the exporter evaluates:

```text
candidate_i = 100 - (100 - severity_i) * product over available j != i(1 - weight_j * severity_j / 100)
overall = max(candidate_i)
```

Taking the maximum across baseline candidates avoids a discontinuity when unequal-weight axes cross. Every candidate is monotone in every input. Therefore a single axis is unchanged, increasing or adding trustworthy evidence cannot lower the score, removing evidence cannot raise the remaining score, and multiple elevated axes add bounded uplift. A retained contributor freezes the complete composite while membership is unchanged. Membership changes are recomputed silently with unavailable axes excluded. Persistence and cap transitions require a fully fresh composite.

Attention is emitted only when every positively weighted, enabled input is trustworthy. A missing configured resource, behavior, or threat input cannot change the denominator and create a higher attention score.

## Prometheus surface

Resource telemetry adds exactly four gauge families, each with the normal six instance identity labels plus `axis=cpu|mem|disk|net`:

- `oie_instance_resource_axis_fresh`
- `oie_instance_resource_axis_available`
- `oie_instance_resource_axis_last_success_timestamp_seconds`
- `oie_instance_resource_axis_stale_seconds`

The resource-axis contract is layered onto the source-health and published compatibility fixtures; the complete release metric inventory is documented in README.md. Cached Libvirt fallback overlays live lifecycle ages and removes expired axis, resource-composite, and dependent attention severity instead of replaying them indefinitely.

Bundled per-axis alerts require their matching axis to be fresh. Overall resource, attention, and project-hot alerts require at least one available resource axis and require every available resource axis to be fresh.
