# Scaling limits

[Documentation index](DOCUMENTATION.md) · [Project README](README.md)

Use these measurements to choose a collection interval and understand the bounds of the synthetic validation. Rerun the scale gate on representative deployment hardware.

**On this page**

- [Supported envelope](#supported-envelope)
- [Reference environment and method](#reference-environment-and-method)
- [Measured collection results](#measured-collection-results)
- [Adversarial remote cardinality](#adversarial-remote-cardinality)
- [State, cleanup, failure, and logging boundaries](#state-cleanup-failure-and-logging-boundaries)

## Supported envelope

In the historical reference measurement below, the supported five-second collection envelope is **500,000 conntrack entries and 500 active domains**. Its conservative p95 processing time is 1,578.391 ms, or 31.6% of the collection interval. This stays below the Scaling safety budget of 50% and leaves time for kernel Netlink delivery, Libvirt RPC latency, scheduling, and Prometheus collection overhead that the synthetic harness cannot reproduce.

The larger measured workloads, including 1,000 active domains, remain useful planning boundaries:

| Conntrack entries | Active domains | Conservative p95 | Share of interval | Minimum practical interval for at least 50% headroom |
| ---: | ---: | ---: | ---: | ---: |
| 100,000 | 100 | 274.862 ms | 5.5% | 5 s |
| 500,000 | 500 | 1,578.391 ms | 31.6% | 5 s |
| 1,000,000 | 1,000 | 3,699.896 ms | 74.0% | 10 s |
| 2,000,000 | 1,000 | 6,402.628 ms | 128.1% | 15 s |

The one-million and two-million rows are measured boundaries, not five-second support claims. Operators should reproduce the scale gate on representative hardware and use the longer listed interval or more headroom when real Netlink and Libvirt latency is significant.

## Reference environment and method

- Date: 2026-08-31.
- Go: go1.24.4, linux/amd64.
- Kernel: Linux 6.18.35.
- CPU: AMD EPYC 9V74, 9 logical CPUs exposed to the runner; exporter worker count capped at 8.
- Memory visible to the runner: 23,109,910,528 bytes.
- Five independent samples per benchmark, one complete production-scale iteration per sample.
- p95 is the nearest-rank p95; with five samples this is the maximum observed sample.
- The complete five-run benchmark process used 980,877,312 bytes maximum resident memory, 170.939 user CPU seconds, and 4.590 system CPU seconds.

The harness uses the real parser, conntrack aggregator, behavior/mining/threat analysis, Libvirt record preparation, domain metric collection, persistent state transitions, and exporter collection lock. Domain records contain two vCPUs, memory, one disk, one network interface, metadata, and a fixed IPv4 address. Normal-scale conntrack input distributes flows over every VM, 512 representative remote endpoints per VM, and 128 destination ports.

The total collection benchmark begins with decoded flows supplied through the existing dump hook. Raw Netlink parsing is measured separately. The conservative pipeline value is therefore `raw Netlink parse p95 + total collection p95`; it intentionally does not subtract overlap or isolated Libvirt time.

This is a synthetic processing envelope. It does not model kernel socket scheduling, Netlink copy time, a slow or remote Libvirt daemon, DNS, Prometheus scrape transport, noisy-neighbour CPU contention, or production logging backends.

## Measured collection results

| Entries / domains | Raw parse p95 | Aggregation p95 | Libvirt p95 | Total collection p95 | Heap per collection | Allocations | Historical exported series | Behavior / mining / threat state |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 100,000 / 100 | 16.883 ms | 180.361 ms | 4.099 ms | 257.979 ms | 46.48 MiB | 230,360 | 6,734 | 800 / 0 / 0 |
| 500,000 / 500 | 147.773 ms | 1,463.977 ms | 17.305 ms | 1,430.618 ms | 233.07 MiB | 1,151,561 | 33,534 | 4,000 / 0 / 0 |
| 1,000,000 / 1,000 | 170.218 ms | 3,382.506 ms | 150.684 ms | 3,529.678 ms | 467.53 MiB | 2,304,493 | 67,034 | 8,000 / 0 / 0 |
| 2,000,000 / 1,000 | 325.134 ms | 6,178.667 ms | 150.684 ms | 6,077.493 ms | 467.14 MiB | 2,296,982 | 67,034 | 8,000 / 0 / 0 |

The table preserves the archived Go 1.24.4 measurement: 67 series per active domain plus 34 fixed host/exporter series. It is not the current schema cardinality.

The 2026-09-07 Go 1.27.1 sweep reports **6,937, 34,537 and 69,037 series** for 100, 500 and 1,000 active domains: 69 per domain plus 37 fixed series in this fixture. The additions are the three fixed retype-result series and instance/disk inventory. This fixture does not populate configured-interface or metadata-address inventory: those add a series per observed interface and distinct port/address in real deployments. Inactive definitions add inventory series separately, and active/recent retypes add the bounded operation series described below. These counts are fixture-specific, not a universal per-VM ceiling.

Doubling conntrack entries at a fixed 1,000-domain inventory does not add series. The benign fixture creates eight retained behavior entries per domain and no mining or threat episode state. The current one-sample sweep passed the collection and state-bound checks; it is not a new p95 measurement and does not replace the historical five-sample latency table.

## Adversarial remote cardinality

The separate adversarial fixture sends every flow to a unique IPv6 remote. Remote evidence remains capped at 32,768 entries, and remote/port evidence remains capped at 65,536 entries.

| Unique remotes | p95 | Heap allocated | Allocations | Retained remote evidence |
| ---: | ---: | ---: | ---: | ---: |
| 100,000 | 354.083 ms | 32.36 MiB | 35,939 | 32,768 |
| 500,000 | 1,722.112 ms | 49.37 MiB | 37,481 | 32,768 |
| 1,000,000 | 3,325.198 ms | 49.37 MiB | 37,481 | 32,768 |
| 2,000,000 | 6,284.177 ms | 49.37 MiB | 37,481 | 32,768 |

Scaling replaces the saturated remote map's full minimum scan with a deterministic min-heap. Victim selection is now O(log n), preserves the existing Space-Saving count and lowest-IP tie break, and reuses evicted heap entries. Allocation volume and retained memory therefore flatten after the cap instead of growing with unique remote count.

## State, cleanup, failure, and logging boundaries

- No uncontrolled overlap: 32 simultaneous collection callers produced a maximum of one active collection cycle through the production collection mutex.
- Bounded state: remote evidence is capped at 32,768, remote/port evidence at 65,536, and threat-log throttle state at 4,096 entries.

### Retype series and polling bounds

Idle volumes create zero per-operation retype series. A copying operation emits active, status, observation-health, and start series plus optional progress (at most five); a copy-ready operation also emits its ready timestamp (at most six). Recent terminal operations emit four required series plus the optional ready timestamp and are retained in memory for one hour with a hard cap of 256 operations (at most 1,280 terminal series) per exporter. An exact repeated source/destination identity on one instance disk replaces its older retained row.

Recent rows and the three fixed result-labeled host counter series reset on exporter restart. The one-hour expiry controls current exporter emission, not deletion of historical samples from Prometheus. A job that becomes too old to reconfirm expires without creating terminal series or incrementing a counter; status `4` is reserved for a successful terminal XML inspection that finds the mirror gone but cannot match the final source.

### Retype observation cadence

Discovery reads at most 256 domain XML documents per full collection cycle, including while no retype is known. For known jobs, the completion-paced fast poller reads one XML document per affected active domain no more often than every five seconds after the preceding attempt completes. Block-job queries run no more often than every fifteen seconds after the preceding query completes, are serialized per domain, and wait thirty seconds after a failed query completes before retrying.

Retype-specific batches use at most four workers and rotate bounded work across domains and disks. With no known job, the fast-poller and block-job paths make no Libvirt calls; bounded discovery remains active.

These per-job intervals are minimum spacing. Shared Libvirt timeout backoff can defer every observation path for at least one minute, and active control/job checks can defer it longer. Dynamic disk statistics are omitted for every disk on a VM with a live disk mirror or saved Libvirt block job. CPU, memory and network statistics can continue when the control/async-job checks permit; missing observations are represented by the existing freshness and availability metrics.

### Cleanup, recovery and logging

- Deletion cleanup reclaimed all seeded behavior, mining, threat, resource, inventory, and sample state. p95 was 0.524 ms for 100 instances, 1.464 ms for 500, and 2.038 ms for 1,000.
- Expiration cleanup reclaimed all stale behavior and mining state for 1,000 still-active instances.
- Incomplete input preserved the exact last-good conntrack snapshot and count; a complete follow-up cycle replaced it and subsequent collection remained bounded.
- Bounded logging: 1,000 new threat episodes emitted exactly 2,000 structured records within a 4 MiB test ceiling. Repeating unchanged evidence inside the throttle interval emitted no additional bytes.
- Predictable cardinality: normal series are linear in active domains, remain unchanged when only flow count doubles at fixed inventory, and failure/recovery-only availability series are bounded by eight per domain plus sixteen fixed series.

The machine-readable measurements are in `testdata/scaling-reference-measurements.json`. `make scale` runs every Scaling boundary contract and one complete scale sweep; extended CI repeats the sweep five times.
