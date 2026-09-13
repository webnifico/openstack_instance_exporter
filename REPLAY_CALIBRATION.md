# Replay calibration

[Documentation index](DOCUMENTATION.md) · [Project README](README.md)

The calibration corpus contains 51 anonymized replay fixtures: 16 benign, 15 abusive, and 20 failure/lifecycle cases. The corpus converts the Data integrity through CI and release validation contracts into representative end-to-end observations without storing tenant addresses, UUIDs, names, packet payloads, or packet contents.

These fixtures validate v2.0.0 behavior at bounded sizes alongside the current operator-policy tests.

**On this page**

- [Fixture contract](#fixture-contract)
- [Corpus inventory](#corpus-inventory)
- [Executable replay paths](#executable-replay-paths)
- [Calibration decision](#calibration-decision)
- [Performance boundary](#performance-boundary)

## Fixture contract

The three strict YAML documents under `testdata/replay/` use schema version 1. Every fixture must provide all of the following fields:

- bounded input observations and collection cadence;
- expected and forbidden metric families;
- an inclusive expected severity range;
- ordered, deduplicated state transitions;
- one expected alert or the literal `none`;
- forbidden alerts;
- maximum expected detection delay; and
- expected recovery behavior.

Unknown YAML fields fail validation. The replay corpus uses a scoped baseline of 136 metric families and 78 alert definitions, plus a closed set of internal behavior classifications. These are fixture inventories, not the complete release surface. Current inventory/retype telemetry and the 82-definition operator policy have separate executable coverage. Fixture identifiers are globally unique, and the inventory test requires the exact 16/15/20 split.

The fixture schema deliberately accepts only aggregate observations: counts, ratios, bounded signal values, source tags, status classes, and lifecycle operation names. A separate contract rejects fields or serialized values that resemble tenant identifiers or payload data.

## Corpus inventory

| Corpus | Count | Required cases |
| --- | ---: | --- |
| Benign | 16 | Web server, reverse proxy, DNS resolver, SMTP relay, database server, database replication, monitoring server, VPN appliance, package update, backup process, high legitimate CPU, high legitimate IOPS, high legitimate connection count, high legitimate remote breadth, alternate-port web service, and a long-lived ordinary TCP connection |
| Abusive | 15 | Horizontal scan, vertical scan, distributed probe, inbound service spray, SMTP abuse, UDP flood, single-target flood, conntrack exhaustion, dedicated-port mining, shared-port mining with high CPU, shared-port traffic without mining corroboration, low-CPU/GPU-like mining, Tor contact, known-bad contact, and one remote present in overlapping threat lists |
| Failure/lifecycle | 20 | IPv4 failure, IPv6 failure, truncated dump, malformed Netlink message, ENOBUFS, timeout, Libvirt outage, per-domain Libvirt failure, counter reset, live migration, cold migration, reboot, shutdown, deletion, IP reuse, duplicate tenant IPs in separate OVN zones, exporter restart, feed outage, feed recovery, and temporary missing resource counters |

## Executable replay paths

### Behavior classifier

The behavior replay constructs aggregate `BehaviorFeature` observations and executes the production classifier, severity scorer, alert-transition persistence, mining confirmation state, cooldown behavior, and clean-cycle recovery. It checks emitted metric presence, severity range, exact state progression, expected classification, detection deadline, and recovery result for every behavior fixture.

### Threat-feed overlap

The threat replay executes production threat-signal collection and source-set history. Per-source evidence remains visible, but Overlapping threat feeds are scored from one deduplicated flow union. The overlap fixture proves that five canonical flows present in two lists produce five combined hits, not ten, while retaining both per-source metric families.

### Failure and recovery

The failure/lifecycle replay invokes the production conntrack reader and aggregation failure paths, source-health state, resource sample baselines, runtime-generation boundaries, VM/IP ownership, OVN zone attribution, behavior reset, threat-feed availability, and missing-axis retention/recovery logic. Partial family reads remain partial, complete read failures remain unavailable, and incomplete observations cannot manufacture healthy zeroes.

### Alert evaluation

The Prometheus replay renders each benign fixture as an input series and evaluates all ten security rules in the scoped baseline fixture with `promtool`. It includes the configured collection interval, source-health gates, and enough evaluation time for every rule's pending duration. No benign fixture produces a warning-level security alert in that baseline. The current enabled policy is evaluated separately by `make operator-test`.

### Run the gate

Run the complete replay-calibration gate with:

```sh
make replay PROMTOOL="$(command -v promtool)"
```

The mandatory workflow invokes that target explicitly in addition to the complete package, race, shuffled, coverage, and public-contract gates.

## Calibration decision

All 15 abusive fixtures produce their intended evidence. High-confidence scans, floods, exhaustion, and dedicated-port mining reach their intended internal classification within the declared deadline. Shared-port mining reaches the bundled warning only after persistence plus sustained CPU corroboration. Shared-port traffic without corroboration and low-CPU/GPU-like traffic retain mining evidence without being promoted to an unsupported warning. Tor and known-bad contacts retain their source identity, while the overlapping-list case retains both sources without double-counting the combined signal.

All 16 benign fixtures remain below every warning-level security rule in the scoped baseline. All 20 failure/lifecycle fixtures preserve missing-versus-zero semantics, freeze or reset state at the appropriate boundary, and recover through a fresh baseline rather than charging outage or migration time.

The fixture-backed calibration retains the documented production thresholds. Any later threshold change must name the fixture it improves, add or update a permanent expectation, preserve the prior golden contracts unless the public change is intentional, and pass both replay and the complete required CI graph.

## Performance boundary

This corpus proves behavioral correctness and alert calibration at representative bounded sizes. It does not claim capacity, latency, allocation, lock-contention, or cardinality results at production scale. Scaling validation owns production-scale performance measurements and bounded-behavior benchmarks.
