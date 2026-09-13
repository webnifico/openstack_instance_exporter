# Behavior and mining evidence

[Documentation index](DOCUMENTATION.md) · [Project README](README.md)

Behavior and mining decisions depend on complete observations tied to the same instance and fixed-IP identity. It does not add metric families or turn OIE into a packet-capture IDS.

**On this page**

- [Supported cadence and persistence](#supported-cadence-and-persistence)
- [Failure, recovery, and lifecycle boundaries](#failure-recovery-and-lifecycle-boundaries)
- [Generic behavior semantics](#generic-behavior-semantics)
- [Mining evidence and independence](#mining-evidence-and-independence)
- [Behavior-event ownership and bounded state](#behavior-event-ownership-and-bounded-state)

## Supported cadence and persistence

The background collection interval defaults to 15 seconds. The supported range is 5 seconds through 1 minute, inclusive; startup rejects values outside that range.

Every persistence gate requires both the configured number of consecutive complete qualifying collections and the minimum eligible elapsed time below.

| Required qualifying collections | Minimum eligible elapsed time |
| ---: | ---: |
| 2 | 15 seconds |
| 3 | 30 seconds |
| 6 | 75 seconds |

### Candidate start and reset

The first qualifying collection starts a candidate. A later complete collection advances it only when the same candidate still qualifies. A complete clean collection, a different generic kind, rule source or rule ID, or a different pending mining endpoint breaks consecutiveness. The old candidate is reset; a different generic candidate starts again at one. A candidate whose last qualifying complete observation is more than 180 seconds old is reset, while the exact 180-second boundary remains eligible. A backward clock movement resets the candidate.

Hit count and elapsed time are independent gates. Fast collections cannot satisfy a gate from count alone, and wall time cannot satisfy one without enough qualifying collections.

## Failure, recovery, and lifecycle boundaries

An incomplete Libvirt or conntrack cycle is not negative evidence and is not a qualifying observation. Last-good behavior and confirmed-mining output is retained, while EWMA, persistence hits, eligible elapsed time, cooldowns, evidence events, and endpoint-switch qualification are frozen. A failed cycle therefore cannot mature a pending candidate.

### Recovery baseline

The first complete conntrack cycle after a failure is a silent statistical rebaseline. Matching positive evidence may preserve an existing candidate or confirmed episode, but it does not advance hits or emit an event. Clean or changed recovery evidence clears the pending candidate and does not seed a replacement until a later complete interval. A clean recovery also clears a confirmed mining episode.

### Identity boundaries

Behavior, mining, and behavior-event state is owned by the exact instance UUID and fixed IP. It is cleared on confirmed deletion, fixed-IP detach, known stopped or paused state, QEMU process-incarnation change, and CPU-time rollback. Cleanup of one fixed IP cannot remove another fixed IP's state. When Libvirt state is unavailable rather than known stopped, affected instance clocks and last-good output freeze instead of being treated as a clean observation.

## Generic behavior semantics

The generic classifier is first-match-wins. Built-in rules run first in their declared order; external YAML rules run afterward in file order. External rules are additive and cannot override or reprioritize a matching built-in rule.

A pending generic candidate is identified by instance UUID, fixed IP, direction, behavior kind, rule source, and rule ID. Evidence remains protocol- and direction-scoped: TCP flood evidence is TCP-only, UDP evidence cannot borrow TCP volume, inbound and outbound evidence cannot mix, and horizontal, vertical, distributed, and single-remote patterns retain their distinct topology. When host-level pressure is attributed across several fixed IPs, one deterministic largest contributor owns the generic event.

The audited first-match outcomes preserve these distinctions:

| Evidence shape | Generic outcome contract |
| --- | --- |
| Dark-space plus protocol evidence | The combined `darkspace_plus_physics` kind wins over either standalone kind |
| Dark-space plus scan evidence | The combined `darkspace_plus_scan` kind wins over either standalone kind |
| Outbound many remotes on one dominant port | Horizontal scan; pure UDP fan-out remains a UDP protocol detection |
| Outbound many ports on one dominant remote | Vertical scan |
| Inbound many new remotes on a dominant service | Service spray |
| Inbound many new remotes without a dominant service | Distributed probe |
| Inbound one dominant remote across many ports | Single-remote multi-port probe |
| TCP or UDP flood | Only that transport's counts, replies, and concentration qualify it |
| Host conntrack pressure | One deterministic largest fixed-IP/direction contributor owns the event |
| EWMA anomaly | Evaluated after the more specific built-in evidence classes |
| External YAML match | Evaluated only after every built-in class declines to match |

### External rules and EWMA

An external rule evaluates only the traffic selected by its configured port set. It cannot borrow whole-direction flow, remote, reply, byte, packet, concentration, or protocol evidence from unrelated traffic. If bounded collection cannot prove the rule's scoped evidence, the rule fails closed. External rules participate only in the generic classifier; they neither replace the built-in mining catalogue nor alter mining persistence.

EWMA anomalies follow the same completeness and identity rules. A failure, recovery rebaseline, clock rollback, or runtime-identity boundary cannot manufacture elapsed history or a behavioral spike.

## Mining evidence and independence

Mining has a dedicated lifecycle independent of the generic first-match classifier. A scan, flood, dark-space, external, or EWMA match may select the generic kind, but it cannot suppress a valid mining candidate or lend that candidate persistence.

Every mining candidate must be an outbound TCP connection to a public, non-VM destination with kernel `SEEN_REPLY` or `ASSURED` evidence. Qualification and published labels come from one real remote-IP/port pair. Counts independently aggregated by port or remote cannot be combined into a nonexistent endpoint, and unrelated web or fan-out traffic cannot satisfy that pair's thresholds.

| Confidence | Pair evidence | Persistence | Direct exporter warning |
| --- | --- | --- | --- |
| `high` | At least two replied flows on a dedicated endpoint | 2 collections and 15 seconds for P1/P2; otherwise 3 collections and 30 seconds | Yes |
| `high_persistent` | One replied flow on a dedicated endpoint | 3 collections and 30 seconds | No; CPU corroboration or the informational fallback is required |
| `shared` | At least three flows, at least two replied, concentrated on one shared endpoint with a limited destination set | 3 collections and 30 seconds | No; CPU corroboration is required |
| `shared_persistent` | One or two replied flows concentrated on one shared endpoint | 6 collections and 75 seconds | No; CPU corroboration is required |

### CPU corroboration and structured events

A shared-port match by itself can never produce a warning or floor generic behavior severity. Candidate tiers remain observable through `oie_instance_mining_suspected` only after their internal gate. The bundled Prometheus warning requires fresh CPU telemetry for every tier and two additional minutes of alert persistence. The `high_persistent`, `shared` and `shared_persistent` tiers also require their five-minute CPU thresholds and minimum sample counts, as listed in the [mining rule reference](README.md#built-in-mining-pool-coverage). The `high` tier alone is eligible for a direct structured mining event and severity floor.

### Endpoint replacement

After an endpoint is confirmed, a change to another mining endpoint remains in the same episode. The old endpoint labels and active metric remain visible while the replacement pair starts its own persistence gate. The replacement is published only after it qualifies; it cannot borrow the old endpoint's hits. A complete cycle with no valid mining evidence ends the episode and removes the metric.

## Behavior-event ownership and bounded state

The behavior transition lifecycle is the sole cooldown and change-detection authority for structured behavior events. The generic threat-event throttle cannot suppress a behavior transition that already passed its own gate. Threat-list and policy events retain their independent throttling.

Behavior-event state is cleared with its exact instance lifecycle. Its global safety bound evicts the oldest state first, deterministically, so capacity pressure cannot choose an arbitrary active identity.

Behavior and mining preserves the public metric identities documented in the v2.0.0 metric catalog. It changes the trustworthiness and lifecycle of existing behavior and mining signals, not their public metric identity.
