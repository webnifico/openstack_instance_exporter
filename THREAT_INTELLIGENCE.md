# Threat intelligence and feed lifecycle

[Documentation index](DOCUMENTATION.md) · [Project README](README.md)

Threat intelligence makes threat-list history depend on complete elapsed-time observations, counts overlapping feed matches once in combined severity, and bounds evidence reporting under hostile traffic. The threat subsystem uses the five configured feed sources and their documented metric families. The supported feeds remain Spamhaus, Tor Exit, Tor Relay, Emerging Threats, and the local custom list.

**On this page**

- [Time-correct scoring](#time-correct-scoring)
- [Feed overlap and per-list evidence](#feed-overlap-and-per-list-evidence)
- [Atomic feed lifecycle](#atomic-feed-lifecycle)
- [Bounded evidence and state](#bounded-evidence-and-state)
- [Public interface compatibility](#public-interface-compatibility)

## Time-correct scoring

The background collection interval defaults to 15 seconds and its supported range remains 5 seconds through 1 minute, inclusive. Threat history uses the complete conntrack snapshot's shared observation timestamp rather than assuming a fixed collection cadence.

`-threat.ewma_tau` configures the threat-history time constant. Its default is `2m30s` and startup requires a duration greater than zero. The matching Ansible variable is `openstack_instance_exporter_threat_ewma_tau`.

For an eligible elapsed interval `dt` and configured time constant `tau`, the history update is:

```text
alpha     = 1 - exp(-dt / tau)
ewma_next = ewma_previous + alpha * (instant - ewma_previous)
```

The production instant signal is `min(1, unique_active_threat_flows / 10)`. The exported threat contribution remains `clamp(0.5 * instant + 0.5 * ewma, 0, 1)`.

### Time and identity boundaries

The first complete observation initializes history to the current instant signal, including a valid observation at Unix epoch zero; the explicit initialized state is the sentinel. Another evaluation at the same timestamp does not advance history. A strictly regressing timestamp rebaselines history to the current instant and new timestamp instead of applying negative elapsed time.

Global conntrack failures and per-instance Libvirt unavailability freeze the logical clock; recovery shifts the global and per-instance clocks by the exact union of unavailable intervals, so only successful elapsed time counts. Confirmed deletion, stopped or paused state, an observed runtime-generation or QEMU-incarnation boundary, and authoritative fixed-IP membership replacement or detach clear the affected instance history. Fixed-IP ordering alone is not a boundary. One history entry is retained per active instance UUID and inactive UUIDs are pruned.

These rules make the same workload comparable at 10-, 15-, and 30-second collection cadences.

### Retained output

An incomplete conntrack observation or per-instance Libvirt-unavailable observation retains the exact last-fresh combined threat severity; it does not recompute the burst component from different evidence while merely freezing the EWMA. EWMA, timestamp, per-list counters, contact identity, and structured evidence remain frozen with it. If that exact instance has no last-fresh combined state, threat severity is unavailable and omitted. A known stopped or paused state clears retained threat history and output, which remain unavailable until a later eligible running observation establishes new state.

## Feed overlap and per-list evidence

Every matching conntrack flow is inserted once into a per-instance combined union while the complete dump is visited. Its canonical identity contains the unordered endpoint IP/port pair, protocol, and ICMP identity fields. A flow listed by Tor Exit and Tor Relay, Spamhaus and Emerging Threats, or a public feed and the custom list therefore contributes one combined active contact, not one contact per list.

The combined union retains an exact deterministic subset of at most 5,000 canonical flow identities per instance. Once that cap is reached, the retained set proves a conservative lower bound and the dropped scalar is an overflow marker; duplicate or reordered raw entries mean it is not an exact unique tail cardinality. Combined severity is already saturated at `1` far below the cap, so tail uncertainty cannot raise it further. Production scoring applies no feed-count or list-class bonus.

For synthetic aggregates that predate the combined union, retained known keys are deduplicated and unknown capped tails use the largest single-source lower bound rather than being added together.

Overlap deduplication changes only combined severity. Every enabled and usable list keeps its existing per-list active-flow metric, contact counter, and structured evidence. One list cannot erase another list's attribution, and overlap cannot multiply a single connection's effect on `oie_instance_threat_list_severity`.

## Atomic feed lifecycle

An enabled feed is unavailable before its first successful load: refresh timestamp, duration, entries, and errors start at zero, no set is usable, and no per-instance list metric or score input is emitted from that source.

A generic provider refresh becomes visible only after the complete response or stable local file has been read, parsed, and validated as a non-empty set. The exporter owns an immutable copy and atomically replaces the entire old set, entry count, last-success timestamp, and last-success duration. IPv4-only, IPv6-only, and dual-family generic feeds are valid. Addresses removed from a successful refresh disappear immediately.

Timeouts, non-200 responses, response-body errors or declared-length mismatches, oversize data, empty data, malformed data, a mixed valid/invalid body, and a local file that changes while being read all reject the attempt. A rejected attempt publishes no partial data, preserves the exact last-good set, entries, timestamp, and successful duration, and increments that provider's cumulative error counter once.

### Spamhaus atomic publication

Spamhaus IPv4 and IPv6 are one atomic snapshot. Every configured family must download, parse, and validate with the correct address family and no unusable catch-all CIDR. If any configured family fails, the complete previous dual-family snapshot is retained. The Spamhaus error counter increments once for each failed configured family request. A successful refresh replaces both families together, clears an unconfigured family, and removes CIDRs no longer present.

### Retry schedule and diagnostics

Enabled Tor exit, Tor relay, Emerging Threats, custom-file and Spamhaus feeds share one refresh scheduler. With a positive refresh interval, a failed initial load or later refresh retries after 30 seconds, then 1, 2, 4 and 5 minutes, capped at 5 minutes; a shorter configured interval remains the upper bound. Each delay starts after the previous attempt completes. Success resets the retry delay and resumes the configured normal interval. Explicit startup-only configurations (`refresh <= 0`) retain their single-attempt behavior. Pending retry waits stop promptly on exporter shutdown. No additional flags or Ansible variables are required.

HTTP failures identify known timeout, DNS, TLS certificate, connection-refusal/reset, unreachable-host and truncated-response causes without printing configured URLs, query tokens or proxy credentials. HTTP status errors retain their numeric status. Unclassified transport failures keep the generic request-failed message. Custom-file failures retain their existing file/parser diagnostics. Failed loads never advance the last-success timestamp or extend snapshot freshness; Spamhaus publishes only after every configured address family succeeds.

### When a snapshot is usable

| Feed state | Usable for matching/scoring | Host lifecycle metrics |
| --- | --- | --- |
| Never successfully loaded | No; unavailable | Zero timestamp, duration, entries, and errors until an attempt fails |
| Last-good age at or below `max(2 * refresh, 1m)` | Yes; fresh or retained after a failed refresh | Last-good entries, timestamp, and successful duration remain visible; errors are cumulative |
| Last-good age above `max(2 * refresh, 1m)` | No; stale/unavailable | Retained entries and last-success data remain visible for diagnosis |
| Successful recovery | Yes; the complete new set replaces last-good atomically | Timestamp, successful duration, and entries advance; cumulative errors remain |

The exact maximum-age boundary is usable. A last-success timestamp more than five minutes in the future is unavailable. A successfully loaded one-shot provider with `refresh <= 0`, including a one-shot custom file, remains usable indefinitely. When a source is unavailable it is excluded from the conntrack snapshot's source-inclusion contract, so its retained bytes cannot emit per-list instance samples or advance threat history.

### Recovery after source loss

A complete conntrack interval with zero usable threat sources makes combined threat output unavailable, even when an older numeric history value remains internally retained. The first later eligible interval after that source outage silently rebaselines the instant, EWMA, and observation timestamp, so unavailable wall time cannot enter the EWMA. That recovery interval can expose current per-list metrics and silently replaces each per-list previous-contact identity with the recovered current keys, but it does not increment cumulative contact counters or emit instance threat-hit summaries.

The next unchanged complete interval therefore cannot manufacture outage-time new contacts. Normal contact and evidence transitions resume on the next eligible complete interval. Initial feed availability with no prior threat history is an initial observation, not a recovery from retained state.

## Bounded evidence and state

Threat traffic is summarized per instance and list rather than logged once per matching flow. One eligible report preserves the exact legacy `threat_list_hit` event for its first canonical representative and adds one `threat_list_summary` event containing active, retained, and dropped counts plus a deterministic evidence sample.

The bounds are:

| State or output | Bound |
| --- | ---: |
| Matching flow identities retained per instance/list | 5,000 |
| Previous contact identities retained per instance/list | 5,000 |
| Representative evidence records per summary | 4 |
| Global `THREAT`/`POLICY` repeat-throttle keys | 4,096 |
| Default repeat interval per instance/list | 5 minutes |
| Line-feed input | 8 MiB |
| Onionoo JSON input | 32 MiB |

Representative evidence is ordered by ascending canonical flow identity. `active_flows` is the saturating sum of retained hits and the overflow marker; above the 5,000-identity cap it is not presented as exact unique cardinality. `evidence_count` and `evidence_capped` state exactly how much endpoint detail is present. Throttle capacity suppresses unseen keys until expired entries are cleaned instead of growing memory. `-threat.log.min_interval=0` remains an explicit operator opt-out from repeat throttling; even then, one collection emits at most one legacy hit and one summary per instance/list, never one event per flow, and no throttle map is populated.

The summary's `direction` records the configured list scope as `outbound`, `inbound`, or `any`. Each representative records source and destination IP/port, protocol, ICMP ID/type/code, and its flow-derived direction, falling back to the configured scope only for ambiguous or VM-to-VM evidence; the legacy event uses the first representative's direction. A dropped-only summary has empty legacy scalar endpoints and an empty representative array. Count addition saturates instead of overflowing, and the repeat-throttle gate runs before evidence sorting.

Incomplete conntrack and per-instance-unavailable collections preserve the exact last-fresh combined severity without updating contact identities, counters, EWMA, or summaries. Threat state is pruned with the exact instance lifecycle. Merely retaining combined output during an incomplete observation cannot create new structured workload evidence, and an unavailable feed's retained bytes are likewise excluded.

An authoritative fixed-IP set replacement or detach, runtime-generation or QEMU-incarnation change, and known stopped or paused state start a new threat episode for the UUID. They clear Intel history and combined output, every provider's previous-contact identity including Spamhaus, and that instance's summary cooldown. Cumulative per-list Prometheus contact counters deliberately remain monotonic for a still-active UUID. Unrelated instance, host-provider, and policy throttle state is untouched. Confirmed instance deletion prunes the identity's complete state, while a known non-running instance remains unavailable until a later eligible running observation establishes new history.

## Public interface compatibility

Threat intelligence preserves existing feed metric names and labels, with layered regression fixtures protecting scoring and lifecycle behavior. Its public additions are limited to the positive `threat.ewma_tau` CLI/Ansible setting and the additive `threat_list_summary` structured-log schema. Existing feed names, per-list metrics, labels, counters, the legacy `threat_list_hit` schema, alert assets, and dashboard assets remain unchanged.
