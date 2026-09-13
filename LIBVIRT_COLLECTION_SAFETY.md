# Libvirt collection behavior

[Documentation index](DOCUMENTATION.md) · [Project README](README.md)

OIE observes domains through Libvirt. Read operations can still contend with Nova for the domain job and QEMU monitor. Exporter-side timeouts do not cancel requests already executing in libvirtd.

Retype lifecycle monitoring is opt-in through `-volume.retype.enable` (Ansible: `openstack_instance_exporter_volume_retype_enable: true`). It defaults to off, with no dedicated discovery, progress polling or retype metric samples. The collection policy below applies with either setting; normal resource queries still need these safeguards and can still reach the affected QEMU RBD metadata getter.

**On this page**

- [Retype observations](#retype-observations)
- [Collection policy](#collection-policy)
- [Missing measurements](#missing-measurements)
- [Limits and deployment validation](#limits-and-deployment-validation)
- [QEMU RBD metadata-query defect](#qemu-rbd-metadata-query-defect)

## Retype observations

When enabled, retype monitoring accepts domain XML only; malformed or unrelated XML cannot prove that a mirror disappeared. Copy-ready XML independently proves logical progress of 100%, including a first observation with libvirt's `cur=end=1` sentinel. The first ready timestamp is preserved through `ready="pivot"` or `ready="abort"` and into the terminal observation. These finalization phases remain active until XML shows the mirror gone; active status 1 covers copying or finalizing without a current `ready="yes"` observation. Connection loss expires unconfirmed identity without manufacturing a terminal outcome. Shutdown takes precedence over a simultaneously ready poll timer.

See libvirt's [block-job progress API](https://libvirt.org/html/libvirt-libvirt-domain.html#virDomainGetBlockJobInfo) and [mirror XML semantics](https://libvirt.org/formatdomain.html#hard-drives-floppy-disks-cdroms).

## Collection policy

### Inventory query

Obtain active and retained inactive domain inventory with only state and interface statistics. These QEMU driver statistics do not require monitor access. Set `VIR_CONNECT_GET_ALL_DOMAINS_STATS_NOWAIT` on every statistics request, including this inventory query.

### Inactive definitions

Retain inactive definitions as inventory only, with their existing separate five-minute metadata cache. Read them with `VIR_DOMAIN_XML_INACTIVE` so a concurrent start cannot turn the request into a live-monitor query. Inactive definitions receive no resource enrichment or block-job polling.

### Control state

Inspect each active domain's control state before live XML or block-job progress queries. Occupied, running-job, error, unknown, and unreadable control states cause the observation to be deferred. There is no blocking fallback when control information or NOWAIT is unsupported.

### Local job markers

When `/run/libvirt/qemu/<domain>.xml` is available, read its UUID and active-job marker before a domain control query. This covers long-running asynchronous jobs between monitor commands, when ControlInfo may temporarily report idle. Every non-idle or unknown job marker defers work, including migration, save/dump, snapshot and backup. These reads are bounded, reject symlinks/nonregular files, and never modify Libvirt state. A missing/nonstandard status directory leaves the public control checks in force; a present but unreadable, mismatched or malformed status file defers the observation. This local status format is an additional guard, not a stable public Libvirt API.

### Live XML identity

Before resource statistics, read live XML and verify the requested UUID. Never use the five-minute metadata cache to decide whether a disk mirror exists. Reuse this fresh metadata for the collection cycle.

### Public disk mirrors

If any disk has a mirror, exclude `VIR_DOMAIN_STATS_BLOCK` from that domain's statistics request. Continue CPU, vCPU, balloon memory and interface statistics when the control/async-job checks permit. This includes local and network copies, active commits, ready/pivot/abort phases, and unrecognized mirror jobs. Disk identity remains present; omitted disk counters, capacity and allocation are not synthesized as zero.

### Saved block jobs

Also inspect the saved `blockjobs` children and its `active` flag immediately before resource statistics. Any child job, active flag or unknown flag excludes the block group even when public XML has no mirror; an explicitly inactive empty marker allows normal recovery. This covers ready, pull, commit, backup and future block-job types without using a monitor job to discover them. A storage-only deferral is distinct from malformed/unreadable status, a UUID mismatch or an active top-level async job: those conditions still defer all monitor-dependent collection. Lightweight retype progress keeps its separate ordinary control/async-job checks.

### Statistics request

Immediately recheck control state before requesting resource statistics for one domain. NOWAIT permits a partial reply if another client acquires the job before the stats request. Do not issue a full monitor-statistics request across all active domains.

### Concurrency limits

All production XML, progress, and statistics queries use one safety layer. A domain's raw request remains registered until the client call exits, even if the caller has timed out. There are four resource-observation workers, a shared eight-slot reader limit (including collection/inventory slots), and a guard against overlapping complete statistics requests.

### Timeout backoff

After a connect, statistics, XML, or progress timeout, or a returned Libvirt operation-timeout error, pause new Libvirt observation and reconnect attempts for at least one minute. This state survives connection replacement within the exporter process. After backoff, repeat control checks before monitor-dependent work. No collection attempt forces a pivot, aborts a block job, changes a VM, opens a disk image, or bypasses Libvirt with a direct QMP socket.

## Missing measurements

### Which measurements remain available

Metric names, labels, and formulas are preserved, including disk capacity and allocation measurements. Domains without an observed job provide the existing measurements. A live mirror or saved block job alone now defers only dynamic disk statistics: CPU usage, guest memory and network measurements can remain fresh. CPU/memory observations can still be absent if the monitor is busy, another async job is active, status is unreadable, or NOWAIT returns partial fields.

Network counters are collected with the host-side inventory request and do not require QEMU monitor access. Existing per-axis freshness/availability metrics and bounded sample retention describe missing data; they do not advance pressure or persistence using invented zero samples. When metadata cannot be established, the existing complete-cycle fallback reports unhealthy Libvirt visibility and retains the last good cycle.

### Why disk deferral covers the whole VM

Disk deferral covers every disk attached to the affected VM, including disks without a mirror, because Libvirt's bulk block-statistics path probes storage information across the VM. Filtering the returned disk records would happen after that probe. The per-disk `virDomainBlockStatsFlags` API avoids the capacity update in Libvirt 10.0 but still takes the shared domain query job and has no NOWAIT option; OIE does not add that fallback. Other VMs continue normal collection unless a timeout activates the existing host-wide Libvirt backoff.

Disk statistics resume automatically after the job clears. No additional polling loop or statistics RPC is introduced: each active domain still receives at most one resource-statistics request per normal collection cycle, with the block group included only when allowed.

### Retype observations during deferral

When retype monitoring is enabled, lifecycle observation remains separate: live mirror XML identifies copy-ready and terminal transitions, and guarded, paced block-job queries provide logical progress when available. A deferred progress observation is unavailable visibility, not an authoritative Nova/Cinder failure. OIE does not repair operations that already failed.

## Limits and deployment validation

NOWAIT avoids waiting to acquire a domain job; it does not impose a time limit after the job is acquired. Libvirt's XML and block-job APIs do not expose a NOWAIT flag. A management operation can also start after an idle-state or XML observation. These client-side protections reduce contention and prevent repeated observation requests after timeout; they cannot guarantee that every Libvirt/QEMU/storage version will be free of monitor stalls.

### Automated coverage

The automated tests cover saved block jobs and active flags without public mirrors, recovery after their removal, a marker appearing after public XML, continued disk identity/progress, busy/unknown/error control states, asynchronous jobs and recovery between monitor commands, operations beginning during preflight, NOWAIT partial replies, local/RBD/active-commit mirrors, missing measurements, domain replacement, inactive inventory and concurrent power transitions, expired deadlines, server and client timeout backoff, raw requests remaining in flight, and production call routing. Existing resource-lifecycle, retype, schema, alert, dashboard, and connection-timeout suites remain applicable.

The collection-to-Prometheus recovery test additionally exercises two VMs and two disks per VM with retype monitoring off and on. It verifies that a mirror on one disk, a saved ready job without a public mirror, or a saved active flag excludes block queries for the affected VM while keeping its CPU, memory and network observations fresh. The other VM retains every measurement group. Disk identity and guarded progress remain available, and disk I/O, capacity and allocation measurements recover after the job clears.

Additional regressions cover a busy monitor after mirror discovery, partial non-storage replies, non-storage timeouts and a status file becoming malformed, mismatched or asynchronously busy between guard checks.

### Deployment checks

A live OpenStack/Libvirt deployment is not available in the build environment. Before production rollout, use the lab to repeat attached-volume retype with OIE running, and exercise live migration, snapshot/backup, resize, disk attach/detach, reboot, and stop/start. Confirm that Nova completes the operations without statistics-held lock timeouts, that deferred observations are visibly unavailable, and that measurements recover afterwards. A real daemon or backend stall must be investigated rather than treated as fixed by a passing mock test.

## QEMU RBD metadata-query defect

Normal OIE resource collection includes Libvirt block statistics. On an affected QEMU build, the resulting `query-named-block-nodes` request can synchronously read an RBD encryption header and block QEMU while the storage read waits. A retype is not required to trigger the underlying defect. Deferring queries around detected jobs reduces exposure but does not make normal collection immune. OIE keeps all existing measurement groups instead of permanently disabling capacity/allocation collection.

QEMU's [upstream correction](https://github.com/qemu/qemu/commit/4af976ef398e4e823addc00bf1c58787ba4952fe) caches the information when the image opens. [Ubuntu bug #2166503](https://bugs.launchpad.net/ubuntu/+source/qemu/+bug/2166503) tracks the distribution backport. Verify patch presence in the exact distribution source and running QEMU build; package versions and backport availability change independently of OIE releases.

### Activate a corrected QEMU build

Existing VMs need a new QEMU process on the fixed build; installing a package, restarting Libvirt or rebooting inside a guest does not update that process. OIE does not install or alter QEMU. Other Libvirt clients require their own observation safeguards; OIE's protections do not change another collector's query behavior.

Upstream references: [bulk statistics API](https://libvirt.org/html/libvirt-libvirt-domain.html#virConnectGetAllDomainStats), [control-state API](https://libvirt.org/html/libvirt-libvirt-domain.html#virDomainGetControlInfo), [Libvirt 10.0 QEMU driver](https://github.com/libvirt/libvirt/blob/v10.0.0/src/qemu/qemu_driver.c), [local job-marker serialization](https://github.com/libvirt/libvirt/blob/v10.0.0/src/qemu/qemu_domainjob.c), [current QEMU driver](https://github.com/libvirt/libvirt/blob/master/src/qemu/qemu_driver.c).
