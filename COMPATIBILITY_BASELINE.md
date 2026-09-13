# Compatibility baseline

[Documentation index](DOCUMENTATION.md) · [Project README](README.md)

**v2.0.0 is the next release after v1.2.0.** Release notes and upgrade comparisons use v1.2.0 as the published baseline. All intervening development changes belong to v2.0.0.

**On this page**

- [Public interfaces](#public-interfaces)
- [Regression evidence](#regression-evidence)
- [Validation](#validation)

## Public interfaces

The v1.2.0 compatibility fixtures preserve 126 metric names and label sets, 48 CLI flags, 63 public Ansible variables, five dashboard UIDs and 69 alert names. Tests compare these interfaces with the current exporter and assets, allowing only explicitly recorded changes.

The v2.0.0 exporter defines 148 `oie_*` metric families and 51 runtime flags. Optional families appear only when their collection requirements are met. The example alert policy contains 82 definitions, of which 33 are enabled by default, plus ten recording rules. All five dashboard UIDs are retained. See the complete metric catalog and runtime defaults in [README.md](README.md).

Five threat-feed refresh-error families are corrected from gauges to counters. Their names and labels are retained. The attention metric's help text is corrected, and the compatibility manifest records the approved metric, alert and role additions. Stricter startup validation rejects invalid explicit configuration; the runtime log-level endpoint uses POST for changes. Review [CONFIGURATION_AND_HTTP.md](CONFIGURATION_AND_HTTP.md) when upgrading.

## Regression evidence

`testdata/compatibility-v1.2.0-compatibility-contract.golden.json` records the stable public interfaces and approved differences. The metric, CLI and alert fixtures with `v1.2.0` in their names identify the published baseline.

Fixtures named `baseline` capture development checkpoints used by layered regression tests; they are not release inventories. Their source identity is retained by commit (`2d04a3914130cbe8e4e07ae1c71b8b4e1e012e8c`). Release-only metadata in these fixtures is normalized to v2.0.0, and structured-log fixture metadata uses an independent schema version. Metric expectations, labels, formulas, alert expressions, dashboard queries and rendered argument contracts retain their recorded values. Checksum manifests protect the resulting fixtures and their references.

Additional fixtures cover source health, resource freshness, behavior and mining, threat history, alert lifecycles, runtime configuration, inventory and optional volume-retype monitoring. Earlier scoped fixtures remain useful regression evidence; the production descriptor registry, current dashboard snapshot and rendered operator-policy tests define the shipped surface.

## Validation

```bash
make contracts PROMTOOL=/path/to/promtool
make docs PROMTOOL=/path/to/promtool
make operator-test PROMTOOL=/path/to/promtool
```

`make check` runs the complete verification graph described in [CI_AND_RELEASE_VALIDATION.md](CI_AND_RELEASE_VALIDATION.md). Numerical comparisons with the published baseline and their limits are documented in [ACCURACY_VALIDATION.md](ACCURACY_VALIDATION.md).
