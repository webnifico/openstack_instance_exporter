# Operator integration tests

[Documentation index](../DOCUMENTATION.md) · [Project README](../README.md)

These checks evaluate the shipped dashboards and rendered Prometheus alert policy with synthetic data. Run them from the repository root.

## Prerequisites

- Python 3 and ansible-core.
- An executable `promtool`; set `PROMTOOL` to its path.

## Run both checks

```bash
make operator-test PROMTOOL=/path/to/promtool
```

## Run one check

| Check | What it covers |
| --- | --- |
| `oie_dashboards_test.py` | Dashboard queries, variable interpolation and telemetry availability |
| `oie_alerts_test.py` | Rendered recording rules, enabled/disabled policy and alert lifecycles |

```bash
PROMTOOL=/path/to/promtool python3 integration_tests/oie_dashboards_test.py
PROMTOOL=/path/to/promtool python3 integration_tests/oie_alerts_test.py
```

## Interpret the results

The bundled Prometheus deployment template renders the definitions and recording rules used by these tests. The tests do not contact a live OpenStack, Prometheus or Grafana deployment.

Package validation results are recorded in [validation.json](validation.json). See [CI and release validation](../CI_AND_RELEASE_VALIDATION.md) for the complete verification graph.
