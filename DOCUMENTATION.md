# Documentation index

[Project README](README.md)

Start with the task you need to complete. The [main README](README.md) contains the overview, operating examples and complete metric and runtime-flag references.

**On this page**

- [Install and upgrade](#install-and-upgrade)
- [Operate and investigate](#operate-and-investigate)
- [Validate and maintain](#validate-and-maintain)
- [Reference shortcuts](#reference-shortcuts)
- [When editing documentation](#when-editing-documentation)

## Install and upgrade

| Guide | Use it to |
| --- | --- |
| [Ansible role](ansible_role/openstack_instance_exporter/README.md) | Install OIE, select a release archive, configure flags and apply a playbook |
| [Operational configuration](OPERATIONAL_CONFIGURATION.md) | Connect the exporter, Prometheus rules and Grafana dashboards |
| [Deployment safeguards](DEPLOYMENT_HARDENING.md) | Understand archive verification, systemd, restart and cleanup behavior |
| [v2.0.0 operator guide](OPERATOR_UPDATE.md) | Prepare inventory views, dashboard imports and the default alert policy |
| [Release package](PACKAGE_MANIFEST.md) | Find source files and release assets, and verify the archive |
| [Compatibility baseline](COMPATIBILITY_BASELINE.md) | Compare the public interfaces with the published v1.2.0 release |

## Operate and investigate

| Guide | Use it to |
| --- | --- |
| [Grafana dashboards](examples/grafana_dashboard_example/README.md) | Import the five dashboards and interpret scope, coverage and retype tables |
| [Prometheus rule installation](examples/prometheus_alerts_example/README.md) | Render and validate the example rules before installing them |
| [Prometheus alert policy](PROMETHEUS_ALERTS.md) | Check defaults, thresholds, persistence and incident identity |
| [Configuration and HTTP](CONFIGURATION_AND_HTTP.md) | Check accepted values, file validation, HTTP limits and log-level changes |
| [Source health](DATA_INTEGRITY.md) | Distinguish fresh, retained and unavailable Libvirt or conntrack data |
| [Resource telemetry](RESOURCE_TELEMETRY.md) | Interpret CPU, memory, disk and network freshness and recovery |
| [Behavior and mining](BEHAVIOR_AND_MINING.md) | Understand evidence, persistence, CPU corroboration and lifecycle resets |
| [Threat intelligence](THREAT_INTELLIGENCE.md) | Understand feed freshness, retries, overlap and bounded evidence |
| [Libvirt collection safeguards](LIBVIRT_COLLECTION_SAFETY.md) | Explain deferred measurements and collection around VM and storage jobs |
| [Scaling limits](SCALING_LIMITS.md) | Choose a collection interval using measured processing and state bounds |

## Validate and maintain

| Guide | Use it to |
| --- | --- |
| [Measurement accuracy](ACCURACY_VALIDATION.md) | Check measurement definitions, baseline comparisons and validation limits |
| [Dashboard and metric reference rules](DASHBOARDS_AND_DOCUMENTATION.md) | Keep queries, units, labels and documentation consistent |
| [Replay calibration](REPLAY_CALIBRATION.md) | Understand the benign, abusive and failure/lifecycle corpus |
| [Operator integration tests](integration_tests/README.md) | Run dashboard and rendered-alert scenarios |
| [CI and release validation](CI_AND_RELEASE_VALIDATION.md) | Run the required gates, validate archives and maintain dependency pins |

## Reference shortcuts

- [Every metric family](README.md#appendix-a-metric-reference)
- [Every runtime flag and default](README.md#tuning-and-configuration)
- [Structured log fields and examples](README.md#appendix-b-log-schema-and-examples)
- [Troubleshooting](README.md#troubleshooting)
- [Glossary](README.md#appendix-c-glossary)

## When editing documentation

Keep runtime flags, metric names, labels, units and default values exact. Link to the focused guide for lifecycle details, keep procedures in execution order, and separate measurements from inferences. Historical fixture inventories describe their recorded checkpoint; the current catalog and rendered operator policy describe the release.

Run `make docs PROMTOOL=/path/to/promtool` from the repository root after changing documentation or dashboards. The required CI graph also runs the complete test suite.
