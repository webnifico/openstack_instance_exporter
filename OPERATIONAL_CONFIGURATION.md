# Operational configuration

[Documentation index](DOCUMENTATION.md) · [Project README](README.md)

The v2.0.0 operational configuration combines a verified exporter archive, one Prometheus alert group and five Grafana dashboards. Deployment inputs and runtime behavior are tested against the assets shipped in this repository.

**On this page**

- [Prometheus alerts](#prometheus-alerts)
- [Ansible role](#ansible-role)
- [Grafana](#grafana)
- [Validation](#validation)

## Prometheus alerts

The example contains one concise alert group with 82 definitions and ten shared recording rules. It enables 33 alerts by default: 30 warnings, one informational mining candidate and two critical host-impact alerts. The remaining 49 diagnostics are opt-in through `enabled: false`; the deployment template must honor that field when rendering native Prometheus rules.

Shared recording rules cover current source health, five-minute observation windows, running instances, resource-axis freshness, feed availability and corroborated host impact. Source failures interrupt pending workload alerts. Detailed thresholds, incident identity and retype-warning semantics are documented in [PROMETHEUS_ALERTS.md](PROMETHEUS_ALERTS.md).

## Ansible role

The role runs the service as root for direct local Libvirt and raw conntrack access. Its defaults select the v2.0.0 Linux amd64 GitHub release URL and pin the bundled archive's SHA-256.

### Select the archive

Set `openstack_instance_exporter_archive_src` to use a local controller archive. A non-empty local path takes precedence over `openstack_instance_exporter_download_url`, so no URL override is needed. The default checksum also verifies the bundled local archive. When selecting a different archive or release, set its matching `openstack_instance_exporter_sha256`.

The release asset must be published before URL-based installation can download it. Installation, restart and cleanup behavior are described in [DEPLOYMENT_HARDENING.md](DEPLOYMENT_HARDENING.md), with examples in the [role README](ansible_role/openstack_instance_exporter/README.md).

### Collection options

Host threat matching without an explicit `host.interfaces` selection uses `bgp-nic`; explicit selections are validated. Collection defaults to `15s` and accepts `5s` through `1m`. Volume-retype monitoring is disabled by default in every profile. Enable it with `openstack_instance_exporter_volume_retype_enable: true`. Ordinary Libvirt collection retains its safety checks whether or not retype monitoring is enabled.

## Grafana

The Cluster, Hypervisor, Project, Instance and Threat List Overview dashboards retain their public UIDs and datasource variables. Import all five JSON files together. The current set includes inactive instance inventory, scope controls, Top N selection, coverage indicators and opt-in timeline annotations. Cluster and Project include attached-volume retype tables. The Threat List Overview includes per-feed investigation and long-window behavior/resource views.

See [DASHBOARDS_AND_DOCUMENTATION.md](DASHBOARDS_AND_DOCUMENTATION.md) for measurement and visibility semantics, and the [Grafana example](examples/grafana_dashboard_example/README.md) for import instructions.

## Validation

Run `make docs`, `make ansible-test`, `make ansible-preflight` and `make operator-test` with the required tools installed. These checks parse the dashboards and rendered rules, validate the role and unit, and exercise the deployed operator policy. `make check` runs the complete release verification graph. Source and synthetic checks do not replace live deployment testing.
