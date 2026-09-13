# Prometheus alert example

[Documentation index](../../DOCUMENTATION.md) · [Project README](../../README.md)

`openstack_instance_exporter_alerts.yml` uses the repository/OpenStack-Ansible templated variable format. It is not a native Prometheus rule file.

## Preserve template escaping

PromQL label quotes in the shipped default deliberately use triple-backslash escapes (`\\\"`). The outer YAML/Jinja layer consumes the extra escaping when it renders the native Prometheus rule file. Keep this form in the template source; do not reduce it to a single backslash there.

## Default policy

The v2.0.0 example contains one group with 82 alert definitions and ten shared recording rules. It enables 33 alerts by default (30 warnings, one informational candidate and two criticals); the other 49 definitions are opt-in. The renderer must emit `group_recording_rules` and omit alerts with `enabled: false`.

### Retype warnings

`OpenStackInstanceVolumeRetypeReadyStalled` warns only after OIE has observed an attached-volume block copy ready and awaiting pivot for ten minutes, then the rule remains true for one more minute. `OpenStackInstanceVolumeRetypeObservationUnhealthy` warns only when block-job observation has failed continuously for two minutes while the main Libvirt source remains healthy. The rules avoid duplicate warnings when the same operation is already in the ready-stalled state, and neither warning declares the authoritative Nova or Cinder outcome.

## Render, validate and install

Render the file through the applicable OpenStack-Ansible/Jinja configuration before installing the rendered output as a Prometheus rule file. Do not point Prometheus `rule_files` directly at this example.

Validate the rendered file before reloading Prometheus:

```bash
promtool check rules /path/to/rendered-openstack-instance-exporter.rules.yml
```

The full policy, thresholds and validation commands are documented in [PROMETHEUS_ALERTS.md](../../PROMETHEUS_ALERTS.md).
