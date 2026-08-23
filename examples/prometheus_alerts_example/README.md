# Prometheus alert example

`openstack_instance_exporter_alerts.yml` uses the repository/OpenStack-Ansible templated variable format. It is not a native Prometheus rule file.

Render the file through the applicable OpenStack-Ansible/Jinja configuration before installing the rendered output as a Prometheus rule file. Do not point Prometheus `rule_files` directly at this example.

Validate the rendered file before reloading Prometheus:

```bash
promtool check rules /path/to/rendered-openstack-instance-exporter.rules.yml
```
