# Ansible Role: OpenStack Instance Exporter

## Requirements

N/A

## Role Variables

```yaml
openstack_instance_exporter_web_telemetry_path: "/metrics"
openstack_instance_exporter_install_dir: "/opt/openstack_instance_exporter"
openstack_instance_exporter_bind_port: 9120
openstack_instance_exporter_network_interface: br-monitoring # if not defined will use 0.0.0.0

# Example of User-Defined IOP Thresholds by Tier
openstack_instance_exporter_read_thresholds:
  - disk_tier: volumes # standard tier
    threshold: 500
  - disk_tier: premium
    threshold: 1500
  - disk_tier: ultra
    threshold: 2500
  - disk_tier: local
    threshold: 5000

openstack_instance_exporter_write_thresholds:
  - disk_tier: volumes # standard tier
    threshold: 500
  - disk_tier: premium
    threshold: 1500
  - disk_tier: ultra
    threshold: 2500
  - disk_tier: local
    threshold: 5000

# Cache expiration settings
openstack_instance_exporter_static_cache_expiration: 1h   # Default 1 hour
openstack_instance_exporter_dynamic_cache_expiration: 10s # Default 10 seconds

# Collection interval setting
openstack_instance_exporter_collection_interval: 10s # Default 10 seconds

# Logging settings
openstack_instance_exporter_enable_logging: false # Default is false (logging off)
```

## Dependencies

None.

## Example Playbook

```
    - hosts: compute
      roles:
        - role: openstack_instance_exporter
```

## License

Apache 2.0

## Author Information

xneelo cloud team