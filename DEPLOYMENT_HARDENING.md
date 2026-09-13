# Deployment and service safeguards

[Documentation index](DOCUMENTATION.md) · [Project README](README.md)

The v2.0.0 Ansible role installs one exporter per compute node on supported amd64 Ubuntu hosts with local QEMU/Libvirt. The shipped service runs as `root:root` for direct Libvirt and raw conntrack access. Raw conntrack collection requires host-namespace `CAP_NET_ADMIN` privilege. See [OPERATIONAL_CONFIGURATION.md](OPERATIONAL_CONFIGURATION.md) for the deployment inputs and optional features.

**On this page**

- [Release source and checksum](#release-source-and-checksum)
- [Configuration and restart](#configuration-and-restart)
- [systemd settings](#systemd-settings)
- [Disable and cleanup](#disable-and-cleanup)
- [Verification](#verification)

## Release source and checksum

The defaults select the versioned v2.0.0 Linux amd64 GitHub archive and its pinned SHA-256. Set `openstack_instance_exporter_archive_src` to use a local controller archive instead; it takes precedence over `openstack_instance_exporter_download_url`. The same checksum verifies either path, and a different archive requires its matching `openstack_instance_exporter_sha256`. The SHA-256 must contain exactly 64 hexadecimal characters. The role validates the selected profile, amd64 architecture, release-source selection and retype boolean before installation.

### Verification and extraction

The role stages the archive as `openstack_instance_exporter.tar.xz` in the installation directory. It verifies that this is a regular, non-symlink file and that its computed SHA-256 matches the configured value. A URL download additionally uses Ansible's checksum verification. The default URL becomes usable once the corresponding release asset is published.

The verified archive is extracted into the installation directory when the archive changes or the executable is absent, empty, non-regular or not executable. Use the archive produced by `scripts/build-release.sh`; `scripts/validate-release.sh` checks its exact member inventory, permissions, static amd64 executable and help probe before deployment. Extraction is directly into the installation directory, so deployment does not provide an atomic binary-swap guarantee.

## Configuration and restart

The role manages the systemd unit, optional logrotate configuration, custom-list input and inline behavior configuration. Relevant changes notify the restart handler. A changed unit triggers a daemon reload before the service is enabled and started. Unchanged managed inputs do not request a restart.

### Bind-address selection

An explicit `openstack_instance_exporter_web_listen_address` controls the bind address. Otherwise the unit derives it from the selected network interface's IPv4 fact. Missing interface facts fail rendering; there is no all-interface fallback in the unit template. The exporter also validates configured flags, local files and interface selections at startup, as described in [CONFIGURATION_AND_HTTP.md](CONFIGURATION_AND_HTTP.md).

## systemd settings

| Setting | Shipped value |
| --- | --- |
| `User`, `Group` | `root`, `root` |
| `Restart` | `always` |
| `RestartSec` | `3s` |
| `TimeoutStopSec` | `15s` |
| `NoNewPrivileges` | `true` |
| `PrivateTmp` | `true` |
| `ProtectHome` | `true` |
| Standard output/error | Journal, or `null` when exporter file logging is enabled |

The service requires access to local Libvirt, host `/proc` and `/sys`, and the conntrack Netlink interface. Enabled network threat feeds also require DNS and outbound HTTP(S). These settings do not create a dedicated service account or restrict the capability bounding set.

## Disable and cleanup

Setting `openstack_instance_exporter_enabled: false` stops and disables an existing service. To remove the installation, explicitly select `--tags cleanup_oie` when running the role's playbook. Before removing the managed installation directory, the role requires an absolute path and rejects `/`, `/etc`, `/opt`, `/usr` and `/var`. Cleanup stops and disables the service, removes its unit, reloads systemd and removes the managed files. The selected installation directory must be dedicated to OIE.

## Verification

Run `make ansible-test` and `make ansible-preflight` with the required `ansible.posix` collection installed. The syntax, render, negative-input and service-contract tests validate the shipped role. CI covers ansible-core 2.12.10 and 2.21.3. Actual host access, restart behavior and live collection still require deployment verification.
