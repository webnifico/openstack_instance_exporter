# OpenStack Instance Exporter v2.0.0 release package

[Documentation index](DOCUMENTATION.md) · [Project README](README.md)

This package contains the complete v2.0.0 repository and Linux amd64 release archive. v1.2.0 is the previous published release and the baseline for upgrade notes.

**On this page**

- [Package contents](#package-contents)
- [Install the source tree](#install-the-source-tree)
- [Release behavior](#release-behavior)
- [Verification](#verification)

## Package contents

| Path | Contents |
| --- | --- |
| Repository root | Exporter source, Go module files, tests, license and operator documentation |
| `.github/` | Required CI, extended verification and dependency-update configuration |
| `ansible_role/openstack_instance_exporter/` | Role, defaults, service template and deployment tests |
| `examples/` | Five Grafana dashboards, Prometheus alert definitions and configuration examples |
| `testdata/`, `integration_tests/` | Compatibility, replay, measurement and operator-policy fixtures |
| `scripts/`, `Makefile` | Build, validation and reproducibility commands |
| `dist/` | `openstack_instance_exporter-v2.0.0-linux-amd64.tar.xz` and `sha256sums.txt` |

## Install the source tree

Replace the previous source files with this tree at the repository root, retaining your repository's `.git` directory. Replacing the source files removes obsolete filenames; simply overlaying a ZIP can leave them behind. Review additions and deletions with `git status` before committing to `main` and creating the v2.0.0 development branch. Git history and local build caches are not included. The binary archive in `dist/` is a release artifact; `.gitignore` excludes that directory from source commits.

## Release behavior

v2.0.0 retains the published metric and label identities while improving source freshness, resource measurements, behavior and mining persistence, threat-feed recovery, configuration validation and Libvirt collection safety. It adds active/inactive inventory, five updated dashboards and an alert policy with 82 definitions, 33 enabled by default, plus ten recording rules.

Attached-volume retype monitoring is opt-in and disabled by default. When enabled, it reports bounded, compute-local Libvirt observations for active and recent RBD block-copy jobs. It does not report detached-volume migrations or authoritative Cinder outcomes. Detected disk mirrors exclude block statistics for the affected VM while CPU, memory and network collection continue when Libvirt control/job checks permit. See [LIBVIRT_COLLECTION_SAFETY.md](LIBVIRT_COLLECTION_SAFETY.md) and [README.md](README.md).

## Verification

From the repository root:

```bash
scripts/validate-release.sh v2.0.0 dist
```

To verify the archive checksum directly:

```bash
cd dist
sha256sum --check sha256sums.txt
```

The package's actual validation results and limitations are recorded in [integration_tests/validation.json](integration_tests/validation.json). Reproduce the full verification with `make check`, the declared Go toolchain, an executable `PROMTOOL`, and Ansible with the required collection. See [CI_AND_RELEASE_VALIDATION.md](CI_AND_RELEASE_VALIDATION.md). Live Libvirt operation, Grafana rendering and notification delivery require deployment verification.
