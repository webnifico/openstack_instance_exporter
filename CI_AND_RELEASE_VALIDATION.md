# CI and release validation

[Documentation index](DOCUMENTATION.md) · [Project README](README.md)

The source repository supplies a complete CI graph for v2.0.0. It validates the exporter, compatibility interfaces, operator assets, deployment role and reproducible release archive.

**On this page**

- [Required workflow](#required-workflow)
- [Hosting enforcement](#hosting-enforcement)
- [Prometheus, Grafana, and compatibility](#prometheus-grafana-and-compatibility)
- [Release archive validation](#release-archive-validation)
- [Scheduled extended verification](#scheduled-extended-verification)
- [Pin maintenance](#pin-maintenance)

## Required workflow

`.github/workflows/ci.yml` evaluates pull requests, every branch push, `v*` release-tag pushes, merge-queue revisions, and explicit manual runs. It checks out the event's exact revision and never uses `pull_request_target`. Workflow permissions are read-only, checkout credentials are not persisted, and every third-party action reference is a full immutable commit SHA.

The required graph has three substantive gates and one stable aggregate status:

| Gate | Required work |
| --- | --- |
| Go, assets, and compatibility | `go vet ./...`; `go mod verify`; `make vuln`; `go test -count=1 ./...`; `go test -race -count=1 ./...`; `go test -shuffle=on -count=10 ./...`; `make coverage`; `make fuzz`; and `make contracts` with an installed, executable `promtool` |
| Ansible | `make ansible-test`, executable `make ansible-preflight`, and `make operator-test` with `promtool` on Ubuntu 22.04/Python 3.10/ansible-core 2.12.10 and Ubuntu 24.04/Python 3.12/ansible-core 2.21.3 |
| Release | `make release VERSION=v2.0.0`; `make release-validate VERSION=v2.0.0`; and `make release-reproducible VERSION=v2.0.0` |
| Aggregate | `Required CI gate` fails unless every preceding gate succeeds; skipped and cancelled dependencies are failures |

The explicit contract target re-executes the highest-value interfaces rather than trusting filenames or broad package success. It covers native Prometheus rule syntax, every Grafana PromQL expression, every bundled alert's promtool lifecycle fixture, the exact emitted metric schema, the CLI flag contract, structured-event shape, v1.2 compatibility, and the deterministic release-builder contract. The complete package test still runs first, so every other regression test remains mandatory too.

There are no path filters, permitted failures, or silent tool skips. A pull request that changes only documentation, CI, release scripts, golden assets, examples, or deployment files still traverses the complete graph. The release job waits for both implementation and deployment verification and always builds the exact checked-out revision.

### Clean source checkouts

The Go suite runs from a source checkout without `dist/`. The release-validator failure test builds and validates a real archive in temporary storage before injecting an inspection failure. `testdata/release-archive.sha256` records the bundled archive checksum for the role-default and README checks. When replacing that release archive, update this record, the role default and the README checksum together. Keep generated archives in the ignored `dist/` directory and publish them as release assets.

## Hosting enforcement

A workflow cannot mark itself mandatory. Repository administrators must create protected-branch and release-tag rulesets that:

1. require the status named `Required CI gate`;
2. evaluate merge-queue revisions;
3. cover the branch from which v2.0.0 is tagged and the `v*` tag namespace;
4. prohibit direct pushes or tag creation that bypass the required status; and
5. prohibit bypass actors for the v2.0.0 release path.

With those settings active, no unverified commit can become v2.0.0. Source review must treat weakening `.github/workflows/ci.yml`, the CI and release validation tests, or the ruleset as a release-blocking change.

## Prometheus, Grafana, and compatibility

CI installs `promtool`, proves it is executable, exports its exact path, and passes that path to all relevant Go and Make targets. Prometheus syntax and lifecycle tests therefore fail if the tool is absent; they never turn into a green skip. Grafana JSON parsing, dashboard query inventory, metric-reference checks, and promtool parsing remain executable tests. Metric-family names and labels, CLI flags, structured-event fields and types, and the v1.2 compatibility snapshot remain byte-frozen or structurally frozen by their existing golden contracts.

`testdata/ci-release-prior-golden-sha256.golden` protects the baseline golden files, including nested checksum manifests. Golden files are never updated merely to make CI pass. An intended public-contract change must be reviewed as such, documented, and supplied with an explicit new contract asset.

Every corrected defect receives a permanent regression test. A test failure is repaired at its cause; reducing counts, disabling a platform, adding a skip, loosening an assertion, or refreshing a golden without an approved contract change is not a valid fix.

## Release archive validation

`scripts/build-release.sh` refuses an output directory that contains unrelated entries rather than deleting operator files. It may replace the requested amd64 archive and manifest, and it removes only the retired same-version arm64 artifact. The builder fixes the archive and manifest modes at `0644` even under a restrictive umask and explicitly targets the baseline `GOAMD64=v1` instruction set.

`scripts/validate-release.sh` rejects anything except one regular, non-symlink, mode-`0644` linux/amd64 archive and its one-line mode-`0644` checksum manifest for the requested version. It requires every inspection tool to be available and successful, verifies the checksum, rejects the removed same-version arm64 artifact, requires exactly one archive member named `openstack_instance_exporter`, extracts into a private temporary directory, and requires:

- mode `0755` and numeric archive ownership `0/0`;
- an amd64 ELF binary reported as static and stripped;
- no ELF interpreter segment; and
- a successful `-h` startup probe.

### Reproducible builds

`scripts/check-reproducible-release.sh` selects one numeric source epoch, using the current UTC time once when neither `SOURCE_DATE_EPOCH` nor Git metadata is available. It creates two isolated distribution directories, invokes the production builder independently for each, validates each result, and compares both the archive and checksum-manifest bytes. A hash match produced by reusing one output is not accepted. The v2.0.0 release commit passes only when two builds are identical.

## Scheduled extended verification

`.github/workflows/extended.yml` runs weekly and on demand. It performs 25 shuffled suite repetitions, two minutes of fuzzing for each conntrack parser, 100 repetitions of lifecycle/cleanup/retention/state tests, and five independent one-iteration samples per benchmark. It is additive evidence, not a replacement for the required graph and not a prerequisite whose delay can hide a required failure.

`make replay` runs the 51-fixture behavioral corpus described in [REPLAY_CALIBRATION.md](REPLAY_CALIBRATION.md). `make operator-test` separately checks the current rendered operator policy.

## Pin maintenance

The source requires Go **1.27.1** or newer. All three Go setup steps read the same `go.mod`, and CI uses `GOTOOLCHAIN=local` so the declared compiler is used without a silent toolchain switch. The bundled linux/amd64 release is built with Go 1.27.1, `CGO_ENABLED=0` and `GOAMD64=v1`; compute nodes do not need Go installed. Historical benchmark and compatibility records retain the compiler versions actually used for those measurements.

### Scrape-format compatibility

The Prometheus client upgrade retains plain, gzip and zstd scrapes; zstd now requires an explicit upstream registration import. An executable HTTP regression test decodes each format and checks identical metric samples. Upstream adds a final period to HELP for `go_gc_gogc_percent`, `go_gc_gomemlimit_bytes` and `go_sched_gomaxprocs_threads`. Historical comparisons normalize only those exact known lines; frozen golden files, metric names, types, labels and measured values are preserved.

### Vulnerability scanning

`make vuln` runs the pinned `govulncheck` v1.7.0 against the current Go vulnerability database and fails on known reachable vulnerabilities. It runs in the required Go gate, the weekly extended workflow and `make check`. This is a point-in-time check of published advisories, not a guarantee that no vulnerabilities exist. Put the selected Go toolchain on `PATH` when running source scans. The scanner is a build tool and is not added to the exporter's runtime module dependencies.

### Dependency updates

Every GitHub Action is pinned to a 40-character commit SHA. `.github/dependabot.yml` proposes weekly GitHub Actions and Go module updates. Updates require review and the normal required graph; tag-only or mutable branch action references are forbidden. Go patch releases still require updating `go.mod`, rebuilding the archive and updating the role checksum together.

Maintain the source at the repository root and enable GitHub Actions and Dependabot for these configurations to run.

`make operator-test` evaluates the bundled dashboard interpolation and telemetry fixtures and the actual rendered operator alert policy. These scenarios supplement the frozen historical alert fixtures. `make check` also requires this target and the executable Ansible preflight; neither is an optional follow-up.

### Prometheus query compatibility

Dashboard Top N ranking uses the PromQL `@` modifier, stable since [Prometheus 2.33](https://github.com/prometheus/prometheus/releases/tag/v2.33.0). The exporter scrape format is separate from this dashboard query requirement. Ubuntu 22.04 ships Prometheus 2.31 with that feature disabled by default; it is not the unconfigured dashboard baseline. CI installs the same checksum-verified `promtool` 2.45.3 on both runner operating systems, independent of their Ansible versions. This is an offline compatibility test tool, not a Prometheus server upgrade.
