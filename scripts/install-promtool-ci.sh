#!/bin/sh
# Install the tested PromQL compatibility baseline independently of runner OS.
# This installs only an offline validation tool, not a Prometheus server.
set -eu

promtool_dir="${1:?usage: install-promtool-ci.sh DESTINATION_DIRECTORY}"
promtool_version=2.45.3
promtool_sha256=53b23de673c54bf6eeac13f17fe14027e8fe7800d0cf361e3177ba96413812b8
promtool_archive="prometheus-${promtool_version}.linux-amd64.tar.gz"
promtool_temp="$(mktemp -d)"
trap 'rm -rf "$promtool_temp"' EXIT HUP INT TERM

curl --fail --silent --show-error --location --retry 3 --connect-timeout 15 --max-time 180 \
  "https://github.com/prometheus/prometheus/releases/download/v${promtool_version}/${promtool_archive}" \
  --output "$promtool_temp/$promtool_archive"
printf '%s  %s\n' "$promtool_sha256" "$promtool_temp/$promtool_archive" | sha256sum --check --status
tar -xzf "$promtool_temp/$promtool_archive" -C "$promtool_temp" \
  --no-same-owner "prometheus-${promtool_version}.linux-amd64/promtool"
mkdir -p "$promtool_dir"
install -m 0755 "$promtool_temp/prometheus-${promtool_version}.linux-amd64/promtool" "$promtool_dir/promtool"
"$promtool_dir/promtool" --version
if [ -n "${GITHUB_ENV:-}" ]; then
  printf 'PROMTOOL=%s/promtool\n' "$(cd "$promtool_dir" && pwd)" >> "$GITHUB_ENV"
fi
