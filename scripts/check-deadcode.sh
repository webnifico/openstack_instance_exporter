#!/bin/sh
set -eu

cd "$(dirname "$0")/.."
go_bin="${GO:-go}"
output="$(mktemp)"
trap 'rm -f "$output"' EXIT HUP INT TERM

# Analyze the executable without test roots: test-only callers must not keep
# unused production helpers alive. Keep the analyzer version reproducible.
GOTOOLCHAIN=local "$go_bin" run golang.org/x/tools/cmd/deadcode@v0.50.0 \
  -filter '^openstack_instance_exporter$' . > "$output"
if [ -s "$output" ]; then
  cat "$output" >&2
  exit 1
fi
echo "No unreachable exporter functions."
