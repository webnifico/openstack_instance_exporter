#!/bin/sh
set -eu

go_cmd=${GO:-go}
minimum=${COVERAGE_MIN:-85.0}
profile=$(mktemp "${TMPDIR:-/tmp}/oie-coverage.XXXXXX")
trap 'rm -f "$profile"' EXIT HUP INT TERM

PROMTOOL="${PROMTOOL:-}" "$go_cmd" test -covermode=atomic -coverprofile="$profile" ./...
total=$($go_cmd tool cover -func="$profile" | awk '/^total:/ { value=$3; sub(/%$/, "", value); print value }')

if [ -z "$total" ]; then
    echo "could not determine total Go statement coverage" >&2
    exit 1
fi

if ! awk -v total="$total" -v minimum="$minimum" 'BEGIN { exit !(total + 0 >= minimum + 0) }'; then
    echo "Go statement coverage ${total}% is below required ${minimum}%" >&2
    exit 1
fi

echo "Go statement coverage ${total}% meets required ${minimum}%"
