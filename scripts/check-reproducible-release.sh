#!/usr/bin/env bash
set -euo pipefail

version="${1:-v2.0.0}"
go_bin="${GO:-go}"

if [[ ! "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "invalid release version: $version" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

source_date_epoch="${SOURCE_DATE_EPOCH:-}"
if [[ -z "$source_date_epoch" ]]; then
  source_date_epoch="$(git log -1 --format=%ct 2>/dev/null || true)"
fi
if [[ -z "$source_date_epoch" ]]; then
  source_date_epoch="$(date -u +%s)"
fi
if [[ ! "$source_date_epoch" =~ ^[0-9]+$ ]]; then
  echo "invalid SOURCE_DATE_EPOCH: $source_date_epoch" >&2
  exit 2
fi

comparison_tmp="$(mktemp -d)"
cleanup() {
  rm -rf -- "$comparison_tmp"
}
trap cleanup EXIT

first_dist="${comparison_tmp}/first"
second_dist="${comparison_tmp}/second"
archive_name="openstack_instance_exporter-${version}-linux-amd64.tar.xz"

GO="$go_bin" SOURCE_DATE_EPOCH="$source_date_epoch" ./scripts/build-release.sh "$version" "$first_dist"
./scripts/validate-release.sh "$version" "$first_dist"
GO="$go_bin" SOURCE_DATE_EPOCH="$source_date_epoch" ./scripts/build-release.sh "$version" "$second_dist"
./scripts/validate-release.sh "$version" "$second_dist"

cmp --silent "${first_dist}/${archive_name}" "${second_dist}/${archive_name}" || {
  echo "independent release archives differ" >&2
  exit 1
}
cmp --silent "${first_dist}/sha256sums.txt" "${second_dist}/sha256sums.txt" || {
  echo "independent release checksum manifests differ" >&2
  exit 1
}

printf 'reproducible %s (%s)\n' "$archive_name" "$(sha256sum "${first_dist}/${archive_name}" | cut -d' ' -f1)"
