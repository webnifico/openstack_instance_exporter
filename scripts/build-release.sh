#!/usr/bin/env bash
set -euo pipefail

version="${1:-v1.3.0}"
dist_dir="${2:-dist}"
go_bin="${GO:-go}"
source_date_epoch="${SOURCE_DATE_EPOCH:-}"

if [[ ! "${version}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "invalid release version: ${version}" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

if [[ -z "${source_date_epoch}" ]]; then
  source_date_epoch="$(git log -1 --format=%ct 2>/dev/null || true)"
fi
if [[ -z "${source_date_epoch}" ]]; then
  source_date_epoch="$(date -u +%s)"
fi
if [[ ! "${source_date_epoch}" =~ ^[0-9]+$ ]]; then
  echo "invalid SOURCE_DATE_EPOCH: ${source_date_epoch}" >&2
  exit 2
fi

mkdir -p "${dist_dir}"

release_tmp="$(mktemp -d)"
trap 'rm -rf -- "${release_tmp}"' EXIT

stage_dir="${release_tmp}/amd64"
archive_name="openstack_instance_exporter-${version}-linux-amd64.tar.xz"
mkdir -p "${stage_dir}"

# A reused distribution directory must not retain the removed ARM artifact for
# this release version. Keep the cleanup exact so unrelated releases survive.
rm -f -- "${dist_dir}/openstack_instance_exporter-${version}-linux-arm64.tar.xz"

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "${go_bin}" build \
  -trimpath \
  -buildvcs=false \
  -ldflags='-s -w -buildid=' \
  -o "${stage_dir}/openstack_instance_exporter" .

tar \
  --sort=name \
  --mtime="@${source_date_epoch}" \
  --owner=0 \
  --group=0 \
  --numeric-owner \
  -C "${stage_dir}" \
  -cJf "${release_tmp}/${archive_name}" \
  openstack_instance_exporter

if [[ "$(tar -tJf "${release_tmp}/${archive_name}")" != "openstack_instance_exporter" ]]; then
  echo "unexpected archive contents: ${archive_name}" >&2
  exit 1
fi
install -m 0644 "${release_tmp}/${archive_name}" "${dist_dir}/${archive_name}"

(
  cd "${dist_dir}"
  sha256sum "${archive_name}" > sha256sums.txt
  sha256sum --check sha256sums.txt
)
