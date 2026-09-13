#!/usr/bin/env bash
set -euo pipefail

version="${1:-v2.0.0}"
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
removed_arm_name="openstack_instance_exporter-${version}-linux-arm64.tar.xz"
mkdir -p "${stage_dir}"

# Refuse a dirty distribution directory rather than deleting unrelated files.
# Existing outputs for this version may be replaced, and the retired
# same-version ARM artifact is the only extra entry the builder removes.
shopt -s nullglob dotglob
distribution_entries=("${dist_dir}"/*)
shopt -u nullglob dotglob
for entry in "${distribution_entries[@]}"; do
  entry_name="${entry##*/}"
  case "$entry_name" in
    "$archive_name"|sha256sums.txt|"$removed_arm_name")
      if [[ -L "$entry" || ! -f "$entry" ]]; then
        echo "release output path is not a regular non-symlink file: $entry" >&2
        exit 1
      fi
      ;;
    *)
      echo "distribution directory contains an unexpected entry: $entry" >&2
      exit 1
      ;;
  esac
done
rm -f -- "${dist_dir}/${removed_arm_name}"

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 "${go_bin}" build \
  -trimpath \
  -buildvcs=false \
  -ldflags='-s -w -buildid=' \
  -o "${stage_dir}/openstack_instance_exporter" .
chmod 0755 "${stage_dir}/openstack_instance_exporter"

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
  chmod 0644 sha256sums.txt
  sha256sum --check sha256sums.txt
)
