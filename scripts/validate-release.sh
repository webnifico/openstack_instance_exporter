#!/usr/bin/env bash
set -euo pipefail

version="${1:-v2.0.0}"
dist_dir="${2:-dist}"

if [[ ! "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "invalid release version: $version" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

archive_name="openstack_instance_exporter-${version}-linux-amd64.tar.xz"
archive_path="${dist_dir}/${archive_name}"
checksum_path="${dist_dir}/sha256sums.txt"
removed_arm_path="${dist_dir}/openstack_instance_exporter-${version}-linux-arm64.tar.xz"

for required_tool in cut file grep mktemp readelf rm sha256sum stat tar wc; do
  if ! command -v "$required_tool" >/dev/null 2>&1; then
    echo "required release-validation tool is unavailable: $required_tool" >&2
    exit 1
  fi
done

for artifact in "$archive_path" "$checksum_path"; do
  if [[ ! -f "$artifact" || -L "$artifact" ]]; then
    echo "release artifact is missing, not regular, or a symlink: $artifact" >&2
    exit 1
  fi
  if [[ "$(stat -c '%a' "$artifact")" != 644 ]]; then
    echo "release artifact mode must be 0644: $artifact" >&2
    exit 1
  fi
done
if [[ -e "$removed_arm_path" || -L "$removed_arm_path" ]]; then
  echo "removed architecture artifact is present: $removed_arm_path" >&2
  exit 1
fi
shopt -s nullglob dotglob
distribution_entries=("$dist_dir"/*)
shopt -u nullglob dotglob
if [[ ${#distribution_entries[@]} -ne 2 ]]; then
  echo "distribution directory must contain exactly the requested amd64 archive and sha256sums.txt" >&2
  exit 1
fi

checksum_line="$(<"$checksum_path")"
archive_hash="$(sha256sum "$archive_path" | cut -d' ' -f1)"
expected_checksum_line="${archive_hash}  ${archive_name}"
if [[ "$checksum_line" != "$expected_checksum_line" ]]; then
  echo "checksum manifest must contain exactly the amd64 archive" >&2
  exit 1
fi
if [[ "$(wc -l < "$checksum_path")" -ne 1 ]]; then
  echo "checksum manifest must contain exactly one newline-terminated record" >&2
  exit 1
fi
(
  cd "$dist_dir"
  sha256sum --check sha256sums.txt
)

mapfile -t archive_members < <(tar -tJf "$archive_path")
if [[ ${#archive_members[@]} -ne 1 || "${archive_members[0]}" != openstack_instance_exporter ]]; then
  echo "release archive must contain exactly openstack_instance_exporter" >&2
  exit 1
fi

validation_tmp="$(mktemp -d)"
cleanup() {
  rm -rf -- "$validation_tmp"
}
trap cleanup EXIT
tar -xJf "$archive_path" -C "$validation_tmp"
binary_path="${validation_tmp}/openstack_instance_exporter"

if [[ ! -f "$binary_path" || -L "$binary_path" || ! -x "$binary_path" ]]; then
  echo "release binary is missing, not regular, a symlink, or not executable" >&2
  exit 1
fi
if [[ "$(stat -c '%a' "$binary_path")" != 755 ]]; then
  echo "release binary mode is not 0755" >&2
  exit 1
fi

file_description="$(file -b "$binary_path")"
for marker in "ELF 64-bit" "x86-64" "statically linked" "stripped"; do
  if [[ "$file_description" != *"$marker"* ]]; then
    echo "release binary is missing file(1) marker '$marker': $file_description" >&2
    exit 1
  fi
done
if ! readelf_output="$(readelf -l "$binary_path")"; then
  echo "readelf failed while validating the release binary" >&2
  exit 1
fi
if grep -q 'INTERP' <<<"$readelf_output"; then
  echo "release binary unexpectedly has a dynamic interpreter" >&2
  exit 1
fi

archive_listing="$(tar --numeric-owner -tvJf "$archive_path")"
if [[ ! "$archive_listing" =~ ^-rwxr-xr-x[[:space:]]+0/0[[:space:]] ]]; then
  echo "release archive mode or numeric ownership is not deterministic: $archive_listing" >&2
  exit 1
fi

"$binary_path" -h >/dev/null 2>&1
printf 'validated %s (%s)\n' "$archive_name" "$archive_hash"
