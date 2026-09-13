package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

const (
	releaseContractVersion         = "v2.0.0"
	releaseContractSourceDateEpoch = int64(1787527527)
	releaseContractBinaryContents  = "deterministic fake executable\n"
)

var releaseContractOutputInventory = []string{
	"openstack_instance_exporter-v2.0.0-linux-amd64.tar.xz",
	"sha256sums.txt",
}

type releaseContractBuild struct {
	distDir       string
	archivePath   string
	manifestPath  string
	archiveBytes  []byte
	manifestBytes []byte
}

func releaseContractFakeGo(t *testing.T) string {
	t.Helper()
	fakeGo := filepath.Join(t.TempDir(), "go")
	fakeGoScript := `#!/usr/bin/env bash
set -euo pipefail
output=""
while (( $# > 0 )); do
  if [[ "$1" == "-o" ]]; then
    output="$2"
    shift 2
    continue
  fi
  shift
done
test -n "${output}"
test "${CGO_ENABLED:-}" = 0
test "${GOOS:-}" = linux
test "${GOARCH:-}" = amd64
test "${GOAMD64:-}" = v1
printf 'deterministic fake executable\n' > "${output}"
chmod 0700 "${output}"
`
	if err := os.WriteFile(fakeGo, []byte(fakeGoScript), 0o755); err != nil {
		t.Fatal(err)
	}
	return fakeGo
}

func buildReleaseContractFixture(t *testing.T, fakeGo string) releaseContractBuild {
	t.Helper()
	distDir := t.TempDir()
	staleARM := filepath.Join(distDir, "openstack_instance_exporter-"+releaseContractVersion+"-linux-arm64.tar.xz")
	if err := os.WriteFile(staleARM, []byte("stale ARM release"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(
		"bash",
		"-c",
		`umask 077; exec bash "$@"`,
		"release-contract",
		"scripts/build-release.sh",
		releaseContractVersion,
		distDir,
	)
	cmd.Env = append(os.Environ(),
		"GO="+fakeGo,
		fmt.Sprintf("SOURCE_DATE_EPOCH=%d", releaseContractSourceDateEpoch),
		"TZ=UTC",
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("release builder failed: %v\n%s", err, output)
	}

	entries, err := os.ReadDir(distDir)
	if err != nil {
		t.Fatal(err)
	}
	gotNames := make([]string, 0, len(entries))
	for _, entry := range entries {
		gotNames = append(gotNames, entry.Name())
	}
	if !reflect.DeepEqual(gotNames, releaseContractOutputInventory) {
		t.Fatalf("release output inventory = %v, want %v", gotNames, releaseContractOutputInventory)
	}

	archivePath := filepath.Join(distDir, releaseContractOutputInventory[0])
	manifestPath := filepath.Join(distDir, releaseContractOutputInventory[1])
	assertReleaseContractFileMode(t, archivePath, 0o644)
	assertReleaseContractFileMode(t, manifestPath, 0o644)

	archiveBytes, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}

	return releaseContractBuild{
		distDir:       distDir,
		archivePath:   archivePath,
		manifestPath:  manifestPath,
		archiveBytes:  archiveBytes,
		manifestBytes: manifestBytes,
	}
}

func assertReleaseContractFileMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("release output %s mode=%s, want regular file", filepath.Base(path), info.Mode())
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("release output %s mode=%#o, want %#o", filepath.Base(path), got, want)
	}
}

func assertReleaseContractArchive(t *testing.T, archivePath string) {
	t.Helper()
	cmd := exec.Command("xz", "--decompress", "--stdout", archivePath)
	tarBytes, err := cmd.Output()
	if err != nil {
		t.Fatalf("decompress release archive: %v", err)
	}

	reader := tar.NewReader(bytes.NewReader(tarBytes))
	header, err := reader.Next()
	if err != nil {
		t.Fatalf("read release archive member: %v", err)
	}
	if header.Name != "openstack_instance_exporter" {
		t.Fatalf("release archive member name=%q, want openstack_instance_exporter", header.Name)
	}
	if header.Typeflag != tar.TypeReg {
		t.Fatalf("release archive member type=%d, want regular file", header.Typeflag)
	}
	if header.Mode != 0o755 {
		t.Fatalf("release archive member mode=%#o, want 0755", header.Mode)
	}
	if header.Uid != 0 || header.Gid != 0 || header.Uname != "" || header.Gname != "" {
		t.Fatalf(
			"release archive ownership uid=%d gid=%d uname=%q gname=%q, want numeric 0/0",
			header.Uid,
			header.Gid,
			header.Uname,
			header.Gname,
		)
	}
	if header.Linkname != "" || header.Devmajor != 0 || header.Devminor != 0 {
		t.Fatalf(
			"release archive member has unexpected link/device metadata: link=%q major=%d minor=%d",
			header.Linkname,
			header.Devmajor,
			header.Devminor,
		)
	}
	wantModTime := time.Unix(releaseContractSourceDateEpoch, 0)
	if !header.ModTime.Equal(wantModTime) {
		t.Fatalf("release archive member mtime=%s, want %s", header.ModTime, wantModTime)
	}
	if header.Size != int64(len(releaseContractBinaryContents)) {
		t.Fatalf("release archive member size=%d, want %d", header.Size, len(releaseContractBinaryContents))
	}
	payload, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read release archive payload: %v", err)
	}
	if string(payload) != releaseContractBinaryContents {
		t.Fatalf("release archive payload=%q, want deterministic fixture", payload)
	}
	if _, err := reader.Next(); err != io.EOF {
		t.Fatalf("release archive contains another member or malformed trailer: %v", err)
	}
}

func assertReleaseContractChecksum(t *testing.T, build releaseContractBuild) {
	t.Helper()
	sum := sha256.Sum256(build.archiveBytes)
	wantManifest := []byte(fmt.Sprintf("%x  %s\n", sum, releaseContractOutputInventory[0]))
	if !bytes.Equal(build.manifestBytes, wantManifest) {
		t.Fatalf("checksum manifest=%q, want %q", build.manifestBytes, wantManifest)
	}

	check := exec.Command("sha256sum", "--check", filepath.Base(build.manifestPath))
	check.Dir = build.distDir
	if output, err := check.CombinedOutput(); err != nil {
		t.Fatalf("checksum verification failed: %v\n%s", err, output)
	}
}

func TestReleaseBuilderRemovesSameVersionStaleARMArtifactAndIsReproducible(t *testing.T) {
	fakeGo := releaseContractFakeGo(t)
	first := buildReleaseContractFixture(t, fakeGo)
	second := buildReleaseContractFixture(t, fakeGo)

	if !bytes.Equal(first.archiveBytes, second.archiveBytes) {
		t.Fatal("two release builds at the same SOURCE_DATE_EPOCH produced different archives")
	}
	if !bytes.Equal(first.manifestBytes, second.manifestBytes) {
		t.Fatal("two release builds at the same SOURCE_DATE_EPOCH produced different checksum manifests")
	}

	assertReleaseContractArchive(t, first.archivePath)
	assertReleaseContractArchive(t, second.archivePath)
	assertReleaseContractChecksum(t, first)
	assertReleaseContractChecksum(t, second)
}

func TestReleaseBuilderRejectsUnexpectedDistributionEntriesWithoutDeletingThem(t *testing.T) {
	distDir := t.TempDir()
	unexpectedPath := filepath.Join(distDir, "operator-notes.txt")
	want := []byte("preserve me\n")
	if err := os.WriteFile(unexpectedPath, want, 0o640); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("bash", "scripts/build-release.sh", releaseContractVersion, distDir)
	cmd.Env = append(
		os.Environ(),
		"GO="+releaseContractFakeGo(t),
		fmt.Sprintf("SOURCE_DATE_EPOCH=%d", releaseContractSourceDateEpoch),
	)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("release builder accepted an unexpected distribution entry\n%s", output)
	}
	if !bytes.Contains(output, []byte("distribution directory contains an unexpected entry")) {
		t.Fatalf("unexpected release-builder output: %s", output)
	}
	got, err := os.ReadFile(unexpectedPath)
	if err != nil {
		t.Fatalf("unexpected entry was removed: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("unexpected entry changed: got %q, want %q", got, want)
	}
}
