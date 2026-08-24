package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestReleaseBuilderRemovesSameVersionStaleARMArtifact(t *testing.T) {
	distDir := t.TempDir()
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
printf 'deterministic fake executable\n' > "${output}"
chmod 0755 "${output}"
`
	if err := os.WriteFile(fakeGo, []byte(fakeGoScript), 0o755); err != nil {
		t.Fatal(err)
	}

	staleARM := filepath.Join(distDir, "openstack_instance_exporter-v1.3.0-linux-arm64.tar.xz")
	if err := os.WriteFile(staleARM, []byte("stale ARM release"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("bash", "scripts/build-release.sh", "v1.3.0", distDir)
	cmd.Env = append(os.Environ(),
		"GO="+fakeGo,
		"SOURCE_DATE_EPOCH=1787527527",
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
	wantNames := []string{
		"openstack_instance_exporter-v1.3.0-linux-amd64.tar.xz",
		"sha256sums.txt",
	}
	if !reflect.DeepEqual(gotNames, wantNames) {
		t.Fatalf("release output inventory = %v, want %v", gotNames, wantNames)
	}

	archivePath := filepath.Join(distDir, wantNames[0])
	listing := exec.Command("tar", "--full-time", "-tJvf", archivePath)
	listing.Env = append(os.Environ(), "TZ=UTC")
	listingOutput, err := listing.CombinedOutput()
	if err != nil {
		t.Fatalf("release archive listing failed: %v\n%s", err, listingOutput)
	}
	if !strings.Contains(string(listingOutput), "2026-08-23 23:25:27") {
		t.Fatalf("release archive does not use SOURCE_DATE_EPOCH: %s", listingOutput)
	}

	checksumBytes, err := os.ReadFile(filepath.Join(distDir, "sha256sums.txt"))
	if err != nil {
		t.Fatal(err)
	}
	checksumLines := strings.Fields(strings.TrimSpace(string(checksumBytes)))
	if len(checksumLines) != 2 || checksumLines[1] != wantNames[0] {
		t.Fatalf("checksum manifest does not describe only the amd64 archive: %q", checksumBytes)
	}
	check := exec.Command("sha256sum", "--check", "sha256sums.txt")
	check.Dir = distDir
	if output, err := check.CombinedOutput(); err != nil {
		t.Fatalf("checksum verification failed: %v\n%s", err, output)
	}
}
