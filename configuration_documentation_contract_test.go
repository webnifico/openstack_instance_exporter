package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const runtimeConfigurationPriorGoldenSHA256Path = "testdata/runtime-configuration-prior-golden-sha256.golden"

func TestRuntimeConfigurationPriorGoldenAssetsAreByteFrozen(t *testing.T) {
	manifest, err := os.ReadFile(runtimeConfigurationPriorGoldenSHA256Path)
	if err != nil {
		t.Fatal(err)
	}
	wantPaths := make(map[string]struct{})
	lines := strings.Split(strings.TrimSpace(string(manifest)), "\n")
	if len(lines) != 35 {
		t.Fatalf("prior golden hash records=%d, want 35", len(lines))
	}
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 2 || len(fields[0]) != 64 || !strings.HasPrefix(fields[1], "testdata/") {
			t.Fatalf("invalid prior-golden hash record %q", line)
		}
		if _, duplicate := wantPaths[fields[1]]; duplicate {
			t.Fatalf("duplicate prior-golden hash path %q", fields[1])
		}
		wantPaths[fields[1]] = struct{}{}
		content, err := os.ReadFile(fields[1])
		if err != nil {
			t.Fatalf("read frozen golden %s: %v", fields[1], err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(content)); got != fields[0] {
			t.Fatalf("frozen golden %s changed: sha256=%s want=%s", fields[1], got, fields[0])
		}
	}

	paths, err := filepath.Glob("testdata/*golden*")
	if err != nil {
		t.Fatal(err)
	}
	gotPaths := make(map[string]struct{})
	for _, path := range paths {
		if strings.Contains(filepath.Base(path), "runtime-configuration") || strings.Contains(filepath.Base(path), "deployment-hardening") || strings.Contains(filepath.Base(path), "ci-release") || strings.Contains(filepath.Base(path), "replay-calibration") || strings.Contains(filepath.Base(path), "scaling") {
			continue
		}
		gotPaths[filepath.ToSlash(path)] = struct{}{}
	}
	if !reflect.DeepEqual(gotPaths, wantPaths) {
		t.Fatalf("Compatibility baseline through Prometheus alert validation golden asset set changed\nwant: %v\ngot:  %v", wantPaths, gotPaths)
	}
}

func TestConfigurationAndHTTPDocumentationContract(t *testing.T) {
	content, err := os.ReadFile("CONFIGURATION_AND_HTTP.md")
	if err != nil {
		t.Fatal(err)
	}
	contractText := string(content)
	for _, statement := range []string{
		"A documented default is used only when its flag is omitted.",
		"all three weights may not be zero and their sum must remain finite.",
		"`5s` through `1m`, inclusive.",
		"enabling host threat matching without explicitly setting the flag selects `bgp-nic`.",
		"Behavior YAML inputs must be stable regular files no larger than 1 MiB.",
		"The exporter retains that validated open handle for logging and runtime level changes.",
		"When it is `false`, `/debug/log-level` is not registered at all",
		"`GET` with any `level` key, including empty or repeated values | `400` | None",
		"`POST` with exactly one non-blank valid `level` value | `200`",
		"Concurrent metrics requests | `4`",
		"`WriteTimeout` | `0` (disabled)",
		"A metrics request that declares a body or transfer encoding is rejected with `400 Bad Request`",
		"Every Compatibility baseline through Prometheus alert validation golden asset remains byte-for-byte unchanged.",
	} {
		if !strings.Contains(contractText, statement) {
			t.Fatalf("Runtime configuration contract is missing %q", statement)
		}
	}
}

func TestRuntimeConfigurationREADMEAndPublicSurfaceContract(t *testing.T) {
	content, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	readme := string(content)
	link := "[`CONFIGURATION_AND_HTTP.md`](CONFIGURATION_AND_HTTP.md)"
	if got := strings.Count(readme, link); got != 1 {
		t.Fatalf("README Runtime configuration contract link count=%d, want 1", got)
	}
	for _, statement := range []string{
		"Startup configuration now rejects invalid explicit intent instead of clamping, defaulting, or broadening it.",
		"the runtime log-level endpoint has strict read-versus-write methods and can be unregistered",
		"The HTTP server uses a `10s` read-header timeout, `2m` idle timeout, 32 KiB maximum-header setting, four concurrent metrics requests, and a `10s` graceful-shutdown deadline.",
	} {
		if !strings.Contains(readme, statement) {
			t.Fatalf("README is missing Runtime configuration contract statement %q", statement)
		}
	}

	additions := compatibilityReadNonEmptyLines(t, runtimeConfigurationCLIFlagAdditionsGoldenPath)
	want := []string{`web.debug-log-level.enable|"true"|Enable the runtime log-level debug endpoint`}
	if !reflect.DeepEqual(additions, want) {
		t.Fatalf("Runtime configuration CLI additions=%v, want %v", additions, want)
	}
	if got := len(compatibilityDescriptorLabelOrder(t)); got != inventoryOIEFamilyCount {
		t.Fatalf("current Prometheus families=%d, want %d", got, inventoryOIEFamilyCount)
	}
}
