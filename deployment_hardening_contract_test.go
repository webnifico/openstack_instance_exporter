package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

const deploymentHardeningPriorGoldenSHA256Path = "testdata/deployment-hardening-prior-golden-sha256.golden"

func TestDeploymentHardeningPriorGoldenAssetsAreByteFrozen(t *testing.T) {
	manifest, err := os.ReadFile(deploymentHardeningPriorGoldenSHA256Path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(manifest)), "\n")
	if len(lines) != 37 {
		t.Fatalf("prior golden hash records=%d, want 37", len(lines))
	}
	wantPaths := make(map[string]struct{}, len(lines))
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
			t.Fatal(err)
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
		base := filepath.Base(path)
		if strings.Contains(base, "deployment-hardening") || strings.Contains(base, "ci-release") || strings.Contains(base, "replay-calibration") || strings.Contains(base, "scaling") {
			continue
		}
		gotPaths[filepath.ToSlash(path)] = struct{}{}
	}
	if !reflect.DeepEqual(gotPaths, wantPaths) {
		t.Fatalf("Compatibility baseline through Runtime configuration golden asset set changed\nwant: %v\ngot:  %v", wantPaths, gotPaths)
	}
}

func TestDeploymentHardeningExporterSurfaceRemainsFrozen(t *testing.T) {
	if got := len(compatibilityDescriptorLabelOrder(t)); got != inventoryOIEFamilyCount {
		t.Fatalf("Prometheus families=%d, want %d", got, inventoryOIEFamilyCount)
	}
	wantCLI := append(compatibilityReadNonEmptyLines(t, "testdata/cli-flags-baseline.golden"), compatibilityReadNonEmptyLines(t, threatIntelligenceCLIFlagAdditionsGoldenPath)...)
	wantCLI = append(wantCLI, compatibilityReadNonEmptyLines(t, runtimeConfigurationCLIFlagAdditionsGoldenPath)...)
	wantCLI = append(wantCLI, volumeRetypeCLIFlagAddition)
	sort.Strings(wantCLI)
	if got := compatibilityRuntimeCLIContract(t); !reflect.DeepEqual(got, wantCLI) {
		t.Fatalf("Operational configuration changed the exporter CLI\nwant: %v\ngot:  %v", wantCLI, got)
	}
}

func TestDeploymentHardeningDeploymentSurfaceIsHistoricallyFrozenAndSuperseded(t *testing.T) {
	wantHistoricalAdditions := []string{
		"openstack_instance_exporter_group",
		"openstack_instance_exporter_libvirt_group",
		"openstack_instance_exporter_libvirt_socket_path",
		"openstack_instance_exporter_manage_service_account",
		"openstack_instance_exporter_user",
	}
	if got := compatibilityReadNonEmptyLines(t, deploymentHardeningAnsibleAdditionsGoldenPath); !reflect.DeepEqual(got, wantHistoricalAdditions) {
		t.Fatalf("historical Deployment hardening Ansible additions changed: %v", got)
	}

	operationalConfiguration := string(readRoleFile(t, "OPERATIONAL_CONFIGURATION.md"))
	if !strings.Contains(operationalConfiguration, "The v2.0.0 operational configuration combines a verified exporter archive") {
		t.Fatal("operational configuration does not identify the contracts it supersedes")
	}
	for _, statement := range []string{
		"v2.0.0 operational configuration",
		"local controller archive",
		"one concise alert group",
	} {
		if !strings.Contains(operationalConfiguration, statement) {
			t.Fatalf("operational configuration contract is missing %q", statement)
		}
	}

	variables := dataIntegrityLoadAnsibleRoleContract(t).PublicVariables
	for _, removed := range wantHistoricalAdditions {
		index := sort.SearchStrings(variables, removed)
		if index < len(variables) && variables[index] == removed {
			t.Fatalf("superseded Deployment hardening variable %q remains live", removed)
		}
	}
}
