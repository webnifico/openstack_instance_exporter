package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestConfigurationAndHTTPDocumentationContract(t *testing.T) {
	readme := dashboardDocumentationReadFile(t, "README.md")
	for _, statement := range []string{
		"(testdata/contracts/cli-flags.txt)",
		"(ansible_role/openstack_instance_exporter/README.md)",
		"5s through 1m",
		"Custom configuration files also load at startup.",
		"protect the listener with network access controls.",
	} {
		if !strings.Contains(readme, statement) {
			t.Errorf("README omits operator guidance %q", statement)
		}
	}
}

func TestRuntimeConfigurationREADMEAndPublicSurfaceContract(t *testing.T) {
	readme := dashboardDocumentationReadFile(t, "README.md")
	if !strings.Contains(readme, "(README.md#deployment)") || !strings.Contains(readme, "--help") {
		t.Fatal("README omits configuration navigation or runtime help")
	}

	additions := []string{}
	for _, line := range compatibilityReadNonEmptyLines(t, "testdata/contracts/cli-flags.txt") {
		if strings.HasPrefix(line, "web.debug-log-level.enable|") {
			additions = append(additions, line)
		}
	}
	want := []string{`web.debug-log-level.enable|"false"|Enable the runtime log-level debug endpoint`}
	if !reflect.DeepEqual(additions, want) {
		t.Fatalf("Runtime configuration CLI additions=%v, want %v", additions, want)
	}
	if got := len(compatibilityDescriptorLabelOrder(t)); got != inventoryOIEFamilyCount {
		t.Fatalf("current Prometheus families=%d, want %d", got, inventoryOIEFamilyCount)
	}
}
