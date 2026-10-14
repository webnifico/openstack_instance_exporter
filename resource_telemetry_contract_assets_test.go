package main

import (
	"strings"
	"testing"
)

func TestResourceTelemetryResourceAxisREADMEContract(t *testing.T) {
	readme := dashboardDocumentationReadFile(t, "README.md")
	for _, statement := range []string{
		"oie_instance_resource_axis_fresh",
		"oie_instance_resource_axis_available",
		"retain last-good measurements",
		"Missing or stale data must not be read as healthy zeroes",
		"(testdata/contracts/metric-schema.txt)",
	} {
		if !strings.Contains(readme, statement) {
			t.Errorf("README omits operator guidance %q", statement)
		}
	}
}
