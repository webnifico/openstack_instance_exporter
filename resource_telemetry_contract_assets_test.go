package main

import (
	"os"
	"strings"
	"testing"
)

func TestResourceTelemetryResourceAxisREADMEContract(t *testing.T) {
	read := func(path string) string {
		t.Helper()
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		return string(content)
	}

	mainREADME := read("README.md")
	for _, family := range []string{
		"oie_instance_resource_axis_fresh",
		"oie_instance_resource_axis_available",
		"oie_instance_resource_axis_last_success_timestamp_seconds",
		"oie_instance_resource_axis_stale_seconds",
	} {
		heading := "- **" + family + "**"
		if got := strings.Count(mainREADME, heading); got != 1 {
			t.Fatalf("README metric heading %q count=%d, want 1", heading, got)
		}
	}

	wantLifecycleTable := `| Axis state | ` + "`oie_instance_resource_axis_fresh`" + ` | ` + "`oie_instance_resource_axis_available`" + ` | Last success | Stale age | Axis severity |
| --- | ---: | ---: | ---: | ---: | --- |
| No successful sample | ` + "`0`" + ` | ` + "`0`" + ` | ` + "`0`" + ` | ` + "`-1`" + ` | Omitted |
| Fresh | ` + "`1`" + ` | ` + "`1`" + ` | Current sample time | Age since current sample | Current value |
| Retained | ` + "`0`" + ` | ` + "`1`" + ` | Unchanged | Increases | Last-good value |
| Unavailable after retention expires | ` + "`0`" + ` | ` + "`0`" + ` | Unchanged | Increases | Omitted |`
	if !strings.Contains(mainREADME, wantLifecycleTable) {
		t.Fatal("README is missing the exact Resource telemetry resource-axis lifecycle table")
	}
	for _, statement := range []string{
		"retained without advancing its EWMA or composite persistence for at most eight collection intervals",
		"Recovery within the two-interval missing-sample grace resumes over one normal interval",
		"Non-finite observations are missing samples, not valid zeroes",
		"require every available axis to be fresh",
	} {
		if !strings.Contains(mainREADME, statement) {
			t.Fatalf("README is missing Resource telemetry contract statement %q", statement)
		}
	}

	operationalConfiguration := read("OPERATIONAL_CONFIGURATION.md")
	if !strings.Contains(operationalConfiguration, "The example contains one concise alert group with 82 definitions and ten shared recording rules.") {
		t.Fatal("operational configuration does not explicitly own the live alert layout")
	}
}
