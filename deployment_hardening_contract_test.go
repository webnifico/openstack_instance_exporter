package main

import (
	"reflect"

	"testing"
)

func TestDeploymentHardeningExporterSurfaceRemainsFrozen(t *testing.T) {
	if got := len(compatibilityDescriptorLabelOrder(t)); got != inventoryOIEFamilyCount {
		t.Fatalf("Prometheus families=%d, want %d", got, inventoryOIEFamilyCount)
	}
	wantCLI := compatibilityReadNonEmptyLines(t, "testdata/contracts/cli-flags.txt")
	if got := compatibilityRuntimeCLIContract(t); !reflect.DeepEqual(got, wantCLI) {
		t.Fatalf("Operational configuration changed the exporter CLI\nwant: %v\ngot:  %v", wantCLI, got)
	}
}
