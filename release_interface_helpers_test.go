package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func compatibilityAssertStringsEqual(t *testing.T, label string, got, want []string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s changed\ngot:  %v\nwant: %v", label, got, want)
	}
}

func compatibilityRuntimeCLIContract(t *testing.T) []string {
	t.Helper()
	tempDir := t.TempDir()
	contractPath := filepath.Join(tempDir, "cli-flags.contract")
	cmd := exec.Command(os.Args[0], "-test.run=^TestDataIntegrityCLIFlagContractSubprocess$")
	cmd.Env = append(os.Environ(),
		dataIntegrityFlagContractHelperEnv+"=1",
		dataIntegrityFlagContractOutputEnv+"="+contractPath,
		dataIntegrityFlagProbeConfigEnv+"="+filepath.Join(tempDir, "missing-behavior-ports.yaml"),
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("collect runtime CLI contract: %v\n%s", err, output)
	}
	data, err := os.ReadFile(contractPath)
	if err != nil {
		t.Fatal(err)
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\n")
}
