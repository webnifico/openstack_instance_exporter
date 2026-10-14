package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Validate the shipped policy through the same renderer used for deployment.
func TestAlertValidationEveryBundledAlertHasExecutableLifecycleFixture(t *testing.T) {
	python := os.Getenv("ANSIBLE_PYTHON")
	if python == "" {
		python = "python3"
	}
	cmd := exec.Command(python, "integration_tests/oie_alerts_verify.py", "--list")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("current alert fixture inventory: %v\n%s", err, output)
	}
	if strings.Count(string(output), " | for=") != 62 {
		t.Fatalf("expected all 62 CURRENT alerts in the executable fixture inventory:\n%s", output)
	}
}
