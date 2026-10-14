package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const startupSensitivityHelperEnv = "OIE_STARTUP_SENSITIVITY_HELPER"
const startupSensitivityLogPathEnv = "OIE_STARTUP_SENSITIVITY_LOG_PATH"
const startupWorkerHelperEnv = "OIE_STARTUP_WORKER_HELPER"
const startupWorkerLogPathEnv = "OIE_STARTUP_WORKER_LOG_PATH"

func TestStartupRejectsOutOfRangeBehaviorSensitivity(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "startup.jsonl")
	cmd := exec.Command(os.Args[0], "-test.run=^TestStartupRejectsOutOfRangeBehaviorSensitivitySubprocess$")
	cmd.Env = append(os.Environ(),
		startupSensitivityHelperEnv+"=1",
		startupSensitivityLogPathEnv+"="+logPath,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("startup sensitivity helper: %v\n%s", err, out)
	}

	event := readStructuredLogEvent(t, logPath, "invalid_startup_configuration")
	if got, _ := event["err"].(string); !strings.Contains(got, "behavior.sensitivity must be between") {
		t.Fatalf("invalid startup error=%q, want behavior.sensitivity range rejection", got)
	}
}

func TestStartupRejectsOutOfRangeBehaviorSensitivitySubprocess(t *testing.T) {
	if os.Getenv(startupSensitivityHelperEnv) != "1" {
		return
	}
	logPath := os.Getenv(startupSensitivityLogPathEnv)
	if logPath == "" {
		t.Fatal("startup sensitivity helper log path is empty")
	}
	code := runMainForTest(t,
		"-behavior.sensitivity=99",
		"-web.telemetry-path=invalid",
		"-log.file.enable=true",
		"-log.file.path="+logPath,
	)
	if code != 2 {
		t.Fatalf("runMain exit code=%d, want 2 for invalid behavior sensitivity", code)
	}
}

func TestStartupRejectsWorkerCountAboveMaximum(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "startup.jsonl")
	cmd := exec.Command(os.Args[0], "-test.run=^TestStartupRejectsWorkerCountAboveMaximumSubprocess$")
	cmd.Env = append(os.Environ(),
		startupWorkerHelperEnv+"=1",
		startupWorkerLogPathEnv+"="+logPath,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("startup worker helper: %v\n%s", err, out)
	}

	event := readStructuredLogEvent(t, logPath, "invalid_startup_configuration")
	if got, _ := event["err"].(string); !strings.Contains(got, "worker.count must be no greater than 64") {
		t.Fatalf("invalid startup error=%q, want worker.count maximum rejection", got)
	}
}

func TestStartupRejectsWorkerCountAboveMaximumSubprocess(t *testing.T) {
	if os.Getenv(startupWorkerHelperEnv) != "1" {
		return
	}
	logPath := os.Getenv(startupWorkerLogPathEnv)
	if logPath == "" {
		t.Fatal("startup worker helper log path is empty")
	}
	code := runMainForTest(t,
		"-worker.count=128",
		"-web.telemetry-path=invalid",
		"-log.file.enable=true",
		"-log.file.path="+logPath,
	)
	if code != 2 {
		t.Fatalf("runMain exit code=%d, want 2 for invalid worker count", code)
	}
}

func readStructuredLogEvent(t *testing.T, logPath, message string) map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var event map[string]interface{}
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("invalid startup JSON log %q: %v", line, err)
		}
		if event["msg"] == message {
			return event
		}
	}
	t.Fatalf("%s event missing from logs: %s", message, data)
	return nil
}
