package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const startupSensitivityHelperEnv = "OIE_STARTUP_SENSITIVITY_HELPER"
const startupSensitivityLogPathEnv = "OIE_STARTUP_SENSITIVITY_LOG_PATH"
const startupWorkerHelperEnv = "OIE_STARTUP_WORKER_HELPER"
const startupWorkerLogPathEnv = "OIE_STARTUP_WORKER_LOG_PATH"

func TestAttentionSeverityHelpNamesEveryScoringInput(t *testing.T) {
	mc, err := NewMetricsCollector(CollectorConfig{
		LibvirtURI:         "qemu:///system",
		CollectionInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer close(mc.shutdownChan)

	helpContract := "Combined attention severity (0-100) based on resource pressure, behavior anomalies, and threat-list signals"
	if got := mc.instanceAttentionSeverityDesc.String(); !strings.Contains(got, `help: "`+helpContract+`"`) {
		t.Fatalf("attention severity help does not describe all scoring inputs: %s", got)
	}
}

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

func TestAlertDescriptionsUseCurrentScoringAndEvidenceSemantics(t *testing.T) {
	wantDescriptions := map[string]string{
		"OpenStackInstanceAttentionHigh":           "Observed combined attention severity is at least 60 and below 85. This broad environment-tuned heuristic requires operator review of its resource, behavior, and threat components.",
		"OpenStackInstanceAttentionSevere":         "Observed combined attention severity is at least 85. This broad environment-tuned heuristic requires operator review of its resource, behavior, and threat components.",
		"OpenStackInstanceZombieFlowWarning":       "Observed conntrack flow count is between 5,001 and 20,000 for thirty minutes. This environment-tuned heuristic may reflect a connection leak or a legitimate pool. Requires operator review.",
		"OpenStackInstanceSpamhausRepeatedContact": "Observed at least five contacts with the currently usable Spamhaus DROP or EDROP feed in five minutes. This optional diagnostic requires operator review.",
	}
	found := make(map[string]bool, len(wantDescriptions))
	for _, group := range loadAlertRules(t).Groups {
		for _, rule := range group.Rules {
			want, ok := wantDescriptions[rule.Alert]
			if !ok {
				continue
			}
			found[rule.Alert] = true
			if got := rule.Annotations["description"]; got != want {
				t.Errorf("%s description=%q, want %q", rule.Alert, got, want)
			}
		}
	}
	for alert := range wantDescriptions {
		if !found[alert] {
			t.Errorf("required alert %s is missing", alert)
		}
	}
}
