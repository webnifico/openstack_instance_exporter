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

func TestStartupConfigLogsEffectiveBehaviorSensitivity(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "startup.jsonl")
	cmd := exec.Command(os.Args[0], "-test.run=^TestStartupConfigLogsEffectiveBehaviorSensitivitySubprocess$")
	cmd.Env = append(os.Environ(),
		startupSensitivityHelperEnv+"=1",
		startupSensitivityLogPathEnv+"="+logPath,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("startup sensitivity helper: %v\n%s", err, out)
	}

	startup := readStartupConfigEvent(t, logPath)
	if got := startup["behavior_sensitivity"]; got != float64(10) {
		t.Fatalf("startup_config behavior_sensitivity=%v, want effective clamped value 10", got)
	}
}

func TestStartupConfigLogsEffectiveBehaviorSensitivitySubprocess(t *testing.T) {
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
		t.Fatalf("runMain exit code=%d, want 2 for invalid telemetry path", code)
	}
}

func TestStartupConfigLogsCappedEffectiveWorkerCount(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "startup.jsonl")
	cmd := exec.Command(os.Args[0], "-test.run=^TestStartupConfigLogsCappedEffectiveWorkerCountSubprocess$")
	cmd.Env = append(os.Environ(),
		startupWorkerHelperEnv+"=1",
		startupWorkerLogPathEnv+"="+logPath,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("startup worker helper: %v\n%s", err, out)
	}

	startup := readStartupConfigEvent(t, logPath)
	if got := startup["worker_count_effective"]; got != float64(64) {
		t.Fatalf("startup_config worker_count_effective=%v, want actual collector cap 64", got)
	}
}

func TestStartupConfigLogsCappedEffectiveWorkerCountSubprocess(t *testing.T) {
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
		t.Fatalf("runMain exit code=%d, want 2 for invalid telemetry path", code)
	}
}

func readStartupConfigEvent(t *testing.T, logPath string) map[string]interface{} {
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
		if event["msg"] == "startup_config" {
			return event
		}
	}
	t.Fatalf("startup_config event missing from logs: %s", data)
	return nil
}

func TestAlertDescriptionsUseCurrentScoringAndEvidenceSemantics(t *testing.T) {
	wantDescriptions := map[string]string{
		"OpenStackInstanceAttentionHigh":           "Combined resource, behavior, and threat-list attention score for instance {{ $labels.instance_uuid }} is elevated. Needs review.",
		"OpenStackInstanceAttentionSevere":         "Instance {{ $labels.instance_uuid }} shows severe combined resource, behavior, or threat-list evidence.",
		"OpenStackInstanceZombieFlowWarning":       "Conntrack flow entries above 5,000 for 30 minutes. Possible application leak or sustained high-flow connection pool.",
		"OpenStackInstanceSpamhausRepeatedContact": "5+ contacts in 5 minutes with IPs or networks present in the Spamhaus DROP/EDROP feed. Investigate the instance and connection evidence.",
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
