package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestMiningAlertTierEvaluationWithPromtool(t *testing.T) {
	promtool := os.Getenv("PROMTOOL")
	if promtool == "" {
		var err error
		promtool, err = exec.LookPath("promtool")
		if err != nil {
			t.Skip("promtool is not installed")
		}
	}

	type nativeRule struct {
		Alert  string            `yaml:"alert"`
		Expr   string            `yaml:"expr"`
		For    string            `yaml:"for,omitempty"`
		Labels map[string]string `yaml:"labels,omitempty"`
	}
	type nativeGroup struct {
		Name  string       `yaml:"name"`
		Rules []nativeRule `yaml:"rules"`
	}
	native := struct {
		Groups []nativeGroup `yaml:"groups"`
	}{Groups: []nativeGroup{{Name: "mining-tier-test"}}}
	for _, group := range loadAlertRules(t).Groups {
		for _, rule := range group.Rules {
			if rule.Alert != "OpenStackInstanceMiningSuspected" && rule.Alert != "OpenStackInstanceMiningCandidatePersistent" {
				continue
			}
			native.Groups[0].Rules = append(native.Groups[0].Rules, nativeRule{
				Alert:  rule.Alert,
				Expr:   renderTemplatedAlertExpression(t, rule.Expr),
				For:    rule.For,
				Labels: rule.Labels,
			})
		}
	}
	if len(native.Groups[0].Rules) != 2 {
		t.Fatalf("selected mining alert rules=%d, want 2", len(native.Groups[0].Rules))
	}

	dir := t.TempDir()
	rulesBytes, err := yaml.Marshal(native)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rules.yml"), rulesBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	testSpec := fmt.Sprintf(`rule_files:
  - %s
evaluation_interval: 1m
tests:
  - name: mining evidence tiers
    interval: 1m
    input_series:
      - series: 'oie_instance_mining_suspected{domain="d",instance_uuid="vm-high",project_uuid="p",user_uuid="u",confidence="high"}'
        values: '1x20'
      - series: 'oie_instance_mining_suspected{domain="d",instance_uuid="vm-high-cpu",project_uuid="p",user_uuid="u",confidence="high_persistent"}'
        values: '1x20'
      - series: 'oie_instance_cpu_vcpu_percent{domain="d",instance_uuid="vm-high-cpu",project_uuid="p",user_uuid="u"}'
        values: '50x20'
      - series: 'oie_instance_mining_suspected{domain="d",instance_uuid="vm-high-no-cpu",project_uuid="p",user_uuid="u",confidence="high_persistent"}'
        values: '1x20'
      - series: 'oie_instance_mining_suspected{domain="d",instance_uuid="vm-high-sparse-cpu",project_uuid="p",user_uuid="u",confidence="high_persistent"}'
        values: '1x20'
      - series: 'oie_instance_cpu_vcpu_percent{domain="d",instance_uuid="vm-high-sparse-cpu",project_uuid="p",user_uuid="u"}'
        values: '50 _x4 50x15'
      - series: 'oie_instance_mining_suspected{domain="d",instance_uuid="vm-shared-hot",project_uuid="p",user_uuid="u",confidence="shared"}'
        values: '1x20'
      - series: 'oie_instance_cpu_vcpu_percent{domain="d",instance_uuid="vm-shared-hot",project_uuid="p",user_uuid="u"}'
        values: '40x20'
      - series: 'oie_instance_mining_suspected{domain="d",instance_uuid="vm-shared-cold",project_uuid="p",user_uuid="u",confidence="shared"}'
        values: '1x20'
      - series: 'oie_instance_cpu_vcpu_percent{domain="d",instance_uuid="vm-shared-cold",project_uuid="p",user_uuid="u"}'
        values: '20x20'
      - series: 'oie_instance_mining_suspected{domain="d",instance_uuid="vm-shared-persistent",project_uuid="p",user_uuid="u",confidence="shared_persistent"}'
        values: '1x20'
      - series: 'oie_instance_cpu_vcpu_percent{domain="d",instance_uuid="vm-shared-persistent",project_uuid="p",user_uuid="u"}'
        values: '65x20'
    alert_rule_test:
      - eval_time: 5m
        alertname: OpenStackInstanceMiningSuspected
        exp_alerts:
          - exp_labels: {domain: d, instance_uuid: vm-high, project_uuid: p, user_uuid: u, confidence: high, severity: warning}
          - exp_labels: {domain: d, instance_uuid: vm-high-cpu, project_uuid: p, user_uuid: u, confidence: high_persistent, severity: warning}
          - exp_labels: {domain: d, instance_uuid: vm-shared-hot, project_uuid: p, user_uuid: u, confidence: shared, severity: warning}
          - exp_labels: {domain: d, instance_uuid: vm-shared-persistent, project_uuid: p, user_uuid: u, confidence: shared_persistent, severity: warning}
      - eval_time: 5m
        alertname: OpenStackInstanceMiningCandidatePersistent
        exp_alerts: []
      - eval_time: 16m
        alertname: OpenStackInstanceMiningCandidatePersistent
        exp_alerts:
          - exp_labels: {domain: d, instance_uuid: vm-high-no-cpu, project_uuid: p, user_uuid: u, confidence: high_persistent, severity: info}
`, filepath.Join(dir, "rules.yml"))
	testPath := filepath.Join(dir, "test.yml")
	if err := os.WriteFile(testPath, []byte(testSpec), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(promtool, "test", "rules", testPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("promtool mining tier tests failed: %v\n%s", err, output)
	}
}
