package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestDataIntegrityWorkloadAlertSourceHealthGatesWithPromtool(t *testing.T) {
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
	}{Groups: []nativeGroup{{Name: "data-integrity-source-health-gates"}}}
	wanted := map[string]struct{}{
		"OpenStackInstanceAttentionHigh":                        {},
		"OpenStackInstanceResourceCPUHigh":                      {},
		"OpenStackInstanceHighStealRate":                        {},
		"OpenStackInstanceExporterHostConntrackUtilizationHigh": {},
		"OpenStackInstanceMiningSuspected":                      {},
	}
	for _, group := range loadAlertRules(t).Groups {
		for _, rule := range group.Rules {
			if _, ok := wanted[rule.Alert]; !ok {
				continue
			}
			expression := normalizedAlertExpression(rule.Expr)
			if strings.HasPrefix(rule.Alert, "OpenStackInstanceMining") {
				expression = renderTemplatedAlertExpression(t, rule.Expr)
			}
			native.Groups[0].Rules = append(native.Groups[0].Rules, nativeRule{
				Alert:  rule.Alert,
				Expr:   expression,
				For:    rule.For,
				Labels: rule.Labels,
			})
			delete(wanted, rule.Alert)
		}
	}
	if len(wanted) != 0 {
		t.Fatalf("source-health lifecycle rules missing from alert file: %v", wanted)
	}

	dir := t.TempDir()
	rulesBytes, err := yaml.Marshal(native)
	if err != nil {
		t.Fatal(err)
	}
	rulesPath := filepath.Join(dir, "rules.yml")
	if err := os.WriteFile(rulesPath, rulesBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	testSpec := fmt.Sprintf(`rule_files:
  - %s
evaluation_interval: 1m
tests:
  - name: libvirt failure resets a pending Libvirt-only alert
    interval: 1m
    input_series:
      - series: 'oie_instance_resource_cpu_severity{domain="d",instance="node",job="openstack-instance-exporter",instance_uuid="vm-cpu",project_uuid="p",user_uuid="u"}'
        values: '80x15'
      - series: 'oie_instance_resource_axis_fresh{axis="cpu",domain="d",instance="node",job="openstack-instance-exporter",instance_uuid="vm-cpu",project_uuid="p",user_uuid="u"}'
        values: '1x15'
      - series: 'oie_instance_resource_axis_available{axis="cpu",domain="d",instance="node",job="openstack-instance-exporter",instance_uuid="vm-cpu",project_uuid="p",user_uuid="u"}'
        values: '1x15'
      - series: 'oie_host_libvirt_ok{instance="node",job="openstack-instance-exporter"}'
        values: '1 1 1 0 0 0 0 0 1 1 1 1 1 1 1 1'
      - series: 'up{instance="node",job="openstack-instance-exporter"}'
        values: '1x15'
    alert_rule_test:
      - eval_time: 7m
        alertname: OpenStackInstanceResourceCPUHigh
        exp_alerts: []
      - eval_time: 12m
        alertname: OpenStackInstanceResourceCPUHigh
        exp_alerts: []
      - eval_time: 13m
        alertname: OpenStackInstanceResourceCPUHigh
        exp_alerts:
          - exp_labels: {domain: d, instance_uuid: vm-cpu, project_uuid: p, user_uuid: u, severity: warning, policy: environment-tuned}

  - name: conntrack failure resets a pending composite alert
    interval: 1m
    input_series:
      - series: 'oie_instance_attention_severity{domain="d",instance="node",job="openstack-instance-exporter",instance_uuid="vm-attention",project_uuid="p",user_uuid="u"}'
        values: '80x15'
      - series: 'oie_instance_resource_axis_fresh{axis="cpu",domain="d",instance="node",job="openstack-instance-exporter",instance_uuid="vm-attention",project_uuid="p",user_uuid="u"}'
        values: '1x15'
      - series: 'oie_instance_resource_axis_available{axis="cpu",domain="d",instance="node",job="openstack-instance-exporter",instance_uuid="vm-attention",project_uuid="p",user_uuid="u"}'
        values: '1x15'
      - series: 'oie_host_libvirt_ok{instance="node",job="openstack-instance-exporter"}'
        values: '1x15'
      - series: 'oie_host_conntrack_raw_ok{instance="node",job="openstack-instance-exporter"}'
        values: '1 1 1 0 0 0 0 0 1 1 1 1 1 1 1 1'
      - series: 'oie_host_threat_feed_fresh{instance="node",job="openstack-instance-exporter",list="TOREXIT"}'
        values: '1x15'
      - series: 'up{instance="node",job="openstack-instance-exporter"}'
        values: '1x15'
    alert_rule_test:
      - eval_time: 7m
        alertname: OpenStackInstanceAttentionHigh
        exp_alerts: []
      - eval_time: 12m
        alertname: OpenStackInstanceAttentionHigh
        exp_alerts: []
      - eval_time: 13m
        alertname: OpenStackInstanceAttentionHigh
        exp_alerts:
          - exp_labels: {domain: d, instance_uuid: vm-attention, project_uuid: p, user_uuid: u, severity: warning, policy: environment-tuned}

  - name: unhealthy target does not suppress a healthy target
    interval: 1m
    input_series:
      - series: 'oie_instance_attention_severity{domain="d",instance="node-good",job="openstack-instance-exporter",instance_uuid="vm-good",project_uuid="p",user_uuid="u"}'
        values: '80x7'
      - series: 'oie_instance_attention_severity{domain="d",instance="node-bad",job="openstack-instance-exporter",instance_uuid="vm-bad",project_uuid="p",user_uuid="u"}'
        values: '80x7'
      - series: 'oie_instance_resource_axis_fresh{axis="cpu",domain="d",instance="node-good",job="openstack-instance-exporter",instance_uuid="vm-good",project_uuid="p",user_uuid="u"}'
        values: '1x7'
      - series: 'oie_instance_resource_axis_available{axis="cpu",domain="d",instance="node-good",job="openstack-instance-exporter",instance_uuid="vm-good",project_uuid="p",user_uuid="u"}'
        values: '1x7'
      - series: 'oie_instance_resource_axis_fresh{axis="cpu",domain="d",instance="node-bad",job="openstack-instance-exporter",instance_uuid="vm-bad",project_uuid="p",user_uuid="u"}'
        values: '1x7'
      - series: 'oie_instance_resource_axis_available{axis="cpu",domain="d",instance="node-bad",job="openstack-instance-exporter",instance_uuid="vm-bad",project_uuid="p",user_uuid="u"}'
        values: '1x7'
      - series: 'oie_host_libvirt_ok{instance="node-good",job="openstack-instance-exporter"}'
        values: '1x7'
      - series: 'oie_host_libvirt_ok{instance="node-bad",job="openstack-instance-exporter"}'
        values: '1x7'
      - series: 'oie_host_conntrack_raw_ok{instance="node-good",job="openstack-instance-exporter"}'
        values: '1x7'
      - series: 'oie_host_conntrack_raw_ok{instance="node-bad",job="openstack-instance-exporter"}'
        values: '0x7'
      - series: 'oie_host_threat_feed_fresh{instance="node-good",job="openstack-instance-exporter",list="TOREXIT"}'
        values: '1x7'
      - series: 'oie_host_threat_feed_fresh{instance="node-bad",job="openstack-instance-exporter",list="TOREXIT"}'
        values: '1x7'
      - series: 'up{instance="node-good",job="openstack-instance-exporter"}'
        values: '1x7'
      - series: 'up{instance="node-bad",job="openstack-instance-exporter"}'
        values: '1x7'
    alert_rule_test:
      - eval_time: 6m
        alertname: OpenStackInstanceAttentionHigh
        exp_alerts:
          - exp_labels: {domain: d, instance_uuid: vm-good, project_uuid: p, user_uuid: u, severity: warning, policy: environment-tuned}

  - name: Libvirt recovery cannot immediately reuse range history
    interval: 1m
    input_series:
      - series: 'oie_instance_cpu_steal_seconds_total{domain="d",instance="node",job="openstack-instance-exporter",instance_uuid="vm-steal",project_uuid="p",user_uuid="u"}'
        values: '0+6x15'
      - series: 'oie_host_libvirt_ok{instance="node",job="openstack-instance-exporter"}'
        values: '1 1 0 0 0 0 1 1 1 1 1 1 1 1 1 1'
      - series: 'up{instance="node",job="openstack-instance-exporter"}'
        values: '1x15'
    alert_rule_test:
      - eval_time: 6m
        alertname: OpenStackInstanceHighStealRate
        exp_alerts: []
      - eval_time: 11m
        alertname: OpenStackInstanceHighStealRate
        exp_alerts: []
      - eval_time: 12m
        alertname: OpenStackInstanceHighStealRate
        exp_alerts: []
      - eval_time: 13m
        alertname: OpenStackInstanceHighStealRate
        exp_alerts:
          - exp_labels: {domain: d, instance_uuid: vm-steal, project_uuid: p, user_uuid: u, severity: warning}

  - name: conntrack-only host alert is suppressed and restarts after recovery
    interval: 1m
    input_series:
      - series: 'oie_host_conntrack_utilization{instance="node",job="openstack-instance-exporter"}'
        values: '0.9x12'
      - series: 'oie_host_conntrack_raw_ok{instance="node",job="openstack-instance-exporter"}'
        values: '1 1 0 0 0 0 1 1 1 1 1 1 1'
      - series: 'up{instance="node",job="openstack-instance-exporter"}'
        values: '1x12'
    alert_rule_test:
      - eval_time: 5m
        alertname: OpenStackInstanceExporterHostConntrackUtilizationHigh
        exp_alerts: []
      - eval_time: 10m
        alertname: OpenStackInstanceExporterHostConntrackUtilizationHigh
        exp_alerts: []
      - eval_time: 11m
        alertname: OpenStackInstanceExporterHostConntrackUtilizationHigh
        exp_alerts:
          - exp_labels: {instance: node, job: openstack-instance-exporter, severity: warning}

  - name: mining suspicion waits for a fully healthy corroboration window
    interval: 1m
    input_series:
      - series: 'oie_instance_mining_suspected{confidence="high_persistent",domain="d",instance="node",job="openstack-instance-exporter",instance_uuid="vm-mining",project_uuid="p",user_uuid="u"}'
        values: '1x12'
      - series: 'oie_instance_cpu_vcpu_percent{domain="d",instance="node",job="openstack-instance-exporter",instance_uuid="vm-mining",project_uuid="p",user_uuid="u"}'
        values: '50x12'
      - series: 'oie_instance_resource_axis_fresh{axis="cpu",domain="d",instance="node",job="openstack-instance-exporter",instance_uuid="vm-mining",project_uuid="p",user_uuid="u"}'
        values: '1x12'
      - series: 'oie_instance_resource_axis_last_success_timestamp_seconds{axis="cpu",domain="d",instance="node",job="openstack-instance-exporter",instance_uuid="vm-mining",project_uuid="p",user_uuid="u"}'
        values: '100+60x12'
      - series: 'oie_host_libvirt_ok{instance="node",job="openstack-instance-exporter"}'
        values: '1x12'
      - series: 'oie_host_conntrack_raw_ok{instance="node",job="openstack-instance-exporter"}'
        values: '1 1 0 0 0 0 1 1 1 1 1 1 1'
      - series: 'up{instance="node",job="openstack-instance-exporter"}'
        values: '1x12'
    alert_rule_test:
      - eval_time: 6m
        alertname: OpenStackInstanceMiningSuspected
        exp_alerts: []
      - eval_time: 9m
        alertname: OpenStackInstanceMiningSuspected
        exp_alerts: []
      - eval_time: 10m
        alertname: OpenStackInstanceMiningSuspected
        exp_alerts: []
      - eval_time: 11m
        alertname: OpenStackInstanceMiningSuspected
        exp_alerts: []
      - eval_time: 12m
        alertname: OpenStackInstanceMiningSuspected
        exp_alerts:
          - exp_labels: {domain: d, instance_uuid: vm-mining, project_uuid: p, user_uuid: u, severity: warning}
`, rulesPath)
	testPath := filepath.Join(dir, "test.yml")
	if err := os.WriteFile(testPath, []byte(testSpec), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(promtool, "test", "rules", testPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("promtool source-health gate lifecycle tests failed: %v\n%s", err, output)
	}
}
