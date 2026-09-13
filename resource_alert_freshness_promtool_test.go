package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestResourceTelemetryResourceAlertFreshnessLifecycleWithPromtool(t *testing.T) {
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
	}{Groups: []nativeGroup{{Name: "resource-telemetry-freshness"}}}
	wanted := map[string]struct{}{
		"OpenStackInstanceResourceCPUHigh":      {},
		"OpenStackInstanceResourceDiskHigh":     {},
		"OpenStackInstanceHighResourcePressure": {},
		"OpenStackInstanceAttentionHigh":        {},
	}
	for _, group := range loadAlertRules(t).Groups {
		for _, rule := range group.Rules {
			if _, selected := wanted[rule.Alert]; !selected {
				continue
			}
			native.Groups[0].Rules = append(native.Groups[0].Rules, nativeRule{
				Alert: rule.Alert, Expr: normalizedAlertExpression(rule.Expr), For: rule.For, Labels: rule.Labels,
			})
			delete(wanted, rule.Alert)
		}
	}
	if len(wanted) != 0 {
		t.Fatalf("Resource telemetry resource freshness lifecycle rules missing: %v", wanted)
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
  - name: an axis alert requires the matching instance axis to be fresh
    interval: 1m
    input_series:
      - series: 'oie_instance_resource_cpu_severity{domain="d",instance="node",job="openstack-instance-exporter",instance_uuid="vm-axis",project_uuid="p",user_uuid="u"}'
        values: '80x15'
      - series: 'oie_instance_resource_disk_severity{domain="d",instance="node",job="openstack-instance-exporter",instance_uuid="vm-axis",project_uuid="p",user_uuid="u"}'
        values: '80x15'
      - series: 'oie_instance_resource_axis_fresh{axis="cpu",domain="d",instance="node",job="openstack-instance-exporter",instance_uuid="vm-axis",project_uuid="p",user_uuid="u"}'
        values: '1 1 0 0 0 0 0 1 1 1 1 1 1 1 1 1'
      - series: 'oie_instance_resource_axis_available{axis="cpu",domain="d",instance="node",job="openstack-instance-exporter",instance_uuid="vm-axis",project_uuid="p",user_uuid="u"}'
        values: '1x16'
      - series: 'oie_instance_resource_axis_fresh{axis="disk",domain="d",instance="node",job="openstack-instance-exporter",instance_uuid="vm-axis",project_uuid="p",user_uuid="u"}'
        values: '1x16'
      - series: 'oie_instance_resource_axis_available{axis="disk",domain="d",instance="node",job="openstack-instance-exporter",instance_uuid="vm-axis",project_uuid="p",user_uuid="u"}'
        values: '1x16'
      - series: 'oie_instance_resource_axis_fresh{axis="cpu",domain="d",instance="node",job="openstack-instance-exporter",instance_uuid="vm-other",project_uuid="p",user_uuid="u"}'
        values: '1x16'
      - series: 'oie_instance_resource_axis_available{axis="cpu",domain="d",instance="node",job="openstack-instance-exporter",instance_uuid="vm-other",project_uuid="p",user_uuid="u"}'
        values: '1x16'
      - series: 'oie_host_libvirt_ok{instance="node",job="openstack-instance-exporter"}'
        values: '1x16'
      - series: 'up{instance="node",job="openstack-instance-exporter"}'
        values: '1x16'
    alert_rule_test:
      - eval_time: 6m
        alertname: OpenStackInstanceResourceCPUHigh
        exp_alerts: []
      - eval_time: 6m
        alertname: OpenStackInstanceResourceDiskHigh
        exp_alerts:
          - exp_labels: {domain: d, instance_uuid: vm-axis, project_uuid: p, user_uuid: u, severity: warning, policy: environment-tuned}
      - eval_time: 11m
        alertname: OpenStackInstanceResourceCPUHigh
        exp_alerts: []
      - eval_time: 12m
        alertname: OpenStackInstanceResourceCPUHigh
        exp_alerts:
          - exp_labels: {domain: d, instance_uuid: vm-axis, project_uuid: p, user_uuid: u, severity: warning, policy: environment-tuned}

  - name: a composite requires every available axis fresh and at least one available
    interval: 1m
    input_series:
      - series: 'oie_instance_resource_severity{domain="d",instance="node",job="openstack-instance-exporter",instance_uuid="vm-mixed",project_uuid="p",user_uuid="u"}'
        values: '80x8'
      - series: 'oie_instance_attention_severity{domain="d",instance="node",job="openstack-instance-exporter",instance_uuid="vm-mixed",project_uuid="p",user_uuid="u"}'
        values: '80x8'
      - series: 'oie_instance_resource_severity{domain="d",instance="node",job="openstack-instance-exporter",instance_uuid="vm-single",project_uuid="p",user_uuid="u"}'
        values: '80x8'
      - series: 'oie_instance_attention_severity{domain="d",instance="node",job="openstack-instance-exporter",instance_uuid="vm-single",project_uuid="p",user_uuid="u"}'
        values: '80x8'
      - series: 'oie_instance_resource_severity{domain="d",instance="node",job="openstack-instance-exporter",instance_uuid="vm-none",project_uuid="p",user_uuid="u"}'
        values: '80x8'
      - series: 'oie_instance_attention_severity{domain="d",instance="node",job="openstack-instance-exporter",instance_uuid="vm-none",project_uuid="p",user_uuid="u"}'
        values: '80x8'
      - series: 'oie_instance_resource_axis_fresh{axis="cpu",domain="d",instance="node",job="openstack-instance-exporter",instance_uuid="vm-mixed",project_uuid="p",user_uuid="u"}'
        values: '1x8'
      - series: 'oie_instance_resource_axis_available{axis="cpu",domain="d",instance="node",job="openstack-instance-exporter",instance_uuid="vm-mixed",project_uuid="p",user_uuid="u"}'
        values: '1x8'
      - series: 'oie_instance_resource_axis_fresh{axis="mem",domain="d",instance="node",job="openstack-instance-exporter",instance_uuid="vm-mixed",project_uuid="p",user_uuid="u"}'
        values: '0x8'
      - series: 'oie_instance_resource_axis_available{axis="mem",domain="d",instance="node",job="openstack-instance-exporter",instance_uuid="vm-mixed",project_uuid="p",user_uuid="u"}'
        values: '1x8'
      - series: 'oie_instance_resource_axis_fresh{axis="cpu",domain="d",instance="node",job="openstack-instance-exporter",instance_uuid="vm-single",project_uuid="p",user_uuid="u"}'
        values: '1x8'
      - series: 'oie_instance_resource_axis_available{axis="cpu",domain="d",instance="node",job="openstack-instance-exporter",instance_uuid="vm-single",project_uuid="p",user_uuid="u"}'
        values: '1x8'
      - series: 'oie_instance_resource_axis_fresh{axis="mem",domain="d",instance="node",job="openstack-instance-exporter",instance_uuid="vm-single",project_uuid="p",user_uuid="u"}'
        values: '0x8'
      - series: 'oie_instance_resource_axis_available{axis="mem",domain="d",instance="node",job="openstack-instance-exporter",instance_uuid="vm-single",project_uuid="p",user_uuid="u"}'
        values: '0x8'
      - series: 'oie_instance_resource_axis_fresh{axis="disk",domain="d",instance="node",job="openstack-instance-exporter",instance_uuid="vm-single",project_uuid="p",user_uuid="u"}'
        values: '0x8'
      - series: 'oie_instance_resource_axis_available{axis="disk",domain="d",instance="node",job="openstack-instance-exporter",instance_uuid="vm-single",project_uuid="p",user_uuid="u"}'
        values: '0x8'
      - series: 'oie_instance_resource_axis_fresh{axis="net",domain="d",instance="node",job="openstack-instance-exporter",instance_uuid="vm-single",project_uuid="p",user_uuid="u"}'
        values: '0x8'
      - series: 'oie_instance_resource_axis_available{axis="net",domain="d",instance="node",job="openstack-instance-exporter",instance_uuid="vm-single",project_uuid="p",user_uuid="u"}'
        values: '0x8'
      - series: 'oie_instance_resource_axis_fresh{axis="cpu",domain="d",instance="node",job="openstack-instance-exporter",instance_uuid="vm-none",project_uuid="p",user_uuid="u"}'
        values: '0x8'
      - series: 'oie_instance_resource_axis_available{axis="cpu",domain="d",instance="node",job="openstack-instance-exporter",instance_uuid="vm-none",project_uuid="p",user_uuid="u"}'
        values: '0x8'
      - series: 'oie_host_libvirt_ok{instance="node",job="openstack-instance-exporter"}'
        values: '1x8'
      - series: 'oie_host_conntrack_raw_ok{instance="node",job="openstack-instance-exporter"}'
        values: '1x8'
      - series: 'oie_host_threat_feed_fresh{instance="node",job="openstack-instance-exporter",list="TOREXIT"}'
        values: '-1x8'
      - series: 'oie_host_threat_feed_fresh{instance="node",job="openstack-instance-exporter",list="TORRELAY"}'
        values: '-1x8'
      - series: 'oie_host_threat_feed_fresh{instance="node",job="openstack-instance-exporter",list="spamhaus"}'
        values: '-1x8'
      - series: 'oie_host_threat_feed_fresh{instance="node",job="openstack-instance-exporter",list="EMERGING"}'
        values: '-1x8'
      - series: 'oie_host_threat_feed_fresh{instance="node",job="openstack-instance-exporter",list="CUSTOMLIST"}'
        values: '-1x8'
      - series: 'up{instance="node",job="openstack-instance-exporter"}'
        values: '1x8'
    alert_rule_test:
      - eval_time: 6m
        alertname: OpenStackInstanceHighResourcePressure
        exp_alerts:
          - exp_labels: {domain: d, instance_uuid: vm-single, project_uuid: p, user_uuid: u, severity: warning, policy: environment-tuned}
      - eval_time: 6m
        alertname: OpenStackInstanceAttentionHigh
        exp_alerts:
          - exp_labels: {domain: d, instance_uuid: vm-single, project_uuid: p, user_uuid: u, severity: warning, policy: environment-tuned}
`, rulesPath)
	testPath := filepath.Join(dir, "test.yml")
	if err := os.WriteFile(testPath, []byte(testSpec), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(promtool, "test", "rules", testPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("promtool Resource telemetry resource freshness lifecycle tests failed: %v\n%s", err, output)
	}
}
