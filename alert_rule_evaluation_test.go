package main

import (
	"gopkg.in/yaml.v3"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

type alertValidationPromtoolRuleFile struct {
	Groups []alertValidationPromtoolRuleGroup `yaml:"groups"`
}

type alertValidationPromtoolRuleGroup struct {
	Name  string                        `yaml:"name"`
	Rules []alertValidationPromtoolRule `yaml:"rules"`
}

type alertValidationPromtoolRule struct {
	Alert  string            `yaml:"alert,omitempty"`
	Record string            `yaml:"record,omitempty"`
	Expr   string            `yaml:"expr"`
	For    string            `yaml:"for,omitempty"`
	Labels map[string]string `yaml:"labels,omitempty"`
}

type alertValidationPromtoolTestFile struct {
	RuleFiles          []string                           `yaml:"rule_files"`
	EvaluationInterval string                             `yaml:"evaluation_interval"`
	Tests              []alertValidationPromtoolTestGroup `yaml:"tests"`
}

type alertValidationPromtoolTestGroup struct {
	Name          string                               `yaml:"name"`
	Interval      string                               `yaml:"interval"`
	InputSeries   []alertValidationPromtoolInputSeries `yaml:"input_series"`
	AlertRuleTest []alertValidationPromtoolAlertTest   `yaml:"alert_rule_test"`
}

type alertValidationPromtoolInputSeries struct {
	Series string `yaml:"series"`
	Values string `yaml:"values"`
}

type alertValidationPromtoolAlertTest struct {
	EvalTime string                                 `yaml:"eval_time"`
	Alert    string                                 `yaml:"alertname"`
	Expected []alertValidationPromtoolExpectedAlert `yaml:"exp_alerts"`
}

type alertValidationPromtoolExpectedAlert struct {
	Labels map[string]string `yaml:"exp_labels"`
}

func alertValidationPromtoolPath(t *testing.T) string {
	t.Helper()
	if path := os.Getenv("PROMTOOL"); path != "" {
		return path
	}
	path, err := exec.LookPath("promtool")
	if err != nil {
		t.Skip("promtool is not installed")
	}
	return path
}

func alertValidationSeries(metric string, labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(metric)
	if len(keys) == 0 {
		return b.String()
	}
	b.WriteByte('{')
	for i, key := range keys {
		if i != 0 {
			b.WriteByte(',')
		}
		b.WriteString(key)
		b.WriteByte('=')
		b.WriteString(strconv.Quote(labels[key]))
	}
	b.WriteByte('}')
	return b.String()
}

func alertValidationValues(sampleCount int, value func(int) float64) string {
	values := make([]string, sampleCount)
	for i := range values {
		values[i] = strconv.FormatFloat(value(i), 'g', -1, 64)
	}
	return strings.Join(values, " ")
}

func alertValidationCopyLabels(labels map[string]string) map[string]string {
	out := make(map[string]string, len(labels)+1)
	for key, value := range labels {
		out[key] = value
	}
	return out
}

func alertValidationInstanceLabels() map[string]string {
	return map[string]string{
		"domain":        "d",
		"instance":      "node",
		"instance_uuid": "vm",
		"job":           "openstack-instance-exporter",
		"project_name":  "project",
		"project_uuid":  "p",
		"server_name":   "server",
		"user_uuid":     "u",
	}
}

func alertValidationLabels(extra map[string]string) map[string]string {
	labels := alertValidationInstanceLabels()
	for key, value := range extra {
		labels[key] = value
	}
	return labels
}

func alertValidationMiningLabels(confidence string) map[string]string {
	return alertValidationLabels(map[string]string{
		"confidence": confidence,
		"family":     "4",
		"ip":         "192.0.2.10",
		"port":       "3333",
		"port_name":  "stratum",
	})
}

func alertValidationRuleInventory(t *testing.T) (map[string]dataIntegrityAlertRule, []string) {
	t.Helper()
	rules := make(map[string]dataIntegrityAlertRule)
	order := make([]string, 0)
	for _, group := range loadCurrentAlertRules(t).Groups {
		for _, rule := range group.Rules {
			if _, duplicate := rules[rule.Alert]; duplicate {
				t.Fatalf("duplicate bundled alert %q", rule.Alert)
			}
			rules[rule.Alert] = dataIntegrityAlertRule{Alert: rule.Alert, Expr: rule.Expr, For: rule.For, Labels: rule.Labels, Annotations: rule.Annotations}
			order = append(order, rule.Alert)
		}
	}
	return rules, order
}

func alertValidationRunSelectedPromtool(t *testing.T, testName string, alertNames []string, groups []alertValidationPromtoolTestGroup) {
	t.Helper()
	rules, _ := alertValidationRuleInventory(t)
	selected := make([]alertValidationPromtoolRule, 0, len(alertNames))
	for _, name := range alertNames {
		rule, ok := rules[name]
		if !ok {
			t.Fatalf("selected Prometheus alert validation rule %q is missing", name)
		}
		selected = append(selected, alertValidationPromtoolRule{
			Alert: name, Expr: normalizedAlertExpression(rule.Expr), For: rule.For, Labels: rule.Labels,
		})
	}
	alertValidationRunPromtoolRules(t, testName, selected, groups)
}

func alertValidationRunPromtoolRules(t *testing.T, testName string, rules []alertValidationPromtoolRule, groups []alertValidationPromtoolTestGroup) {
	t.Helper()
	promtool := alertValidationPromtoolPath(t)
	// Evaluate the shipped measurement helpers before alerts at the same timestamp.
	provided := map[string]alertValidationPromtoolRule{}
	for _, r := range rules {
		if r.Record != "" {
			provided[r.Record] = r
		}
	}
	composed := []alertValidationPromtoolRule{}
	for _, group := range loadCurrentAlertRules(t).Groups {
		for _, r := range group.RecordingRules {
			selected := alertValidationPromtoolRule{Record: r.Record, Expr: r.Expr, Labels: r.Labels}
			if override, ok := provided[r.Record]; ok {
				selected = override
				delete(provided, r.Record)
			}
			composed = append(composed, selected)
		}
	}
	for _, r := range rules {
		if r.Record != "" {
			if _, ok := provided[r.Record]; ok {
				composed = append(composed, r)
			}
		}
	}
	for _, r := range rules {
		if r.Record == "" {
			composed = append(composed, r)
		}
	}
	rules = composed

	native := alertValidationPromtoolRuleFile{Groups: []alertValidationPromtoolRuleGroup{{Name: testName, Rules: rules}}}
	dir := t.TempDir()
	ruleBytes, err := yaml.Marshal(native)
	if err != nil {
		t.Fatal(err)
	}
	rulesPath := filepath.Join(dir, "rules.yml")
	if err := os.WriteFile(rulesPath, ruleBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	testBytes, err := yaml.Marshal(alertValidationPromtoolTestFile{
		RuleFiles: []string{rulesPath}, EvaluationInterval: "1m", Tests: groups,
	})
	if err != nil {
		t.Fatal(err)
	}
	testPath := filepath.Join(dir, "tests.yml")
	if err := os.WriteFile(testPath, testBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(promtool, "test", "rules", testPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("promtool rejected %s: %v\n%s", testName, err, output)
	}
}
