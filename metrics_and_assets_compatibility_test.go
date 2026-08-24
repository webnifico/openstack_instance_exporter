package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/yaml.v3"
)

var (
	descNameRE   = regexp.MustCompile(`fqName: "([^"]+)"`)
	descLabelsRE = regexp.MustCompile(`variableLabels: \{([^}]*)\}`)
	oieMetricRE  = regexp.MustCompile(`\boie_[A-Za-z0-9_]+\b`)
)

func descriptorContract(t *testing.T) ([]string, map[string]struct{}) {
	t.Helper()
	mc, err := NewMetricsCollector(CollectorConfig{LibvirtURI: "qemu:///system", CollectionInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer close(mc.shutdownChan)
	ch := make(chan *prometheus.Desc, 4096)
	mc.Describe(ch)
	close(ch)
	lines := make([]string, 0, 128)
	names := make(map[string]struct{}, 128)
	for desc := range ch {
		s := desc.String()
		nameMatch := descNameRE.FindStringSubmatch(s)
		if len(nameMatch) != 2 {
			t.Fatalf("cannot parse descriptor %q", s)
		}
		labels := ""
		if labelMatch := descLabelsRE.FindStringSubmatch(s); len(labelMatch) == 2 {
			labels = labelMatch[1]
		}
		lines = append(lines, nameMatch[1]+"|"+labels)
		names[nameMatch[1]] = struct{}{}
	}
	sort.Strings(lines)
	return lines, names
}

func goldenLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(strings.TrimSpace(string(b)))
}

func TestMetricNamesAndLabelsMatchV120Golden(t *testing.T) {
	got, _ := descriptorContract(t)
	v120 := goldenLines(t, "testdata/metrics-v1.2.0.golden")
	additions := goldenLines(t, "testdata/metrics-v1.3.0-additions.golden")
	want := append(append([]string{}, v120...), additions...)
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("metric contract changed outside approved v1.3.0 additions\nwant:\n%s\n\ngot:\n%s", strings.Join(want, "\n"), strings.Join(got, "\n"))
	}
}

func TestDefaultRuntimeCollectorsRemainRegistered(t *testing.T) {
	collectors := defaultRuntimeCollectors()
	if len(collectors) != 3 {
		t.Fatalf("runtime collector count = %d, want 3", len(collectors))
	}
	got := make(map[string]struct{})
	for _, collector := range collectors {
		ch := make(chan *prometheus.Desc, 256)
		collector.Describe(ch)
		close(ch)
		for desc := range ch {
			if match := descNameRE.FindStringSubmatch(desc.String()); len(match) == 2 {
				got[match[1]] = struct{}{}
			}
		}
	}
	for _, required := range []string{"go_build_info", "go_gc_duration_seconds", "process_cpu_seconds_total"} {
		if _, ok := got[required]; !ok {
			available := make([]string, 0, len(got))
			for name := range got {
				available = append(available, name)
			}
			sort.Strings(available)
			t.Fatalf("default runtime metric %q is missing; got %v", required, available)
		}
	}
}

type alertRulesFile struct {
	Groups []struct {
		Name  string `yaml:"group_name"`
		Job   string `yaml:"group_exporter_job"`
		Rules []struct {
			Alert       string            `yaml:"alert"`
			Expr        string            `yaml:"expr"`
			For         string            `yaml:"for"`
			Labels      map[string]string `yaml:"labels"`
			Annotations map[string]string `yaml:"annotations"`
		} `yaml:"group_rules"`
	} `yaml:"prometheus_alert_rules"`
}

func loadAlertRules(t *testing.T) alertRulesFile {
	t.Helper()
	b, err := os.ReadFile("examples/prometheus_alerts_example/openstack_instance_exporter_alerts.yml")
	if err != nil {
		t.Fatal(err)
	}
	var file alertRulesFile
	decoder := yaml.NewDecoder(bytes.NewReader(b))
	decoder.KnownFields(true)
	if err := decoder.Decode(&file); err != nil {
		t.Fatalf("alert YAML: %v", err)
	}
	return file
}

func renderTemplatedAlertExpression(t *testing.T, expression string) string {
	t.Helper()
	var rendered struct {
		Expr string `yaml:"expr"`
	}
	if err := yaml.Unmarshal([]byte("expr: \""+expression+"\"\n"), &rendered); err != nil {
		t.Fatalf("alert expression is unsafe for the double-quoted Prometheus template: %v", err)
	}
	return rendered.Expr
}

func normalizedAlertExpression(expression string) string {
	return strings.ReplaceAll(expression, `\"`, `"`)
}

func TestPrometheusAlertExpressionsWithPromtool(t *testing.T) {
	promtool := os.Getenv("PROMTOOL")
	if promtool == "" {
		var err error
		promtool, err = exec.LookPath("promtool")
		if err != nil {
			t.Skip("promtool is not installed")
		}
	}
	file := loadAlertRules(t)
	type nativeRule struct {
		Alert       string            `yaml:"alert"`
		Expr        string            `yaml:"expr"`
		For         string            `yaml:"for,omitempty"`
		Labels      map[string]string `yaml:"labels,omitempty"`
		Annotations map[string]string `yaml:"annotations,omitempty"`
	}
	type nativeGroup struct {
		Name  string       `yaml:"name"`
		Rules []nativeRule `yaml:"rules"`
	}
	native := struct {
		Groups []nativeGroup `yaml:"groups"`
	}{}
	for _, group := range file.Groups {
		ng := nativeGroup{Name: group.Name, Rules: make([]nativeRule, 0, len(group.Rules))}
		for _, rule := range group.Rules {
			ng.Rules = append(ng.Rules, nativeRule{
				Alert: rule.Alert, Expr: normalizedAlertExpression(rule.Expr), For: rule.For,
				Labels: rule.Labels, Annotations: rule.Annotations,
			})
		}
		native.Groups = append(native.Groups, ng)
	}
	b, err := yaml.Marshal(native)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "rules.yml")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(promtool, "check", "rules", path)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("promtool rejected alert rules: %v\n%s", err, output)
	}
}

func TestEveryGrafanaPromQLExpressionWithPromtool(t *testing.T) {
	promtool := os.Getenv("PROMTOOL")
	if promtool == "" {
		var err error
		promtool, err = exec.LookPath("promtool")
		if err != nil {
			t.Skip("promtool is not installed")
		}
	}

	replacer := strings.NewReplacer(
		"$__rate_interval", "5m",
		"$gvar_oie_hypervisor", ".*",
		"$gvar_oie_instance_uuid", ".*",
		"$gvar_oie_project_name", ".*",
		"$gvar_oie_project_uuid", ".*",
		"${__range_s}", "3600",
		"${gvar_oie_rank_by:raw}", "max_over_time",
		"${gvar_oie_rank_instances_by:raw}", "max_over_time",
		"${gvar_oie_rank_projects_by:raw}", "max_over_time",
		"${gvar_oie_top_instances}", "10",
		"${gvar_oie_top_n}", "10",
		"${gvar_oie_top_projects}", "10",
	)
	type recordingRule struct {
		Record string `yaml:"record"`
		Expr   string `yaml:"expr"`
	}
	type recordingGroup struct {
		Name  string          `yaml:"name"`
		Rules []recordingRule `yaml:"rules"`
	}
	ruleFile := struct {
		Groups []recordingGroup `yaml:"groups"`
	}{Groups: []recordingGroup{{Name: "openstack_instance_exporter_dashboards"}}}

	dashboards, err := filepath.Glob("examples/grafana_dashboard_example/*.json")
	if err != nil || len(dashboards) == 0 {
		t.Fatalf("dashboard glob: %v, files=%d", err, len(dashboards))
	}
	sort.Strings(dashboards)
	for _, dashboardPath := range dashboards {
		data, err := os.ReadFile(dashboardPath)
		if err != nil {
			t.Fatal(err)
		}
		var dashboard any
		if err := json.Unmarshal(data, &dashboard); err != nil {
			t.Fatalf("%s is invalid JSON: %v", dashboardPath, err)
		}
		var inspect func(any)
		inspect = func(value any) {
			switch typed := value.(type) {
			case map[string]any:
				if expression, ok := typed["expr"].(string); ok && strings.TrimSpace(expression) != "" {
					index := len(ruleFile.Groups[0].Rules)
					ruleFile.Groups[0].Rules = append(ruleFile.Groups[0].Rules, recordingRule{
						Record: fmt.Sprintf("oie_dashboard_expression_%03d", index),
						Expr:   replacer.Replace(expression),
					})
				}
				for _, child := range typed {
					inspect(child)
				}
			case []any:
				for _, child := range typed {
					inspect(child)
				}
			}
		}
		inspect(dashboard)
	}
	if len(ruleFile.Groups[0].Rules) == 0 {
		t.Fatal("Grafana dashboards contain no PromQL expressions")
	}

	rulesYAML, err := yaml.Marshal(ruleFile)
	if err != nil {
		t.Fatal(err)
	}
	rulesPath := filepath.Join(t.TempDir(), "dashboard-rules.yml")
	if err := os.WriteFile(rulesPath, rulesYAML, 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(promtool, "check", "rules", rulesPath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("promtool rejected a Grafana PromQL expression: %v\n%s", err, output)
	}
}

func TestGrafanaMiningVisibilityUsesExporterEvidenceAndAlertSemantics(t *testing.T) {
	type expectedPanel struct {
		id        int
		panelType string
	}
	tests := []struct {
		path          string
		rowID         int
		rowTitle      string
		panels        []expectedPanel
		warningPanel  int
		evidencePanel int
	}{
		{
			path:     "examples/grafana_dashboard_example/openstack_instance_exporter_cluster.json",
			rowID:    22000,
			rowTitle: "Mining Detection",
			panels: []expectedPanel{
				{id: 22001, panelType: "table"},
				{id: 22002, panelType: "stat"},
			},
			warningPanel:  22002,
			evidencePanel: 22001,
		},
		{
			path:     "examples/grafana_dashboard_example/openstack_instance_exporter_instance.json",
			rowID:    2090,
			rowTitle: "Instance Mining Detection",
			panels: []expectedPanel{
				{id: 2091, panelType: "stat"},
				{id: 2092, panelType: "stat"},
				{id: 2093, panelType: "timeseries"},
				{id: 2094, panelType: "timeseries"},
			},
			warningPanel:  2092,
			evidencePanel: 2093,
		},
	}

	for _, test := range tests {
		t.Run(filepath.Base(test.path), func(t *testing.T) {
			data, err := os.ReadFile(test.path)
			if err != nil {
				t.Fatal(err)
			}
			var dashboard map[string]any
			if err := json.Unmarshal(data, &dashboard); err != nil {
				t.Fatalf("invalid dashboard JSON: %v", err)
			}
			panelsByID := make(map[int]map[string]any)
			var collect func(any)
			collect = func(value any) {
				switch typed := value.(type) {
				case map[string]any:
					if rawID, exists := typed["id"].(float64); exists {
						panelsByID[int(rawID)] = typed
					}
					if children, exists := typed["panels"]; exists {
						collect(children)
					}
				case []any:
					for _, child := range typed {
						collect(child)
					}
				}
			}
			collect(dashboard["panels"])

			row := panelsByID[test.rowID]
			if row == nil || row["type"] != "row" || row["title"] != test.rowTitle {
				t.Fatalf("mining row %d missing or changed: %#v", test.rowID, row)
			}
			for _, expected := range test.panels {
				panel := panelsByID[expected.id]
				if panel == nil || panel["type"] != expected.panelType {
					t.Fatalf("mining panel %d missing or type=%v, want %s", expected.id, panel["type"], expected.panelType)
				}
				targets, ok := panel["targets"].([]any)
				if !ok || len(targets) == 0 {
					t.Fatalf("mining panel %d has no targets", expected.id)
				}
				usesMiningEvidence := false
				for _, target := range targets {
					targetMap, _ := target.(map[string]any)
					expression, _ := targetMap["expr"].(string)
					if strings.Contains(expression, "oie_instance_mining_suspected") {
						usesMiningEvidence = true
					}
				}
				if !usesMiningEvidence {
					t.Fatalf("mining panel %d does not use oie_instance_mining_suspected", expected.id)
				}
			}

			evidence := panelsByID[test.evidencePanel]
			evidenceTarget := evidence["targets"].([]any)[0].(map[string]any)
			for _, label := range []string{"server_name", "instance_uuid", "project_name", "ip", "port", "port_name", "confidence", "priority"} {
				if !strings.Contains(evidenceTarget["expr"].(string), label) {
					t.Errorf("evidence panel %d omits identifying label %q", test.evidencePanel, label)
				}
			}

			warning := panelsByID[test.warningPanel]
			warningExpression := warning["targets"].([]any)[0].(map[string]any)["expr"].(string)
			for _, required := range []string{
				`confidence="high"`,
				`confidence="high_persistent"`,
				`confidence="shared"`,
				`confidence="shared_persistent"`,
				"avg_over_time(oie_instance_cpu_vcpu_percent",
				"count_over_time(oie_instance_cpu_vcpu_percent",
				">= 35",
				">= 40",
				">= 60",
				">= 3",
			} {
				if !strings.Contains(warningExpression, required) {
					t.Errorf("warning panel %d is missing alert-semantic fragment %q", test.warningPanel, required)
				}
			}
		})
	}
}

func TestAlertInventoryMatchesV120Golden(t *testing.T) {
	file := loadAlertRules(t)
	got := make([]string, 0, 80)
	seen := make(map[string]struct{})
	for _, group := range file.Groups {
		for _, rule := range group.Rules {
			if rule.Alert == "" || rule.Expr == "" {
				t.Fatalf("alert has missing name or expression: %#v", rule)
			}
			if _, duplicate := seen[rule.Alert]; duplicate {
				t.Fatalf("duplicate alert %q", rule.Alert)
			}
			seen[rule.Alert] = struct{}{}
			got = append(got, rule.Alert)
		}
	}
	want := append(goldenLines(t, "testdata/alerts-v1.2.0.golden"), goldenLines(t, "testdata/alerts-v1.3.0-additions.golden")...)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("alert inventory changed outside approved v1.3.0 additions\nwant:\n%s\n\ngot:\n%s", strings.Join(want, "\n"), strings.Join(got, "\n"))
	}
}

func TestMiningAlertCorroboratesAmbiguousPortCandidates(t *testing.T) {
	file := loadAlertRules(t)
	for _, group := range file.Groups {
		for _, rule := range group.Rules {
			if rule.Alert != "OpenStackInstanceMiningSuspected" {
				continue
			}
			expression := renderTemplatedAlertExpression(t, rule.Expr)
			for _, required := range []string{
				`oie_instance_mining_suspected{confidence="high"} == 1`,
				`oie_instance_mining_suspected{confidence="high_persistent"} == 1`,
				`oie_instance_mining_suspected{confidence="shared"} == 1`,
				`oie_instance_mining_suspected{confidence="shared_persistent"} == 1`,
				`avg_over_time(oie_instance_cpu_vcpu_percent[5m])`,
				`count_over_time(oie_instance_cpu_vcpu_percent[5m])`,
			} {
				if !strings.Contains(expression, required) {
					t.Fatalf("mining alert expression is missing %q: %s", required, expression)
				}
			}
			if rule.For != "" {
				t.Fatalf("mining alert adds a second blanket persistence delay: for=%q", rule.For)
			}
			if rule.Labels["severity"] != "warning" {
				t.Fatalf("mining alert severity=%q", rule.Labels["severity"])
			}
			return
		}
	}
	t.Fatal("OpenStackInstanceMiningSuspected alert is missing")
}

func TestPersistentDedicatedMiningCandidateAlertIsInformational(t *testing.T) {
	file := loadAlertRules(t)
	for _, group := range file.Groups {
		for _, rule := range group.Rules {
			if rule.Alert != "OpenStackInstanceMiningCandidatePersistent" {
				continue
			}
			expression := renderTemplatedAlertExpression(t, rule.Expr)
			for _, required := range []string{
				`oie_instance_mining_suspected{confidence="high_persistent"} == 1`,
				`unless on (domain, instance_uuid, project_uuid, user_uuid)`,
				`avg_over_time(oie_instance_cpu_vcpu_percent[5m])`,
			} {
				if !strings.Contains(expression, required) {
					t.Fatalf("persistent mining candidate expression is missing %q: %s", required, expression)
				}
			}
			if rule.For != "15m" || rule.Labels["severity"] != "info" {
				t.Fatalf("persistent mining candidate for=%q severity=%q", rule.For, rule.Labels["severity"])
			}
			return
		}
	}
	t.Fatal("OpenStackInstanceMiningCandidatePersistent alert is missing")
}

func TestAlertsAndDashboardsOnlyReferenceExportedOIEMetrics(t *testing.T) {
	_, exported := descriptorContract(t)
	check := func(source, text string) {
		t.Helper()
		for _, metric := range oieMetricRE.FindAllString(text, -1) {
			if strings.HasSuffix(metric, "_") {
				continue
			}
			if _, ok := exported[metric]; !ok {
				t.Errorf("%s references unexported metric %q", source, metric)
			}
		}
	}

	alertBytes, err := os.ReadFile("examples/prometheus_alerts_example/openstack_instance_exporter_alerts.yml")
	if err != nil {
		t.Fatal(err)
	}
	check("alerts", string(alertBytes))

	dashboards, err := filepath.Glob("examples/grafana_dashboard_example/*.json")
	if err != nil || len(dashboards) == 0 {
		t.Fatalf("dashboard glob: %v, files=%d", err, len(dashboards))
	}
	for _, path := range dashboards {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var parsed interface{}
		if err := json.Unmarshal(b, &parsed); err != nil {
			t.Fatalf("%s is invalid JSON: %v", path, err)
		}
		check(path, string(b))
	}
}

func TestGrafanaDiskReferencesUseExportedVolumeUUIDLabel(t *testing.T) {
	descriptors, _ := descriptorContract(t)
	volumeUUIDExported := false
	for _, descriptor := range descriptors {
		if strings.HasPrefix(descriptor, "oie_instance_disk_info|") && strings.Contains(descriptor, "volume_uuid") {
			volumeUUIDExported = true
			break
		}
	}
	if !volumeUUIDExported {
		t.Fatal("oie_instance_disk_info does not export the volume_uuid label")
	}

	dashboards, err := filepath.Glob("examples/grafana_dashboard_example/*.json")
	if err != nil || len(dashboards) == 0 {
		t.Fatalf("dashboard glob: %v, files=%d", err, len(dashboards))
	}
	volumeUUIDReferences := 0
	for _, path := range dashboards {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var dashboard any
		if err := json.Unmarshal(b, &dashboard); err != nil {
			t.Fatalf("%s is invalid JSON: %v", path, err)
		}
		var inspect func(any)
		inspect = func(value any) {
			switch typed := value.(type) {
			case map[string]any:
				for _, child := range typed {
					inspect(child)
				}
			case []any:
				for _, child := range typed {
					inspect(child)
				}
			case string:
				if !strings.Contains(typed, "oie_instance_disk_") {
					return
				}
				if strings.Contains(typed, "disk_uuid") {
					t.Errorf("%s references nonexistent disk label disk_uuid in %q", path, typed)
				}
				if strings.Contains(typed, "volume_uuid") {
					volumeUUIDReferences++
				}
			}
		}
		inspect(dashboard)
	}
	if volumeUUIDReferences == 0 {
		t.Fatal("Grafana disk queries do not use the exported volume_uuid label")
	}
}

func TestGrafanaByDiskPanelsPreserveExportedDiskIdentity(t *testing.T) {
	b, err := os.ReadFile("examples/grafana_dashboard_example/openstack_instance_exporter_instance.json")
	if err != nil {
		t.Fatal(err)
	}
	var dashboard any
	if err := json.Unmarshal(b, &dashboard); err != nil {
		t.Fatalf("instance dashboard is invalid JSON: %v", err)
	}

	panelsChecked := 0
	var inspect func(any)
	inspect = func(value any) {
		switch typed := value.(type) {
		case map[string]any:
			title, _ := typed["title"].(string)
			if strings.Contains(title, "by Disk") {
				panelsChecked++
				targets, ok := typed["targets"].([]any)
				if !ok || len(targets) == 0 {
					t.Errorf("panel %q has no query targets", title)
				} else {
					for _, targetValue := range targets {
						target, ok := targetValue.(map[string]any)
						if !ok {
							t.Errorf("panel %q has a malformed query target", title)
							continue
						}
						expr, _ := target["expr"].(string)
						if strings.Count(expr, "volume_uuid, disk_type, disk_path") != 2 {
							t.Errorf("panel %q does not preserve the exported disk_path identity in both aggregations: %q", title, expr)
						}
						legend, _ := target["legendFormat"].(string)
						if !strings.Contains(legend, "{{ disk_path }}") {
							t.Errorf("panel %q legend does not identify distinct disk paths: %q", title, legend)
						}
					}
				}
			}
			for _, child := range typed {
				inspect(child)
			}
		case []any:
			for _, child := range typed {
				inspect(child)
			}
		}
	}
	inspect(dashboard)
	if panelsChecked != 4 {
		t.Fatalf("checked %d by-Disk panels, want 4", panelsChecked)
	}
}

func TestCorrectedAlertMathContracts(t *testing.T) {
	file := loadAlertRules(t)
	expressions := make(map[string]string)
	for _, group := range file.Groups {
		for _, rule := range group.Rules {
			expressions[rule.Alert] = rule.Expr
		}
	}
	for alert, metric := range map[string]string{
		"OpenStackInstanceDiskReadLatencyHigh":  "oie_instance_disk_read_latency_seconds",
		"OpenStackInstanceDiskWriteLatencyHigh": "oie_instance_disk_write_latency_seconds",
		"OpenStackInstanceDiskFlushLatencyHigh": "oie_instance_disk_flush_latency_seconds",
	} {
		expr := expressions[alert]
		if !strings.Contains(expr, metric) || strings.Contains(expr, "requests_total") {
			t.Fatalf("%s still has low-rate latency distortion: %s", alert, expr)
		}
	}
	for alert, dropped := range map[string]string{
		"OpenStackInstanceNetworkReceiveDropRatioHigh":  "oie_instance_net_rx_dropped_total",
		"OpenStackInstanceNetworkTransmitDropRatioHigh": "oie_instance_net_tx_dropped_total",
	} {
		expr := expressions[alert]
		if strings.Count(expr, dropped) < 2 || !strings.Contains(expr, "+ rate(") {
			t.Fatalf("%s does not divide drops by delivered+dropped packets: %s", alert, expr)
		}
	}
}
