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

func TestMetricNamesAndLabelsMatchRelease(t *testing.T) {
	got, _ := descriptorContract(t)
	want := compatibilityReadNonEmptyLines(t, "testdata/contracts/metric-descriptors.txt")
	compatibilityAssertStringsEqual(t, "release metric names and labels", got, want)
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
		PlainExpressions bool   `yaml:"group_plain_expressions,omitempty" json:"plain_expressions,omitempty"`
		Name             string `yaml:"group_name" json:"name"`
		Job              string `yaml:"group_exporter_job" json:"exporter_job"`
		Interval         string `yaml:"group_interval,omitempty" json:"interval,omitempty"`
		RecordingRules   []struct {
			Record string            `yaml:"record"`
			Expr   string            `yaml:"expr"`
			Labels map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`
		} `yaml:"group_recording_rules,omitempty"`
		Rules []struct {
			Enabled     *bool             `yaml:"enabled,omitempty"`
			Alert       string            `yaml:"alert" json:"alert"`
			Expr        string            `yaml:"expr" json:"expr"`
			For         string            `yaml:"for" json:"for"`
			Labels      map[string]string `yaml:"labels" json:"labels"`
			Annotations map[string]string `yaml:"annotations" json:"annotations"`
		} `yaml:"group_rules" json:"rules"`
	} `yaml:"prometheus_alert_rules" json:"Groups"`
}

func loadCurrentAlertRules(t *testing.T) alertRulesFile {
	t.Helper()
	cmd := exec.Command(dataIntegrityFindAnsiblePython(t), "-c", "import sys,yaml; sys.path.insert(0, 'integration_tests'); from oie_alerts_test import load_policy; print(yaml.safe_dump(load_policy(('metrics','alerts'))))")
	b, err := cmd.Output()
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

func renderCurrentAlertRulesNative(t *testing.T) []byte {
	t.Helper()
	// Exercise the actual deployment renderer, including shared measurements.
	cmd := exec.Command(dataIntegrityFindAnsiblePython(t), "-c", "import sys; sys.path.insert(0, 'integration_tests'); from oie_alerts_test import render; print(render())")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("current deployment renderer: %v\n%s", err, output)
	}
	return output
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
	path := filepath.Join(t.TempDir(), "rules.yml")
	if err := os.WriteFile(path, renderCurrentAlertRulesNative(t), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(promtool, "check", "rules", path)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("promtool rejected native alerts, recordings or annotations: %v\n%s", err, output)
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
		"$__rate_interval", "5m", "${gvar_oie_volume_uuid}", ".*", "${__from}", "0", "${__to}", "3600000", "$__interval", "1m",
		"${gvar_oie_hypervisor}", ".*",
		"$gvar_oie_hypervisor", ".*",
		"$gvar_oie_instance_uuid", ".*",
		"$gvar_oie_project_name", ".*",
		"$gvar_oie_project_uuid", ".*",
		"${__range_s}", "3600", "$__range", "1h",
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
	dashboards := dashboardDocumentationLoadDashboards(t)
	for _, name := range []string{"cluster", "instance"} {
		d := dashboards["openstack_instance_exporter_"+name+".json"]
		table := dashboardDocumentationPanelByID(t, d, 22001)
		if table.Type != "table" {
			t.Fatal("mining evidence must have a readable table")
		}
		expr := dashboardDocumentationPanelExpressions(table)
		for _, required := range []string{"oie_instance_mining_suspected", "ip", "port", "port_name", "confidence", "avg_over_time(", "count_over_time(", "oie_host_conntrack_raw_ok"} {
			if !strings.Contains(expr, required) {
				t.Errorf("%s missing %s", name, required)
			}
		}
		for _, id := range []int{22002, 22003, 22004} {
			p := dashboardDocumentationPanelByID(t, d, id)
			if p.Type != "stat" {
				t.Fatal("compact coverage stats required")
			}
		}
		// The qualification can be stated in the evidence table or its summary.
		summary := dashboardDocumentationPanelByID(t, d, 22002)
		if !strings.Contains(strings.ToLower(table.Description+" "+summary.Description), "not proof") {
			t.Fatal("mining evidence cannot claim proof")
		}
	}
}

func TestAlertInventoryMatchesRelease(t *testing.T) {
	got := []string{}
	seen := map[string]bool{}
	for _, group := range loadCurrentAlertRules(t).Groups {
		for _, rule := range group.Rules {
			if rule.Alert == "" || rule.Expr == "" || seen[rule.Alert] {
				t.Fatalf("invalid or duplicate alert: %s", rule.Alert)
			}
			seen[rule.Alert] = true
			got = append(got, rule.Alert)
		}
	}
	sort.Strings(got)
	compatibilityAssertStringsEqual(t, "release alert inventory", got, compatibilityReadNonEmptyLines(t, "testdata/contracts/alerts.txt"))
}

func TestMiningAlertCorroboratesAmbiguousPortCandidates(t *testing.T) {
	helpers := map[string]string{}
	for _, group := range loadCurrentAlertRules(t).Groups {
		for _, r := range group.RecordingRules {
			helpers[r.Record] = r.Expr
		}
	}
	expr := helpers["oie:mining_warning"]
	for _, required := range []string{`confidence="high"`, `confidence="shared"`, `confidence="shared_persistent"`, "oie:cpu_percent_5m >= 35", "oie:cpu_percent_5m >= 60", "oie:network_current"} {
		if !strings.Contains(expr, required) {
			t.Errorf("mining evidence helper missing %q", required)
		}
	}
	rules := operationalConfigurationAlertInventory(t, loadCurrentAlertRules(t))
	if rules["OpenStackInstanceMiningSuspected"].Expr != "oie:mining_warning == 1" {
		t.Fatal("mining notification is detached from its evidence helper")
	}
}

func TestPersistentDedicatedMiningCandidateAlertIsInformational(t *testing.T) {
	rules := operationalConfigurationAlertInventory(t, loadCurrentAlertRules(t))
	rule, ok := rules["OpenStackInstanceMiningCandidatePersistent"]
	if !ok || rule.Labels["severity"] != "info" {
		t.Fatal("persistent mining candidate must remain informational")
	}
	for _, required := range []string{`confidence="high_persistent"`, "oie:cpu_percent_5m >= 40", "oie:network_current", "unless on (job, instance, instance_uuid) oie:mining_warning"} {
		if !strings.Contains(rule.Expr, required) {
			t.Errorf("candidate rule missing %q", required)
		}
	}
}

func TestAlertsAndDashboardsOnlyReferenceExportedOIEMetrics(t *testing.T) {
	_, exported := descriptorContract(t)
	check := func(source, text string) {
		t.Helper()
		for _, metric := range oieMetricRE.FindAllString(text, -1) {
			if dashboardDerivedLabel(metric) {
				continue
			}
			if strings.HasSuffix(metric, "_") {
				continue
			}
			if _, ok := exported[metric]; !ok {
				t.Errorf("%s references unexported metric %q", source, metric)
			}
		}
	}

	for _, group := range loadCurrentAlertRules(t).Groups {
		for _, rule := range group.Rules {
			check(rule.Alert, rule.Expr)
		}
		for _, rule := range group.RecordingRules {
			check(rule.Record, rule.Expr)
		}
	}

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
			if strings.Contains(title, "by disk (Top N)") {
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
	helpers := map[string]string{}
	for _, group := range loadCurrentAlertRules(t).Groups {
		for _, rule := range group.RecordingRules {
			helpers[rule.Record] = rule.Expr
		}
	}
	for _, direction := range []string{"read", "write", "flush"} {
		expr := helpers["oie:disk:"+direction+"_latency_seconds"]
		seconds := `oie_instance_disk_` + direction + `_seconds_total{job="openstack-instance-exporter"}`
		requests := `oie_instance_disk_` + direction + `_requests_total{job="openstack-instance-exporter"}`
		for _, required := range []string{"rate(" + seconds + "[5m]) / rate(" + requests + "[5m])", "count_over_time(", "oie:resource_axis_current"} {
			if !strings.Contains(expr, required) {
				t.Errorf("%s latency is missing %q: %s", direction, required, expr)
			}
		}
		if strings.Contains(expr, "clamp_min") {
			t.Errorf("%s latency must not clamp low request rates", direction)
		}
	}
	for _, direction := range []string{"rx", "tx"} {
		expr := helpers["oie:network:"+direction+"_drop_ratio"]
		packets := `increase(oie_instance_net_` + direction + `_packets_total{job="openstack-instance-exporter"}[5m])`
		drops := `increase(oie_instance_net_` + direction + `_dropped_total{job="openstack-instance-exporter"}[5m])`
		if !strings.Contains(expr, drops+" / ("+packets+" + "+drops+")") {
			t.Errorf("%s drops must divide by delivered+dropped packets: %s", direction, expr)
		}
	}
}

func dashboardDerivedLabel(name string) bool {
	switch name {
	case "oie_event", "oie_source", "oie_rank_source", "oie_column", "oie_hypervisor", "oie_volume_uuid", "retype_field", "instance_choice",
		"oie_instance", "oie_project", "oie_resource", "oie_family", "oie_scope", "oie_status", "oie_unit", "oie_additive", "oie_collector", "oie_direction", "oie_disk_origin", "oie_offender",
		"oie_entity_dashboard", "oie_entity_variable", "oie_entity_value", "oie_condition":
		return true
	}
	return false
}
