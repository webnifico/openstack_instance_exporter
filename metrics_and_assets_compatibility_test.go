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
	baselineAdditions := goldenLines(t, "testdata/metrics-baseline-additions.golden")
	v200DataIntegrityAdditions := goldenLines(t, "testdata/metrics-v2.0.0-data-integrity-additions.golden")
	v200ResourceTelemetryAdditions := goldenLines(t, "testdata/metrics-v2.0.0-resource-telemetry-additions.golden")
	v200AlertValidationAdditions := goldenLines(t, alertValidationMetricAdditionsPath)
	want := append(append([]string{}, v120...), baselineAdditions...)
	want = append(want, v200DataIntegrityAdditions...)
	want = append(want, v200ResourceTelemetryAdditions...)
	want = append(want, v200AlertValidationAdditions...)
	want = append(want, volumeRetypeMetricDescriptors...)
	want = append(want, inventoryMetricDescriptors...)
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("metric contract changed outside the approved v2.0.0 additions\nwant:\n%s\n\ngot:\n%s", strings.Join(want, "\n"), strings.Join(got, "\n"))
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
		Name           string `yaml:"group_name" json:"name"`
		Job            string `yaml:"group_exporter_job" json:"exporter_job"`
		RecordingRules []struct {
			Record string `yaml:"record"`
			Expr   string `yaml:"expr"`
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

func loadAlertRules(t *testing.T) alertRulesFile {
	t.Helper()
	// Tests for the historical Data integrity through Prometheus alert validation alert transformations use
	// the frozen Prometheus alert validation fixture. Operational configuration tests and the general syntax test load
	// the current operational example through loadCurrentAlertRules.
	b, err := os.ReadFile(alertValidationAlertContractGoldenPath)
	if err != nil {
		t.Fatal(err)
	}
	var file alertRulesFile
	if err := dataIntegrityDecodeSingleJSON(b, &file); err != nil {
		t.Fatalf("historical alert JSON: %v", err)
	}
	for groupIndex := range file.Groups {
		for ruleIndex := range file.Groups[groupIndex].Rules {
			file.Groups[groupIndex].Rules[ruleIndex].Expr = strings.ReplaceAll(
				file.Groups[groupIndex].Rules[ruleIndex].Expr,
				`"`,
				`\"`,
			)
		}
	}
	return file
}

func loadCurrentAlertRules(t *testing.T) alertRulesFile {
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
	file := loadCurrentAlertRules(t)
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
		"$__rate_interval", "5m", "${gvar_oie_volume_uuid}", ".*", "${__from}", "0", "${__to}", "3600000", "$__interval", "1m",
		"${gvar_oie_hypervisor}", ".*",
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
	dashboards := dashboardDocumentationLoadDashboards(t)
	for _, name := range []string{"cluster", "instance"} {
		d := dashboards["openstack_instance_exporter_"+name+".json"]
		table := dashboardDocumentationPanelByID(t, d, 22001)
		if table.Type != "table" {
			t.Fatal("mining evidence must have a readable table")
		}
		expr := dashboardDocumentationPanelExpressions(table)
		for _, required := range []string{"oie_instance_mining_suspected", "ip", "port", "port_name", "confidence", "priority", "avg_over_time(", "count_over_time(", "oie_host_conntrack_raw_ok"} {
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
		if !strings.Contains(strings.ToLower(table.Description), "not proof") {
			t.Fatal("mining evidence cannot claim proof")
		}
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
	want := append(goldenLines(t, "testdata/alerts-v1.2.0.golden"), goldenLines(t, "testdata/alerts-baseline-additions.golden")...)
	want = append(want,
		"OpenStackInstanceExporterUnavailable",
		"OpenStackInstanceExporterLibvirtCollectionUnhealthy",
		"OpenStackInstanceExporterLibvirtDataStale",
		"OpenStackInstanceExporterTorRelayListRefreshStale",
		"OpenStackInstanceExporterCollectionCycleNearInterval",
		"OpenStackInstanceExporterHostCPUPressureSustained",
		"OpenStackInstanceExporterHostMemoryPressureSustained",
	)
	// Prometheus alert validation intentionally reorganizes the existing inventory into four policy
	// groups. Preserve the legacy membership contract while allowing that
	// reviewed ordering change and exactly the seven new coverage alerts above.
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("alert inventory changed outside approved v2.0.0 Prometheus alert validation additions\nwant:\n%s\n\ngot:\n%s", strings.Join(want, "\n"), strings.Join(got, "\n"))
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
			for _, confidence := range []string{"high", "high_persistent", "shared", "shared_persistent"} {
				selector := `oie_instance_mining_suspected{confidence="` + confidence + `"}`
				start := strings.Index(expression, selector)
				if start < 0 {
					t.Fatalf("mining alert expression is missing %q: %s", selector, expression)
				}
				end := start + 600
				if end > len(expression) {
					end = len(expression)
				}
				if !strings.Contains(expression[start:end], "== 1") {
					t.Fatalf("mining alert tier %q is not tested for positive evidence: %s", confidence, expression)
				}
			}
			for _, required := range []string{
				`avg_over_time(oie_instance_cpu_vcpu_percent[5m])`,
				`count_over_time(oie_instance_cpu_vcpu_percent[5m])`,
			} {
				if !strings.Contains(expression, required) {
					t.Fatalf("mining alert expression is missing %q: %s", required, expression)
				}
			}
			if rule.For != "1m" {
				t.Fatalf("mining alert pending interval=%q, want reviewed Prometheus alert validation interval 1m", rule.For)
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
				`oie_instance_mining_suspected{confidence="high_persistent"}`,
				`unless on (domain, instance_uuid, project_uuid, user_uuid, instance, job)`,
				`avg_over_time(oie_instance_cpu_vcpu_percent[5m])`,
			} {
				if !strings.Contains(expression, required) {
					t.Fatalf("persistent mining candidate expression is missing %q: %s", required, expression)
				}
			}
			if rule.For != "15m" || rule.Labels["severity"] != "info" || rule.Labels["policy"] != "environment-tuned" {
				t.Fatalf("persistent mining candidate for=%q severity=%q policy=%q", rule.For, rule.Labels["severity"], rule.Labels["policy"])
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
		if strings.Count(expr, "rate("+dropped+"[5m])") < 2 ||
			!strings.Contains(expr, "+ (rate("+dropped+"[5m])") ||
			!strings.Contains(expr, "/ clamp_min(") {
			t.Fatalf("%s does not divide drops by delivered+dropped packets: %s", alert, expr)
		}
	}
}

func dashboardDerivedLabel(name string) bool {
	switch name {
	case "oie_event", "oie_source", "oie_column", "oie_hypervisor", "oie_volume_uuid", "retype_field", "instance_choice":
		return true
	}
	return false
}
