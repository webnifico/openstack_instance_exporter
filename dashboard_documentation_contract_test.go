package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	dashboardDocumentationPriorContractSHA256Path = "testdata/dashboard-documentation-prior-contract-sha256.txt"
	dashboardDocumentationContractPath            = "DASHBOARDS_AND_DOCUMENTATION.md"
	dashboardDocumentationGrafanaREADMEPath       = "examples/grafana_dashboard_example/README.md"
	dashboardDocumentationHypervisorMatcher       = `instance=~"^${gvar_oie_hypervisor}(:[0-9]+)?$"`
)

var (
	dashboardDocumentationOIESelectorRE = regexp.MustCompile(`\b(oie_[A-Za-z0-9_]+)(?:\s*\{((?:[^{}]|\$\{[^{}]*\})*)\})?`)
	dashboardDocumentationMatcherRE     = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)\s*(?:=~|!~|!=|=)`)
	dashboardDocumentationLabelValuesRE = regexp.MustCompile(`label_values\(\s*(oie_[A-Za-z0-9_]+)(?:\s*\{((?:[^{}]|\$\{[^{}]*\})*)\})?\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)`)
	dashboardDocumentationGroupingRE    = regexp.MustCompile(`(?:by|without|on|ignoring|group_left|group_right)\s*\(([^)]*)\)`)
	dashboardDocumentationAlertLabelRE  = regexp.MustCompile(`\$labels\.([A-Za-z_][A-Za-z0-9_]*)`)
	dashboardDocumentationDocFlagRE     = regexp.MustCompile("^\\| `([^`]+)` \\| `([^`]*)` \\|")
	dashboardDocumentationOIEJobRE      = regexp.MustCompile(`\bjob\s*=\s*"openstack-instance-exporter"`)
)

type dashboardDocumentationDashboard struct {
	Title   string                        `json:"title"`
	UID     string                        `json:"uid"`
	Version int                           `json:"version"`
	Panels  []dashboardDocumentationPanel `json:"panels"`
}

type dashboardDocumentationPanel struct {
	ID          int                           `json:"id"`
	Title       string                        `json:"title"`
	Type        string                        `json:"type"`
	Description string                        `json:"description"`
	Panels      []dashboardDocumentationPanel `json:"panels"`
	Targets     []struct {
		Expr         string `json:"expr"`
		LegendFormat string `json:"legendFormat"`
	} `json:"targets"`
	FieldConfig struct {
		Defaults struct {
			Unit   string `json:"unit"`
			Custom struct {
				AxisLabel string `json:"axisLabel"`
				Stacking  struct {
					Mode string `json:"mode"`
				} `json:"stacking"`
			} `json:"custom"`
		} `json:"defaults"`
	} `json:"fieldConfig"`
}

type dashboardDocumentationMetricDoc struct {
	Type   string
	Labels string
	Unit   string
}

func dashboardDocumentationReadFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func dashboardDocumentationLoadDashboards(t *testing.T) map[string]dashboardDocumentationDashboard {
	t.Helper()
	paths, err := filepath.Glob("examples/grafana_dashboard_example/*.json")
	if err != nil || len(paths) != 5 {
		t.Fatalf("dashboard inventory: %v, files=%d", err, len(paths))
	}
	sort.Strings(paths)
	result := make(map[string]dashboardDocumentationDashboard, len(paths))
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var dashboard dashboardDocumentationDashboard
		decoder := json.NewDecoder(strings.NewReader(string(data)))
		if err := decoder.Decode(&dashboard); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
		if dashboard.Title == "" || dashboard.UID == "" || dashboard.Version <= 0 {
			t.Fatalf("%s has incomplete identity: %+v", path, dashboard)
		}
		result[filepath.Base(path)] = dashboard
	}
	return result
}

func dashboardDocumentationFlattenPanels(panels []dashboardDocumentationPanel) []dashboardDocumentationPanel {
	result := make([]dashboardDocumentationPanel, 0, len(panels))
	for _, panel := range panels {
		result = append(result, panel)
		result = append(result, dashboardDocumentationFlattenPanels(panel.Panels)...)
	}
	return result
}

func dashboardDocumentationPanelByID(t *testing.T, dashboard dashboardDocumentationDashboard, id int) dashboardDocumentationPanel {
	t.Helper()
	for _, panel := range dashboardDocumentationFlattenPanels(dashboard.Panels) {
		if panel.ID == id {
			return panel
		}
	}
	t.Fatalf("dashboard %s has no panel %d", dashboard.UID, id)
	return dashboardDocumentationPanel{}
}

func dashboardDocumentationPanelExpressions(panel dashboardDocumentationPanel) string {
	expressions := make([]string, 0, len(panel.Targets))
	for _, target := range panel.Targets {
		expressions = append(expressions, target.Expr)
	}
	return strings.Join(expressions, "\n")
}

func dashboardDocumentationMetricLabels(t *testing.T) (map[string]map[string]struct{}, map[string]struct{}) {
	t.Helper()
	labelsByMetric := make(map[string]map[string]struct{})
	allLabels := map[string]struct{}{
		"instance":        {},
		"job":             {},
		"threat_source":   {},
		"oie_event":       {},
		"oie_source":      {},
		"oie_column":      {},
		"oie_hypervisor":  {},
		"oie_volume_uuid": {},
		"retype_field":    {},
		"instance_choice": {},
	}
	for name, rawLabels := range compatibilityDescriptorLabelOrder(t) {
		labels := map[string]struct{}{
			"instance": {},
			"job":      {},
		}
		if rawLabels != "" {
			for _, label := range strings.Split(rawLabels, ",") {
				labels[label] = struct{}{}
				allLabels[label] = struct{}{}
			}
		}
		labelsByMetric[name] = labels
	}
	return labelsByMetric, allLabels
}

func dashboardDocumentationValidateOIEExpressionLabels(t *testing.T, source, expression string, labelsByMetric map[string]map[string]struct{}, allLabels map[string]struct{}) {
	t.Helper()
	selectors := dashboardDocumentationOIESelectorRE.FindAllStringSubmatch(expression, -1)
	for _, selector := range selectors {
		name := selector[1]
		if dashboardDerivedLabel(name) {
			continue
		}
		allowed, exists := labelsByMetric[name]
		if !exists {
			t.Errorf("%s references missing metric %q", source, name)
			continue
		}
		for _, matcher := range dashboardDocumentationMatcherRE.FindAllStringSubmatch(selector[2], -1) {
			if _, exists := allowed[matcher[1]]; !exists {
				t.Errorf("%s selector for %s references missing label %q", source, name, matcher[1])
			}
		}
	}
	if len(selectors) == 0 {
		return
	}
	for _, grouping := range dashboardDocumentationGroupingRE.FindAllStringSubmatch(expression, -1) {
		for _, label := range strings.Split(grouping[1], ",") {
			label = strings.TrimSpace(label)
			if label == "" {
				continue
			}
			if _, exists := allLabels[label]; !exists {
				t.Errorf("%s groups or matches OIE data on unknown label %q", source, label)
			}
		}
	}
}

func dashboardDocumentationValidateOIEJobSelectors(t *testing.T, source, expression string) {
	t.Helper()
	for _, selector := range dashboardDocumentationOIESelectorRE.FindAllStringSubmatch(expression, -1) {
		if dashboardDerivedLabel(selector[1]) {
			continue
		}
		if !dashboardDocumentationOIEJobRE.MatchString(selector[2]) {
			t.Errorf("%s selector for %s must include job=\"openstack-instance-exporter\": %q", source, selector[1], selector[0])
		}
		if strings.Contains(selector[2], "gvar_oie_hypervisor") &&
			!strings.Contains(selector[2], dashboardDocumentationHypervisorMatcher) {
			t.Errorf("%s selector for %s does not anchor the regex-safe hypervisor value and optional port: %q", source, selector[1], selector[0])
		}
	}
}

func dashboardDocumentationWalkJSON(value any, visit func(key, text string)) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if text, ok := child.(string); ok {
				visit(key, text)
			}
			dashboardDocumentationWalkJSON(child, visit)
		}
	case []any:
		for _, child := range typed {
			dashboardDocumentationWalkJSON(child, visit)
		}
	}
}

func TestDashboardDocumentationPriorContractsAreByteFrozen(t *testing.T) {
	manifest := dashboardDocumentationReadFile(t, dashboardDocumentationPriorContractSHA256Path)
	lines := strings.Split(strings.TrimSpace(manifest), "\n")
	if len(lines) != 46 {
		t.Fatalf("prior contract records=%d, want 46", len(lines))
	}
	seen := make(map[string]struct{}, len(lines))
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 2 || len(fields[0]) != 64 || !strings.HasPrefix(fields[1], "testdata/") {
			t.Fatalf("invalid prior contract hash record %q", line)
		}
		if _, duplicate := seen[fields[1]]; duplicate {
			t.Fatalf("duplicate prior contract path %s", fields[1])
		}
		seen[fields[1]] = struct{}{}
		data, err := os.ReadFile(fields[1])
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != fields[0] {
			t.Fatalf("frozen prior contract %s changed: sha256=%s want=%s", fields[1], got, fields[0])
		}
	}
}

func TestDashboardDocumentationDashboardAndAlertLabelsMatchFinalSchema(t *testing.T) {
	labelsByMetric, allLabels := dashboardDocumentationMetricLabels(t)

	paths, err := filepath.Glob("examples/grafana_dashboard_example/*.json")
	if err != nil || len(paths) != 5 {
		t.Fatalf("dashboard inventory: %v, files=%d", err, len(paths))
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var document any
		if err := json.Unmarshal(data, &document); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
		dashboardDocumentationWalkJSON(document, func(key, value string) {
			source := path + " " + key
			if key == "expr" {
				dashboardDocumentationValidateOIEExpressionLabels(t, source, value, labelsByMetric, allLabels)
				dashboardDocumentationValidateOIEJobSelectors(t, source, value)
			}
			for _, query := range dashboardDocumentationLabelValuesRE.FindAllStringSubmatch(value, -1) {
				metric, matchers, requested := query[1], query[2], query[3]
				selector := metric + "{" + matchers + "}"
				dashboardDocumentationValidateOIEExpressionLabels(t, source, selector, labelsByMetric, allLabels)
				dashboardDocumentationValidateOIEJobSelectors(t, source, selector)
				allowed, exists := labelsByMetric[metric]
				if !exists {
					t.Errorf("%s label_values references missing metric %q", source, metric)
				} else if _, exists := allowed[requested]; !exists {
					t.Errorf("%s label_values requests missing %s label %q", source, metric, requested)
				}
			}
		})
	}

	alerts := loadCurrentAlertRules(t)
	for _, group := range alerts.Groups {
		for _, rule := range group.Rules {
			expression := normalizedAlertExpression(rule.Expr)
			dashboardDocumentationValidateOIEExpressionLabels(t, "alert "+rule.Alert, expression, labelsByMetric, allLabels)
			for key, annotation := range rule.Annotations {
				for _, reference := range dashboardDocumentationAlertLabelRE.FindAllStringSubmatch(annotation, -1) {
					if _, exists := allLabels[reference[1]]; !exists {
						t.Errorf("alert %s annotation %s references unknown label %q", rule.Alert, key, reference[1])
					}
				}
			}
		}
	}
}

func TestDashboardDocumentationDashboardsUseValidatedSemantics(t *testing.T) {
	dashboards := dashboardDocumentationLoadDashboards(t)
	cluster := dashboards["openstack_instance_exporter_cluster.json"]
	hypervisor := dashboards["openstack_instance_exporter_hypervisor.json"]
	instance := dashboards["openstack_instance_exporter_instance.json"]
	project := dashboards["openstack_instance_exporter_project.json"]
	threats := dashboards["openstack_instance_exporter_threats.json"]
	clusterJSON := dashboardDocumentationReadFile(t, "examples/grafana_dashboard_example/openstack_instance_exporter_cluster.json")
	if strings.Contains(clusterJSON, `"name": "gvar_oie_disk_uuid"`) {
		t.Error("cluster dashboard retains the unused gvar_oie_disk_uuid variable")
	}

	sourceHealth := dashboardDocumentationPanelByID(t, cluster, 23001)
	if got := dashboardDocumentationPanelExpressions(sourceHealth); !strings.Contains(got, "oie_host_conntrack_raw_ok") || !strings.Contains(got, "oie_host_libvirt_ok") || sourceHealth.FieldConfig.Defaults.Unit != "bool" {
		t.Fatalf("source-health panel does not match the final schema: title=%q unit=%q expr=%q", sourceHealth.Title, sourceHealth.FieldConfig.Defaults.Unit, got)
	}
	sourceAge := dashboardDocumentationPanelByID(t, cluster, 23002)
	if got := dashboardDocumentationPanelExpressions(sourceAge); !strings.Contains(got, "oie_host_conntrack_stale_seconds") || !strings.Contains(got, "oie_host_libvirt_stale_seconds") || sourceAge.FieldConfig.Defaults.Unit != "s" || !strings.Contains(strings.ToLower(sourceAge.Description), "retained") {
		t.Fatalf("source-age panel does not explain retained data: title=%q unit=%q expr=%q description=%q", sourceAge.Title, sourceAge.FieldConfig.Defaults.Unit, got, sourceAge.Description)
	}
	feedState := dashboardDocumentationPanelByID(t, threats, 3065)
	feedStateText := strings.ToLower(feedState.Description)
	if got := dashboardDocumentationPanelExpressions(feedState); !strings.Contains(got, "oie_host_threat_feed_fresh") || feedState.FieldConfig.Defaults.Unit != "short" || !strings.Contains(feedStateText, "-1 means disabled") || !strings.Contains(feedStateText, "0 means enabled but unusable") || !strings.Contains(feedStateText, "1 means enabled with a usable snapshot") || !strings.Contains(feedStateText, "retained") {
		t.Fatalf("threat-feed state panel does not document all three states: title=%q unit=%q expr=%q description=%q", feedState.Title, feedState.FieldConfig.Defaults.Unit, got, feedState.Description)
	}
	feedAge := dashboardDocumentationPanelByID(t, threats, 3064)
	for _, target := range feedAge.Targets {
		if !strings.Contains(target.Expr, "_refresh_last_success_timestamp_seconds") || !strings.Contains(target.Expr, "> 0") {
			t.Errorf("feed-age query does not omit never-successful timestamps: %q", target.Expr)
		}
	}
	if lower := strings.ToLower(feedAge.Description); !strings.Contains(lower, "never-successful") || !strings.Contains(lower, "omitted") {
		t.Errorf("feed-age panel does not explain never-successful omission: %q", feedAge.Description)
	}
	axisState := dashboardDocumentationPanelByID(t, cluster, 23003)
	axisExpression := dashboardDocumentationPanelExpressions(axisState)
	for _, required := range []string{"oie_instance_resource_axis_fresh", "oie_instance_resource_axis_available", `axis`, `project_uuid`, `instance_uuid`} {
		if !strings.Contains(axisExpression, required) {
			t.Errorf("resource-axis state panel omits %q", required)
		}
	}
	for _, required := range []string{"fresh", "retained", "unavailable"} {
		if !strings.Contains(strings.ToLower(axisState.Description), required) {
			t.Errorf("resource-axis state description omits %q", required)
		}
	}
	processCPU := dashboardDocumentationPanelByID(t, cluster, 1225)
	if processCPU.FieldConfig.Defaults.Unit != "percent" || !strings.Contains(dashboardDocumentationPanelExpressions(processCPU), "100 * rate(process_cpu_seconds_total") {
		t.Fatalf("exporter CPU panel must convert CPU-seconds/second to percent: unit=%q expr=%q", processCPU.FieldConfig.Defaults.Unit, dashboardDocumentationPanelExpressions(processCPU))
	}
	for _, id := range []int{1248, 1249} {
		panel := dashboardDocumentationPanelByID(t, hypervisor, id)
		if panel.FieldConfig.Defaults.Unit != "Gibits" || !strings.Contains(panel.Title, "Throughput") {
			t.Errorf("hypervisor network panel %d has misleading unit/title: unit=%q title=%q", id, panel.FieldConfig.Defaults.Unit, panel.Title)
		}
	}
	for _, test := range []struct {
		dashboard dashboardDocumentationDashboard
		panelID   int
	}{
		{dashboard: hypervisor, panelID: 1305},
		{dashboard: project, panelID: 1304},
	} {
		panel := dashboardDocumentationPanelByID(t, test.dashboard, test.panelID)
		expression := dashboardDocumentationPanelExpressions(panel)
		if len(panel.Targets) != 1 ||
			panel.FieldConfig.Defaults.Unit != "suffix:vCPU-s/s" ||
			!strings.Contains(expression, "oie_instance_cpu_steal_seconds_total") ||
			!strings.Contains(expression, "oie_instance_cpu_wait_seconds_total") ||
			!strings.Contains(expression, "\n  or\n") {
			t.Errorf("scheduler-delay panel %d does not use one delay-preferred/wait-fallback series: unit=%q targets=%d expr=%q", test.panelID, panel.FieldConfig.Defaults.Unit, len(panel.Targets), expression)
		}
	}
	clusterComposition := dashboardDocumentationPanelByID(t, cluster, 1239)
	if len(clusterComposition.Targets) != 2 ||
		!strings.Contains(clusterComposition.Targets[1].Expr, "clamp_min(") ||
		!strings.Contains(clusterComposition.Targets[1].Expr, "oie_instance_cpu_vcpu_percent") ||
		!strings.Contains(clusterComposition.Targets[1].Expr, "\n  -\n") {
		t.Errorf("cluster CPU composition does not subtract instance workload from host total: %q", dashboardDocumentationPanelExpressions(clusterComposition))
	}
	hypervisorComposition := dashboardDocumentationPanelByID(t, hypervisor, 1245)
	if len(hypervisorComposition.Targets) != 2 ||
		!strings.Contains(hypervisorComposition.Targets[1].Expr, "clamp_min(") ||
		!strings.Contains(hypervisorComposition.Targets[1].Expr, "oie_host_cpu_usage_percent") ||
		!strings.Contains(hypervisorComposition.Targets[1].Expr, "oie_instance_cpu_vcpu_percent") {
		t.Errorf("hypervisor CPU composition does not clamp host-minus-instance overhead at zero: %q", dashboardDocumentationPanelExpressions(hypervisorComposition))
	}
	for filename, dashboard := range dashboards {
		for _, panel := range dashboardDocumentationFlattenPanels(dashboard.Panels) {
			if !strings.Contains(dashboardDocumentationPanelExpressions(panel), "oie_instance_mem_used_mb") {
				continue
			}
			lowerDescription := strings.ToLower(panel.Description)
			for _, required := range []string{
				"balloon current minus balloon usable",
				"not qemu rss",
			} {
				if !strings.Contains(lowerDescription, required) {
					t.Errorf("%s memory panel %d does not disclose guest-view memory semantics %q: %q", filename, panel.ID, required, panel.Description)
				}
			}
		}
	}
	clusterMemoryRatios := dashboardDocumentationPanelByID(t, cluster, 1263)
	if !strings.Contains(clusterMemoryRatios.Title, "Not Physical VM Occupancy") ||
		!strings.Contains(strings.ToLower(clusterMemoryRatios.Description), "may exceed 100%") {
		t.Errorf("cluster cross-view memory ratios overstate physical VM occupancy: title=%q description=%q", clusterMemoryRatios.Title, clusterMemoryRatios.Description)
	}
	rawMemoryDelta := dashboardDocumentationPanelByID(t, hypervisor, 1308)
	rawMemoryDeltaText := strings.ToLower(rawMemoryDelta.Title + "\n" + rawMemoryDelta.Description)
	if !strings.Contains(rawMemoryDeltaText, "raw commit delta") ||
		!strings.Contains(rawMemoryDeltaText, "not nova scheduler or placement capacity") ||
		!strings.Contains(rawMemoryDeltaText, "allocation ratios") {
		t.Errorf("hypervisor raw physical-minus-allocation panel claims scheduler capacity: title=%q description=%q", rawMemoryDelta.Title, rawMemoryDelta.Description)
	}
	for _, id := range []int{4001, 4010} {
		panel := dashboardDocumentationPanelByID(t, hypervisor, id)
		if panel.FieldConfig.Defaults.Unit != "ops" ||
			!strings.Contains(panel.Title, "Rate") ||
			!strings.Contains(strings.ToLower(panel.Description), "generic events-per-second unit") {
			t.Errorf("hypervisor drops/errors panel %d must use a generic event-rate presentation: title=%q unit=%q description=%q", id, panel.Title, panel.FieldConfig.Defaults.Unit, panel.Description)
		}
	}
	axisUnavailable := dashboardDocumentationPanelByID(t, cluster, 23003)
	if len(axisUnavailable.Targets) != 3 ||
		!strings.HasPrefix(strings.TrimSpace(axisUnavailable.Targets[2].Expr), "count by (axis)") ||
		!strings.Contains(axisUnavailable.Targets[2].Expr, "== 0") {
		t.Errorf("resource-axis unavailable series does not count zero-valued availability samples: %q", dashboardDocumentationPanelExpressions(axisUnavailable))
	}
	diskServiceRate := dashboardDocumentationPanelByID(t, instance, 2076)
	if diskServiceRate.FieldConfig.Defaults.Unit != "suffix:s/s" ||
		!strings.Contains(strings.ToLower(diskServiceRate.Title), "service-time rate") ||
		!strings.Contains(strings.ToLower(diskServiceRate.Description), "per wall-clock second") {
		t.Errorf("instance read/write service-time rate has misleading presentation: title=%q unit=%q description=%q", diskServiceRate.Title, diskServiceRate.FieldConfig.Defaults.Unit, diskServiceRate.Description)
	}
	projectAttention := dashboardDocumentationPanelByID(t, project, 1403)
	if expression := dashboardDocumentationPanelExpressions(projectAttention); strings.Contains(expression, "topk(20") || !strings.Contains(expression, "topk(${gvar_oie_top_instances}") {
		t.Errorf("project Top Instances attention panel retains a hidden 20-series cap: %q", expression)
	}
	for _, test := range []struct {
		dashboard dashboardDocumentationDashboard
		panelID   int
	}{
		{dashboard: cluster, panelID: 1274},
		{dashboard: project, panelID: 1300},
	} {
		panel := dashboardDocumentationPanelByID(t, test.dashboard, test.panelID)
		if panel.FieldConfig.Defaults.Unit != "bytes" {
			t.Errorf("disk capacity panel %d does not use IEC byte rendering: unit=%q", test.panelID, panel.FieldConfig.Defaults.Unit)
		}
	}

	for _, test := range []struct {
		dashboard dashboardDocumentationDashboard
		panelID   int
	}{
		{dashboard: cluster, panelID: 22002},
		{dashboard: instance, panelID: 22002},
	} {
		panel := dashboardDocumentationPanelByID(t, test.dashboard, test.panelID)
		lower := strings.ToLower(panel.Title + "\n" + panel.Description)
		if !strings.Contains(lower, "mining evidence") || !strings.Contains(lower, "not proof") {
			t.Errorf("mining panel %d must identify strongest evidence without claiming confirmation: %q / %q", test.panelID, panel.Title, panel.Description)
		}
	}

	allDashboardText := ""
	for filename, dashboard := range dashboards {
		for _, panel := range dashboardDocumentationFlattenPanels(dashboard.Panels) {
			expressions := dashboardDocumentationPanelExpressions(panel)
			allDashboardText += panel.Title + "\n" + panel.Description + "\n" + expressions + "\n"
			if panel.Type != "table" && strings.Contains(expressions, "oie_") && panel.FieldConfig.Defaults.Unit == "" {
				t.Errorf("%s panel %d %q has no display unit", filename, panel.ID, panel.Title)
			}
			if panel.Type == "timeseries" && panel.FieldConfig.Defaults.Custom.Stacking.Mode != "none" {
				t.Errorf("%s time-series panel %d %q does not explicitly disable stacking (mode=%q)", filename, panel.ID, panel.Title, panel.FieldConfig.Defaults.Custom.Stacking.Mode)
			}
			for _, forbiddenUnit := range []string{"GBs", "decgbytes", "Gbits", "decmbytes"} {
				if panel.FieldConfig.Defaults.Unit == forbiddenUnit {
					t.Errorf("%s panel %d %q uses decimal display unit %q for binary-scaled data", filename, panel.ID, panel.Title, forbiddenUnit)
				}
			}
		}
	}
	for _, required := range []string{
		"up{job=", "oie_host_conntrack_utilization", "oie_host_cpu_usage_percent", "oie_host_mem_available_mb",
		"topk(", "oie_instance_resource_cpu_severity", "oie_instance_resource_mem_severity",
		"oie_instance_resource_disk_severity", "oie_instance_resource_net_severity",
		"oie_instance_outbound_unique_remotes", "oie_instance_threat_tor_exit_active_flows",
		"oie_host_threat_feed_fresh", "oie_instance_mining_suspected", "oie_instance_info",
	} {
		if !strings.Contains(allDashboardText, required) {
			t.Errorf("dashboard set does not expose %q", required)
		}
	}
	for _, forbidden := range []string{
		"Likely Vertical Scanning Activity", "Likely Horizontal Scanning Activity",
		"Likely Brute-Force Activity", "Potential Port Spammers", "Persistent Threats", "Chronic Threats",
		"7d Unique IPs", "30d Unique IPs", "High Packet Senders", "High Packet Receivers",
		"Sustained CPU Saturation", "Heavy Disk Writers", "Top Bandwidth Consumers",
		"Monthly Bandwidth Leaders", "All Provider Threat Contacts", "Total Threat List Hits",
	} {
		if strings.Contains(allDashboardText, forbidden) {
			t.Errorf("dashboard wording overclaims bounded observational evidence with %q", forbidden)
		}
	}
	if !strings.Contains(strings.ToLower(threats.Title+allDashboardText), "evidence") {
		t.Fatal("threat dashboards never identify list matches and behavior features as evidence")
	}
}

func dashboardDocumentationParseMetricDocs(t *testing.T, readme string) map[string]dashboardDocumentationMetricDoc {
	t.Helper()
	result := make(map[string]dashboardDocumentationMetricDoc)
	scanner := bufio.NewScanner(strings.NewReader(readme))
	current := ""
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "- **oie_") && strings.HasSuffix(line, "**") {
			current = strings.TrimSuffix(strings.TrimPrefix(line, "- **"), "**")
			if _, duplicate := result[current]; duplicate {
				t.Fatalf("duplicate README metric block %s", current)
			}
			result[current] = dashboardDocumentationMetricDoc{}
			continue
		}
		if current == "" {
			continue
		}
		doc := result[current]
		switch {
		case strings.HasPrefix(line, "  - Type: "):
			doc.Type = strings.TrimSpace(strings.TrimPrefix(line, "  - Type: "))
		case strings.HasPrefix(line, "  - labels: "):
			doc.Labels = strings.TrimSpace(strings.TrimPrefix(line, "  - labels: "))
			if doc.Labels == "none" {
				doc.Labels = ""
			}
		case strings.HasPrefix(line, "  - unit: "):
			doc.Unit = strings.TrimSpace(strings.TrimPrefix(line, "  - unit: "))
		}
		result[current] = doc
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}

func dashboardDocumentationSortedLabels(labels string) string {
	if labels == "" {
		return ""
	}
	values := strings.Split(labels, ",")
	for index := range values {
		values[index] = strings.TrimSpace(values[index])
	}
	sort.Strings(values)
	return strings.Join(values, ",")
}

func TestDashboardDocumentationREADMECatalogMatchesEveryFinalMetric(t *testing.T) {
	docs := dashboardDocumentationParseMetricDocs(t, dashboardDocumentationReadFile(t, "README.md"))
	labels := compatibilityDescriptorLabelOrder(t)
	if len(docs) != inventoryOIEFamilyCount || len(labels) != inventoryOIEFamilyCount {
		t.Fatalf("README/exporter metric families=%d/%d, want %d", len(docs), len(labels), inventoryOIEFamilyCount)
	}

	families, _ := dataIntegrityFullRegistryFixture(t)
	types := make(map[string]string, inventoryOIEFamilyCount)
	for _, family := range families {
		if strings.HasPrefix(family.GetName(), "oie_") {
			types[family.GetName()] = family.GetType().String()
		}
	}
	for name, wantLabels := range labels {
		doc, exists := docs[name]
		if !exists {
			t.Errorf("README omits metric %s", name)
			continue
		}
		if !strings.EqualFold(doc.Type, types[name]) {
			t.Errorf("README type for %s=%q, exporter=%q", name, doc.Type, types[name])
		}
		if got, want := dashboardDocumentationSortedLabels(doc.Labels), dashboardDocumentationSortedLabels(wantLabels); got != want {
			t.Errorf("README labels for %s=%q, exporter=%q", name, got, want)
		}
		unit := strings.ToLower(doc.Unit)
		if unit == "" {
			t.Errorf("README unit for %s is empty", name)
		}
		switch {
		case strings.Contains(name, "_gbytes"):
			if !strings.Contains(unit, "gib") && !strings.Contains(unit, "gibibyte") {
				t.Errorf("README unit for %s=%q does not describe binary gibibytes", name, doc.Unit)
			}
		case strings.Contains(name, "_mb"):
			if !strings.Contains(unit, "mib") && !strings.Contains(unit, "mebibyte") {
				t.Errorf("README unit for %s=%q does not describe binary mebibytes", name, doc.Unit)
			}
		case strings.Contains(name, "_bytes"):
			if !strings.Contains(unit, "byte") {
				t.Errorf("README unit for %s=%q does not describe bytes", name, doc.Unit)
			}
		case strings.Contains(name, "_seconds"):
			if !strings.Contains(unit, "second") {
				t.Errorf("README unit for %s=%q does not describe seconds", name, doc.Unit)
			}
		case strings.HasSuffix(name, "_percent"):
			if !strings.Contains(unit, "percent") {
				t.Errorf("README unit for %s=%q does not describe percent", name, doc.Unit)
			}
		case strings.HasSuffix(name, "_severity"):
			if !strings.Contains(unit, "0-100") {
				t.Errorf("README unit for %s=%q does not describe the 0-100 score", name, doc.Unit)
			}
		}
	}
}

func dashboardDocumentationDocumentedFlagDefaults(t *testing.T, readme string) map[string]string {
	t.Helper()
	result := make(map[string]string)
	for _, line := range strings.Split(readme, "\n") {
		match := dashboardDocumentationDocFlagRE.FindStringSubmatch(line)
		if len(match) != 3 {
			continue
		}
		if _, duplicate := result[match[1]]; duplicate {
			t.Fatalf("README documents flag %s more than once", match[1])
		}
		result[match[1]] = match[2]
	}
	return result
}

func dashboardDocumentationUnquoteDefault(value string) string {
	if unquoted, err := strconv.Unquote(value); err == nil {
		return unquoted
	}
	return value
}

func dashboardDocumentationDefaultsEqual(runtime, documented string) bool {
	runtime = dashboardDocumentationUnquoteDefault(runtime)
	documented = dashboardDocumentationUnquoteDefault(documented)
	if runtime == documented {
		return true
	}
	if runtimeDuration, err := time.ParseDuration(runtime); err == nil {
		if documentedDuration, err := time.ParseDuration(documented); err == nil {
			return runtimeDuration == documentedDuration
		}
	}
	if runtimeNumber, err := strconv.ParseFloat(runtime, 64); err == nil {
		if documentedNumber, err := strconv.ParseFloat(documented, 64); err == nil {
			return runtimeNumber == documentedNumber
		}
	}
	return false
}

func TestDashboardDocumentationREADMEDocumentsEveryRuntimeDefaultExactly(t *testing.T) {
	documented := dashboardDocumentationDocumentedFlagDefaults(t, dashboardDocumentationReadFile(t, "README.md"))
	runtime := compatibilityRuntimeCLIContract(t)
	if len(documented) != len(runtime) {
		t.Fatalf("README/runtime flag counts=%d/%d", len(documented), len(runtime))
	}
	for _, line := range runtime {
		fields := strings.SplitN(line, "|", 3)
		if len(fields) != 3 {
			t.Fatalf("invalid runtime flag contract %q", line)
		}
		got, exists := documented[fields[0]]
		if !exists {
			t.Errorf("README omits runtime flag %s", fields[0])
			continue
		}
		if !dashboardDocumentationDefaultsEqual(fields[1], got) {
			t.Errorf("README default for %s=%q, runtime=%s", fields[0], got, fields[1])
		}
	}
}

func TestDashboardDocumentationContract(t *testing.T) {
	contractText := strings.ToLower(dashboardDocumentationReadFile(t, dashboardDocumentationContractPath))
	for _, phrase := range []string{
		"metric name", "metric type", "labels", "unit", "availability", "freshness",
		"retained", "missing", "persistence", "alert requirements", "runtime defaults",
		"5s through 1m", "ubuntu 22.04", "ubuntu 24.04", "cap_net_admin",
		"libvirt", "ansible", "500,000 conntrack entries", "500 active domains",
		"one exporter per compute node", "does not prove compromise", "does not prove mining",
		"overlapping tenant ips", "asymmetric routing", "payload",
	} {
		if !strings.Contains(contractText, phrase) {
			t.Errorf("Dashboard and documentation contract document is missing %q", phrase)
		}
	}

	readme := dashboardDocumentationReadFile(t, "README.md")
	if got := strings.Count(readme, "[DASHBOARDS_AND_DOCUMENTATION.md](DASHBOARDS_AND_DOCUMENTATION.md)"); got != 1 {
		t.Fatalf("README Dashboard and documentation contract link count=%d, want 1", got)
	}
	for _, forbidden := range []string{
		"Detecting low-level network abuses", "anomaly/abuse detection", "single VM creating the blast radius",
		"normal web traffic or unrelated outbound fan-out cannot hide a pool connection",
		"They can hide payload, but they cannot hide host resource use or conntrack state",
		"leak detection",
	} {
		if strings.Contains(readme, forbidden) {
			t.Errorf("README retains unsupported claim %q", forbidden)
		}
	}

	grafanaReadme := strings.ToLower(dashboardDocumentationReadFile(t, dashboardDocumentationGrafanaREADMEPath))
	for _, phrase := range []string{
		"prometheus", "grafana 12", "openstack-instance-exporter", "node exporter",
		"import", "fresh", "retained", "not proof", "five dashboards",
	} {
		if !strings.Contains(grafanaReadme, phrase) {
			t.Errorf("Grafana example README is missing %q", phrase)
		}
	}
	for filename := range dashboardDocumentationLoadDashboards(t) {
		if !strings.Contains(grafanaReadme, strings.ToLower(filename)) {
			t.Errorf("Grafana example README omits %s", filename)
		}
	}
}

func TestDashboardDocumentationDocumentationGateIsMandatory(t *testing.T) {
	makefile := dashboardDocumentationReadFile(t, "Makefile")
	if !strings.Contains(makefile, "docs:") || !strings.Contains(makefile, "check: vet test coverage test-race test-shuffle fuzz contracts replay scale docs ansible-test") {
		t.Fatal("Makefile does not make the Dashboard and documentation documentation/dashboard gate mandatory")
	}
	workflow := ciReleaseLoadWorkflow(t, ".github/workflows/ci.yml")
	count := 0
	for _, job := range workflow.Jobs {
		for _, step := range job.Steps {
			if strings.TrimSpace(step.Run) == `make docs PROMTOOL="$PROMTOOL"` {
				count++
			}
		}
	}
	if count != 1 {
		t.Fatalf("required CI exact Dashboard and documentation docs-gate steps=%d, want 1", count)
	}
	readme := dashboardDocumentationReadFile(t, "README.md")
	if !strings.Contains(readme, "`make docs PROMTOOL=/path/to/promtool`") {
		t.Fatal("README does not document the executable Dashboard and documentation validation command")
	}
}

func TestDashboardDocumentationFinalContractMatchesOperationalLayout(t *testing.T) {
	contract := dashboardDocumentationReadFile(t, dashboardDocumentationContractPath)
	for _, required := range []string{
		"The five-dashboard Grafana 12 set",
		"one concise group with 82 definitions",
		"all v1.2.0 alert names remain present",
		"All 82 bundled rules have executable lifecycle coverage",
		"shipped Ansible role runs the service as root",
		"detailed in `OPERATIONAL_CONFIGURATION.md`",
	} {
		if !strings.Contains(contract, required) {
			t.Errorf("final dashboard/documentation contract omits %q", required)
		}
	}
	for _, obsolete := range []string{
		"alert pack has four policy groups",
		"78 inherited alert-validation rules",
		"runs a dedicated non-root service account",
	} {
		if strings.Contains(contract, obsolete) {
			t.Errorf("final dashboard/documentation contract retains obsolete statement %q", obsolete)
		}
	}
}

func TestDashboardDocumentationVolumeRetypeLifecycleSemantics(t *testing.T) {
	requiredByFile := map[string][]string{
		"README.md": {
			"completion-paced fast poller",
			"no more often than every five seconds",
			"measured from the end of the preceding attempt",
			"no more often than every fifteen seconds after the preceding query completes",
			"waits thirty seconds after a failed or timed-out query completes",
			"bounded discovery XML inspection still runs",
			"RBD pool names, not Cinder volume-type names",
			"RBD image basenames that retain the `volume-` prefix",
			"remove that prefix before passing either value to `openstack volume show`",
			"Status `4` is emitted only after a successful XML inspection",
			"too old to reconfirm expires without a terminal status",
			"in-memory exporter-process state and reset on exporter restart",
			"exact same source/destination identity",
		},
		dashboardDocumentationContractPath: {
			"completion-paced fast poller",
			"no more often than every five seconds after the preceding attempt completes",
			"no more often than every fifteen seconds after the preceding query completes",
			"wait thirty seconds after a failed query completes",
			"bounded discovery XML inspection continues",
			"Status **Outcome Unknown** is emitted only after a successful terminal XML inspection",
			"loss of reconfirmation alone expires the active row",
			"reset on restart",
			"exact repeated source/destination identity retains only its newest row",
			"Source RBD Pool",
			"Destination RBD Pool",
			"Source RBD Image",
			"Destination RBD Image",
			"strip that prefix before using either value with `openstack volume show`",
		},
		"PACKAGE_MANIFEST.md": {
			"Attached-volume retype monitoring is opt-in and disabled by default.",
			"bounded, compute-local Libvirt observations",
			"It does not report detached-volume migrations or authoritative Cinder outcomes.",
			"Detected disk mirrors exclude block statistics for the affected VM",
			"CPU, memory and network collection continue when Libvirt control/job checks permit",
			"[LIBVIRT_COLLECTION_SAFETY.md](LIBVIRT_COLLECTION_SAFETY.md)",
			"[README.md](README.md)",
		},
		"SCALING_LIMITS.md": {
			"completion-paced fast poller",
			"no more often than every five seconds after the preceding attempt completes",
			"no more often than every fifteen seconds after the preceding query completes",
			"wait thirty seconds after a failed query completes",
			"bounded discovery remains active",
			"too old to reconfirm expires without creating terminal series",
			"status `4` is reserved for a successful terminal XML inspection",
			"reset on exporter restart",
			"exact repeated source/destination identity",
		},
		dashboardDocumentationGrafanaREADMEPath: {
			"completion-paced fast poller",
			"no more often than every five seconds after the preceding attempt completes",
			"no more often than every fifteen seconds after the preceding query completes",
			"waits thirty seconds after a failed query completes",
			"Bounded discovery XML inspection continues",
			"Unknown is emitted only after a successful terminal XML inspection",
			"too old to reconfirm expires without a terminal result",
			"reset on exporter restart",
			"exact repeated source/destination identity",
			"Source RBD Pool",
			"Destination RBD Pool",
			"Source RBD Image",
			"Destination RBD Image",
			"strip the prefix before passing either value to `openstack volume show`",
		},
	}
	for path, required := range requiredByFile {
		content := dashboardDocumentationReadFile(t, path)
		for _, phrase := range required {
			if !strings.Contains(content, phrase) {
				t.Errorf("%s omits volume-retype lifecycle wording %q", path, phrase)
			}
		}
		for _, obsolete := range []string{
			"an unconfirmed operation eventually becomes `unknown`",
			"ages into a bounded `unknown`",
			"ages to terminal `unknown`",
		} {
			if strings.Contains(content, obsolete) {
				t.Errorf("%s retains obsolete volume-retype wording %q", path, obsolete)
			}
		}
	}
}

func TestDashboardDocumentationPublicExporterAndAlertSurfacesStayFrozen(t *testing.T) {
	if got := len(compatibilityDescriptorLabelOrder(t)); got != inventoryOIEFamilyCount {
		t.Fatalf("current Prometheus families=%d, want %d", got, inventoryOIEFamilyCount)
	}
	wantCLI := append(compatibilityReadNonEmptyLines(t, "testdata/cli-flags-baseline.golden"), compatibilityReadNonEmptyLines(t, threatIntelligenceCLIFlagAdditionsGoldenPath)...)
	wantCLI = append(wantCLI, compatibilityReadNonEmptyLines(t, runtimeConfigurationCLIFlagAdditionsGoldenPath)...)
	wantCLI = append(wantCLI, volumeRetypeCLIFlagAddition)
	sort.Strings(wantCLI)
	if got := compatibilityRuntimeCLIContract(t); strings.Join(got, "\n") != strings.Join(wantCLI, "\n") {
		t.Fatal("Dashboard and documentation changed the exporter CLI")
	}
	alerts := loadCurrentAlertRules(t)
	count := 0
	for _, group := range alerts.Groups {
		count += len(group.Rules)
	}
	if count != 82 {
		t.Fatalf("Dashboard and documentation alert rules=%d, want current operational inventory 82", count)
	}
}

func TestDashboardDocumentationRollingWindowsAndSourcesAreHonest(t *testing.T) {
	dashboards := dashboardDocumentationLoadDashboards(t)
	project := dashboards["openstack_instance_exporter_project.json"]
	cluster := dashboards["openstack_instance_exporter_cluster.json"]

	for _, id := range []int{1257, 1258} {
		panel := dashboardDocumentationPanelByID(t, project, id)
		if !strings.Contains(panel.Title, "Volume (Rolling 1 Minute)") ||
			!strings.Contains(panel.Description, "not a cumulative total over the full dashboard time range") ||
			!strings.Contains(dashboardDocumentationPanelExpressions(panel), "increase(") {
			t.Errorf("project panel %d overstates a rolling increase as a total: title=%q description=%q", id, panel.Title, panel.Description)
		}
	}

	memoryDelta := dashboardDocumentationPanelByID(t, project, 1309)
	if strings.Contains(memoryDelta.FieldConfig.Defaults.Custom.AxisLabel, "Unused RAM") ||
		!strings.Contains(memoryDelta.FieldConfig.Defaults.Custom.AxisLabel, "Configured minus guest-view used") {
		t.Errorf("project panel 1309 axis overstates a guest-view diagnostic as unused physical RAM: %q", memoryDelta.FieldConfig.Defaults.Custom.AxisLabel)
	}

	highAttention := dashboardDocumentationPanelByID(t, project, 1412)
	for _, required := range []string{"composite", "conntrack behavior", "threat-feed", "heuristic"} {
		if !strings.Contains(highAttention.Description, required) {
			t.Errorf("project panel 1412 omits composite-attention caveat %q: %q", required, highAttention.Description)
		}
	}

	for _, id := range []int{1211, 1219, 1221} {
		panel := dashboardDocumentationPanelByID(t, cluster, id)
		if !strings.Contains(panel.Description, "OIE exporter instrumentation") || strings.Contains(panel.Description, "guest OS reporting") {
			t.Errorf("cluster exporter-internal panel %d claims a guest/Libvirt source: %q", id, panel.Description)
		}
	}
	libvirtDuration := dashboardDocumentationPanelByID(t, cluster, 1218)
	if !strings.Contains(libvirtDuration.Description, "OIE exporter instrumentation around the Libvirt domain collection") ||
		!strings.Contains(libvirtDuration.Description, "exporter collection wall time") {
		t.Errorf("cluster Libvirt-duration panel misstates the measured wall time: %q", libvirtDuration.Description)
	}
	exporterRSS := dashboardDocumentationPanelByID(t, cluster, 1226)
	if exporterRSS.FieldConfig.Defaults.Unit != "bytes" {
		t.Errorf("cluster exporter RSS panel must use IEC byte rendering: unit=%q", exporterRSS.FieldConfig.Defaults.Unit)
	}

	commit := dashboardDocumentationPanelByID(t, cluster, 1232)
	if !strings.Contains(commit.Title, "Raw Commit Ratios") ||
		!strings.Contains(commit.Description, "not Nova Scheduler or Placement capacity") ||
		!strings.Contains(commit.Description, "CPU pinning cannot be inferred") {
		t.Errorf("cluster raw commit panel overstates scheduler semantics: title=%q description=%q", commit.Title, commit.Description)
	}

	fixedIPs := dashboardDocumentationPanelByID(t, cluster, 20003)
	if !strings.Contains(fixedIPs.Description, "inventory count, not observed network activity") ||
		strings.Contains(fixedIPs.Description, "guest OS reporting") {
		t.Errorf("cluster fixed-IP inventory panel has an incorrect source/meaning: %q", fixedIPs.Description)
	}
}
