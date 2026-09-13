package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type dashboardAccuracySample struct {
	Labels string  `yaml:"labels"`
	Value  float64 `yaml:"value"`
}

type dashboardAccuracyExpressionTest struct {
	Expr     string                    `yaml:"expr"`
	EvalTime string                    `yaml:"eval_time"`
	Expected []dashboardAccuracySample `yaml:"exp_samples"`
}

type dashboardAccuracyScenario struct {
	Name        string                               `yaml:"name"`
	Interval    string                               `yaml:"interval"`
	InputSeries []alertValidationPromtoolInputSeries `yaml:"input_series"`
	Expressions []dashboardAccuracyExpressionTest    `yaml:"promql_expr_test"`
}

func dashboardAccuracyQuery(t *testing.T, dashboard string, id, target int) string {
	t.Helper()
	dashboards := dashboardDocumentationLoadDashboards(t)
	panel := dashboardDocumentationPanelByID(t, dashboards["openstack_instance_exporter_"+dashboard+".json"], id)
	if target >= len(panel.Targets) {
		t.Fatalf("%s panel %d target %d missing", dashboard, id, target)
	}
	return strings.NewReplacer(
		"${gvar_oie_volume_uuid}", ".*", "${gvar_oie_hypervisor}", ".*", "$gvar_oie_instance_uuid", ".*",
		"$gvar_oie_project_name", ".*", "$gvar_oie_project_uuid", ".*",
		"${gvar_oie_top_n}", "10", "${gvar_oie_top_projects}", "10",
		"${gvar_oie_rank_by:raw}", "max_over_time", "${gvar_oie_rank_projects_by:raw}", "max_over_time",
		"${__range_s}", "600", "$__rate_interval", "5m",
	).Replace(panel.Targets[target].Expr)
}

func dashboardAccuracyRun(t *testing.T, scenarios []dashboardAccuracyScenario) {
	t.Helper()
	input := struct {
		EvaluationInterval string                      `yaml:"evaluation_interval"`
		Tests              []dashboardAccuracyScenario `yaml:"tests"`
	}{"10s", scenarios}
	data, err := yaml.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "dashboard-accuracy.yml")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(alertValidationPromtoolPath(t), "test", "rules", path)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("actual dashboard query evaluation failed: %v\n%s", err, output)
	}
}

func dashboardAccuracySeries(name, labels, values string) alertValidationPromtoolInputSeries {
	return alertValidationPromtoolInputSeries{Series: name + "{" + labels + "}", Values: values}
}

const dashboardAccuracyHostLabels = `job="openstack-instance-exporter",instance="compute-a:9120"`
const dashboardAccuracyVMLabels = dashboardAccuracyHostLabels + `,domain="instance-a",instance_uuid="vm-a",project_uuid="project-a",project_name="Project A",user_uuid="user-a"`

func dashboardAccuracyHealth() []alertValidationPromtoolInputSeries {
	values := map[string]string{
		"up": "1x60", "oie_host_libvirt_ok": "1x60", "oie_host_conntrack_raw_ok": "1x60",
		"oie_host_libvirt_stale_seconds": "0x60", "oie_host_conntrack_stale_seconds": "0x60",
		"oie_host_collection_interval_seconds": "15x60",
	}
	out := make([]alertValidationPromtoolInputSeries, 0, len(values))
	for name, samples := range values {
		out = append(out, dashboardAccuracySeries(name, dashboardAccuracyHostLabels, samples))
	}
	return out
}

func dashboardAccuracyExpected(expr string, value float64) dashboardAccuracyExpressionTest {
	return dashboardAccuracyExpressionTest{Expr: expr, EvalTime: "10m", Expected: []dashboardAccuracySample{{Labels: "{}", Value: value}}}
}

func dashboardAccuracyReplaceMetric(series []alertValidationPromtoolInputSeries, metric, values string) {
	for i := range series {
		if strings.HasPrefix(series[i].Series, metric+"{") {
			series[i].Values = values
		}
	}
}

func TestDashboardAccuracyMiningStatusTransitionsWithPromtool(t *testing.T) {
	queries := []string{dashboardAccuracyQuery(t, "instance", 22002, 0), dashboardAccuracyQuery(t, "cluster", 22002, 0)}
	var scenarios []dashboardAccuracyScenario
	for _, condition := range []string{"clean", "active", "cleared", "scrape-down", "libvirt-down", "conntrack-down", "stale", "disabled", "partial-instances", "missing-target-health", "missing-cpu", "short-cpu-history", "cpu-qualified", "cpu-below", "no-series"} {
		series := dashboardAccuracyHealth()
		series = append(series, dashboardAccuracySeries("oie_instance_info", dashboardAccuracyVMLabels, "1x60"), dashboardAccuracySeries("oie_instance_state_code", dashboardAccuracyVMLabels, "1x60"))
		if condition != "disabled" {
			series = append(series, dashboardAccuracySeries("oie_instance_outbound_flows", dashboardAccuracyVMLabels+`,ip="192.0.2.1",family="ipv4"`, "0x60"))
		}
		want := 0.0
		if condition == "active" || condition == "cleared" || strings.Contains(condition, "cpu") {
			confidence, values := "high", "1x60"
			if condition == "cleared" {
				values = "1x54 stale _x5"
			} else {
				want = 1
			}
			if strings.Contains(condition, "cpu") {
				confidence = "high_persistent"
			}
			series = append(series, dashboardAccuracySeries("oie_instance_mining_suspected", dashboardAccuracyVMLabels+`,ip="192.0.2.1",family="ipv4",port="14444",confidence="`+confidence+`"`, values))
		}
		switch condition {
		case "scrape-down":
			dashboardAccuracyReplaceMetric(series, "up", "1x54 0x5")
			want = -1
		case "libvirt-down":
			dashboardAccuracyReplaceMetric(series, "oie_host_libvirt_ok", "1x54 0x5")
			want = -1
		case "conntrack-down":
			dashboardAccuracyReplaceMetric(series, "oie_host_conntrack_raw_ok", "1x54 0x5")
			want = -1
		case "stale":
			dashboardAccuracyReplaceMetric(series, "oie_host_conntrack_stale_seconds", "120x60")
			want = -1
		case "disabled":
			want = -1
		case "partial-instances":
			series = append(series, dashboardAccuracySeries("oie_instance_info", strings.ReplaceAll(dashboardAccuracyVMLabels, "vm-a", "vm-b"), "1x60"))
			want = -1
		case "missing-target-health":
			series = append(series, dashboardAccuracySeries("up", strings.ReplaceAll(dashboardAccuracyHostLabels, "compute-a", "compute-b"), "1x60"))
			want = 0
		case "short-cpu-history":
			series = append(series, dashboardAccuracySeries("oie_instance_cpu_vcpu_percent", dashboardAccuracyVMLabels, "_x58 90 90"))
		case "cpu-qualified":
			series = append(series, dashboardAccuracySeries("oie_instance_cpu_vcpu_percent", dashboardAccuracyVMLabels, "90x60"))
		case "cpu-below":
			series = append(series, dashboardAccuracySeries("oie_instance_cpu_vcpu_percent", dashboardAccuracyVMLabels, "10x60"))
		case "no-series":
			series = nil
			want = -1
		}
		var checks []dashboardAccuracyExpressionTest
		for _, expr := range queries {
			value := want
			checks = append(checks, dashboardAccuracyExpected(expr, value))
		}
		scenarios = append(scenarios, dashboardAccuracyScenario{condition, "10s", series, checks})
	}
	dashboardAccuracyRun(t, scenarios)
}

func TestDashboardAccuracyThreatCurrentCountsWithPromtool(t *testing.T) {
	var scenarios []dashboardAccuracyScenario
	for _, condition := range []string{"active", "cleared", "missing", "feed-unusable", "feeds-disabled", "partial", "duplicate-instance"} {
		series := dashboardAccuracyHealth()
		series = append(series, dashboardAccuracySeries("oie_instance_info", dashboardAccuracyVMLabels, "1x60"), dashboardAccuracySeries("oie_instance_state_code", dashboardAccuracyVMLabels, "1x60"))
		feed, severity := "1x60", "75x60"
		if condition == "cleared" {
			severity = "75x54 0x5"
		}
		if condition == "missing" {
			severity = "75x54 stale _x5"
		}
		if condition == "feed-unusable" {
			feed = "0x60"
		}
		if condition == "feeds-disabled" {
			feed = "-1x60"
		}
		series = append(series,
			dashboardAccuracySeries("oie_host_threat_feed_fresh", dashboardAccuracyHostLabels+`,list="TOREXIT"`, feed),
			dashboardAccuracySeries("oie_host_threat_feed_fresh", dashboardAccuracyHostLabels+`,list="SPAMHAUS"`, "-1x60"),
			dashboardAccuracySeries("oie_instance_threat_list_severity", dashboardAccuracyVMLabels, severity))
		if condition == "partial" {
			series = append(series, dashboardAccuracySeries("oie_instance_info", strings.ReplaceAll(dashboardAccuracyVMLabels, "vm-a", "vm-b"), "1x60"))
		}
		if condition == "duplicate-instance" {
			series = append(series, dashboardAccuracySeries("oie_instance_threat_list_severity", dashboardAccuracyVMLabels+`,replica="b"`, severity))
		}
		var checks []dashboardAccuracyExpressionTest
		for _, id := range []int{3001, 3002, 3004} {
			want := 75.0
			if id == 3001 || id == 3004 {
				want = 1
			}
			if condition == "cleared" {
				want = 0
			}
			if condition == "missing" || condition == "feed-unusable" || condition == "feeds-disabled" || condition == "partial" {
				want = -1
			}
			checks = append(checks, dashboardAccuracyExpected(dashboardAccuracyQuery(t, "threats", id, 0), want))
		}
		scenarios = append(scenarios, dashboardAccuracyScenario{condition, "10s", series, checks})
	}
	dashboardAccuracyRun(t, scenarios)
}

func TestDashboardAccuracyMemoryKeepsAllocationDenominatorWithPromtool(t *testing.T) {
	var scenarios []dashboardAccuracyScenario
	for _, condition := range []string{"complete", "missing-used", "unhealthy-source"} {
		series := dashboardAccuracyHealth()
		for i, used := range []string{"500x60", "1500x60"} {
			labels := strings.ReplaceAll(dashboardAccuracyVMLabels, "vm-a", fmt.Sprintf("vm-%d", i))
			series = append(series, dashboardAccuracySeries("oie_instance_mem_allocated_mb", labels, "2000x60"))
			if condition != "missing-used" || i == 0 {
				series = append(series, dashboardAccuracySeries("oie_instance_mem_used_mb", labels, used))
			}
		}
		if condition == "unhealthy-source" {
			dashboardAccuracyReplaceMetric(series, "oie_host_libvirt_ok", "0x60")
		}
		var checks []dashboardAccuracyExpressionTest
		for _, test := range []struct {
			dashboard  string
			id, target int
			labels     string
		}{
			{"hypervisor", 1270, 0, `{instance="compute-a:9120",oie_hypervisor="compute-a"}`},
			{"project", 1270, 0, `{project_name="Project A",project_uuid="project-a"}`},
			{"cluster", 1263, 3, `{job="openstack-instance-exporter"}`},
		} {
			expected := []dashboardAccuracySample{}
			if condition == "complete" {
				expected = append(expected, dashboardAccuracySample{test.labels, 50})
			}
			checks = append(checks, dashboardAccuracyExpressionTest{dashboardAccuracyQuery(t, test.dashboard, test.id, test.target), "10m", expected})
		}
		scenarios = append(scenarios, dashboardAccuracyScenario{condition, "10s", series, checks})
	}
	dashboardAccuracyRun(t, scenarios)
}

func TestDashboardAccuracyCPUCompositionKeepsHealthyCalculationWithPromtool(t *testing.T) {
	var scenarios []dashboardAccuracyScenario
	for _, condition := range []string{"complete", "missing-instance-cpu"} {
		series := dashboardAccuracyHealth()
		series = append(series,
			dashboardAccuracySeries("oie_host_cpu_threads", dashboardAccuracyHostLabels, "8x60"),
			dashboardAccuracySeries("oie_host_cpu_usage_percent", dashboardAccuracyHostLabels, "50x60"))
		for i := 0; i < 2; i++ {
			labels := strings.ReplaceAll(dashboardAccuracyVMLabels, "vm-a", fmt.Sprintf("vm-%d", i))
			series = append(series, dashboardAccuracySeries("oie_instance_cpu_vcpu_count", labels, "2x60"))
			if condition == "complete" || i == 0 {
				series = append(series, dashboardAccuracySeries("oie_instance_cpu_vcpu_percent", labels, "50x60"))
			}
		}
		var checks []dashboardAccuracyExpressionTest
		for target := 0; target < 2; target++ {
			expected := []dashboardAccuracySample{}
			if condition == "complete" {
				expected = append(expected, dashboardAccuracySample{"{}", 25})
			}
			checks = append(checks, dashboardAccuracyExpressionTest{dashboardAccuracyQuery(t, "cluster", 1239, target), "10m", expected})
		}
		scenarios = append(scenarios, dashboardAccuracyScenario{condition, "10s", series, checks})
	}
	dashboardAccuracyRun(t, scenarios)
}

func TestDashboardAccuracyLatencyKeepsIOWeightsAndMatchedDisksWithPromtool(t *testing.T) {
	var scenarios []dashboardAccuracyScenario
	for _, condition := range []string{"complete", "missing-time", "missing-requests", "different-sample-cohorts", "idle", "unhealthy-source"} {
		series := dashboardAccuracyHealth()
		for i, rates := range [][2]string{{"0+100x60", "0+1x60"}, {"0+900x60", "0+90x60"}} {
			labels := dashboardAccuracyVMLabels + fmt.Sprintf(`,volume_uuid="volume-%d",disk_type="premium",disk_path="vd%d"`, i, i)
			if condition == "idle" {
				rates = [2]string{"0x60", "0x60"}
			}
			if condition != "missing-requests" || i == 0 {
				series = append(series, dashboardAccuracySeries("oie_instance_disk_read_requests_total", labels, rates[0]))
			}
			if condition != "missing-time" || i == 0 {
				if condition == "different-sample-cohorts" && i == 1 {
					rates[1] = "0+90x54 _ 5040 5130 5220 5310 5400"
				}
				series = append(series, dashboardAccuracySeries("oie_instance_disk_read_seconds_total", labels, rates[1]))
			}
		}
		if condition == "unhealthy-source" {
			dashboardAccuracyReplaceMetric(series, "oie_host_libvirt_ok", "0x60")
		}
		var checks []dashboardAccuracyExpressionTest
		for _, test := range []struct {
			dashboard string
			id        int
			labels    string
			scale     float64
		}{
			{"hypervisor", 1306, `{instance="compute-a:9120",oie_hypervisor="compute-a"}`, 1},
			{"project", 1305, `{project_name="Project A",project_uuid="project-a"}`, 1},
			{"instance", 2074, `{instance="compute-a:9120",instance_uuid="vm-a",project_name="Project A",project_uuid="project-a"}`, 1000},
		} {
			want := .091
			if condition != "complete" {
				want = .01
			}
			expected := []dashboardAccuracySample{}
			if condition != "idle" && condition != "unhealthy-source" {
				expected = append(expected, dashboardAccuracySample{test.labels, want * test.scale})
			}
			checks = append(checks, dashboardAccuracyExpressionTest{dashboardAccuracyQuery(t, test.dashboard, test.id, 0), "10m", expected})
		}
		scenarios = append(scenarios, dashboardAccuracyScenario{condition, "10s", series, checks})
	}
	dashboardAccuracyRun(t, scenarios)
}

func TestDashboardAccuracyCurrentStatusCannotReuseEarlierRangeValues(t *testing.T) {
	for dashboard, ids := range map[string][]int{"instance": {2091, 2092}, "cluster": {22002}, "threats": {3001, 3002, 3003, 3004}} {
		data, err := os.ReadFile(filepath.Join("examples/grafana_dashboard_example", "openstack_instance_exporter_"+dashboard+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var raw map[string]any
		if err := json.Unmarshal(data, &raw); err != nil {
			t.Fatal(err)
		}
		var check func(any)
		check = func(value any) {
			switch v := value.(type) {
			case []any:
				for _, p := range v {
					check(p)
				}
			case map[string]any:
				for _, id := range ids {
					if v["id"] != float64(id) {
						continue
					}
					for _, target := range v["targets"].([]any) {
						q := target.(map[string]any)
						if q["instant"] != true || q["range"] != false {
							t.Errorf("%s/%d is not a current instant query", dashboard, id)
						}
					}
					options := v["options"].(map[string]any)["reduceOptions"].(map[string]any)
					if fmt.Sprint(options["calcs"]) != "[last]" {
						t.Errorf("%s/%d reuses non-current samples", dashboard, id)
					}
				}
				if p, ok := v["panels"]; ok {
					check(p)
				}
			}
		}
		check(raw["panels"])
	}
}
