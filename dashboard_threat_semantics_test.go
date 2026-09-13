package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type threatSemanticsTarget struct {
	Expr         string `json:"expr"`
	LegendFormat string `json:"legendFormat"`
}

type threatSemanticsPanel struct {
	ID          int                     `json:"id"`
	Title       string                  `json:"title"`
	Description string                  `json:"description"`
	Targets     []threatSemanticsTarget `json:"targets"`
	Panels      []threatSemanticsPanel  `json:"panels"`
}

type threatSemanticsDashboard struct {
	Panels []threatSemanticsPanel `json:"panels"`
}

func loadThreatSemanticsDashboard(t *testing.T) threatSemanticsDashboard {
	t.Helper()
	path := filepath.Join(
		"examples",
		"grafana_dashboard_example",
		"openstack_instance_exporter_threats.json",
	)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var dashboard threatSemanticsDashboard
	if err := json.Unmarshal(data, &dashboard); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return dashboard
}

func findThreatSemanticsPanel(t *testing.T, dashboard threatSemanticsDashboard, id int) threatSemanticsPanel {
	t.Helper()
	var visit func([]threatSemanticsPanel) (threatSemanticsPanel, bool)
	visit = func(panels []threatSemanticsPanel) (threatSemanticsPanel, bool) {
		for _, panel := range panels {
			if panel.ID == id {
				return panel, true
			}
			if nested, ok := visit(panel.Panels); ok {
				return nested, true
			}
		}
		return threatSemanticsPanel{}, false
	}
	panel, ok := visit(dashboard.Panels)
	if !ok {
		t.Fatalf("threat dashboard panel %d not found", id)
	}
	return panel
}

func threatSemanticsSingleTarget(t *testing.T, panel threatSemanticsPanel) threatSemanticsTarget {
	t.Helper()
	if len(panel.Targets) != 1 {
		t.Fatalf("panel %d has %d targets, want 1", panel.ID, len(panel.Targets))
	}
	return panel.Targets[0]
}

func TestThreatDashboardNonAdditiveFixedIPMetricsUseExplicitWorstSeries(t *testing.T) {
	dashboard := loadThreatSemanticsDashboard(t)
	grouping := "max by (instance_uuid, project_uuid, project_name, user_uuid)"

	for _, id := range []int{4001, 4002, 4003, 4004} {
		panel := findThreatSemanticsPanel(t, dashboard, id)
		target := threatSemanticsSingleTarget(t, panel)
		if strings.Count(target.Expr, grouping) != 2 ||
			!strings.Contains(target.Expr, "max_over_time(") ||
			!strings.Contains(target.Expr, "and on(instance_uuid, project_uuid, project_name, user_uuid)") {
			t.Errorf("panel %d does not collapse fixed-IP/family gauges to one ranked worst series per instance: %q", id, target.Expr)
		}
		lower := strings.ToLower(panel.Title + "\n" + panel.Description)
		if !strings.Contains(lower, "fixed-ip") || !strings.Contains(lower, "address-family") {
			t.Errorf("panel %d does not disclose fixed-IP/address-family semantics", id)
		}
		if strings.Contains(target.LegendFormat, "{{ ip }}") || strings.Contains(target.LegendFormat, "{{ family }}") {
			t.Errorf("panel %d unexpectedly exposes collapsed dimensions in legend %q", id, target.LegendFormat)
		}
	}

	for _, id := range []int{5003, 6003} {
		panel := findThreatSemanticsPanel(t, dashboard, id)
		target := threatSemanticsSingleTarget(t, panel)
		if strings.Count(target.Expr, grouping) != 2 ||
			!strings.Contains(target.Expr, "max_over_time(") ||
			strings.Contains(target.Expr, "sum_over_time(") {
			t.Errorf("panel %d does not report the largest scrape-frequency-independent fixed-IP/family churn burst per instance: %q", id, target.Expr)
		}
		lower := strings.ToLower(panel.Description)
		if !strings.Contains(lower, "not a monotonic event counter") ||
			!strings.Contains(lower, "not a") ||
			!strings.Contains(lower, "instance-wide union") ||
			!strings.Contains(lower, "understate") ||
			!strings.Contains(lower, "do not inflate") {
			t.Errorf("panel %d does not disclose its non-additive approximation", id)
		}
	}
}

func TestThreatDashboardAdditiveDeviceCountersAreAggregatedPerInstance(t *testing.T) {
	dashboard := loadThreatSemanticsDashboard(t)
	grouping := "sum by (instance_uuid, project_uuid, project_name, user_uuid)"
	tests := map[int]string{
		4005: "oie_instance_net_tx_packets_total",
		4006: "oie_instance_net_rx_packets_total",
		4008: "oie_instance_disk_write_gbytes_total",
		5002: "oie_instance_net_tx_gbytes_total",
		6002: "oie_instance_net_tx_gbytes_total",
	}
	for id, metric := range tests {
		panel := findThreatSemanticsPanel(t, dashboard, id)
		target := threatSemanticsSingleTarget(t, panel)
		if strings.Count(target.Expr, grouping) != 2 ||
			strings.Count(target.Expr, "increase("+metric) != 2 ||
			!strings.Contains(target.Expr, "and on(instance_uuid, project_uuid, project_name, user_uuid)") {
			t.Errorf("panel %d does not aggregate %s to one ranked series per instance: %q", id, metric, target.Expr)
		}
		if !strings.Contains(strings.ToLower(panel.Description), "summed across every libvirt") {
			t.Errorf("panel %d does not disclose device aggregation", id)
		}
	}
}

func TestThreatDashboardContactIncreasesAggregateListsAndDirectionsPerInstance(t *testing.T) {
	dashboard := loadThreatSemanticsDashboard(t)
	metrics := []string{
		"oie_instance_threat_tor_exit_contacts_total",
		"oie_instance_threat_tor_relay_contacts_total",
		"oie_instance_threat_customlist_contacts_total",
		"oie_instance_threat_emergingthreats_contacts_total",
		"oie_instance_threat_spamhaus_contacts_total",
	}
	for _, id := range []int{5004, 6004} {
		panel := findThreatSemanticsPanel(t, dashboard, id)
		target := threatSemanticsSingleTarget(t, panel)
		if strings.Count(target.Expr, "sum by (instance_uuid, project_uuid, project_name, user_uuid)") != 2 ||
			strings.Count(target.Expr, "label_replace(") != 10 ||
			strings.Count(target.Expr, `"threat_source"`) != 10 ||
			strings.Contains(target.Expr, "__name__") ||
			strings.Contains(target.Expr, " + increase(") {
			t.Errorf("panel %d does not aggregate every list and direction into one instance series: %q", id, target.Expr)
		}
		for _, metric := range metrics {
			if strings.Count(target.Expr, "increase("+metric) != 2 {
				t.Errorf("panel %d does not include %s exactly once in the displayed aggregate and once in the rank aggregate: %q", id, metric, target.Expr)
			}
		}
		if strings.Contains(target.LegendFormat, "{{ direction }}") {
			t.Errorf("panel %d legend exposes a direction that the query should aggregate: %q", id, target.LegendFormat)
		}
		if !strings.Contains(strings.ToLower(panel.Description), "both traffic directions") {
			t.Errorf("panel %d does not disclose direction aggregation", id)
		}
	}
}

func TestThreatDashboardIntervalContactEventsAreNotCalledARate(t *testing.T) {
	dashboard := loadThreatSemanticsDashboard(t)
	row := findThreatSemanticsPanel(t, dashboard, 6005)
	if strings.Contains(row.Title, "Rate") || !strings.Contains(row.Title, "Events over $__rate_interval") {
		t.Errorf("interval increase row is mislabeled as a per-second rate: %q", row.Title)
	}
	for _, id := range []int{3046, 3047, 3048, 3049, 3050} {
		panel := findThreatSemanticsPanel(t, dashboard, id)
		target := threatSemanticsSingleTarget(t, panel)
		if !strings.Contains(target.Expr, "increase(") || strings.Contains(target.Expr, "rate(") {
			t.Errorf("panel %d must remain an interval event count: %q", id, target.Expr)
		}
	}
}
