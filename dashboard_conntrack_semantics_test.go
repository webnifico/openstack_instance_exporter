package main

import (
	"strings"
	"testing"
)

func TestDashboardConntrackInstanceFlowPanelsAggregatePerInstance(t *testing.T) {
	dashboards := dashboardDocumentationLoadDashboards(t)
	dashboard := dashboards["openstack_instance_exporter_instance.json"]

	for _, id := range []int{2052, 2053, 2054} {
		panel := dashboardDocumentationPanelByID(t, dashboard, id)
		if !strings.Contains(panel.Title, "Endpoint-Attributed Flows") {
			t.Errorf("panel %d title does not identify endpoint attribution: %q", id, panel.Title)
		}
		if len(panel.Targets) != 1 {
			t.Fatalf("panel %d targets=%d, want 1", id, len(panel.Targets))
		}
		expression := panel.Targets[0].Expr
		const aggregate = "sum by (project_name, project_uuid, instance_uuid) ("
		if strings.Count(expression, aggregate) != 2 {
			t.Errorf("panel %d must aggregate both display and ranking values once per instance: %q", id, expression)
		}
		for _, forbidden := range []string{
			"sum by (project_name, project_uuid, instance_uuid, family)",
			"sum by (project_name, project_uuid, instance_uuid, ip)",
		} {
			if strings.Contains(expression, forbidden) {
				t.Errorf("panel %d retains per-identity grouping %q", id, forbidden)
			}
		}
		if !strings.Contains(panel.Description, "additive across") || !strings.Contains(panel.Description, "one total per instance") {
			t.Errorf("panel %d does not document its additive per-instance aggregation: %q", id, panel.Description)
		}
		if !strings.Contains(strings.ToLower(panel.FieldConfig.Defaults.Custom.AxisLabel), "endpoint-attributed") {
			t.Errorf("panel %d axis does not identify endpoint attribution: %q", id, panel.FieldConfig.Defaults.Custom.AxisLabel)
		}
	}
}

func TestDashboardConntrackInstanceUniquePanelsExposeIdentityScope(t *testing.T) {
	dashboards := dashboardDocumentationLoadDashboards(t)
	dashboard := dashboards["openstack_instance_exporter_instance.json"]

	for _, id := range []int{2079, 2080, 2081, 2087} {
		panel := dashboardDocumentationPanelByID(t, dashboard, id)
		if !strings.Contains(panel.Title, "by Fixed IP / Family") {
			t.Errorf("panel %d title does not identify fixed-IP/family scope: %q", id, panel.Title)
		}
		if !strings.Contains(panel.Description, "non-additive") || !strings.Contains(panel.Description, "not an exact instance-wide union") {
			t.Errorf("panel %d overstates its unique-count scope: %q", id, panel.Description)
		}
		if !strings.Contains(panel.Description, "applied independently to the unique and new") ||
			!strings.Contains(panel.Description, "up to 2N lines") {
			t.Errorf("panel %d does not disclose independent Top N selection for its two queries: %q", id, panel.Description)
		}
		for _, target := range panel.Targets {
			if !strings.Contains(target.LegendFormat, "{{ ip }}") || !strings.Contains(target.LegendFormat, "IPv{{ family }}") {
				t.Errorf("panel %d legend does not expose fixed IP and family: %q", id, target.LegendFormat)
			}
		}
	}
}

func TestDashboardConntrackProjectPanelsRankUniqueEntities(t *testing.T) {
	dashboards := dashboardDocumentationLoadDashboards(t)
	dashboard := dashboards["openstack_instance_exporter_project.json"]

	flowPanel := dashboardDocumentationPanelByID(t, dashboard, 1404)
	flowExpression := dashboardDocumentationPanelExpressions(flowPanel)
	if !strings.Contains(flowPanel.Title, "Endpoint-Attributed Flows") {
		t.Errorf("project panel 1404 title does not identify endpoint attribution: %q", flowPanel.Title)
	}
	if strings.Contains(flowExpression, "topk(20") {
		t.Fatal("project conntrack panel retains an undocumented hard topk(20) cap")
	}
	if strings.Count(flowExpression, "sum by (instance_uuid, project_uuid, project_name) (") != 2 || strings.Contains(flowExpression, "family)") {
		t.Errorf("project conntrack panel must display and rank one additive total per instance: %q", flowExpression)
	}

	for _, id := range []int{1405, 1406} {
		panel := dashboardDocumentationPanelByID(t, dashboard, id)
		expression := dashboardDocumentationPanelExpressions(panel)
		if strings.Contains(expression, "topk(20") {
			t.Errorf("panel %d retains an undocumented hard topk(20) cap", id)
		}
		if strings.Count(expression, "max by (instance_uuid, project_uuid, project_name) (") != 2 || strings.Contains(expression, "project_name, family") {
			t.Errorf("panel %d must display and rank one worst fixed-IP/family value per instance: %q", id, expression)
		}
		if !strings.Contains(panel.Description, "worst-series approximation") || !strings.Contains(panel.Description, "not an exact union") {
			t.Errorf("panel %d does not disclose its non-additive approximation: %q", id, panel.Description)
		}
	}

	for _, id := range []int{1407, 1408} {
		panel := dashboardDocumentationPanelByID(t, dashboard, id)
		for _, target := range panel.Targets {
			expression := target.Expr
			if strings.Count(expression, "sum by (project_uuid, project_name, direction) (") != 1 {
				t.Errorf("panel %d target %s should keep direction only in its displayed series: %q", id, target.LegendFormat, expression)
			}
			if strings.Count(expression, "sum by (project_uuid, project_name) (") != 1 {
				t.Errorf("panel %d target %s must rank one value per project: %q", id, target.LegendFormat, expression)
			}
		}
	}
}

func TestDashboardConntrackSourcesAndIntervalUnitsAreExplicit(t *testing.T) {
	dashboards := dashboardDocumentationLoadDashboards(t)
	cases := []struct {
		file string
		ids  []int
	}{
		{"openstack_instance_exporter_cluster.json", []int{1254}},
		{"openstack_instance_exporter_instance.json", []int{2052, 2053, 2054, 2079, 2080, 2081, 2082, 2083, 2084, 2087, 2088}},
		{"openstack_instance_exporter_project.json", []int{1404, 1405, 1406, 1407, 1408}},
	}
	for _, testCase := range cases {
		for _, id := range testCase.ids {
			panel := dashboardDocumentationPanelByID(t, dashboards[testCase.file], id)
			if !strings.Contains(panel.Description, "Linux kernel conntrack") {
				t.Errorf("%s panel %d has incorrect source: %q", testCase.file, id, panel.Description)
			}
			if strings.Contains(panel.Description, "Libvirt/QEMU") {
				t.Errorf("%s panel %d retains unrelated Libvirt source boilerplate", testCase.file, id)
			}
		}
	}

	intervalPanel := dashboardDocumentationPanelByID(t, dashboards["openstack_instance_exporter_project.json"], 1408)
	if strings.Contains(intervalPanel.Title, "Contacts Rate") ||
		!strings.Contains(intervalPanel.Title, "over $__rate_interval") ||
		!strings.Contains(intervalPanel.Description, "not a per-second rate") {
		t.Errorf("panel 1408 does not distinguish increase() interval deltas from a rate: title=%q description=%q", intervalPanel.Title, intervalPanel.Description)
	}
	for _, target := range intervalPanel.Targets {
		if !strings.Contains(target.Expr, "increase(") || strings.Contains(target.Expr, "rate(") {
			t.Errorf("panel 1408 target is not an interval delta: %q", target.Expr)
		}
	}
}

func TestDashboardConntrackProjectTotalsDiscloseEndpointAttribution(t *testing.T) {
	dashboards := dashboardDocumentationLoadDashboards(t)
	dashboard := dashboards["openstack_instance_exporter_project.json"]

	for _, id := range []int{1206, 1262, 1263} {
		panel := dashboardDocumentationPanelByID(t, dashboard, id)
		if !strings.Contains(panel.Title, "Endpoint-Attributed Flows") {
			t.Errorf("panel %d title does not identify endpoint attribution: %q", id, panel.Title)
		}
		if !strings.Contains(panel.Description, "endpoint-attributed flow count") ||
			!strings.Contains(panel.Description, "not a count of unique kernel conntrack entries") ||
			!strings.Contains(panel.Description, "one kernel entry can contribute more than once") {
			t.Errorf("panel %d does not disclose endpoint-count semantics: %q", id, panel.Description)
		}
		if !strings.Contains(panel.Description, "Linux kernel conntrack") {
			t.Errorf("panel %d does not identify its kernel conntrack source: %q", id, panel.Description)
		}
	}

	averagePanel := dashboardDocumentationPanelByID(t, dashboard, 1268)
	if !strings.Contains(averagePanel.Title, "Average Conntrack Endpoint-Attributed Flows per Active Instance") {
		t.Errorf("panel 1268 title obscures its numerator and denominator: %q", averagePanel.Title)
	}
	for _, required := range []string{
		"Average current endpoint-attributed conntrack flow count per active instance",
		"divided by its active instance count",
		"not a unique kernel-entry count",
		"not a time average",
		"Linux kernel conntrack",
	} {
		if !strings.Contains(averagePanel.Description, required) {
			t.Errorf("panel 1268 description is missing %q: %q", required, averagePanel.Description)
		}
	}
	expression := dashboardDocumentationPanelExpressions(averagePanel)
	if strings.Count(expression, "oie_instance_conntrack_ip_flows") != 2 ||
		strings.Count(expression, "oie_instance_info") != 2 ||
		strings.Count(expression, "\n/\n") != 2 {
		t.Errorf("panel 1268 no longer displays and ranks conntrack-attribution / active-instance ratios: %q", expression)
	}
}

func TestDashboardHostConntrackPanelsIdentifyKernelSource(t *testing.T) {
	dashboards := dashboardDocumentationLoadDashboards(t)
	cases := []struct {
		file string
		ids  []int
	}{
		{"openstack_instance_exporter_cluster.json", []int{1220, 1254, 1269, 20001, 20002}},
		{"openstack_instance_exporter_hypervisor.json", []int{1224, 1272}},
	}
	for _, testCase := range cases {
		for _, id := range testCase.ids {
			panel := dashboardDocumentationPanelByID(t, dashboards[testCase.file], id)
			if !strings.Contains(panel.Description, "conntrack") || !strings.Contains(panel.Description, "OIE") {
				t.Errorf("%s panel %d does not identify OIE conntrack collection: %q", testCase.file, id, panel.Description)
			}
			if strings.Contains(panel.Description, "Libvirt/QEMU") {
				t.Errorf("%s panel %d retains unrelated Libvirt source boilerplate", testCase.file, id)
			}
		}
	}
}

func TestDashboardConntrackConcentrationPanelsExposeIdentityScope(t *testing.T) {
	dashboards := dashboardDocumentationLoadDashboards(t)
	dashboard := dashboards["openstack_instance_exporter_instance.json"]

	for _, id := range []int{2082, 2088} {
		panel := dashboardDocumentationPanelByID(t, dashboard, id)
		if !strings.Contains(panel.Title, "by Fixed IP / Family") {
			t.Errorf("panel %d title does not identify fixed-IP/family scope: %q", id, panel.Title)
		}
		if !strings.Contains(panel.Description, "Each line is one fixed IP and address family") ||
			!strings.Contains(panel.Description, "non-additive") ||
			!strings.Contains(panel.Description, "not an exact instance-wide value") {
			t.Errorf("panel %d overstates concentration scope: %q", id, panel.Description)
		}
		for _, target := range panel.Targets {
			if !strings.Contains(target.LegendFormat, "{{ ip }}") || !strings.Contains(target.LegendFormat, "IPv{{ family }}") {
				t.Errorf("panel %d legend does not expose fixed IP and family: %q", id, target.LegendFormat)
			}
		}
	}
}

func TestDashboardThreatMatchSumsTolerateUnavailableLists(t *testing.T) {
	dashboards := dashboardDocumentationLoadDashboards(t)
	dashboard := dashboards["openstack_instance_exporter_instance.json"]

	for _, id := range []int{2083, 2084} {
		panel := dashboardDocumentationPanelByID(t, dashboard, id)
		expression := dashboardDocumentationPanelExpressions(panel)
		if strings.Count(expression, "label_replace(") != 10 {
			t.Errorf("panel %d must label all five available list sources in display and ranking expressions: %q", id, expression)
		}
		if strings.Count(expression, " or label_replace(") != 8 {
			t.Errorf("panel %d must union five list sources before each aggregation: %q", id, expression)
		}
		if strings.Contains(expression, " + sum by") {
			t.Errorf("panel %d uses cross-list arithmetic that disappears when one source is unavailable: %q", id, expression)
		}
		for _, source := range []string{"tor_exit", "tor_relay", "spamhaus", "emergingthreats", "customlist"} {
			if strings.Count(expression, `"threat_source","`+source+`"`)+strings.Count(expression, `"threat_source", "`+source+`"`) != 2 {
				t.Errorf("panel %d does not carry source identity %q in display and ranking expressions", id, source)
			}
		}
		if !strings.Contains(panel.Description, "not a distinct-") ||
			!strings.Contains(panel.Description, "multiple configured lists and/or directions") ||
			!strings.Contains(panel.Description, "disabled or unavailable list does not suppress") {
			t.Errorf("panel %d does not disclose sum/overlap/availability semantics: %q", id, panel.Description)
		}
	}
}

func TestDashboardClusterAttributedFlowTitleIsExplicit(t *testing.T) {
	dashboards := dashboardDocumentationLoadDashboards(t)
	panel := dashboardDocumentationPanelByID(t, dashboards["openstack_instance_exporter_cluster.json"], 1254)
	if !strings.Contains(panel.Title, "Endpoint-Attributed Flows") {
		t.Errorf("cluster panel 1254 title does not identify endpoint attribution: %q", panel.Title)
	}
	if !strings.Contains(strings.ToLower(panel.FieldConfig.Defaults.Custom.AxisLabel), "endpoint-attributed") {
		t.Errorf("cluster panel 1254 axis does not identify endpoint attribution: %q", panel.FieldConfig.Defaults.Custom.AxisLabel)
	}
}

func TestDashboardConntrackProjectRatiosDiscloseEndpointAttribution(t *testing.T) {
	dashboards := dashboardDocumentationLoadDashboards(t)
	project := dashboards["openstack_instance_exporter_project.json"]

	tests := []struct {
		id            int
		titleFragment string
		denominator   string
	}{
		{id: 1266, titleFragment: "vs Host Capacity", denominator: "oie_host_conntrack_max"},
		{id: 1267, titleFragment: "vs Observed Host Entries", denominator: "oie_host_conntrack_entries"},
	}
	for _, test := range tests {
		panel := dashboardDocumentationPanelByID(t, project, test.id)
		lowerDescription := strings.ToLower(panel.Description)
		if !strings.Contains(panel.Title, "Attributed Conntrack Endpoint Load") ||
			!strings.Contains(panel.Title, test.titleFragment) ||
			strings.Contains(panel.Title, "Share") {
			t.Errorf("panel %d overstates endpoint attribution as a share: %q", test.id, panel.Title)
		}
		for _, required := range []string{
			"linux kernel conntrack",
			"per-fixed-ip and address-family endpoint attributions",
			"east-west flow",
			"need not sum to 100%",
			"can exceed 100%",
		} {
			if !strings.Contains(lowerDescription, required) {
				t.Errorf("panel %d does not disclose endpoint-attribution limitation %q: %q", test.id, required, panel.Description)
			}
		}
		expression := dashboardDocumentationPanelExpressions(panel)
		if !strings.Contains(expression, "oie_instance_conntrack_ip_flows") || !strings.Contains(expression, test.denominator) {
			t.Errorf("panel %d ratio does not use its documented numerator and denominator: %q", test.id, expression)
		}
	}
}
