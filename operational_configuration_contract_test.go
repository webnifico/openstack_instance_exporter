package main

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

const operationalConfigurationReleaseDownloadURL = "https://github.com/webnifico/openstack_instance_exporter/releases/download/{{ openstack_instance_exporter_version }}/openstack_instance_exporter-{{ openstack_instance_exporter_version }}-linux-{{ openstack_instance_exporter_architecture }}.tar.xz"

func operationalConfigurationAlertInventory(t *testing.T, file alertRulesFile) map[string]struct {
	Expr        string
	For         string
	Labels      map[string]string
	Annotations map[string]string
} {
	t.Helper()
	inventory := make(map[string]struct {
		Expr        string
		For         string
		Labels      map[string]string
		Annotations map[string]string
	})
	for _, group := range file.Groups {
		for _, rule := range group.Rules {
			if rule.Alert == "" || rule.Expr == "" {
				t.Fatalf("alert group %q contains an unnamed or empty rule", group.Name)
			}
			if _, duplicate := inventory[rule.Alert]; duplicate {
				t.Fatalf("duplicate alert name %q", rule.Alert)
			}
			inventory[rule.Alert] = struct {
				Expr        string
				For         string
				Labels      map[string]string
				Annotations map[string]string
			}{
				Expr:        normalizedAlertExpression(rule.Expr),
				For:         rule.For,
				Labels:      rule.Labels,
				Annotations: rule.Annotations,
			}
		}
	}
	return inventory
}

func TestOperationalConfigurationPrometheusRulesAreNearDropInAndConcise(t *testing.T) {
	file := loadCurrentAlertRules(t)
	if len(file.Groups) != 1 || file.Groups[0].Name != "OpenStack Instance Exporter" || file.Groups[0].Job != "openstack-instance-exporter" {
		t.Fatal("existing group identity changed")
	}
	current := operationalConfigurationAlertInventory(t, file)
	if len(current) != 82 || len(file.Groups[0].RecordingRules) != 10 {
		t.Fatal("expected 80 retained alert names, two corroborated host criticals and ten shared recording rules")
	}
	for _, g := range dataIntegrityLoadFrozenAlertContract(t).Groups {
		for _, r := range g.Rules {
			if _, ok := current[r.Alert]; !ok {
				t.Errorf("removed baseline alert %s", r.Alert)
			}
		}
	}
	enabled, critical, optional := 0, 0, 0
	for _, r := range file.Groups[0].Rules {
		if r.Enabled != nil && !*r.Enabled {
			optional++
			if r.Labels["severity"] != "info" {
				t.Error("optional workload diagnostics must be informational")
			}
			continue
		}
		enabled++
		if r.Labels["severity"] == "critical" {
			critical++
			if !strings.HasPrefix(r.Alert, "OpenStackInstanceExporterHost") {
				t.Errorf("uncorroborated critical %s", r.Alert)
			}
		}
		if !strings.Contains(r.Annotations["dashboard_path"], "&from=") {
			t.Errorf("%s lacks incident time link", r.Alert)
		}
	}
	if enabled != 33 || optional != 49 || critical != 2 {
		t.Fatalf("enabled/optional/critical=%d/%d/%d", enabled, optional, critical)
	}
}

func TestOperationalConfigurationCorrectedMetricWording(t *testing.T) {
	current := operationalConfigurationAlertInventory(t, loadCurrentAlertRules(t))
	required := map[string]string{
		"OpenStackInstanceHighStealRate":                     "scheduler-delay evidence",
		"OpenStackInstanceExporterHostCPUPressureSustained":  "excluding idle and I/O wait",
		"OpenStackInstanceExporterHostCPUContentionCritical": "excluding idle and I/O wait",
		"OpenStackInstanceHighBandwidthRateRX":               "Optional workload diagnostic",
		"OpenStackInstanceDiskReadLatencyHigh":               "at least 60 measured operations",
		"OpenStackInstanceMiningSuspected":                   "not proof of mining",
		"OpenStackInstanceHighMemorySwapInRate":              "five minutes",
	}
	for name, phrase := range required {
		if !strings.Contains(current[name].Annotations["description"], phrase) {
			t.Errorf("%s missing %s", name, phrase)
		}
	}
}

func TestOperationalConfigurationV2AlertsPinDirectSelectorsToExporterJob(t *testing.T) {
	current := operationalConfigurationAlertInventory(t, loadCurrentAlertRules(t))
	required := map[string][]string{
		"OpenStackInstanceExporterUnavailable": {
			`up{job="openstack-instance-exporter"}`,
		},
		"OpenStackInstanceExporterCollectionCycleNearInterval": {
			`oie_host_collection_cycle_duration_seconds{job="openstack-instance-exporter"}`,
			`oie_host_collection_interval_seconds{job="openstack-instance-exporter"}`,
		},
		"OpenStackInstanceExporterHostCPUPressureSustained": {
			`oie_host_cpu_usage_percent{job="openstack-instance-exporter"}`,
		},
		"OpenStackInstanceExporterHostMemoryPressureSustained": {
			`oie_host_mem_available_mb{job="openstack-instance-exporter"}`,
			`oie_host_mem_mb_total{job="openstack-instance-exporter"}`,
		},
		"OpenStackInstanceExporterLibvirtCollectionUnhealthy": {
			`oie_host_libvirt_ok{job="openstack-instance-exporter"}`,
		},
		"OpenStackInstanceExporterLibvirtDataStale": {
			`oie_host_libvirt_stale_seconds{job="openstack-instance-exporter"}`,
		},
		"OpenStackInstanceVolumeRetypeReadyStalled": {
			`oie_instance_disk_retype_status_code{job="openstack-instance-exporter"}`,
			`oie_host_libvirt_ok{job="openstack-instance-exporter"}`,
		},
		"OpenStackInstanceVolumeRetypeObservationUnhealthy": {
			`oie_instance_disk_retype_observation_healthy{job="openstack-instance-exporter"}`,
			`oie_instance_disk_retype_status_code{job="openstack-instance-exporter"}`,
			`oie_host_libvirt_ok{job="openstack-instance-exporter"}`,
		},
		"OpenStackInstanceExporterTorRelayListRefreshStale": {
			`oie_host_threat_feed_fresh{job="openstack-instance-exporter",list="TORRELAY"}`,
		},
	}
	for alert, selectors := range required {
		rule, ok := current[alert]
		if !ok {
			t.Fatalf("v2 alert %q is missing", alert)
		}
		for _, selector := range selectors {
			if !strings.Contains(rule.Expr, selector) {
				t.Errorf("v2 alert %q does not isolate selector %q to the exporter job: %s", alert, selector, rule.Expr)
			}
		}
	}
}

func TestOperationalConfigurationProjectHotCountsDistinctInstancesWithPromtool(t *testing.T) {
	const alertName = "OpenStackProjectManyHotInstances"
	current := operationalConfigurationAlertInventory(t, loadCurrentAlertRules(t))
	rule, ok := current[alertName]
	if !ok {
		t.Fatalf("%s is missing", alertName)
	}
	if !strings.Contains(rule.Expr, "max by (instance_uuid, project_uuid, project_name)") {
		t.Fatal("project counts must deduplicate UUIDs after target-local health gating")
	}
	series := func(unique int, duplicate bool) []alertValidationPromtoolInputSeries {
		out := make([]alertValidationPromtoolInputSeries, 0, unique+1)
		for index := 0; index < unique; index++ {
			labels := map[string]string{
				"domain":        fmt.Sprintf("instance-%08d", index),
				"instance":      "compute-a:9120",
				"instance_uuid": fmt.Sprintf("00000000-0000-0000-0000-%012d", index),
				"job":           "openstack-instance-exporter",
				"project_name":  "project-a",
				"project_uuid":  "project-uuid-a",
				"user_uuid":     "user-a",
			}
			out = append(out, alertValidationPromtoolInputSeries{
				Series: alertValidationSeries("oie_instance_attention_severity", labels),
				Values: alertValidationValues(12, func(int) float64 { return 70 }),
			})
		}
		if duplicate && len(out) > 0 {
			labels := map[string]string{
				"domain":             "instance-00000000",
				"instance":           "compute-b:9120",
				"instance_uuid":      "00000000-0000-0000-0000-000000000000",
				"job":                "openstack-instance-exporter",
				"project_name":       "project-a",
				"project_uuid":       "project-uuid-a",
				"prometheus_replica": "replica-b",
				"user_uuid":          "user-a",
			}
			out = append(out, alertValidationPromtoolInputSeries{
				Series: alertValidationSeries("oie_instance_attention_severity", labels),
				Values: alertValidationValues(12, func(int) float64 { return 70 }),
			})
		}
		for _, metric := range []string{"oie:instance_running", "oie:resource_current", "oie:libvirt_ready_5m", "oie:conntrack_ready_5m", "oie:feeds_ready"} {
			for _, instance := range []string{"compute-a:9120", "compute-b:9120"} {
				for index := 0; index < unique; index++ {
					out = append(out, alertValidationPromtoolInputSeries{Series: alertValidationSeries(metric, map[string]string{"job": "openstack-instance-exporter", "instance": instance, "instance_uuid": fmt.Sprintf("00000000-0000-0000-0000-%012d", index)}), Values: "1x12"})
				}
			}
		}
		return out
	}

	alertRule := alertValidationPromtoolRule{Alert: alertName, Expr: rule.Expr, For: rule.For, Labels: rule.Labels}
	expected := map[string]string{"project_name": "project-a", "project_uuid": "project-uuid-a", "severity": "info"}
	alertValidationRunPromtoolRules(t, "distinct project hot instances", []alertValidationPromtoolRule{alertRule}, []alertValidationPromtoolTestGroup{
		{
			Name:          "duplicate migration series does not become a tenth instance",
			Interval:      "1m",
			InputSeries:   series(9, true),
			AlertRuleTest: []alertValidationPromtoolAlertTest{{EvalTime: "10m", Alert: alertName}},
		},
		{
			Name:        "ten distinct instances fire",
			Interval:    "1m",
			InputSeries: series(10, true),
			AlertRuleTest: []alertValidationPromtoolAlertTest{{
				EvalTime: "10m", Alert: alertName,
				Expected: []alertValidationPromtoolExpectedAlert{{Labels: expected}},
			}},
		},
	})
}

func operationalConfigurationLineCount(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		return 0
	}
	lines := strings.Count(string(data), "\n")
	if data[len(data)-1] != '\n' {
		lines++
	}
	return lines
}

func TestOperationalConfigurationAnsibleRoleIsNearDropInAndLabFirst(t *testing.T) {
	lineBudgets := map[string]int{
		"ansible_role/openstack_instance_exporter/defaults/main.yml":                                310,
		"ansible_role/openstack_instance_exporter/handlers/main.yml":                                10,
		"ansible_role/openstack_instance_exporter/tasks/main.yml":                                   320,
		"ansible_role/openstack_instance_exporter/templates/openstack_instance_exporter.service.j2": 300,
		"ansible_role/openstack_instance_exporter/tests/preflight.yml":                              114, // Third invalid-configuration case: retype opt-in.
		"ansible_role/openstack_instance_exporter/tests/render_test.py":                             320, // Includes default download and local archive precedence.
	}
	for path, maximum := range lineBudgets {
		if got := operationalConfigurationLineCount(t, path); got > maximum {
			t.Fatalf("%s lines=%d, simplicity budget=%d", path, got, maximum)
		}
	}

	var baseline dataIntegrityAnsibleRoleContract
	baselineBytes, err := os.ReadFile(dataIntegrityAnsibleGoldenPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := dataIntegrityDecodeSingleJSON(baselineBytes, &baseline); err != nil {
		t.Fatal(err)
	}
	wantVariables := append([]string(nil), baseline.PublicVariables...)
	wantVariables = append(wantVariables,
		"openstack_instance_exporter_archive_src",
		"openstack_instance_exporter_download_url",
		"openstack_instance_exporter_volume_retype_enable",
		"openstack_instance_exporter_threat_ewma_tau",
	)
	sort.Strings(wantVariables)
	if got := dataIntegrityLoadAnsibleRoleContract(t).PublicVariables; !reflect.DeepEqual(got, wantVariables) {
		t.Fatalf("Operational configuration Ansible variables are not the baseline surface plus the reviewed additions\nwant: %v\ngot:  %v", wantVariables, got)
	}

	roleRoot := "ansible_role/openstack_instance_exporter"
	defaults := string(readRoleFile(t, filepath.Join(roleRoot, "defaults/main.yml")))
	for _, required := range []string{
		`openstack_instance_exporter_version: "v2.0.0"`,
		`openstack_instance_exporter_archive_src: ""`,
		`openstack_instance_exporter_download_url: "` + operationalConfigurationReleaseDownloadURL + `"`,
	} {
		if !strings.Contains(defaults, required) {
			t.Fatalf("role defaults missing %q", required)
		}
	}

	tasks := string(readRoleFile(t, filepath.Join(roleRoot, "tasks/main.yml")))
	for _, required := range []string{
		"Copy the local openstack_instance_exporter tarball",
		"Download the configured openstack_instance_exporter tarball",
		"Validate openstack_instance_exporter release settings",
		"(openstack_instance_exporter_archive_src | length > 0) or (openstack_instance_exporter_download_url | length > 0)",
		"openstack_instance_exporter_archive_src | length == 0",
		"openstack_instance_exporter_sha256 is match('^[0-9a-fA-F]{64}$')",
		"(oie_tar_stat.stat.checksum | lower) == (openstack_instance_exporter_sha256 | lower)",
	} {
		if !strings.Contains(tasks, required) {
			t.Fatalf("release source contract is missing %q", required)
		}
	}
	for _, removed := range []string{
		"Validate safe openstack_instance_exporter installation paths",
		"Reject directory-valued openstack_instance_exporter",
		"oie_unmanaged_install_entries",
	} {
		if strings.Contains(tasks, removed) {
			t.Fatalf("superseded Ansible bloat remains: %q", removed)
		}
	}

	template := string(readRoleFile(t, filepath.Join(roleRoot, "templates/openstack_instance_exporter.service.j2")))
	for _, required := range []string{"Type=simple", "User=root", "Group=root", "NoNewPrivileges=true", "PrivateTmp=true", "ProtectHome=true"} {
		if strings.Count(template, required) != 1 {
			t.Fatalf("near-drop-in unit directive %q count=%d, want 1", required, strings.Count(template, required))
		}
	}
	for _, removed := range []string{
		"openstack_instance_exporter_user",
		"openstack_instance_exporter_group",
		"CapabilityBoundingSet=",
		"AmbientCapabilities=",
		"ProtectSystem=strict",
	} {
		if strings.Contains(template, removed) {
			t.Fatalf("superseded Deployment hardening unit surface %q remains", removed)
		}
	}
}

func TestOperationalConfigurationAnsibleReadmeUsesBundledReleaseChecksum(t *testing.T) {
	const (
		defaultsPath = "ansible_role/openstack_instance_exporter/defaults/main.yml"
		readmePath   = "ansible_role/openstack_instance_exporter/README.md"
		manifestPath = "testdata/release-archive.sha256"
	)

	defaults := string(readRoleFile(t, defaultsPath))
	version := ""
	for _, line := range strings.Split(defaults, "\n") {
		const prefix = "openstack_instance_exporter_version:"
		if strings.HasPrefix(line, prefix) {
			version = strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, prefix)), `"`)
			break
		}
	}
	if version == "" {
		t.Fatalf("%s does not declare openstack_instance_exporter_version", defaultsPath)
	}

	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(manifestBytes), "\n") {
		t.Fatalf("%s checksum record is not newline-terminated", manifestPath)
	}
	manifest := strings.TrimSuffix(string(manifestBytes), "\n")
	if manifest == "" || strings.Contains(manifest, "\n") {
		t.Fatalf("%s must contain exactly one newline-terminated checksum record", manifestPath)
	}
	fields := strings.Fields(manifest)
	if len(fields) != 2 || len(fields[0]) != 64 || strings.Trim(fields[0], "0123456789abcdef") != "" {
		t.Fatalf("%s contains an invalid checksum record %q", manifestPath, manifest)
	}
	wantArchive := "openstack_instance_exporter-" + version + "-linux-amd64.tar.xz"
	if fields[1] != wantArchive {
		t.Fatalf("%s archive=%q, want current role version archive %q", manifestPath, fields[1], wantArchive)
	}

	readme := string(readRoleFile(t, readmePath))
	wantArchiveExample := `openstack_instance_exporter_archive_src: "/path/on/ansible/controller/` + wantArchive + `"`
	if strings.Count(readme, wantArchiveExample) != 1 {
		t.Fatalf("%s must contain exactly one current archive example %q", readmePath, wantArchiveExample)
	}
	wantChecksumExample := `openstack_instance_exporter_sha256: "` + fields[0] + `"`
	if strings.Count(defaults, wantChecksumExample) != 1 {
		t.Fatalf("%s must pin the bundled archive checksum: %q", defaultsPath, wantChecksumExample)
	}
	if strings.Count(readme, wantChecksumExample) != 1 {
		t.Fatalf("%s must contain exactly one checksum example matching %s: %q", readmePath, manifestPath, wantChecksumExample)
	}
}

func TestOperationalConfigurationGrafanaAuditKeptOnlyModestAdditions(t *testing.T) {
	dashboards := dashboardDocumentationLoadDashboards(t)
	for name, d := range dashboards {
		panels := dashboardDocumentationFlattenPanels(d.Panels)
		if len(panels) > 80 {
			t.Errorf("%s dashboard grew beyond the reviewed scope", name)
		}
		if dashboardDocumentationPanelByID(t, d, 25000).Type != "text" {
			t.Error("current scope and reset must be visible")
		}
	}
}
