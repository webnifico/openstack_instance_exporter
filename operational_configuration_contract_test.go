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

func TestOperationalConfigurationAlertReferenceMatchesShippedPolicy(t *testing.T) {
	file := loadCurrentAlertRules(t)
	policy := operationalConfigurationAlertInventory(t, file)
	helpers := 0
	for _, group := range file.Groups {
		helpers += len(group.RecordingRules)
	}
	readme := dashboardDocumentationReadFile(t, "README.md")
	if !strings.Contains(readme, "(examples/prometheus_alerts_example/openstack_instance_exporter_alerts.yml)") {
		t.Fatal("README must link the shipped alert policy")
	}
	want := fmt.Sprintf("%d enabled alerts and %d helper recording rules", len(policy), helpers)
	if !strings.Contains(readme, want) {
		t.Fatalf("README must describe the shipped policy inventory: %s", want)
	}
	// The linked policy remains the complete reference for expressions, severities and holds.
	t.Run("LinkedPolicy", TestReleaseAlertPolicySemanticContract)
}

func TestOperationalConfigurationPrometheusRulesAreNearDropInAndConcise(t *testing.T) {
	file := loadCurrentAlertRules(t)
	if len(file.Groups) != 1 || file.Groups[0].Name != "OpenStack Instance Exporter" || file.Groups[0].Job != "openstack-instance-exporter" {
		t.Fatal("existing group identity changed")
	}
	current := operationalConfigurationAlertInventory(t, file)
	if len(current) != 62 || len(file.Groups[0].RecordingRules) != 30 {
		t.Fatal("expected 62 alerts and 30 notification-only helpers")
	}
	for name, rule := range current {
		// Formatting whitespace does not count toward expression complexity.
		if len(strings.Join(strings.Fields(rule.Expr), " ")) > 900 {
			t.Errorf("%s exceeds the readable expression limit: %d characters", name, len(rule.Expr))
		}
	}
	currentNames := make([]string, 0, len(current))
	for name := range current {
		currentNames = append(currentNames, name)
	}
	sort.Strings(currentNames)
	compatibilityAssertStringsEqual(t, "release alert inventory", currentNames, compatibilityReadNonEmptyLines(t, "testdata/contracts/alerts.txt"))
	enabled, critical, informational, warning := 0, 0, 0, 0
	for _, r := range file.Groups[0].Rules {
		if r.Enabled != nil {
			t.Errorf("%s has a per-alert enable flag; all listed alerts must render", r.Alert)
		}
		enabled++
		if r.Labels["severity"] == "info" {
			informational++
		}
		if r.Labels["severity"] == "warning" {
			warning++
		}
		if r.Labels["severity"] == "critical" {
			critical++
			if !strings.HasPrefix(r.Alert, "OpenStackInstanceExporterHost") {
				t.Errorf("uncorroborated critical %s", r.Alert)
			}
		}
		if len(r.Annotations) != 2 || r.Annotations["summary"] == "" || r.Annotations["description"] == "" {
			t.Errorf("%s must provide only a summary and an actionable description", r.Alert)
		}
	}
	if enabled != 62 || informational != 19 || warning != 41 || critical != 2 {
		t.Fatalf("enabled/informational/warning/critical=%d/%d/%d/%d", enabled, informational, warning, critical)
	}
}

func TestOperationalConfigurationCorrectedMetricWording(t *testing.T) {
	current := operationalConfigurationAlertInventory(t, loadCurrentAlertRules(t))
	required := map[string]string{
		"OpenStackInstanceHighStealRate":                     "scheduler waiting",
		"OpenStackInstanceExporterHostCPUPressureSustained":  "excluding idle and I/O wait",
		"OpenStackInstanceExporterHostCPUContentionCritical": "excluding idle and I/O wait",
		"OpenStackInstanceHighBandwidthRateRX":               "History required",
		"OpenStackInstanceDiskReadLatencyHigh":               ">=60 operations",
		"OpenStackInstanceMiningSuspected":                   "does not confirm mining",
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
			`oie_host_mem_available_mib{job="openstack-instance-exporter"}`,
			`oie_host_mem_mib_total{job="openstack-instance-exporter"}`,
		},
		"OpenStackInstanceExporterLibvirtCollectionUnhealthy": {
			`oie_host_libvirt_ok{job="openstack-instance-exporter"}`,
		},
		"OpenStackInstanceExporterLibvirtDataStale": {
			`oie_host_libvirt_last_success_timestamp_seconds{job="openstack-instance-exporter"}`,
		},
		"OpenStackInstanceVolumeRetypeReadyStalled": {
			`oie_instance_disk_retype_status_code{job="openstack-instance-exporter"}`,
			`oie:libvirt_ready`,
		},
		"OpenStackInstanceVolumeRetypeObservationUnhealthy": {
			`oie_instance_disk_retype_observation_healthy{job="openstack-instance-exporter"}`,
			`oie:libvirt_ready`,
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

func TestOperationalConfigurationAnsibleRoleStaysCompact(t *testing.T) {
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

	wantVariables := compatibilityReadNonEmptyLines(t, "testdata/contracts/ansible-variables.txt")
	if got := dataIntegrityLoadAnsibleRoleContract(t).PublicVariables; !reflect.DeepEqual(got, wantVariables) {
		t.Fatalf("release Ansible variables changed\nwant: %v\ngot: %v", wantVariables, got)
	}

	roleRoot := "ansible_role/openstack_instance_exporter"
	defaults := string(readRoleFile(t, filepath.Join(roleRoot, "defaults/main.yml")))
	for _, required := range []string{
		`openstack_instance_exporter_version: "v2.0.0"`,
		`openstack_instance_exporter_local_install: false`,
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
			t.Fatalf("unsupported installation construct remains: %q", removed)
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

func TestOperationalConfigurationAnsibleReleaseChecksumAndReadmeReference(t *testing.T) {
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
	for _, reference := range []string{
		"(defaults/main.yml)", "openstack_instance_exporter_archive_src", "openstack_instance_exporter_sha256",
		"(requirements.yml)", "(templates/openstack_instance_exporter.service.j2)",
		"ansible-playbook -i inventory deploy-oie.yml", "service runs as root",
		"openstack_instance_exporter_enabled: true", "openstack_instance_exporter_web_listen_address:",
		"openstack_instance_exporter_log_file_enable: true",
	} {
		if !strings.Contains(readme, reference) {
			t.Fatalf("%s omits release-installation reference %q", readmePath, reference)
		}
	}
	wantChecksumExample := `openstack_instance_exporter_sha256: "` + fields[0] + `"`
	if strings.Count(defaults, wantChecksumExample) != 1 {
		t.Fatalf("%s must pin the bundled archive checksum: %q", defaultsPath, wantChecksumExample)
	}

}

func TestOperationalConfigurationGrafanaPanelCountAndScopeControls(t *testing.T) {
	dashboards := dashboardDocumentationLoadDashboards(t)
	for name, d := range dashboards {
		panels := dashboardDocumentationFlattenPanels(d.Panels)
		// Keep dashboard panel counts within the defined limits.
		limit := 81
		if name == "openstack_instance_exporter_cluster.json" {
			limit = 89
		} else if name == "openstack_instance_exporter_instance.json" {
			limit = 88
		}
		if len(panels) > limit {
			t.Errorf("%s dashboard exceeds its panel-count limit", name)
		}
		if dashboardDocumentationPanelByID(t, d, 25000).Type != "text" {
			t.Error("current scope and reset must be visible")
		}
	}
}
