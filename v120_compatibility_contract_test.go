package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

const compatibilityV120CompatibilityGoldenPath = "testdata/compatibility-v1.2.0-compatibility-contract.golden.json"

type compatibilityCompatibilitySource struct {
	Kind   string `json:"kind"`
	Commit string `json:"commit"`
}

type compatibilityCountedFile struct {
	Path  string `json:"path"`
	Count int    `json:"count"`
}

type compatibilityMetricTypeChange struct {
	Name         string `json:"name"`
	PreviousType string `json:"previous_type"`
	CurrentType  string `json:"current_type"`
}

type compatibilityMetricHelpChange struct {
	Name         string `json:"name"`
	PreviousHelp string `json:"previous_help"`
	CurrentHelp  string `json:"current_help"`
}

type compatibilityMetricAddition struct {
	Descriptor string `json:"descriptor"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	Help       string `json:"help"`
}

type compatibilityMetricsCompatibility struct {
	LegacyNamesAndLabels compatibilityCountedFile        `json:"legacy_names_and_labels"`
	ApprovedTypeChanges  []compatibilityMetricTypeChange `json:"approved_type_changes"`
	ApprovedHelpChanges  []compatibilityMetricHelpChange `json:"approved_help_changes"`
	ApprovedAdditions    []compatibilityMetricAddition   `json:"approved_additions"`
}

type compatibilityCLICompatibility struct {
	LegacyContract compatibilityCountedFile `json:"legacy_contract"`
}

type compatibilityDefaultChange struct {
	Name     string `json:"name"`
	Previous string `json:"previous"`
	Current  string `json:"current"`
}

type compatibilityAnsibleCompatibility struct {
	LegacyPublicVariables  []string                     `json:"legacy_public_variables"`
	ApprovedAdditions      []string                     `json:"approved_additions"`
	ApprovedDefaultChanges []compatibilityDefaultChange `json:"approved_default_changes"`
}

type compatibilityGrafanaCompatibility struct {
	LegacyDashboardUIDs map[string]string `json:"legacy_dashboard_uids"`
}

type compatibilityAlertCompatibility struct {
	LegacyRules               compatibilityCountedFile `json:"legacy_rules"`
	LegacyNames               compatibilityCountedFile `json:"legacy_names"`
	ApprovedAdditions         []string                 `json:"approved_additions"`
	ApprovedExpressionChanges []string                 `json:"approved_expression_changes"`
	ApprovedAnnotationChanges []string                 `json:"approved_annotation_changes"`
}

type compatibilityV120CompatibilityContract struct {
	Source  compatibilityCompatibilitySource  `json:"source"`
	Metrics compatibilityMetricsCompatibility `json:"metrics"`
	CLI     compatibilityCLICompatibility     `json:"cli"`
	Ansible compatibilityAnsibleCompatibility `json:"ansible"`
	Grafana compatibilityGrafanaCompatibility `json:"grafana"`
	Alerts  compatibilityAlertCompatibility   `json:"alerts"`
}

type compatibilityMetricFamilyContract struct {
	Type string
	Help string
}

func compatibilityLoadV120CompatibilityContract(t *testing.T) compatibilityV120CompatibilityContract {
	t.Helper()
	data, err := os.ReadFile(compatibilityV120CompatibilityGoldenPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := dataIntegrityRejectDuplicateJSONKeys(data); err != nil {
		t.Fatalf("%s: %v", compatibilityV120CompatibilityGoldenPath, err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var contract compatibilityV120CompatibilityContract
	if err := decoder.Decode(&contract); err != nil {
		t.Fatalf("decode %s: %v", compatibilityV120CompatibilityGoldenPath, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		t.Fatalf("%s has trailing JSON content: value=%v err=%v", compatibilityV120CompatibilityGoldenPath, trailing, err)
	}
	return contract
}

func compatibilityReadContractLines(t *testing.T, contract compatibilityCountedFile) []string {
	t.Helper()
	data, err := os.ReadFile(contract.Path)
	if err != nil {
		t.Fatal(err)
	}
	trimmed := strings.TrimSpace(string(data))
	lines := []string{}
	if trimmed != "" {
		lines = strings.Split(trimmed, "\n")
	}
	if len(lines) != contract.Count {
		t.Fatalf("%s records=%d, want %d", contract.Path, len(lines), contract.Count)
	}
	return lines
}

func compatibilitySortedStrings(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}

func compatibilityAssertStringsEqual(t *testing.T, label string, got, want []string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s changed\ngot:  %v\nwant: %v", label, got, want)
	}
}

func compatibilityRuntimeCLIContract(t *testing.T) []string {
	t.Helper()
	tempDir := t.TempDir()
	contractPath := filepath.Join(tempDir, "cli-flags.contract")
	cmd := exec.Command(os.Args[0], "-test.run=^TestDataIntegrityCLIFlagContractSubprocess$")
	cmd.Env = append(os.Environ(),
		dataIntegrityFlagContractHelperEnv+"=1",
		dataIntegrityFlagContractOutputEnv+"="+contractPath,
		dataIntegrityFlagProbeConfigEnv+"="+filepath.Join(tempDir, "missing-behavior-ports.yaml"),
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("collect runtime CLI contract: %v\n%s", err, output)
	}
	data, err := os.ReadFile(contractPath)
	if err != nil {
		t.Fatal(err)
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\n")
}

func compatibilityLoadRawAlertContract(t *testing.T, path string) dataIntegrityAlertFile {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var contract dataIntegrityAlertFile
	if err := dataIntegrityDecodeSingleYAML(data, &contract, true); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return contract
}

func compatibilityAlertInventory(t *testing.T, contract dataIntegrityAlertFile) ([]string, map[string]dataIntegrityAlertRule) {
	t.Helper()
	names := make([]string, 0, 80)
	rules := make(map[string]dataIntegrityAlertRule, 80)
	for groupIndex, group := range contract.Groups {
		if group.Name == "" || group.Job == "" {
			t.Fatalf("alert group %d has an empty name or exporter job", groupIndex)
		}
		for ruleIndex, rule := range group.Rules {
			if rule.Alert == "" || rule.Expr == "" {
				t.Fatalf("alert group %q rule %d has an empty name or expression", group.Name, ruleIndex)
			}
			if _, duplicate := rules[rule.Alert]; duplicate {
				t.Fatalf("duplicate alert %q", rule.Alert)
			}
			names = append(names, rule.Alert)
			rules[rule.Alert] = rule
		}
	}
	return names, rules
}

func compatibilityAssertSourceIdentity(t *testing.T, source compatibilityCompatibilitySource) {
	t.Helper()
	want := compatibilityCompatibilitySource{
		Kind:   "development-baseline",
		Commit: "2d04a3914130cbe8e4e07ae1c71b8b4e1e012e8c",
	}
	if source != want {
		t.Fatalf("Compatibility baseline source identity=%+v, want %+v", source, want)
	}
}

func compatibilityAssertMetricCompatibility(t *testing.T, contract compatibilityMetricsCompatibility) {
	t.Helper()
	legacy := compatibilityReadContractLines(t, contract.LegacyNamesAndLabels)
	current, _ := descriptorContract(t)
	wantCurrent := append([]string(nil), legacy...)
	for _, addition := range contract.ApprovedAdditions {
		wantCurrent = append(wantCurrent, addition.Descriptor)
	}
	// Compatibility baseline's compatibility manifest remains an immutable record of the
	// v1.2.0 -> development baseline delta. v2.0.0 additions are approved separately so
	// later work cannot rewrite that historical manifest.
	wantCurrent = append(wantCurrent, goldenLines(t, dataIntegrityOIEAdditionsGoldenPath)...)
	wantCurrent = append(wantCurrent, goldenLines(t, resourceTelemetryOIEAdditionsGoldenPath)...)
	wantCurrent = append(wantCurrent, goldenLines(t, "testdata/metrics-v2.0.0-alert-validation-additions.golden")...)
	wantCurrent = append(wantCurrent, volumeRetypeMetricDescriptors...)
	wantCurrent = append(wantCurrent, inventoryMetricDescriptors...)
	sort.Strings(wantCurrent)
	compatibilityAssertStringsEqual(t, "v1.2 metric names and labels plus approved v2.0.0 additions", current, wantCurrent)

	families, _ := dataIntegrityFullRegistryFixture(t)
	actual := make(map[string]compatibilityMetricFamilyContract, len(families))
	for _, family := range families {
		if strings.HasPrefix(family.GetName(), "oie_") {
			actual[family.GetName()] = compatibilityMetricFamilyContract{
				Type: family.GetType().String(),
				Help: family.GetHelp(),
			}
		}
	}
	if len(actual) != len(current) {
		t.Fatalf("gathered OIE families=%d, descriptor families=%d", len(actual), len(current))
	}

	if len(contract.ApprovedTypeChanges) != 5 {
		t.Fatalf("approved metric type corrections=%d, want 5", len(contract.ApprovedTypeChanges))
	}
	seenTypeChanges := make(map[string]struct{}, len(contract.ApprovedTypeChanges))
	for _, change := range contract.ApprovedTypeChanges {
		if change.PreviousType != "GAUGE" || change.CurrentType != "COUNTER" {
			t.Fatalf("metric type correction for %s is %s -> %s, want GAUGE -> COUNTER", change.Name, change.PreviousType, change.CurrentType)
		}
		if _, duplicate := seenTypeChanges[change.Name]; duplicate {
			t.Fatalf("duplicate metric type correction %s", change.Name)
		}
		seenTypeChanges[change.Name] = struct{}{}
		if got := actual[change.Name].Type; got != change.CurrentType {
			t.Fatalf("metric %s type=%s, want approved %s", change.Name, got, change.CurrentType)
		}
	}

	if len(contract.ApprovedHelpChanges) != 1 {
		t.Fatalf("approved metric help corrections=%d, want 1", len(contract.ApprovedHelpChanges))
	}
	for _, change := range contract.ApprovedHelpChanges {
		if change.PreviousHelp == "" || change.CurrentHelp == "" || change.PreviousHelp == change.CurrentHelp {
			t.Fatalf("invalid help-only correction for %s: %+v", change.Name, change)
		}
		family, ok := actual[change.Name]
		if !ok {
			t.Fatalf("help-only corrected metric %s is missing", change.Name)
		}
		if family.Type != "GAUGE" || family.Help != change.CurrentHelp {
			t.Fatalf("help-only corrected metric %s type/help=%q/%q", change.Name, family.Type, family.Help)
		}
	}

	if len(contract.ApprovedAdditions) != 1 {
		t.Fatalf("approved metric additions=%d, want 1", len(contract.ApprovedAdditions))
	}
	for _, addition := range contract.ApprovedAdditions {
		family, ok := actual[addition.Name]
		if !ok {
			t.Fatalf("approved metric addition %s is missing", addition.Name)
		}
		if family.Type != addition.Type || family.Help != addition.Help {
			t.Fatalf("approved metric addition %s type/help=%q/%q, want %q/%q", addition.Name, family.Type, family.Help, addition.Type, addition.Help)
		}
	}
}

func compatibilityAssertCLICompatibility(t *testing.T, contract compatibilityCLICompatibility) {
	t.Helper()
	want := compatibilityReadContractLines(t, contract.LegacyContract)
	want = append(want, compatibilityReadNonEmptyLines(t, threatIntelligenceCLIFlagAdditionsGoldenPath)...)
	want = append(want, compatibilityReadNonEmptyLines(t, runtimeConfigurationCLIFlagAdditionsGoldenPath)...)
	want = append(want, volumeRetypeCLIFlagAddition)
	sort.Strings(want)
	got := compatibilityRuntimeCLIContract(t)
	compatibilityAssertStringsEqual(t, "v1.2 CLI names, defaults, and help plus frozen Threat intelligence/Runtime configuration additions", got, want)
}

func compatibilityAssertAnsibleCompatibility(t *testing.T, contract compatibilityAnsibleCompatibility) {
	t.Helper()
	if len(contract.LegacyPublicVariables) != 63 {
		t.Fatalf("legacy Ansible variables=%d, want 63", len(contract.LegacyPublicVariables))
	}
	if len(contract.ApprovedAdditions) != 2 {
		t.Fatalf("approved Ansible variable additions=%d, want 2", len(contract.ApprovedAdditions))
	}
	wantVariables := append([]string(nil), contract.LegacyPublicVariables...)
	wantVariables = append(wantVariables, contract.ApprovedAdditions...)
	// Threat intelligence additions are approved separately so the immutable v1.2.0 ->
	// development baseline compatibility manifest remains historical reference.
	wantVariables = append(wantVariables, goldenLines(t, threatIntelligenceAnsibleAdditionsGoldenPath)...)
	// Operational configuration supersedes the Deployment hardening deployment surface. The near-drop-in role
	// adds only explicit local/URL archive selection.
	wantVariables = append(wantVariables,
		"openstack_instance_exporter_archive_src",
		"openstack_instance_exporter_download_url",
		"openstack_instance_exporter_volume_retype_enable",
	)
	sort.Strings(wantVariables)
	role := dataIntegrityLoadAnsibleRoleContract(t)
	compatibilityAssertStringsEqual(t, "v1.2 Ansible variables plus approved additions", role.PublicVariables, wantVariables)

	if len(contract.ApprovedDefaultChanges) != 1 {
		t.Fatalf("approved Ansible default changes=%d, want 1", len(contract.ApprovedDefaultChanges))
	}
	defaults, ok := role.Defaults.(map[string]any)
	if !ok {
		t.Fatalf("Ansible defaults type=%T, want map[string]any", role.Defaults)
	}
	for _, change := range contract.ApprovedDefaultChanges {
		if change.Previous == "" || change.Current == "" || change.Previous == change.Current {
			t.Fatalf("invalid Ansible default correction: %+v", change)
		}
		if change.Name == "openstack_instance_exporter_version" || change.Name == "openstack_instance_exporter_sha256" {
			// Operational configuration owns the v2.0.0 release source defaults.
			continue
		}
		if got := fmt.Sprint(defaults[change.Name]); got != change.Current {
			t.Fatalf("Ansible default %s=%q, want approved %q", change.Name, got, change.Current)
		}
	}
}

func compatibilityAssertGrafanaCompatibility(t *testing.T, contract compatibilityGrafanaCompatibility) {
	t.Helper()
	if len(contract.LegacyDashboardUIDs) != 5 {
		t.Fatalf("legacy dashboard UIDs=%d, want 5", len(contract.LegacyDashboardUIDs))
	}
	got := make(map[string]string)
	for _, dashboard := range dataIntegrityLoadGrafanaContracts(t) {
		got[dashboard.File] = dashboard.UID
	}
	if !reflect.DeepEqual(got, contract.LegacyDashboardUIDs) {
		t.Fatalf("v1.2 dashboard identity contract changed\ngot:  %v\nwant: %v", got, contract.LegacyDashboardUIDs)
	}
}

func compatibilityAssertAlertCompatibility(t *testing.T, contract compatibilityAlertCompatibility) {
	t.Helper()
	legacyContract := compatibilityLoadRawAlertContract(t, contract.LegacyRules.Path)
	// Compare v1.2.0 to the immutable development baseline semantic golden. The live bundled
	// rules may layer separately reviewed v2.0.0 changes without rewriting this
	// historical compatibility record.
	currentContract := dataIntegrityLoadFrozenAlertContract(t)
	legacyNames, legacyRules := compatibilityAlertInventory(t, legacyContract)
	currentNames, currentRules := compatibilityAlertInventory(t, currentContract)
	if len(legacyNames) != contract.LegacyRules.Count {
		t.Fatalf("legacy alert rules=%d, want %d", len(legacyNames), contract.LegacyRules.Count)
	}
	compatibilityAssertStringsEqual(t, "v1.2 alert name golden", legacyNames, compatibilityReadContractLines(t, contract.LegacyNames))
	wantCurrentNames := append(append([]string(nil), legacyNames...), contract.ApprovedAdditions...)
	compatibilityAssertStringsEqual(t, "v1.2 alert names plus approved additions", currentNames, wantCurrentNames)

	if len(legacyContract.Groups) != len(currentContract.Groups) {
		t.Fatalf("alert group count changed from %d to %d", len(legacyContract.Groups), len(currentContract.Groups))
	}
	for index := range legacyContract.Groups {
		oldGroup := legacyContract.Groups[index]
		newGroup := currentContract.Groups[index]
		if oldGroup.Name != newGroup.Name || oldGroup.Job != newGroup.Job {
			t.Fatalf("alert group %d identity changed from %q/%q to %q/%q", index, oldGroup.Name, oldGroup.Job, newGroup.Name, newGroup.Job)
		}
	}

	expressionChanges := make([]string, 0, len(contract.ApprovedExpressionChanges))
	annotationChanges := make([]string, 0, len(contract.ApprovedAnnotationChanges))
	for _, name := range legacyNames {
		oldRule := legacyRules[name]
		newRule, exists := currentRules[name]
		if !exists {
			t.Fatalf("legacy alert %s was removed", name)
		}
		if oldRule.Expr != newRule.Expr {
			expressionChanges = append(expressionChanges, name)
		}
		if !reflect.DeepEqual(oldRule.Annotations, newRule.Annotations) {
			annotationChanges = append(annotationChanges, name)
		}
		if oldRule.For != newRule.For {
			t.Fatalf("legacy alert %s for changed from %q to %q", name, oldRule.For, newRule.For)
		}
		if !reflect.DeepEqual(oldRule.Labels, newRule.Labels) {
			t.Fatalf("legacy alert %s labels changed from %v to %v", name, oldRule.Labels, newRule.Labels)
		}
	}
	sort.Strings(expressionChanges)
	sort.Strings(annotationChanges)
	compatibilityAssertStringsEqual(t, "approved v1.2 alert expression changes", expressionChanges, compatibilitySortedStrings(contract.ApprovedExpressionChanges))
	compatibilityAssertStringsEqual(t, "approved v1.2 alert annotation changes", annotationChanges, compatibilitySortedStrings(contract.ApprovedAnnotationChanges))
	if len(expressionChanges) != 17 {
		t.Fatalf("approved alert expression changes=%d, want 17", len(expressionChanges))
	}
	if len(annotationChanges) != 4 {
		t.Fatalf("approved alert annotation changes=%d, want 4", len(annotationChanges))
	}
}

func TestCompatibilityV120CompatibilityContract(t *testing.T) {
	contract := compatibilityLoadV120CompatibilityContract(t)
	compatibilityAssertSourceIdentity(t, contract.Source)
	compatibilityAssertMetricCompatibility(t, contract.Metrics)
	compatibilityAssertCLICompatibility(t, contract.CLI)
	compatibilityAssertAnsibleCompatibility(t, contract.Ansible)
	compatibilityAssertGrafanaCompatibility(t, contract.Grafana)
	compatibilityAssertAlertCompatibility(t, contract.Alerts)
}
