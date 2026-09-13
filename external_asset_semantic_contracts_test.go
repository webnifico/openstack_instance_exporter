package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	dataIntegrityAlertGoldenPath                  = "testdata/data-integrity-prometheus-alert-contract-baseline.golden.json"
	dataIntegrityAlertGateGoldenPath              = "testdata/data-integrity-prometheus-alert-source-health-gates-v2.0.0.golden"
	dataIntegrityAlertRangeGateGoldenPath         = "testdata/data-integrity-prometheus-alert-source-health-range-gates-v2.0.0.golden"
	dataIntegrityAlertExpressionGoldenPath        = "testdata/data-integrity-prometheus-alert-expression-sha256-v2.0.0-data-integrity.golden"
	resourceTelemetryAlertExpressionGoldenPath    = "testdata/resource-telemetry-prometheus-alert-expression-sha256-v2.0.0-resource-telemetry.golden"
	behaviorMiningAlertExpressionGoldenPath       = "testdata/behavior-mining-prometheus-alert-expression-sha256-v2.0.0-behavior-mining.golden"
	dataIntegrityGrafanaGoldenPath                = "testdata/data-integrity-grafana-dashboard-contract-baseline.golden.json"
	dashboardDocumentationGrafanaGoldenPath       = "testdata/dashboard-documentation-grafana-dashboard-contract-v2.0.0.json"
	dashboardAccuracyGrafanaGoldenPath            = "testdata/dashboard-accuracy-grafana-contract-v2.0.0.json"
	dataIntegrityAnsibleGoldenPath                = "testdata/data-integrity-ansible-role-contract-baseline.golden.json"
	dataIntegrityAnsibleRenderGoldenPath          = "testdata/data-integrity-ansible-rendered-service-contract-baseline.golden.json"
	threatIntelligenceAnsibleAdditionsGoldenPath  = "testdata/ansible-vars-v2.0.0-threat-intelligence-additions.golden"
	deploymentHardeningAnsibleAdditionsGoldenPath = "testdata/ansible-vars-v2.0.0-deployment-hardening-additions.golden"
)

func dataIntegrityCompareGolden(t *testing.T, path string, value any) {
	t.Helper()
	got, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatalf("marshal semantic contract: %v", err)
	}
	got = append(got, '\n')
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("semantic external-asset contract changed: %s\nwant:\n%s\ngot:\n%s", path, want, got)
	}
}

type dataIntegrityAlertFile struct {
	Groups []dataIntegrityAlertGroup `yaml:"prometheus_alert_rules"`
}

type dataIntegrityAlertGroup struct {
	Name  string                   `yaml:"group_name" json:"name"`
	Job   string                   `yaml:"group_exporter_job" json:"exporter_job"`
	Rules []dataIntegrityAlertRule `yaml:"group_rules" json:"rules"`
}

type dataIntegrityAlertRule struct {
	Alert       string            `yaml:"alert" json:"alert"`
	Expr        string            `yaml:"expr" json:"expr"`
	For         string            `yaml:"for" json:"for,omitempty"`
	Labels      map[string]string `yaml:"labels" json:"labels"`
	Annotations map[string]string `yaml:"annotations" json:"annotations"`
}

func dataIntegrityDecodeSingleYAML(data []byte, value any, knownFields bool) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(knownFields)
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err != nil {
			return fmt.Errorf("decode trailing YAML content: %w", err)
		}
		return fmt.Errorf("multiple YAML documents are not allowed")
	}
	return nil
}

func dataIntegrityDecodeSingleJSON(data []byte, value any) error {
	if err := dataIntegrityRejectDuplicateJSONKeys(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err != nil {
			return fmt.Errorf("decode trailing JSON content: %w", err)
		}
		return fmt.Errorf("multiple JSON values are not allowed")
	}
	return nil
}

func dataIntegrityRejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var walkValue func() error
	walkValue = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return fmt.Errorf("JSON object key has type %T", keyToken)
				}
				if _, duplicate := seen[key]; duplicate {
					return fmt.Errorf("duplicate JSON object key %q", key)
				}
				seen[key] = struct{}{}
				if err := walkValue(); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil {
				return err
			}
			if end != json.Delim('}') {
				return fmt.Errorf("JSON object ended with %v", end)
			}
		case '[':
			for decoder.More() {
				if err := walkValue(); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil {
				return err
			}
			if end != json.Delim(']') {
				return fmt.Errorf("JSON array ended with %v", end)
			}
		default:
			return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
		}
		return nil
	}
	if err := walkValue(); err != nil {
		return err
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return fmt.Errorf("decode trailing JSON token: %w", err)
		}
		return fmt.Errorf("multiple JSON values are not allowed; trailing token %v", token)
	}
	return nil
}

func dataIntegrityLoadAlertContract(t *testing.T) dataIntegrityAlertFile {
	t.Helper()
	// Operational configuration deliberately replaced the overgrown live rule pack with the
	// concise baseline-compatible layout. Compatibility tests continue to exercise
	// their immutable Prometheus alert validation semantic fixture instead of constraining the live
	// operational example forever.
	path := alertValidationAlertContractGoldenPath
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var contract dataIntegrityAlertFile
	if err := dataIntegrityDecodeSingleJSON(b, &contract); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	seen := make(map[string]struct{})
	for groupIndex := range contract.Groups {
		group := &contract.Groups[groupIndex]
		if group.Name == "" || group.Job == "" {
			t.Fatalf("alert group %d has an empty name or exporter job", groupIndex)
		}
		for ruleIndex := range group.Rules {
			rule := &group.Rules[ruleIndex]
			if rule.Alert == "" || rule.Expr == "" {
				t.Fatalf("alert group %q rule %d has an empty name or expression", group.Name, ruleIndex)
			}
			if _, duplicate := seen[rule.Alert]; duplicate {
				t.Fatalf("duplicate alert name %q", rule.Alert)
			}
			seen[rule.Alert] = struct{}{}
			rule.Expr = normalizedAlertExpression(rule.Expr)
		}
	}
	return contract
}

func dataIntegrityLoadFrozenAlertContract(t *testing.T) dataIntegrityAlertFile {
	t.Helper()
	b, err := os.ReadFile(dataIntegrityAlertGoldenPath)
	if err != nil {
		t.Fatal(err)
	}
	var contract dataIntegrityAlertFile
	if err := dataIntegrityDecodeSingleJSON(b, &contract); err != nil {
		t.Fatalf("%s: %v", dataIntegrityAlertGoldenPath, err)
	}
	return contract
}

type dataIntegrityAlertGateSources struct {
	Libvirt   bool
	Conntrack bool
}

func dataIntegrityLoadAlertGateContract(t *testing.T) map[string]dataIntegrityAlertGateSources {
	t.Helper()
	b, err := os.ReadFile(dataIntegrityAlertGateGoldenPath)
	if err != nil {
		t.Fatal(err)
	}
	gates := make(map[string]dataIntegrityAlertGateSources)
	for lineNumber, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		name, sources, ok := strings.Cut(line, "|")
		if !ok || name == "" {
			t.Fatalf("%s:%d: invalid gate contract line %q", dataIntegrityAlertGateGoldenPath, lineNumber+1, line)
		}
		if _, duplicate := gates[name]; duplicate {
			t.Fatalf("%s:%d: duplicate alert %q", dataIntegrityAlertGateGoldenPath, lineNumber+1, name)
		}
		switch sources {
		case "libvirt":
			gates[name] = dataIntegrityAlertGateSources{Libvirt: true}
		case "conntrack":
			gates[name] = dataIntegrityAlertGateSources{Conntrack: true}
		case "libvirt,conntrack":
			gates[name] = dataIntegrityAlertGateSources{Libvirt: true, Conntrack: true}
		default:
			t.Fatalf("%s:%d: invalid sources %q", dataIntegrityAlertGateGoldenPath, lineNumber+1, sources)
		}
	}
	if len(gates) != 62 {
		t.Fatalf("Data integrity source-health gated alerts=%d, want 62", len(gates))
	}
	return gates
}

type dataIntegrityAlertRangeGate struct {
	Window string
	Legs   int
}

func dataIntegrityLoadAlertRangeGateContract(t *testing.T) map[string]dataIntegrityAlertRangeGate {
	t.Helper()
	b, err := os.ReadFile(dataIntegrityAlertRangeGateGoldenPath)
	if err != nil {
		t.Fatal(err)
	}
	gates := make(map[string]dataIntegrityAlertRangeGate)
	for lineNumber, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		fields := strings.Split(line, "|")
		if len(fields) != 3 || fields[0] == "" || !regexp.MustCompile(`^[1-9][0-9]*[smhdwy]$`).MatchString(fields[1]) {
			t.Fatalf("%s:%d: invalid range-gate contract line %q", dataIntegrityAlertRangeGateGoldenPath, lineNumber+1, line)
		}
		legs, err := strconv.Atoi(fields[2])
		if err != nil || legs < 1 {
			t.Fatalf("%s:%d: invalid range-gate leg count %q", dataIntegrityAlertRangeGateGoldenPath, lineNumber+1, fields[2])
		}
		if _, duplicate := gates[fields[0]]; duplicate {
			t.Fatalf("%s:%d: duplicate alert %q", dataIntegrityAlertRangeGateGoldenPath, lineNumber+1, fields[0])
		}
		gates[fields[0]] = dataIntegrityAlertRangeGate{Window: fields[1], Legs: legs}
	}
	if len(gates) != 30 {
		t.Fatalf("Data integrity continuous source-health gated alerts=%d, want 30", len(gates))
	}
	return gates
}

const (
	dataIntegrityLibvirtAlertGate       = `and on (instance, job) (oie_host_libvirt_ok{job="openstack-instance-exporter"} == 1)`
	dataIntegrityConntrackAlertGate     = `and on (instance, job) (oie_host_conntrack_raw_ok{job="openstack-instance-exporter"} == 1)`
	resourceTelemetryResourceAxisLabels = `domain, instance_uuid, project_uuid, user_uuid, instance, job`
)

var dataIntegrityRangeAlertGateRE = regexp.MustCompile(`and on \(instance, job\) \(min_over_time\(oie_host_(libvirt_ok|conntrack_raw_ok)\{job="openstack-instance-exporter"\}\[[1-9][0-9]*[smhdwy]\]\) == 1\)`)

func dataIntegrityRangeAlertGate(metric, window string) string {
	return fmt.Sprintf(`and on (instance, job) (min_over_time(%s{job="openstack-instance-exporter"}[%s]) == 1)`, metric, window)
}

func resourceTelemetryResourceAxisFreshGate(axis string) string {
	return fmt.Sprintf(`and on (%s) (oie_instance_resource_axis_fresh{axis=%q} == 1)`, resourceTelemetryResourceAxisLabels, axis)
}

func resourceTelemetryAllAvailableResourceAxesFreshGate() string {
	return fmt.Sprintf(
		`and on (%[1]s) ((sum by (%[1]s) (oie_instance_resource_axis_fresh) == sum by (%[1]s) (oie_instance_resource_axis_available)) and on (%[1]s) (sum by (%[1]s) (oie_instance_resource_axis_available) > 0))`,
		resourceTelemetryResourceAxisLabels,
	)
}

func behaviorMiningMiningCPUCurrentFreshGate() string {
	return fmt.Sprintf("and on (%[1]s) max by (%[1]s) (oie_instance_resource_axis_fresh{axis=%q} == 1)", resourceTelemetryResourceAxisLabels, "cpu")
}

func behaviorMiningMiningCPUFreshRangeGate() string {
	return fmt.Sprintf("and on (%[1]s) max by (%[1]s) (min_over_time(oie_instance_resource_axis_fresh{axis=%q}[5m]) == 1)", resourceTelemetryResourceAxisLabels, "cpu")
}

func behaviorMiningMiningCPUCollectionProgressGate() string {
	return fmt.Sprintf("and on (%[1]s) max by (%[1]s) (changes(oie_instance_resource_axis_last_success_timestamp_seconds{axis=%q}[5m]) >= 2)", resourceTelemetryResourceAxisLabels, "cpu")
}

func behaviorMiningExpressionWithoutMiningCPUFreshnessGates(expression string) string {
	for _, gate := range []string{
		behaviorMiningMiningCPUCurrentFreshGate(),
		behaviorMiningMiningCPUFreshRangeGate(),
		behaviorMiningMiningCPUCollectionProgressGate(),
	} {
		expression = strings.ReplaceAll(expression, gate, "")
	}
	return strings.Join(strings.Fields(expression), " ")
}

func resourceTelemetryExpressionWithoutResourceFreshnessGates(expression string) string {
	expression = behaviorMiningExpressionWithoutMiningCPUFreshnessGates(expression)
	for _, axis := range []string{"cpu", "mem", "disk", "net"} {
		expression = strings.ReplaceAll(expression, resourceTelemetryResourceAxisFreshGate(axis), "")
	}
	expression = strings.ReplaceAll(expression, resourceTelemetryAllAvailableResourceAxesFreshGate(), "")
	return strings.Join(strings.Fields(expression), " ")
}

func dataIntegrityExpressionWithoutSourceHealthGates(expression string) string {
	expression = resourceTelemetryExpressionWithoutResourceFreshnessGates(expression)
	expression = dataIntegrityRangeAlertGateRE.ReplaceAllString(expression, "")
	expression = strings.ReplaceAll(expression, dataIntegrityLibvirtAlertGate, "")
	expression = strings.ReplaceAll(expression, dataIntegrityConntrackAlertGate, "")
	expression = strings.Join(strings.Fields(expression), " ")
	expression = strings.ReplaceAll(expression, "( ", "(")
	expression = strings.ReplaceAll(expression, " )", ")")
	return expression
}

func dataIntegrityExpressionNonHealthMetrics(expression string) []string {
	expression = behaviorMiningExpressionWithoutMiningCPUFreshnessGates(expression)
	metrics := oieMetricRE.FindAllString(expression, -1)
	filtered := make([]string, 0, len(metrics))
	for _, metric := range metrics {
		if metric == "oie_host_libvirt_ok" || metric == "oie_host_conntrack_raw_ok" {
			continue
		}
		filtered = append(filtered, metric)
	}
	return filtered
}

func dataIntegrityAlertRulesByName(t *testing.T, contract dataIntegrityAlertFile) map[string]dataIntegrityAlertRule {
	t.Helper()
	rules := make(map[string]dataIntegrityAlertRule)
	for _, group := range contract.Groups {
		for _, rule := range group.Rules {
			if _, duplicate := rules[rule.Alert]; duplicate {
				t.Fatalf("duplicate alert name %q", rule.Alert)
			}
			rules[rule.Alert] = rule
		}
	}
	return rules
}

func dataIntegrityPriorAlertRulesInFrozenOrder(t *testing.T, current dataIntegrityAlertFile) []dataIntegrityAlertRule {
	t.Helper()
	currentByName := dataIntegrityAlertRulesByName(t, current)
	frozen := dataIntegrityLoadFrozenAlertContract(t)
	rules := make([]dataIntegrityAlertRule, 0, len(currentByName))
	for _, group := range frozen.Groups {
		for _, prior := range group.Rules {
			currentRule, ok := currentByName[prior.Alert]
			if !ok {
				t.Fatalf("frozen alert %q is missing", prior.Alert)
			}
			rules = append(rules, currentRule)
		}
	}
	return rules
}

func TestDataIntegrityPrometheusAlertSemanticContract(t *testing.T) {
	current := dataIntegrityLoadAlertContract(t)
	frozen := dataIntegrityLoadFrozenAlertContract(t)
	gates := dataIntegrityLoadAlertGateContract(t)
	rangeGates := dataIntegrityLoadAlertRangeGateContract(t)
	currentByName := dataIntegrityAlertRulesByName(t, current)
	seenGates := make(map[string]struct{}, len(gates))
	seenRangeGates := make(map[string]struct{}, len(rangeGates))
	for _, wantGroup := range frozen.Groups {
		for ruleIndex := range wantGroup.Rules {
			want := wantGroup.Rules[ruleIndex]
			got, ok := currentByName[want.Alert]
			if !ok {
				t.Fatalf("frozen alert %q is missing", want.Alert)
			}
			historicalLabels := make(map[string]string, len(got.Labels))
			for name, value := range got.Labels {
				if name != "policy" || value != "environment-tuned" {
					historicalLabels[name] = value
				}
			}
			historicalFor := alertValidationReviewedHistoricalDuration(got.Alert, got.For)
			if historicalFor != want.For || !reflect.DeepEqual(historicalLabels, want.Labels) {
				t.Fatalf("alert %q changed its frozen duration or labels\ngot:  %#v\nwant: %#v", want.Alert, got, want)
			}
			normalizedExpression := alertValidationExpressionWithoutReviewedTransformations(got.Alert, got.Expr)

			sources, gated := gates[got.Alert]
			rangeGate, rangeGated := rangeGates[got.Alert]
			if rangeGated && !gated {
				t.Fatalf("continuous source-health gate contract references ungated alert %s", got.Alert)
			}
			allRangeGateCount := len(dataIntegrityRangeAlertGateRE.FindAllString(normalizedExpression, -1))
			if rangeGated {
				seenRangeGates[got.Alert] = struct{}{}
				wantLibvirtRangeCount := 0
				wantConntrackRangeCount := 0
				if sources.Libvirt {
					wantLibvirtRangeCount = rangeGate.Legs
				}
				if sources.Conntrack {
					wantConntrackRangeCount = rangeGate.Legs
				}
				libvirtRangeCount := strings.Count(normalizedExpression, dataIntegrityRangeAlertGate("oie_host_libvirt_ok", rangeGate.Window))
				conntrackRangeCount := strings.Count(normalizedExpression, dataIntegrityRangeAlertGate("oie_host_conntrack_raw_ok", rangeGate.Window))
				if libvirtRangeCount != wantLibvirtRangeCount || conntrackRangeCount != wantConntrackRangeCount || allRangeGateCount != wantLibvirtRangeCount+wantConntrackRangeCount {
					t.Fatalf("alert %s continuous %s source-health gate counts=%d/%d/all=%d, want %d/%d/all=%d", got.Alert, rangeGate.Window, libvirtRangeCount, conntrackRangeCount, allRangeGateCount, wantLibvirtRangeCount, wantConntrackRangeCount, wantLibvirtRangeCount+wantConntrackRangeCount)
				}
			} else if allRangeGateCount != 0 {
				t.Fatalf("alert %s unexpectedly has %d continuous source-health gates", got.Alert, allRangeGateCount)
			}
			if !gated {
				if normalizedExpression != want.Expr {
					t.Fatalf("ungated alert %s expression changed outside reviewed Prometheus alert validation transformations\nwant: %s\ngot:  %s\nnormalized: %s", got.Alert, want.Expr, got.Expr, normalizedExpression)
				}
				continue
			}
			seenGates[got.Alert] = struct{}{}
			if strings.HasPrefix(got.Alert, "OpenStackInstanceMining") {
				if !reflect.DeepEqual(dataIntegrityExpressionNonHealthMetrics(normalizedExpression), dataIntegrityExpressionNonHealthMetrics(want.Expr)) {
					t.Fatalf("mining alert %s changed its workload metric inputs\nwant: %s\ngot:  %s", got.Alert, want.Expr, got.Expr)
				}
				wantTargetMatches := 2
				if got.Alert == "OpenStackInstanceMiningSuspected" {
					wantTargetMatches = 6
				}
				targetMatch := "on (domain, instance_uuid, project_uuid, user_uuid, instance, job)"
				targetAggregate := "max by (domain, instance_uuid, project_uuid, user_uuid, instance, job)"
				historicalExpression := behaviorMiningExpressionWithoutMiningCPUFreshnessGates(normalizedExpression)
				if strings.Count(historicalExpression, targetMatch) != wantTargetMatches || strings.Count(historicalExpression, targetAggregate) != wantTargetMatches {
					t.Fatalf("mining alert %s historical target-local correlation counts changed: on=%d max_by=%d want=%d", got.Alert, strings.Count(historicalExpression, targetMatch), strings.Count(historicalExpression, targetAggregate), wantTargetMatches)
				}
			} else if dataIntegrityExpressionWithoutSourceHealthGates(normalizedExpression) != dataIntegrityExpressionWithoutSourceHealthGates(want.Expr) {
				t.Fatalf("alert %s changed beyond source-health gates\nwant: %s\ngot:  %s", got.Alert, want.Expr, got.Expr)
			}
			libvirtCount := strings.Count(normalizedExpression, dataIntegrityLibvirtAlertGate)
			conntrackCount := strings.Count(normalizedExpression, dataIntegrityConntrackAlertGate)
			if sources.Libvirt {
				if libvirtCount == 0 {
					t.Fatalf("alert %s is missing its Libvirt source-health gate", got.Alert)
				}
			} else if libvirtCount != 0 {
				t.Fatalf("conntrack-only alert %s unexpectedly has %d Libvirt gates", got.Alert, libvirtCount)
			}
			if sources.Conntrack {
				if conntrackCount == 0 {
					t.Fatalf("alert %s is missing its conntrack source-health gate", got.Alert)
				}
				if sources.Libvirt && conntrackCount != libvirtCount {
					t.Fatalf("alert %s Libvirt/conntrack gate counts=%d/%d, want equal non-zero counts", got.Alert, libvirtCount, conntrackCount)
				}
			} else if conntrackCount != 0 {
				t.Fatalf("Libvirt-only alert %s unexpectedly has %d conntrack gates", got.Alert, conntrackCount)
			}
		}
	}
	if len(seenGates) != len(gates) {
		missing := make([]string, 0)
		for name := range gates {
			if _, seen := seenGates[name]; !seen {
				missing = append(missing, name)
			}
		}
		sort.Strings(missing)
		t.Fatalf("gate contract references missing alert rules: %v", missing)
	}
	if len(seenRangeGates) != len(rangeGates) {
		missing := make([]string, 0)
		for name := range rangeGates {
			if _, seen := seenRangeGates[name]; !seen {
				missing = append(missing, name)
			}
		}
		sort.Strings(missing)
		t.Fatalf("continuous gate contract references missing alert rules: %v", missing)
	}
}

func TestDataIntegrityPrometheusAlertExpressionSHA256Contract(t *testing.T) {
	var got strings.Builder
	for _, rule := range dataIntegrityPriorAlertRulesInFrozenOrder(t, dataIntegrityLoadAlertContract(t)) {
		normalized := alertValidationExpressionWithoutReviewedTransformations(rule.Alert, rule.Expr)
		digest := sha256.Sum256([]byte(resourceTelemetryExpressionWithoutResourceFreshnessGates(normalized)))
		fmt.Fprintf(&got, "%s|%x\n", rule.Alert, digest)
	}
	want, err := os.ReadFile(dataIntegrityAlertExpressionGoldenPath)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != string(want) {
		t.Fatalf("exact Data integrity v2.0.0 alert expression contract changed: %s\nwant:\n%s\ngot:\n%s", dataIntegrityAlertExpressionGoldenPath, want, got.String())
	}
}

func TestResourceTelemetryPrometheusAlertResourceFreshnessContract(t *testing.T) {
	axisRules := map[string]string{
		"OpenStackInstanceResourceCPUHigh":    "cpu",
		"OpenStackInstanceResourceCPUSevere":  "cpu",
		"OpenStackInstanceResourceMemHigh":    "mem",
		"OpenStackInstanceResourceMemSevere":  "mem",
		"OpenStackInstanceResourceDiskHigh":   "disk",
		"OpenStackInstanceResourceDiskSevere": "disk",
		"OpenStackInstanceResourceNetHigh":    "net",
		"OpenStackInstanceResourceNetSevere":  "net",
	}
	compositeRules := map[string]struct{}{
		"OpenStackInstanceAttentionHigh":          {},
		"OpenStackInstanceAttentionSevere":        {},
		"OpenStackInstanceHighResourcePressure":   {},
		"OpenStackInstanceSevereResourcePressure": {},
		"OpenStackProjectManyHotInstances":        {},
	}

	seenAxis := make(map[string]struct{}, len(axisRules))
	seenComposite := make(map[string]struct{}, len(compositeRules))
	allAxesGate := resourceTelemetryAllAvailableResourceAxesFreshGate()
	for _, group := range dataIntegrityLoadAlertContract(t).Groups {
		for _, rule := range group.Rules {
			expression := alertValidationExpressionWithoutReviewedTransformations(rule.Alert, rule.Expr)
			axis, wantsAxis := axisRules[rule.Alert]
			_, wantsComposite := compositeRules[rule.Alert]
			axisGateCount := 0
			for _, candidate := range []string{"cpu", "mem", "disk", "net"} {
				count := strings.Count(expression, resourceTelemetryResourceAxisFreshGate(candidate))
				axisGateCount += count
				if wantsAxis && candidate == axis && count != 1 {
					t.Fatalf("alert %s %s-axis freshness gates=%d, want 1", rule.Alert, axis, count)
				}
				if (!wantsAxis || candidate != axis) && count != 0 {
					t.Fatalf("alert %s unexpectedly has %d %s-axis freshness gates", rule.Alert, count, candidate)
				}
			}
			compositeGateCount := strings.Count(expression, allAxesGate)
			switch {
			case wantsAxis:
				seenAxis[rule.Alert] = struct{}{}
				if axisGateCount != 1 || compositeGateCount != 0 {
					t.Fatalf("axis alert %s resource gates axis=%d composite=%d, want 1/0", rule.Alert, axisGateCount, compositeGateCount)
				}
			case wantsComposite:
				seenComposite[rule.Alert] = struct{}{}
				if axisGateCount != 0 || compositeGateCount != 1 {
					t.Fatalf("composite alert %s resource gates axis=%d composite=%d, want 0/1", rule.Alert, axisGateCount, compositeGateCount)
				}
			default:
				if axisGateCount != 0 || compositeGateCount != 0 {
					t.Fatalf("unapproved alert %s has Resource telemetry resource freshness gates", rule.Alert)
				}
			}
		}
	}
	if len(seenAxis) != len(axisRules) || len(seenComposite) != len(compositeRules) {
		t.Fatalf("Resource telemetry resource-gated alerts missing: axis=%v composite=%v", seenAxis, seenComposite)
	}
}

func TestResourceTelemetryPrometheusAlertExpressionSHA256Contract(t *testing.T) {
	var got strings.Builder
	for _, rule := range dataIntegrityPriorAlertRulesInFrozenOrder(t, dataIntegrityLoadAlertContract(t)) {
		normalized := alertValidationExpressionWithoutReviewedTransformations(rule.Alert, rule.Expr)
		digest := sha256.Sum256([]byte(behaviorMiningExpressionWithoutMiningCPUFreshnessGates(normalized)))
		fmt.Fprintf(&got, "%s|%x\n", rule.Alert, digest)
	}
	want, err := os.ReadFile(resourceTelemetryAlertExpressionGoldenPath)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != string(want) {
		t.Fatalf("exact Resource telemetry v2.0.0 alert expression contract changed: %s\nwant:\n%s\ngot:\n%s", resourceTelemetryAlertExpressionGoldenPath, want, got.String())
	}
}

func TestBehaviorMiningPrometheusMiningCPUCollectionFreshnessContract(t *testing.T) {
	wantLegs := map[string]int{
		"OpenStackInstanceMiningSuspected":           3,
		"OpenStackInstanceMiningCandidatePersistent": 1,
	}
	seen := make(map[string]struct{}, len(wantLegs))
	for _, group := range dataIntegrityLoadAlertContract(t).Groups {
		for _, rule := range group.Rules {
			expression := alertValidationExpressionWithoutReviewedTransformations(rule.Alert, rule.Expr)
			want, approved := wantLegs[rule.Alert]
			counts := []int{
				strings.Count(expression, behaviorMiningMiningCPUCurrentFreshGate()),
				strings.Count(expression, behaviorMiningMiningCPUFreshRangeGate()),
				strings.Count(expression, behaviorMiningMiningCPUCollectionProgressGate()),
			}
			if !approved {
				if counts[0] != 0 || counts[1] != 0 || counts[2] != 0 {
					t.Fatalf("unapproved alert %s has Behavior and mining mining CPU freshness gates: %v", rule.Alert, counts)
				}
				continue
			}
			seen[rule.Alert] = struct{}{}
			if counts[0] != want || counts[1] != want || counts[2] != want {
				t.Fatalf("alert %s Behavior and mining mining CPU freshness gate counts=%v, want [%d %d %d]", rule.Alert, counts, want, want, want)
			}
		}
	}
	if len(seen) != len(wantLegs) {
		t.Fatalf("Behavior and mining mining CPU freshness alerts missing: %v", seen)
	}
}

func TestBehaviorMiningPrometheusAlertExpressionSHA256Contract(t *testing.T) {
	var got strings.Builder
	for _, rule := range dataIntegrityPriorAlertRulesInFrozenOrder(t, dataIntegrityLoadAlertContract(t)) {
		normalized := alertValidationExpressionWithoutReviewedTransformations(rule.Alert, rule.Expr)
		digest := sha256.Sum256([]byte(normalized))
		fmt.Fprintf(&got, "%s|%x\n", rule.Alert, digest)
	}
	want, err := os.ReadFile(behaviorMiningAlertExpressionGoldenPath)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != string(want) {
		t.Fatalf("exact Behavior and mining v2.0.0 alert expression contract changed: %s\nwant:\n%s\ngot:\n%s", behaviorMiningAlertExpressionGoldenPath, want, got.String())
	}
}

type dataIntegrityGrafanaContract struct {
	File           string                      `json:"file"`
	UID            string                      `json:"uid"`
	Title          string                      `json:"title"`
	SemanticSHA256 string                      `json:"semantic_sha256"`
	Variables      []map[string]any            `json:"variables"`
	Panels         []dataIntegrityGrafanaPanel `json:"panels"`
}

type dataIntegrityGrafanaPanel struct {
	ID      json.Number      `json:"id"`
	Title   string           `json:"title"`
	Type    string           `json:"type"`
	Parents []string         `json:"parents,omitempty"`
	Targets []map[string]any `json:"targets,omitempty"`
}

var dataIntegrityGrafanaVariableKeys = []string{
	"name", "type", "label", "description", "query", "definition", "regex", "sort", "refresh",
	"hide", "multi", "includeAll", "allValue", "datasource",
}

var dataIntegrityGrafanaTargetKeys = []string{
	"refId", "expr", "legendFormat", "format", "instant", "range", "hide", "datasource",
	"editorMode", "exemplar",
}

func dataIntegrityProjectMap(source map[string]any, keys []string) map[string]any {
	projected := make(map[string]any)
	for _, key := range keys {
		if value, ok := source[key]; ok {
			projected[key] = value
		}
	}
	return projected
}

func dataIntegrityCollectGrafanaPanels(t *testing.T, raw any, parents []string, destination *[]dataIntegrityGrafanaPanel, seen map[string]struct{}) {
	t.Helper()
	values, ok := raw.([]any)
	if !ok {
		return
	}
	for _, value := range values {
		panel, ok := value.(map[string]any)
		if !ok {
			t.Fatalf("dashboard panel is %T, want object", value)
		}
		id, ok := panel["id"].(json.Number)
		if !ok || id == "" {
			t.Fatalf("dashboard panel has invalid id %#v", panel["id"])
		}
		canonicalID, err := strconv.ParseInt(id.String(), 10, 64)
		if err != nil || canonicalID < 0 || strconv.FormatInt(canonicalID, 10) != id.String() {
			t.Fatalf("dashboard panel has non-canonical integer id %q", id)
		}
		title, _ := panel["title"].(string)
		panelType, _ := panel["type"].(string)
		if strings.TrimSpace(title) == "" || strings.TrimSpace(panelType) == "" {
			t.Fatalf("dashboard panel %d has an empty title or type", canonicalID)
		}
		identity := strconv.FormatInt(canonicalID, 10)
		if _, duplicate := seen[identity]; duplicate {
			t.Fatalf("dashboard contains duplicate panel id %s", identity)
		}
		seen[identity] = struct{}{}
		contract := dataIntegrityGrafanaPanel{ID: id, Title: title, Type: panelType, Parents: append([]string(nil), parents...)}
		if rawTargets, exists := panel["targets"]; exists {
			targets, ok := rawTargets.([]any)
			if !ok {
				t.Fatalf("panel %s targets are %T, want array", identity, rawTargets)
			}
			seenRefs := make(map[string]struct{})
			for targetIndex, rawTarget := range targets {
				target, ok := rawTarget.(map[string]any)
				if !ok {
					t.Fatalf("panel %s target %d is %T, want object", identity, targetIndex, rawTarget)
				}
				projected := dataIntegrityProjectMap(target, dataIntegrityGrafanaTargetKeys)
				expr, _ := projected["expr"].(string)
				if strings.TrimSpace(expr) == "" {
					t.Fatalf("panel %s target %d has no PromQL/expression", identity, targetIndex)
				}
				refID, _ := projected["refId"].(string)
				if refID == "" {
					t.Fatalf("panel %s target %d has no refId", identity, targetIndex)
				}
				if _, duplicate := seenRefs[refID]; duplicate {
					t.Fatalf("panel %s has duplicate target refId %q", identity, refID)
				}
				seenRefs[refID] = struct{}{}
				contract.Targets = append(contract.Targets, projected)
			}
		}
		*destination = append(*destination, contract)
		childParents := append(append([]string(nil), parents...), identity+":"+title)
		dataIntegrityCollectGrafanaPanels(t, panel["panels"], childParents, destination, seen)
	}
}

func dataIntegrityRemovePostDashboardDocumentationGrafanaPanel(raw any, removeID string) {
	values, ok := raw.([]any)
	if !ok {
		return
	}
	for _, value := range values {
		panel, ok := value.(map[string]any)
		if !ok {
			continue
		}
		children, ok := panel["panels"].([]any)
		if !ok {
			continue
		}
		filtered := children[:0]
		for _, child := range children {
			childPanel, _ := child.(map[string]any)
			childID, _ := childPanel["id"].(json.Number)
			if childID.String() == removeID {
				continue
			}
			filtered = append(filtered, child)
		}
		panel["panels"] = filtered
		dataIntegrityRemovePostDashboardDocumentationGrafanaPanel(filtered, removeID)
	}
}

func dataIntegrityLoadGrafanaContracts(t *testing.T) []dataIntegrityGrafanaContract {
	t.Helper()
	paths, err := filepath.Glob("examples/grafana_dashboard_example/*.json")
	if err != nil || len(paths) == 0 {
		t.Fatalf("dashboard glob: %v, files=%d", err, len(paths))
	}
	sort.Strings(paths)
	contracts := make([]dataIntegrityGrafanaContract, 0, len(paths))
	seenUIDs := make(map[string]struct{})
	for _, path := range paths {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var dashboard map[string]any
		if err := dataIntegrityDecodeSingleJSON(b, &dashboard); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		uid, _ := dashboard["uid"].(string)
		title, _ := dashboard["title"].(string)
		if uid == "" || title == "" {
			t.Fatalf("%s has an empty UID or title", path)
		}
		if _, duplicate := seenUIDs[uid]; duplicate {
			t.Fatalf("duplicate dashboard UID %q", uid)
		}
		seenUIDs[uid] = struct{}{}
		// The current accuracy contract includes every panel and its real version.
		// Historical baseline/v2 contracts stay byte-frozen; they are not rewritten
		// to approve the missing-data and measurement-label corrections.
		// The readable projection below gives focused diffs for the primary public
		// contract. This digest covers every remaining normalized JSON field,
		// including layout, options, field configuration, datasource settings,
		// variable selections, target options, and array ordering.
		normalized, err := json.Marshal(dashboard)
		if err != nil {
			t.Fatalf("normalize complete dashboard %s: %v", path, err)
		}
		contract := dataIntegrityGrafanaContract{
			File:           filepath.Base(path),
			UID:            uid,
			Title:          title,
			SemanticSHA256: fmt.Sprintf("%x", sha256.Sum256(normalized)),
		}
		if templating, ok := dashboard["templating"].(map[string]any); ok {
			if variables, ok := templating["list"].([]any); ok {
				seenVariables := make(map[string]struct{})
				for variableIndex, rawVariable := range variables {
					variable, ok := rawVariable.(map[string]any)
					if !ok {
						t.Fatalf("%s variable %d is %T, want object", path, variableIndex, rawVariable)
					}
					name, _ := variable["name"].(string)
					if name == "" {
						t.Fatalf("%s variable %d has no name", path, variableIndex)
					}
					if _, duplicate := seenVariables[name]; duplicate {
						t.Fatalf("%s has duplicate variable %q", path, name)
					}
					seenVariables[name] = struct{}{}
					contract.Variables = append(contract.Variables, dataIntegrityProjectMap(variable, dataIntegrityGrafanaVariableKeys))
				}
			}
		}
		dataIntegrityCollectGrafanaPanels(t, dashboard["panels"], nil, &contract.Panels, make(map[string]struct{}))
		sort.Slice(contract.Panels, func(i, j int) bool {
			left, _ := strconv.Atoi(contract.Panels[i].ID.String())
			right, _ := strconv.Atoi(contract.Panels[j].ID.String())
			if left != right {
				return left < right
			}
			return contract.Panels[i].Title < contract.Panels[j].Title
		})
		contracts = append(contracts, contract)
	}
	return contracts
}

func TestDataIntegrityGrafanaDashboardSemanticContract(t *testing.T) {
	if _, err := os.Stat(dataIntegrityGrafanaGoldenPath); err != nil {
		t.Fatalf("historical Data integrity Grafana contract is missing: %v", err)
	}
	if _, err := os.Stat(dashboardDocumentationGrafanaGoldenPath); err != nil {
		t.Fatalf("historical Dashboard and documentation contract is missing: %v", err)
	}
	dataIntegrityCompareGolden(t, "testdata/operator-grafana-contract-v2.0.0.json", dataIntegrityLoadGrafanaContracts(t))
}

type dataIntegrityAnsibleRoleContract struct {
	PublicVariables []string `json:"public_variables"`
	Defaults        any      `json:"defaults"`
	Tasks           any      `json:"tasks"`
	Handlers        any      `json:"handlers"`
}

var dataIntegrityAnsiblePublicVariableRE = regexp.MustCompile(`\bopenstack_instance_exporter_[a-zA-Z0-9_]+\b`)

func dataIntegrityLoadYAMLSemantics(t *testing.T, path string) (any, []byte) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var value any
	if err := dataIntegrityDecodeSingleYAML(b, &value, false); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return value, b
}

func dataIntegrityLoadAnsibleRoleContract(t *testing.T) dataIntegrityAnsibleRoleContract {
	t.Helper()
	defaultsPath := "ansible_role/openstack_instance_exporter/defaults/main.yml"
	tasksPath := "ansible_role/openstack_instance_exporter/tasks/main.yml"
	handlersPath := "ansible_role/openstack_instance_exporter/handlers/main.yml"
	templatePath := "ansible_role/openstack_instance_exporter/templates/openstack_instance_exporter.service.j2"
	defaults, defaultsRaw := dataIntegrityLoadYAMLSemantics(t, defaultsPath)
	tasks, tasksRaw := dataIntegrityLoadYAMLSemantics(t, tasksPath)
	handlers, handlersRaw := dataIntegrityLoadYAMLSemantics(t, handlersPath)
	templateRaw, err := os.ReadFile(templatePath)
	if err != nil {
		t.Fatal(err)
	}
	allRaw := bytes.Join([][]byte{defaultsRaw, tasksRaw, handlersRaw, templateRaw}, []byte{'\n'})
	variableSet := make(map[string]struct{})
	for _, name := range dataIntegrityAnsiblePublicVariableRE.FindAllString(string(allRaw), -1) {
		variableSet[name] = struct{}{}
	}
	variables := make([]string, 0, len(variableSet))
	for name := range variableSet {
		variables = append(variables, name)
	}
	sort.Strings(variables)
	return dataIntegrityAnsibleRoleContract{
		PublicVariables: variables,
		Defaults:        defaults,
		Tasks:           tasks,
		Handlers:        handlers,
	}
}

func TestDataIntegrityAnsibleRoleSemanticContract(t *testing.T) {
	contract := dataIntegrityLoadAnsibleRoleContract(t)
	additions := make(map[string]struct{})
	for _, path := range []string{threatIntelligenceAnsibleAdditionsGoldenPath} {
		for _, name := range goldenLines(t, path) {
			additions[name] = struct{}{}
		}
	}
	additions["openstack_instance_exporter_archive_src"] = struct{}{}
	additions["openstack_instance_exporter_download_url"] = struct{}{}
	additions["openstack_instance_exporter_volume_retype_enable"] = struct{}{}
	inherited := contract.PublicVariables[:0]
	for _, name := range contract.PublicVariables {
		if _, added := additions[name]; !added {
			inherited = append(inherited, name)
		}
	}
	contract.PublicVariables = inherited

	baselineBytes, err := os.ReadFile(dataIntegrityAnsibleGoldenPath)
	if err != nil {
		t.Fatal(err)
	}
	var baseline dataIntegrityAnsibleRoleContract
	if err := dataIntegrityDecodeSingleJSON(baselineBytes, &baseline); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(contract.PublicVariables, baseline.PublicVariables) {
		t.Fatalf("inherited Ansible public variables changed\nwant: %v\ngot:  %v", baseline.PublicVariables, contract.PublicVariables)
	}
	currentDefaults, ok := contract.Defaults.(map[string]any)
	if !ok {
		t.Fatalf("current Ansible defaults type=%T", contract.Defaults)
	}
	baselineDefaults, ok := baseline.Defaults.(map[string]any)
	if !ok {
		t.Fatalf("baseline Ansible defaults type=%T", baseline.Defaults)
	}
	for name, want := range baselineDefaults {
		if name == "openstack_instance_exporter_logrotate_content" ||
			name == "openstack_instance_exporter_version" ||
			name == "openstack_instance_exporter_sha256" {
			continue
		}
		got, exists := currentDefaults[name]
		gotJSON, gotErr := json.Marshal(got)
		wantJSON, wantErr := json.Marshal(want)
		if !exists || gotErr != nil || wantErr != nil || !bytes.Equal(gotJSON, wantJSON) {
			t.Fatalf("inherited Ansible default %s changed: got=%s want=%s", name, gotJSON, wantJSON)
		}
	}
}

const dataIntegrityAnsibleRenderScript = `
import json
import sys
from pathlib import Path
from ansible.parsing.dataloader import DataLoader
from ansible.template import Templar
try:
    from ansible.template import trust_as_template
except ImportError:
    def trust_as_template(value):
        return value

role = Path(sys.argv[1])
loader = DataLoader()
defaults = loader.load_from_file(str(role / "defaults" / "main.yml"))
source = trust_as_template((role / "templates" / "openstack_instance_exporter.service.j2").read_text(encoding="utf-8"))

def render(overrides):
    variables = dict(defaults)
    variables.update(overrides)
    variables["inventory_hostname"] = "localhost"
    variables["hostvars"] = {
        "localhost": {"ansible_br_monitoring": {"ipv4": {"address": "192.0.2.50"}}}
    }
    return Templar(loader=loader, variables=variables).template(source)

profiles = [
    "disabled", "resource-only", "outbound-standard", "outbound-observant",
    "outbound-max", "bidir-standard", "bidir-observant", "bidir-max",
]
rendered = {profile: render({"openstack_instance_exporter_profile": profile}) for profile in profiles}
rendered["explicit-override-matrix"] = render({
    "openstack_instance_exporter_profile": "bidir-max",
    "openstack_instance_exporter_behavior_sensitivity": 2.25,
    "openstack_instance_exporter_severity_weight_resource": 0.40,
    "openstack_instance_exporter_severity_weight_behavior": 0.35,
    "openstack_instance_exporter_severity_weight_threat_list": 0.25,
    "openstack_instance_exporter_inbound_behavior_enable": False,
    "openstack_instance_exporter_outbound_behavior_enable": False,
    "openstack_instance_exporter_behavior_ewma_fast_tau": "1m",
    "openstack_instance_exporter_behavior_ewma_slow_tau": "1h",
    "openstack_instance_exporter_behavior_ports_config_path": "/etc/oie/ports.yml",
    "openstack_instance_exporter_behavior_ports_config_yaml": "behavior: {ports: {inbound_monitored: {22: ssh}}}",
    "openstack_instance_exporter_behavior_rules_config_path": "/etc/oie/rules.yml",
    "openstack_instance_exporter_behavior_rules_config_yaml": "rules: [{id: ssh, ports: [22], kind: ssh}]",
    "openstack_instance_exporter_tor_exit_enable": True,
    "openstack_instance_exporter_tor_exit_direction": "any",
    "openstack_instance_exporter_tor_exit_url": "https://example.invalid/tor-exit.json",
    "openstack_instance_exporter_tor_exit_refresh": "11m",
    "openstack_instance_exporter_tor_relay_enable": True,
    "openstack_instance_exporter_tor_relay_direction": "any",
    "openstack_instance_exporter_tor_relay_url": "https://example.invalid/tor-relay.json",
    "openstack_instance_exporter_tor_relay_refresh": "12m",
    "openstack_instance_exporter_spamhaus_enable": True,
    "openstack_instance_exporter_spamhaus_direction": "any",
    "openstack_instance_exporter_spamhaus_url": "https://example.invalid/drop.txt",
    "openstack_instance_exporter_spamhaus_ipv6_url": "https://example.invalid/dropv6.txt",
    "openstack_instance_exporter_spamhaus_refresh": "13m",
    "openstack_instance_exporter_emergingthreats_enable": True,
    "openstack_instance_exporter_emergingthreats_direction": "any",
    "openstack_instance_exporter_emergingthreats_url": "https://example.invalid/emerging.txt",
    "openstack_instance_exporter_emergingthreats_refresh": "14m",
    "openstack_instance_exporter_customlist_enable": True,
    "openstack_instance_exporter_customlist_direction": "any",
    "openstack_instance_exporter_customlist_path": "/etc/oie/custom.txt",
    "openstack_instance_exporter_customlist_refresh": "15m",
    "openstack_instance_exporter_conntrack_raw_rcvbuf_bytes": 67108864,
    "openstack_instance_exporter_conntrack_raw_rcv_timeout": "9s",
    "openstack_instance_exporter_conntrack_ipv4_enable": True,
    "openstack_instance_exporter_conntrack_ipv6_enable": False,
    "openstack_instance_exporter_web_listen_address": "127.0.0.1:19120",
    "openstack_instance_exporter_web_telemetry_path": "/oie-metrics",
    "openstack_instance_exporter_collection_interval": "30s",
    "openstack_instance_exporter_worker_count": 4,
    "openstack_instance_exporter_libvirt_uri": "qemu:///system",
    "openstack_instance_exporter_contacts_direction": "any",
    "openstack_instance_exporter_host_threats_enable": True,
    "openstack_instance_exporter_host_interfaces": ["bgp-nic", "br-monitoring"],
    "openstack_instance_exporter_host_ips_allow_private": True,
    "openstack_instance_exporter_log_file_enable": True,
    "openstack_instance_exporter_log_file_path": "/var/log/oie.log",
    "openstack_instance_exporter_log_level": "debug",
    "openstack_instance_exporter_threat_log_min_interval": "1m",
})
rendered["interface-bind-override"] = render({
    "openstack_instance_exporter_profile": "disabled",
    "openstack_instance_exporter_web_listen_address": "",
    "openstack_instance_exporter_network_interface": "br-monitoring",
    "openstack_instance_exporter_bind_port": 19120,
})
rendered["config-path-without-content"] = render({
    "openstack_instance_exporter_profile": "disabled",
    "openstack_instance_exporter_behavior_ports_config_path": "/etc/oie/ports-unused.yml",
    "openstack_instance_exporter_behavior_rules_config_path": "/etc/oie/rules-unused.yml",
})
rendered["config-content-without-path"] = render({
    "openstack_instance_exporter_profile": "disabled",
    "openstack_instance_exporter_behavior_ports_config_yaml": "behavior: {ports: {}}",
    "openstack_instance_exporter_behavior_rules_config_yaml": "rules: []",
})
print(json.dumps(rendered, sort_keys=True))
`

type dataIntegrityRenderedServiceContract struct {
	Unit      []string `json:"unit"`
	ExecStart []string `json:"exec_start"`
}

func dataIntegrityFindAnsiblePython(t *testing.T) string {
	t.Helper()
	candidates := []string{os.Getenv("ANSIBLE_PYTHON")}
	if relative, err := filepath.Abs("../../../toolchains/ansible-venv/bin/python"); err == nil {
		candidates = append(candidates, relative)
	}
	if path, err := exec.LookPath("python3"); err == nil {
		candidates = append(candidates, path)
	}
	seen := make(map[string]struct{})
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if _, duplicate := seen[candidate]; duplicate {
			continue
		}
		seen[candidate] = struct{}{}
		cmd := exec.Command(candidate, "-c", "import ansible")
		cmd.Env = append(os.Environ(), "ANSIBLE_LOCAL_TEMP="+t.TempDir())
		if err := cmd.Run(); err == nil {
			return candidate
		}
	}
	t.Skip("Ansible Python is unavailable; rendered service contract is covered by make ansible-render")
	return ""
}

func dataIntegrityParseRenderedService(t *testing.T, rendered string) dataIntegrityRenderedServiceContract {
	t.Helper()
	contract := dataIntegrityRenderedServiceContract{}
	for _, line := range strings.Split(rendered, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		contract.Unit = append(contract.Unit, line)
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		if key == "ExecStart" {
			if len(contract.ExecStart) != 0 {
				t.Fatalf("rendered service has multiple ExecStart directives:\n%s", rendered)
			}
			contract.ExecStart = strings.Fields(value)
		}
	}
	for _, required := range []string{
		"[Unit]", "Description=", "After=", "[Service]", "User=", "Group=", "Restart=",
		"RestartSec=", "StandardOutput=", "StandardError=", "[Install]", "WantedBy=",
	} {
		found := false
		for _, line := range contract.Unit {
			if line == required || strings.HasPrefix(line, required) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("rendered service is missing required semantic %s:\n%s", required, rendered)
		}
	}
	if len(contract.ExecStart) == 0 {
		t.Fatalf("rendered service is missing required runtime properties:\n%s", rendered)
	}
	return contract
}

func dataIntegrityLoadRenderedServiceContracts(t *testing.T) map[string]dataIntegrityRenderedServiceContract {
	t.Helper()
	python := dataIntegrityFindAnsiblePython(t)
	rolePath, err := filepath.Abs("ansible_role/openstack_instance_exporter")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(python, "-c", dataIntegrityAnsibleRenderScript, rolePath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Env = append(os.Environ(), "ANSIBLE_LOCAL_TEMP="+t.TempDir())
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("render Ansible service contracts: %v\n%s", err, stderr.String())
	}
	var rendered map[string]string
	if err := json.Unmarshal(output, &rendered); err != nil {
		t.Fatalf("decode rendered Ansible services: %v\n%s", err, output)
	}
	contracts := make(map[string]dataIntegrityRenderedServiceContract, len(rendered))
	for profile, service := range rendered {
		contracts[profile] = dataIntegrityParseRenderedService(t, service)
	}
	for _, required := range []string{
		"disabled", "resource-only", "outbound-standard", "outbound-observant", "outbound-max",
		"bidir-standard", "bidir-observant", "bidir-max", "explicit-override-matrix",
		"interface-bind-override", "config-path-without-content", "config-content-without-path",
	} {
		if _, exists := contracts[required]; !exists {
			t.Fatalf("rendered service contract is missing %q", required)
		}
	}
	return contracts
}

func TestDataIntegrityAnsibleRenderedServiceArgumentContract(t *testing.T) {
	baselineBytes, err := os.ReadFile(dataIntegrityAnsibleRenderGoldenPath)
	if err != nil {
		t.Fatal(err)
	}
	var baseline map[string]dataIntegrityRenderedServiceContract
	if err := dataIntegrityDecodeSingleJSON(baselineBytes, &baseline); err != nil {
		t.Fatal(err)
	}
	current := dataIntegrityLoadRenderedServiceContracts(t)
	if len(current) != len(baseline) {
		t.Fatalf("rendered service cases=%d, want %d", len(current), len(baseline))
	}
	stableUnit := func(lines []string) []string {
		stable := make([]string, 0, len(lines))
		for _, line := range lines {
			if line == "[Unit]" || line == "[Service]" || line == "[Install]" ||
				strings.HasPrefix(line, "Description=") || strings.HasPrefix(line, "After=") ||
				strings.HasPrefix(line, "ExecStart=") || strings.HasPrefix(line, "Restart=") ||
				strings.HasPrefix(line, "RestartSec=") || strings.HasPrefix(line, "StandardOutput=") ||
				strings.HasPrefix(line, "StandardError=") || strings.HasPrefix(line, "WantedBy=") {
				stable = append(stable, line)
			}
		}
		return stable
	}
	for name, want := range baseline {
		got, exists := current[name]
		if !exists {
			t.Fatalf("rendered service case %q was removed", name)
		}
		if !reflect.DeepEqual(got.ExecStart, want.ExecStart) {
			t.Fatalf("rendered service %q exporter arguments changed\nwant: %v\ngot:  %v", name, want.ExecStart, got.ExecStart)
		}
		if !reflect.DeepEqual(stableUnit(got.Unit), stableUnit(want.Unit)) {
			t.Fatalf("rendered service %q inherited unit semantics changed\nwant: %v\ngot:  %v", name, stableUnit(want.Unit), stableUnit(got.Unit))
		}
	}
}

func TestDataIntegrityExternalAssetDecodersRejectTrailingOrDuplicateData(t *testing.T) {
	var yamlValue map[string]any
	if err := dataIntegrityDecodeSingleYAML([]byte("first: true\n---\nsecond: true\n"), &yamlValue, false); err == nil {
		t.Fatal("YAML contract decoder accepted a trailing document")
	}
	if err := dataIntegrityDecodeSingleYAML([]byte("first: true\n\n"), &yamlValue, false); err != nil {
		t.Fatalf("YAML contract decoder rejected trailing whitespace: %v", err)
	}

	var jsonValue map[string]any
	if err := dataIntegrityDecodeSingleJSON([]byte(`{"first":true} {"second":true}`), &jsonValue); err == nil {
		t.Fatal("JSON contract decoder accepted a trailing value")
	}
	if err := dataIntegrityDecodeSingleJSON([]byte(`{"first":true,"first":false}`), &jsonValue); err == nil {
		t.Fatal("JSON contract decoder accepted a duplicate object key")
	}
	if err := dataIntegrityDecodeSingleJSON([]byte("{\"first\":true}\n\n"), &jsonValue); err != nil {
		t.Fatalf("JSON contract decoder rejected trailing whitespace: %v", err)
	}
}
