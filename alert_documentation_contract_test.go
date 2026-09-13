package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

const (
	alertValidationAlertContractGoldenPath = "testdata/alert-validation-prometheus-alert-contract-v2.0.0.golden.json"
	alertValidationAlertExpressionPath     = "testdata/alert-validation-prometheus-alert-expression-sha256-v2.0.0.golden"
	alertValidationAlertGateGoldenPath     = "testdata/alert-validation-prometheus-alert-source-health-gates-v2.0.0.golden"
	alertValidationMetricAdditionsPath     = "testdata/metrics-v2.0.0-alert-validation-additions.golden"
	alertValidationMetricSchemaPath        = "testdata/metrics-v2.0.0-alert-validation-schema.golden"
	alertValidationPriorGoldenSHA256Path   = "testdata/alert-validation-prior-golden-sha256.golden"
	alertValidationOIEFamilyCount          = 136
)

var alertValidationAlertGroupContract = []struct {
	Name   string
	Policy string
	Rules  int
}{
	{Name: "OpenStack Instance Exporter - Exporter and Source Health", Policy: "default", Rules: 11},
	{Name: "OpenStack Instance Exporter - Host Capacity and Shared-Resource Danger", Policy: "default", Rules: 12},
	{Name: "OpenStack Instance Exporter - High-Confidence Security Evidence", Policy: "default", Rules: 10},
	{Name: "OpenStack Instance Exporter - OPTIONAL Environment-Tuned Workload Heuristics", Policy: "optional-environment-tuned", Rules: 45},
}

var (
	alertValidationCurrentUpGateRE   = regexp.MustCompile(` and on \(instance, job\) \(max by \(instance, job\) \(up\{job="openstack-instance-exporter"\}\) == 1\)`)
	alertValidationRangeUpGateRE     = regexp.MustCompile(` and on \(instance, job\) \(min by \(instance, job\) \(min_over_time\(up\{job="openstack-instance-exporter"\}\[[1-9][0-9]*[smhdwy]\]\)\) == 1\)`)
	alertValidationCurrentFeedGateRE = regexp.MustCompile(
		` and on \(instance, job\) \(max by \(instance, job\) \(oie_host_threat_feed_fresh\{job="openstack-instance-exporter"(?:,list="(?:TOREXIT|TORRELAY|EMERGING|CUSTOMLIST|spamhaus)")?\}\) == 1\)`,
	)
	alertValidationRangeFeedGateRE = regexp.MustCompile(
		` and on \(instance, job\) \(min by \(instance, job\) \(min_over_time\(oie_host_threat_feed_fresh\{job="openstack-instance-exporter",list="(?:TOREXIT|TORRELAY|EMERGING|CUSTOMLIST|spamhaus)"\}\[[1-9][0-9]*[smhdwy]\]\)\) == 1\)`,
	)
)

const (
	alertValidationOptionalAnyFeedGate           = ` and on (instance, job) ((max by (instance, job) (oie_host_threat_feed_fresh{job="openstack-instance-exporter"}) == 1) or ((max by (instance, job) (up{job="openstack-instance-exporter"}) == 1) unless on (instance, job) max by (instance, job) (oie_host_threat_feed_fresh{job="openstack-instance-exporter"})))`
	alertValidationCurrentAnyFeedSameScrapeGate  = ` and on (instance, job) (max by (instance, job) ((oie_host_threat_feed_fresh{job="openstack-instance-exporter"} == 1) and on (instance, job, list) (timestamp(oie_host_threat_feed_fresh{job="openstack-instance-exporter"}) == on (instance, job) group_left max by (instance, job) (timestamp(up{job="openstack-instance-exporter"})))) == 1)`
	alertValidationOptionalAnyFeedSameScrapeGate = ` and on (instance, job) ((max by (instance, job) ((oie_host_threat_feed_fresh{job="openstack-instance-exporter"} == 1) and on (instance, job, list) (timestamp(oie_host_threat_feed_fresh{job="openstack-instance-exporter"}) == on (instance, job) group_left max by (instance, job) (timestamp(up{job="openstack-instance-exporter"})))) == 1) or ((max by (instance, job) (up{job="openstack-instance-exporter"}) == 1) unless on (instance, job) (max by (instance, job) (timestamp(oie_host_threat_feed_fresh{job="openstack-instance-exporter"}) == on (instance, job) group_left max by (instance, job) (timestamp(up{job="openstack-instance-exporter"}))) > 0)))`
	alertValidationOptionalAnyFeedTriStateGate   = ` and on (instance, job) ((max by (instance, job) (oie_host_threat_feed_fresh{job="openstack-instance-exporter"}) == 1) or (max by (instance, job) (oie_host_threat_feed_fresh{job="openstack-instance-exporter"}) == -1 and on (instance, job) (count by (instance, job) (max by (instance, job, list) (oie_host_threat_feed_fresh{job="openstack-instance-exporter"})) == 5)))`
)

func alertValidationMatchingParenthesis(expression string, open int) int {
	depth := 0
	for index := open; index < len(expression); index++ {
		switch expression[index] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return index
			}
		}
	}
	return -1
}

func alertValidationPreviousUnmatchedOpenParenthesis(expression string, before int) int {
	depth := 0
	for index := before - 1; index >= 0; index-- {
		switch expression[index] {
		case ')':
			depth++
		case '(':
			if depth == 0 {
				return index
			}
			depth--
		}
	}
	return -1
}

// alertValidationExpressionWithoutScrapeCohortGuards removes only the reviewed Prometheus alert validation
// wrapper around one primary selector or range function. The wrapper binds its
// latest sample to Prometheus's up timestamp and, for range functions, binds
// primary and up sample counts. Its inner primary expression is the frozen
// Compatibility baseline through Threat intelligence expression input.
func alertValidationExpressionWithoutScrapeCohortGuards(expression string) string {
	const (
		timestampMarker = " and (timestamp("
		countMarker     = " and (count_over_time("
	)
	for {
		marker := strings.Index(expression, timestampMarker)
		if marker < 0 {
			return expression
		}
		wrapperOpen := alertValidationPreviousUnmatchedOpenParenthesis(expression, marker)
		guardOpen := marker + len(" and ")
		if wrapperOpen < 0 || guardOpen >= len(expression) || expression[guardOpen] != '(' {
			return expression
		}
		guardClose := alertValidationMatchingParenthesis(expression, guardOpen)
		if guardClose < 0 {
			return expression
		}
		afterGuards := guardClose + 1
		if strings.HasPrefix(expression[afterGuards:], countMarker) {
			countOpen := afterGuards + len(" and ")
			countClose := alertValidationMatchingParenthesis(expression, countOpen)
			if countClose < 0 {
				return expression
			}
			afterGuards = countClose + 1
		}
		if afterGuards >= len(expression) || expression[afterGuards] != ')' {
			return expression
		}
		primary := expression[wrapperOpen+1 : marker]
		expression = expression[:wrapperOpen] + primary + expression[afterGuards+1:]
	}
}

func alertValidationReviewedHistoricalDuration(alert, current string) string {
	switch alert {
	case "OpenStackInstanceExporterHostConntrackReadErrors",
		"OpenStackInstanceExporterHostThreatListed":
		return "0s"
	case "OpenStackInstanceMiningSuspected":
		return ""
	default:
		return current
	}
}

func alertValidationFirstParenthesizedConjunct(expression string) (string, bool) {
	if !strings.HasPrefix(expression, "(") {
		return expression, false
	}
	depth := 0
	for index, character := range expression {
		switch character {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				if strings.HasPrefix(expression[index+1:], " and ") {
					return expression[1:index], true
				}
				return expression, false
			}
		}
	}
	return expression, false
}

func alertValidationFirstParenthesizedMiningOwner(expression string) (string, bool) {
	if !strings.HasPrefix(expression, "(") {
		return expression, false
	}
	close := alertValidationMatchingParenthesis(expression, 0)
	if close < 0 {
		return expression, false
	}
	const ownerExclusion = " unless on (domain, instance_uuid, project_uuid, user_uuid) "
	if !strings.HasPrefix(expression[close+1:], ownerExclusion) {
		return expression, false
	}
	return expression[1:close], true
}

func alertValidationNormalizeProjectManyHotInstances(expression string) string {
	const (
		prefix     = "count by (project_uuid, project_name) (max by (domain, instance_uuid, project_uuid, project_name, user_uuid) ("
		suffix     = ")) >= 10"
		priorStart = "count by (project_uuid, project_name) ("
		priorEnd   = ") >= 10"
	)
	if !strings.HasPrefix(expression, prefix) || !strings.HasSuffix(expression, suffix) {
		return expression
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(expression, prefix), suffix)
	return priorStart + inner + priorEnd
}

func alertValidationNormalizeMiningIdentity(expression string) string {
	const (
		prefix = "max by (domain, instance_uuid, project_uuid, user_uuid) ("
		suffix = ") > 0"
	)
	if !strings.HasPrefix(expression, prefix) || !strings.HasSuffix(expression, suffix) {
		return expression
	}
	return strings.TrimSuffix(strings.TrimPrefix(expression, prefix), suffix)
}

func alertValidationExpressionWithoutReviewedTransformations(alert, expression string) string {
	reviewedDeduplicationPrior := map[string]string{
		"OpenStackInstanceHighDiskGBReadTotalLongTerm":          `sum by (domain, instance_uuid, project_uuid, user_uuid) (increase(oie_instance_disk_read_gbytes_total[6h]) and on (instance, job) (min_over_time(oie_host_libvirt_ok{job="openstack-instance-exporter"}[6h]) == 1) and on (instance, job) (oie_host_libvirt_ok{job="openstack-instance-exporter"} == 1)) > 250`,
		"OpenStackInstanceHighDiskGBWriteTotalLongTerm":         `sum by (domain, instance_uuid, project_uuid, user_uuid) (increase(oie_instance_disk_write_gbytes_total[6h]) and on (instance, job) (min_over_time(oie_host_libvirt_ok{job="openstack-instance-exporter"}[6h]) == 1) and on (instance, job) (oie_host_libvirt_ok{job="openstack-instance-exporter"} == 1)) > 250`,
		"OpenStackInstanceTorExitRepeatedContact":               `increase(oie_instance_threat_tor_exit_contacts_total[5m]) >= 5 and on (instance, job) (min_over_time(oie_host_libvirt_ok{job="openstack-instance-exporter"}[5m]) == 1) and on (instance, job) (min_over_time(oie_host_conntrack_raw_ok{job="openstack-instance-exporter"}[5m]) == 1) and on (instance, job) (oie_host_libvirt_ok{job="openstack-instance-exporter"} == 1) and on (instance, job) (oie_host_conntrack_raw_ok{job="openstack-instance-exporter"} == 1)`,
		"OpenStackInstanceTorRelayRepeatedContact":              `increase(oie_instance_threat_tor_relay_contacts_total[5m]) >= 5 and on (instance, job) (min_over_time(oie_host_libvirt_ok{job="openstack-instance-exporter"}[5m]) == 1) and on (instance, job) (min_over_time(oie_host_conntrack_raw_ok{job="openstack-instance-exporter"}[5m]) == 1) and on (instance, job) (oie_host_libvirt_ok{job="openstack-instance-exporter"} == 1) and on (instance, job) (oie_host_conntrack_raw_ok{job="openstack-instance-exporter"} == 1)`,
		"OpenStackInstanceSpamhausRepeatedContact":              `increase(oie_instance_threat_spamhaus_contacts_total[5m]) >= 5 and on (instance, job) (min_over_time(oie_host_libvirt_ok{job="openstack-instance-exporter"}[5m]) == 1) and on (instance, job) (min_over_time(oie_host_conntrack_raw_ok{job="openstack-instance-exporter"}[5m]) == 1) and on (instance, job) (oie_host_libvirt_ok{job="openstack-instance-exporter"} == 1) and on (instance, job) (oie_host_conntrack_raw_ok{job="openstack-instance-exporter"} == 1)`,
		"OpenStackInstanceEmergingThreatsRepeatedContact":       `increase(oie_instance_threat_emergingthreats_contacts_total[5m]) >= 5 and on (instance, job) (min_over_time(oie_host_libvirt_ok{job="openstack-instance-exporter"}[5m]) == 1) and on (instance, job) (min_over_time(oie_host_conntrack_raw_ok{job="openstack-instance-exporter"}[5m]) == 1) and on (instance, job) (oie_host_libvirt_ok{job="openstack-instance-exporter"} == 1) and on (instance, job) (oie_host_conntrack_raw_ok{job="openstack-instance-exporter"} == 1)`,
		"OpenStackInstanceCustomListRepeatedContact":            `increase(oie_instance_threat_customlist_contacts_total[5m]) >= 5 and on (instance, job) (min_over_time(oie_host_libvirt_ok{job="openstack-instance-exporter"}[5m]) == 1) and on (instance, job) (min_over_time(oie_host_conntrack_raw_ok{job="openstack-instance-exporter"}[5m]) == 1) and on (instance, job) (oie_host_libvirt_ok{job="openstack-instance-exporter"} == 1) and on (instance, job) (oie_host_conntrack_raw_ok{job="openstack-instance-exporter"} == 1)`,
		"OpenStackInstanceExporterHostThreatListed":             `max by (list, ip, family, job) (oie_host_threat_provider_ip_listed) > 0`,
		"OpenStackInstanceExporterHostConntrackUtilizationHigh": `oie_host_conntrack_utilization > 0.8 and on (instance, job) (oie_host_conntrack_raw_ok{job="openstack-instance-exporter"} == 1)`,
		"OpenStackInstanceExporterProcessCPUHigh":               `rate(process_cpu_seconds_total{job="openstack-instance-exporter"}[5m]) > 0.5`,
	}
	if prior, replaced := reviewedDeduplicationPrior[alert]; replaced {
		return prior
	}

	feedStalePrior := map[string]string{
		"OpenStackInstanceExporterTorExitListRefreshStale":         `(time() - oie_host_threat_tor_exit_refresh_last_success_timestamp_seconds) > 43200`,
		"OpenStackInstanceExporterSpamhausListRefreshStale":        `(time() - oie_host_threat_spamhaus_refresh_last_success_timestamp_seconds) > 43200`,
		"OpenStackInstanceExporterEmergingThreatsListRefreshStale": `(time() - oie_host_threat_emergingthreats_refresh_last_success_timestamp_seconds) > 43200`,
		"OpenStackInstanceExporterCustomListRefreshStale":          `(time() - oie_host_threat_customlist_refresh_last_success_timestamp_seconds) > 43200`,
	}
	if prior, replaced := feedStalePrior[alert]; replaced {
		return prior
	}

	expression = alertValidationExpressionWithoutScrapeCohortGuards(expression)
	expression = strings.ReplaceAll(expression, alertValidationOptionalAnyFeedTriStateGate, "")
	expression = strings.ReplaceAll(expression, alertValidationOptionalAnyFeedSameScrapeGate, "")
	expression = strings.ReplaceAll(expression, alertValidationCurrentAnyFeedSameScrapeGate, "")
	expression = strings.ReplaceAll(expression, alertValidationOptionalAnyFeedGate, "")
	expression = alertValidationRangeFeedGateRE.ReplaceAllString(expression, "")
	expression = alertValidationCurrentFeedGateRE.ReplaceAllString(expression, "")
	expression = alertValidationRangeUpGateRE.ReplaceAllString(expression, "")
	expression = alertValidationCurrentUpGateRE.ReplaceAllString(expression, "")

	switch alert {
	case "OpenStackInstanceAttentionHigh",
		"OpenStackInstanceThreatScoreHigh",
		"OpenStackInstanceBehaviorScoreHigh",
		"OpenStackInstanceHighResourcePressure",
		"OpenStackInstanceResourceCPUHigh",
		"OpenStackInstanceResourceMemHigh",
		"OpenStackInstanceResourceDiskHigh",
		"OpenStackInstanceResourceNetHigh",
		"OpenStackInstanceConntrackFlowsBurst",
		"OpenStackInstanceZombieFlowWarning":
		if prior, ok := alertValidationFirstParenthesizedConjunct(expression); ok {
			return prior
		}
	case "OpenStackProjectManyHotInstances":
		return alertValidationNormalizeProjectManyHotInstances(expression)
	case "OpenStackInstanceExporterConntrackRawReaderFailed":
		if prior, ok := alertValidationFirstParenthesizedConjunct(expression); ok {
			return prior
		}
	case "OpenStackInstanceExporterConntrackReadStale":
		return `max by (instance, job) (oie_host_conntrack_stale_seconds{job="openstack-instance-exporter"}) > 120`
	case "OpenStackInstanceExporterHostConntrackReadErrors":
		return `increase(oie_host_conntrack_read_errors_total[10m]) > 5`
	case "OpenStackInstanceMiningSuspected":
		return alertValidationNormalizeMiningIdentity(expression)
	case "OpenStackInstanceMiningCandidatePersistent":
		if priorOwner, ok := alertValidationFirstParenthesizedMiningOwner(expression); ok {
			expression = priorOwner
		}
		return alertValidationNormalizeMiningIdentity(expression)
	case "OpenStackInstanceExporterProcessCPUHigh":
		if strings.HasPrefix(expression, "(") {
			if close := strings.Index(expression, ") > 0.5"); close == len(expression)-len(") > 0.5") {
				return expression[1:close] + " > 0.5"
			}
		}
	}
	return expression
}

func alertValidationSourceGateCount(expression, metric string) int {
	direct := fmt.Sprintf(` and on (instance, job) (%s{job="openstack-instance-exporter"} == 1)`, metric)
	aggregated := fmt.Sprintf(` and on (instance, job) (max by (instance, job) (%s{job="openstack-instance-exporter"}) == 1)`, metric)
	return strings.Count(expression, direct) + strings.Count(expression, aggregated)
}

func alertValidationSortedSetKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func TestAlertValidationPriorGoldenAssetsAreByteFrozen(t *testing.T) {
	manifest, err := os.ReadFile(alertValidationPriorGoldenSHA256Path)
	if err != nil {
		t.Fatal(err)
	}
	wantPaths := make(map[string]struct{})
	for _, line := range strings.Split(strings.TrimSpace(string(manifest)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || len(fields[0]) != 64 || !strings.HasPrefix(fields[1], "testdata/") {
			t.Fatalf("invalid prior-golden hash record %q", line)
		}
		if _, duplicate := wantPaths[fields[1]]; duplicate {
			t.Fatalf("duplicate prior-golden hash path %q", fields[1])
		}
		wantPaths[fields[1]] = struct{}{}
		content, err := os.ReadFile(fields[1])
		if err != nil {
			t.Fatalf("read frozen golden %s: %v", fields[1], err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(content)); got != fields[0] {
			t.Fatalf("frozen golden %s changed: sha256=%s want=%s", fields[1], got, fields[0])
		}
	}

	paths, err := filepath.Glob("testdata/*golden*")
	if err != nil {
		t.Fatal(err)
	}
	gotPaths := make(map[string]struct{})
	for _, path := range paths {
		if strings.Contains(filepath.Base(path), "alert-validation") || strings.Contains(filepath.Base(path), "runtime-configuration") || strings.Contains(filepath.Base(path), "deployment-hardening") || strings.Contains(filepath.Base(path), "ci-release") || strings.Contains(filepath.Base(path), "replay-calibration") || strings.Contains(filepath.Base(path), "scaling") {
			continue
		}
		gotPaths[filepath.ToSlash(path)] = struct{}{}
	}
	if !reflect.DeepEqual(gotPaths, wantPaths) {
		t.Fatalf("Compatibility baseline through Threat intelligence golden asset set changed\nwant: %v\ngot:  %v", alertValidationSortedSetKeys(wantPaths), alertValidationSortedSetKeys(gotPaths))
	}
}

func TestAlertValidationPrometheusAlertExactContract(t *testing.T) {
	current := dataIntegrityLoadAlertContract(t)
	if len(current.Groups) != len(alertValidationAlertGroupContract) {
		t.Fatalf("Prometheus alert validation alert groups=%d, want %d", len(current.Groups), len(alertValidationAlertGroupContract))
	}
	for index, want := range alertValidationAlertGroupContract {
		group := current.Groups[index]
		if group.Name != want.Name || group.Job != "openstack-instance-exporter" {
			t.Fatalf("Prometheus alert validation group %d identity=%q/%q, want %q/openstack-instance-exporter", index, group.Name, group.Job, want.Name)
		}
		if len(group.Rules) != want.Rules {
			t.Fatalf("Prometheus alert validation group %q rules=%d, want %d", group.Name, len(group.Rules), want.Rules)
		}
		markedOptional := strings.Contains(group.Name, "OPTIONAL Environment-Tuned")
		if (want.Policy == "optional-environment-tuned") != markedOptional {
			t.Fatalf("Prometheus alert validation group %q policy=%q optional marker=%v", group.Name, want.Policy, markedOptional)
		}
		for _, rule := range group.Rules {
			policy, hasPolicy := rule.Labels["policy"]
			if markedOptional {
				if !hasPolicy || policy != "environment-tuned" {
					t.Fatalf("optional rule %q policy label=%q present=%v, want environment-tuned", rule.Alert, policy, hasPolicy)
				}
			} else if hasPolicy {
				t.Fatalf("default rule %q unexpectedly has policy label %q", rule.Alert, policy)
			}
		}
	}
	dataIntegrityCompareGolden(t, alertValidationAlertContractGoldenPath, current)
}

func TestAlertValidationPrometheusAlertExpressionSHA256Contract(t *testing.T) {
	current := dataIntegrityLoadAlertContract(t)
	var got strings.Builder
	count := 0
	for _, group := range current.Groups {
		for _, rule := range group.Rules {
			digest := sha256.Sum256([]byte(rule.Expr))
			fmt.Fprintf(&got, "%s|%x\n", rule.Alert, digest)
			count++
		}
	}
	if count != 78 {
		t.Fatalf("Prometheus alert validation alert expression count=%d, want 78", count)
	}
	want, err := os.ReadFile(alertValidationAlertExpressionPath)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != string(want) {
		t.Fatalf("exact Prometheus alert validation final alert expression contract changed: %s\nwant:\n%s\ngot:\n%s", alertValidationAlertExpressionPath, want, got.String())
	}
}

func alertValidationLoadAlertGateContract(t *testing.T) map[string]string {
	t.Helper()
	content, err := os.ReadFile(alertValidationAlertGateGoldenPath)
	if err != nil {
		t.Fatal(err)
	}
	gates := make(map[string]string)
	for lineNumber, line := range strings.Split(strings.TrimSpace(string(content)), "\n") {
		alert, gate, ok := strings.Cut(line, "|")
		if !ok || alert == "" {
			t.Fatalf("%s:%d: invalid gate record %q", alertValidationAlertGateGoldenPath, lineNumber+1, line)
		}
		switch gate {
		case "none", "libvirt", "conntrack", "libvirt,conntrack":
		default:
			t.Fatalf("%s:%d: invalid gate class %q", alertValidationAlertGateGoldenPath, lineNumber+1, gate)
		}
		if _, duplicate := gates[alert]; duplicate {
			t.Fatalf("%s:%d: duplicate alert %q", alertValidationAlertGateGoldenPath, lineNumber+1, alert)
		}
		gates[alert] = gate
	}
	return gates
}

func alertValidationGateClass(sources dataIntegrityAlertGateSources) string {
	switch {
	case sources.Libvirt && sources.Conntrack:
		return "libvirt,conntrack"
	case sources.Libvirt:
		return "libvirt"
	case sources.Conntrack:
		return "conntrack"
	default:
		return "none"
	}
}

func TestAlertValidationPrometheusSourceHealthGateContract(t *testing.T) {
	current := dataIntegrityLoadAlertContract(t)
	gates := alertValidationLoadAlertGateContract(t)
	priorGates := dataIntegrityLoadAlertGateContract(t)
	seen := make(map[string]struct{}, len(gates))
	for _, group := range current.Groups {
		for _, rule := range group.Rules {
			gate, ok := gates[rule.Alert]
			if !ok {
				t.Fatalf("alert %q has no Prometheus alert validation source-health classification", rule.Alert)
			}
			seen[rule.Alert] = struct{}{}
			if prior, inherited := priorGates[rule.Alert]; inherited && gate != alertValidationGateClass(prior) {
				t.Fatalf("alert %q source-health class=%q, want inherited %q", rule.Alert, gate, alertValidationGateClass(prior))
			}
			withoutCohortGuards := alertValidationExpressionWithoutScrapeCohortGuards(rule.Expr)
			libvirtCount := alertValidationSourceGateCount(withoutCohortGuards, "oie_host_libvirt_ok")
			conntrackCount := alertValidationSourceGateCount(withoutCohortGuards, "oie_host_conntrack_raw_ok")
			wantLibvirt := gate == "libvirt" || gate == "libvirt,conntrack"
			wantConntrack := gate == "conntrack" || gate == "libvirt,conntrack"
			if (libvirtCount > 0) != wantLibvirt || (conntrackCount > 0) != wantConntrack {
				t.Fatalf("alert %q gate class=%q but direct Libvirt/conntrack gate counts=%d/%d", rule.Alert, gate, libvirtCount, conntrackCount)
			}
		}
	}
	if len(seen) != len(gates) {
		missing := make([]string, 0)
		for alert := range gates {
			if _, ok := seen[alert]; !ok {
				missing = append(missing, alert)
			}
		}
		sort.Strings(missing)
		t.Fatalf("Prometheus alert validation source-health contract references absent alerts: %v", missing)
	}
}

func TestAlertValidationPrometheusAlertWordingContract(t *testing.T) {
	current := dataIntegrityLoadAlertContract(t)
	approvedEvidenceWording := []string{
		"evidence consistent with",
		"observed sustained",
		"requires operator review",
		"potential",
		"suspected",
	}
	bannedClaims := []string{
		"is attacking",
		"definitely mining",
		"is malicious",
		"tenant is malicious",
		"thrashing storage",
		"is thrashing",
		"likely targeted attack",
		"indicating severe",
		"indicates severe",
		"indicating backend saturation",
		"indicates backend saturation",
		"brute-force/flood indicator",
		"worm/brute-force",
		"high security risk",
		"suggests heavy abuse",
		"strong scan/ddos indicator",
	}
	for groupIndex, group := range current.Groups {
		for _, rule := range group.Rules {
			if len(rule.Annotations) != 2 || rule.Annotations["description"] == "" || rule.Annotations["summary"] == "" {
				t.Fatalf("alert %q must have exactly non-empty description and summary annotations", rule.Alert)
			}
			wording := strings.ToLower(rule.Annotations["description"] + " " + rule.Annotations["summary"])
			for _, claim := range bannedClaims {
				if strings.Contains(wording, claim) {
					t.Fatalf("alert %q contains unsupported certainty claim %q", rule.Alert, claim)
				}
			}
			// Exporter/source-health rules report literal availability and freshness
			// facts. Inferential capacity, security, and workload claims must use an
			// evidence qualifier instead of overstating what telemetry proves.
			if groupIndex != 0 {
				approved := false
				for _, phrase := range approvedEvidenceWording {
					approved = approved || strings.Contains(wording, phrase)
				}
				if !approved {
					t.Fatalf("inferential alert %q does not use approved evidence wording", rule.Alert)
				}
			}
		}
	}
}

func TestAlertValidationREADMEContract(t *testing.T) {
	content, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	readme := string(content)
	link := "[`PROMETHEUS_ALERTS.md`](PROMETHEUS_ALERTS.md)"
	if got := strings.Count(readme, link); got != 1 {
		t.Fatalf("README Prometheus alert validation contract link count=%d, want 1", got)
	}
	for _, statement := range []string{
		"The v2.0.0 alert policy contains 82 definitions with 33 enabled by default and ten shared recording rules.",
		"The rendered one-group policy is tested for source health, persistence, recovery and incident identity.",
	} {
		if !strings.Contains(readme, statement) {
			t.Fatalf("README is missing Prometheus alert validation contract statement %q", statement)
		}
	}
}

func TestAlertValidationDocumentationContract(t *testing.T) {
	content, err := os.ReadFile("PROMETHEUS_ALERTS.md")
	if err != nil {
		t.Fatal(err)
	}
	contractText := string(content)
	for _, statement := range []string{
		"82 alert definitions",
		"Every alert name appears exactly once.",
		"All alert names from the published v1.2.0 baseline remain available.",
		"The default policy enables 33 alerts.",
		"Definitions marked `enabled: false` are omitted by the deployment template until an operator enables them.",
		"A generic high CPU, IOPS, bandwidth, connection-count, fan-out, or aggregate anomaly score is not proof of abuse.",
		"Render it with support for both `group_recording_rules` and each alert's `enabled` flag.",
		"Every alert includes an identity-specific `dashboard_path` with an evaluation-time window.",
		"Libvirt-dependent workload rules require current Libvirt health; conntrack-dependent rules require current conntrack health; mixed rules require both.",
		"A failed source interrupts pending workload alerts.",
		"Observed-window checks cannot establish that every wall-clock scrape happened.",
		"Current host CPU, memory and conntrack-capacity readings are omitted when unavailable rather than replayed as live host observations.",
		"`oie_host_collection_interval_seconds` reports the effective configured interval and uses exactly `15s` when an internal caller omits it.",
		"`oie_host_threat_feed_fresh` emits exactly five series on every scrape.",
		"Its exact `list` values are `TOREXIT`, `TORRELAY`, `EMERGING`, `CUSTOMLIST`, and `spamhaus`.",
		"A failed feed refresh never extends snapshot freshness.",
		"Exporter unavailability requires five minutes of failed scrapes.",
		"The corresponding warning predicates are disjoint from the critical predicates.",
		"Disk identity is preserved, so separate affected devices are separate incidents.",
		"Tor contact diagnostics are opt-in.",
		"Multiple ports on one VM form one incident.",
		"Retype monitoring is disabled by default.",
		"It is suppressed when the same operation is already ready-stalled.",
		"Every bundled rule has executable Prometheus lifecycle coverage.",
		"The operator tests exercise the rendered deployment template, enabled/disabled policy, recording rules, pending durations, source interruptions and recovery.",
	} {
		if !strings.Contains(contractText, statement) {
			t.Fatalf("Prometheus alert validation contract is missing %q", statement)
		}
	}
}

func TestAlertValidationPublicSurfaceChangesAreExact(t *testing.T) {
	t.Run("PrometheusRegistry", func(t *testing.T) {
		orderedLabels := compatibilityDescriptorLabelOrder(t)
		if got := len(orderedLabels); got != inventoryOIEFamilyCount || resourceTelemetryOIEFamilyCount != 134 {
			t.Fatalf("current Prometheus families=%d, want %d with frozen Resource telemetry count %d", got, inventoryOIEFamilyCount, resourceTelemetryOIEFamilyCount)
		}
		inherited := make(map[string]struct{}, resourceTelemetryOIEFamilyCount)
		for _, path := range []string{
			compatibilityOIEBaselineGoldenPath,
			dataIntegrityOIEAdditionsGoldenPath,
			resourceTelemetryOIEAdditionsGoldenPath,
		} {
			for _, line := range compatibilityReadNonEmptyLines(t, path) {
				inherited[compatibilityMetricNameFromSchemaLine(t, line)] = struct{}{}
			}
		}
		gotAdditions := make([]string, 0, alertValidationOIEFamilyCount-resourceTelemetryOIEFamilyCount)
		for name, labels := range orderedLabels {
			if _, exists := inherited[name]; !exists {
				if _, retype := laterMetricFamilyNames()[name]; !retype {
					gotAdditions = append(gotAdditions, name+"|"+labels)
				}
			}
		}
		sort.Strings(gotAdditions)
		wantAdditions := compatibilityReadNonEmptyLines(t, alertValidationMetricAdditionsPath)
		sort.Strings(wantAdditions)
		if !reflect.DeepEqual(gotAdditions, wantAdditions) {
			t.Fatalf("Prometheus alert validation metric additions changed\nwant: %v\ngot:  %v", wantAdditions, gotAdditions)
		}

		families, _ := dataIntegrityFullRegistryFixture(t)
		fullSchema := compatibilityOIESchemaByName(t, families, orderedLabels)
		gotSchema := make([]string, 0, len(wantAdditions))
		for _, addition := range wantAdditions {
			name := compatibilityMetricNameFromSchemaLine(t, addition)
			line, ok := fullSchema[name]
			if !ok {
				t.Fatalf("Prometheus alert validation metric %s was described but not gathered", name)
			}
			gotSchema = append(gotSchema, line)
		}
		sort.Strings(gotSchema)
		wantSchema := compatibilityReadNonEmptyLines(t, alertValidationMetricSchemaPath)
		sort.Strings(wantSchema)
		if !reflect.DeepEqual(gotSchema, wantSchema) {
			t.Fatalf("Prometheus alert validation metric type/help/label schema changed\nwant: %v\ngot:  %v", wantSchema, gotSchema)
		}
	})

	t.Run("CLI", func(t *testing.T) {
		contractPath := filepath.Join(t.TempDir(), "cli-flags.contract")
		cmd := exec.Command(os.Args[0], "-test.run=^TestDataIntegrityCLIFlagContractSubprocess$")
		cmd.Env = append(os.Environ(),
			dataIntegrityFlagContractHelperEnv+"=1",
			dataIntegrityFlagContractOutputEnv+"="+contractPath,
			dataIntegrityFlagProbeConfigEnv+"="+filepath.Join(t.TempDir(), "missing-behavior-ports.yaml"),
		)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("collect Prometheus alert validation runtime CLI contract: %v\n%s", err, output)
		}
		got, err := os.ReadFile(contractPath)
		if err != nil {
			t.Fatal(err)
		}
		want := append(compatibilityReadNonEmptyLines(t, "testdata/cli-flags-baseline.golden"), compatibilityReadNonEmptyLines(t, threatIntelligenceCLIFlagAdditionsGoldenPath)...)
		want = append(want, compatibilityReadNonEmptyLines(t, runtimeConfigurationCLIFlagAdditionsGoldenPath)...)
		want = append(want, volumeRetypeCLIFlagAddition)
		sort.Strings(want)
		if strings.TrimSpace(string(got)) != strings.Join(want, "\n") {
			t.Fatalf("runtime CLI contract changed outside inherited Prometheus alert validation and exact Runtime configuration additions\nwant:\n%s\ngot:\n%s", strings.Join(want, "\n"), got)
		}
	})

	t.Run("Ansible", func(t *testing.T) {
		content, err := os.ReadFile(dataIntegrityAnsibleGoldenPath)
		if err != nil {
			t.Fatal(err)
		}
		var inherited dataIntegrityAnsibleRoleContract
		if err := dataIntegrityDecodeSingleJSON(content, &inherited); err != nil {
			t.Fatal(err)
		}
		want := append([]string(nil), inherited.PublicVariables...)
		want = append(want, compatibilityReadNonEmptyLines(t, threatIntelligenceAnsibleAdditionsGoldenPath)...)
		want = append(want,
			"openstack_instance_exporter_archive_src",
			"openstack_instance_exporter_download_url",
			"openstack_instance_exporter_volume_retype_enable",
		)
		sort.Strings(want)
		got := dataIntegrityLoadAnsibleRoleContract(t).PublicVariables
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("Prometheus alert validation Ansible public variables changed\nwant: %v\ngot:  %v", want, got)
		}
	})

	t.Run("ThreatFeeds", func(t *testing.T) {
		manager := &ThreatManager{}
		providers := newThreatProviders(manager, CollectorConfig{})
		got := []string{"Spamhaus"}
		for _, provider := range providers {
			got = append(got, provider.Name)
		}
		want := []string{"Spamhaus", "TorExit", "TorRelay", "EmergingThreats", "CustomList"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("Prometheus alert validation threat feeds=%v, want frozen %v", got, want)
		}
	})

	t.Run("StructuredLogs", func(t *testing.T) {
		// The Compatibility baseline discovery contract already composes the frozen Threat intelligence
		// additions. Re-running it here proves Prometheus alert validation introduced no callsite,
		// event, or field beyond that exact inherited schema.
		TestCompatibilityStructuredLogProductionCallsitesMatchGolden(t)
	})
}
