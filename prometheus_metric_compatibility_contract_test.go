package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	dto "github.com/prometheus/client_model/go"
)

const (
	compatibilityOIEBaselineFamilyCount     = 127
	compatibilityOIEBaselineGoldenPath      = "testdata/compatibility-oie-prometheus-metric-contract-baseline.golden"
	dataIntegrityOIEFamilyCount             = 130
	dataIntegrityOIEAdditionsGoldenPath     = "testdata/metrics-v2.0.0-data-integrity-additions.golden"
	resourceTelemetryOIEFamilyCount         = 134
	resourceTelemetryOIEAdditionsGoldenPath = "testdata/metrics-v2.0.0-resource-telemetry-additions.golden"
)

func compatibilityDescriptorLabelOrder(t *testing.T) map[string]string {
	t.Helper()

	descriptors, _ := descriptorContract(t)
	labelsByName := make(map[string]string, len(descriptors))
	for _, descriptor := range descriptors {
		name, labels, ok := strings.Cut(descriptor, "|")
		if !ok || name == "" {
			t.Fatalf("invalid descriptor contract line %q", descriptor)
		}
		if _, duplicate := labelsByName[name]; duplicate {
			t.Fatalf("duplicate descriptor contract for %s", name)
		}
		labelsByName[name] = labels
	}
	return labelsByName
}

func compatibilitySortedLabelNames(labels string) string {
	if labels == "" {
		return ""
	}
	values := strings.Split(labels, ",")
	sort.Strings(values)
	return strings.Join(values, ",")
}

func compatibilityGatheredLabelNames(familyLabelNames map[string]struct{}) string {
	labels := make([]string, 0, len(familyLabelNames))
	for label := range familyLabelNames {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	return strings.Join(labels, ",")
}

func compatibilityReadNonEmptyLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\n")
}

func compatibilityOIESchemaByName(t *testing.T, families []*dto.MetricFamily, orderedLabels map[string]string) map[string]string {
	t.Helper()

	schemaByName := make(map[string]string, len(orderedLabels))
	for _, family := range families {
		name := family.GetName()
		if !strings.HasPrefix(name, "oie_") {
			continue
		}
		if _, duplicate := schemaByName[name]; duplicate {
			t.Fatalf("duplicate gathered OIE metric family %s", name)
		}

		labelOrder, described := orderedLabels[name]
		if !described {
			t.Fatalf("gathered OIE metric family %s has no exporter descriptor", name)
		}

		gatheredLabelSet := make(map[string]struct{})
		for _, metric := range family.Metric {
			for _, label := range metric.Label {
				gatheredLabelSet[label.GetName()] = struct{}{}
			}
		}
		if got, want := compatibilityGatheredLabelNames(gatheredLabelSet), compatibilitySortedLabelNames(labelOrder); got != want {
			t.Fatalf("metric family %s gathered labels=%q, descriptor labels=%q", name, got, labelOrder)
		}

		schemaByName[name] = fmt.Sprintf(
			"%s|type=%s|help=%s|labels=%s",
			name,
			family.GetType().String(),
			family.GetHelp(),
			labelOrder,
		)
	}
	return schemaByName
}

func compatibilityMetricNameFromSchemaLine(t *testing.T, line string) string {
	t.Helper()
	name, _, ok := strings.Cut(line, "|")
	if !ok || name == "" {
		t.Fatalf("invalid metric schema line %q", line)
	}
	return name
}

func normalizeHistoricalMetricHelp(schema string) string {
	// Frozen compatibility contracts preserve the exact wording shipped by
	// earlier releases. Production HELP may correct a misleading description
	// without changing the metric name, type, labels, or numeric semantics.
	// client_golang 1.21+ adds a final period to these three runtime HELP
	// strings. Match the complete known lines so other schema drift still fails.
	for _, line := range []string{
		"go_gc_gogc_percent|type=GAUGE|help=Heap size target percentage configured by the user, otherwise 100. This value is set by the GOGC environment variable, and the runtime/debug.SetGCPercent function. Sourced from /gc/gogc:percent",
		"go_gc_gomemlimit_bytes|type=GAUGE|help=Go runtime memory limit configured by the user, otherwise math.MaxInt64. This value is set by the GOMEMLIMIT environment variable, and the runtime/debug.SetMemoryLimit function. Sourced from /gc/gomemlimit:bytes",
		"go_sched_gomaxprocs_threads|type=GAUGE|help=The current runtime.GOMAXPROCS setting, or the number of operating system threads that can execute user-level Go code simultaneously. Sourced from /sched/gomaxprocs:threads",
	} {
		schema = strings.ReplaceAll(schema, line+".|labels=", line+"|labels=")
	}
	return strings.NewReplacer(
		"help=Libvirt block allocation boundary in bytes (offset of the highest written sector); not backend physical usage", "help=Physical space used on storage",
		"help=Disk read gibibytes; metric name retained for compatibility", "help=Disk read gigabytes",
		"help=Disk write gibibytes; metric name retained for compatibility", "help=Disk write gigabytes",
		"help=Network receive gibibytes; metric name retained for compatibility", "help=Network receive gigabytes",
		"help=Network transmit gibibytes; metric name retained for compatibility", "help=Network transmit gigabytes",
		"help=Allocated memory for this instance in mebibytes; metric name retained for compatibility", "help=Allocated memory for this instance (MB)",
		"help=Guest-view used memory for this instance in mebibytes; metric name retained for compatibility", "help=Guest-view used memory for this instance (MB)",
		"help=Libvirt-reported resident set size of the process running this instance in mebibytes; includes resident process mappings and is not unique physical host RAM consumption; metric name retained for compatibility", "help=Resident Set Size (Actual Host RAM used) (MB)",
		"help=Seconds since the last successful conntrack read; -1 before the first success", "help=Seconds since last successful conntrack read",
		"help=Total physical memory on this hypervisor in mebibytes; metric name retained for compatibility", "help=Total physical memory on this hypervisor (MB)",
		"help=Free host memory (MemFree) in mebibytes; metric name retained for compatibility", "help=Free host memory (MemFree) in MB",
		"help=Available host memory (MemAvailable) in mebibytes; metric name retained for compatibility", "help=Available host memory (MemAvailable) in MB",
		"help=Total vCPU host-scheduler runqueue delay exposed to the guest as steal time", "help=Total time vCPU spent waiting on Host Scheduler",
		"help=Compatibility counter for total vCPU host-scheduler runqueue wait; an alternative to delay/steal, not guest I/O wait", "help=Total time vCPU spent waiting on I/O",
	).Replace(schema)
}

func TestCompatibilityOIEPrometheusMetricContract(t *testing.T) {
	orderedLabels := compatibilityDescriptorLabelOrder(t)
	families, _ := dataIntegrityFullRegistryFixture(t)
	currentSchema := compatibilityOIESchemaByName(t, families, orderedLabels)
	compatibilityLines := compatibilityReadNonEmptyLines(t, compatibilityOIEBaselineGoldenPath)
	if len(compatibilityLines) != compatibilityOIEBaselineFamilyCount {
		t.Fatalf("Compatibility baseline golden families=%d, want %d", len(compatibilityLines), compatibilityOIEBaselineFamilyCount)
	}

	for _, want := range compatibilityLines {
		name := compatibilityMetricNameFromSchemaLine(t, want)
		got, exists := currentSchema[name]
		if !exists {
			t.Fatalf("Compatibility baseline metric family %s was removed", name)
		}
		got = normalizeHistoricalMetricHelp(got)
		if got != want {
			t.Fatalf("Compatibility baseline metric family %s changed\nwant: %s\ngot:  %s", name, want, got)
		}
	}
}

func TestDataIntegrityOIEPrometheusMetricAdditions(t *testing.T) {
	orderedLabels := compatibilityDescriptorLabelOrder(t)
	compatibilityNames := make(map[string]struct{}, compatibilityOIEBaselineFamilyCount)
	for _, line := range compatibilityReadNonEmptyLines(t, compatibilityOIEBaselineGoldenPath) {
		compatibilityNames[compatibilityMetricNameFromSchemaLine(t, line)] = struct{}{}
	}
	laterNames := make(map[string]struct{}, alertValidationOIEFamilyCount-dataIntegrityOIEFamilyCount)
	for _, path := range []string{resourceTelemetryOIEAdditionsGoldenPath, alertValidationMetricAdditionsPath} {
		for _, line := range goldenLines(t, path) {
			name, _, ok := strings.Cut(line, "|")
			if !ok || name == "" {
				t.Fatalf("invalid later metric addition %q", line)
			}
			laterNames[name] = struct{}{}
		}
	}
	for name := range laterMetricFamilyNames() {
		laterNames[name] = struct{}{}
	}
	gotAdditions := make([]string, 0, dataIntegrityOIEFamilyCount-compatibilityOIEBaselineFamilyCount)
	for name, labels := range orderedLabels {
		if _, inherited := compatibilityNames[name]; !inherited {
			if _, later := laterNames[name]; !later {
				gotAdditions = append(gotAdditions, name+"|"+labels)
			}
		}
	}
	sort.Strings(gotAdditions)
	wantAdditions := goldenLines(t, dataIntegrityOIEAdditionsGoldenPath)
	sort.Strings(wantAdditions)
	if strings.Join(gotAdditions, "\n") != strings.Join(wantAdditions, "\n") {
		t.Fatalf("v2.0.0 Data integrity metric additions changed\nwant:\n%s\n\ngot:\n%s", strings.Join(wantAdditions, "\n"), strings.Join(gotAdditions, "\n"))
	}
}

func TestResourceTelemetryOIEPrometheusMetricAdditions(t *testing.T) {
	orderedLabels := compatibilityDescriptorLabelOrder(t)
	if len(orderedLabels) != inventoryOIEFamilyCount {
		t.Fatalf("current exporter descriptor families=%d, want %d", len(orderedLabels), inventoryOIEFamilyCount)
	}

	families, descriptorNames := dataIntegrityFullRegistryFixture(t)
	if len(descriptorNames) != inventoryOIEFamilyCount {
		t.Fatalf("production fixture descriptors=%d, want %d", len(descriptorNames), inventoryOIEFamilyCount)
	}
	if got := len(compatibilityOIESchemaByName(t, families, orderedLabels)); got != inventoryOIEFamilyCount {
		t.Fatalf("gathered OIE metric families=%d, want %d", got, inventoryOIEFamilyCount)
	}

	inherited := make(map[string]struct{}, dataIntegrityOIEFamilyCount)
	for _, line := range compatibilityReadNonEmptyLines(t, compatibilityOIEBaselineGoldenPath) {
		inherited[compatibilityMetricNameFromSchemaLine(t, line)] = struct{}{}
	}
	for _, line := range goldenLines(t, dataIntegrityOIEAdditionsGoldenPath) {
		name, _, ok := strings.Cut(line, "|")
		if !ok || name == "" {
			t.Fatalf("invalid Data integrity addition %q", line)
		}
		inherited[name] = struct{}{}
	}
	alertValidationNames := make(map[string]struct{}, alertValidationOIEFamilyCount-resourceTelemetryOIEFamilyCount)
	for _, line := range goldenLines(t, alertValidationMetricAdditionsPath) {
		name, _, ok := strings.Cut(line, "|")
		if !ok || name == "" {
			t.Fatalf("invalid Prometheus alert validation addition %q", line)
		}
		alertValidationNames[name] = struct{}{}
	}

	gotAdditions := make([]string, 0, resourceTelemetryOIEFamilyCount-dataIntegrityOIEFamilyCount)
	for name, labels := range orderedLabels {
		if _, exists := inherited[name]; !exists {
			if _, alertValidation := alertValidationNames[name]; !alertValidation {
				if _, retype := laterMetricFamilyNames()[name]; !retype {
					gotAdditions = append(gotAdditions, name+"|"+labels)
				}
			}
		}
	}
	sort.Strings(gotAdditions)
	wantAdditions := goldenLines(t, resourceTelemetryOIEAdditionsGoldenPath)
	sort.Strings(wantAdditions)
	if strings.Join(gotAdditions, "\n") != strings.Join(wantAdditions, "\n") {
		t.Fatalf("v2.0.0 Resource telemetry metric additions changed\nwant:\n%s\n\ngot:\n%s", strings.Join(wantAdditions, "\n"), strings.Join(gotAdditions, "\n"))
	}
}

func TestCorrectedMetricHelpAndDocumentationSemantics(t *testing.T) {
	families, _ := dataIntegrityFullRegistryFixture(t)
	helpByName := make(map[string]string, len(families))
	for _, family := range families {
		helpByName[family.GetName()] = family.GetHelp()
	}
	wantHelp := map[string]string{
		"oie_instance_mem_rss_mb":          "Libvirt-reported resident set size of the process running this instance in mebibytes; includes resident process mappings and is not unique physical host RAM consumption; metric name retained for compatibility",
		"oie_host_conntrack_stale_seconds": "Seconds since the last successful conntrack read; -1 before the first success",
	}
	for name, want := range wantHelp {
		if got := helpByName[name]; got != want {
			t.Errorf("metric %s HELP=%q, want %q", name, got, want)
		}
	}

	content, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	readme := string(content)
	if strings.Contains(readme, "over the last scrape interval") {
		t.Error("README still describes exporter-derived rates as scrape-interval calculations")
	}
	if got := strings.Count(readme, "over the last successful exporter collection interval"); got != 6 {
		t.Errorf("README collection-interval descriptions=%d, want 6", got)
	}
	if got := strings.Count(strings.ToLower(readme), "seconds since the last successful conntrack read; `-1` before the first success"); got != 3 {
		t.Errorf("README conntrack stale-sentinel descriptions=%d, want 3", got)
	}
}
