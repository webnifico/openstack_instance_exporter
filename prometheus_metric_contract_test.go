package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	dto "github.com/prometheus/client_model/go"
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

func normalizeRuntimeMetricHelp(schema string) string {
	for _, line := range []string{
		"go_gc_gogc_percent|type=GAUGE|help=Heap size target percentage configured by the user, otherwise 100. This value is set by the GOGC environment variable, and the runtime/debug.SetGCPercent function. Sourced from /gc/gogc:percent",
		"go_gc_gomemlimit_bytes|type=GAUGE|help=Go runtime memory limit configured by the user, otherwise math.MaxInt64. This value is set by the GOMEMLIMIT environment variable, and the runtime/debug.SetMemoryLimit function. Sourced from /gc/gomemlimit:bytes",
		"go_sched_gomaxprocs_threads|type=GAUGE|help=The current runtime.GOMAXPROCS setting, or the number of operating system threads that can execute user-level Go code simultaneously. Sourced from /sched/gomaxprocs:threads",
	} {
		schema = strings.ReplaceAll(schema, line+".|labels=", line+"|labels=")
	}
	return schema
}

func TestReleasePrometheusMetricSchema(t *testing.T) {
	ordered := compatibilityDescriptorLabelOrder(t)
	families, _ := dataIntegrityFullRegistryFixture(t)
	schema := compatibilityOIESchemaByName(t, families, ordered)
	got := make([]string, 0, len(schema))
	for _, line := range schema {
		got = append(got, line)
	}
	sort.Strings(got)
	want := compatibilityReadNonEmptyLines(t, "testdata/contracts/metric-schema.txt")
	compatibilityAssertStringsEqual(t, "release metric type, help and ordered labels", got, want)
}

func TestCorrectedMetricHelpAndDocumentationSemantics(t *testing.T) {
	families, _ := dataIntegrityFullRegistryFixture(t)
	helpByName := make(map[string]string, len(families))
	for _, family := range families {
		helpByName[family.GetName()] = family.GetHelp()
	}
	wantHelp := map[string]string{
		"oie_instance_mem_rss_mib":          "Libvirt-reported resident set size of the process running this instance in mebibytes; includes resident process mappings and is not unique physical host RAM consumption",
		"oie_host_conntrack_stale_seconds": "Seconds since the last successful conntrack read; -1 before the first success",
	}
	for name, want := range wantHelp {
		if got := helpByName[name]; got != strings.ReplaceAll(want, "fresh or retained severity value", "fresh or retained measurement") {
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
	for _, statement := range []string{
		"not unique physical host RAM consumption",
		"`_mib` and `_gib` use MiB and GiB",
		"(testdata/contracts/metric-schema.txt)",
	} {
		if !strings.Contains(readme, statement) {
			t.Errorf("README omits metric interpretation guidance %q", statement)
		}
	}
}
