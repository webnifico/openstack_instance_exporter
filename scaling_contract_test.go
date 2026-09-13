package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

const (
	scalingPriorGoldenSHA256Path = "testdata/scaling-prior-golden-sha256.golden"
	scalingMeasurementsPath      = "testdata/scaling-reference-measurements.json"
)

type scalingReferenceMeasurements struct {
	SchemaVersion     int                           `json:"schema_version"`
	MeasurementDate   string                        `json:"measurement_date"`
	Environment       scalingMeasurementEnvironment `json:"environment"`
	Benchmark         scalingMeasurementRun         `json:"benchmark"`
	Workloads         []scalingWorkloadMeasurement  `json:"workloads"`
	Cleanup           []scalingCleanupMeasurement   `json:"cleanup"`
	RemoteSaturation  []scalingRemoteMeasurement    `json:"remote_cardinality_saturation"`
	SupportedEnvelope scalingSupportedEnvelope      `json:"supported_envelope"`
}

type scalingMeasurementEnvironment struct {
	GoVersion   string `json:"go_version"`
	GOOS        string `json:"goos"`
	GOARCH      string `json:"goarch"`
	Kernel      string `json:"kernel"`
	CPUModel    string `json:"cpu_model"`
	LogicalCPUs int    `json:"logical_cpus"`
	MemoryBytes uint64 `json:"memory_bytes"`
}

type scalingMeasurementRun struct {
	Runs                      int     `json:"runs"`
	BenchtimeIterations       int     `json:"benchtime_iterations"`
	CollectionIntervalSeconds float64 `json:"collection_interval_seconds"`
	MaxRSSBytes               uint64  `json:"max_rss_bytes"`
	UserCPUSeconds            float64 `json:"user_cpu_seconds"`
	SystemCPUSeconds          float64 `json:"system_cpu_seconds"`
}

type scalingWorkloadMeasurement struct {
	ConntrackEntries          int     `json:"conntrack_entries"`
	ActiveDomains             int     `json:"active_domains"`
	RawNetlinkParseP95MS      float64 `json:"raw_netlink_parse_p95_ms"`
	ConntrackAggregationP95MS float64 `json:"conntrack_aggregation_p95_ms"`
	LibvirtCollectionP95MS    float64 `json:"libvirt_collection_p95_ms"`
	TotalCollectionP95MS      float64 `json:"total_collection_p95_ms"`
	ConservativePipelineP95MS float64 `json:"conservative_pipeline_p95_ms"`
	HeapBytesPerCollection    uint64  `json:"heap_bytes_per_collection"`
	AllocationsPerCollection  uint64  `json:"allocations_per_collection"`
	ExportedSeries            int     `json:"exported_series"`
	BehaviorStateEntries      int     `json:"behavior_state_entries"`
	MiningStateEntries        int     `json:"mining_state_entries"`
	ThreatStateEntries        int     `json:"threat_state_entries"`
}

type scalingCleanupMeasurement struct {
	Instances   int     `json:"instances"`
	P95MS       float64 `json:"p95_ms"`
	HeapBytes   uint64  `json:"heap_bytes"`
	Allocations uint64  `json:"allocations"`
}

type scalingRemoteMeasurement struct {
	UniqueRemotes int     `json:"unique_remotes"`
	P95MS         float64 `json:"p95_ms"`
	RetainedState int     `json:"retained_state"`
}

type scalingSupportedEnvelope struct {
	MaxConntrackEntries              int     `json:"max_conntrack_entries"`
	MaxActiveDomains                 int     `json:"max_active_domains"`
	MinimumCollectionIntervalSeconds float64 `json:"minimum_collection_interval_seconds"`
	P95BudgetFraction                float64 `json:"p95_budget_fraction"`
}

func scalingLoadMeasurements(t *testing.T) scalingReferenceMeasurements {
	t.Helper()
	data, err := os.ReadFile(scalingMeasurementsPath)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var measurements scalingReferenceMeasurements
	if err := decoder.Decode(&measurements); err != nil {
		t.Fatal(err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err != nil {
			t.Fatalf("decode trailing measurement data: %v", err)
		}
		t.Fatal("reference measurement file contains trailing JSON")
	}
	return measurements
}

func TestScalingPriorGoldenAssetsAreByteFrozen(t *testing.T) {
	manifest, err := os.ReadFile(scalingPriorGoldenSHA256Path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(manifest)), "\n")
	if len(lines) != 41 {
		t.Fatalf("prior golden hash records=%d, want 41", len(lines))
	}
	wantPaths := make(map[string]struct{}, len(lines))
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 2 || len(fields[0]) != 64 || !strings.HasPrefix(fields[1], "testdata/") {
			t.Fatalf("invalid prior-golden hash record %q", line)
		}
		if _, duplicate := wantPaths[fields[1]]; duplicate {
			t.Fatalf("duplicate prior-golden hash path %q", fields[1])
		}
		content, err := os.ReadFile(fields[1])
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(content)); got != fields[0] {
			t.Fatalf("frozen golden %s changed: sha256=%s want=%s", fields[1], got, fields[0])
		}
		wantPaths[fields[1]] = struct{}{}
	}

	paths, err := filepath.Glob("testdata/*golden*")
	if err != nil {
		t.Fatal(err)
	}
	gotPaths := make(map[string]struct{})
	for _, path := range paths {
		if strings.Contains(filepath.Base(path), "scaling") {
			continue
		}
		gotPaths[filepath.ToSlash(path)] = struct{}{}
	}
	if !reflect.DeepEqual(gotPaths, wantPaths) {
		t.Fatalf("Compatibility baseline through Replay calibration golden asset set changed\nwant: %v\ngot:  %v", wantPaths, gotPaths)
	}
}

func TestScalingReferenceMeasurementsCoverProductionScale(t *testing.T) {
	measurements := scalingLoadMeasurements(t)
	if measurements.SchemaVersion != 1 || measurements.MeasurementDate == "" {
		t.Fatalf("invalid measurement identity: schema=%d date=%q", measurements.SchemaVersion, measurements.MeasurementDate)
	}
	environment := measurements.Environment
	if environment.GoVersion == "" || environment.GOOS == "" || environment.GOARCH == "" || environment.Kernel == "" || environment.CPUModel == "" || environment.LogicalCPUs <= 0 || environment.MemoryBytes == 0 {
		t.Fatalf("incomplete measurement environment: %+v", environment)
	}
	run := measurements.Benchmark
	if run.Runs < 5 || run.BenchtimeIterations != 1 || run.CollectionIntervalSeconds <= 0 || run.MaxRSSBytes == 0 || run.UserCPUSeconds <= 0 || run.SystemCPUSeconds < 0 {
		t.Fatalf("incomplete benchmark run metadata: %+v", run)
	}

	wantScales := [][2]int{
		{100_000, 100},
		{500_000, 500},
		{1_000_000, 1_000},
		{2_000_000, 1_000},
	}
	if len(measurements.Workloads) != len(wantScales) {
		t.Fatalf("workloads=%d, want %d", len(measurements.Workloads), len(wantScales))
	}
	previousSeries := 0
	for index, want := range wantScales {
		got := measurements.Workloads[index]
		if got.ConntrackEntries != want[0] || got.ActiveDomains != want[1] {
			t.Fatalf("workload[%d]=%d/%d, want %d/%d", index, got.ConntrackEntries, got.ActiveDomains, want[0], want[1])
		}
		if got.RawNetlinkParseP95MS <= 0 || got.ConntrackAggregationP95MS <= 0 || got.LibvirtCollectionP95MS <= 0 || got.TotalCollectionP95MS <= 0 {
			t.Fatalf("workload[%d] has non-positive duration: %+v", index, got)
		}
		wantConservative := got.RawNetlinkParseP95MS + got.TotalCollectionP95MS
		if math.Abs(got.ConservativePipelineP95MS-wantConservative) > 0.01 {
			t.Fatalf("workload[%d] conservative p95=%f, want raw+total=%f", index, got.ConservativePipelineP95MS, wantConservative)
		}
		if got.HeapBytesPerCollection == 0 || got.AllocationsPerCollection == 0 || got.ExportedSeries <= 0 || got.BehaviorStateEntries < 0 || got.MiningStateEntries < 0 || got.ThreatStateEntries < 0 {
			t.Fatalf("workload[%d] has invalid memory/cardinality/state data: %+v", index, got)
		}
		if got.ExportedSeries < previousSeries {
			t.Fatalf("workload[%d] series=%d regressed below prior scale %d", index, got.ExportedSeries, previousSeries)
		}
		previousSeries = got.ExportedSeries
	}

	if len(measurements.Cleanup) != 3 || len(measurements.RemoteSaturation) != 4 {
		t.Fatalf("cleanup/remote sample counts=%d/%d, want 3/4", len(measurements.Cleanup), len(measurements.RemoteSaturation))
	}
	for index, domains := range []int{100, 500, 1_000} {
		got := measurements.Cleanup[index]
		if got.Instances != domains || got.P95MS <= 0 || got.HeapBytes == 0 || got.Allocations == 0 {
			t.Fatalf("cleanup[%d] invalid: %+v", index, got)
		}
	}
	for index, entries := range []int{100_000, 500_000, 1_000_000, 2_000_000} {
		got := measurements.RemoteSaturation[index]
		if got.UniqueRemotes != entries || got.P95MS <= 0 || got.RetainedState != maxRemoteMapSize {
			t.Fatalf("remote saturation[%d] invalid: %+v", index, got)
		}
	}

	envelope := measurements.SupportedEnvelope
	if envelope.MaxConntrackEntries <= 0 || envelope.MaxActiveDomains <= 0 || envelope.MinimumCollectionIntervalSeconds <= 0 || envelope.P95BudgetFraction <= 0 || envelope.P95BudgetFraction > 0.5 {
		t.Fatalf("invalid supported envelope: %+v", envelope)
	}
	matched := false
	for _, workload := range measurements.Workloads {
		if workload.ConntrackEntries == envelope.MaxConntrackEntries && workload.ActiveDomains == envelope.MaxActiveDomains {
			matched = true
			budgetMS := envelope.MinimumCollectionIntervalSeconds * 1000 * envelope.P95BudgetFraction
			if workload.ConservativePipelineP95MS >= budgetMS {
				t.Fatalf("supported workload p95 %.3fms is not below %.0f%% budget %.3fms", workload.ConservativePipelineP95MS, envelope.P95BudgetFraction*100, budgetMS)
			}
		}
	}
	if !matched {
		t.Fatalf("supported envelope %d/%d is not a measured workload", envelope.MaxConntrackEntries, envelope.MaxActiveDomains)
	}
}

func TestScalingBenchmarkHarnessInventory(t *testing.T) {
	source, err := os.ReadFile("scaling_benchmark_test.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, name := range []string{
		"BenchmarkScalingRawNetlinkParse", "BenchmarkScalingConntrackAggregation",
		"BenchmarkScalingRemoteCardinalitySaturation", "BenchmarkScalingLibvirtDomainCollection",
		"BenchmarkScalingTotalCollection", "BenchmarkScalingDeletionCleanup",
		"TestScalingCollectionCyclesCannotOverlap", "TestScalingSeriesCardinalityGrowsLinearly",
		"TestScalingBehaviorEvidenceMapsRemainHardBounded", "TestScalingDeletionAndExpirationReclaimOwnedState",
		"TestScalingIncompleteScaleCyclePreservesLastGoodAndRecovers", "TestScalingStructuredThreatLogVolumeIsCollectionBounded",
	} {
		if !strings.Contains(text, "func "+name+"(") {
			t.Errorf("Scaling harness is missing %s", name)
		}
	}
	for _, scale := range []string{"100_000", "500_000", "1_000_000", "2_000_000"} {
		if !strings.Contains(text, scale) {
			t.Errorf("Scaling harness is missing scale %s", scale)
		}
	}
}

func TestScalingScaleGateIsRequiredAndRepeatedInExtendedCI(t *testing.T) {
	makefile, err := os.ReadFile("Makefile")
	if err != nil {
		t.Fatal(err)
	}
	makeText := string(makefile)
	if !strings.Contains(makeText, "scale:") || !strings.Contains(makeText, "check: vet test coverage test-race test-shuffle fuzz contracts replay scale docs ansible-test") {
		t.Fatal("Makefile does not make the Scaling scale gate mandatory")
	}

	required := ciReleaseLoadWorkflow(t, ".github/workflows/ci.yml")
	extended := ciReleaseLoadWorkflow(t, ".github/workflows/extended.yml")
	countExact := func(workflow ciReleaseWorkflow, command string) int {
		count := 0
		for _, job := range workflow.Jobs {
			for _, step := range job.Steps {
				if strings.TrimSpace(step.Run) == command {
					count++
				}
			}
		}
		return count
	}
	if got := countExact(required, "make scale"); got != 1 {
		t.Fatalf("required CI exact make scale steps=%d, want 1", got)
	}
	if got := countExact(extended, "make scale SCALE_COUNT=5"); got != 1 {
		t.Fatalf("extended CI exact repeated scale steps=%d, want 1", got)
	}
	if strings.Contains(ciReleaseWorkflowCommands(extended), "go test -run='^$' -bench=.") {
		t.Fatal("extended CI retained the unbounded generic benchmark command")
	}
}

func TestScalingScalingDocumentStatesMeasuredBoundaries(t *testing.T) {
	data, err := os.ReadFile("SCALING_LIMITS.md")
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ToLower(string(data))
	for _, phrase := range []string{
		"100,000", "500,000", "1,000,000", "2,000,000", "1,000 active domains",
		"supported envelope", "p95", "resident memory", "exported series", "last-good",
		"no uncontrolled overlap", "bounded logging", "o(log n)", "synthetic",
	} {
		if !strings.Contains(text, phrase) {
			t.Errorf("Scaling scaling document is missing %q", phrase)
		}
	}
}

func TestScalingPublicExporterSurfacesStayFrozen(t *testing.T) {
	if got := len(compatibilityDescriptorLabelOrder(t)); got != inventoryOIEFamilyCount {
		t.Fatalf("current Prometheus families=%d, want %d", got, inventoryOIEFamilyCount)
	}
	wantCLI := append(compatibilityReadNonEmptyLines(t, "testdata/cli-flags-baseline.golden"), compatibilityReadNonEmptyLines(t, threatIntelligenceCLIFlagAdditionsGoldenPath)...)
	wantCLI = append(wantCLI, compatibilityReadNonEmptyLines(t, runtimeConfigurationCLIFlagAdditionsGoldenPath)...)
	wantCLI = append(wantCLI, volumeRetypeCLIFlagAddition)
	sort.Strings(wantCLI)
	if got := compatibilityRuntimeCLIContract(t); !reflect.DeepEqual(got, wantCLI) {
		t.Fatalf("Scaling changed the exporter CLI\nwant: %v\ngot:  %v", wantCLI, got)
	}
}
