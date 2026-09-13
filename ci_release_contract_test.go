package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const ciReleasePriorGoldenSHA256Path = "testdata/ci-release-prior-golden-sha256.golden"

type ciReleaseWorkflow struct {
	Name        string                          `yaml:"name"`
	On          map[string]any                  `yaml:"on"`
	Permissions map[string]string               `yaml:"permissions"`
	Concurrency ciReleaseWorkflowConcurrency    `yaml:"concurrency"`
	Env         map[string]string               `yaml:"env"`
	Jobs        map[string]ciReleaseWorkflowJob `yaml:"jobs"`
}

type ciReleaseWorkflowConcurrency struct {
	Group            string `yaml:"group"`
	CancelInProgress any    `yaml:"cancel-in-progress"`
}

type ciReleaseWorkflowJob struct {
	Name           string                    `yaml:"name"`
	If             string                    `yaml:"if"`
	Needs          any                       `yaml:"needs"`
	RunsOn         any                       `yaml:"runs-on"`
	TimeoutMinutes int                       `yaml:"timeout-minutes"`
	Strategy       ciReleaseWorkflowStrategy `yaml:"strategy"`
	Steps          []ciReleaseWorkflowStep   `yaml:"steps"`
}

type ciReleaseWorkflowStrategy struct {
	FailFast bool                    `yaml:"fail-fast"`
	Matrix   ciReleaseWorkflowMatrix `yaml:"matrix"`
}

type ciReleaseWorkflowMatrix struct {
	Include []map[string]string `yaml:"include"`
}

type ciReleaseWorkflowStep struct {
	Name  string            `yaml:"name"`
	Uses  string            `yaml:"uses"`
	Run   string            `yaml:"run"`
	Shell string            `yaml:"shell"`
	With  map[string]any    `yaml:"with"`
	Env   map[string]string `yaml:"env"`
}

func ciReleaseLoadWorkflow(t *testing.T, path string) ciReleaseWorkflow {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	var workflow ciReleaseWorkflow
	if err := decoder.Decode(&workflow); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err != nil {
			t.Fatalf("decode trailing %s data: %v", path, err)
		}
		t.Fatalf("%s contains another YAML document", path)
	}
	return workflow
}

func ciReleaseWorkflowCommands(workflow ciReleaseWorkflow) string {
	var commands []string
	for _, job := range workflow.Jobs {
		for _, step := range job.Steps {
			if step.Run != "" {
				commands = append(commands, step.Run)
			}
		}
	}
	return strings.Join(commands, "\n")
}

func ciReleaseNeedsSet(t *testing.T, value any) map[string]bool {
	t.Helper()
	result := make(map[string]bool)
	switch typed := value.(type) {
	case nil:
	case string:
		result[typed] = true
	case []any:
		for _, item := range typed {
			name, ok := item.(string)
			if !ok {
				t.Fatalf("workflow needs item has type %T", item)
			}
			result[name] = true
		}
	default:
		t.Fatalf("workflow needs has type %T", value)
	}
	return result
}

func ciReleaseStringList(t *testing.T, value any) []string {
	t.Helper()
	items, ok := value.([]any)
	if !ok {
		t.Fatalf("workflow list has type %T", value)
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		text, ok := item.(string)
		if !ok {
			t.Fatalf("workflow list item has type %T", item)
		}
		result = append(result, text)
	}
	return result
}

func TestCIReleasePriorGoldenAssetsAreByteFrozen(t *testing.T) {
	manifest, err := os.ReadFile(ciReleasePriorGoldenSHA256Path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(manifest)), "\n")
	if len(lines) != 39 {
		t.Fatalf("prior golden hash records=%d, want 39", len(lines))
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
		wantPaths[fields[1]] = struct{}{}
		content, err := os.ReadFile(fields[1])
		if err != nil {
			t.Fatal(err)
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
		if strings.Contains(filepath.Base(path), "ci-release") || strings.Contains(filepath.Base(path), "replay-calibration") || strings.Contains(filepath.Base(path), "scaling") {
			continue
		}
		gotPaths[filepath.ToSlash(path)] = struct{}{}
	}
	if !reflect.DeepEqual(gotPaths, wantPaths) {
		t.Fatalf("Compatibility baseline through Deployment hardening golden asset set changed\nwant: %v\ngot:  %v", wantPaths, gotPaths)
	}
}

func TestCIReleasePublicExporterAndDeploymentSurfacesStayFrozen(t *testing.T) {
	if got := len(compatibilityDescriptorLabelOrder(t)); got != inventoryOIEFamilyCount {
		t.Fatalf("current Prometheus families=%d, want %d", got, inventoryOIEFamilyCount)
	}
	wantCLI := append(compatibilityReadNonEmptyLines(t, "testdata/cli-flags-baseline.golden"), compatibilityReadNonEmptyLines(t, threatIntelligenceCLIFlagAdditionsGoldenPath)...)
	wantCLI = append(wantCLI, compatibilityReadNonEmptyLines(t, runtimeConfigurationCLIFlagAdditionsGoldenPath)...)
	wantCLI = append(wantCLI, volumeRetypeCLIFlagAddition)
	sort.Strings(wantCLI)
	if got := compatibilityRuntimeCLIContract(t); !reflect.DeepEqual(got, wantCLI) {
		t.Fatalf("CI and release validation changed the exporter CLI\nwant: %v\ngot:  %v", wantCLI, got)
	}
	wantAnsible := []string{
		"openstack_instance_exporter_group",
		"openstack_instance_exporter_libvirt_group",
		"openstack_instance_exporter_libvirt_socket_path",
		"openstack_instance_exporter_manage_service_account",
		"openstack_instance_exporter_user",
	}
	if got := compatibilityReadNonEmptyLines(t, deploymentHardeningAnsibleAdditionsGoldenPath); !reflect.DeepEqual(got, wantAnsible) {
		t.Fatalf("CI and release validation changed the reviewed Deployment hardening Ansible additions: %v", got)
	}
}

func TestCIReleaseRequiredWorkflowCoversEveryReleaseGate(t *testing.T) {
	workflow := ciReleaseLoadWorkflow(t, ".github/workflows/ci.yml")
	if workflow.Name != "Required CI" {
		t.Fatalf("required workflow name=%q", workflow.Name)
	}
	for _, event := range []string{"pull_request", "push", "merge_group", "workflow_dispatch"} {
		if _, exists := workflow.On[event]; !exists {
			t.Fatalf("required workflow is missing %s trigger", event)
		}
	}
	push, ok := workflow.On["push"].(map[string]any)
	if !ok {
		t.Fatalf("push trigger has type %T", workflow.On["push"])
	}
	if got := ciReleaseStringList(t, push["branches"]); !reflect.DeepEqual(got, []string{"**"}) {
		t.Fatalf("push branches=%v, want every branch", got)
	}
	if got := ciReleaseStringList(t, push["tags"]); !reflect.DeepEqual(got, []string{"v*"}) {
		t.Fatalf("push tags=%v, want v*", got)
	}
	if !reflect.DeepEqual(workflow.Permissions, map[string]string{"contents": "read"}) {
		t.Fatalf("workflow permissions=%v, want contents: read", workflow.Permissions)
	}
	wantJobs := []string{"ansible_verification", "go_verification", "release_verification", "required"}
	gotJobs := make([]string, 0, len(workflow.Jobs))
	for name := range workflow.Jobs {
		gotJobs = append(gotJobs, name)
	}
	sort.Strings(gotJobs)
	if !reflect.DeepEqual(gotJobs, wantJobs) {
		t.Fatalf("required workflow jobs=%v, want %v", gotJobs, wantJobs)
	}

	commands := ciReleaseWorkflowCommands(workflow)
	for _, required := range []string{
		"go vet ./...",
		`PROMTOOL="$PROMTOOL" go test -count=1 ./...`,
		`PROMTOOL="$PROMTOOL" go test -race -count=1 ./...`,
		`PROMTOOL="$PROMTOOL" go test -shuffle=on -count=10 ./...`,
		`make coverage PROMTOOL="$PROMTOOL"`,
		`make contracts PROMTOOL="$PROMTOOL"`,
		`make operator-test PROMTOOL="$PROMTOOL"`,
		"make fuzz",
		"make ansible-test",
		"make ansible-preflight",
		"make release VERSION=v2.0.0",
		"make release-validate VERSION=v2.0.0",
		"make release-reproducible VERSION=v2.0.0",
	} {
		if strings.Count(commands, required) != 1 {
			t.Fatalf("required command %q count=%d, want 1", required, strings.Count(commands, required))
		}
	}

	ansible := workflow.Jobs["ansible_verification"]
	var matrix []string
	for _, item := range ansible.Strategy.Matrix.Include {
		matrix = append(matrix, item["os"]+"|"+item["python"]+"|"+item["ansible_core"])
	}
	sort.Strings(matrix)
	wantMatrix := []string{"ubuntu-22.04|3.10|2.12.10", "ubuntu-24.04|3.12|2.21.3"}
	if !reflect.DeepEqual(matrix, wantMatrix) {
		t.Fatalf("Ansible matrix=%v, want %v", matrix, wantMatrix)
	}

	releaseNeeds := ciReleaseNeedsSet(t, workflow.Jobs["release_verification"].Needs)
	if !reflect.DeepEqual(releaseNeeds, map[string]bool{"go_verification": true, "ansible_verification": true}) {
		t.Fatalf("release needs=%v", releaseNeeds)
	}
	requiredJob := workflow.Jobs["required"]
	if requiredJob.Name != "Required CI gate" || !strings.Contains(requiredJob.If, "always()") {
		t.Fatalf("aggregate gate name/condition=%q/%q", requiredJob.Name, requiredJob.If)
	}
	wantNeeds := map[string]bool{"go_verification": true, "ansible_verification": true, "release_verification": true}
	if got := ciReleaseNeedsSet(t, requiredJob.Needs); !reflect.DeepEqual(got, wantNeeds) {
		t.Fatalf("aggregate needs=%v, want %v", got, wantNeeds)
	}
	if !strings.Contains(commands, `test "$GO_RESULT" = success`) ||
		!strings.Contains(commands, `test "$ANSIBLE_RESULT" = success`) ||
		!strings.Contains(commands, `test "$RELEASE_RESULT" = success`) {
		t.Fatal("aggregate status does not fail closed over every mandatory result")
	}
}

func TestCIReleaseWorkflowSecurityAndImmutableActions(t *testing.T) {
	actionPattern := regexp.MustCompile(`^[^@[:space:]]+@[0-9a-f]{40}$`)
	for _, path := range []string{".github/workflows/ci.yml", ".github/workflows/extended.yml"} {
		workflow := ciReleaseLoadWorkflow(t, path)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		source := string(data)
		if !reflect.DeepEqual(workflow.Permissions, map[string]string{"contents": "read"}) {
			t.Fatalf("%s permissions=%v, want contents: read", path, workflow.Permissions)
		}
		for _, forbidden := range []string{"pull_request_target", "continue-on-error", "permissions: write", "contents: write", "paths:", "paths-ignore:", "@main", "@master"} {
			if strings.Contains(source, forbidden) {
				t.Fatalf("%s contains forbidden workflow construct %q", path, forbidden)
			}
		}
		for jobName, job := range workflow.Jobs {
			for _, step := range job.Steps {
				if step.Uses == "" {
					continue
				}
				if !actionPattern.MatchString(step.Uses) {
					t.Fatalf("%s job %s action %q is not pinned to a full SHA", path, jobName, step.Uses)
				}
				if strings.HasPrefix(step.Uses, "actions/checkout@") {
					if got, exists := step.With["persist-credentials"]; !exists || got != false {
						t.Fatalf("%s checkout persist-credentials=%v, want false", path, got)
					}
				}
			}
		}
	}
}

func TestCIReleaseScheduledWorkflowIsAdditiveAndExtended(t *testing.T) {
	workflow := ciReleaseLoadWorkflow(t, ".github/workflows/extended.yml")
	if workflow.Name != "Extended verification" {
		t.Fatalf("extended workflow name=%q", workflow.Name)
	}
	for _, event := range []string{"schedule", "workflow_dispatch"} {
		if _, exists := workflow.On[event]; !exists {
			t.Fatalf("extended workflow is missing %s trigger", event)
		}
	}
	schedules, ok := workflow.On["schedule"].([]any)
	if !ok || len(schedules) != 1 {
		t.Fatalf("extended schedules=%#v, want exactly one", workflow.On["schedule"])
	}
	schedule, ok := schedules[0].(map[string]any)
	if !ok || schedule["cron"] != "23 6 * * 0" {
		t.Fatalf("extended schedule=%#v", schedules[0])
	}
	if _, exists := workflow.On["pull_request"]; exists {
		t.Fatal("extended workflow must not replace or duplicate the pull-request gate")
	}
	commands := ciReleaseWorkflowCommands(workflow)
	for _, required := range []string{
		"-shuffle=on -count=25 ./...",
		"make fuzz FUZZTIME=2m",
		"-count=100 -run='(?i)(cleanup|lifecycle|retained|state)'",
		"make scale SCALE_COUNT=5",
	} {
		if !strings.Contains(commands, required) {
			t.Fatalf("extended workflow is missing %q", required)
		}
	}
	if strings.Contains(strings.ToLower(commands), "replay") {
		t.Fatal("CI and release validation must not claim or invent the Replay calibration replay corpus")
	}
}

func TestCIReleaseMakeAndReleaseScriptContracts(t *testing.T) {
	makefileBytes, err := os.ReadFile("Makefile")
	if err != nil {
		t.Fatal(err)
	}
	makefile := string(makefileBytes)
	for _, target := range []string{"contracts:", "operator-test:", "release-validate:", "release-reproducible:"} {
		if strings.Count(makefile, target) != 1 {
			t.Fatalf("Makefile target %q count=%d", target, strings.Count(makefile, target))
		}
	}
	for _, contractTest := range []string{
		"TestPrometheusAlertExpressionsWithPromtool",
		"TestEveryGrafanaPromQLExpressionWithPromtool",
		"TestAlertValidationEveryBundledAlertHasExecutableLifecycleFixture",
		"TestAlertValidationEveryBundledAlertLifecycleWithPromtool",
		"TestAlertValidationPublicSurfaceChangesAreExact",
		"TestDataIntegrityPrometheusEndToEndMetricContract",
		"TestDataIntegrityCLIFlagContract",
		"TestCompatibilityStructuredLogProductionCallsitesMatchGolden",
		"TestDataIntegrityBehaviorStructuredEventContract",
		"TestDataIntegrityMiningStructuredEventContract",
		"TestDataIntegrityThreatStructuredEventContracts",
		"TestThreatIntelligenceStructuredLogAdditionsContract",
		"TestCompatibilityV120CompatibilityContract",
		"TestReleaseBuilderRemovesSameVersionStaleARMArtifactAndIsReproducible",
	} {
		if strings.Count(makefile, contractTest) != 1 {
			t.Fatalf("Makefile explicit contract %q count=%d, want 1", contractTest, strings.Count(makefile, contractTest))
		}
	}
	for _, scriptPath := range []string{"scripts/validate-release.sh", "scripts/check-reproducible-release.sh"} {
		info, err := os.Stat(scriptPath)
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o755 {
			t.Fatalf("%s mode=%s, want regular 0755", scriptPath, info.Mode())
		}
		if output, err := exec.Command("bash", "-n", scriptPath).CombinedOutput(); err != nil {
			t.Fatalf("%s syntax: %v\n%s", scriptPath, err, output)
		}
	}

	validator := string(readRoleFile(t, "scripts/validate-release.sh"))
	for _, required := range []string{
		"required release-validation tool is unavailable",
		"distribution directory must contain exactly the requested amd64 archive and sha256sums.txt",
		"sha256sum --check sha256sums.txt",
		"mapfile -t archive_members",
		`[[ ! -f "$binary_path" || -L "$binary_path" || ! -x "$binary_path" ]]`,
		`"statically linked"`,
		`"stripped"`,
		"readelf -l",
		"readelf failed while validating the release binary",
		`"$binary_path" -h`,
	} {
		if !strings.Contains(validator, required) {
			t.Fatalf("release validator is missing %q", required)
		}
	}
	reproducer := string(readRoleFile(t, "scripts/check-reproducible-release.sh"))
	if got := strings.Count(reproducer, "./scripts/build-release.sh"); got != 2 {
		t.Fatalf("independent release build count=%d, want 2", got)
	}
	for _, required := range []string{
		`cmp --silent "${first_dist}/${archive_name}" "${second_dist}/${archive_name}"`,
		`cmp --silent "${first_dist}/sha256sums.txt" "${second_dist}/sha256sums.txt"`,
	} {
		if !strings.Contains(reproducer, required) {
			t.Fatalf("reproducibility checker is missing %q", required)
		}
	}

	for _, scriptPath := range []string{"scripts/validate-release.sh", "scripts/check-reproducible-release.sh"} {
		cmd := exec.Command("bash", scriptPath, "not-a-version", t.TempDir())
		if err := cmd.Run(); err == nil {
			t.Fatalf("%s accepted an invalid version", scriptPath)
		}
	}
}

func TestCIReleaseVersionDefaultsStayAligned(t *testing.T) {
	makefile := string(readRoleFile(t, "Makefile"))
	makeVersionMatch := regexp.MustCompile(`(?m)^VERSION \?= (v[0-9]+\.[0-9]+\.[0-9]+)$`).FindStringSubmatch(makefile)
	if len(makeVersionMatch) != 2 {
		t.Fatal("Makefile must declare exactly one semantic VERSION default")
	}
	makeVersion := makeVersionMatch[1]

	var defaults map[string]any
	if err := yaml.Unmarshal(readRoleFile(t, "ansible_role/openstack_instance_exporter/defaults/main.yml"), &defaults); err != nil {
		t.Fatal(err)
	}
	roleVersion, ok := defaults["openstack_instance_exporter_version"].(string)
	if !ok || roleVersion == "" {
		t.Fatal("Ansible role must declare openstack_instance_exporter_version")
	}
	if roleVersion != makeVersion {
		t.Fatalf("Ansible role version=%q, Makefile VERSION=%q", roleVersion, makeVersion)
	}

	wantDefault := `version="${1:-` + makeVersion + `}"`
	for _, scriptPath := range []string{
		"scripts/build-release.sh",
		"scripts/validate-release.sh",
		"scripts/check-reproducible-release.sh",
	} {
		script := string(readRoleFile(t, scriptPath))
		if got := strings.Count(script, wantDefault); got != 1 {
			t.Errorf("%s release-version default count=%d, want exactly one %q", scriptPath, got, wantDefault)
		}
	}
}

func TestCIReleaseReproducibilitySelectsOneUTCEpochOutsideGit(t *testing.T) {
	root := t.TempDir()
	scriptsDir := filepath.Join(root, "scripts")
	if err := os.MkdirAll(scriptsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeExecutable := func(path, content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	checker, err := os.ReadFile("scripts/check-reproducible-release.sh")
	if err != nil {
		t.Fatal(err)
	}
	writeExecutable(filepath.Join(scriptsDir, "check-reproducible-release.sh"), string(checker))
	writeExecutable(filepath.Join(scriptsDir, "build-release.sh"), `#!/usr/bin/env bash
set -euo pipefail
version="$1"
dist_dir="$2"
test "${SOURCE_DATE_EPOCH:-}" = 1788566400
mkdir -p "$dist_dir"
archive_name="openstack_instance_exporter-${version}-linux-amd64.tar.xz"
printf '%s\n' "$SOURCE_DATE_EPOCH" > "$dist_dir/$archive_name"
printf 'manifest %s\n' "$SOURCE_DATE_EPOCH" > "$dist_dir/sha256sums.txt"
`)
	writeExecutable(filepath.Join(scriptsDir, "validate-release.sh"), `#!/usr/bin/env bash
set -euo pipefail
test -f "$2/openstack_instance_exporter-$1-linux-amd64.tar.xz"
test -f "$2/sha256sums.txt"
`)

	toolDir := t.TempDir()
	dateCountPath := filepath.Join(t.TempDir(), "date-count")
	writeExecutable(filepath.Join(toolDir, "git"), "#!/usr/bin/env bash\nexit 1\n")
	writeExecutable(filepath.Join(toolDir, "date"), `#!/usr/bin/env bash
set -euo pipefail
count=0
if [[ -f "$DATE_COUNT_PATH" ]]; then
  read -r count < "$DATE_COUNT_PATH"
fi
count=$((count + 1))
printf '%s\n' "$count" > "$DATE_COUNT_PATH"
if [[ "$count" -ne 1 ]]; then
  exit 80
fi
printf '1788566400\n'
`)

	cmd := exec.Command("bash", filepath.Join(scriptsDir, "check-reproducible-release.sh"), "v2.0.0")
	cmd.Env = append(
		os.Environ(),
		"SOURCE_DATE_EPOCH=",
		"DATE_COUNT_PATH="+dateCountPath,
		"PATH="+toolDir+string(os.PathListSeparator)+os.Getenv("PATH"),
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Git-less reproducibility check failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "reproducible openstack_instance_exporter-v2.0.0-linux-amd64.tar.xz") {
		t.Fatalf("unexpected reproducibility output: %s", output)
	}
	count, err := os.ReadFile(dateCountPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(count) != "1\n" {
		t.Fatalf("UTC fallback invocation count=%q, want one", count)
	}
}

func TestCIReleaseReleaseValidatorRejectsMalformedInventories(t *testing.T) {
	const version = "v2.0.0"
	archiveName := "openstack_instance_exporter-" + version + "-linux-amd64.tar.xz"
	armName := "openstack_instance_exporter-" + version + "-linux-arm64.tar.xz"

	run := func(t *testing.T, distDir string) string {
		t.Helper()
		cmd := exec.Command("bash", "scripts/validate-release.sh", version, distDir)
		output, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("release validator accepted malformed inventory\n%s", output)
		}
		return string(output)
	}
	writePlaceholderInventory := func(t *testing.T, distDir string) {
		t.Helper()
		archivePath := filepath.Join(distDir, archiveName)
		archive := []byte("not an archive\n")
		if err := os.WriteFile(archivePath, archive, 0o644); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(archive)
		manifest := fmt.Sprintf("%x  %s\n", sum, archiveName)
		if err := os.WriteFile(filepath.Join(distDir, "sha256sums.txt"), []byte(manifest), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("missing artifacts", func(t *testing.T) {
		if output := run(t, t.TempDir()); !strings.Contains(output, "release artifact is missing") {
			t.Fatalf("unexpected validator output: %s", output)
		}
	})

	t.Run("symlink archive", func(t *testing.T) {
		distDir := t.TempDir()
		target := filepath.Join(distDir, "target")
		if err := os.WriteFile(target, []byte("target"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(distDir, archiveName)); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(distDir, "sha256sums.txt"), []byte("invalid\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if output := run(t, distDir); !strings.Contains(output, "a symlink") {
			t.Fatalf("unexpected validator output: %s", output)
		}
	})

	t.Run("extra checksum record", func(t *testing.T) {
		distDir := t.TempDir()
		writePlaceholderInventory(t, distDir)
		manifestPath := filepath.Join(distDir, "sha256sums.txt")
		manifest, err := os.ReadFile(manifestPath)
		if err != nil {
			t.Fatal(err)
		}
		manifest = append(manifest, []byte(strings.Repeat("0", 64)+"  unexpected\n")...)
		if err := os.WriteFile(manifestPath, manifest, 0o644); err != nil {
			t.Fatal(err)
		}
		if output := run(t, distDir); !strings.Contains(output, "exactly the amd64 archive") {
			t.Fatalf("unexpected validator output: %s", output)
		}
	})

	t.Run("removed arm artifact", func(t *testing.T) {
		distDir := t.TempDir()
		writePlaceholderInventory(t, distDir)
		if err := os.WriteFile(filepath.Join(distDir, armName), []byte("removed\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if output := run(t, distDir); !strings.Contains(output, "removed architecture artifact is present") {
			t.Fatalf("unexpected validator output: %s", output)
		}
	})

	t.Run("extra distribution entry", func(t *testing.T) {
		distDir := t.TempDir()
		writePlaceholderInventory(t, distDir)
		if err := os.WriteFile(filepath.Join(distDir, "unexpected.txt"), []byte("unexpected\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if output := run(t, distDir); !strings.Contains(output, "distribution directory must contain exactly") {
			t.Fatalf("unexpected validator output: %s", output)
		}
	})

	for _, name := range []string{archiveName, "sha256sums.txt"} {
		name := name
		t.Run("noncanonical mode "+name, func(t *testing.T) {
			distDir := t.TempDir()
			writePlaceholderInventory(t, distDir)
			if err := os.Chmod(filepath.Join(distDir, name), 0o600); err != nil {
				t.Fatal(err)
			}
			if output := run(t, distDir); !strings.Contains(output, "release artifact mode must be 0644") {
				t.Fatalf("unexpected validator output: %s", output)
			}
		})
	}
}

func TestCIReleaseValidatorFailsClosedWhenReadelfFails(t *testing.T) {
	const version = "v2.0.0"

	// Build a real archive in temporary storage; dist/ is not tracked in Git.
	distDir := t.TempDir()
	build := exec.Command("bash", "scripts/build-release.sh", version, distDir)
	build.Env = append(os.Environ(),
		"GO="+filepath.Join(runtime.GOROOT(), "bin", "go"),
		fmt.Sprintf("SOURCE_DATE_EPOCH=%d", releaseContractSourceDateEpoch),
	)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build release fixture: %v\n%s", err, output)
	}
	validate := exec.Command("bash", "scripts/validate-release.sh", version, distDir)
	if output, err := validate.CombinedOutput(); err != nil {
		t.Fatalf("validate release fixture before readelf failure: %v\n%s", err, output)
	}

	toolDir := t.TempDir()
	readelfPath := filepath.Join(toolDir, "readelf")
	if err := os.WriteFile(readelfPath, []byte("#!/usr/bin/env bash\nexit 73\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "scripts/validate-release.sh", version, distDir)
	cmd.Env = append(os.Environ(), "PATH="+toolDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("release validator accepted a binary without successful readelf validation\n%s", output)
	}
	if !strings.Contains(string(output), "readelf failed while validating the release binary") {
		t.Fatalf("unexpected validator output: %s", output)
	}
}

func TestCIReleaseDocumentationContracts(t *testing.T) {
	contractText := string(readRoleFile(t, "CI_AND_RELEASE_VALIDATION.md"))
	for _, statement := range []string{
		"It validates the exporter, compatibility interfaces, operator assets, deployment role and reproducible release archive.",
		"The release job waits for both implementation and deployment verification",
		"A workflow cannot mark itself mandatory.",
		"no unverified commit can become v2.0.0",
		"Golden files are never updated merely to make CI pass.",
		"The v2.0.0 release commit passes only when two builds are identical.",
		"refuses an output directory that contains unrelated entries",
		"current UTC time once when neither `SOURCE_DATE_EPOCH` nor Git metadata is available",
		"`make replay` runs the 51-fixture behavioral corpus",
		"Every GitHub Action is pinned to a 40-character commit SHA.",
	} {
		if !strings.Contains(contractText, statement) {
			t.Fatalf("CI and release validation contract is missing %q", statement)
		}
	}
	readme := string(readRoleFile(t, "README.md"))
	link := "[`CI_AND_RELEASE_VALIDATION.md`](CI_AND_RELEASE_VALIDATION.md)"
	if got := strings.Count(readme, link); got != 1 {
		t.Fatalf("README CI and release validation contract link count=%d, want 1", got)
	}
	for _, statement := range []string{
		"The supplied source-repository workflows give pull requests, branch and release-tag pushes, merge-queue revisions, and manual verification one required CI graph when the source is installed at a repository root.",
		"`make release-validate` requires the exact two-file mode-`0644` inventory",
		"`make release-reproducible` creates and validates two independent builds",
		"Repository administrators must configure the protected-branch and `v*` tag rulesets",
	} {
		if !strings.Contains(readme, statement) {
			t.Fatalf("README is missing CI and release validation statement %q", statement)
		}
	}
}
