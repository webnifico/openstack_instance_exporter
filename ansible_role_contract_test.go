package main

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func readRoleFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAnsibleRoleYAMLIsSyntacticallyValid(t *testing.T) {
	for _, path := range []string{
		"ansible_role/openstack_instance_exporter/defaults/main.yml",
		"ansible_role/openstack_instance_exporter/tasks/main.yml",
		"ansible_role/openstack_instance_exporter/handlers/main.yml",
		"ansible_role/openstack_instance_exporter/requirements.yml",
	} {
		var parsed interface{}
		if err := yaml.Unmarshal(readRoleFile(t, path), &parsed); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
}

func TestAnsibleRoleCollectionRequirements(t *testing.T) {
	var requirements struct {
		Collections []struct {
			Name    string `yaml:"name"`
			Version string `yaml:"version"`
		} `yaml:"collections"`
	}
	if err := yaml.Unmarshal(readRoleFile(t, "ansible_role/openstack_instance_exporter/requirements.yml"), &requirements); err != nil {
		t.Fatal(err)
	}
	if len(requirements.Collections) != 1 ||
		requirements.Collections[0].Name != "ansible.posix" ||
		requirements.Collections[0].Version != ">=1.5.4,<2.0.0" {
		t.Fatalf("role collection requirements = %#v, want ansible.posix >=1.5.4,<2.0.0", requirements.Collections)
	}
}

func TestAnsibleRolePreservesAnsible212CompatibleBuiltins(t *testing.T) {
	tasks := string(readRoleFile(t, "ansible_role/openstack_instance_exporter/tasks/main.yml"))
	handlers := string(readRoleFile(t, "ansible_role/openstack_instance_exporter/handlers/main.yml"))
	for _, unsupported := range []string{"| normpath", "ansible.builtin.systemd_service:"} {
		if strings.Contains(tasks, unsupported) || strings.Contains(handlers, unsupported) {
			t.Fatalf("role uses post-2.12 Ansible feature %q", unsupported)
		}
	}
	for _, required := range []string{"ansible.builtin.get_url:", "ansible.builtin.systemd:"} {
		if !strings.Contains(tasks, required) {
			t.Fatalf("role tasks missing 2.12-compatible FQCN %q", required)
		}
	}
}

func TestAnsibleRoleReleaseAndEnablementContracts(t *testing.T) {
	defaults := string(readRoleFile(t, "ansible_role/openstack_instance_exporter/defaults/main.yml"))
	tasks := string(readRoleFile(t, "ansible_role/openstack_instance_exporter/tasks/main.yml"))
	if !strings.Contains(defaults, `openstack_instance_exporter_version: "v1.3.0"`) {
		t.Fatal("role default release is not v1.3.0")
	}
	for _, architecture := range []string{"x86_64: amd64", "amd64: amd64"} {
		if !strings.Contains(defaults, architecture) {
			t.Fatalf("role defaults missing amd64 architecture mapping %q", architecture)
		}
	}
	var architectureDefaults struct {
		ArchitectureMap map[string]string `yaml:"openstack_instance_exporter_architecture_map"`
		Architecture    string            `yaml:"openstack_instance_exporter_architecture"`
	}
	if err := yaml.Unmarshal([]byte(defaults), &architectureDefaults); err != nil {
		t.Fatal(err)
	}
	if len(architectureDefaults.ArchitectureMap) != 2 ||
		architectureDefaults.ArchitectureMap["x86_64"] != "amd64" ||
		architectureDefaults.ArchitectureMap["amd64"] != "amd64" {
		t.Fatalf("role architecture map is not amd64-only: %#v", architectureDefaults.ArchitectureMap)
	}
	if architectureDefaults.Architecture == "" {
		t.Fatal("compatible architecture override variable was removed")
	}
	if !strings.Contains(tasks, "openstack_instance_exporter_enabled | bool") ||
		!strings.Contains(tasks, "not (openstack_instance_exporter_enabled | bool)") {
		t.Fatal("enabled/disabled role guards are incomplete")
	}
	if !strings.Contains(tasks, "linux-{{ openstack_instance_exporter_architecture }}.tar.xz") ||
		!strings.Contains(tasks, "openstack_instance_exporter_architecture == 'amd64'") {
		t.Fatal("release download is not restricted to the amd64 artifact")
	}
	if !strings.Contains(tasks, "checksum: \"sha256:{{ openstack_instance_exporter_sha256 }}\"") {
		t.Fatal("release checksum contract changed")
	}
}

func TestAnsibleCleanupUsesSafeModules(t *testing.T) {
	tasks := string(readRoleFile(t, "ansible_role/openstack_instance_exporter/tasks/main.yml"))
	for _, unsafe := range []string{"ansible.builtin.shell:", "ansible.builtin.command:", "rm -f"} {
		if strings.Contains(tasks, unsafe) {
			t.Fatalf("cleanup contains unsafe command %q", unsafe)
		}
	}
	if !strings.Contains(tasks, "ansible.builtin.find:") || !strings.Contains(tasks, "oie_log_files.files | default([])") {
		t.Fatal("module-based log cleanup is missing")
	}
	if !strings.Contains(tasks, "/etc/logrotate.d/openstack_instance_exporter") {
		t.Fatal("logrotate install/cleanup contract was lost")
	}
}

func TestAnsibleLogCleanupOnlyFindsManagedRotations(t *testing.T) {
	var taskList []struct {
		Name  string           `yaml:"name"`
		Block []map[string]any `yaml:"block"`
	}
	if err := yaml.Unmarshal(readRoleFile(t, "ansible_role/openstack_instance_exporter/tasks/main.yml"), &taskList); err != nil {
		t.Fatal(err)
	}
	for _, topLevelTask := range taskList {
		if topLevelTask.Name != "OpenStack Instance Exporter Cleanup Tasks" {
			continue
		}
		tasks := make(map[string]map[string]any, len(topLevelTask.Block))
		positions := make(map[string]int, len(topLevelTask.Block))
		for index, task := range topLevelTask.Block {
			name, _ := task["name"].(string)
			tasks[name] = task
			positions[name] = index
		}

		exactName := "Remove configured openstack_instance_exporter log file"
		exactRemoval := tasks[exactName]
		exactModule, ok := exactRemoval["ansible.builtin.file"].(map[string]any)
		if !ok || exactModule["path"] != "{{ openstack_instance_exporter_log_file_path }}" || exactModule["state"] != "absent" {
			t.Fatalf("exact configured log path is not removed safely before rotation discovery: %#v", exactRemoval)
		}

		findName := "Find standard openstack_instance_exporter log files"
		findTask := tasks[findName]
		findModule, ok := findTask["ansible.builtin.find"].(map[string]any)
		if !ok {
			t.Fatal("log rotation cleanup does not use ansible.builtin.find")
		}
		if positions[exactName] >= positions[findName] {
			t.Fatal("exact configured log path is not removed before rotation discovery")
		}
		if findModule["use_regex"] != true {
			t.Fatalf("log rotation filename matching is not exact regex matching: %#v", findModule)
		}
		if findModule["hidden"] != true {
			t.Fatalf("log rotation cleanup does not include a configured dot-prefixed log file: %#v", findModule)
		}
		pattern, _ := findModule["patterns"].(string)
		if !strings.Contains(pattern, "regex_escape") || !strings.Contains(pattern, "[0-9]+") {
			t.Fatalf("log rotation cleanup does not escape the configured basename and restrict matches to numeric rotations: %q", pattern)
		}
		return
	}
	t.Fatal("cleanup task block is missing")
}

func TestAnsibleMutatingBlocksRejectRootFilesystemTargets(t *testing.T) {
	var taskList []struct {
		Name  string           `yaml:"name"`
		Block []map[string]any `yaml:"block"`
	}
	if err := yaml.Unmarshal(readRoleFile(t, "ansible_role/openstack_instance_exporter/tasks/main.yml"), &taskList); err != nil {
		t.Fatal(err)
	}

	blocks := map[string]string{
		"Installation and Configuration":            "Validate safe openstack_instance_exporter installation paths",
		"OpenStack Instance Exporter Cleanup Tasks": "Validate safe openstack_instance_exporter cleanup paths",
	}
	for blockName, assertionName := range blocks {
		t.Run(blockName, func(t *testing.T) {
			for _, topLevelTask := range taskList {
				if topLevelTask.Name != blockName {
					continue
				}
				for index, task := range topLevelTask.Block {
					if task["name"] != assertionName {
						continue
					}
					if index != 0 {
						t.Fatalf("path safety assertion is task %d, want first before any mutation", index+1)
					}
					assertPathSafetyContract(t, task)
					return
				}
				t.Fatal("path safety assertion is missing")
			}
			t.Fatal("mutating task block is missing")
		})
	}
}

func assertPathSafetyContract(t *testing.T, task map[string]any) {
	t.Helper()
	assertion, ok := task["ansible.builtin.assert"].(map[string]any)
	if !ok {
		t.Fatal("path validation does not use ansible.builtin.assert")
	}
	conditions, ok := assertion["that"].([]any)
	if !ok {
		t.Fatal("path validation has no assertion conditions")
	}
	joined := make([]string, 0, len(conditions))
	for _, condition := range conditions {
		conditionText, ok := condition.(string)
		if !ok {
			t.Fatalf("path validation condition has type %T, want string", condition)
		}
		joined = append(joined, conditionText)
	}
	contract := strings.Join(joined, "\n")
	for _, variable := range []string{
		"openstack_instance_exporter_install_dir",
		"openstack_instance_exporter_customlist_path",
		"openstack_instance_exporter_behavior_ports_config_path",
		"openstack_instance_exporter_behavior_rules_config_path",
		"openstack_instance_exporter_log_file_path",
	} {
		if !strings.Contains(contract, variable) {
			t.Fatalf("path validation does not protect %s", variable)
		}
		trimContract := "(" + variable + " | string) == (" + variable + " | string | trim)"
		if !strings.Contains(contract, trimContract) {
			t.Fatalf("path validation validates a trimmed value but modules may consume untrimmed %s", variable)
		}
	}
	if strings.Count(contract, "is match('^/')") != 5 ||
		strings.Count(contract, "regex_replace('/+', '/')") != 5 ||
		strings.Count(contract, "regex_search('(^|/)[.][.]?(/|$)')") != 5 {
		t.Fatalf("path validation does not require absolute, non-root, traversal-free targets for every configurable target:\n%s", contract)
	}
	for _, glob := range []string{"'*' not in", "'?' not in", "'[' not in"} {
		if !strings.Contains(contract, glob+" (openstack_instance_exporter_log_file_path | string | trim)") {
			t.Fatalf("log path validation does not reject %s basename glob metacharacters:\n%s", glob, contract)
		}
	}
}

func TestAnsibleFileValuedPathsAreCheckedBeforeMutation(t *testing.T) {
	var taskList []struct {
		Name  string           `yaml:"name"`
		Block []map[string]any `yaml:"block"`
	}
	if err := yaml.Unmarshal(readRoleFile(t, "ansible_role/openstack_instance_exporter/tasks/main.yml"), &taskList); err != nil {
		t.Fatal(err)
	}

	blocks := map[string]struct {
		statName   string
		assertName string
	}{
		"Installation and Configuration": {
			statName:   "Inspect openstack_instance_exporter file-valued paths before installation changes",
			assertName: "Reject directory-valued openstack_instance_exporter installation paths",
		},
		"OpenStack Instance Exporter Cleanup Tasks": {
			statName:   "Inspect openstack_instance_exporter file-valued paths before cleanup",
			assertName: "Reject directory-valued openstack_instance_exporter cleanup paths",
		},
	}
	for blockName, expected := range blocks {
		t.Run(blockName, func(t *testing.T) {
			for _, topLevelTask := range taskList {
				if topLevelTask.Name != blockName {
					continue
				}
				if len(topLevelTask.Block) < 3 {
					t.Fatal("mutating block has no pre-mutation file path guards")
				}
				statTask := topLevelTask.Block[1]
				assertTask := topLevelTask.Block[2]
				if statTask["name"] != expected.statName || assertTask["name"] != expected.assertName {
					t.Fatalf("file path guards are not immediately after the leading path assertion: tasks 2-3 are %q and %q", statTask["name"], assertTask["name"])
				}
				statYAML, err := yaml.Marshal(statTask)
				if err != nil {
					t.Fatal(err)
				}
				statContract := string(statYAML)
				for _, variable := range []string{
					"openstack_instance_exporter_customlist_path",
					"openstack_instance_exporter_behavior_ports_config_path",
					"openstack_instance_exporter_behavior_rules_config_path",
					"openstack_instance_exporter_log_file_path",
				} {
					if !strings.Contains(statContract, variable) {
						t.Fatalf("file path inspection does not cover %s:\n%s", variable, statContract)
					}
				}
				assertYAML, err := yaml.Marshal(assertTask)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(assertYAML), "item.stat.isdir") {
					t.Fatalf("directory-valued path assertion is missing:\n%s", assertYAML)
				}
				return
			}
			t.Fatal("mutating task block is missing")
		})
	}
}

func TestAnsibleInstallDirectoryIsLstatGuardedBeforeMutation(t *testing.T) {
	var taskList []struct {
		Name  string           `yaml:"name"`
		Block []map[string]any `yaml:"block"`
	}
	if err := yaml.Unmarshal(readRoleFile(t, "ansible_role/openstack_instance_exporter/tasks/main.yml"), &taskList); err != nil {
		t.Fatal(err)
	}

	for _, topLevelTask := range taskList {
		if topLevelTask.Name != "Installation and Configuration" {
			continue
		}
		positions := make(map[string]int, len(topLevelTask.Block))
		tasks := make(map[string]map[string]any, len(topLevelTask.Block))
		for index, task := range topLevelTask.Block {
			name, _ := task["name"].(string)
			positions[name] = index
			tasks[name] = task
		}

		statName := "Inspect openstack_instance_exporter installation directory before installation changes"
		statTask := tasks[statName]
		statModule, ok := statTask["ansible.builtin.stat"].(map[string]any)
		if !ok {
			t.Fatal("installation directory is not inspected with ansible.builtin.stat")
		}
		if statModule["path"] != "{{ openstack_instance_exporter_install_dir }}" || statModule["follow"] != false {
			t.Fatalf("installation directory inspection is not a non-following lstat: %#v", statModule)
		}

		assertName := "Reject an unsafe existing openstack_instance_exporter installation path"
		assertTask := tasks[assertName]
		assertYAML, err := yaml.Marshal(assertTask)
		if err != nil {
			t.Fatal(err)
		}
		assertContract := string(assertYAML)
		for _, required := range []string{"oie_install_dir_stat.stat.exists", "oie_install_dir_stat.stat.isdir", "oie_install_dir_stat.stat.islnk"} {
			if !strings.Contains(assertContract, required) {
				t.Fatalf("installation directory guard is missing %q:\n%s", required, assertContract)
			}
		}
		for _, firstMutation := range []string{
			"Enable nf_conntrack_acct",
			"Ensure the openstack_instance_exporter install directory exists",
			"Download openstack_instance_exporter tarball",
		} {
			if positions[statName] >= positions[firstMutation] || positions[assertName] >= positions[firstMutation] {
				t.Fatalf("installation path lstat guards do not precede %q", firstMutation)
			}
		}
		return
	}
	t.Fatal("installation task block is missing")
}

func TestAnsibleCleanupDirectoryIsLstatGuardedBeforeMutation(t *testing.T) {
	var taskList []struct {
		Name  string           `yaml:"name"`
		Block []map[string]any `yaml:"block"`
	}
	if err := yaml.Unmarshal(readRoleFile(t, "ansible_role/openstack_instance_exporter/tasks/main.yml"), &taskList); err != nil {
		t.Fatal(err)
	}

	for _, topLevelTask := range taskList {
		if topLevelTask.Name != "OpenStack Instance Exporter Cleanup Tasks" {
			continue
		}
		positions := make(map[string]int, len(topLevelTask.Block))
		tasks := make(map[string]map[string]any, len(topLevelTask.Block))
		for index, task := range topLevelTask.Block {
			name, _ := task["name"].(string)
			positions[name] = index
			tasks[name] = task
		}

		statName := "Inspect openstack_instance_exporter installation directory before cleanup"
		statTask := tasks[statName]
		statModule, ok := statTask["ansible.builtin.stat"].(map[string]any)
		if !ok {
			t.Fatal("cleanup installation directory is not inspected with ansible.builtin.stat")
		}
		if statModule["path"] != "{{ openstack_instance_exporter_install_dir }}" || statModule["follow"] != false {
			t.Fatalf("cleanup installation directory inspection is not a non-following lstat: %#v", statModule)
		}

		assertName := "Reject an unsafe existing openstack_instance_exporter cleanup path"
		assertTask := tasks[assertName]
		assertYAML, err := yaml.Marshal(assertTask)
		if err != nil {
			t.Fatal(err)
		}
		assertContract := string(assertYAML)
		for _, required := range []string{"oie_cleanup_install_dir.stat.exists", "oie_cleanup_install_dir.stat.isdir", "oie_cleanup_install_dir.stat.islnk"} {
			if !strings.Contains(assertContract, required) {
				t.Fatalf("cleanup installation directory guard is missing %q:\n%s", required, assertContract)
			}
		}
		for _, firstMutation := range []string{
			"Ensure openstack_instance_exporter service is stopped and disabled",
			"Remove openstack_instance_exporter systemd service file",
			"Remove managed openstack_instance_exporter installation artifacts",
		} {
			if positions[statName] >= positions[firstMutation] || positions[assertName] >= positions[firstMutation] {
				t.Fatalf("cleanup path lstat guards do not precede %q", firstMutation)
			}
		}
		return
	}
	t.Fatal("cleanup task block is missing")
}

func TestAnsibleUnknownProfileIsRejectedBeforeMutation(t *testing.T) {
	var taskList []struct {
		Name  string           `yaml:"name"`
		Block []map[string]any `yaml:"block"`
	}
	if err := yaml.Unmarshal(readRoleFile(t, "ansible_role/openstack_instance_exporter/tasks/main.yml"), &taskList); err != nil {
		t.Fatal(err)
	}

	for _, topLevelTask := range taskList {
		if topLevelTask.Name != "Installation and Configuration" {
			continue
		}
		if len(topLevelTask.Block) == 0 || topLevelTask.Block[0]["name"] != "Validate safe openstack_instance_exporter installation paths" {
			t.Fatal("leading installation validation task is missing")
		}
		assertion, ok := topLevelTask.Block[0]["ansible.builtin.assert"].(map[string]any)
		if !ok {
			t.Fatal("leading installation validation does not use assert")
		}
		conditions, _ := yaml.Marshal(assertion["that"])
		contract := string(conditions)
		for _, required := range []string{
			"openstack_instance_exporter_profile",
			"openstack_instance_exporter_profile_defaults.keys()",
			"disabled",
		} {
			if !strings.Contains(contract, required) {
				t.Fatalf("unknown profile validation is missing %q:\n%s", required, contract)
			}
		}
		return
	}
	t.Fatal("installation task block is missing")
}

func TestAnsibleInstallDirectoryCleanupRefusesUnmanagedContent(t *testing.T) {
	var taskList []struct {
		Name  string           `yaml:"name"`
		Block []map[string]any `yaml:"block"`
	}
	if err := yaml.Unmarshal(readRoleFile(t, "ansible_role/openstack_instance_exporter/tasks/main.yml"), &taskList); err != nil {
		t.Fatal(err)
	}

	var cleanup []map[string]any
	for _, topLevelTask := range taskList {
		if topLevelTask.Name == "OpenStack Instance Exporter Cleanup Tasks" {
			cleanup = topLevelTask.Block
			break
		}
	}
	if len(cleanup) == 0 {
		t.Fatal("cleanup task block is missing")
	}
	tasks := make(map[string]map[string]any, len(cleanup))
	for _, task := range cleanup {
		name, _ := task["name"].(string)
		tasks[name] = task
	}

	managedRemoval := tasks["Remove managed openstack_instance_exporter installation artifacts"]
	managedYAML, err := yaml.Marshal(managedRemoval)
	if err != nil {
		t.Fatal(err)
	}
	managedContract := string(managedYAML)
	for _, artifact := range []string{
		"openstack_instance_exporter_install_dir }}/openstack_instance_exporter",
		"openstack_instance_exporter_install_dir }}/openstack_instance_exporter.tar.xz",
	} {
		if !strings.Contains(managedContract, artifact) {
			t.Fatalf("managed cleanup does not remove %s:\n%s", artifact, managedContract)
		}
	}
	if !strings.Contains(managedContract, "state: absent") {
		t.Fatalf("managed artifact cleanup does not use file state=absent:\n%s", managedContract)
	}

	inspection := tasks["Inspect openstack_instance_exporter installation directory for unmanaged content"]
	findModule, ok := inspection["ansible.builtin.find"].(map[string]any)
	if !ok {
		t.Fatal("managed installation cleanup does not use ansible.builtin.find")
	}
	if findModule["file_type"] != "any" || findModule["recurse"] != true || findModule["hidden"] != true || findModule["follow"] != false {
		t.Fatalf("managed cleanup inspection is not recursive, hidden/link aware, and type complete: %#v", findModule)
	}

	refusal := tasks["Refuse removal of an installation directory containing unmanaged content"]
	refusalYAML, err := yaml.Marshal(refusal)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(refusalYAML), "oie_unmanaged_install_entries.files") || !strings.Contains(string(refusalYAML), "length) == 0") {
		t.Fatalf("cleanup does not reject unmanaged install-directory entries:\n%s", refusalYAML)
	}
	if !strings.Contains(string(refusalYAML), "oie_unmanaged_install_entries.skipped_paths") {
		t.Fatalf("cleanup does not reject an incomplete install-directory inspection:\n%s", refusalYAML)
	}

	finalRemoval := tasks["Remove the empty openstack_instance_exporter installation directory"]
	finalYAML, err := yaml.Marshal(finalRemoval)
	if err != nil {
		t.Fatal(err)
	}
	finalContract := string(finalYAML)
	if !strings.Contains(finalContract, "oie_unmanaged_install_entries.files") ||
		!strings.Contains(finalContract, "oie_unmanaged_install_entries.skipped_paths") ||
		!strings.Contains(finalContract, "state: absent") {
		t.Fatalf("final installation-directory removal is not guarded by the empty inspection result:\n%s", finalContract)
	}
	if _, remains := tasks["Remove the openstack_instance_exporter installation directory"]; remains {
		t.Fatal("blind recursive installation-directory removal remains in cleanup")
	}
}

func TestAnsibleUpgradeAndIdempotencyContracts(t *testing.T) {
	tasks := string(readRoleFile(t, "ansible_role/openstack_instance_exporter/tasks/main.yml"))
	handlers := string(readRoleFile(t, "ansible_role/openstack_instance_exporter/handlers/main.yml"))
	for _, required := range []string{
		"register: oie_tar_download_result",
		"register: oie_template_result",
		"when: oie_tar_download_result.changed or oie_template_result.changed",
		"notify: Restart openstack_instance_exporter service",
	} {
		if !strings.Contains(tasks, required) {
			t.Fatalf("upgrade/idempotency contract missing %q", required)
		}
	}
	if !strings.Contains(handlers, "ansible.builtin.systemd:") || !strings.Contains(handlers, "state: restarted") {
		t.Fatal("idempotent restart handler contract changed")
	}
}

func TestAnsibleExtractionRunsOnlyForUpgradeOrRepair(t *testing.T) {
	var taskList []struct {
		Block []map[string]any `yaml:"block"`
	}
	if err := yaml.Unmarshal(readRoleFile(t, "ansible_role/openstack_instance_exporter/tasks/main.yml"), &taskList); err != nil {
		t.Fatal(err)
	}

	for _, topLevelTask := range taskList {
		positions := make(map[string]int, len(topLevelTask.Block))
		for index, task := range topLevelTask.Block {
			name, _ := task["name"].(string)
			positions[name] = index
		}
		for _, task := range topLevelTask.Block {
			if task["name"] != "Extract openstack_instance_exporter tarball" {
				continue
			}
			condition, conditional := task["when"]
			if !conditional {
				t.Fatal("archive extraction is unconditional, so an unchanged role run is not idempotent")
			}
			if _, ok := task["ansible.builtin.unarchive"]; !ok {
				t.Fatal("archive extraction no longer uses ansible.builtin.unarchive")
			}
			conditionYAML, err := yaml.Marshal(condition)
			if err != nil {
				t.Fatal(err)
			}
			conditionText := string(conditionYAML)
			for _, required := range []string{
				"oie_tar_download_result.changed",
				"oie_installed_binary.stat.isreg",
				"oie_installed_binary.stat.executable",
				"oie_installed_binary.stat.size",
			} {
				if !strings.Contains(conditionText, required) {
					t.Fatalf("archive extraction condition is missing %q: %s", required, conditionText)
				}
			}

			statName := "Inspect installed openstack_instance_exporter binary"
			statPosition, found := positions[statName]
			if !found || statPosition >= positions["Extract openstack_instance_exporter tarball"] {
				t.Fatal("installed binary is not inspected before conditional extraction")
			}
			statTask := topLevelTask.Block[statPosition]
			statModule, ok := statTask["ansible.builtin.stat"].(map[string]any)
			if !ok || statModule["path"] != "{{ openstack_instance_exporter_install_dir }}/openstack_instance_exporter" || statModule["follow"] != false {
				t.Fatalf("installed binary inspection is not a non-following file check: %#v", statTask)
			}
			if statTask["register"] != "oie_installed_binary" {
				t.Fatalf("installed binary inspection register changed: %#v", statTask["register"])
			}
			return
		}
	}
	t.Fatal("archive extraction task is missing")
}

func TestAnsibleDisabledAndCleanupContracts(t *testing.T) {
	tasks := string(readRoleFile(t, "ansible_role/openstack_instance_exporter/tasks/main.yml"))
	for _, required := range []string{
		"not (openstack_instance_exporter_enabled | bool)",
		"when: oie_disabled_service_file.stat.exists",
		"tags: never, cleanup_oie",
		"when: service_file_removed.changed",
		"path: \"{{ openstack_instance_exporter_install_dir }}\"",
		"state: absent",
	} {
		if !strings.Contains(tasks, required) {
			t.Fatalf("disabled/cleanup contract missing %q", required)
		}
	}
}

func TestReleaseBuilderMatchesAnsibleArtifactContract(t *testing.T) {
	script := string(readRoleFile(t, "scripts/build-release.sh"))
	makefile := string(readRoleFile(t, "Makefile"))
	for _, required := range []string{
		`archive_name="openstack_instance_exporter-${version}-linux-amd64.tar.xz"`,
		`source_date_epoch="${SOURCE_DATE_EPOCH:-}"`,
		`--mtime="@${source_date_epoch}"`,
		"sha256sum --check sha256sums.txt",
		"CGO_ENABLED=0 GOOS=linux GOARCH=amd64",
		`sha256sum "${archive_name}" > sha256sums.txt`,
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("release builder missing %q", required)
		}
	}
	for _, removed := range []string{"for arch in", `GOARCH="${arch}"`} {
		if strings.Contains(script, removed) {
			t.Fatalf("release builder retains removed architecture logic %q", removed)
		}
	}
	if got := strings.Count(script, "GOARCH="); got != 1 {
		t.Fatalf("release builder has %d architecture builds, want exactly one", got)
	}
	if !strings.Contains(makefile, "VERSION ?= v1.3.0") {
		t.Fatal("release builder is not pinned to v1.3.0 by default")
	}
}

func TestAnsibleServiceTemplateKeepsInterfaceDerivedBindingAndProfiles(t *testing.T) {
	template := string(readRoleFile(t, "ansible_role/openstack_instance_exporter/templates/openstack_instance_exporter.service.j2"))
	for _, required := range []string{
		"openstack_instance_exporter_network_interface.replace('-', '_')",
		"openstack_instance_exporter_profile_defaults.get(profile_name, {})",
		"-web.listen-address=",
		"-behavior.sensitivity=",
		"-conntrack.ipv4.enable=",
		"-conntrack.ipv6.enable=",
	} {
		if !strings.Contains(template, required) {
			t.Fatalf("service template lost required rendering contract %q", required)
		}
	}
	for _, inlineYAML := range []string{
		"openstack_instance_exporter_behavior_ports_config_yaml",
		"openstack_instance_exporter_behavior_rules_config_yaml",
	} {
		if !strings.Contains(template, inlineYAML+" is defined") || !strings.Contains(template, inlineYAML+"|trim|length > 0") {
			t.Fatalf("service template can pass a missing strict config file for %q", inlineYAML)
		}
	}
}
