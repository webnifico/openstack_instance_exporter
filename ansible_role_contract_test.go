package main

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const ansibleTasksPath = "ansible_role/openstack_instance_exporter/tasks/main.yml"

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
		ansibleTasksPath,
		"ansible_role/openstack_instance_exporter/handlers/main.yml",
		"ansible_role/openstack_instance_exporter/requirements.yml",
	} {
		var parsed any
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
	path := "ansible_role/openstack_instance_exporter/requirements.yml"
	if err := yaml.Unmarshal(readRoleFile(t, path), &requirements); err != nil {
		t.Fatal(err)
	}
	if len(requirements.Collections) != 1 ||
		requirements.Collections[0].Name != "ansible.posix" ||
		requirements.Collections[0].Version != ">=1.5.4,<1.6.0" {
		t.Fatalf("role collection requirements = %#v", requirements.Collections)
	}
}

func TestAnsibleRolePreservesAnsible212CompatibleBuiltins(t *testing.T) {
	tasks := string(readRoleFile(t, ansibleTasksPath))
	handlers := string(readRoleFile(t, "ansible_role/openstack_instance_exporter/handlers/main.yml"))
	for _, unsupported := range []string{"| normpath", "ansible.builtin.systemd_service:"} {
		if strings.Contains(tasks, unsupported) || strings.Contains(handlers, unsupported) {
			t.Fatalf("role uses post-2.12 Ansible feature %q", unsupported)
		}
	}
	for _, required := range []string{
		"ansible.builtin.copy:",
		"ansible.builtin.get_url:",
		"ansible.builtin.systemd:",
		"ansible.builtin.unarchive:",
	} {
		if !strings.Contains(tasks, required) {
			t.Fatalf("role tasks missing compatible module %q", required)
		}
	}
}

func TestAnsibleRoleReleaseAndEnablementContracts(t *testing.T) {
	defaults := string(readRoleFile(t, "ansible_role/openstack_instance_exporter/defaults/main.yml"))
	tasks := string(readRoleFile(t, ansibleTasksPath))
	for _, required := range []string{
		`openstack_instance_exporter_version: "v2.0.0"`,
		`openstack_instance_exporter_archive_src: ""`,
		`openstack_instance_exporter_download_url: "` + operationalConfigurationReleaseDownloadURL + `"`,
		"x86_64: amd64",
		"amd64: amd64",
	} {
		if !strings.Contains(defaults, required) {
			t.Fatalf("role defaults missing %q", required)
		}
	}
	for _, required := range []string{
		"Validate openstack_instance_exporter release settings",
		"openstack_instance_exporter_architecture == 'amd64'",
		"(openstack_instance_exporter_archive_src | length > 0) or (openstack_instance_exporter_download_url | length > 0)",
		"openstack_instance_exporter_archive_src | length == 0",
		"openstack_instance_exporter_sha256 is match('^[0-9a-fA-F]{64}$')",
		"src: \"{{ openstack_instance_exporter_archive_src }}\"",
		"url: \"{{ openstack_instance_exporter_download_url }}\"",
		"checksum: \"sha256:{{ openstack_instance_exporter_sha256 }}\"",
		"checksum_algorithm: sha256",
		"oie_tar_stat.stat.checksum",
		"openstack_instance_exporter_enabled | bool",
		"not (openstack_instance_exporter_enabled | bool)",
	} {
		if !strings.Contains(tasks, required) {
			t.Fatalf("release/deployment contract missing %q", required)
		}
	}
}

func TestAnsibleRoleTaskSurfaceIsCompact(t *testing.T) {
	tasks := string(readRoleFile(t, ansibleTasksPath))
	lines := strings.Count(tasks, "\n")
	if !strings.HasSuffix(tasks, "\n") {
		lines++
	}
	if lines > 320 {
		t.Fatalf("role task file has %d lines, want at most 320", lines)
	}
	if got := strings.Count(tasks, "ansible.builtin.assert:"); got != 3 {
		t.Fatalf("role has %d assertion tasks, want three focused checks", got)
	}
	for _, removed := range []string{
		"Validate safe openstack_instance_exporter installation paths",
		"Inspect openstack_instance_exporter file-valued paths",
		"Reject directory-valued openstack_instance_exporter",
		"Refuse removal of an installation directory containing unmanaged content",
		"oie_unmanaged_install_entries",
	} {
		if strings.Contains(tasks, removed) {
			t.Fatalf("superseded deployment bloat remains: %q", removed)
		}
	}
}

func TestAnsibleCleanupUsesFocusedModules(t *testing.T) {
	tasks := string(readRoleFile(t, ansibleTasksPath))
	for _, unsafe := range []string{
		"ansible.builtin.shell:",
		"ansible.builtin.command:",
		"rm -f",
		"ansible.builtin.find:",
	} {
		if strings.Contains(tasks, unsafe) {
			t.Fatalf("cleanup retains unnecessary command or discovery %q", unsafe)
		}
	}
	for _, required := range []string{
		"Validate the openstack_instance_exporter cleanup directory",
		"openstack_instance_exporter_install_dir not in ['/', '/etc', '/opt', '/usr', '/var']",
		"Remove managed openstack_instance_exporter files",
		"/etc/logrotate.d/openstack_instance_exporter",
		"{{ openstack_instance_exporter_install_dir }}",
		"item | string | length > 1",
		"item | string is match('^/')",
	} {
		if !strings.Contains(tasks, required) {
			t.Fatalf("focused cleanup contract missing %q", required)
		}
	}
}

func TestAnsibleUpgradeAndIdempotencyContracts(t *testing.T) {
	tasks := string(readRoleFile(t, ansibleTasksPath))
	handlers := string(readRoleFile(t, "ansible_role/openstack_instance_exporter/handlers/main.yml"))
	for _, required := range []string{
		"register: oie_tar_local_result",
		"register: oie_tar_download_result",
		"register: oie_template_result",
		"oie_tar_local_result.changed | default(false)",
		"oie_tar_download_result.changed | default(false)",
		"oie_installed_binary.stat.isreg",
		"oie_installed_binary.stat.executable",
		"oie_installed_binary.stat.size",
		"notify: Restart openstack_instance_exporter service",
	} {
		if !strings.Contains(tasks, required) {
			t.Fatalf("upgrade/idempotency contract missing %q", required)
		}
	}
	if !strings.Contains(handlers, "ansible.builtin.systemd:") ||
		!strings.Contains(handlers, "state: restarted") {
		t.Fatal("restart handler contract changed")
	}
}

func TestAnsibleExtractionRunsOnlyForUpgradeOrRepair(t *testing.T) {
	var taskList []struct {
		Block []map[string]any `yaml:"block"`
	}
	if err := yaml.Unmarshal(readRoleFile(t, ansibleTasksPath), &taskList); err != nil {
		t.Fatal(err)
	}
	for _, topLevel := range taskList {
		positions := make(map[string]int, len(topLevel.Block))
		for index, task := range topLevel.Block {
			name, _ := task["name"].(string)
			positions[name] = index
		}
		for _, task := range topLevel.Block {
			if task["name"] != "Extract openstack_instance_exporter tarball" {
				continue
			}
			condition, ok := task["when"].(string)
			if !ok {
				t.Fatal("archive extraction has no string condition")
			}
			for _, required := range []string{
				"oie_tar_local_result.changed",
				"oie_tar_download_result.changed",
				"oie_installed_binary.stat.isreg",
				"oie_installed_binary.stat.executable",
				"oie_installed_binary.stat.size",
			} {
				if !strings.Contains(condition, required) {
					t.Fatalf("archive extraction condition missing %q", required)
				}
			}
			if positions["Inspect installed openstack_instance_exporter binary"] >=
				positions["Extract openstack_instance_exporter tarball"] {
				t.Fatal("installed binary is not inspected before extraction")
			}
			return
		}
	}
	t.Fatal("archive extraction task is missing")
}

func TestAnsibleDisabledAndCleanupContracts(t *testing.T) {
	tasks := string(readRoleFile(t, ansibleTasksPath))
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
		"GOAMD64=v1",
		`chmod 0755 "${stage_dir}/openstack_instance_exporter"`,
		"chmod 0644 sha256sums.txt",
		"distribution directory contains an unexpected entry",
		`sha256sum "${archive_name}" > sha256sums.txt`,
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("release builder missing %q", required)
		}
	}
	if strings.Count(script, "GOARCH=") != 1 {
		t.Fatal("release builder must produce exactly one architecture")
	}
	if !strings.Contains(makefile, "VERSION ?= v2.0.0") {
		t.Fatal("release builder is not pinned to v2.0.0 by default")
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
			t.Fatalf("service template lost %q", required)
		}
	}
}
