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

func dataIntegrityCompareExpected(t *testing.T, path string, value any) {
	t.Helper()
	got, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var actual, expected any
	if err := dataIntegrityDecodeSingleJSON(got, &actual); err != nil {
		t.Fatal(err)
	}
	if err := dataIntegrityDecodeSingleJSON(want, &expected); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("release contract changed: %s\nwant:\n%s\ngot:\n%s", path, want, got)
	}
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
	"editorMode", "exemplar", "panelId", "withTransforms",
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
					ds, _ := target["datasource"].(map[string]any)
					sourceID, validID := target["panelId"].(json.Number)
					_, exists := seen[sourceID.String()]
					if ds["uid"] != "-- Dashboard --" || !validID || !exists || sourceID.String() == identity || target["withTransforms"] != false {
						t.Fatalf("panel %s target %d must have PromQL or reuse an earlier raw panel result", identity, targetIndex)
					}
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

	dataIntegrityCompareExpected(t, "testdata/contracts/dashboards.json", dataIntegrityLoadGrafanaContracts(t))
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

func TestReleaseAlertPolicySemanticContract(t *testing.T) {
	policy, _ := dataIntegrityLoadYAMLSemantics(t, "examples/prometheus_alerts_example/openstack_instance_exporter_alerts.yml")
	dataIntegrityCompareExpected(t, "testdata/contracts/alert-policy.json", policy)
}

func TestDataIntegrityAnsibleRoleSemanticContract(t *testing.T) {
	current := dataIntegrityLoadAnsibleRoleContract(t)
	dataIntegrityCompareExpected(t, "testdata/contracts/ansible-role.json", current)
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
# Match the role loader: trusted defaults can contain nested Jinja templates.
defaults_path = role / "defaults" / "main.yml"
defaults = loader.load(trust_as_template(defaults_path.read_text(encoding="utf-8")), file_name=str(defaults_path))
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
    "openstack_instance_exporter_inbound_behavior_enable": False,
    "openstack_instance_exporter_outbound_behavior_enable": False,
    "openstack_instance_exporter_behavior_ewma_fast_tau": "1m",
    "openstack_instance_exporter_behavior_ewma_slow_tau": "1h",
    "openstack_instance_exporter_behavior_ports_config_path": "/etc/oie/ports.yml",
    "openstack_instance_exporter_behavior_ports_config_yaml": "behavior: {ports: {inbound_monitored: {22: ssh}}}",
    "openstack_instance_exporter_behavior_rules_config_path": "/etc/oie/rules.yml",
    "openstack_instance_exporter_behavior_rules_config_yaml": "rules: [{id: ssh, ports: [22], signal: ssh}]",
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
    "openstack_instance_exporter_behavior_ports_config_path": "/etc/oie/ports.yml",
    "openstack_instance_exporter_behavior_rules_config_path": "/etc/oie/rules.yml",
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
	dataIntegrityCompareExpected(t, "testdata/contracts/ansible-services.json", dataIntegrityLoadRenderedServiceContracts(t))
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
