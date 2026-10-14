package main

import (
	"bytes"

	"encoding/json"

	"io"
	"os"
	"strings"
	"testing"
)

type threatIntelligenceStructuredLogAdditions struct {
	Version         string                              `json:"version"`
	AdditiveFields  map[string]map[string]string        `json:"additive_fields"`
	ArrayItemFields map[string]map[string]string        `json:"array_item_fields"`
	Messages        []compatibilityStructuredLogMessage `json:"messages"`
}

func loadThreatIntelligenceStructuredLogAdditions(t *testing.T) threatIntelligenceStructuredLogAdditions {
	t.Helper()
	data, err := os.ReadFile("testdata/contracts/threat-summary.json")
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var additions threatIntelligenceStructuredLogAdditions
	if err := decoder.Decode(&additions); err != nil {
		t.Fatalf("decode Threat intelligence structured-log additions: %v", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err != nil {
			t.Fatalf("decode trailing Threat intelligence structured-log data: %v", err)
		}
		t.Fatalf("Threat intelligence structured-log additions contain trailing data: %#v", trailing)
	}
	return additions
}

func TestThreatIntelligenceDocumentationContract(t *testing.T) {
	readme := dashboardDocumentationReadFile(t, "README.md")
	for _, statement := range []string{
		"Threat-feed matches and mining candidates are evidence",
		"retain last-good measurements",
		"Missing or stale data must not be read as healthy zeroes.",
	} {
		if !strings.Contains(readme, statement) {
			t.Errorf("README omits operator guidance %q", statement)
		}
	}
}

func TestThreatIntelligenceREADMEContract(t *testing.T) {
	readme := dashboardDocumentationReadFile(t, "README.md")
	for _, statement := range []string{
		"(testdata/contracts/threat-summary.json)",
		"(testdata/contracts/structured-logs.json)",
		"(ansible_role/openstack_instance_exporter/README.md)",
		"not proof of compromise or mining",
	} {
		if !strings.Contains(readme, statement) {
			t.Errorf("README omits operator guidance %q", statement)
		}
	}
}

func TestThreatIntelligenceStructuredLogAdditionsContract(t *testing.T) {
	additions := loadThreatIntelligenceStructuredLogAdditions(t)
	if additions.Version != "v2.0.0" {
		t.Fatalf("Threat intelligence structured-log version=%q", additions.Version)
	}
	if len(additions.AdditiveFields) != 0 {
		t.Fatalf("Threat intelligence contract retains unsupported additive fields: %#v", additions.AdditiveFields)
	}
	if len(additions.Messages) != 1 || additions.Messages[0].Message != "threat_list_summary" || len(additions.Messages[0].Variants) != 1 {
		t.Fatalf("Threat intelligence structured-log messages=%#v", additions.Messages)
	}
	variant := additions.Messages[0].Variants[0]
	if variant.Level != "WARN" || variant.Category != "threat" || variant.Component != "threat" {
		t.Fatalf("threat_list_summary identity=%#v", variant)
	}
	allowedTypes := map[string]struct{}{"array": {}, "boolean": {}, "number": {}, "string": {}}
	for field, fieldType := range variant.Required {
		if _, ok := allowedTypes[fieldType]; !ok {
			t.Fatalf("threat_list_summary field %s has unsupported type %s", field, fieldType)
		}
	}
	if variant.Required["representative_evidence"] != "array" || len(variant.Required) != 15 || len(variant.Optional) != 0 {
		t.Fatalf("threat_list_summary schema=%#v", variant)
	}
	wantEvidenceTypes := additions.ArrayItemFields["representative_evidence"]
	if len(wantEvidenceTypes) != 9 || wantEvidenceTypes["icmp_id"] != "number" ||
		wantEvidenceTypes["icmp_type"] != "number" || wantEvidenceTypes["icmp_code"] != "number" {
		t.Fatalf("representative_evidence item schema=%v", wantEvidenceTypes)
	}

	sources := compatibilityParseProductionSources(t)
	loggers := compatibilityDiscoverComponentLoggers(t, sources)
	providers := compatibilityDiscoverProviderBindings(t, sources)
	callsites, _, _ := compatibilityDiscoverLogCallsites(t, sources, loggers, providers)
	foundSummary := false
	foundStartupField := false
	for _, callsite := range callsites {
		switch callsite.Message {
		case "threat_list_summary":
			foundSummary = callsite.Level == variant.Level && callsite.Category == variant.Category &&
				callsite.Component == variant.Component && callsite.FieldsKnown && compatibilityCallFieldsFitVariant(callsite.Fields, variant)
		case "startup_config":
			for _, field := range callsite.Fields {
				if field == "threat_ewma_tau" {
					foundStartupField = true
				}
			}
		}
	}
	if !foundSummary || foundStartupField {
		t.Fatalf("Threat intelligence structured-log production coverage: summary=%v startup_tau=%v", foundSummary, foundStartupField)
	}
}

func TestThreatIntelligenceThreatSummaryRuntimeContract(t *testing.T) {
	legacy := loadCompatibilityStructuredLogContract(t)
	additions := loadThreatIntelligenceStructuredLogAdditions(t)
	variant := additions.Messages[0].Variants[0]

	buffer, restore := compatibilityCaptureStructuredLogs()
	defer restore()

	local := IPStrToKey("10.0.0.8")
	remote := IPStrToKey("198.51.100.8")
	key := MakeConntrackPairKey(local, 49152, remote, 443, 6, 0, 0, 0)
	tm := &ThreatManager{threatLogMinInterval: 0}
	tm.logThreatHitSummary(
		"TOREXIT", "domain-contract", "server-contract", "instance-contract",
		"project-contract", "project-name-contract", "user-contract",
		map[PairKey]ConntrackEntry{key: {
			Src: "10.0.0.8", Dst: "198.51.100.8", SrcPort: 49152, DstPort: 443, Proto: 6,
		}},
		0,
		map[IPKey]struct{}{local: {}},
		ContactOut,
	)

	events, err := compatibilityDecodeStructuredLogs(buffer.String())
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("threat summary runtime events=%d, want legacy hit plus summary", len(events))
	}
	compatibilityAssertEventMatchesContract(t, legacy, events[0], "threat_list_hit", "default")

	summary := events[1]
	wantFields := compatibilityCopyStringMap(legacy.Envelope.Required)
	for field, fieldType := range legacy.Envelope.NoticeRequired {
		wantFields[field] = fieldType
	}
	for field, fieldType := range variant.Required {
		wantFields[field] = fieldType
	}
	if len(summary) != len(wantFields) {
		t.Fatalf("threat_list_summary fields=%v, want %v", compatibilitySortedMapKeysAny(summary), compatibilitySortedMapKeys(wantFields))
	}
	for field, fieldType := range wantFields {
		value, ok := summary[field]
		if !ok || compatibilityJSONType(value) != fieldType {
			t.Fatalf("threat_list_summary field %s=%#v type=%s, want %s", field, value, compatibilityJSONType(value), fieldType)
		}
	}
	if summary["msg"] != "threat_list_summary" || summary["direction"] != "outbound" || summary["active_flows"] != json.Number("1") {
		t.Fatalf("threat_list_summary identity/count=%#v", summary)
	}
	evidence := summary["representative_evidence"].([]interface{})
	if len(evidence) != 1 {
		t.Fatalf("representative evidence count=%d, want 1", len(evidence))
	}
	representative, ok := evidence[0].(map[string]interface{})
	if !ok {
		t.Fatalf("representative evidence type=%T", evidence[0])
	}
	wantEvidenceTypes := additions.ArrayItemFields["representative_evidence"]
	if len(representative) != len(wantEvidenceTypes) {
		t.Fatalf("representative evidence fields=%v", compatibilitySortedMapKeysAny(representative))
	}
	for field, fieldType := range wantEvidenceTypes {
		if got := compatibilityJSONType(representative[field]); got != fieldType {
			t.Fatalf("representative evidence field %s type=%s, want %s", field, got, fieldType)
		}
	}
}
