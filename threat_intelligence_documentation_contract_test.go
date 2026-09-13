package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

const (
	threatIntelligencePriorGoldenSHA256Path      = "testdata/threat-intelligence-prior-golden-sha256.golden"
	threatIntelligenceStructuredLogAdditionsPath = "testdata/threat-intelligence-structured-log-additions-v2.0.0.golden.json"
)

type threatIntelligenceStructuredLogAdditions struct {
	Version         string                              `json:"version"`
	AdditiveFields  map[string]map[string]string        `json:"additive_fields"`
	ArrayItemFields map[string]map[string]string        `json:"array_item_fields"`
	Messages        []compatibilityStructuredLogMessage `json:"messages"`
}

func loadThreatIntelligenceStructuredLogAdditions(t *testing.T) threatIntelligenceStructuredLogAdditions {
	t.Helper()
	data, err := os.ReadFile(threatIntelligenceStructuredLogAdditionsPath)
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

func threatIntelligenceInheritedStructuredLogCallsite(callsite compatibilityLogCallsite) compatibilityLogCallsite {
	if callsite.Message != "startup_config" || !callsite.FieldsKnown {
		return callsite
	}
	inherited := callsite
	inherited.Fields = make([]string, 0, len(callsite.Fields))
	for _, field := range callsite.Fields {
		if field != "threat_ewma_tau" {
			inherited.Fields = append(inherited.Fields, field)
		}
	}
	return inherited
}

func TestThreatIntelligencePriorGoldenAssetsAreByteFrozen(t *testing.T) {
	manifest, err := os.ReadFile(threatIntelligencePriorGoldenSHA256Path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(manifest)), "\n")
	if len(lines) != 25 {
		t.Fatalf("prior golden hash records=%d, want 25", len(lines))
	}
	seen := make(map[string]struct{}, len(lines))
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 2 || len(fields[0]) != 64 || !strings.HasPrefix(fields[1], "testdata/") {
			t.Fatalf("invalid prior-golden hash record %q", line)
		}
		if _, duplicate := seen[fields[1]]; duplicate {
			t.Fatalf("duplicate prior-golden hash path %q", fields[1])
		}
		seen[fields[1]] = struct{}{}
		content, err := os.ReadFile(fields[1])
		if err != nil {
			t.Fatalf("read frozen golden %s: %v", fields[1], err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(content)); got != fields[0] {
			t.Fatalf("frozen golden %s changed: sha256=%s want=%s", fields[1], got, fields[0])
		}
	}
}

func TestThreatIntelligenceDocumentationContract(t *testing.T) {
	content, err := os.ReadFile("THREAT_INTELLIGENCE.md")
	if err != nil {
		t.Fatalf("read Threat intelligence contract: %v", err)
	}
	contractText := string(content)

	for _, statement := range []string{
		"The threat subsystem uses the five configured feed sources and their documented metric families.",
		"The supported feeds remain Spamhaus, Tor Exit, Tor Relay, Emerging Threats, and the local custom list.",
		"The background collection interval defaults to 15 seconds and its supported range remains 5 seconds through 1 minute, inclusive.",
		"Its default is `2m30s` and startup requires a duration greater than zero.",
		"alpha     = 1 - exp(-dt / tau)",
		"ewma_next = ewma_previous + alpha * (instant - ewma_previous)",
		"The production instant signal is `min(1, unique_active_threat_flows / 10)`.",
		"including a valid observation at Unix epoch zero; the explicit initialized state is the sentinel.",
		"A strictly regressing timestamp rebaselines history to the current instant and new timestamp instead of applying negative elapsed time.",
		"recovery shifts the global and per-instance clocks by the exact union of unavailable intervals, so only successful elapsed time counts.",
		"authoritative fixed-IP membership replacement or detach clear the affected instance history.",
		"Fixed-IP ordering alone is not a boundary.",
		"One history entry is retained per active instance UUID and inactive UUIDs are pruned.",
		"An incomplete conntrack observation or per-instance Libvirt-unavailable observation retains the exact last-fresh combined threat severity; it does not recompute the burst component from different evidence while merely freezing the EWMA.",
		"If that exact instance has no last-fresh combined state, threat severity is unavailable and omitted.",
		"A known stopped or paused state clears retained threat history and output, which remain unavailable until a later eligible running observation establishes new state.",
		"These rules make the same workload comparable at 10-, 15-, and 30-second collection cadences.",
		"A flow listed by Tor Exit and Tor Relay, Spamhaus and Emerging Threats, or a public feed and the custom list therefore contributes one combined active contact, not one contact per list.",
		"Once that cap is reached, the retained set proves a conservative lower bound and the dropped scalar is an overflow marker; duplicate or reordered raw entries mean it is not an exact unique tail cardinality.",
		"Combined severity is already saturated at `1` far below the cap, so tail uncertainty cannot raise it further.",
		"Production scoring applies no feed-count or list-class bonus.",
		"Every enabled and usable list keeps its existing per-list active-flow metric, contact counter, and structured evidence.",
		"A rejected attempt publishes no partial data, preserves the exact last-good set, entries, timestamp, and successful duration, and increments that provider's cumulative error counter once.",
		"Spamhaus IPv4 and IPv6 are one atomic snapshot.",
		"The exact maximum-age boundary is usable.",
		"A successfully loaded one-shot provider with `refresh <= 0`, including a one-shot custom file, remains usable indefinitely.",
		"A complete conntrack interval with zero usable threat sources makes combined threat output unavailable, even when an older numeric history value remains internally retained.",
		"The first later eligible interval after that source outage silently rebaselines the instant, EWMA, and observation timestamp, so unavailable wall time cannot enter the EWMA.",
		"That recovery interval can expose current per-list metrics and silently replaces each per-list previous-contact identity with the recovered current keys, but it does not increment cumulative contact counters or emit instance threat-hit summaries.",
		"The next unchanged complete interval therefore cannot manufacture outage-time new contacts.",
		"One eligible report preserves the exact legacy `threat_list_hit` event for its first canonical representative and adds one `threat_list_summary` event",
		"`-threat.log.min_interval=0` remains an explicit operator opt-out from repeat throttling",
		"The summary's `direction` records the configured list scope as `outbound`, `inbound`, or `any`.",
		"A dropped-only summary has empty legacy scalar endpoints and an empty representative array.",
		"above the 5,000-identity cap it is not presented as exact unique cardinality.",
		"Incomplete conntrack and per-instance-unavailable collections preserve the exact last-fresh combined severity without updating contact identities, counters, EWMA, or summaries.",
		"They clear Intel history and combined output, every provider's previous-contact identity including Spamhaus, and that instance's summary cooldown.",
		"Cumulative per-list Prometheus contact counters deliberately remain monotonic for a still-active UUID.",
		"Threat intelligence preserves existing feed metric names and labels, with layered regression fixtures protecting scoring and lifecycle behavior.",
	} {
		if !strings.Contains(contractText, statement) {
			t.Fatalf("Threat intelligence contract is missing %q", statement)
		}
	}

	wantBounds := `| Matching flow identities retained per instance/list | 5,000 |
| Previous contact identities retained per instance/list | 5,000 |
| Representative evidence records per summary | 4 |
| Global ` + "`THREAT`/`POLICY`" + ` repeat-throttle keys | 4,096 |
| Default repeat interval per instance/list | 5 minutes |
| Line-feed input | 8 MiB |
| Onionoo JSON input | 32 MiB |`
	if !strings.Contains(contractText, wantBounds) {
		t.Fatal("Threat intelligence contract is missing the exact bounded-state table")
	}
}

func TestThreatIntelligenceREADMEContract(t *testing.T) {
	content, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	readme := string(content)
	link := "[`THREAT_INTELLIGENCE.md`](THREAT_INTELLIGENCE.md)"
	if got := strings.Count(readme, link); got != 1 {
		t.Fatalf("README Threat intelligence contract link count=%d, want 1", got)
	}
	for _, statement := range []string{
		"Threat-list history now uses real elapsed time with a `2m30s` default EWMA time constant across the supported 5-second through 1-minute collection range.",
		"One canonical connection contributes once to combined severity even when several lists match, while per-list metrics and evidence remain intact.",
		"Incomplete telemetry retains the exact last-fresh combined signal instead of recomputing one component; without last-fresh state the signal is unavailable.",
		"An interval with no usable threat source is also unavailable, and the first eligible recovery silently rebaselines without charging outage time.",
		"authoritative fixed-IP/runtime boundaries reset episode state without resetting cumulative contact counters.",
		"Feed refreshes replace complete validated snapshots atomically, retain last-good data on failure, and exclude stale or never-loaded sources from scoring",
		"| `threat.ewma_tau` | `2m30s` | Threat-list history EWMA time constant; must be greater than zero. |",
	} {
		if !strings.Contains(readme, statement) {
			t.Fatalf("README is missing Threat intelligence contract statement %q", statement)
		}
	}
}

func TestThreatIntelligencePublicConfigAdditionsAreFrozen(t *testing.T) {
	cli := compatibilityReadNonEmptyLines(t, threatIntelligenceCLIFlagAdditionsGoldenPath)
	if len(cli) != 1 || cli[0] != `threat.ewma_tau|"2m30s"|Threat-list history EWMA time constant` {
		t.Fatalf("Threat intelligence CLI additions=%v", cli)
	}
	ansible := compatibilityReadNonEmptyLines(t, threatIntelligenceAnsibleAdditionsGoldenPath)
	if len(ansible) != 1 || ansible[0] != "openstack_instance_exporter_threat_ewma_tau" {
		t.Fatalf("Threat intelligence Ansible additions=%v", ansible)
	}
}

func TestThreatIntelligenceStructuredLogAdditionsContract(t *testing.T) {
	additions := loadThreatIntelligenceStructuredLogAdditions(t)
	if additions.Version != "v2.0.0-threat-intelligence" {
		t.Fatalf("Threat intelligence structured-log version=%q", additions.Version)
	}
	if got := additions.AdditiveFields["startup_config"]["threat_ewma_tau"]; got != "string" {
		t.Fatalf("startup_config threat_ewma_tau additive type=%q, want string", got)
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
	if variant.Required["representative_evidence"] != "array" || len(variant.Required) != 16 || len(variant.Optional) != 0 {
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
	if !foundSummary || !foundStartupField {
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

func TestThreatIntelligencePrometheusRegistryRemainsFrozen(t *testing.T) {
	orderedLabels := compatibilityDescriptorLabelOrder(t)
	if resourceTelemetryOIEFamilyCount != 134 {
		t.Fatalf("frozen Resource telemetry family constant=%d, want 134", resourceTelemetryOIEFamilyCount)
	}
	if got := len(orderedLabels); got != inventoryOIEFamilyCount {
		t.Fatalf("current descriptor families=%d, want %d", got, inventoryOIEFamilyCount)
	}
	alertValidationNames := alertValidationMetricFamilyNames(t)
	for name := range laterMetricFamilyNames() {
		alertValidationNames[name] = struct{}{}
	}
	inheritedDescriptors := 0
	for name := range orderedLabels {
		if _, added := alertValidationNames[name]; !added {
			inheritedDescriptors++
		}
	}
	if inheritedDescriptors != resourceTelemetryOIEFamilyCount {
		t.Fatalf("Threat intelligence descriptor subset=%d, want frozen count 134", inheritedDescriptors)
	}
	families, descriptorNames := dataIntegrityFullRegistryFixture(t)
	schema := compatibilityOIESchemaByName(t, families, orderedLabels)
	inheritedFixture := 0
	for name := range descriptorNames {
		if _, added := alertValidationNames[name]; !added {
			inheritedFixture++
		}
	}
	inheritedGathered := 0
	for name := range schema {
		if _, added := alertValidationNames[name]; !added {
			inheritedGathered++
		}
	}
	if inheritedFixture != 134 || inheritedGathered != 134 {
		t.Fatalf("Threat intelligence runtime registry subset no longer matches the frozen 134-family contract: descriptors=%d gathered=%d", inheritedFixture, inheritedGathered)
	}
}
