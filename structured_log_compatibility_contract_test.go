package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

const compatibilityStructuredLogGoldenPath = "testdata/compatibility-structured-log-contract-baseline.golden.json"

type compatibilityStructuredLogContract struct {
	SchemaVersion       int                                   `json:"schema_version"`
	Envelope            compatibilityStructuredLogEnvelope    `json:"envelope"`
	PlaintextExceptions []compatibilityStructuredLogPlaintext `json:"plaintext_exceptions"`
	DynamicSources      []compatibilityStructuredLogDynamic   `json:"dynamic_sources"`
	Messages            []compatibilityStructuredLogMessage   `json:"messages"`
}

type compatibilityStructuredLogEnvelope struct {
	Required       map[string]string `json:"required"`
	NoticeRequired map[string]string `json:"notice_required"`
}

type compatibilityStructuredLogPlaintext struct {
	Name   string `json:"name"`
	Source string `json:"source"`
	Format string `json:"format"`
}

type compatibilityStructuredLogDynamic struct {
	Kind             string   `json:"kind"`
	Source           string   `json:"source"`
	ConcreteMessages []string `json:"concrete_messages"`
	OpenEnded        bool     `json:"open_ended"`
}

type compatibilityStructuredLogMessage struct {
	Message  string                              `json:"message"`
	Variants []compatibilityStructuredLogVariant `json:"variants"`
}

type compatibilityStructuredLogVariant struct {
	Name      string            `json:"name"`
	Level     string            `json:"level"`
	Category  string            `json:"category"`
	Component string            `json:"component"`
	Required  map[string]string `json:"required"`
	Optional  map[string]string `json:"optional"`
}

type compatibilityParsedSource struct {
	Path string
	File *ast.File
}

type compatibilityLoggerIdentity struct {
	Category  string
	Component string
}

type compatibilityProviderBinding struct {
	Name   string
	Logger string
}

type compatibilityLogCallsite struct {
	Message     string
	Level       string
	Category    string
	Component   string
	Fields      []string
	FieldsKnown bool
	Location    string
}

func loadCompatibilityStructuredLogContract(t *testing.T) compatibilityStructuredLogContract {
	t.Helper()
	b, err := os.ReadFile(compatibilityStructuredLogGoldenPath)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	var contract compatibilityStructuredLogContract
	if err := decoder.Decode(&contract); err != nil {
		t.Fatalf("decode structured-log contract: %v", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err != nil {
			t.Fatalf("decode trailing structured-log contract data: %v", err)
		}
		t.Fatalf("structured-log contract contains a trailing JSON value: %#v", trailing)
	}
	return contract
}

func TestCompatibilityStructuredLogGoldenIsCompleteAndValid(t *testing.T) {
	contract := loadCompatibilityStructuredLogContract(t)
	if contract.SchemaVersion != 1 {
		t.Fatalf("structured-log baseline schema version=%d, want 1", contract.SchemaVersion)
	}
	if len(contract.Messages) != 47 {
		t.Fatalf("structured-log message count=%d, want 47", len(contract.Messages))
	}
	wantEnvelope := map[string]string{
		"category": "string", "component": "string", "level": "string", "msg": "string", "time": "string",
	}
	if !compatibilityEqualStringMap(contract.Envelope.Required, wantEnvelope) {
		t.Fatalf("structured-log envelope=%v, want %v", contract.Envelope.Required, wantEnvelope)
	}
	if !compatibilityEqualStringMap(contract.Envelope.NoticeRequired, map[string]string{"severity_class": "string"}) {
		t.Fatalf("structured-log notice envelope=%v", contract.Envelope.NoticeRequired)
	}

	allowedTypes := map[string]struct{}{"boolean": {}, "number": {}, "string": {}}
	allowedLevels := map[string]struct{}{"DEBUG": {}, "ERROR": {}, "INFO": {}, "WARN": {}}
	seenMessages := make(map[string]struct{}, len(contract.Messages))
	previousMessage := ""
	for messageIndex, message := range contract.Messages {
		if message.Message == "" || len(message.Variants) == 0 {
			t.Fatalf("message %d has an empty name or no variants: %#v", messageIndex, message)
		}
		if previousMessage != "" && message.Message <= previousMessage {
			t.Fatalf("messages are not strictly sorted: %q follows %q", message.Message, previousMessage)
		}
		previousMessage = message.Message
		if _, duplicate := seenMessages[message.Message]; duplicate {
			t.Fatalf("duplicate structured-log message %q", message.Message)
		}
		seenMessages[message.Message] = struct{}{}
		seenVariants := make(map[string]struct{}, len(message.Variants))
		for variantIndex, variant := range message.Variants {
			if variant.Name == "" || variant.Category == "" || variant.Component == "" {
				t.Fatalf("message %q variant %d has an empty identity: %#v", message.Message, variantIndex, variant)
			}
			if _, ok := allowedLevels[variant.Level]; !ok {
				t.Fatalf("message %q variant %q has invalid level %q", message.Message, variant.Name, variant.Level)
			}
			if _, duplicate := seenVariants[variant.Name]; duplicate {
				t.Fatalf("message %q has duplicate variant %q", message.Message, variant.Name)
			}
			seenVariants[variant.Name] = struct{}{}
			if variant.Required == nil || variant.Optional == nil {
				t.Fatalf("message %q variant %q must explicitly record required and optional fields", message.Message, variant.Name)
			}
			for field, fieldType := range variant.Required {
				if _, envelope := contract.Envelope.Required[field]; envelope {
					t.Fatalf("message %q variant %q repeats envelope field %q", message.Message, variant.Name, field)
				}
				if _, notice := contract.Envelope.NoticeRequired[field]; notice {
					t.Fatalf("message %q variant %q repeats notice field %q", message.Message, variant.Name, field)
				}
				if _, ok := allowedTypes[fieldType]; !ok {
					t.Fatalf("message %q variant %q field %q has invalid type %q", message.Message, variant.Name, field, fieldType)
				}
			}
			for field, fieldType := range variant.Optional {
				if _, duplicate := variant.Required[field]; duplicate {
					t.Fatalf("message %q variant %q field %q is both required and optional", message.Message, variant.Name, field)
				}
				if _, ok := allowedTypes[fieldType]; !ok {
					t.Fatalf("message %q variant %q optional field %q has invalid type %q", message.Message, variant.Name, field, fieldType)
				}
			}
		}
	}

	if len(contract.PlaintextExceptions) != 1 || contract.PlaintextExceptions[0].Name != "failed_to_open_logfile" {
		t.Fatalf("plaintext structured-log exceptions=%#v, want only failed_to_open_logfile", contract.PlaintextExceptions)
	}
	if len(contract.DynamicSources) != 2 {
		t.Fatalf("structured-log dynamic source count=%d, want 2", len(contract.DynamicSources))
	}
	for _, dynamic := range contract.DynamicSources {
		if dynamic.Kind == "" || dynamic.Source == "" || len(dynamic.ConcreteMessages) == 0 {
			t.Fatalf("invalid structured-log dynamic source: %#v", dynamic)
		}
		for _, message := range dynamic.ConcreteMessages {
			if _, ok := seenMessages[message]; !ok {
				t.Fatalf("dynamic source %q references unrecorded message %q", dynamic.Kind, message)
			}
		}
	}
}

func TestCompatibilityStructuredLogGoldenSerializesWithRuntimeTypes(t *testing.T) {
	if compatibilityRunIsolatedStructuredLogTest(t) {
		return
	}
	contract := loadCompatibilityStructuredLogContract(t)
	buf, restore := compatibilityCaptureStructuredLogs()
	defer restore()

	type expectedEvent struct {
		Message string
		Variant compatibilityStructuredLogVariant
		Fields  map[string]string
	}
	expected := make([]expectedEvent, 0, len(contract.Messages))
	for _, message := range contract.Messages {
		for _, variant := range message.Variants {
			fields := compatibilityCopyStringMap(variant.Required)
			compatibilityEmitContractEvent(message.Message, variant, fields)
			expected = append(expected, expectedEvent{Message: message.Message, Variant: variant, Fields: fields})
			if len(variant.Optional) > 0 {
				withOptional := compatibilityCopyStringMap(variant.Required)
				for field, fieldType := range variant.Optional {
					withOptional[field] = fieldType
				}
				compatibilityEmitContractEvent(message.Message, variant, withOptional)
				expected = append(expected, expectedEvent{Message: message.Message, Variant: variant, Fields: withOptional})
			}
		}
	}

	events, err := compatibilityDecodeStructuredLogs(buf.String())
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != len(expected) {
		t.Fatalf("serialized structured-log events=%d, want %d", len(events), len(expected))
	}
	for index, event := range events {
		want := expected[index]
		if event["msg"] != want.Message || event["level"] != want.Variant.Level ||
			event["category"] != want.Variant.Category || event["component"] != want.Variant.Component {
			t.Fatalf("event %d identity=%#v, want msg=%q variant=%#v", index, event, want.Message, want.Variant)
		}
		wantFields := compatibilityCopyStringMap(contract.Envelope.Required)
		if want.Variant.Level == "WARN" {
			for field, fieldType := range contract.Envelope.NoticeRequired {
				wantFields[field] = fieldType
			}
			if event["severity_class"] != "notice" {
				t.Fatalf("event %d notice severity_class=%#v, want notice", index, event["severity_class"])
			}
		}
		for field, fieldType := range want.Fields {
			wantFields[field] = fieldType
		}
		if len(event) != len(wantFields) {
			t.Fatalf("event %d msg=%q fields=%v, want exact schema %v", index, want.Message, compatibilitySortedMapKeysAny(event), compatibilitySortedMapKeys(wantFields))
		}
		for field, fieldType := range wantFields {
			value, ok := event[field]
			if !ok {
				t.Fatalf("event %d msg=%q missing field %q", index, want.Message, field)
			}
			if gotType := compatibilityJSONType(value); gotType != fieldType {
				t.Fatalf("event %d msg=%q field %q type=%s value=%#v, want %s", index, want.Message, field, gotType, value, fieldType)
			}
		}
	}
}

func TestCompatibilityStructuredLogAdaptersPreserveRuntimeSerialization(t *testing.T) {
	if compatibilityRunIsolatedStructuredLogTest(t) {
		return
	}
	buf, restore := compatibilityCaptureStructuredLogs()
	defer restore()

	logger := NewComponentLogger("contract", "adapter")
	stamp := time.Date(2026, time.August, 29, 12, 34, 56, 0, time.UTC)
	logger.Debug("adapter_debug", "duration", 3*time.Second)
	logger.Info("adapter_info", "time_value", stamp)
	logger.Notice("adapter_notice", "enabled", true)
	logger.Error("adapter_error", "err", errors.New("contract error"))

	events, err := compatibilityDecodeStructuredLogs(buf.String())
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 4 {
		t.Fatalf("adapter event count=%d, want 4; events=%#v", len(events), events)
	}
	wants := []struct {
		message   string
		level     string
		field     string
		fieldType string
	}{
		{"adapter_debug", "DEBUG", "duration", "number"},
		{"adapter_info", "INFO", "time_value", "string"},
		{"adapter_notice", "WARN", "enabled", "boolean"},
		{"adapter_error", "ERROR", "err", "string"},
	}
	for index, want := range wants {
		event := events[index]
		if event["msg"] != want.message || event["level"] != want.level || event["category"] != "contract" || event["component"] != "adapter" {
			t.Fatalf("adapter event %d=%#v, want msg=%s level=%s contract/adapter", index, event, want.message, want.level)
		}
		if gotType := compatibilityJSONType(event[want.field]); gotType != want.fieldType {
			t.Fatalf("adapter event %s field %s type=%s, want %s", want.message, want.field, gotType, want.fieldType)
		}
	}
	if events[2]["severity_class"] != "notice" {
		t.Fatalf("notice adapter event=%#v, want severity_class=notice", events[2])
	}
}

func TestCompatibilityBehaviorAlertProductionVariantsMatchGolden(t *testing.T) {
	if compatibilityRunIsolatedStructuredLogTest(t) {
		return
	}
	contract := loadCompatibilityStructuredLogContract(t)
	buf, restore := compatibilityCaptureStructuredLogs()
	defer restore()

	target := behaviorAlertTarget{
		Domain: "domain-contract", ServerName: "server-contract", InstanceUUID: "instance-contract",
		ProjectUUID: "project-contract", ProjectName: "project-name-contract", UserUUID: "user-contract",
	}
	base := behaviorAlertEvent{
		Feature: BehaviorFeature{
			Direction: "outbound", Flows: 10, UniqueRemotes: 2, NewRemotes: 1, UniqueDstPorts: 3,
			NewDstPorts: 1, MaxSingleRemote: 7, MaxSingleDstPort: 8,
		},
		Evidence: behaviorAlertEvidence{
			TopDstPort: 22, TopDstPortName: "ssh", TopRemoteIP: "198.51.100.8",
			TopRemoteShare: 0.7, TopPortShare: 0.8, EvidenceMode: "exact",
		},
		Kind: "outbound_horizontal_scan_suspected", Reason: "contract", Detail: "contract",
		PersistenceHits: 3, PersistenceRequired: 3, EmitReason: "new_kind",
		SeverityScore: 60, ConfidenceScore: 70, SeverityBand: "high", PriorityBasis: "contract",
		Priority: "P3", HostImpact: 0.1, BehaviorSignal: 0.5, SrcIP: "10.0.0.8", DstIP: "198.51.100.8",
	}

	fallback := &ConntrackManager{}
	fallback.routeBehaviorAlert(target, buildBehaviorAlertKVs(base))

	tm := &ThreatManager{threatLogMinInterval: 0}
	routed := &ConntrackManager{LogThreat: tm.logThreatEvent}
	approximate := base
	approximate.Feature.RemoteEvidenceApproximate = true
	approximate.Feature.RemoteMapCapped = true
	routed.routeBehaviorAlert(target, buildBehaviorAlertKVs(approximate))
	routed.routeBehaviorAlert(target, buildBehaviorAlertKVs(base))

	mining := base
	mining.Kind = miningBehaviorKind
	mining.Mining = miningDetectionEvidence{
		Valid: true, Confidence: miningPortConfidenceHigh,
		miningTierSummary: miningTierSummary{Flows: 4, RepliedFlows: 3, UniqueRemotes: 2, UniquePorts: 1},
	}
	routed.routeBehaviorAlert(target, buildBehaviorAlertKVs(mining))

	events, err := compatibilityDecodeStructuredLogs(buf.String())
	if err != nil {
		t.Fatal(err)
	}
	wantVariants := []string{"fallback_generic", "routed_approximate", "routed_generic", "routed_mining"}
	if len(events) != len(wantVariants) {
		t.Fatalf("behavior alert event count=%d, want %d", len(events), len(wantVariants))
	}
	for index, variant := range wantVariants {
		compatibilityAssertEventMatchesContract(t, contract, events[index], "behavior_alert", variant)
	}
}

func TestCompatibilityResourceEventProductionBuilderMatchesGolden(t *testing.T) {
	if compatibilityRunIsolatedStructuredLogTest(t) {
		return
	}
	contract := loadCompatibilityStructuredLogContract(t)
	buf, restore := compatibilityCaptureStructuredLogs()
	defer restore()

	axis := resourceAxisResult{
		Available: true, Fresh: true, State: resourceAxisStateFresh, PRaw: 0.8, Conf: 0.9, Impact: 0.7, PEff: 0.6,
		EWMA: 0.5, Sev: 80, Alpha: 0.4, Tau: 120,
	}
	out := resourceV2Output{
		Available: true, Fresh: true, DtSeconds: 15, OverallRaw: 80, OverallFinal: 80,
		AxesGE90: 1, TopAxis: "cpu", CPU: axis, MEM: axis, DISK: axis, NET: axis,
	}
	state := &resourceV2State{LastBand: 0, OverallHi95Streak: 2}
	collector := &MetricsCollector{}
	collector.maybeLogResourceV2Event(
		"domain-contract", "server-contract", "instance-contract", "project-contract",
		"project-name-contract", "user-contract", out, state,
	)

	events, err := compatibilityDecodeStructuredLogs(buf.String())
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("resource event count=%d, want 1", len(events))
	}
	// Resource telemetry layers per-axis freshness evidence onto the development baseline resource event.
	// Remove only those approved additive keys before asserting that the frozen
	// historical event contract is otherwise byte-for-byte complete.
	baselineEvent := make(map[string]interface{}, len(events[0]))
	for key, value := range events[0] {
		baselineEvent[key] = value
	}
	for _, prefix := range []string{"cpu", "mem", "disk", "net"} {
		delete(baselineEvent, prefix+"_fresh")
		delete(baselineEvent, prefix+"_available")
		delete(baselineEvent, prefix+"_last_success_timestamp_seconds")
		delete(baselineEvent, prefix+"_stale_seconds")
	}
	compatibilityAssertEventMatchesContract(t, contract, baselineEvent, "resource_v2_event", "default")
}

func TestCompatibilityStructuredLogDecoderRejectsDuplicateKeys(t *testing.T) {
	if compatibilityRunIsolatedStructuredLogTest(t) {
		return
	}
	buf, restore := compatibilityCaptureStructuredLogs()
	defer restore()
	logKV(LogLevelInfo, "contract", "duplicates", "duplicate_probe", "same", 1, "same", 2)
	if _, err := compatibilityDecodeStructuredLogs(buf.String()); err == nil {
		t.Fatal("structured-log decoder accepted duplicate JSON fields")
	}
}

func TestCompatibilityStructuredLogProductionCallsitesMatchGolden(t *testing.T) {
	contract := loadCompatibilityStructuredLogContract(t)
	threatIntelligenceAdditions := loadThreatIntelligenceStructuredLogAdditions(t)
	contractByMessage := make(map[string]compatibilityStructuredLogMessage, len(contract.Messages)+len(threatIntelligenceAdditions.Messages))
	for _, message := range contract.Messages {
		contractByMessage[message.Message] = message
	}
	for _, message := range threatIntelligenceAdditions.Messages {
		if _, inherited := contractByMessage[message.Message]; inherited {
			t.Fatalf("Threat intelligence structured-log addition duplicates inherited message %q", message.Message)
		}
		contractByMessage[message.Message] = message
	}

	sources := compatibilityParseProductionSources(t)
	loggers := compatibilityDiscoverComponentLoggers(t, sources)
	providers := compatibilityDiscoverProviderBindings(t, sources)
	callsites, providerDynamicCounts, threatDispatches := compatibilityDiscoverLogCallsites(t, sources, loggers, providers)

	if providerDynamicCounts["_refresh"] != 1 || providerDynamicCounts["_refresh_failed"] != 1 || len(providerDynamicCounts) != 2 {
		t.Fatalf("provider dynamic log callsites=%v, want one success and one failure", providerDynamicCounts)
	}
	if threatDispatches != 1 {
		t.Fatalf("dynamic logThreatEvent dispatch count=%d, want 1", threatDispatches)
	}

	seenMessages := make(map[string]int, len(contract.Messages))
	for _, callsite := range callsites {
		message, ok := contractByMessage[callsite.Message]
		if !ok {
			t.Errorf("unrecorded production structured-log message %q at %s", callsite.Message, callsite.Location)
			continue
		}
		seenMessages[callsite.Message]++
		matched := false
		baselineCallsite := threatIntelligenceInheritedStructuredLogCallsite(callsite)
		for _, variant := range message.Variants {
			if variant.Level != baselineCallsite.Level || variant.Category != baselineCallsite.Category || variant.Component != baselineCallsite.Component {
				continue
			}
			if baselineCallsite.FieldsKnown && !compatibilityCallFieldsFitVariant(baselineCallsite.Fields, variant) {
				continue
			}
			matched = true
			break
		}
		if !matched {
			t.Errorf("production callsite has no matching golden variant: %#v", callsite)
		}
	}
	for message := range contractByMessage {
		if seenMessages[message] == 0 {
			t.Errorf("golden structured-log message %q has no production callsite", message)
		}
	}

	compatibilityValidateDynamicSourceContracts(t, contract, providers, loggers)
	compatibilityValidatePlaintextExceptions(t, contract)
}

func TestCompatibilityStructuredLogProviderBindingsAreResolved(t *testing.T) {
	sources := compatibilityParseProductionSources(t)
	providers := compatibilityDiscoverProviderBindings(t, sources)
	want := []compatibilityProviderBinding{
		{Name: "CustomList", Logger: "logCustomlistThreat"},
		{Name: "EmergingThreats", Logger: "logEmergingthreatsThreat"},
		{Name: "TorExit", Logger: "logTorexitThreat"},
		{Name: "TorRelay", Logger: "logTorrelayThreat"},
	}
	if len(providers) != len(want) {
		t.Fatalf("production provider bindings=%#v, want %#v", providers, want)
	}
	for index := range want {
		if providers[index] != want[index] {
			t.Fatalf("production provider bindings=%#v, want %#v", providers, want)
		}
	}
}

func compatibilityParseProductionSources(t *testing.T) []compatibilityParsedSource {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		paths = append(paths, entry.Name())
	}
	sort.Strings(paths)
	fset := token.NewFileSet()
	sources := make([]compatibilityParsedSource, 0, len(paths))
	for _, path := range paths {
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse production source %s: %v", path, err)
		}
		sources = append(sources, compatibilityParsedSource{Path: path, File: file})
	}
	return sources
}

func compatibilityDiscoverComponentLoggers(t *testing.T, sources []compatibilityParsedSource) map[string]compatibilityLoggerIdentity {
	t.Helper()
	loggers := make(map[string]compatibilityLoggerIdentity)
	for _, source := range sources {
		ast.Inspect(source.File, func(node ast.Node) bool {
			valueSpec, ok := node.(*ast.ValueSpec)
			if !ok || len(valueSpec.Names) != len(valueSpec.Values) {
				return true
			}
			for index, value := range valueSpec.Values {
				call, ok := value.(*ast.CallExpr)
				if !ok || len(call.Args) != 2 {
					continue
				}
				fun, ok := call.Fun.(*ast.Ident)
				if !ok || fun.Name != "NewComponentLogger" {
					continue
				}
				category, categoryOK := compatibilityASTString(call.Args[0])
				component, componentOK := compatibilityASTString(call.Args[1])
				if !categoryOK || !componentOK {
					t.Fatalf("%s: component logger %s has nonliteral identity", source.Path, valueSpec.Names[index].Name)
				}
				loggers[valueSpec.Names[index].Name] = compatibilityLoggerIdentity{Category: category, Component: component}
			}
			return true
		})
	}
	if len(loggers) != 10 {
		t.Fatalf("production component logger count=%d, want 10: %v", len(loggers), loggers)
	}
	return loggers
}

func compatibilityDiscoverProviderBindings(t *testing.T, sources []compatibilityParsedSource) []compatibilityProviderBinding {
	t.Helper()
	providers := make([]compatibilityProviderBinding, 0, 4)
	for _, source := range sources {
		if source.Path != "prometheus_scrape_cycle_collector_factory.go" {
			continue
		}
		var factory *ast.FuncDecl
		for _, declaration := range source.File.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if ok && function.Name.Name == "newThreatProviders" {
				factory = function
				break
			}
		}
		if factory == nil {
			t.Fatalf("%s: newThreatProviders is missing", source.Path)
		}
		ast.Inspect(factory.Body, func(node ast.Node) bool {
			literal, ok := node.(*ast.CompositeLit)
			if !ok {
				return true
			}
			if literal.Type != nil {
				typeName, ok := literal.Type.(*ast.Ident)
				if !ok || typeName.Name != "IPThreatProvider" {
					return true
				}
			}
			var name, logger string
			for _, element := range literal.Elts {
				pair, ok := element.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := pair.Key.(*ast.Ident)
				if !ok {
					continue
				}
				switch key.Name {
				case "Name":
					name, _ = compatibilityASTString(pair.Value)
				case "Logger":
					if value, ok := pair.Value.(*ast.Ident); ok {
						logger = value.Name
					}
				}
			}
			if name != "" || logger != "" {
				if name == "" || logger == "" {
					t.Fatalf("%s: incomplete IPThreatProvider log binding name=%q logger=%q", source.Path, name, logger)
				}
				providers = append(providers, compatibilityProviderBinding{Name: name, Logger: logger})
			}
			return true
		})
	}
	sort.Slice(providers, func(i, j int) bool { return providers[i].Name < providers[j].Name })
	if len(providers) != 4 {
		t.Fatalf("production threat provider count=%d, want 4: %#v", len(providers), providers)
	}
	return providers
}

func compatibilityDiscoverLogCallsites(
	t *testing.T,
	sources []compatibilityParsedSource,
	loggers map[string]compatibilityLoggerIdentity,
	providers []compatibilityProviderBinding,
) ([]compatibilityLogCallsite, map[string]int, int) {
	t.Helper()
	callsites := make([]compatibilityLogCallsite, 0, 64)
	providerDynamicCounts := make(map[string]int)
	threatDispatches := 0
	for _, source := range sources {
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, source.Path, nil, 0)
		if err != nil {
			t.Fatalf("reparse production source %s: %v", source.Path, err)
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			location := fset.Position(call.Pos()).String()
			if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == "logKV" {
				if len(call.Args) < 4 {
					t.Fatalf("malformed logKV call at %s", location)
				}
				level, ok := compatibilityASTLogLevel(call.Args[0])
				if !ok {
					t.Fatalf("nonliteral logKV level at %s", location)
				}
				message, messageOK := compatibilityASTString(call.Args[3])
				if !messageOK {
					event, eventOK := call.Args[3].(*ast.Ident)
					category, categoryOK := call.Args[1].(*ast.Ident)
					component, componentOK := call.Args[2].(*ast.Ident)
					function, receiver := compatibilityASTEnclosingFunction(parsed, call.Pos())
					if eventOK && event.Name == "event" && categoryOK && category.Name == "category" &&
						componentOK && component.Name == "component" && level == "WARN" &&
						source.Path == "threat_hits_and_metrics.go" && function == "logThreatEvent" && receiver == "ThreatManager" {
						threatDispatches++
						return true
					}
					t.Fatalf("unapproved dynamic logKV message at %s", location)
				}
				category, categoryOK := compatibilityASTString(call.Args[1])
				component, componentOK := compatibilityASTString(call.Args[2])
				if !categoryOK || !componentOK {
					t.Fatalf("nonliteral logKV identity at %s", location)
				}
				fields, fieldsKnown := compatibilityASTCallFields(call, 4)
				callsites = append(callsites, compatibilityLogCallsite{Message: message, Level: level, Category: category, Component: component, Fields: fields, FieldsKnown: fieldsKnown, Location: location})
				return true
			}

			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if selector.Sel.Name == "LogThreat" && len(call.Args) >= 2 {
				tag, tagOK := compatibilityASTString(call.Args[0])
				message, messageOK := compatibilityASTString(call.Args[1])
				if !tagOK || !messageOK {
					t.Fatalf("dynamic LogThreat callback invocation at %s", location)
				}
				category := "threat"
				switch strings.ToUpper(tag) {
				case "BEHAVIOR":
					category = "behavior"
				case "POLICY":
					category = "policy"
				}
				callsites = append(callsites, compatibilityLogCallsite{Message: message, Level: "WARN", Category: category, Component: category, Location: location})
				return true
			}

			level, loggerMethod := compatibilityComponentLoggerLevel(selector.Sel.Name)
			if !loggerMethod || len(call.Args) == 0 {
				return true
			}
			if receiver, ok := selector.X.(*ast.Ident); ok {
				identity, registered := loggers[receiver.Name]
				if !registered {
					return true
				}
				message, ok := compatibilityASTString(call.Args[0])
				if !ok {
					t.Fatalf("unapproved dynamic ComponentLogger message at %s", location)
				}
				fields, fieldsKnown := compatibilityASTCallFields(call, 1)
				callsites = append(callsites, compatibilityLogCallsite{Message: message, Level: level, Category: identity.Category, Component: identity.Component, Fields: fields, FieldsKnown: fieldsKnown, Location: location})
				return true
			}
			receiver, ok := selector.X.(*ast.SelectorExpr)
			if !ok || receiver.Sel.Name != "Logger" {
				return true
			}
			suffix, ok := compatibilityProviderMessageSuffix(call.Args[0])
			if !ok {
				t.Fatalf("unapproved provider logger message at %s", location)
			}
			providerDynamicCounts[suffix]++
			fields, fieldsKnown := compatibilityASTCallFields(call, 1)
			for _, provider := range providers {
				identity, exists := loggers[provider.Logger]
				if !exists {
					t.Fatalf("provider %q references unknown component logger %q", provider.Name, provider.Logger)
				}
				message := strings.ToLower(provider.Name) + suffix
				callsites = append(callsites, compatibilityLogCallsite{Message: message, Level: level, Category: identity.Category, Component: identity.Component, Fields: fields, FieldsKnown: fieldsKnown, Location: location + "[" + provider.Name + "]"})
			}
			return true
		})
	}
	return callsites, providerDynamicCounts, threatDispatches
}

func compatibilityValidateDynamicSourceContracts(
	t *testing.T,
	contract compatibilityStructuredLogContract,
	providers []compatibilityProviderBinding,
	loggers map[string]compatibilityLoggerIdentity,
) {
	t.Helper()
	byKind := make(map[string]compatibilityStructuredLogDynamic, len(contract.DynamicSources))
	for _, dynamic := range contract.DynamicSources {
		byKind[dynamic.Kind] = dynamic
	}
	providerDynamic, ok := byKind["provider_refresh_name"]
	if !ok || providerDynamic.OpenEnded {
		t.Fatalf("provider dynamic source is missing or incorrectly open-ended: %#v", providerDynamic)
	}
	wantProviderMessages := make([]string, 0, len(providers)*2)
	for _, provider := range providers {
		if _, ok := loggers[provider.Logger]; !ok {
			t.Fatalf("provider %q logger %q is not registered", provider.Name, provider.Logger)
		}
		prefix := strings.ToLower(provider.Name)
		wantProviderMessages = append(wantProviderMessages, prefix+"_refresh", prefix+"_refresh_failed")
	}
	sort.Strings(wantProviderMessages)
	gotProviderMessages := append([]string(nil), providerDynamic.ConcreteMessages...)
	sort.Strings(gotProviderMessages)
	if strings.Join(gotProviderMessages, "\n") != strings.Join(wantProviderMessages, "\n") {
		t.Fatalf("provider dynamic messages=%v, want %v", gotProviderMessages, wantProviderMessages)
	}

	threatDynamic, ok := byKind["threat_event_callback"]
	if !ok || !threatDynamic.OpenEnded || len(threatDynamic.ConcreteMessages) != 1 || threatDynamic.ConcreteMessages[0] != "behavior_alert" {
		t.Fatalf("threat event dynamic source=%#v, want open-ended path with current behavior_alert", threatDynamic)
	}
}

func compatibilityValidatePlaintextExceptions(t *testing.T, contract compatibilityStructuredLogContract) {
	t.Helper()
	exception := contract.PlaintextExceptions[0]
	b, err := os.ReadFile(exception.Source)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), strconv.Quote(exception.Format)) {
		t.Fatalf("plaintext exception %q format no longer exists in %s", exception.Name, exception.Source)
	}
}

func compatibilityEmitContractEvent(message string, variant compatibilityStructuredLogVariant, fields map[string]string) {
	keys := compatibilitySortedMapKeys(fields)
	args := make([]interface{}, 0, len(keys)*2)
	for _, field := range keys {
		args = append(args, field, compatibilitySampleValue(fields[field]))
	}
	level := map[string]LogLevel{
		"DEBUG": LogLevelDebug,
		"ERROR": LogLevelError,
		"INFO":  LogLevelInfo,
		"WARN":  LogLevelNotice,
	}[variant.Level]
	logKV(level, variant.Category, variant.Component, message, args...)
}

func compatibilityAssertEventMatchesContract(
	t *testing.T,
	contract compatibilityStructuredLogContract,
	event map[string]interface{},
	messageName string,
	variantName string,
) {
	t.Helper()
	var selected *compatibilityStructuredLogVariant
	for messageIndex := range contract.Messages {
		message := &contract.Messages[messageIndex]
		if message.Message != messageName {
			continue
		}
		for variantIndex := range message.Variants {
			if message.Variants[variantIndex].Name == variantName {
				selected = &message.Variants[variantIndex]
				break
			}
		}
	}
	if selected == nil {
		t.Fatalf("structured-log contract has no %s/%s variant", messageName, variantName)
	}
	wantFields := compatibilityCopyStringMap(contract.Envelope.Required)
	for field, fieldType := range selected.Required {
		wantFields[field] = fieldType
	}
	if selected.Level == "WARN" {
		for field, fieldType := range contract.Envelope.NoticeRequired {
			wantFields[field] = fieldType
		}
	}
	if len(event) != len(wantFields) {
		t.Fatalf("event %s/%s fields=%v, want %v", messageName, variantName, compatibilitySortedMapKeysAny(event), compatibilitySortedMapKeys(wantFields))
	}
	for field, fieldType := range wantFields {
		value, ok := event[field]
		if !ok {
			t.Fatalf("event %s/%s is missing field %q", messageName, variantName, field)
		}
		if gotType := compatibilityJSONType(value); gotType != fieldType {
			t.Fatalf("event %s/%s field %q type=%s value=%#v, want %s", messageName, variantName, field, gotType, value, fieldType)
		}
	}
	if event["msg"] != messageName || event["level"] != selected.Level ||
		event["category"] != selected.Category || event["component"] != selected.Component {
		t.Fatalf("event %s/%s identity=%#v, want %#v", messageName, variantName, event, *selected)
	}
}

// These contracts capture the process-wide logger and assert the complete event
// stream. Collector tests can still be finishing their asynchronous shutdown
// logs after their cleanup closes a channel. Run log-capture contracts in a fresh
// test process so those unrelated events cannot enter the stream; keep every
// schema, ordering and event-count assertion intact.
func compatibilityRunIsolatedStructuredLogTest(t *testing.T) bool {
	t.Helper()
	const isolatedTestEnv = "OIE_ISOLATED_STRUCTURED_LOG_TEST"
	if os.Getenv(isolatedTestEnv) == t.Name() {
		return false
	}
	cmd := exec.Command(os.Args[0], "-test.run=^"+regexp.QuoteMeta(t.Name())+"$", "-test.count=1", "-test.timeout=10s")
	cmd.Env = append(os.Environ(), isolatedTestEnv+"="+t.Name())
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("isolated structured-log contract failed: %v\n%s", err, output)
	}
	return true
}

func compatibilityCaptureStructuredLogs() (*bytes.Buffer, func()) {
	oldRoot := getRootLogger()
	oldDefault := slog.Default()
	buf := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	rootLoggerVal.Store(logger)
	slog.SetDefault(logger)
	return buf, func() {
		rootLoggerVal.Store(oldRoot)
		slog.SetDefault(oldDefault)
	}
}

func compatibilityDecodeStructuredLogs(raw string) ([]map[string]interface{}, error) {
	events := make([]map[string]interface{}, 0, 64)
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		decoder := json.NewDecoder(strings.NewReader(scanner.Text()))
		decoder.UseNumber()
		opening, err := decoder.Token()
		if err != nil || opening != json.Delim('{') {
			return nil, fmt.Errorf("decode structured log opening %q: token=%v err=%w", scanner.Text(), opening, err)
		}
		event := make(map[string]interface{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, fmt.Errorf("decode structured log key: %w", err)
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, fmt.Errorf("structured log key type=%T, want string", keyToken)
			}
			if _, duplicate := event[key]; duplicate {
				return nil, fmt.Errorf("structured log contains duplicate field %q", key)
			}
			var value interface{}
			if err := decoder.Decode(&value); err != nil {
				return nil, fmt.Errorf("decode structured log field %q: %w", key, err)
			}
			event[key] = value
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return nil, fmt.Errorf("decode structured log closing: token=%v err=%w", closing, err)
		}
		var trailing interface{}
		if err := decoder.Decode(&trailing); err != io.EOF {
			return nil, fmt.Errorf("structured log has trailing value %#v (err=%v)", trailing, err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

func compatibilityASTString(expression ast.Expr) (string, bool) {
	literal, ok := expression.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(literal.Value)
	return value, err == nil
}

func compatibilityASTEnclosingFunction(file *ast.File, position token.Pos) (string, string) {
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Body == nil || position < function.Body.Pos() || position > function.Body.End() {
			continue
		}
		receiver := ""
		if function.Recv != nil && len(function.Recv.List) == 1 {
			switch receiverType := function.Recv.List[0].Type.(type) {
			case *ast.Ident:
				receiver = receiverType.Name
			case *ast.StarExpr:
				if ident, ok := receiverType.X.(*ast.Ident); ok {
					receiver = ident.Name
				}
			}
		}
		return function.Name.Name, receiver
	}
	return "", ""
}

func compatibilityASTLogLevel(expression ast.Expr) (string, bool) {
	ident, ok := expression.(*ast.Ident)
	if !ok {
		return "", false
	}
	levels := map[string]string{
		"LogLevelDebug": "DEBUG", "LogLevelError": "ERROR", "LogLevelInfo": "INFO", "LogLevelNotice": "WARN",
	}
	level, ok := levels[ident.Name]
	return level, ok
}

func compatibilityComponentLoggerLevel(method string) (string, bool) {
	levels := map[string]string{"Debug": "DEBUG", "Error": "ERROR", "Info": "INFO", "Notice": "WARN"}
	level, ok := levels[method]
	return level, ok
}

func compatibilityProviderMessageSuffix(expression ast.Expr) (string, bool) {
	binary, ok := expression.(*ast.BinaryExpr)
	if !ok || binary.Op != token.ADD {
		return "", false
	}
	suffix, ok := compatibilityASTString(binary.Y)
	if !ok || (suffix != "_refresh" && suffix != "_refresh_failed") {
		return "", false
	}
	call, ok := binary.X.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return "", false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "ToLower" {
		return "", false
	}
	packageName, ok := selector.X.(*ast.Ident)
	if !ok || packageName.Name != "strings" {
		return "", false
	}
	providerName, ok := call.Args[0].(*ast.SelectorExpr)
	if !ok || providerName.Sel.Name != "Name" {
		return "", false
	}
	return suffix, true
}

func compatibilityASTCallFields(call *ast.CallExpr, start int) ([]string, bool) {
	if call.Ellipsis.IsValid() || len(call.Args) < start || (len(call.Args)-start)%2 != 0 {
		return nil, false
	}
	fields := make([]string, 0, (len(call.Args)-start)/2)
	for index := start; index < len(call.Args); index += 2 {
		field, ok := compatibilityASTString(call.Args[index])
		if !ok {
			return nil, false
		}
		fields = append(fields, field)
	}
	sort.Strings(fields)
	return fields, true
}

func compatibilityCallFieldsFitVariant(fields []string, variant compatibilityStructuredLogVariant) bool {
	actual := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		actual[field] = struct{}{}
	}
	for field := range variant.Required {
		if _, ok := actual[field]; !ok {
			return false
		}
	}
	for field := range actual {
		if _, required := variant.Required[field]; required {
			continue
		}
		if _, optional := variant.Optional[field]; !optional {
			return false
		}
	}
	return true
}

func compatibilitySampleValue(fieldType string) interface{} {
	switch fieldType {
	case "array":
		return []map[string]interface{}{{"contract": "value"}}
	case "boolean":
		return true
	case "number":
		return 1.25
	case "string":
		return "contract-value"
	default:
		panic("unsupported structured-log field type " + fieldType)
	}
}

func compatibilityJSONType(value interface{}) string {
	switch value.(type) {
	case []interface{}:
		return "array"
	case bool:
		return "boolean"
	case json.Number:
		return "number"
	case string:
		return "string"
	default:
		return "other"
	}
}

func compatibilityCopyStringMap(source map[string]string) map[string]string {
	copy := make(map[string]string, len(source))
	for key, value := range source {
		copy[key] = value
	}
	return copy
}

func compatibilityEqualStringMap(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func compatibilitySortedMapKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func compatibilitySortedMapKeysAny(values map[string]interface{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
