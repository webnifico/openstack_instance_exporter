package main

import (
	"math"
	"os"
	"path/filepath"
	"testing"
)

func TestStartupScalarValidationRejectsNonFiniteValues(t *testing.T) {
	tests := []struct {
		name        string
		sensitivity float64
		resource    float64
		behavior    float64
		threat      float64
	}{
		{name: "NaN sensitivity", sensitivity: math.NaN(), resource: 0.45, behavior: 0.45, threat: 0.10},
		{name: "positive infinite sensitivity", sensitivity: math.Inf(1), resource: 0.45, behavior: 0.45, threat: 0.10},
		{name: "negative infinite sensitivity", sensitivity: math.Inf(-1), resource: 0.45, behavior: 0.45, threat: 0.10},
		{name: "NaN resource weight", sensitivity: 1, resource: math.NaN(), behavior: 0.45, threat: 0.10},
		{name: "infinite behavior weight", sensitivity: 1, resource: 0.45, behavior: math.Inf(1), threat: 0.10},
		{name: "infinite threat weight", sensitivity: 1, resource: 0.45, behavior: 0.45, threat: math.Inf(-1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateStartupScalarFlags(test.sensitivity, test.resource, test.behavior, test.threat); err == nil {
				t.Fatal("non-finite startup value was accepted")
			}
		})
	}
}

func TestStartupScalarValidationPreservesFiniteValueSemantics(t *testing.T) {
	for _, values := range [][4]float64{
		{1, 0.45, 0.45, 0.10},
		{0, 0, 0, 0},
		{-1, -1, -1, -1},
		{10, 1, 2, 3},
	} {
		if err := validateStartupScalarFlags(values[0], values[1], values[2], values[3]); err != nil {
			t.Fatalf("finite startup values %v were rejected: %v", values, err)
		}
	}
}

func TestRunMainRejectsNonFiniteStartupScalars(t *testing.T) {
	for _, argument := range []string{
		"-behavior.sensitivity=NaN",
		"-severity.weight.resource=+Inf",
		"-severity.weight.behavior=-Inf",
		"-severity.weight.threat_list=NaN",
	} {
		t.Run(argument, func(t *testing.T) {
			code := runMainForTest(t, argument, "-libvirt.uri=qemu+ssh://host/system")
			if code != 2 {
				t.Fatalf("non-finite startup value exit=%d, want configuration error exit 2", code)
			}
		})
	}
}

func TestRunMainRejectsInvalidTelemetryPatterns(t *testing.T) {
	for _, pattern := range []string{
		"/metrics/{",
		"/debug/%6cog-level",
		"/debug/log%2dlevel",
	} {
		t.Run(pattern, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("invalid telemetry pattern panicked: %v", recovered)
				}
			}()
			code := runMainForTest(t,
				"-web.telemetry-path="+pattern,
				"-conntrack.ipv4.enable=false",
				"-conntrack.ipv6.enable=false",
			)
			if code != 2 {
				t.Fatalf("invalid telemetry pattern exit=%d, want configuration error exit 2", code)
			}
		})
	}
}

func TestRunMainRejectsDangerousRuntimeValuesBeforeCollectorInitialization(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "empty listen address", args: []string{"-web.listen-address="}},
		{name: "zero collection interval", args: []string{"-collection.interval=0s"}},
		{name: "zero fast EWMA tau", args: []string{"-behavior.ewma_fast_tau=0s"}},
		{name: "negative slow EWMA tau", args: []string{"-behavior.ewma_slow_tau=-1s"}},
		{name: "fast EWMA not faster than slow", args: []string{"-behavior.ewma_fast_tau=2h", "-behavior.ewma_slow_tau=1h"}},
		{name: "negative workers", args: []string{"-worker.count=-1"}},
		{name: "negative conntrack receive buffer", args: []string{"-conntrack.raw.rcvbuf_bytes=-1"}},
		{name: "zero conntrack receive timeout", args: []string{"-conntrack.raw.rcv_timeout=0s"}},
		{name: "negative log throttle", args: []string{"-threat.log.min_interval=-1s"}},
		{name: "negative Tor refresh", args: []string{"-tor.exit.enable=true", "-tor.exit.refresh=-1s"}},
		{name: "invalid Tor URL", args: []string{"-tor.exit.enable=true", "-tor.exit.url=ftp://example.test/list"}},
		{name: "invalid relay URL", args: []string{"-tor.relay.enable=true", "-tor.relay.url=/local/relay.json"}},
		{name: "invalid EmergingThreats URL", args: []string{"-emergingthreats.enable=true", "-emergingthreats.url=https:///missing-host"}},
		{name: "invalid Spamhaus IPv4 URL", args: []string{"-spamhaus.enable=true", "-spamhaus.url=file:///tmp/drop.txt"}},
		{name: "invalid Spamhaus IPv6 URL", args: []string{"-spamhaus.enable=true", "-spamhaus.ipv6.url=ftp://example.test/dropv6.txt"}},
		{name: "empty Spamhaus URLs", args: []string{"-spamhaus.enable=true", "-spamhaus.url=", "-spamhaus.ipv6.url="}},
		{name: "empty custom list path", args: []string{"-customlist.enable=true", "-customlist.path=   "}},
		{name: "negative custom refresh", args: []string{"-customlist.enable=true", "-customlist.path=/tmp/list", "-customlist.refresh=-1s"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			args := append([]string{"-libvirt.uri=qemu+ssh://host/system"}, test.args...)
			if code := runMainForTest(t, args...); code != 2 {
				t.Fatalf("invalid runtime configuration exit=%d, want configuration error exit 2", code)
			}
		})
	}
}

func TestRunMainPreservesSingleFamilySpamhausConfiguration(t *testing.T) {
	for _, args := range [][]string{
		{"-spamhaus.url=https://example.test/drop.txt", "-spamhaus.ipv6.url="},
		{"-spamhaus.url=", "-spamhaus.ipv6.url=https://example.test/dropv6.txt"},
	} {
		arguments := []string{"-libvirt.uri=qemu+ssh://host/system", "-spamhaus.enable=true"}
		arguments = append(arguments, args...)
		if code := runMainForTest(t, arguments...); code != 1 {
			t.Fatalf("valid single-family Spamhaus configuration exit=%d, want collector initialization exit 1", code)
		}
	}
}

func TestRunMainRejectsUnknownFlagExplicitly(t *testing.T) {
	code := runMainForTest(t,
		"-libvirt.uri=qemu+ssh://host/system",
		"-definitely.unknown=true",
	)
	if code != 2 {
		t.Fatalf("unknown flag exit=%d, want configuration error exit 2", code)
	}
}

func TestTelemetryPathMustBeDirectlyReachable(t *testing.T) {
	for _, path := range []string{
		"/",
		"/metrics/",
		"/metrics?format=openmetrics",
		"/metrics#fragment",
		"/metrics//nested",
		"/metrics/../other",
		"/{metric}",
		"/{rest...}",
		"/metrics%2fextra",
		"/metrics%7Bname%7D",
	} {
		if err := validateTelemetryPath(path); err == nil {
			t.Errorf("unreachable telemetry path %q was accepted", path)
		}
	}
}

func TestTelemetryPathIsValidatedBeforeCollectorInitialization(t *testing.T) {
	code := runMainForTest(t,
		"-libvirt.uri=qemu+ssh://host/system",
		"-web.telemetry-path=/metrics?query=unreachable",
	)
	if code != 2 {
		t.Fatalf("invalid telemetry path exit=%d, want configuration error before collector initialization", code)
	}
}

func TestNewMetricsCollectorRejectsUnsupportedLibvirtURI(t *testing.T) {
	if _, err := NewMetricsCollector(CollectorConfig{LibvirtURI: "qemu+ssh://hypervisor/system"}); err == nil {
		t.Fatal("unsupported libvirt URI was accepted")
	}
}

func writeConfigTestFile(t *testing.T, name, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestBehaviorPortsRejectUnknownYAMLFields(t *testing.T) {
	path := writeConfigTestFile(t, "ports.yml", "behavior:\n  ports:\n    outbound_monitored:\n      443: https\n    typo_field: true\n")
	_, _, status := BuildBehaviorPortMaps(path)
	if status.Status != "parse_error" {
		t.Fatalf("status = %q, want parse_error: %s", status.Status, status.Err)
	}
}

func TestExternalRulesRejectUnknownAndInvalidFields(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{name: "unknown field", yaml: "rules:\n  - id: test\n    direction: outbound\n    ports: [443]\n    kind: test\n    typo_field: 1\n"},
		{name: "invalid port", yaml: "rules:\n  - id: test\n    direction: outbound\n    ports: [70000]\n    kind: test\n"},
		{name: "invalid ratio", yaml: "rules:\n  - id: test\n    direction: outbound\n    ports: [443]\n    ratios:\n      unreplied: 1.5\n    kind: test\n"},
		{name: "duplicate id", yaml: "rules:\n  - {id: test, ports: [443], kind: one}\n  - {id: test, ports: [80], kind: two}\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeConfigTestFile(t, "rules.yml", tt.yaml)
			rules, status := LoadBehaviorExternalRules(path)
			if status.Status != "error" || len(rules) != 0 {
				t.Fatalf("status=%q rules=%d err=%q, want hard validation error", status.Status, len(rules), status.Err)
			}
		})
	}
}

func TestExistingBehaviorYAMLFormatsRemainValid(t *testing.T) {
	portsPath := writeConfigTestFile(t, "ports.yml", "behavior:\n  ports:\n    inbound_monitored:\n      22: ssh\n    outbound_monitored:\n      443: https\n")
	in, out, portsStatus := BuildBehaviorPortMaps(portsPath)
	if portsStatus.Status != "loaded" || in[22] != "ssh" || out[443] != "https" {
		t.Fatalf("valid ports config rejected: %#v", portsStatus)
	}

	rulesPath := writeConfigTestFile(t, "rules.yml", "port_sets:\n  web: [80, 443]\nrules:\n  - id: web_probe\n    direction: outbound\n    port_set: web\n    flows_min: 2\n    ratios:\n      unreplied: 0.5\n    kind: web_probe\n    reason: test\n    severity: high\n")
	rules, rulesStatus := LoadBehaviorExternalRules(rulesPath)
	if rulesStatus.Status != "loaded" || len(rules) != 1 {
		t.Fatalf("valid rules config rejected: %#v", rulesStatus)
	}
}

func TestExternalRulesRejectInvalidLegacySeverity(t *testing.T) {
	path := writeConfigTestFile(t, "rules.yml", "rules:\n  - id: test\n    ports: [443]\n    kind: test\n    severity: severe\n")
	if rules, status := LoadBehaviorExternalRules(path); status.Status != "error" || len(rules) != 0 {
		t.Fatalf("invalid legacy severity accepted: status=%q rules=%d", status.Status, len(rules))
	}
}
