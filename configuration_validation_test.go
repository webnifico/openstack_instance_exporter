package main

import (
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func runMainWithOccupiedListenerForTest(t *testing.T, args ...string) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	args = append(args,
		"-libvirt.uri=qemu:///system",
		"-web.listen-address="+listener.Addr().String(),
		"-conntrack.ipv4.enable=false",
		"-conntrack.ipv6.enable=false",
	)
	return runMainForTest(t, args...)
}

func TestStartupScalarValidationRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name        string
		sensitivity float64
		resource    float64
		behavior    float64
		threat      float64
		wantError   string
	}{
		{name: "NaN sensitivity", sensitivity: math.NaN(), resource: 0.45, behavior: 0.45, threat: 0.10, wantError: "behavior.sensitivity must be finite"},
		{name: "positive infinite sensitivity", sensitivity: math.Inf(1), resource: 0.45, behavior: 0.45, threat: 0.10, wantError: "behavior.sensitivity must be finite"},
		{name: "negative infinite sensitivity", sensitivity: math.Inf(-1), resource: 0.45, behavior: 0.45, threat: 0.10, wantError: "behavior.sensitivity must be finite"},
		{name: "below minimum sensitivity", sensitivity: math.Nextafter(minimumBehaviorSensitivity, math.Inf(-1)), resource: 0.45, behavior: 0.45, threat: 0.10, wantError: "behavior.sensitivity must be between"},
		{name: "above maximum sensitivity", sensitivity: math.Nextafter(maximumBehaviorSensitivity, math.Inf(1)), resource: 0.45, behavior: 0.45, threat: 0.10, wantError: "behavior.sensitivity must be between"},
		{name: "NaN resource weight", sensitivity: 1, resource: math.NaN(), behavior: 0.45, threat: 0.10, wantError: "severity.weight.resource must be finite"},
		{name: "positive infinite resource weight", sensitivity: 1, resource: math.Inf(1), behavior: 0.45, threat: 0.10, wantError: "severity.weight.resource must be finite"},
		{name: "negative infinite resource weight", sensitivity: 1, resource: math.Inf(-1), behavior: 0.45, threat: 0.10, wantError: "severity.weight.resource must be finite"},
		{name: "negative resource weight", sensitivity: 1, resource: -math.SmallestNonzeroFloat64, behavior: 0.45, threat: 0.10, wantError: "severity.weight.resource must be zero or greater"},
		{name: "NaN behavior weight", sensitivity: 1, resource: 0.45, behavior: math.NaN(), threat: 0.10, wantError: "severity.weight.behavior must be finite"},
		{name: "positive infinite behavior weight", sensitivity: 1, resource: 0.45, behavior: math.Inf(1), threat: 0.10, wantError: "severity.weight.behavior must be finite"},
		{name: "negative infinite behavior weight", sensitivity: 1, resource: 0.45, behavior: math.Inf(-1), threat: 0.10, wantError: "severity.weight.behavior must be finite"},
		{name: "negative behavior weight", sensitivity: 1, resource: 0.45, behavior: -math.SmallestNonzeroFloat64, threat: 0.10, wantError: "severity.weight.behavior must be zero or greater"},
		{name: "NaN threat weight", sensitivity: 1, resource: 0.45, behavior: 0.45, threat: math.NaN(), wantError: "severity.weight.threat_list must be finite"},
		{name: "positive infinite threat weight", sensitivity: 1, resource: 0.45, behavior: 0.45, threat: math.Inf(1), wantError: "severity.weight.threat_list must be finite"},
		{name: "negative infinite threat weight", sensitivity: 1, resource: 0.45, behavior: 0.45, threat: math.Inf(-1), wantError: "severity.weight.threat_list must be finite"},
		{name: "negative threat weight", sensitivity: 1, resource: 0.45, behavior: 0.45, threat: -math.SmallestNonzeroFloat64, wantError: "severity.weight.threat_list must be zero or greater"},
		{name: "all weights zero", sensitivity: 1, resource: 0, behavior: 0, threat: 0, wantError: "severity weights must not all be zero"},
		{name: "weight sum overflow", sensitivity: 1, resource: math.MaxFloat64, behavior: math.MaxFloat64, threat: 0, wantError: "severity weight sum must be finite"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateStartupScalarFlags(test.sensitivity, test.resource, test.behavior, test.threat)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("invalid startup values error=%v, want substring %q", err, test.wantError)
			}
		})
	}
}

func TestStartupScalarValidationPreservesValidBoundariesAndDefaults(t *testing.T) {
	for _, values := range [][4]float64{
		{1, 0.45, 0.45, 0.10},
		{minimumBehaviorSensitivity, 0.45, 0.45, 0.10},
		{10, 1, 2, 3},
		{1, 1, 0, 0},
		{1, 0, 1, 0},
		{1, 0, 0, 1},
		{1, math.MaxFloat64, 0, 0},
		{1, math.SmallestNonzeroFloat64, 0, 0},
	} {
		if err := validateStartupScalarFlags(values[0], values[1], values[2], values[3]); err != nil {
			t.Fatalf("valid startup values %v were rejected: %v", values, err)
		}
	}
}

func TestRunMainRejectsInvalidStartupScalars(t *testing.T) {
	maxFloat := strconv.FormatFloat(math.MaxFloat64, 'g', -1, 64)
	for _, argument := range []string{
		"-behavior.sensitivity=NaN",
		"-behavior.sensitivity=0.09999999999999999",
		"-behavior.sensitivity=10.000000000000002",
		"-severity.weight.resource=+Inf",
		"-severity.weight.resource=-0.000000000000000001",
		"-severity.weight.behavior=-Inf",
		"-severity.weight.behavior=-0.000000000000000001",
		"-severity.weight.threat_list=NaN",
		"-severity.weight.threat_list=-0.000000000000000001",
	} {
		t.Run(argument, func(t *testing.T) {
			code := runMainForTest(t, argument, "-libvirt.uri=qemu+ssh://host/system")
			if code != 2 {
				t.Fatalf("invalid startup value exit=%d, want configuration error exit 2", code)
			}
		})
	}

	for name, arguments := range map[string][]string{
		"all severity weights zero": {
			"-severity.weight.resource=0",
			"-severity.weight.behavior=0",
			"-severity.weight.threat_list=0",
		},
		"severity weight sum overflow": {
			"-severity.weight.resource=" + maxFloat,
			"-severity.weight.behavior=" + maxFloat,
			"-severity.weight.threat_list=0",
		},
	} {
		t.Run(name, func(t *testing.T) {
			arguments = append(arguments, "-libvirt.uri=qemu+ssh://host/system")
			if code := runMainForTest(t, arguments...); code != 2 {
				t.Fatalf("invalid startup values exit=%d, want configuration error exit 2", code)
			}
		})
	}
}

func TestStartupLogLevelValidationPreservesSupportedValues(t *testing.T) {
	for _, level := range []string{"debug", "INFO", " warn ", "notice", "error"} {
		if err := validateLogLevel(level); err != nil {
			t.Errorf("supported log level %q rejected: %v", level, err)
		}
	}
}

func TestStartupLogLevelValidationRejectsUnsupportedValues(t *testing.T) {
	for _, level := range []string{"", "   ", "trace", "warning", "fatal", "0"} {
		t.Run(strconv.Quote(level), func(t *testing.T) {
			if err := validateLogLevel(level); err == nil {
				t.Fatalf("unsupported log level %q was accepted", level)
			}
			if code := runMainForTest(t, "-log.level="+level, "-libvirt.uri=qemu+ssh://host/system"); code != 2 {
				t.Fatalf("unsupported log level %q exit=%d, want configuration error exit 2", level, code)
			}
		})
	}
}

func TestRunMainAcceptsScalarAndLogLevelBoundaries(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "all defaults"},
		{name: "minimum sensitivity", args: []string{"-behavior.sensitivity=0.1"}},
		{name: "maximum sensitivity", args: []string{"-behavior.sensitivity=10"}},
		{name: "resource weight only", args: []string{"-severity.weight.resource=1", "-severity.weight.behavior=0", "-severity.weight.threat_list=0"}},
		{name: "behavior weight only", args: []string{"-severity.weight.resource=0", "-severity.weight.behavior=1", "-severity.weight.threat_list=0"}},
		{name: "threat weight only", args: []string{"-severity.weight.resource=0", "-severity.weight.behavior=0", "-severity.weight.threat_list=1"}},
		{name: "debug log level", args: []string{"-log.level=DEBUG"}},
		{name: "info log level", args: []string{"-log.level=info"}},
		{name: "warn log level", args: []string{"-log.level= warn "}},
		{name: "notice log level", args: []string{"-log.level=notice"}},
		{name: "error log level", args: []string{"-log.level=error"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if code := runMainWithOccupiedListenerForTest(t, test.args...); code != 1 {
				t.Fatalf("valid startup configuration exit=%d, want collector initialization failure exit 1", code)
			}
		})
	}
}

func TestRunMainRejectsEveryPositionalArgumentForm(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "single positional", args: []string{"unexpected"}},
		{name: "positional after valid flag", args: []string{"-worker.count=1", "unexpected"}},
		{name: "first positional hides invalid later flag", args: []string{"unexpected", "-behavior.sensitivity=99"}},
		{name: "argument separator alone", args: []string{"--"}},
		{name: "argument separator before flag", args: []string{"--", "-worker.count=1"}},
		{name: "space separated bool value", args: []string{"-outbound.behavior.enable", "true"}},
		{name: "invalid space separated bool value", args: []string{"-outbound.behavior.enable", "maybe"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if code := runMainForTest(t, test.args...); code != 2 {
				t.Fatalf("positional arguments exit=%d, want configuration error exit 2", code)
			}
		})
	}
}

func TestEarlyFlagValidationDoesNotOpenUnvalidatedLogPath(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "positional argument", args: []string{"unexpected"}},
		{name: "invalid log level", args: []string{"-log.level=trace"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			logPath := filepath.Join(t.TempDir(), "must-not-be-created.log")
			args := append([]string{
				"-log.file.enable=true",
				"-log.file.path=" + logPath,
			}, test.args...)
			if code := runMainForTest(t, args...); code != 2 {
				t.Fatalf("invalid startup configuration exit=%d, want 2", code)
			}
			if _, err := os.Stat(logPath); !os.IsNotExist(err) {
				t.Fatalf("unvalidated log path was opened: stat error=%v", err)
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
		{name: "collection interval below supported range", args: []string{"-collection.interval=4.999s"}},
		{name: "collection interval above supported range", args: []string{"-collection.interval=60.001s"}},
		{name: "zero fast EWMA tau", args: []string{"-behavior.ewma_fast_tau=0s"}},
		{name: "negative slow EWMA tau", args: []string{"-behavior.ewma_slow_tau=-1s"}},
		{name: "fast EWMA not faster than slow", args: []string{"-behavior.ewma_fast_tau=2h", "-behavior.ewma_slow_tau=1h"}},
		{name: "zero threat EWMA tau", args: []string{"-threat.ewma_tau=0s"}},
		{name: "negative threat EWMA tau", args: []string{"-threat.ewma_tau=-1s"}},
		{name: "negative workers", args: []string{"-worker.count=-1"}},
		{name: "workers above supported maximum", args: []string{"-worker.count=65"}},
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

func TestRunMainAcceptsWorkerCountBoundaries(t *testing.T) {
	for _, workers := range []string{"0", "1", strconv.Itoa(maxDomainWorkers)} {
		t.Run(workers, func(t *testing.T) {
			code := runMainWithOccupiedListenerForTest(t, "-worker.count="+workers)
			if code != 1 {
				t.Fatalf("valid worker count %s exit=%d, want collector initialization failure exit 1", workers, code)
			}
		})
	}
}

func TestCollectionIntervalValidationBoundaries(t *testing.T) {
	tests := []struct {
		name     string
		interval time.Duration
		wantErr  bool
	}{
		{name: "one millisecond below minimum", interval: 4999 * time.Millisecond, wantErr: true},
		{name: "exact minimum", interval: 5 * time.Second},
		{name: "exact maximum", interval: time.Minute},
		{name: "one millisecond above maximum", interval: 60001 * time.Millisecond, wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateCollectionInterval(test.interval)
			if (err != nil) != test.wantErr {
				t.Fatalf("validateCollectionInterval(%v) error=%v, wantErr=%v", test.interval, err, test.wantErr)
			}
		})
	}
}

func TestRunMainAcceptsCollectionIntervalBoundaries(t *testing.T) {
	for _, interval := range []string{"5s", "1m"} {
		t.Run(interval, func(t *testing.T) {
			code := runMainWithOccupiedListenerForTest(t, "-collection.interval="+interval)
			if code != 1 {
				t.Fatalf("valid boundary interval %s exit=%d, want collector initialization failure exit 1", interval, code)
			}
		})
	}
}

func TestRunMainPreservesSingleFamilySpamhausConfiguration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v4":
			_, _ = w.Write([]byte("192.0.2.0/24 ; test\n"))
		case "/v6":
			_, _ = w.Write([]byte("2001:db8::/32 ; test\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	for _, args := range [][]string{
		{"-spamhaus.url=" + server.URL + "/v4", "-spamhaus.ipv6.url="},
		{"-spamhaus.url=", "-spamhaus.ipv6.url=" + server.URL + "/v6"},
	} {
		arguments := []string{"-spamhaus.enable=true"}
		arguments = append(arguments, args...)
		if code := runMainWithOccupiedListenerForTest(t, arguments...); code != 1 {
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
		{name: "null direction", yaml: "rules:\n  - id: test\n    direction: null\n    ports: [443]\n    kind: test\n"},
		{name: "null threshold", yaml: "rules:\n  - id: test\n    ports: [443]\n    flows_min: null\n    kind: test\n"},
		{name: "null ratios", yaml: "rules:\n  - id: test\n    ports: [443]\n    ratios: null\n    kind: test\n"},
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
