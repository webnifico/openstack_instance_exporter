package main

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func runtimeConfigurationConfiguredFlags(names ...string) map[string]struct{} {
	configured := make(map[string]struct{}, len(names))
	for _, name := range names {
		configured[name] = struct{}{}
	}
	return configured
}

func TestRuntimeConfigurationThreatFeedURLValidation(t *testing.T) {
	for _, rawURL := range []string{
		"http://example.test/feed",
		"https://example.test/feed?format=text",
		"https://example.test:65535/feed",
		"https://[2001:db8::1]:443/feed",
	} {
		if err := validateThreatFeedURL("feed.url", rawURL); err != nil {
			t.Errorf("valid URL %q rejected: %v", rawURL, err)
		}
	}

	for _, rawURL := range []string{
		"",
		"   ",
		" https://example.test/feed",
		"https://example.test/feed ",
		"ftp://example.test/feed",
		"https:///feed",
		"https:example.test/feed",
		"https://user@example.test/feed",
		"https://user:secret@example.test/feed",
		"https://example.test:/feed",
		"https://example.test:0/feed",
		"https://example.test:65536/feed",
		"https://example.test:notaport/feed",
	} {
		if err := validateThreatFeedURL("feed.url", rawURL); err == nil {
			t.Errorf("invalid URL %q accepted", rawURL)
		}
	}
}

func TestRuntimeConfigurationExplicitDisabledThreatInputsStillValidate(t *testing.T) {
	tests := []struct {
		name       string
		cfg        CollectorConfig
		configured map[string]struct{}
	}{
		{
			name:       "disabled Tor URL",
			cfg:        CollectorConfig{TorExit: ThreatListConfig{URL: "ftp://example.test/feed"}},
			configured: runtimeConfigurationConfiguredFlags("tor.exit.url"),
		},
		{
			name:       "disabled relay refresh",
			cfg:        CollectorConfig{TorRelay: ThreatListConfig{Refresh: -time.Second}},
			configured: runtimeConfigurationConfiguredFlags("tor.relay.refresh"),
		},
		{
			name:       "disabled Emerging Threats credentials",
			cfg:        CollectorConfig{Emerging: ThreatListConfig{URL: "https://user:secret@example.test/feed"}},
			configured: runtimeConfigurationConfiguredFlags("emergingthreats.url"),
		},
		{
			name:       "disabled Spamhaus whitespace URL",
			cfg:        CollectorConfig{Spamhaus: SpamhausConfig{URLv4: "   "}},
			configured: runtimeConfigurationConfiguredFlags("spamhaus.url"),
		},
		{
			name:       "disabled Spamhaus invalid port",
			cfg:        CollectorConfig{Spamhaus: SpamhausConfig{URLv6: "https://example.test:65536/dropv6.txt"}},
			configured: runtimeConfigurationConfiguredFlags("spamhaus.ipv6.url"),
		},
		{
			name:       "disabled custom refresh",
			cfg:        CollectorConfig{Custom: CustomListConfig{Refresh: -time.Second}},
			configured: runtimeConfigurationConfiguredFlags("customlist.refresh"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateExplicitThreatInputs(test.cfg, test.configured); err == nil {
				t.Fatal("invalid explicit disabled-feed configuration was accepted")
			}
		})
	}
}

func TestRuntimeConfigurationCustomListFailsClosedAtStartup(t *testing.T) {
	validPath := filepath.Join(t.TempDir(), "valid.txt")
	if err := os.WriteFile(validPath, []byte("192.0.2.10\n2001:db8::10\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := CollectorConfig{Custom: CustomListConfig{Path: validPath}}
	if err := validateExplicitThreatInputs(cfg, runtimeConfigurationConfiguredFlags("customlist.path")); err != nil {
		t.Fatalf("valid explicit custom list rejected: %v", err)
	}

	for name, contents := range map[string]string{
		"empty":       "",
		"comments":    "# no entries\n",
		"malformed":   "not-an-address\n",
		"unspecified": "0.0.0.0\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "custom.txt")
			if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			bad := CollectorConfig{Custom: CustomListConfig{Path: path}}
			if err := validateExplicitThreatInputs(bad, runtimeConfigurationConfiguredFlags("customlist.path")); err == nil {
				t.Fatal("broken custom list was accepted")
			}
		})
	}

	missing := CollectorConfig{Custom: CustomListConfig{Path: filepath.Join(t.TempDir(), "missing.txt")}}
	if err := validateExplicitThreatInputs(missing, runtimeConfigurationConfiguredFlags("customlist.path")); err == nil {
		t.Fatal("missing custom list was accepted")
	}

	fifoPath := filepath.Join(t.TempDir(), "custom.fifo")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- validateExplicitThreatInputs(
			CollectorConfig{Custom: CustomListConfig{Path: fifoPath}},
			runtimeConfigurationConfiguredFlags("customlist.path"),
		)
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("custom-list FIFO was accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("custom-list FIFO blocked startup validation")
	}
}

func TestHostThreatInterfacesKeepV13Fallback(t *testing.T) {
	if got := hostInterfacesForStartup(true, false, ""); got != "bgp-nic" {
		t.Fatalf("implicit enabled host interface=%q, want bgp-nic", got)
	}
	if got := hostInterfacesForStartup(false, false, ""); got != "" {
		t.Fatalf("disabled host interface=%q, want empty", got)
	}
	if got := hostInterfacesForStartup(true, true, ""); got != "" {
		t.Fatalf("explicit empty host interface=%q, want validation to reject it", got)
	}
	if got := hostInterfacesForStartup(true, false, "br-monitoring"); got != "br-monitoring" {
		t.Fatalf("configured host interface=%q, want br-monitoring", got)
	}
}

func TestRuntimeConfigurationConfiguredHostInterfacesFailClosed(t *testing.T) {
	lookupCalls := 0
	lookup := func(name string) (*net.Interface, error) {
		lookupCalls++
		if name == "br-monitoring" {
			return &net.Interface{Name: name}, nil
		}
		return nil, errors.New("not found")
	}

	if err := validateConfiguredHostInterfaces(true, false, "", lookup); err == nil {
		t.Fatal("enabled host threats accepted an empty interface list")
	}
	if err := validateConfiguredHostInterfaces(false, true, "", lookup); err == nil {
		t.Fatal("disabled host threats accepted an explicitly empty interface list")
	}
	if err := validateConfiguredHostInterfaces(false, true, "missing0", lookup); err == nil {
		t.Fatal("disabled host threats ignored a configured missing interface")
	}
	if err := validateConfiguredHostInterfaces(true, true, "br-monitoring, missing0", lookup); err == nil {
		t.Fatal("enabled host threats accepted a partially missing interface list")
	}
	if err := validateConfiguredHostInterfaces(true, true, "br-monitoring,,br-monitoring", lookup); err == nil {
		t.Fatal("interface list with an empty component was accepted")
	}
	if err := validateConfiguredHostInterfaces(true, true, "br-monitoring,br-monitoring", lookup); err != nil {
		t.Fatalf("compatible duplicate interface names were rejected: %v", err)
	}
	if lookupCalls == 0 {
		t.Fatal("configured interfaces were not looked up")
	}
}

func TestRuntimeConfigurationConfiguredLogFileValidationAndCheckedInitialization(t *testing.T) {
	preserveLoggingTestState(t)

	if err := validateConfiguredLogFile(false, filepath.Join(t.TempDir(), "inactive")); err != nil {
		t.Fatalf("inactive log path was validated: %v", err)
	}
	for _, path := range []string{"", "   ", t.TempDir(), filepath.Join(t.TempDir(), "missing", "oie.log")} {
		if err := validateConfiguredLogFile(true, path); err == nil {
			t.Errorf("invalid enabled log path %q was accepted", path)
		}
	}

	fifoPath := filepath.Join(t.TempDir(), "oie.fifo")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateConfiguredLogFile(true, fifoPath); err == nil {
		t.Fatal("log FIFO passed preflight")
	}

	InitLogging("warn", "", false)
	if _, err := InitLoggingChecked("debug", fifoPath, true); err == nil {
		t.Fatal("checked logging accepted a FIFO")
	}
	if got := CurrentLogLevel(); got != "warn" {
		t.Fatalf("failed checked initialization changed log level to %q", got)
	}

	logPath := filepath.Join(t.TempDir(), "oie.log")
	if err := validateConfiguredLogFile(true, logPath); err != nil {
		t.Fatalf("new regular log path failed preflight: %v", err)
	}
	if level, err := InitLoggingChecked("debug", logPath, true); err != nil || level != "debug" {
		t.Fatalf("checked logging = (%q, %v), want debug,nil", level, err)
	}
	logMain.Debug("runtime_configuration_checked_log_destination")
	if logFileHandle == nil {
		t.Fatal("checked logging did not retain its file")
	}
	if err := logFileHandle.Sync(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(logPath)
	if err != nil || !strings.Contains(string(data), "runtime_configuration_checked_log_destination") {
		t.Fatalf("checked log output missing: err=%v data=%s", err, data)
	}
}

func TestRuntimeConfigurationListenAddressAndLibvirtURIValidation(t *testing.T) {
	for _, address := range []string{
		"0.0.0.0:9120",
		"127.0.0.1:0",
		":9120",
		"localhost:9120",
		"[::1]:9120",
		"[fe80::1%eth0]:9120",
	} {
		if err := validateListenAddress(address); err != nil {
			t.Errorf("valid listen address %q rejected: %v", address, err)
		}
	}
	for _, address := range []string{
		"",
		"   ",
	} {
		if err := validateListenAddress(address); err == nil {
			t.Errorf("invalid listen address %q accepted", address)
		}
	}
	for _, address := range []string{" 127.0.0.1:9120", "127.0.0.1:9120 ", "127.0.0.1", "127.0.0.1:-1", "127.0.0.1:65536", "bad/name:9120"} {
		if listener, err := listenForHTTP(address); err == nil {
			_ = listener.Close()
			t.Errorf("invalid listen address %q reached a listener", address)
		}
	}

	for _, uri := range []string{
		"qemu:///system",
		"/run/libvirt/libvirt-sock",
		"qemu+unix:///system",
		"qemu+unix:///system?socket=/run/libvirt/custom.sock",
		"unix:///run/libvirt/custom.sock",
	} {
		if err := validateLibvirtURI(uri); err != nil {
			t.Errorf("valid libvirt URI %q rejected: %v", uri, err)
		}
	}
	for _, uri := range []string{
		"",
		"   ",
		" qemu:///system",
		"qemu+ssh://host/system",
		"qemu+unix://host/system",
		"qemu+tcp:///system?socket=/run/libvirt.sock",
		"qemu+unix:///system?socket=relative.sock",
		"qemu+unix:///system?socket=%zz",
	} {
		if err := validateLibvirtURI(uri); err == nil {
			t.Errorf("invalid libvirt URI %q accepted", uri)
		}
	}
}

func TestRuntimeConfigurationDirectionAndBehaviorPathIntentValidation(t *testing.T) {
	baseDirections := map[string]string{"contacts.direction": "out"}
	if err := validateExplicitDirections(nil, baseDirections); err != nil {
		t.Fatalf("default directions rejected: %v", err)
	}
	for _, alias := range []string{"out", "outbound", "src", "in", "inbound", "dst", "any", " IN "} {
		directions := map[string]string{"contacts.direction": alias, "tor.exit.direction": ""}
		if err := validateExplicitDirections(runtimeConfigurationConfiguredFlags("contacts.direction", "tor.exit.direction"), directions); err != nil {
			t.Errorf("compatible direction %q rejected: %v", alias, err)
		}
	}
	for name, directions := range map[string]map[string]string{
		"blank default":       {"contacts.direction": ""},
		"invalid default":     {"contacts.direction": "sideways"},
		"whitespace override": {"contacts.direction": "out", "tor.exit.direction": "   "},
		"invalid override":    {"contacts.direction": "out", "spamhaus.direction": "sideways"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateExplicitDirections(runtimeConfigurationConfiguredFlags("contacts.direction", "tor.exit.direction", "spamhaus.direction"), directions); err == nil {
				t.Fatal("invalid direction configuration was accepted")
			}
		})
	}

	if err := validateBehaviorConfigPaths(nil, map[string]string{}); err != nil {
		t.Fatalf("omitted behavior paths rejected: %v", err)
	}
	for _, path := range []string{"", "   ", " /etc/oie/ports.yml", "bad\x00path"} {
		if err := validateBehaviorConfigPaths(
			runtimeConfigurationConfiguredFlags("behavior.ports_config"),
			map[string]string{"behavior.ports_config": path},
		); err == nil {
			t.Errorf("invalid explicit behavior path %q accepted", path)
		}
	}
}

func TestRuntimeConfigurationBehaviorConfigReadsAreRegularAndBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ports.yml")
	want := "behavior:\n  ports:\n    outbound_monitored: {443: https}\n"
	if err := os.WriteFile(path, []byte(want), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readStableRegularConfigFile(path, "behavior.ports_config", maximumBehaviorConfigFileBytes)
	if err != nil || string(got) != want {
		t.Fatalf("stable config read = (%q, %v)", got, err)
	}

	oversized := filepath.Join(t.TempDir(), "oversized.yml")
	if err := os.WriteFile(oversized, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(oversized, maximumBehaviorConfigFileBytes+1); err != nil {
		t.Fatal(err)
	}
	if _, err := readStableRegularConfigFile(oversized, "behavior.ports_config", maximumBehaviorConfigFileBytes); err == nil {
		t.Fatal("oversized behavior config was accepted")
	}

	fifo := filepath.Join(t.TempDir(), "ports.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := readStableRegularConfigFile(fifo, "behavior.ports_config", maximumBehaviorConfigFileBytes)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("behavior-config FIFO was accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("behavior-config FIFO blocked startup")
	}
}

func TestRuntimeConfigurationRunMainRejectsConfiguredInputBeforeListening(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := probe.Addr().String()
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}

	if code := runMainForTest(t,
		"-web.listen-address="+address,
		"-host.threats.enable=true",
		"-host.interfaces=oie-no-such0",
	); code != 2 {
		t.Fatalf("missing configured interface exit=%d, want 2", code)
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("invalid interface unexpectedly consumed or broadened listener %s: %v", address, err)
	}
	_ = listener.Close()

	for _, args := range [][]string{
		{"-host.threats.enable=true"},
		{"-tor.exit.url=ftp://example.test/feed"},
		{"-tor.exit.refresh=-1s"},
		{"-contacts.direction=sideways"},
		{"-tor.exit.direction=   "},
		{"-behavior.ports_config="},
		{"-behavior.rules_config=   "},
		{"-libvirt.uri=   "},
	} {
		if code := runMainForTest(t, args...); code != 2 {
			t.Errorf("invalid configured input %q exit=%d, want 2", args, code)
		}
	}
	if code := runMainForTest(t,
		"-web.listen-address=bad/address:9120",
		"-conntrack.ipv4.enable=false",
		"-conntrack.ipv6.enable=false",
	); code != 1 {
		t.Errorf("invalid non-empty listen address exit=%d, want listener runtime error 1", code)
	}
}
