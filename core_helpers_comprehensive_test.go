package main

import (
	"bytes"
	"log/slog"

	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func preserveLoggingTestState(t *testing.T) {
	t.Helper()

	logMu.Lock()
	previousRoot := getRootLogger()
	previousDefault := slog.Default()
	previousLevel := CurrentLogLevel()
	previousFile := logFileHandle
	previousWriter := logFileWriter

	// Keep the previous file alive while checked initialization replaces the test state.
	logFileHandle = nil
	logFileWriter = nil
	logMu.Unlock()

	t.Cleanup(func() {
		logMu.Lock()
		testFile := logFileHandle
		logFileHandle = previousFile
		logFileWriter = previousWriter
		rootLoggerVal.Store(previousRoot)
		currentLogLevelVal.Store(previousLevel)
		slog.SetDefault(previousDefault)
		logMu.Unlock()

		if testFile != nil && testFile != previousFile {
			_ = testFile.Close()
		}
	})
}

func TestNetworkAddressClassificationAndConversion(t *testing.T) {
	uuidBytes := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	if got := uuidBytesToString(uuidBytes); got != "00112233-4455-6677-8899-aabbccddeeff" {
		t.Fatalf("UUID conversion = %q", got)
	}
	if got := uuidBytesToString(uuidBytes[:15]); got != "" {
		t.Fatalf("short UUID conversion = %q", got)
	}

	private := []string{"10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.1.1", "127.0.0.1", "::1", "fe80::1", "fc00::1", "ff02::1", "0.0.0.0"}
	for _, raw := range private {
		if !isPrivateOrLocal(net.ParseIP(raw)) {
			t.Errorf("%s not classified private/local", raw)
		}
		if !isPrivateOrLocalStr(raw) {
			t.Errorf("%s string not classified private/local", raw)
		}
	}
	for _, raw := range []string{"8.8.8.8", "172.15.255.255", "172.32.0.1", "2001:4860:4860::8888"} {
		if isPrivateOrLocal(net.ParseIP(raw)) {
			t.Errorf("%s classified private/local", raw)
		}
	}
	if !isPrivateOrLocal(nil) || !isPrivateOrLocal(net.IP{1, 2, 3}) {
		t.Fatal("nil or malformed IP was treated as public")
	}
	if isPrivateOrLocalStr("not-an-ip") {
		t.Fatal("malformed IP string was treated as private")
	}

	hosts := map[string]struct{}{"203.0.113.10": {}}
	for _, raw := range []string{"203.0.113.10", "169.254.169.254", "fe80::1"} {
		if !isInfrastructureIP(raw, hosts) {
			t.Errorf("%s not classified as infrastructure", raw)
		}
	}
	for _, raw := range []string{"not-an-ip", "8.8.8.8", "fd00::1"} {
		if isInfrastructureIP(raw, hosts) {
			t.Errorf("%s classified as infrastructure", raw)
		}
	}

	v4 := IPStrToKey("192.0.2.4")
	if !isIPv4MappedKey(v4) || IPKeyToString(v4) != "192.0.2.4" {
		t.Fatalf("IPv4 key roundtrip = %v/%q", isIPv4MappedKey(v4), IPKeyToString(v4))
	}
	v6 := IPStrToKey("2001:db8::4")
	if isIPv4MappedKey(v6) || IPKeyToString(v6) != "2001:db8::4" {
		t.Fatalf("IPv6 key roundtrip = %v/%q", isIPv4MappedKey(v6), IPKeyToString(v6))
	}
	if IPStrToKey("bad") != (IPKey{}) {
		t.Fatal("invalid IP produced a non-zero key")
	}
	if V4BytesToKey([]byte{1, 2, 3}) != (IPKey{}) || V6BytesToKey(make([]byte, 15)) != (IPKey{}) {
		t.Fatal("partial address produced a non-zero key")
	}
	if AddrToKey(netip.Addr{}) != (IPKey{}) {
		t.Fatal("invalid netip address produced a key")
	}
	if !isLocalOnlyKey(IPStrToKey("127.0.0.1")) || isLocalOnlyKey(IPStrToKey("10.0.0.1")) {
		t.Fatal("local-only classification is wrong")
	}
	if !isInfrastructureKey(IPStrToKey("169.254.3.4"), nil) || !isInfrastructureKey(IPStrToKey("fe80::2"), nil) || isInfrastructureKey(IPStrToKey("fd00::2"), nil) {
		t.Fatal("infrastructure key classification is wrong")
	}
	hostKey := IPStrToKey("10.1.1.1")
	if !isInfrastructureKey(hostKey, map[IPKey]struct{}{hostKey: {}}) {
		t.Fatal("explicit host key was not infrastructure")
	}
}

func TestPairKeyOrderingAndIdentity(t *testing.T) {
	a := IPStrToKey("192.0.2.1")
	b := IPStrToKey("192.0.2.2")
	forward := MakeConntrackPairKey(a, 5000, b, 443, 6, 7, 8, 9)
	reverse := MakeConntrackPairKey(b, 443, a, 5000, 6, 7, 8, 9)
	if forward != reverse {
		t.Fatalf("pair key is not direction-independent: %+v != %+v", forward, reverse)
	}
	if !strings.Contains(PairKeyString(forward), "|6|7:8:9") {
		t.Fatalf("pair key string lost protocol identity: %q", PairKeyString(forward))
	}
	if compareIPKey(a, a) != 0 || compareIPKey(a, b) >= 0 || compareIPKey(b, a) <= 0 {
		t.Fatal("IP key comparison is wrong")
	}
	if compareEndpoint(a, 2, a, 3) >= 0 || compareEndpoint(a, 3, a, 2) <= 0 || compareEndpoint(a, 2, a, 2) != 0 {
		t.Fatal("endpoint port comparison is wrong")
	}
}

func TestInterfaceAndPortMapHelpers(t *testing.T) {
	interfaces := parseInterfaceList(" eth0,eth1, eth0, ,br-ex ")
	if len(interfaces) != 3 {
		t.Fatalf("interfaces = %#v", interfaces)
	}
	original := map[uint16]string{22: "ssh"}
	copyMap := copyPortNameMap(original)
	copyMap[22] = "changed"
	if original[22] != "ssh" {
		t.Fatal("copyPortNameMap aliases the input")
	}
}

func TestMetricMathAndAppendConstMetric(t *testing.T) {
	for input, want := range map[float64]float64{-1: 0, 0.5: 0.5, 2: 1} {
		if got := clamp01(input); got != want {
			t.Errorf("clamp01(%v) = %v", input, got)
		}
	}
	for input, want := range map[int]int{-1: 0, 50: 50, 101: 100} {
		if got := clampInt01To100(input); got != want {
			t.Errorf("clampInt01To100(%d) = %d", input, got)
		}
	}
	if got := roundToFiveDecimals(1.234567); got != 1.23457 {
		t.Fatalf("rounding = %v", got)
	}
	var metrics []prometheus.Metric
	desc := prometheus.NewDesc("test_comprehensive_metric", "test", []string{"label"}, nil)
	appendConstMetric(&metrics, desc, prometheus.GaugeValue, 7, "value")
	if len(metrics) != 1 || !strings.Contains(metrics[0].Desc().String(), "test_comprehensive_metric") {
		t.Fatalf("const metric = %#v", metrics)
	}
}

func TestLoggingLevelsAndJSONFileOutput(t *testing.T) {
	preserveLoggingTestState(t)
	path := t.TempDir() + "/exporter.log"
	for input, want := range map[string]string{
		"debug": "debug", "INFO": "info", " notice ": "warn", "warn": "warn", "error": "error",
	} {
		_, got, valid := parseLogLevel(input)
		if !valid || got != want {
			t.Errorf("parse %q = %q valid=%v", input, got, valid)
		}
	}
	if _, _, valid := parseLogLevel("junk"); valid {
		t.Fatal("invalid logging level was accepted")
	}
	beforeInvalid := CurrentLogLevel()
	if _, err := InitLoggingChecked("junk", path, true); err == nil {
		t.Fatal("checked logging accepted an invalid level")
	}
	if CurrentLogLevel() != beforeInvalid {
		t.Fatal("invalid checked logging request mutated the active level")
	}
	applied, err := InitLoggingChecked("debug", path, true)
	if err != nil || applied != "debug" || CurrentLogLevel() != "debug" {
		t.Fatalf("logging level = %q/%q err=%v", applied, CurrentLogLevel(), err)
	}
	logger := NewComponentLogger("test-category", "test-component")
	logger.Debug("debug_event", "answer", 42)
	logger.Info("info_event", "answer", 42)
	logger.Notice("notice_event", "answer", 42)
	logger.Error("error_event", "answer", 42)
	logKV(LogLevelDebug, "category", "component", "compat_debug")
	logKV(LogLevelInfo, "category", "component", "compat_info")
	logKV(LogLevelNotice, "category", "component", "compat_notice")
	logKV(LogLevelError, "category", "component", "compat_error")
	logKV(LogLevel(99), "category", "component", "compat_default")
	if logFileHandle != nil {
		_ = logFileHandle.Sync()
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"debug_event", "info_event", "notice_event", "error_event", "severity_class", "compat_default"} {
		if !bytes.Contains(b, []byte(expected)) {
			t.Errorf("log output missing %q: %s", expected, b)
		}
	}
	before := CurrentLogLevel()
	if _, err := InitLoggingChecked("error", t.TempDir(), true); err == nil {
		t.Fatal("directory logfile destination was accepted")
	}
	if got := CurrentLogLevel(); got != before {
		t.Fatalf("failed checked logging changed level from %q to %q", before, got)
	}
}

func TestResourceSampleWrapperAndCounterEdges(t *testing.T) {
	im := &InstanceManager{}
	now := time.Unix(1000, 0)
	if _, _, _, valid := im.calculateMemRates("vm", 1, 2, 3, 4, now); valid {
		t.Fatal("first memory wrapper sample was valid")
	}
	in, out, major, valid := im.calculateMemRates("vm", 11, 22, 8, 9, now.Add(10*time.Second))
	if !valid || in != 1 || out != 2 || major != .5 {
		t.Fatalf("memory wrapper rates = %v/%v/%v valid=%v", in, out, major, valid)
	}
	_, _, _, inValid, outValid, majorValid := im.calculateMemRatesWithAvailability("vm-reset", 10, 10, 10, 10, true, true, true, true, now)
	if inValid || outValid || majorValid {
		t.Fatal("first explicit memory sample was valid")
	}
	_, _, _, inValid, outValid, majorValid = im.calculateMemRatesWithAvailability("vm-reset", 9, 10, 9, 10, true, true, true, true, now.Add(time.Second))
	if inValid || !outValid || majorValid {
		t.Fatalf("memory reset availability = %v/%v/%v", inValid, outValid, majorValid)
	}

	if _, _, _, valid := im.calculateNetRates("net", 1, 1, 0, 0, now); valid {
		t.Fatal("first network sample was valid")
	}
	pps, dropRate, drops, valid := im.calculateNetRates("net", 1, 1, 0, 0, now.Add(time.Second))
	if !valid || pps != 0 || dropRate != 0 || drops != 0 {
		t.Fatalf("zero-delta network rates = %v/%v/%v valid=%v", pps, dropRate, drops, valid)
	}
	if _, _, _, valid := im.calculateNetRates("net", 0, 1, 0, 0, now.Add(2*time.Second)); valid {
		t.Fatal("network counter reset was valid")
	}
}

func TestHostMetricWrappersAndParsingFailures(t *testing.T) {
	free, avail, freeOK, availOK := parseHostMemInfo(strings.NewReader("MemFree: -1 kB\nMemAvailable: junk kB\n"))
	if free != 0 || avail != 0 || freeOK || availOK {
		t.Fatalf("invalid meminfo = %v/%v/%v/%v", free, avail, freeOK, availOK)
	}
	mc := &MetricsCollector{}
	free, avail = mc.getHostMemInfo()
	_, _, freeOK, availOK = mc.getHostMemInfoWithAvailability()
	if !freeOK || !availOK || free < 0 || avail < 0 {
		t.Fatalf("host memory = %v/%v available=%v/%v", free, avail, freeOK, availOK)
	}
	_ = mc.getHostCPUPercent()
	_, _ = mc.getHostCPUPercentWithAvailability()
	if total, ok := hostTotalMemBytesWithAvailability(); !ok || total == 0 || hostTotalMemBytes() == 0 {
		t.Fatalf("host total memory = %d available=%v", total, ok)
	}
	value, ok := hostConntrackMaxWithAvailability()
	if ok && value == 0 {
		t.Fatalf("conntrack max = %d available=%v", value, ok)
	}
}
