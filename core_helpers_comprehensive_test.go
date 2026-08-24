package main

import (
	"bytes"
	"log/slog"
	"math"
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

	// Keep the previous file alive while InitLogging replaces the test state.
	// InitLogging closes the handle currently stored in logFileHandle.
	logFileHandle = nil
	logMu.Unlock()

	t.Cleanup(func() {
		logMu.Lock()
		testFile := logFileHandle
		logFileHandle = previousFile
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

	v4 := IPToKey(net.ParseIP("192.0.2.4"))
	if !isIPv4MappedKey(v4) || IPKeyToString(v4) != "192.0.2.4" {
		t.Fatalf("IPv4 key roundtrip = %v/%q", isIPv4MappedKey(v4), IPKeyToString(v4))
	}
	v6 := IPToKey(net.ParseIP("2001:db8::4"))
	if isIPv4MappedKey(v6) || IPKeyToString(v6) != "2001:db8::4" {
		t.Fatalf("IPv6 key roundtrip = %v/%q", isIPv4MappedKey(v6), IPKeyToString(v6))
	}
	if IPToKey(nil) != (IPKey{}) || IPToKey(net.IP{1, 2, 3}) != (IPKey{}) || IPStrToKey("bad") != (IPKey{}) {
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
		"debug": "debug", "INFO": "info", " notice ": "warn", "warn": "warn", "error": "error", "junk": "info",
	} {
		_, got := normalizeLogLevel(input)
		if got != want {
			t.Errorf("normalize %q = %q", input, got)
		}
	}
	if applied := InitLogging("debug", path, true); applied != "debug" || CurrentLogLevel() != "debug" {
		t.Fatalf("logging level = %q/%q", applied, CurrentLogLevel())
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
	if got := InitLogging("error", t.TempDir(), true); got != "error" {
		t.Fatalf("failed-file logging level = %q", got)
	}
}

func TestAttentionWeightedInputCombinations(t *testing.T) {
	scoring := SeverityConfig{ResourceWeight: .5, BehaviorWeight: .3, ThreatWeight: .2}
	if got := attentionSeverityWeighted(scoring, 80, true, 50, true, 20, true); math.Abs(got-59) > 0.0001 {
		t.Fatalf("weighted attention = %v", got)
	}
	if got := attentionSeverityWeighted(scoring, 80, false, 50, true, 20, false); got != 50 {
		t.Fatalf("available-axis renormalization = %v", got)
	}
	if got := attentionSeverityWeighted(SeverityConfig{}, 100, true, 100, true, 100, true); got != 0 {
		t.Fatalf("zero-weight attention = %v", got)
	}
	if attentionInputsAvailable(SeverityConfig{}, true, true, true) {
		t.Fatal("zero-weight inputs reported available")
	}
}

func TestAttentionWeightedInputCombinationsDoNotOverflowFiniteWeights(t *testing.T) {
	tests := []struct {
		name                                            string
		scoring                                         SeverityConfig
		resourceSeverity, behaviorScore, threatSeverity float64
		resourceActive, behaviorActive, threatActive    bool
		want                                            float64
	}{
		{
			name:             "single maximum finite weight",
			scoring:          SeverityConfig{ResourceWeight: math.MaxFloat64},
			resourceSeverity: 73,
			resourceActive:   true,
			want:             73,
		},
		{
			name:             "equal maximum finite weights",
			scoring:          SeverityConfig{ResourceWeight: math.MaxFloat64, BehaviorWeight: math.MaxFloat64},
			resourceSeverity: 80,
			behaviorScore:    20,
			resourceActive:   true,
			behaviorActive:   true,
			want:             50,
		},
		{
			name:             "maximum finite relative weights",
			scoring:          SeverityConfig{ResourceWeight: math.MaxFloat64, BehaviorWeight: math.MaxFloat64 / 2},
			resourceSeverity: 90,
			behaviorScore:    30,
			resourceActive:   true,
			behaviorActive:   true,
			want:             70,
		},
		{
			name:             "inactive maximum weight is ignored",
			scoring:          SeverityConfig{ResourceWeight: math.MaxFloat64, BehaviorWeight: 1},
			resourceSeverity: 100,
			behaviorScore:    42,
			behaviorActive:   true,
			want:             42,
		},
		{
			name:             "zero and negative weights remain ignored",
			scoring:          SeverityConfig{ResourceWeight: -math.MaxFloat64, BehaviorWeight: 0, ThreatWeight: 2},
			resourceSeverity: 100,
			behaviorScore:    100,
			threatSeverity:   25,
			resourceActive:   true,
			behaviorActive:   true,
			threatActive:     true,
			want:             25,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := attentionSeverityWeighted(
				test.scoring,
				test.resourceSeverity,
				test.resourceActive,
				test.behaviorScore,
				test.behaviorActive,
				test.threatSeverity,
				test.threatActive,
			)
			if math.IsNaN(got) || math.IsInf(got, 0) || math.Abs(got-test.want) > 0.0001 {
				t.Fatalf("weighted attention = %v, want %v", got, test.want)
			}
		})
	}

	ignored := SeverityConfig{ResourceWeight: -1, BehaviorWeight: 0, ThreatWeight: -2}
	if got := attentionSeverityWeighted(ignored, 100, true, 100, true, 100, true); got != 0 {
		t.Fatalf("all non-positive weights produced %v, want 0", got)
	}
	if attentionInputsAvailable(ignored, true, true, true) {
		t.Fatal("non-positive weighted inputs reported available")
	}
}

func TestResourceV2MathAndStateLifecycle(t *testing.T) {
	axis := resourceAxisV2{}
	ew, alpha, tau := updateAxisV2(&axis, 2, 10, 2, 8)
	if ew != 1 || alpha != 1 || tau != 0 {
		t.Fatalf("axis initialization = %v/%v/%v", ew, alpha, tau)
	}
	ew, alpha, tau = updateAxisV2(&axis, 0, 10, 2, 8)
	if ew >= 1 || alpha <= 0 || tau != 8 {
		t.Fatalf("axis decay = %v/%v/%v", ew, alpha, tau)
	}
	if got := axisSeverityV2(2, 1, 2, 2); got != 100 {
		t.Fatalf("axis severity clamp = %v", got)
	}
	if lpBlend(3, 1, 2, 3, 4, 0, 0, 0, 0) != 0 {
		t.Fatal("zero-weight Lp blend is non-zero")
	}
	if lpBlend(0, 100, 0, 0, 0, 1, 0, 0, 0) != 100 {
		t.Fatal("default-power Lp blend is wrong")
	}
	for input, want := range map[float64]int{0: 0, 30: 30, 60: 60, 85: 85} {
		if got := band30_60_85(input); got != want {
			t.Errorf("band(%v) = %d", input, got)
		}
	}
	if countAxesAbove90(90, 91, 89, 100) != 3 {
		t.Fatal("axis threshold count is wrong")
	}
	for _, tt := range []struct {
		values [4]float64
		want   string
	}{
		{[4]float64{4, 3, 2, 1}, "cpu"},
		{[4]float64{1, 4, 3, 2}, "mem"},
		{[4]float64{1, 2, 4, 3}, "disk"},
		{[4]float64{1, 2, 3, 4}, "net"},
	} {
		if got := topAxisName(tt.values[0], tt.values[1], tt.values[2], tt.values[3]); got != tt.want {
			t.Errorf("top axis = %q, want %q", got, tt.want)
		}
	}

	mc := &MetricsCollector{collectionInterval: 15 * time.Second}
	now := time.Unix(1000, 0)
	input := resourceV2Input{Now: now, CpuAvailable: true, CpuPRaw: 1, CpuConf: 1, CpuImpact: 1}
	for i := 0; i < 3; i++ {
		input.Now = now.Add(time.Duration(i) * 15 * time.Second)
		out, _ := mc.computeResourceV2("vm-high", input)
		if i < 2 && (!out.CapActive || out.OverallFinal != 95) {
			t.Fatalf("single-axis cap cycle %d = %+v", i, out)
		}
		if i == 2 && (!out.PersistenceTriggered || out.CapActive || out.OverallFinal <= 95) {
			t.Fatalf("persistence cycle = %+v", out)
		}
	}
	out, state := mc.computeResourceV2("vm-two-axis", resourceV2Input{
		Now: now, CpuAvailable: true, CpuPRaw: 1, CpuConf: 1, CpuImpact: 1,
		MemAvailable: true, MemPRaw: 1, MemConf: 1, MemImpact: 1,
	})
	if out.AxesGE90 != 2 || out.CapActive || out.OverallFinal <= 95 {
		t.Fatalf("two-axis output = %+v", out)
	}
	mc.maybeLogResourceV2Event("d", "s", "vm-two-axis", "p", "pn", "u", out, state)
	mc.maybeLogResourceV2Event("d", "s", "vm-two-axis", "p", "pn", "u", resourceV2Output{}, state)
	mc.maybeLogResourceV2Event("", "", "", "", "", "", out, nil)

	var fields []any
	appendAxisFieldsV2(&fields, "cpu", out.CPU)
	if len(fields) != 16 {
		t.Fatalf("axis structured field count = %d", len(fields))
	}
	mc.getResourceV2State("keep")
	mc.getResourceV2State("remove")
	mc.cleanupResourceV2(map[string]struct{}{"keep": {}})
	if _, ok := mc.resourceV2["keep"]; !ok {
		t.Fatal("active resource state was removed")
	}
	if _, ok := mc.resourceV2["remove"]; ok {
		t.Fatal("inactive resource state was retained")
	}
	(&MetricsCollector{}).cleanupResourceV2(nil)
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
	if ok && (value == 0 || hostConntrackMax() != value) {
		t.Fatalf("conntrack max = %d available=%v", value, ok)
	}
}
