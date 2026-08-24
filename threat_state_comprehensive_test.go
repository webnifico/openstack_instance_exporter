package main

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func newThreatStateTestProvider(name string) *IPThreatProvider {
	metricPrefix := strings.ToLower(name)
	p := &IPThreatProvider{
		Name:                          name,
		Enabled:                       true,
		RefreshInterval:               time.Hour,
		Direction:                     ContactOut,
		LogTag:                        strings.ToUpper(name),
		Logger:                        NewComponentLogger("test", "threat"),
		Set:                           make(map[IPKey]struct{}),
		CountMap:                      make(map[string]float64),
		PrevHits:                      make(map[string]map[string]struct{}),
		InstanceContactsMetricName:    "test_" + metricPrefix + "_contacts_total",
		InstanceActiveMetricName:      "test_" + metricPrefix + "_active_flows",
		HostRefreshLastMetricName:     "test_" + metricPrefix + "_refresh_last_success",
		HostRefreshDurationMetricName: "test_" + metricPrefix + "_refresh_duration",
		HostRefreshErrorsMetricName:   "test_" + metricPrefix + "_refresh_errors_total",
		HostEntriesMetricName:         "test_" + metricPrefix + "_entries",
	}
	p.SetAtomic.Store(p.Set)
	return p
}

func newThreatStateTestManager(providers ...*IPThreatProvider) *ThreatManager {
	tm := &ThreatManager{
		shutdownChan:         make(chan struct{}),
		httpClient:           &http.Client{Timeout: time.Second},
		Providers:            providers,
		spamDir:              ContactOut,
		spamCount:            make(map[string]float64),
		spamPrevHits:         make(map[string]map[string]struct{}),
		spamBucketsV4:        make(map[uint16][]*net.IPNet),
		spamBucketsV6:        make(map[uint32][]*net.IPNet),
		threatLastHit:        make(map[string]time.Time),
		hostThreatHits:       make(map[string]map[string]string),
		threatLogMinInterval: time.Minute,
		hostIPsAllowPrivate:  true,
		hostInterfaces:       make(map[string]struct{}),
	}
	initThreatMetrics(tm)
	return tm
}

func TestThreatDirectionNormalizationAndSignalUnion(t *testing.T) {
	cases := map[string]string{
		" out ":    "outbound",
		"OUTBOUND": "outbound",
		"src":      "outbound",
		"in":       "inbound",
		"INBOUND":  "inbound",
		"dst":      "inbound",
		"any":      "any",
	}
	for input, want := range cases {
		if got := normalizeDirectionForLog(input); got != want {
			t.Fatalf("normalizeDirectionForLog(%q)=%q, want %q", input, got, want)
		}
	}

	for _, tc := range []struct {
		current float64
		signal  float64
		want    float64
	}{
		{-1, -1, 0},
		{0.2, 0, 0.2},
		{0.2, 0.5, 0.6},
		{2, 0.5, 1},
		{0.5, 2, 1},
	} {
		if got := combineThreatSignalsUnion(tc.current, tc.signal); got != tc.want {
			t.Fatalf("combineThreatSignalsUnion(%v,%v)=%v, want %v", tc.current, tc.signal, got, tc.want)
		}
	}
}

func TestThreatIntelHistoryInitializationUpdateAndAvailability(t *testing.T) {
	mc := &MetricsCollector{}
	if got := mc.snapshotIntelHistory("missing", 0.7); got != 0.7 {
		t.Fatalf("missing history fallback=%v, want 0.7", got)
	}
	if got, ok := mc.snapshotIntelHistoryAvailable("missing"); ok || got != 0 {
		t.Fatalf("missing history=(%v,%v), want (0,false)", got, ok)
	}
	if got := mc.updateIntelHistory("vm-1", 0.8); got != 0.8 {
		t.Fatalf("initial history=%v, want 0.8", got)
	}
	if got := mc.updateIntelHistory("vm-1", 0.2); got < 0.739999 || got > 0.740001 {
		t.Fatalf("updated history=%v, want 0.74", got)
	}
	if got, ok := mc.snapshotIntelHistoryAvailable("vm-1"); !ok || got < 0.739999 || got > 0.740001 {
		t.Fatalf("history snapshot=(%v,%v), want approximately (0.74,true)", got, ok)
	}
	mc.intelHistory["uninitialized"] = &IntelHistory{EWMA: 0.9}
	if _, ok := mc.snapshotIntelHistoryAvailable("uninitialized"); ok {
		t.Fatal("uninitialized history reported available")
	}
}

func TestThreatCountersThrottleAndCleanup(t *testing.T) {
	p := newThreatStateTestProvider("Provider")
	tm := newThreatStateTestManager(p)
	if got := tm.addThreatCount(p.CountMap, &p.CountMu, "vm-1", 2); got != 2 {
		t.Fatalf("first threat count=%v, want 2", got)
	}
	if got := tm.addThreatCount(p.CountMap, &p.CountMu, "vm-1", 0); got != 2 {
		t.Fatalf("zero delta changed threat count to %v", got)
	}

	now := time.Unix(1_700_000_000, 0)
	if !tm.shouldLogThreatHit("key", now) {
		t.Fatal("first threat hit was suppressed")
	}
	if tm.shouldLogThreatHit("key", now.Add(30*time.Second)) {
		t.Fatal("threat hit inside throttle interval was logged")
	}
	if !tm.shouldLogThreatHit("key", now.Add(time.Minute)) {
		t.Fatal("threat hit at throttle boundary was suppressed")
	}
	if !tm.shouldLogThreatHit("key", now.Add(-time.Hour)) {
		t.Fatal("wall-clock rollback suppressed threat logging until the old timestamp")
	}
	tm.threatLogMinInterval = 0
	if !tm.shouldLogThreatHit("unthrottled", now) || !tm.shouldLogThreatHit("unthrottled", now) {
		t.Fatal("disabled threat throttle suppressed a hit")
	}

	p.CountMap = map[string]float64{"active": 1, "stale": 2}
	p.PrevHits = map[string]map[string]struct{}{"active": {"a": {}}, "stale": {"b": {}}}
	tm.spamCount = map[string]float64{"active": 3, "stale": 4}
	tm.spamPrevHits = map[string]map[string]struct{}{"active": {"a": {}}, "stale": {"b": {}}}
	tm.cleanupThreatCounts(map[string]struct{}{"active": {}})
	if len(p.CountMap) != 1 || p.CountMap["active"] != 1 || len(p.PrevHits) != 1 || len(tm.spamCount) != 1 || len(tm.spamPrevHits) != 1 {
		t.Fatalf("threat cleanup retained stale state: provider=%v prev=%v spam=%v spamPrev=%v", p.CountMap, p.PrevHits, tm.spamCount, tm.spamPrevHits)
	}

	tm.threatLogMinInterval = time.Minute
	tm.threatLastHit = map[string]time.Time{
		"old":    time.Now().Add(-2 * time.Minute),
		"recent": time.Now(),
	}
	tm.cleanupThreatLastHit()
	if _, ok := tm.threatLastHit["old"]; ok {
		t.Fatal("old threat throttle state was retained")
	}
	if _, ok := tm.threatLastHit["recent"]; !ok {
		t.Fatal("recent threat throttle state was removed")
	}
}

func TestThreatEnablementAndFreshSourceSelection(t *testing.T) {
	now := time.Now()
	disabled := newThreatStateTestProvider("Disabled")
	disabled.Enabled = false
	fresh := newThreatStateTestProvider("Fresh")
	fresh.LastSuccess = float64(now.Unix())
	fresh.EntryCount = 1
	stale := newThreatStateTestProvider("Stale")
	stale.LastSuccess = float64(now.Add(-3 * time.Hour).Unix())
	stale.EntryCount = 1
	empty := newThreatStateTestProvider("Empty")
	empty.LastSuccess = float64(now.Unix())
	tm := newThreatStateTestManager(disabled, fresh, stale, empty)

	if !tm.anyThreatsEnabled() {
		t.Fatal("enabled provider was not detected")
	}
	tm.Providers = append(tm.Providers, nil)
	spamFresh, providers := tm.freshThreatSources(now)
	tm.Providers = tm.Providers[:len(tm.Providers)-1]
	if spamFresh || len(providers) != 1 || providers[0] != fresh {
		t.Fatalf("fresh sources=(spam=%v, providers=%v), want only fresh provider", spamFresh, providers)
	}
	tm.spamEnabled = true
	tm.spamEntries = 2
	tm.spamLastSuccessUnix = float64(now.Unix())
	tm.spamRefresh = time.Hour
	spamFresh, _ = tm.freshThreatSources(now)
	if !spamFresh {
		t.Fatal("fresh Spamhaus source was not selected")
	}
	if spam, got := (*ThreatManager)(nil).freshThreatSources(now); spam || got != nil {
		t.Fatalf("nil manager fresh sources=(%v,%v), want false,nil", spam, got)
	}

	tm.spamEnabled = false
	fresh.Enabled = false
	stale.Enabled = false
	empty.Enabled = false
	if tm.anyThreatsEnabled() {
		t.Fatal("disabled threat configuration reported enabled")
	}
	tm.spamEnabled = true
	if !tm.anyThreatsEnabled() {
		t.Fatal("enabled Spamhaus configuration was not detected")
	}
}

func TestThreatHitExportTracksOnlyNewContacts(t *testing.T) {
	p := newThreatStateTestProvider("Export")
	tm := newThreatStateTestManager(p)
	hitKey := MakePairKey(IPStrToKey("10.0.0.10"), 12345, IPStrToKey("198.51.100.20"), 443, 6)
	hits := map[PairKey]ConntrackEntry{
		hitKey: {Src: "10.0.0.10", Dst: "198.51.100.20", SrcPort: 12345, DstPort: 443, Proto: 6},
	}
	ipSet := map[string]struct{}{"10.0.0.10": {}, "invalid": {}}
	metrics := make([]prometheus.Metric, 0)
	signal := 0.0
	tm.exportProviderHits(p, hits, 0, ipSet, "domain", "server", "vm-1", "project", "project-name", "user", &metrics, &signal, true)
	if len(metrics) != 2 || p.CountMap["vm-1"] != 1 || len(p.PrevHits["vm-1"]) != 1 || signal != 0.1 {
		t.Fatalf("first export metrics=%d count=%v prev=%v signal=%v", len(metrics), p.CountMap["vm-1"], p.PrevHits["vm-1"], signal)
	}

	metrics = nil
	signal = 0
	tm.exportProviderHits(p, hits, 0, ipSet, "domain", "server", "vm-1", "project", "project-name", "user", &metrics, &signal, true)
	if p.CountMap["vm-1"] != 1 {
		t.Fatalf("unchanged contact incremented total to %v", p.CountMap["vm-1"])
	}

	metrics = nil
	signal = 1
	tm.exportProviderHits(p, nil, 0, ipSet, "domain", "server", "vm-1", "project", "project-name", "user", &metrics, &signal, true)
	if len(metrics) != 2 || signal != 1 || len(p.PrevHits["vm-1"]) != 0 {
		t.Fatalf("empty export metrics=%d signal=%v prev=%v", len(metrics), signal, p.PrevHits["vm-1"])
	}

	metrics = nil
	tm.exportProviderHits(nil, hits, 0, ipSet, "domain", "server", "vm-1", "project", "project-name", "user", &metrics, &signal, true)
	if len(metrics) != 0 {
		t.Fatal("nil provider emitted metrics")
	}
}

func TestThreatMetricDescriptionAndHostMetricCollection(t *testing.T) {
	p := newThreatStateTestProvider("Metrics")
	p.LastSuccess = 10
	p.LastDuration = 2
	p.EntryCount = 3
	atomic.StoreUint64(&p.ErrorCount, 4)
	tm := newThreatStateTestManager(p)
	tm.spamEnabled = true
	tm.spamLastSuccessUnix = 20
	tm.spamLastRefreshSeconds = 5
	tm.spamEntries = 6
	atomic.StoreUint64(&tm.spamRefreshErrors, 7)
	tm.hostThreatsEnabled = true
	tm.hostThreatHits["list"] = map[string]string{"192.0.2.1": "ipv4"}

	descCh := make(chan *prometheus.Desc, 16)
	tm.describeThreatMetrics(descCh)
	if len(descCh) != 4 {
		t.Fatalf("threat descriptor count=%d, want 4", len(descCh))
	}
	tm.describeHostMetrics(descCh)
	if len(descCh) != 13 {
		t.Fatalf("combined descriptor count=%d, want 13", len(descCh))
	}

	metrics := make([]prometheus.Metric, 0)
	tm.collectHostThreatMetrics(&metrics)
	if len(metrics) != 9 {
		t.Fatalf("host threat metric count=%d, want 9", len(metrics))
	}

	disabledMetrics := make([]prometheus.Metric, 0)
	var mu sync.RWMutex
	var lastSuccess, lastDuration float64
	var errors uint64
	var entries int
	appendThreatHostMetrics(&disabledMetrics, false, &mu, &lastSuccess, &lastDuration, &errors, &entries,
		newHostMetricDesc("test_disabled_last", "test"),
		newHostMetricDesc("test_disabled_duration", "test"),
		newHostMetricDesc("test_disabled_errors", "test"),
		newHostMetricDesc("test_disabled_entries", "test"))
	if len(disabledMetrics) != 0 {
		t.Fatal("disabled source emitted host metrics")
	}
}

func TestThreatFileAndHTTPParsers(t *testing.T) {
	tm := newThreatStateTestManager()
	feedPath := filepath.Join(t.TempDir(), "feed.txt")
	if err := os.WriteFile(feedPath, []byte("# comment\n192.0.2.1\n192.0.2.1\nfe80::1%eth0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	set, err := tm.fetchFileLines(feedPath)
	if err != nil || len(set) != 2 {
		t.Fatalf("valid file feed=(%v,%v), want two entries", set, err)
	}
	if _, err := tm.fetchFileLines(filepath.Dir(feedPath)); err == nil {
		t.Fatal("directory threat feed unexpectedly accepted")
	}
	if _, err := tm.fetchFileLines(filepath.Join(filepath.Dir(feedPath), "missing")); err == nil {
		t.Fatal("missing threat feed unexpectedly accepted")
	}
	if _, err := scanIPLines(strings.NewReader("0.0.0.0\n")); err == nil {
		t.Fatal("unspecified threat address unexpectedly accepted")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/lines":
			_, _ = w.Write([]byte("192.0.2.2\n2001:db8::2\n"))
		case "/onionoo":
			_, _ = w.Write([]byte(`{"relays":[{"or_addresses":["192.0.2.3:9001","[2001:db8::3]:9001","[fe80::3%eth0]:9001"]}]}`))
		case "/trailing":
			_, _ = w.Write([]byte(`{"relays":[]} {"extra":true}`))
		case "/empty":
			_, _ = w.Write([]byte(" \n"))
		default:
			http.Error(w, "no", http.StatusBadGateway)
		}
	}))
	defer server.Close()
	tm.httpClient = server.Client()
	if got, err := tm.fetchURLLines(server.URL + "/lines"); err != nil || len(got) != 2 {
		t.Fatalf("line HTTP feed=(%v,%v), want two entries", got, err)
	}
	if got, err := tm.fetchOnionoo(server.URL + "/onionoo"); err != nil || len(got) != 3 {
		t.Fatalf("Onionoo HTTP feed=(%v,%v), want three entries", got, err)
	}
	if _, err := tm.fetchOnionoo(server.URL + "/trailing"); err == nil {
		t.Fatal("trailing Onionoo JSON unexpectedly accepted")
	}
	if _, err := tm.fetchURLLines(server.URL + "/empty"); err == nil {
		t.Fatal("empty HTTP feed unexpectedly accepted")
	}
	if _, err := tm.fetchURLLines(server.URL + "/status"); err == nil {
		t.Fatal("non-200 HTTP feed unexpectedly accepted")
	}
	if _, err := tm.fetchURLLines("file:///tmp/feed"); err == nil {
		t.Fatal("non-HTTP threat URL unexpectedly accepted")
	}
	if _, err := tm.fetchURLLines("https://user:pass@example.test/feed"); err == nil {
		t.Fatal("credential-bearing threat URL unexpectedly accepted")
	}
	tm.httpClient = nil
	if _, err := tm.fetchURLLines(server.URL + "/lines"); err == nil {
		t.Fatal("HTTP fetch without a client unexpectedly accepted")
	}
}

func TestThreatProviderRefreshSuccessFailureAndShutdown(t *testing.T) {
	p := newThreatStateTestProvider("Refresh")
	tm := newThreatStateTestManager(p)
	if err := tm.refreshProviderOnce(nil); err == nil {
		t.Fatal("nil provider refresh unexpectedly succeeded")
	}
	if err := tm.refreshProviderOnce(&IPThreatProvider{}); err == nil {
		t.Fatal("provider without fetcher unexpectedly succeeded")
	}
	p.Fetcher = func() (map[IPKey]struct{}, error) { return nil, errors.New("fetch failed") }
	if err := tm.refreshProviderOnce(p); err == nil {
		t.Fatal("provider fetch error was ignored")
	}

	wantKey := IPStrToKey("192.0.2.77")
	p.Fetcher = func() (map[IPKey]struct{}, error) {
		return map[IPKey]struct{}{wantKey: {}}, nil
	}
	if err := tm.refreshProviderOnce(p); err != nil {
		t.Fatalf("valid provider refresh failed: %v", err)
	}
	if p.EntryCount != 1 || p.LastSuccess <= 0 {
		t.Fatalf("valid provider refresh state: entries=%d last=%v", p.EntryCount, p.LastSuccess)
	}
	loaded, ok := p.SetAtomic.Load().(map[IPKey]struct{})
	if !ok {
		t.Fatal("provider atomic set has unexpected type")
	}
	if _, ok := loaded[wantKey]; !ok {
		t.Fatal("provider atomic set is missing refreshed address")
	}

	p.RefreshInterval = 0
	close(tm.shutdownChan)
	done := make(chan struct{})
	go func() {
		tm.runProviderRefresher(p)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("provider refresher did not stop on shutdown")
	}

	errorProvider := newThreatStateTestProvider("ErrorRefresh")
	errorProvider.RefreshInterval = 0
	errorProvider.Fetcher = func() (map[IPKey]struct{}, error) { return nil, errors.New("boom") }
	errorTM := newThreatStateTestManager(errorProvider)
	close(errorTM.shutdownChan)
	errorTM.runProviderRefresher(errorProvider)
	if atomic.LoadUint64(&errorProvider.ErrorCount) != 1 {
		t.Fatalf("provider refresh errors=%d, want 1", atomic.LoadUint64(&errorProvider.ErrorCount))
	}
}

func TestThreatProviderPeriodicRefresherRunsUntilShutdown(t *testing.T) {
	p := newThreatStateTestProvider("Periodic")
	p.RefreshInterval = 5 * time.Millisecond
	calls := make(chan struct{}, 8)
	p.Fetcher = func() (map[IPKey]struct{}, error) {
		calls <- struct{}{}
		return map[IPKey]struct{}{IPStrToKey("192.0.2.88"): {}}, nil
	}
	tm := newThreatStateTestManager(p)
	done := make(chan struct{})
	go func() {
		tm.runProviderRefresher(p)
		close(done)
	}()
	for i := 0; i < 2; i++ {
		select {
		case <-calls:
		case <-time.After(time.Second):
			close(tm.shutdownChan)
			t.Fatal("periodic provider refresh did not run")
		}
	}
	close(tm.shutdownChan)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("periodic provider refresher did not stop")
	}
}

func TestThreatDomainSignalCollectionFreshStaleAndOutage(t *testing.T) {
	p := newThreatStateTestProvider("Intel")
	now := time.Now()
	p.LastSuccess = float64(now.Unix())
	p.EntryCount = 1
	tm := newThreatStateTestManager(p)
	tm.spamEnabled = true
	tm.spamEntries = 1
	tm.spamRefresh = time.Hour
	tm.spamLastSuccessUnix = float64(now.Unix())
	mc := &MetricsCollector{tm: tm, intelHistory: make(map[string]*IntelHistory)}
	vmIP := "10.0.0.10"
	remote1 := "198.51.100.10"
	remote2 := "198.51.100.20"
	spamKey := MakePairKey(IPStrToKey(vmIP), 1000, IPStrToKey(remote1), 443, 6)
	providerKey := MakePairKey(IPStrToKey(vmIP), 1001, IPStrToKey(remote2), 443, 6)
	agg := &ConntrackAgg{
		SpamhausHits: map[string]map[PairKey]ConntrackEntry{
			"vm-1": {spamKey: {Src: vmIP, Dst: remote1, SrcPort: 1000, DstPort: 443, Proto: 6}},
		},
		ProviderHits: map[string]map[string]map[PairKey]ConntrackEntry{
			p.Name: {"vm-1": {providerKey: {Src: vmIP, Dst: remote2, SrcPort: 1001, DstPort: 443, Proto: 6}}},
		},
	}
	metrics := make([]prometheus.Metric, 0)
	signal, available := mc.collectDomainThreatSignals(agg, map[string]struct{}{vmIP: {}},
		"domain", "server", "vm-1", "project", "project-name", "user", true, &metrics)
	if !available || signal <= 0 || len(metrics) != 4 {
		t.Fatalf("fresh threat signals=(%v,%v), metrics=%d", signal, available, len(metrics))
	}
	if _, ok := mc.snapshotIntelHistoryAvailable("vm-1"); !ok {
		t.Fatal("fresh threat signal did not update history")
	}

	metrics = nil
	previous, available := mc.collectDomainThreatSignals(nil, map[string]struct{}{vmIP: {}},
		"domain", "server", "vm-1", "project", "project-name", "user", false, &metrics)
	if !available || previous <= 0 || len(metrics) != 0 {
		t.Fatalf("conntrack outage signal=(%v,%v), metrics=%d", previous, available, len(metrics))
	}

	p.LastSuccess = float64(now.Add(-3 * time.Hour).Unix())
	tm.spamLastSuccessUnix = float64(now.Add(-3 * time.Hour).Unix())
	if got, ok := mc.collectDomainThreatSignals(agg, nil, "domain", "server", "new-vm", "project", "project-name", "user", true, &metrics); ok || got != 0 {
		t.Fatalf("stale threat feeds returned (%v,%v), want unavailable", got, ok)
	}
	if got, ok := (&MetricsCollector{}).collectDomainThreatSignals(agg, nil, "domain", "server", "vm", "project", "project-name", "user", true, &metrics); ok || got != 0 {
		t.Fatalf("collector without threat manager returned (%v,%v)", got, ok)
	}
}

func TestThreatActiveFlowMetricIncludesCappedEvidence(t *testing.T) {
	p := newThreatStateTestProvider("Capped")
	now := time.Now()
	p.LastSuccess = float64(now.Unix())
	p.EntryCount = 1
	tm := newThreatStateTestManager(p)
	mc := &MetricsCollector{tm: tm, intelHistory: make(map[string]*IntelHistory)}

	vmIP := "10.0.0.10"
	remote := "198.51.100.20"
	hitKey := MakePairKey(IPStrToKey(vmIP), 1001, IPStrToKey(remote), 443, 6)
	agg := &ConntrackAgg{
		ProviderHits: map[string]map[string]map[PairKey]ConntrackEntry{
			p.Name: {"vm-1": {hitKey: {Src: vmIP, Dst: remote, SrcPort: 1001, DstPort: 443, Proto: 6}}},
		},
		ProviderHitsDropped: map[string]map[string]uint64{
			p.Name: {"vm-1": 7},
		},
	}
	metrics := make([]prometheus.Metric, 0)
	signal, available := mc.collectDomainThreatSignals(
		agg,
		map[string]struct{}{vmIP: {}},
		"domain", "server", "vm-1", "project", "project-name", "user",
		true,
		&metrics,
	)
	if !available || len(metrics) != 2 {
		t.Fatalf("capped threat collection available=%v metrics=%d", available, len(metrics))
	}
	var active dto.Metric
	if err := metrics[0].Write(&active); err != nil {
		t.Fatal(err)
	}
	if got := active.GetGauge().GetValue(); got != 8 {
		t.Fatalf("active threat flows=%v, want retained plus dropped evidence 8", got)
	}
	if signal != 0.8 {
		t.Fatalf("threat signal=%v, want 0.8 from all eight active flows", signal)
	}
}

func TestThreatHostStateAndDiscoveryControls(t *testing.T) {
	tm := newThreatStateTestManager()
	if got := tm.discoverHostIPs(false, true); got != nil {
		t.Fatalf("disabled host discovery=%v, want nil", got)
	}
	tm.setHostThreatHitsForList("disabled", map[string]string{"192.0.2.1": "ipv4"})
	if len(tm.hostThreatHits) != 0 {
		t.Fatal("disabled host threat state was updated")
	}
	tm.hostThreatsEnabled = true
	tm.setHostThreatHitsForList("enabled", map[string]string{"192.0.2.1": "ipv4"})
	if tm.hostThreatHits["enabled"]["192.0.2.1"] != "ipv4" {
		t.Fatal("enabled host threat state was not stored")
	}

	// A nonexistent interface makes these checks deterministic while exercising
	// the host-list replacement paths.
	tm.hostInterfaces = map[string]struct{}{"definitely-not-an-interface": {}}
	tm.updateHostThreatsFromIPSet("ip-set", map[IPKey]struct{}{IPStrToKey("192.0.2.1"): {}})
	_, cidr, err := net.ParseCIDR("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	tm.updateHostThreatsFromCIDRs("cidr", []*net.IPNet{cidr})
	if hits := tm.hostThreatHits["ip-set"]; hits == nil || len(hits) != 0 {
		t.Fatalf("IP-set host hits=%v, want an empty replacement map", hits)
	}
	if hits := tm.hostThreatHits["cidr"]; hits == nil || len(hits) != 0 {
		t.Fatalf("CIDR host hits=%v, want an empty replacement map", hits)
	}
}

func TestThreatLoggingEntryPointsRespectDirectionAndThrottle(t *testing.T) {
	tm := newThreatStateTestManager()
	tm.threatLogMinInterval = time.Hour
	ct := ConntrackEntry{Src: "10.0.0.10", Dst: "198.51.100.10"}
	// Direction mismatch returns before allocating throttle state.
	tm.logThreatHit("TEST", "domain", "server", "vm", "project", "project-name", "user", ct, "in", ContactOut)
	if len(tm.threatLastHit) != 0 {
		t.Fatal("direction-mismatched threat hit changed throttle state")
	}
	tm.logThreatHit("TEST", "domain", "server", "vm", "project", "project-name", "user", ct, "out", ContactAny)
	if len(tm.threatLastHit) != 1 {
		t.Fatal("matching threat hit did not create throttle state")
	}
	tm.logHostThreatHit("list", "192.0.2.1", "ipv4")
	tm.logHostThreatHit("list", "192.0.2.1", "ipv4")
	if len(tm.threatLastHit) != 2 {
		t.Fatal("host threat hit throttle key was not stable")
	}
	for _, tag := range []string{"BEHAVIOR", "POLICY", "THREAT"} {
		tm.logThreatEvent(tag, "event", "domain", "vm", "project", "project-name", "user", "detail", tag)
	}
	if len(tm.threatLastHit) != 5 {
		t.Fatalf("threat event throttle entries=%d, want 5", len(tm.threatLastHit))
	}
}

func TestBehaviorThreatLogThrottleSeparatesAlertKinds(t *testing.T) {
	tm := newThreatStateTestManager()
	tm.threatLogMinInterval = time.Hour

	tm.logThreatEvent(
		"BEHAVIOR", "behavior_alert", "domain", "vm", "project", "project-name", "user",
		"kind", "outbound_horizontal_scan_suspected",
	)
	tm.logThreatEvent(
		"BEHAVIOR", "behavior_alert", "domain", "vm", "project", "project-name", "user",
		"kind", "outbound_stratum_mining_suspected",
	)

	if len(tm.threatLastHit) != 2 {
		t.Fatalf("distinct behavior kinds share throttle state: got %d entries, want 2", len(tm.threatLastHit))
	}
}

func TestSpamhausSuccessfulRefreshBuildsAllIndexesAndStops(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v4":
			_, _ = w.Write([]byte("10.0.0.0/8 ; wide\n192.0.2.0/24 ; bucket\n"))
		case "/v6":
			_, _ = w.Write([]byte("3001::/16 ; wide\n2001:db8::/32 ; bucket\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	tm := newThreatStateTestManager()
	tm.httpClient = server.Client()
	tm.spamEnabled = true
	tm.spamURL = server.URL + "/v4"
	tm.spamV6URL = server.URL + "/v6"
	tm.refreshSpamhausList()
	if tm.spamEntries != 4 || tm.spamLastSuccessUnix <= 0 {
		t.Fatalf("Spamhaus refresh entries=%d last=%v", tm.spamEntries, tm.spamLastSuccessUnix)
	}
	if len(tm.spamWideV4) != 1 || len(tm.spamBucketsV4) != 1 || len(tm.spamWideV6) != 1 || len(tm.spamBucketsV6) != 1 {
		t.Fatalf("Spamhaus indexes wide4=%v bucket4=%v wide6=%v bucket6=%v", tm.spamWideV4, tm.spamBucketsV4, tm.spamWideV6, tm.spamBucketsV6)
	}

	tm.spamRefresh = 0
	close(tm.shutdownChan)
	done := make(chan struct{})
	go func() {
		tm.startSpamhausRefresher()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Spamhaus refresher did not stop on shutdown")
	}
}

func TestThreatHostDiscoveryAndExactListUpdates(t *testing.T) {
	tm := newThreatStateTestManager()
	tm.hostThreatsEnabled = true
	tm.hostIPsAllowPrivate = true
	tm.hostInterfaces = map[string]struct{}{"lo": {}}
	hostIPs := tm.getHostIPs()
	behaviorIPs := tm.getBehaviorHostIPs()
	if len(behaviorIPs) < len(hostIPs) {
		t.Fatalf("behavior host discovery=%v, expected at least configured host discovery=%v", behaviorIPs, hostIPs)
	}
	if len(hostIPs) == 0 {
		t.Log("loopback interface addresses are unavailable in this environment")
		return
	}
	ipSet := make(map[IPKey]struct{}, len(hostIPs))
	nets := make([]*net.IPNet, 0, len(hostIPs))
	for _, hostIP := range hostIPs {
		key := IPStrToKey(hostIP.Address)
		if key == (IPKey{}) || (hostIP.Family != "ipv4" && hostIP.Family != "ipv6") {
			t.Fatalf("invalid discovered host IP: %+v", hostIP)
		}
		ipSet[key] = struct{}{}
		parsed := net.ParseIP(hostIP.Address)
		bits := 128
		if parsed.To4() != nil {
			bits = 32
			parsed = parsed.To4()
		}
		nets = append(nets, &net.IPNet{IP: parsed, Mask: net.CIDRMask(bits, bits)})
	}
	tm.updateHostThreatsFromIPSet("exact", ipSet)
	tm.updateHostThreatsFromCIDRs("cidrs", nets)
	if len(tm.hostThreatHits["exact"]) != len(hostIPs) || len(tm.hostThreatHits["cidrs"]) != len(hostIPs) {
		t.Fatalf("host threat matches exact=%v cidrs=%v hosts=%v", tm.hostThreatHits["exact"], tm.hostThreatHits["cidrs"], hostIPs)
	}

	tm.hostIPsAllowPrivate = false
	if publicOnly := tm.getHostIPs(); len(publicOnly) != 0 {
		t.Fatalf("private/local loopback addresses were not filtered: %v", publicOnly)
	}
}

func TestBehaviorHostIPDiscoveryIgnoresHostThreatInterfaceWhitelist(t *testing.T) {
	interfaces := []net.Interface{{Name: "management0", Flags: net.FlagUp}}
	addresses := func(net.Interface) ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: net.ParseIP("10.20.30.40"), Mask: net.CIDRMask(24, 32)}}, nil
	}
	threatFilter := map[string]struct{}{"bgp-nic": {}}
	if got := discoverHostIPsFromInterfaces(interfaces, addresses, true, threatFilter); len(got) != 0 {
		t.Fatalf("host-threat discovery ignored its interface whitelist: %+v", got)
	}
	if got := discoverHostIPsFromInterfaces(interfaces, addresses, true, nil); len(got) != 1 || got[0].Address != "10.20.30.40" {
		t.Fatal("behavior host/control discovery was incorrectly constrained by the host-threat interface whitelist")
	}
}
