package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

type threatIntelligenceProviderLifecycleSnapshot struct {
	addresses   []string
	lastSuccess float64
	duration    float64
	entries     int
}

func threatIntelligenceProviderSnapshot(p *IPThreatProvider) threatIntelligenceProviderLifecycleSnapshot {
	p.Mu.RLock()
	defer p.Mu.RUnlock()
	addresses := make([]string, 0, len(p.Set))
	for address := range p.Set {
		addresses = append(addresses, IPKeyToString(address))
	}
	sort.Strings(addresses)
	return threatIntelligenceProviderLifecycleSnapshot{
		addresses:   addresses,
		lastSuccess: p.LastSuccess,
		duration:    p.LastDuration,
		entries:     p.EntryCount,
	}
}

func threatIntelligenceMetricValue(t *testing.T, metric interface{ Write(*dto.Metric) error }) float64 {
	t.Helper()
	var encoded dto.Metric
	if err := metric.Write(&encoded); err != nil {
		t.Fatal(err)
	}
	if encoded.Gauge != nil {
		return encoded.Gauge.GetValue()
	}
	if encoded.Counter != nil {
		return encoded.Counter.GetValue()
	}
	t.Fatalf("metric has neither gauge nor counter value: %v", encoded.String())
	return 0
}

func threatIntelligenceAssertThreatFeedStates(t *testing.T, metrics []prometheus.Metric, want map[string]float64) {
	t.Helper()
	got := make(map[string]float64, len(want))
	for _, metric := range metrics {
		if !strings.Contains(metric.Desc().String(), `fqName: "oie_host_threat_feed_fresh"`) {
			continue
		}
		var encoded dto.Metric
		if err := metric.Write(&encoded); err != nil {
			t.Fatal(err)
		}
		list := ""
		for _, label := range encoded.Label {
			if label.GetName() == "list" {
				list = label.GetValue()
			}
		}
		if list == "" || encoded.Gauge == nil {
			t.Fatalf("invalid threat-feed state sample: %s", encoded.String())
		}
		if _, duplicate := got[list]; duplicate {
			t.Fatalf("duplicate threat-feed state sample for %q", list)
		}
		got[list] = encoded.GetGauge().GetValue()
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("threat-feed states=%v, want exact fixed tri-state set %v", got, want)
	}
}

func TestThreatIntelligenceGenericHTTPFeedLifecycleRetainsExactLastGood(t *testing.T) {
	const (
		feedInitial int32 = iota
		feedHTTPError
		feedMalformed
		feedEmpty
		feedRecoveredV4
		feedRecoveredV6
	)
	var mode atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		switch mode.Load() {
		case feedInitial:
			_, _ = io.WriteString(w, "192.0.2.10\n2001:db8::10\n")
		case feedHTTPError:
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		case feedMalformed:
			_, _ = io.WriteString(w, "198.51.100.20\nnot-an-address\n")
		case feedEmpty:
			_, _ = io.WriteString(w, "# no entries\n")
		case feedRecoveredV4:
			_, _ = io.WriteString(w, "198.51.100.40\n")
		case feedRecoveredV6:
			_, _ = io.WriteString(w, "2001:db8:ffff::40\n")
		default:
			http.Error(w, "unknown fixture", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	p := newThreatStateTestProvider("threat_intelligence_http")
	tm := newThreatStateTestManager(p)
	tm.httpClient = server.Client()
	p.Fetcher = func() (map[IPKey]struct{}, error) { return tm.fetchURLLines(server.URL) }

	if err := tm.refreshProviderAttempt(p); err != nil {
		t.Fatalf("initial refresh failed: %v", err)
	}
	initial := threatIntelligenceProviderSnapshot(p)
	if !reflect.DeepEqual(initial.addresses, []string{"192.0.2.10", "2001:db8::10"}) ||
		initial.entries != 2 || initial.lastSuccess <= 0 || initial.duration < 0 ||
		atomic.LoadUint64(&p.ErrorCount) != 0 {
		t.Fatalf("initial lifecycle state=%+v errors=%d", initial, atomic.LoadUint64(&p.ErrorCount))
	}

	// Fixed sentinels make exact failure retention deterministic even when the
	// success and recovery requests happen within the same wall-clock second.
	p.Mu.Lock()
	p.LastSuccess = 123
	p.LastDuration = 4.5
	p.Mu.Unlock()
	lastGood := threatIntelligenceProviderSnapshot(p)

	for _, failure := range []struct {
		name string
		mode int32
	}{
		{name: "http_error", mode: feedHTTPError},
		{name: "malformed_after_valid_prefix", mode: feedMalformed},
		{name: "empty", mode: feedEmpty},
	} {
		t.Run(failure.name, func(t *testing.T) {
			mode.Store(failure.mode)
			if err := tm.refreshProviderAttempt(p); err == nil {
				t.Fatal("failed feed unexpectedly refreshed")
			}
			if got := threatIntelligenceProviderSnapshot(p); !reflect.DeepEqual(got, lastGood) {
				t.Fatalf("failure changed last-good state: got %+v want %+v", got, lastGood)
			}
		})
	}

	fullBody := "203.0.113.50\n203.0.113.51\n"
	validPrefix := "203.0.113.50\n"
	tm.httpClient = &http.Client{Transport: threatRoundTripperFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode:    http.StatusOK,
			Status:        "200 OK",
			Header:        make(http.Header),
			Body:          io.NopCloser(io.LimitReader(&threatIntelligenceStaticReader{body: []byte(validPrefix)}, int64(len(validPrefix)))),
			ContentLength: int64(len(fullBody)),
			Request:       request,
		}, nil
	})}
	p.Fetcher = func() (map[IPKey]struct{}, error) {
		return tm.fetchURLLines("https://feed.example.test/truncated")
	}
	if err := tm.refreshProviderAttempt(p); err == nil {
		t.Fatal("declared truncated response published its valid prefix")
	}
	if got := threatIntelligenceProviderSnapshot(p); !reflect.DeepEqual(got, lastGood) {
		t.Fatalf("truncated response changed last-good state: got %+v want %+v", got, lastGood)
	}

	timeoutServer := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	}))
	defer timeoutServer.Close()
	timeoutClient := timeoutServer.Client()
	timeoutClient.Timeout = 20 * time.Millisecond
	tm.httpClient = timeoutClient
	p.Fetcher = func() (map[IPKey]struct{}, error) { return tm.fetchURLLines(timeoutServer.URL) }
	if err := tm.refreshProviderAttempt(p); err == nil {
		t.Fatal("timed-out download unexpectedly refreshed")
	}
	if got := threatIntelligenceProviderSnapshot(p); !reflect.DeepEqual(got, lastGood) {
		t.Fatalf("timeout changed last-good state: got %+v want %+v", got, lastGood)
	}

	tm.httpClient = server.Client()
	p.Fetcher = func() (map[IPKey]struct{}, error) { return tm.fetchURLLines(server.URL) }
	mode.Store(feedRecoveredV4)
	if err := tm.refreshProviderAttempt(p); err != nil {
		t.Fatalf("IPv4 recovery failed: %v", err)
	}
	recoveredV4 := threatIntelligenceProviderSnapshot(p)
	if !reflect.DeepEqual(recoveredV4.addresses, []string{"198.51.100.40"}) || recoveredV4.entries != 1 ||
		recoveredV4.lastSuccess <= lastGood.lastSuccess || recoveredV4.duration < 0 {
		t.Fatalf("IPv4 recovery did not exactly replace the old feed: %+v", recoveredV4)
	}

	mode.Store(feedRecoveredV6)
	if err := tm.refreshProviderAttempt(p); err != nil {
		t.Fatalf("IPv6-only refresh failed: %v", err)
	}
	recoveredV6 := threatIntelligenceProviderSnapshot(p)
	if !reflect.DeepEqual(recoveredV6.addresses, []string{"2001:db8:ffff::40"}) || recoveredV6.entries != 1 {
		t.Fatalf("IPv6 refresh did not remove the previous IPv4 address: %+v", recoveredV6)
	}
	if got := atomic.LoadUint64(&p.ErrorCount); got != 5 {
		t.Fatalf("refresh error counter=%d, want five failed attempts", got)
	}

	metrics := make([]prometheus.Metric, 0, 9)
	tm.collectHostThreatMetrics(&metrics)
	if len(metrics) != 9 || threatIntelligenceMetricValue(t, metrics[0]) != recoveredV6.lastSuccess ||
		threatIntelligenceMetricValue(t, metrics[1]) != recoveredV6.duration ||
		threatIntelligenceMetricValue(t, metrics[2]) != 5 || threatIntelligenceMetricValue(t, metrics[3]) != 1 {
		t.Fatalf("published lifecycle metrics do not match state: metrics=%d state=%+v", len(metrics), recoveredV6)
	}
	threatIntelligenceAssertThreatFeedStates(t, metrics, map[string]float64{
		"TOREXIT": -1, "TORRELAY": -1, "EMERGING": -1, "CUSTOMLIST": -1, "spamhaus": -1,
	})
}

// threatIntelligenceStaticReader deliberately returns a clean EOF after a valid prefix.
// fetchHTTPBytes must still reject it when Content-Length describes more data.
type threatIntelligenceStaticReader struct {
	body []byte
}

func (r *threatIntelligenceStaticReader) Read(dst []byte) (int, error) {
	if len(r.body) == 0 {
		return 0, io.EOF
	}
	n := copy(dst, r.body)
	r.body = r.body[n:]
	return n, nil
}

func TestThreatIntelligenceCustomFileFeedLifecycleRetainsExactLastGood(t *testing.T) {
	path := t.TempDir() + "/custom-threat-feed.txt"
	if err := os.WriteFile(path, []byte("192.0.2.60\n2001:db8::60\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := newThreatStateTestProvider("threat_intelligence_file")
	tm := newThreatStateTestManager(p)
	p.Fetcher = func() (map[IPKey]struct{}, error) { return tm.fetchFileLines(path) }

	if err := tm.refreshProviderAttempt(p); err != nil {
		t.Fatalf("initial file refresh failed: %v", err)
	}
	p.Mu.Lock()
	p.LastSuccess = 321
	p.LastDuration = 7
	p.Mu.Unlock()
	lastGood := threatIntelligenceProviderSnapshot(p)

	for index, body := range [][]byte{
		[]byte("198.51.100.61\nmalformed\n"),
		[]byte("# empty after parsing\n"),
	} {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := tm.refreshProviderAttempt(p); err == nil {
			t.Fatalf("invalid file fixture %d unexpectedly refreshed", index)
		}
		if got := threatIntelligenceProviderSnapshot(p); !reflect.DeepEqual(got, lastGood) {
			t.Fatalf("invalid file fixture %d changed last-good state: got %+v want %+v", index, got, lastGood)
		}
	}

	if err := os.WriteFile(path, []byte("2001:db8:ffff::61\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := tm.refreshProviderAttempt(p); err != nil {
		t.Fatalf("file feed recovery failed: %v", err)
	}
	recovered := threatIntelligenceProviderSnapshot(p)
	if !reflect.DeepEqual(recovered.addresses, []string{"2001:db8:ffff::61"}) || recovered.entries != 1 || recovered.lastSuccess <= 321 {
		t.Fatalf("file recovery did not remove last-good addresses: %+v", recovered)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := tm.refreshProviderAttempt(p); err == nil {
		t.Fatal("missing custom file unexpectedly refreshed")
	}
	if got := threatIntelligenceProviderSnapshot(p); !reflect.DeepEqual(got, recovered) {
		t.Fatalf("file open failure changed recovered state: got %+v want %+v", got, recovered)
	}
	if got := atomic.LoadUint64(&p.ErrorCount); got != 3 {
		t.Fatalf("file refresh errors=%d, want 3", got)
	}
}

func TestThreatIntelligenceProviderPublishesOwnedCompleteSnapshots(t *testing.T) {
	first := map[IPKey]struct{}{
		IPStrToKey("192.0.2.70"):   {},
		IPStrToKey("2001:db8::70"): {},
	}
	p := newThreatStateTestProvider("threat_intelligence_owned")
	p.Fetcher = func() (map[IPKey]struct{}, error) { return first, nil }
	tm := newThreatStateTestManager(p)
	if err := tm.refreshProviderAttempt(p); err != nil {
		t.Fatal(err)
	}

	delete(first, IPStrToKey("192.0.2.70"))
	first[IPStrToKey("198.51.100.70")] = struct{}{}
	got := threatIntelligenceProviderSnapshot(p)
	if !reflect.DeepEqual(got.addresses, []string{"192.0.2.70", "2001:db8::70"}) {
		t.Fatalf("fetcher mutated an already published snapshot: %+v", got)
	}
}

type threatIntelligenceSpamhausSnapshot struct {
	v4            []string
	v6            []string
	wideV4        []string
	wideV6        []string
	bucketV4Count int
	bucketV6Count int
	lastSuccess   float64
	duration      float64
	entries       int
}

func threatIntelligenceCIDRStrings(networks []*net.IPNet) []string {
	out := make([]string, 0, len(networks))
	for _, network := range networks {
		out = append(out, network.String())
	}
	sort.Strings(out)
	return out
}

func threatIntelligenceSpamSnapshot(tm *ThreatManager) threatIntelligenceSpamhausSnapshot {
	tm.spamMu.RLock()
	defer tm.spamMu.RUnlock()
	return threatIntelligenceSpamhausSnapshot{
		v4:            threatIntelligenceCIDRStrings(tm.spamNetsV4),
		v6:            threatIntelligenceCIDRStrings(tm.spamNetsV6),
		wideV4:        threatIntelligenceCIDRStrings(tm.spamWideV4),
		wideV6:        threatIntelligenceCIDRStrings(tm.spamWideV6),
		bucketV4Count: len(tm.spamBucketsV4),
		bucketV6Count: len(tm.spamBucketsV6),
		lastSuccess:   tm.spamLastSuccessUnix,
		duration:      tm.spamLastRefreshSeconds,
		entries:       tm.spamEntries,
	}
}

func TestThreatIntelligenceSpamhausDualFamilyLifecycleIsOneAtomicSnapshot(t *testing.T) {
	const (
		spamInitial int32 = iota
		spamPartialFailure
		spamBothHTTPFailure
		spamRecovered
		spamSingleFamily
	)
	var mode atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch mode.Load() {
		case spamInitial:
			switch request.URL.Path {
			case "/v4":
				_, _ = io.WriteString(w, "10.0.0.0/8 ; wide\n192.0.2.0/24 ; bucket\n")
			case "/v6":
				_, _ = io.WriteString(w, "3001::/16 ; wide\n2001:db8::/32 ; bucket\n")
			}
		case spamPartialFailure:
			if request.URL.Path == "/v4" {
				_, _ = io.WriteString(w, "198.51.100.0/24 ; must not publish\n")
			} else {
				_, _ = io.WriteString(w, "malformed\n")
			}
		case spamBothHTTPFailure:
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		case spamRecovered:
			if request.URL.Path == "/v4" {
				_, _ = io.WriteString(w, "198.51.100.0/24 ; replacement\n")
			} else {
				_, _ = io.WriteString(w, "2001:db8:ffff::/48 ; replacement\n")
			}
		case spamSingleFamily:
			if request.URL.Path == "/v4" {
				_, _ = io.WriteString(w, "203.0.113.0/24 ; v4 only\n")
			} else {
				_, _ = io.WriteString(w, "2001:db8:abcd::/48 ; v6 only\n")
			}
		default:
			http.Error(w, "unknown fixture", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	tm := newThreatStateTestManager()
	tm.httpClient = server.Client()
	tm.spamEnabled = true
	tm.spamURL = server.URL + "/v4"
	tm.spamV6URL = server.URL + "/v6"
	tm.refreshSpamhausList()
	initial := threatIntelligenceSpamSnapshot(tm)
	if initial.entries != 4 || initial.lastSuccess <= 0 || initial.duration < 0 ||
		!reflect.DeepEqual(initial.v4, []string{"10.0.0.0/8", "192.0.2.0/24"}) ||
		!reflect.DeepEqual(initial.v6, []string{"2001:db8::/32", "3001::/16"}) ||
		len(initial.wideV4) != 1 || len(initial.wideV6) != 1 ||
		initial.bucketV4Count != 1 || initial.bucketV6Count != 1 {
		t.Fatalf("initial Spamhaus snapshot=%+v", initial)
	}

	tm.spamMu.Lock()
	tm.spamLastSuccessUnix = 500
	tm.spamLastRefreshSeconds = 9
	tm.spamMu.Unlock()
	lastGood := threatIntelligenceSpamSnapshot(tm)

	mode.Store(spamPartialFailure)
	tm.refreshSpamhausList()
	if got := threatIntelligenceSpamSnapshot(tm); !reflect.DeepEqual(got, lastGood) {
		t.Fatalf("one-family failure partially published: got %+v want %+v", got, lastGood)
	}
	if got := atomic.LoadUint64(&tm.spamRefreshErrors); got != 1 {
		t.Fatalf("partial refresh errors=%d, want 1 failed family", got)
	}

	mode.Store(spamBothHTTPFailure)
	tm.refreshSpamhausList()
	if got := threatIntelligenceSpamSnapshot(tm); !reflect.DeepEqual(got, lastGood) {
		t.Fatalf("dual HTTP failure changed last-good state: got %+v want %+v", got, lastGood)
	}
	if got := atomic.LoadUint64(&tm.spamRefreshErrors); got != 3 {
		t.Fatalf("dual refresh errors=%d, want 3 failed family downloads", got)
	}

	mode.Store(spamRecovered)
	tm.refreshSpamhausList()
	recovered := threatIntelligenceSpamSnapshot(tm)
	if recovered.lastSuccess <= 500 || recovered.duration < 0 || recovered.entries != 2 ||
		!reflect.DeepEqual(recovered.v4, []string{"198.51.100.0/24"}) ||
		!reflect.DeepEqual(recovered.v6, []string{"2001:db8:ffff::/48"}) ||
		recovered.bucketV4Count != 1 || recovered.bucketV6Count != 1 {
		t.Fatalf("Spamhaus recovery did not atomically replace both families: %+v", recovered)
	}

	mode.Store(spamSingleFamily)
	tm.spamV6URL = ""
	tm.refreshSpamhausList()
	v4Only := threatIntelligenceSpamSnapshot(tm)
	if !reflect.DeepEqual(v4Only.v4, []string{"203.0.113.0/24"}) || len(v4Only.v6) != 0 ||
		v4Only.entries != 1 || v4Only.bucketV6Count != 0 || len(v4Only.wideV6) != 0 {
		t.Fatalf("IPv4-only success retained the old IPv6 family: %+v", v4Only)
	}

	tm.spamURL = ""
	tm.spamV6URL = server.URL + "/v6"
	tm.refreshSpamhausList()
	v6Only := threatIntelligenceSpamSnapshot(tm)
	if len(v6Only.v4) != 0 || !reflect.DeepEqual(v6Only.v6, []string{"2001:db8:abcd::/48"}) ||
		v6Only.entries != 1 || v6Only.bucketV4Count != 0 || len(v6Only.wideV4) != 0 {
		t.Fatalf("IPv6-only success retained the old IPv4 family: %+v", v6Only)
	}
	if got := atomic.LoadUint64(&tm.spamRefreshErrors); got != 3 {
		t.Fatalf("successful recovery changed cumulative errors: %d", got)
	}

	metrics := make([]prometheus.Metric, 0, 9)
	tm.collectHostThreatMetrics(&metrics)
	if len(metrics) != 9 || threatIntelligenceMetricValue(t, metrics[0]) != v6Only.lastSuccess ||
		threatIntelligenceMetricValue(t, metrics[1]) != v6Only.duration || threatIntelligenceMetricValue(t, metrics[2]) != 3 ||
		threatIntelligenceMetricValue(t, metrics[3]) != 1 {
		t.Fatalf("Spamhaus lifecycle metrics do not match the atomic snapshot: metrics=%d state=%+v", len(metrics), v6Only)
	}
	threatIntelligenceAssertThreatFeedStates(t, metrics, map[string]float64{
		"TOREXIT": -1, "TORRELAY": -1, "EMERGING": -1, "CUSTOMLIST": -1, "spamhaus": 1,
	})
}

func TestThreatIntelligenceConcurrentProviderRefreshNeverPublishesPartialSet(t *testing.T) {
	const entriesPerSnapshot = 128
	sets := [2]map[IPKey]struct{}{}
	for setIndex := range sets {
		sets[setIndex] = make(map[IPKey]struct{}, entriesPerSnapshot)
		for entry := 0; entry < entriesPerSnapshot; entry++ {
			sets[setIndex][IPStrToKey(fmt.Sprintf("198.51.%d.%d", 100+setIndex, entry+1))] = struct{}{}
		}
	}

	p := newThreatStateTestProvider("ThreatIntelligenceConcurrent")
	tm := newThreatStateTestManager(p)
	var generation atomic.Uint64
	p.Fetcher = func() (map[IPKey]struct{}, error) {
		return sets[generation.Add(1)%2], nil
	}
	if err := tm.refreshProviderAttempt(p); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	failures := make(chan string, 1)
	wg.Add(2)
	go func() {
		defer wg.Done()
		for attempt := 0; attempt < 32; attempt++ {
			if err := tm.refreshProviderAttempt(p); err != nil {
				select {
				case failures <- err.Error():
				default:
				}
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for read := 0; read < 512; read++ {
			snapshot, _ := p.SetAtomic.Load().(map[IPKey]struct{})
			if len(snapshot) != entriesPerSnapshot {
				select {
				case failures <- fmt.Sprintf("partial entry count %d", len(snapshot)):
				default:
				}
				return
			}
			family := -1
			for address := range snapshot {
				current := int(address[14]) - 100
				if family == -1 {
					family = current
				}
				if current != family || (current != 0 && current != 1) {
					select {
					case failures <- "mixed snapshot generations":
					default:
					}
					return
				}
			}
		}
	}()
	wg.Wait()
	select {
	case failure := <-failures:
		t.Fatal(failure)
	default:
	}
}
