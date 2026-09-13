package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

type threatRoundTripperFunc func(*http.Request) (*http.Response, error)

func (f threatRoundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type threatErrorReader struct {
	err error
}

func (r threatErrorReader) Read([]byte) (int, error) {
	return 0, r.err
}

func TestThreatLineFeedRejectsEmptyAndMalformedInput(t *testing.T) {
	for _, input := range []string{"", "# comments only\n", "not-an-ip\n", "192.0.2.1\nnot-an-ip\n"} {
		if _, err := scanIPLines(strings.NewReader(input)); err == nil {
			t.Fatalf("scanIPLines(%q) unexpectedly succeeded", input)
		}
	}

	got, err := scanIPLines(strings.NewReader("# feed\n192.0.2.1\n2001:db8::1\n"))
	if err != nil {
		t.Fatalf("valid feed failed: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("valid feed entries = %d, want 2", len(got))
	}
}

func TestThreatLineFeedValidatesAddressZoneSyntax(t *testing.T) {
	for _, input := range []string{
		"192.0.2.1%eth0\n",
		"192.0.2.1%\n",
		"2001:db8::1%\n",
	} {
		if _, err := scanIPLines(strings.NewReader(input)); err == nil {
			t.Fatalf("scanIPLines(%q) accepted a malformed address suffix", input)
		}
	}

	got, err := scanIPLines(strings.NewReader("fe80::1%eth0\n"))
	if err != nil {
		t.Fatalf("valid scoped IPv6 address failed: %v", err)
	}
	if _, ok := got[IPStrToKey("fe80::1")]; !ok || len(got) != 1 {
		t.Fatalf("scoped IPv6 address was not normalized: %#v", got)
	}
}

func TestSpamhausPartialFamilyRefreshPreservesWholeLastGoodFeed(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("malformed\n"))
	}))
	defer bad.Close()
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("2001:db8::/32 ; DROPv6\n"))
	}))
	defer good.Close()

	_, oldV4, _ := net.ParseCIDR("192.0.2.0/24")
	_, oldV6, _ := net.ParseCIDR("2001:db8:ffff::/48")
	tm := &ThreatManager{
		httpClient:             good.Client(),
		spamURL:                bad.URL,
		spamV6URL:              good.URL,
		spamNetsV4:             []*net.IPNet{oldV4},
		spamNetsV6:             []*net.IPNet{oldV6},
		spamLastSuccessUnix:    123,
		spamLastRefreshSeconds: 4,
		spamEntries:            2,
	}
	tm.refreshSpamhausList()

	if tm.spamLastSuccessUnix != 123 || tm.spamLastRefreshSeconds != 4 {
		t.Fatalf("partial refresh advanced success state: timestamp=%v duration=%v", tm.spamLastSuccessUnix, tm.spamLastRefreshSeconds)
	}
	if len(tm.spamNetsV4) != 1 || tm.spamNetsV4[0].String() != oldV4.String() || len(tm.spamNetsV6) != 1 || tm.spamNetsV6[0].String() != oldV6.String() {
		t.Fatalf("partial refresh replaced last-good feed: v4=%v v6=%v", tm.spamNetsV4, tm.spamNetsV6)
	}
}

func TestSpamhausFeedRejectsEmptyAndMalformedInput(t *testing.T) {
	for _, input := range []string{"", "# comments only\n", "bad-cidr\n", "192.0.2.0/24 ; SBL\nbad-cidr\n"} {
		if _, err := parseSpamhausCIDRs(strings.NewReader(input)); err == nil {
			t.Fatalf("parseSpamhausCIDRs(%q) unexpectedly succeeded", input)
		}
	}

	nets, err := parseSpamhausCIDRs(strings.NewReader("192.0.2.0/24 ; SBL\n2001:db8::/32 ; DROPv6\n"))
	if err != nil || len(nets) != 2 {
		t.Fatalf("valid Spamhaus feed = %d entries, err %v", len(nets), err)
	}
}

func TestProviderRefreshPreservesLastGoodSet(t *testing.T) {
	old := map[IPKey]struct{}{IPStrToKey("192.0.2.7"): {}}
	p := &IPThreatProvider{
		Name:            "test",
		RefreshInterval: time.Minute,
		Set:             old,
		Fetcher: func() (map[IPKey]struct{}, error) {
			return map[IPKey]struct{}{}, nil
		},
	}
	p.SetAtomic.Store(old)
	tm := &ThreatManager{}
	if err := tm.refreshProviderOnce(p); err == nil {
		t.Fatal("empty refresh unexpectedly succeeded")
	}
	got, _ := p.SetAtomic.Load().(map[IPKey]struct{})
	if len(got) != 1 {
		t.Fatalf("last-good set was replaced: %#v", got)
	}
	if p.LastSuccess != 0 || p.EntryCount != 0 {
		t.Fatalf("failed refresh changed success state: timestamp=%v entries=%d", p.LastSuccess, p.EntryCount)
	}
}

func TestThreatIPSetRejectsIPv4AndIPv6UnspecifiedAddresses(t *testing.T) {
	for _, raw := range []string{"0.0.0.0", "::"} {
		if err := validateThreatIPSet(map[IPKey]struct{}{IPStrToKey(raw): {}}); err == nil {
			t.Fatalf("unspecified threat address %s unexpectedly accepted", raw)
		}
	}
}

func TestSpamhausWrongFamilyRefreshPreservesWholeLastGoodFeed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v4":
			_, _ = w.Write([]byte("2001:db8::/32 ; wrong family\n"))
		case "/v6":
			_, _ = w.Write([]byte("192.0.2.0/24 ; wrong family\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	_, oldV4, _ := net.ParseCIDR("198.51.100.0/24")
	_, oldV6, _ := net.ParseCIDR("2001:db8:ffff::/48")
	tm := &ThreatManager{
		httpClient:             server.Client(),
		spamURL:                server.URL + "/v4",
		spamV6URL:              server.URL + "/v6",
		spamNetsV4:             []*net.IPNet{oldV4},
		spamNetsV6:             []*net.IPNet{oldV6},
		spamLastSuccessUnix:    123,
		spamLastRefreshSeconds: 4,
		spamEntries:            2,
	}
	tm.refreshSpamhausList()

	if tm.spamLastSuccessUnix != 123 || tm.spamLastRefreshSeconds != 4 {
		t.Fatalf("wrong-family refresh advanced success state: timestamp=%v duration=%v", tm.spamLastSuccessUnix, tm.spamLastRefreshSeconds)
	}
	if len(tm.spamNetsV4) != 1 || tm.spamNetsV4[0].String() != oldV4.String() ||
		len(tm.spamNetsV6) != 1 || tm.spamNetsV6[0].String() != oldV6.String() {
		t.Fatalf("wrong-family refresh replaced last-good feed: v4=%v v6=%v", tm.spamNetsV4, tm.spamNetsV6)
	}
}

func TestSpamhausCatchAllRefreshPreservesWholeLastGoodFeed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v4":
			_, _ = w.Write([]byte("0.0.0.0/0 ; unusable catch-all\n"))
		case "/v6":
			_, _ = w.Write([]byte("::/0 ; unusable catch-all\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	_, oldV4, _ := net.ParseCIDR("198.51.100.0/24")
	_, oldV6, _ := net.ParseCIDR("2001:db8:ffff::/48")
	tm := &ThreatManager{
		httpClient:             server.Client(),
		spamURL:                server.URL + "/v4",
		spamV6URL:              server.URL + "/v6",
		spamNetsV4:             []*net.IPNet{oldV4},
		spamNetsV6:             []*net.IPNet{oldV6},
		spamLastSuccessUnix:    123,
		spamLastRefreshSeconds: 4,
		spamEntries:            2,
	}
	tm.refreshSpamhausList()

	if tm.spamLastSuccessUnix != 123 || tm.spamLastRefreshSeconds != 4 {
		t.Fatalf("catch-all refresh advanced success state: timestamp=%v duration=%v", tm.spamLastSuccessUnix, tm.spamLastRefreshSeconds)
	}
	if len(tm.spamNetsV4) != 1 || tm.spamNetsV4[0].String() != oldV4.String() ||
		len(tm.spamNetsV6) != 1 || tm.spamNetsV6[0].String() != oldV6.String() {
		t.Fatalf("catch-all refresh replaced last-good feed: v4=%v v6=%v", tm.spamNetsV4, tm.spamNetsV6)
	}
}

func TestThreatHTTPFetchIsSizeBounded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "999999999")
		_, _ = io.Copy(w, bytes.NewBufferString("192.0.2.1\n"))
	}))
	defer server.Close()

	tm := &ThreatManager{httpClient: server.Client()}
	if _, err := tm.fetchURLLines(server.URL); err == nil {
		t.Fatal("oversized response declaration unexpectedly accepted")
	}
}

func TestThreatHTTPStatusErrorDoesNotExposeURLQuery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	const secret = "super-secret-feed-token"
	tm := &ThreatManager{httpClient: server.Client()}
	_, err := tm.fetchURLLines(server.URL + "/feed?token=" + secret)
	if err == nil {
		t.Fatal("non-success response unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("HTTP status error exposed configured URL query: %v", err)
	}
}

func TestThreatHTTPRequestErrorDoesNotExposeURLQuery(t *testing.T) {
	client := &http.Client{Transport: threatRoundTripperFunc(func(request *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("proxy rejected %s: %w", request.URL.String(), io.ErrUnexpectedEOF)
	})}

	const secret = "super-secret-feed-token"
	tm := &ThreatManager{httpClient: client}
	_, err := tm.fetchURLLines("https://feed.example.test/list?token=" + secret)
	if err == nil {
		t.Fatal("failed threat request unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("HTTP request error exposed configured URL query: %v", err)
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("redacted request error did not preserve its cause: %v", err)
	}
}

func TestThreatHTTPBodyErrorDoesNotExposeURLQuery(t *testing.T) {
	client := &http.Client{Transport: threatRoundTripperFunc(func(request *http.Request) (*http.Response, error) {
		bodyErr := fmt.Errorf("proxy body failed for %s: %w", request.URL.String(), io.ErrUnexpectedEOF)
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     make(http.Header),
			Body:       io.NopCloser(threatErrorReader{err: bodyErr}),
			Request:    request,
		}, nil
	})}

	const secret = "super-secret-feed-token"
	tm := &ThreatManager{httpClient: client}
	_, err := tm.fetchURLLines("https://feed.example.test/list?token=" + secret)
	if err == nil {
		t.Fatal("failed threat response body unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("HTTP response body error exposed configured URL query: %v", err)
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("redacted response body error did not preserve its cause: %v", err)
	}
}

func TestThreatFileBoundedReadRejectsTruncatedValidPrefix(t *testing.T) {
	validPrefix := "192.0.2.1\n"
	input := validPrefix + "\n198.51.100.2\n"
	if _, err := readBoundedThreatFile(strings.NewReader(input), int64(len(validPrefix))); err == nil {
		t.Fatal("bounded file read accepted a valid-looking truncated prefix from an oversized file")
	}
}

func TestThreatFileFetcherRejectsFIFOWithoutBlocking(t *testing.T) {
	path := t.TempDir() + "/feed.fifo"
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := (&ThreatManager{}).fetchFileLines(path)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO threat feed unexpectedly succeeded")
		}
	case <-time.After(2 * time.Second):
		// Unblock the pre-fix os.Open so the regression test does not leak a
		// permanently blocked goroutine when demonstrating the failure.
		writer, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err == nil {
			_ = writer.Close()
		}
		t.Fatal("FIFO threat feed blocked during open")
	}
}

func TestThreatFileStableReadRejectsShrinkAfterStat(t *testing.T) {
	path := t.TempDir() + "/feed.txt"
	original := []byte("192.0.2.1\n198.51.100.2\n")
	validPrefix := []byte("192.0.2.1\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	initial, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, int64(len(validPrefix))); err != nil {
		t.Fatal(err)
	}
	if _, err := readStableThreatFile(f, initial, threatLineFeedMaxBytes); err == nil {
		t.Fatal("stable file read accepted a valid partial prefix after the open file shrank")
	}
}

func TestThreatFileStableReadAllowsAtomicReplacement(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/feed.txt"
	replacement := dir + "/replacement.txt"
	original := []byte("192.0.2.1\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	initial, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(replacement, []byte("198.51.100.2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	body, err := readStableThreatFile(f, initial, threatLineFeedMaxBytes)
	if err != nil {
		t.Fatalf("atomic replacement invalidated already-open stable feed: %v", err)
	}
	if !bytes.Equal(body, original) {
		t.Fatalf("atomic replacement changed already-open feed contents: got %q want %q", body, original)
	}
}

func TestThreatFeedFreshnessValidation(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	if threatFeedFresh(0, time.Hour, now) {
		t.Fatal("never-loaded feed reported fresh")
	}
	if !threatFeedFresh(float64(now.Add(-90*time.Minute).Unix()), time.Hour, now) {
		t.Fatal("valid feed inside two refresh intervals reported stale")
	}
	if threatFeedFresh(float64(now.Add(-3*time.Hour).Unix()), time.Hour, now) {
		t.Fatal("feed older than two refresh intervals reported fresh")
	}
	if threatFeedFresh(float64(now.Add(10*time.Minute).Unix()), time.Hour, now) {
		t.Fatal("feed timestamp too far in the future reported fresh")
	}
	if !threatFeedFresh(float64(now.Add(-30*24*time.Hour).Unix()), 0, now) {
		t.Fatal("one-shot static feed should remain fresh after a successful load")
	}
}

func TestThreatFeedFreshnessDoesNotOverflowLargeRefreshInterval(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	refresh := time.Duration(1 << 62)
	lastSuccess := float64(now.Add(-24 * time.Hour).Unix())
	if !threatFeedFresh(lastSuccess, refresh, now) {
		t.Fatal("large refresh interval overflowed and made a recent successful feed stale")
	}
}

func TestOnionooRejectsStructurallyValidEmptyFeed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"relays":[]}`))
	}))
	defer server.Close()
	tm := &ThreatManager{httpClient: server.Client()}
	if _, err := tm.fetchOnionoo(server.URL); err == nil {
		t.Fatal("empty Onionoo response unexpectedly accepted")
	}
}

func TestOnionooRejectsMixedValidAndMalformedAddresses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"relays":[{"or_addresses":["192.0.2.3:9001","not-an-address"]}]}`))
	}))
	defer server.Close()

	tm := &ThreatManager{httpClient: server.Client()}
	if got, err := tm.fetchOnionoo(server.URL); err == nil {
		t.Fatalf("mixed valid/malformed Onionoo response unexpectedly succeeded with %d partial entries", len(got))
	}
}
