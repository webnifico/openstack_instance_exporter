package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func TestThreatFeedRecoveryBackoffResetsAfterSuccess(t *testing.T) {
	var retry threatFeedRetry
	for i, seconds := range []int{30, 60, 120, 240, 300, 300, 300} {
		if got := retry.next(time.Hour, false); got != time.Duration(seconds)*time.Second {
			t.Fatalf("failure %d: next attempt in %s, want %ds", i+1, got, seconds)
		}
	}
	if got := retry.next(time.Hour, true); got != time.Hour {
		t.Fatalf("successful recovery changed normal refresh: %s", got)
	}
	if got := retry.next(time.Hour, false); got != 30*time.Second {
		t.Fatalf("new failure did not reset to the first retry: %s", got)
	}
	for _, refresh := range []time.Duration{0, -time.Second, 5 * time.Second, 45 * time.Second} {
		var retry threatFeedRetry
		for i := 0; i < 20; i++ {
			got := retry.next(refresh, false)
			if (refresh <= 0 && got != refresh) || (refresh > 0 && (got <= 0 || got > refresh)) {
				t.Fatalf("configured interval %s produced invalid retry %s", refresh, got)
			}
		}
	}
}

func waitThreatFeedRecovery(t *testing.T, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !ready() {
		if time.Now().After(deadline) {
			t.Fatal("feed did not reach the expected recovery state")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestThreatFeedRecoveryEveryProviderRetriesAndPreservesLastGood(t *testing.T) {
	for _, name := range []string{"TOREXIT", "TORRELAY", "EMERGING", "CUSTOMLIST", "spamhaus-v4", "spamhaus-v6", "spamhaus-dual"} {
		t.Run(name, func(t *testing.T) {
			const interval = 5 * time.Millisecond
			const endpoint = "https://feed.example.test/"
			shutdown := make(chan struct{})
			cfg := CollectorConfig{}
			path := filepath.Join(t.TempDir(), "custom-list.txt")
			switch name {
			case "TOREXIT":
				cfg.TorExit = ThreatListConfig{Enable: true, URL: endpoint + "tor", Refresh: interval}
			case "TORRELAY":
				cfg.TorRelay = ThreatListConfig{Enable: true, URL: endpoint + "tor", Refresh: interval}
			case "EMERGING":
				cfg.Emerging = ThreatListConfig{Enable: true, URL: endpoint + "ips", Refresh: interval}
			case "CUSTOMLIST":
				cfg.Custom = CustomListConfig{Enable: true, Path: path, Refresh: interval}
			default:
				cfg.Spamhaus = SpamhausConfig{Enable: true, Refresh: interval}
				if name != "spamhaus-v6" {
					cfg.Spamhaus.URLv4 = endpoint + "v4"
				}
				if name != "spamhaus-v4" {
					cfg.Spamhaus.URLv6 = endpoint + "v6"
				}
			}
			tm := newThreatManager(cfg, shutdown)
			initThreatMetrics(tm)
			var mode atomic.Int32
			tm.httpClient.Transport = threatRoundTripperFunc(func(request *http.Request) (*http.Response, error) {
				current := mode.Load()
				if current == 0 {
					return nil, context.DeadlineExceeded
				}
				body, status := "", http.StatusOK
				// On dual-family refresh, make IPv4 succeed while IPv6 fails.
				if current == 2 && !(name == "spamhaus-dual" && request.URL.Path == "/v4") {
					status = http.StatusServiceUnavailable
				} else {
					switch request.URL.Path {
					case "/tor":
						body = `{"relays":[{"or_addresses":["192.0.2.10:443"]}]}`
						if current >= 2 {
							body = `{"relays":[{"or_addresses":["198.51.100.20:443","[2001:db8::20]:9001"]}]}`
						}
					case "/ips":
						body = "192.0.2.10\n"
						if current >= 2 {
							body = "198.51.100.20\n2001:db8::20\n"
						}
					case "/v4":
						body = "192.0.2.0/24\n"
						if current >= 2 {
							body = "198.51.100.0/24\n203.0.113.0/24\n"
						}
					case "/v6":
						body = "2001:db8::/48\n"
						if current >= 2 {
							body = "2001:db8:1::/48\n2001:db8:2::/48\n"
						}
					}
				}
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)), Request: request}, nil
			})
			var provider *IPThreatProvider
			for _, candidate := range tm.Providers {
				if candidate.Enabled {
					provider = candidate
				}
			}
			failures := func() uint64 {
				if provider != nil {
					return atomic.LoadUint64(&provider.ErrorCount)
				}
				return atomic.LoadUint64(&tm.spamRefreshErrors)
			}
			entries := func() int {
				if provider != nil {
					return threatIntelligenceProviderSnapshot(provider).entries
				}
				return threatIntelligenceSpamSnapshot(tm).entries
			}
			state := func() float64 {
				var metrics []prometheus.Metric
				tm.collectHostThreatMetrics(&metrics)
				list := name
				if provider == nil {
					list = "spamhaus"
				}
				return alertValidationThreatFeedFreshValues(t, metrics)[list]
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				if provider != nil {
					tm.runProviderRefresher(provider)
				} else {
					tm.startSpamhausRefresher()
				}
			}()
			t.Cleanup(func() {
				close(shutdown)
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("refresher did not stop")
				}
			})
			waitThreatFeedRecovery(t, func() bool { return failures() >= 1 })
			if entries() != 0 || state() != 0 {
				t.Fatal("failed initial load was presented as usable")
			}
			writeCustom := func(contents string) {
				if err := os.WriteFile(path+".new", []byte(contents), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(path+".new", path); err != nil {
					t.Fatal(err)
				}
			}
			writeCustom("192.0.2.10\n")
			mode.Store(1)
			waitThreatFeedRecovery(t, func() bool { return entries() > 0 && state() == 1 })
			initialEntries := entries()
			beforeFailure := failures()
			writeCustom("malformed-address\n")
			mode.Store(2)
			waitThreatFeedRecovery(t, func() bool { return failures() > beforeFailure })
			if entries() != initialEntries || state() != 1 {
				t.Fatal("failed refresh discarded the usable snapshot or published a partial family")
			}
			// Retrying does not extend the lifetime of the last successful load.
			if provider != nil {
				provider.Mu.Lock()
				provider.LastSuccess = float64(time.Now().Add(-2 * time.Minute).Unix())
				provider.Mu.Unlock()
			} else {
				tm.spamMu.Lock()
				tm.spamLastSuccessUnix = float64(time.Now().Add(-2 * time.Minute).Unix())
				tm.spamMu.Unlock()
			}
			if entries() != initialEntries || state() != 0 {
				t.Fatal("expired retained data was presented as usable during retries")
			}
			writeCustom("198.51.100.20\n2001:db8::20\n")
			mode.Store(3)
			waitThreatFeedRecovery(t, func() bool { return entries() == 2*initialEntries && state() == 1 })
		})
	}
}

func TestThreatFeedRecoveryShutdownCancelsBackoff(t *testing.T) {
	for _, interval := range []time.Duration{time.Hour, 0} {
		t.Run(interval.String(), func(t *testing.T) {
			tm := newThreatStateTestManager()
			called, done := make(chan struct{}), make(chan struct{})
			var attempts atomic.Int32
			go func() {
				defer close(done)
				tm.runThreatFeedRefresher(interval, func() bool {
					if attempts.Add(1) == 1 {
						close(called)
					}
					return false
				})
			}()
			<-called
			close(tm.shutdownChan)
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("shutdown waited for the retry delay")
			}
			if attempts.Load() != 1 {
				t.Fatal("refresh ran again after shutdown")
			}
		})
	}
}

func TestThreatFeedRecoveryHTTPDiagnosticsRetainCausesWithoutSecrets(t *testing.T) {
	certificate := &x509.Certificate{}
	for _, tc := range []struct {
		name, want string
		cause      error
	}{
		{"timeout", "timed out", context.DeadlineExceeded},
		{"dns-timeout", "timed out", &net.DNSError{Err: "private-detail", IsTimeout: true}},
		{"cancel", "canceled", context.Canceled},
		{"dns-not-found", "DNS name not found", &net.DNSError{Err: "private-detail", Name: "secret.example", IsNotFound: true}},
		{"dns", "DNS lookup failed", &net.DNSError{Err: "private-detail"}},
		{"tls-authority", "authority is not trusted", x509.UnknownAuthorityError{Cert: certificate}},
		{"tls-name", "hostname mismatch", x509.HostnameError{Certificate: certificate, Host: "secret.example"}},
		{"tls-time", "expired or not yet valid", x509.CertificateInvalidError{Cert: certificate, Reason: x509.Expired}},
		{"tls-invalid", "validation failed", x509.CertificateInvalidError{Cert: certificate, Reason: x509.IncompatibleUsage}},
		{"tls-roots", "trust store unavailable", x509.SystemRootsError{Err: errors.New("private-detail")}},
		{"tls-handshake", "handshake received an invalid response", tls.RecordHeaderError{Msg: "private-detail"}},
		{"refused", "connection refused", &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}},
		{"reset", "connection reset", syscall.ECONNRESET},
		{"network-unreachable", "network or host unreachable", syscall.ENETUNREACH},
		{"host-unreachable", "network or host unreachable", syscall.EHOSTUNREACH},
		{"body-truncated", "closed before response completed", io.ErrUnexpectedEOF},
		{"connection-closed", "closed before response completed", io.EOF},
		{"other", "request failed", errors.New("private-detail")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, bodyFailure := range []bool{false, true} {
				client := &http.Client{Transport: threatRoundTripperFunc(func(request *http.Request) (*http.Response, error) {
					cause := fmt.Errorf("proxy credential=private-detail url=%s: %w", request.URL.String(), tc.cause)
					if !bodyFailure {
						return nil, cause
					}
					return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(threatErrorReader{err: cause}), ContentLength: -1, Request: request}, nil
				})}
				tm := &ThreatManager{httpClient: client}
				_, err := tm.fetchHTTPBytes("https://secret.example/feed?token=private-detail", 1024)
				if err == nil || !strings.Contains(err.Error(), tc.want) || !errors.Is(err, tc.cause) {
					t.Fatalf("body=%t: diagnostic %v, want %q with preserved cause", bodyFailure, err, tc.want)
				}
				for _, secret := range []string{"private-detail", "secret.example", "credential=", "token="} {
					if strings.Contains(err.Error(), secret) {
						t.Fatalf("diagnostic exposed %q: %v", secret, err)
					}
				}
			}
		})
	}
}
