package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestMetricsScrapeCompressionPreservesSamples(t *testing.T) {
	registry := prometheus.NewRegistry()
	counter := prometheus.NewCounter(prometheus.CounterOpts{Name: "oie_test_scrape_total", Help: "Scrape compatibility fixture."})
	registry.MustRegister(counter)
	counter.Add(42)
	handler := newMetricsHTTPHandler(registry)
	want := []byte("# HELP oie_test_scrape_total Scrape compatibility fixture.\n# TYPE oie_test_scrape_total counter\noie_test_scrape_total 42\n")
	for _, tc := range []struct{ name, accept, encoding string }{
		{"plain", "", ""},
		{"gzip", "gzip", "gzip"},
		{"zstd", "zstd", "zstd"},
		{"preferred_zstd", "zstd;q=1, gzip;q=0.5", "zstd"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
			request.Header.Set("Accept", "text/plain; version=0.0.4")
			request.Header.Set("Accept-Encoding", tc.accept)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusOK || response.Header().Get("Content-Encoding") != tc.encoding {
				t.Fatalf("scrape status/encoding = %d/%q, want 200/%q", response.Code, response.Header().Get("Content-Encoding"), tc.encoding)
			}
			var reader io.Reader = response.Body
			switch tc.encoding {
			case "gzip":
				decoded, err := gzip.NewReader(response.Body)
				if err != nil {
					t.Fatal(err)
				}
				defer decoded.Close()
				reader = decoded
			case "zstd":
				decoded, err := zstd.NewReader(response.Body)
				if err != nil {
					t.Fatal(err)
				}
				defer decoded.Close()
				reader = decoded
			}
			body, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(body, want) {
				t.Fatalf("decoded scrape = %q, want %q", body, want)
			}
		})
	}
}

type blockingMetricsGatherer struct {
	started chan struct{}
	release <-chan struct{}
}

type failingMetricsGatherer struct{}

func (failingMetricsGatherer) Gather() ([]*dto.MetricFamily, error) {
	return nil, errors.New("gather failed")
}

type panicOnceMetricsGatherer struct {
	panicked bool
}

func (g *panicOnceMetricsGatherer) Gather() ([]*dto.MetricFamily, error) {
	if !g.panicked {
		g.panicked = true
		panic("gather panic")
	}
	return nil, nil
}

func (g *blockingMetricsGatherer) Gather() ([]*dto.MetricFamily, error) {
	g.started <- struct{}{}
	<-g.release
	return nil, nil
}

func TestRuntimeConfigurationHTTPServerHasExplicitProductionLimits(t *testing.T) {
	handler := http.NewServeMux()
	srv := newExporterHTTPServer("127.0.0.1:12345", handler)

	if srv.Addr != "127.0.0.1:12345" || srv.Handler != handler {
		t.Fatalf("server address/handler = (%q, %p), want configured values", srv.Addr, srv.Handler)
	}
	if srv.ReadHeaderTimeout != defaultHTTPReadHeaderTimeout {
		t.Fatalf("ReadHeaderTimeout = %s, want %s", srv.ReadHeaderTimeout, defaultHTTPReadHeaderTimeout)
	}
	if srv.IdleTimeout != defaultHTTPIdleTimeout {
		t.Fatalf("IdleTimeout = %s, want %s", srv.IdleTimeout, defaultHTTPIdleTimeout)
	}
	if srv.MaxHeaderBytes != defaultHTTPMaxHeaderBytes {
		t.Fatalf("MaxHeaderBytes = %d, want %d", srv.MaxHeaderBytes, defaultHTTPMaxHeaderBytes)
	}
	if srv.WriteTimeout != 0 {
		t.Fatalf("WriteTimeout = %s, want zero so valid large/slow scrapes are not truncated", srv.WriteTimeout)
	}
}

func TestRuntimeConfigurationMetricsConcurrencyLimitRejectsSaturationAndReleasesSlots(t *testing.T) {
	release := make(chan struct{})
	gatherer := &blockingMetricsGatherer{
		started: make(chan struct{}, maximumConcurrentMetricsRequests+1),
		release: release,
	}
	handler := newMetricsHTTPHandler(gatherer)

	statuses := make(chan int, maximumConcurrentMetricsRequests)
	var requests sync.WaitGroup
	for range maximumConcurrentMetricsRequests {
		requests.Add(1)
		go func() {
			defer requests.Done()
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
			statuses <- recorder.Code
		}()
	}
	for range maximumConcurrentMetricsRequests {
		select {
		case <-gatherer.started:
		case <-time.After(time.Second):
			t.Fatal("metrics request did not occupy its in-flight slot")
		}
	}

	overflow := httptest.NewRecorder()
	handler.ServeHTTP(overflow, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if overflow.Code != http.StatusServiceUnavailable {
		t.Fatalf("saturated metrics status = %d, want %d", overflow.Code, http.StatusServiceUnavailable)
	}
	if !strings.Contains(overflow.Body.String(), "Limit of concurrent requests reached") {
		t.Fatalf("saturated metrics response = %q, want explicit limit message", overflow.Body.String())
	}

	close(release)
	requests.Wait()
	close(statuses)
	for status := range statuses {
		if status != http.StatusOK {
			t.Fatalf("admitted metrics status = %d, want %d", status, http.StatusOK)
		}
	}

	afterRelease := httptest.NewRecorder()
	handler.ServeHTTP(afterRelease, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if afterRelease.Code != http.StatusOK {
		t.Fatalf("metrics status after slot release = %d, want %d", afterRelease.Code, http.StatusOK)
	}
}

func TestRuntimeConfigurationMetricsConcurrencySlotSurvivesGatherFailureAndPanic(t *testing.T) {
	failingHandler := newMetricsHTTPHandler(failingMetricsGatherer{})
	for i := range maximumConcurrentMetricsRequests + 1 {
		recorder := httptest.NewRecorder()
		failingHandler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		if recorder.Code != http.StatusInternalServerError {
			t.Fatalf("failing gather %d status = %d, want %d (a 503 would indicate a leaked slot)", i, recorder.Code, http.StatusInternalServerError)
		}
	}

	panicGatherer := &panicOnceMetricsGatherer{}
	panicHandler := newMetricsHTTPHandler(panicGatherer)
	func() {
		defer func() {
			if recovered := recover(); recovered == nil {
				t.Fatal("gather panic was not propagated")
			}
		}()
		panicHandler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/metrics", nil))
	}()
	recorder := httptest.NewRecorder()
	panicHandler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("metrics status after gather panic = %d, want %d (a 503 would indicate a leaked slot)", recorder.Code, http.StatusOK)
	}
}

func TestRuntimeConfigurationMetricsRequestBodyCannotOccupyGatherSlot(t *testing.T) {
	release := make(chan struct{})
	gatherer := &blockingMetricsGatherer{
		started: make(chan struct{}, 1),
		release: release,
	}
	handler := newMetricsHTTPHandler(gatherer)

	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/metrics", strings.NewReader("x")),
		func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
			r.ContentLength = -1
			r.TransferEncoding = []string{"chunked"}
			return r
		}(),
	} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("body-bearing metrics status = %d, want %d", recorder.Code, http.StatusBadRequest)
		}
		if !request.Close {
			t.Fatal("body-bearing metrics request did not request connection close")
		}
		select {
		case <-gatherer.started:
			t.Fatal("body-bearing metrics request reached the gatherer")
		default:
		}
	}

	result := make(chan int, 1)
	go func() {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		result <- recorder.Code
	}()
	select {
	case <-gatherer.started:
	case <-time.After(time.Second):
		t.Fatal("normal bodyless scrape did not reach the gatherer")
	}
	close(release)
	if status := <-result; status != http.StatusOK {
		t.Fatalf("normal bodyless scrape status = %d, want %d", status, http.StatusOK)
	}
}

func TestRuntimeConfigurationHTTPServerRejectsOversizedRequestHeaders(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	srv := newExporterHTTPServer(ln.Addr().String(), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	errCh := make(chan error, 1)
	go func() { errCh <- serveHTTPUntilShutdown(ctx, srv, ln, time.Second) }()

	request, err := http.NewRequest(http.MethodGet, "http://"+ln.Addr().String(), nil)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	request.Header.Set("X-Oversized", strings.Repeat("x", defaultHTTPMaxHeaderBytes+(8<<10)))
	client := &http.Client{Timeout: time.Second}
	resp, err := client.Do(request)
	if err != nil {
		cancel()
		t.Fatalf("oversized-header request failed before receiving server response: %v", err)
	}
	_, readErr := io.Copy(io.Discard, resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil || closeErr != nil {
		cancel()
		t.Fatalf("oversized-header response read/close = (%v, %v)", readErr, closeErr)
	}
	if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		cancel()
		t.Fatalf("oversized-header status = %d, want %d", resp.StatusCode, http.StatusRequestHeaderFieldsTooLarge)
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("server shutdown after oversized header: %v", err)
	}
}

func TestRuntimeConfigurationHTTPReadHeaderTimeoutClosesIncompleteRequest(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	srv := newExporterHTTPServer(ln.Addr().String(), http.NotFoundHandler())
	const testTimeout = 30 * time.Millisecond
	srv.ReadHeaderTimeout = testTimeout
	errCh := make(chan error, 1)
	go func() { errCh <- serveHTTPUntilShutdown(ctx, srv, ln, time.Second) }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "GET /metrics HTTP/1.1\r\nHost: exporter\r\nX-Incomplete:"); err != nil {
		cancel()
		t.Fatal(err)
	}
	started := time.Now()
	if err := conn.SetReadDeadline(started.Add(time.Second)); err != nil {
		cancel()
		t.Fatal(err)
	}
	_, readErr := io.ReadAll(conn)
	if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
		cancel()
		t.Fatal("incomplete request remained open beyond the read-header deadline")
	}
	if elapsed := time.Since(started); elapsed < testTimeout/2 {
		cancel()
		t.Fatalf("incomplete request closed after %s, before the %s read-header timeout", elapsed, testTimeout)
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("server shutdown after read-header timeout: %v", err)
	}
}

func TestRuntimeConfigurationHTTPIdleTimeoutClosesKeepAliveConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	srv := newExporterHTTPServer(ln.Addr().String(), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	const testTimeout = 30 * time.Millisecond
	srv.IdleTimeout = testTimeout
	errCh := make(chan error, 1)
	go func() { errCh <- serveHTTPUntilShutdown(ctx, srv, ln, time.Second) }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)
	if _, err := fmt.Fprintf(conn, "GET /metrics HTTP/1.1\r\nHost: %s\r\n\r\n", ln.Addr().String()); err != nil {
		cancel()
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	_, readErr := io.Copy(io.Discard, resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil || closeErr != nil || resp.StatusCode != http.StatusOK {
		cancel()
		t.Fatalf("initial keep-alive response = (status %d, read %v, close %v)", resp.StatusCode, readErr, closeErr)
	}

	time.Sleep(4 * testTimeout)
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		cancel()
		t.Fatal(err)
	}
	_, _ = fmt.Fprintf(conn, "GET /metrics HTTP/1.1\r\nHost: %s\r\n\r\n", ln.Addr().String())
	if second, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet}); err == nil {
		_ = second.Body.Close()
		cancel()
		t.Fatal("idle keep-alive connection accepted another request after its deadline")
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("server shutdown after idle timeout: %v", err)
	}
}

func TestRuntimeConfigurationHTTPServerAllowsLargeSlowMetricsResponse(t *testing.T) {
	var payload strings.Builder
	for i := range 20000 {
		fmt.Fprintf(&payload, "oie_http_test_large_metric{series=%q} %d\n", fmt.Sprint(i), i)
	}
	want := payload.String()

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("HTTP response writer does not support flushing")
			return
		}
		for offset := 0; offset < len(want); offset += 16 << 10 {
			end := min(offset+(16<<10), len(want))
			if _, err := io.WriteString(w, want[offset:end]); err != nil {
				return
			}
			flusher.Flush()
			time.Sleep(time.Millisecond)
		}
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	srv := newExporterHTTPServer(ln.Addr().String(), handler)
	errCh := make(chan error, 1)
	go func() { errCh <- serveHTTPUntilShutdown(ctx, srv, ln, time.Second) }()

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + ln.Addr().String() + "/metrics")
	if err != nil {
		cancel()
		t.Fatalf("large/slow metrics request failed: %v", err)
	}
	got, readErr := io.ReadAll(resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil || closeErr != nil {
		cancel()
		t.Fatalf("large/slow metrics response read/close = (%v, %v)", readErr, closeErr)
	}
	if resp.StatusCode != http.StatusOK || string(got) != want {
		cancel()
		t.Fatalf("large/slow metrics response = (status %d, %d bytes), want (status %d, %d bytes)", resp.StatusCode, len(got), http.StatusOK, len(want))
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("server shutdown after large/slow response: %v", err)
	}
}

func TestRuntimeConfigurationHTTPShutdownDrainsInFlightRequest(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	handlerFinished := make(chan struct{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		_, _ = io.WriteString(w, "drained")
		close(handlerFinished)
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	srv := newExporterHTTPServer(ln.Addr().String(), handler)
	serverErr := make(chan error, 1)
	go func() { serverErr <- serveHTTPUntilShutdown(ctx, srv, ln, time.Second) }()

	clientResult := make(chan error, 1)
	go func() {
		resp, requestErr := http.Get("http://" + ln.Addr().String())
		if requestErr != nil {
			clientResult <- requestErr
			return
		}
		body, readErr := io.ReadAll(resp.Body)
		closeErr := resp.Body.Close()
		if readErr != nil || closeErr != nil || resp.StatusCode != http.StatusOK || string(body) != "drained" {
			clientResult <- fmt.Errorf("response = (status %d, body %q, read %v, close %v)", resp.StatusCode, body, readErr, closeErr)
			return
		}
		clientResult <- nil
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("in-flight request did not start")
	}
	cancel()
	close(release)
	if err := <-clientResult; err != nil {
		t.Fatalf("in-flight request was not drained: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("graceful HTTP shutdown failed: %v", err)
	}
	select {
	case <-handlerFinished:
	default:
		t.Fatal("server returned before in-flight handler completed")
	}
}

func TestRuntimeConfigurationHTTPShutdownForceClosesAfterDeadline(t *testing.T) {
	started := make(chan struct{})
	requestCanceled := make(chan struct{})
	handler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(requestCanceled)
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	srv := newExporterHTTPServer(ln.Addr().String(), handler)
	serverErr := make(chan error, 1)
	go func() { serverErr <- serveHTTPUntilShutdown(ctx, srv, ln, 30*time.Millisecond) }()
	clientResult := make(chan error, 1)
	go func() {
		resp, requestErr := http.Get("http://" + ln.Addr().String())
		if requestErr == nil {
			_, requestErr = io.ReadAll(resp.Body)
			_ = resp.Body.Close()
		}
		clientResult <- requestErr
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("blocking request did not start")
	}
	cancel()
	select {
	case err := <-serverErr:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("forced shutdown error = %v, want deadline exceeded", err)
		}
	case <-time.After(time.Second):
		t.Fatal("forced shutdown exceeded its bound")
	}
	select {
	case <-requestCanceled:
	case <-time.After(time.Second):
		t.Fatal("forced close did not cancel the active request")
	}
	select {
	case err := <-clientResult:
		if err == nil {
			t.Fatal("forced close unexpectedly delivered a complete response")
		}
	case <-time.After(time.Second):
		t.Fatal("forced close left the client request blocked")
	}
}
