package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestHTTPListenerBindFailureIsReturned(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()

	if _, err := listenForHTTP(occupied.Addr().String()); err == nil {
		t.Fatal("bind failure was not returned")
	}
}

func TestHTTPServerStartsAndShutsDownGracefully(t *testing.T) {
	ln, err := listenForHTTP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})}
	errCh := make(chan error, 1)
	go func() { errCh <- serveHTTPUntilShutdown(ctx, srv, ln, time.Second) }()

	resp, err := http.Get("http://" + ln.Addr().String())
	if err != nil {
		cancel()
		t.Fatalf("server did not start: %v", err)
	}
	_ = resp.Body.Close()
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("graceful shutdown failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("graceful shutdown did not complete")
	}
}

func TestHTTPShutdownIsBounded(t *testing.T) {
	ln, err := listenForHTTP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
	})}
	errCh := make(chan error, 1)
	go func() { errCh <- serveHTTPUntilShutdown(ctx, srv, ln, 30*time.Millisecond) }()
	go func() { _, _ = http.Get("http://" + ln.Addr().String()) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("blocking request did not start")
	}
	cancel()
	select {
	case err := <-errCh:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("bounded shutdown error = %v, want deadline exceeded", err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown exceeded its bound")
	}
	close(release)
}
