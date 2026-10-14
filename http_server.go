package main

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	// Preserve the zstd scrape support previously enabled by client_golang.
	_ "github.com/prometheus/client_golang/prometheus/promhttp/zstd"
)

const (
	defaultHTTPReadHeaderTimeout     = 10 * time.Second
	defaultHTTPIdleTimeout           = 2 * time.Minute
	defaultHTTPMaxHeaderBytes        = 32 << 10
	maximumConcurrentMetricsRequests = 4
	defaultHTTPShutdownTimeout       = 10 * time.Second
)

func newMetricsHTTPHandler(gatherer prometheus.Gatherer) http.Handler {
	metrics := promhttp.HandlerFor(gatherer, promhttp.HandlerOpts{
		MaxRequestsInFlight: maximumConcurrentMetricsRequests,
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prometheus scrapes do not carry request bodies. Reject a declared body
		// before it can consume a bounded gather slot while the client withholds
		// the body bytes indefinitely.
		if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
			r.Close = true
			http.Error(w, "metrics requests must not include a body", http.StatusBadRequest)
			return
		}
		metrics.ServeHTTP(w, r)
	})
}

func newExporterHTTPServer(address string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: defaultHTTPReadHeaderTimeout,
		IdleTimeout:       defaultHTTPIdleTimeout,
		MaxHeaderBytes:    defaultHTTPMaxHeaderBytes,
		// A metrics response can legitimately be large or slow. The bounded
		// in-flight limit protects the exporter without aborting valid scrapes.
		WriteTimeout: 0,
	}
}
