package main

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func TestConcurrentFirstScrapesShareOneCollection(t *testing.T) {
	var calls atomic.Int32
	desc := prometheus.NewDesc("test_concurrent_first_scrape", "test", nil, nil)
	mc := &MetricsCollector{
		shutdownChan:       make(chan struct{}),
		collectionInterval: time.Hour,
		collectionRunner: func() []prometheus.Metric {
			calls.Add(1)
			time.Sleep(20 * time.Millisecond)
			return []prometheus.Metric{prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, 1)}
		},
	}
	defer close(mc.shutdownChan)

	const scrapes = 24
	var wg sync.WaitGroup
	wg.Add(scrapes)
	for i := 0; i < scrapes; i++ {
		go func() {
			defer wg.Done()
			ch := make(chan prometheus.Metric, 1)
			mc.Collect(ch)
			if len(ch) != 1 {
				t.Errorf("scrape emitted %d metrics, want 1", len(ch))
			}
		}()
	}
	wg.Wait()
	if got := calls.Load(); got != 1 {
		t.Fatalf("collection calls = %d, want 1", got)
	}
}

func TestEmptyFirstCollectionIsStillCached(t *testing.T) {
	var calls atomic.Int32
	mc := &MetricsCollector{
		shutdownChan:       make(chan struct{}),
		collectionInterval: time.Hour,
		collectionRunner: func() []prometheus.Metric {
			calls.Add(1)
			return nil
		},
	}
	defer close(mc.shutdownChan)

	for i := 0; i < 3; i++ {
		mc.Collect(make(chan prometheus.Metric))
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("empty collection calls = %d, want 1", got)
	}
}
