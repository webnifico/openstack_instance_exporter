package main

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func TestBackgroundCollectorCadenceDoesNotDriftByCollectionDuration(t *testing.T) {
	const interval = 400 * time.Millisecond
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	secondStarted := make(chan time.Time, 1)
	shutdown := make(chan struct{})
	done := make(chan struct{})
	var calls atomic.Int32

	mc := &MetricsCollector{
		shutdownChan:       shutdown,
		collectionInterval: interval,
		collectionRunner: func() []prometheus.Metric {
			switch calls.Add(1) {
			case 1:
				close(firstStarted)
				<-releaseFirst
			case 2:
				secondStarted <- time.Now()
			}
			return nil
		},
	}
	go func() {
		mc.startBackgroundCollector()
		close(done)
	}()
	defer func() {
		close(shutdown)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("background collector did not stop after shutdown")
		}
	}()

	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("first background collection did not start")
	}

	time.Sleep(250 * time.Millisecond)
	releasedAt := time.Now()
	close(releaseFirst)

	select {
	case startedAt := <-secondStarted:
		if delay := startedAt.Sub(releasedAt); delay >= 300*time.Millisecond {
			t.Fatalf("next collection started %v after the prior collection completed; cadence drifted by collection duration", delay)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("next collection waited a full interval after the prior collection completed")
	}
}

func TestWaitForBackgroundCollectionDeadlinePrefersShutdownAfterTimerDelivery(t *testing.T) {
	shutdown := make(chan struct{})
	close(shutdown)
	if waitForBackgroundCollectionDeadline(time.Now().Add(-time.Second), shutdown) {
		t.Fatal("a ready timer was allowed to start a collection after shutdown")
	}

	running := make(chan struct{})
	if !waitForBackgroundCollectionDeadline(time.Now().Add(-time.Second), running) {
		t.Fatal("an elapsed deadline was suppressed while the collector was running")
	}
}

func TestAdvanceBackgroundCollectionDeadlineSkipsMissedIntervals(t *testing.T) {
	previous := time.Unix(100, 0)
	interval := 10 * time.Second

	if got, want := advanceBackgroundCollectionDeadline(previous, interval, time.Unix(105, 0)), time.Unix(110, 0); !got.Equal(want) {
		t.Fatalf("deadline before next interval = %v, want %v", got, want)
	}
	if got, want := advanceBackgroundCollectionDeadline(previous, interval, time.Unix(110, 0)), time.Unix(120, 0); !got.Equal(want) {
		t.Fatalf("deadline at missed interval = %v, want %v", got, want)
	}
	if got, want := advanceBackgroundCollectionDeadline(previous, interval, time.Unix(137, 0)), time.Unix(140, 0); !got.Equal(want) {
		t.Fatalf("deadline after several missed intervals = %v, want %v", got, want)
	}
}

func TestInitialScrapeDoesNotQueueAnImmediateBackgroundCollection(t *testing.T) {
	const interval = 200 * time.Millisecond
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	secondStarted := make(chan struct{}, 1)
	shutdown := make(chan struct{})
	var calls atomic.Int32

	desc := prometheus.NewDesc("test_initial_scrape_schedule", "test", nil, nil)
	mc := &MetricsCollector{
		shutdownChan:       shutdown,
		collectionInterval: interval,
		collectionRunner: func() []prometheus.Metric {
			switch calls.Add(1) {
			case 1:
				close(firstStarted)
				<-releaseFirst
			case 2:
				secondStarted <- struct{}{}
			}
			return []prometheus.Metric{prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, 1)}
		},
	}
	defer close(shutdown)

	firstDone := make(chan struct{})
	go func() {
		ch := make(chan prometheus.Metric, 1)
		mc.Collect(ch)
		close(firstDone)
	}()

	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("initial scrape did not start")
	}
	time.Sleep(interval + 50*time.Millisecond)
	close(releaseFirst)
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("initial scrape did not finish")
	}

	select {
	case <-secondStarted:
		t.Fatal("background collection was queued behind the long initial scrape")
	case <-time.After(interval / 2):
	}
	select {
	case <-secondStarted:
	case <-time.After(2 * interval):
		t.Fatal("background collection did not start one interval after cache initialization")
	}
}
