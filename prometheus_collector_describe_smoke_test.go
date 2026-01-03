package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"testing"
	"time"
)

func TestMetricsCollectorDescribeRegisterNoPanic(t *testing.T) {
	cfg := CollectorConfig{
		LibvirtURI:          "qemu:///system",
		WorkerCount:         1,
		CollectionInterval:  time.Second,
		ConntrackIPv4Enable: false,
		ConntrackIPv6Enable: false,
	}
	mc, err := NewMetricsCollector(cfg)
	if err != nil {
		t.Fatalf("NewMetricsCollector error: %v", err)
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(mc)

	ch := make(chan *prometheus.Desc, 4096)
	mc.Describe(ch)
	close(ch)

	got := 0
	for range ch {
		got++
	}
	if got == 0 {
		t.Fatalf("Describe produced 0 descs")
	}
}
