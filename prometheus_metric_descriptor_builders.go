package main

import (
	"github.com/prometheus/client_golang/prometheus"
)

func newThreatDomainInstanceDirectionDesc(name, help string) *prometheus.Desc {
	return prometheus.NewDesc(name, help, labelsInstance("direction"), nil)
}

func appendConstMetric(metrics *[]prometheus.Metric, desc *prometheus.Desc, valueType prometheus.ValueType, value float64, labels ...string) {
	*metrics = append(*metrics, prometheus.MustNewConstMetric(desc, valueType, value, labels...))
}

// -----------------------------------------------------------------------------
// Utility Functions
// -----------------------------------------------------------------------------

// shardIndex calculates a deterministic shard (0..shardCount-1) for a given string.
func newHostMetricDesc(name, help string) *prometheus.Desc {
	return prometheus.NewDesc(name, help, nil, nil)
}
func newInstanceMetricDesc(name, help string) *prometheus.Desc {
	return prometheus.NewDesc(name, help, labelsInstance(), nil)
}
func newInstanceMetricDescExtra(name, help string, extra ...string) *prometheus.Desc {
	return prometheus.NewDesc(name, help, labelsInstance(extra...), nil)
}
func newInstanceSeverityMetricDesc(name, help string) *prometheus.Desc {
	return prometheus.NewDesc(name, help, labelsInstance(), nil)
}
func newInstanceConntrackMetricDesc(name, help string) *prometheus.Desc {
	return prometheus.NewDesc(name, help, labelsInstance("ip", "family"), nil)
}
