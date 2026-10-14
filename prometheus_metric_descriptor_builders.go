package main

import (
	"github.com/prometheus/client_golang/prometheus"
)

func newThreatDomainInstanceDirectionDesc(name, help string) *prometheus.Desc {
	return prometheus.NewDesc(name, help, labelsInstance("direction"), nil)
}

// -----------------------------------------------------------------------------
// Utility Functions
// -----------------------------------------------------------------------------

// newHostMetricDesc describes a host measurement without instance labels.
func newHostMetricDesc(name, help string) *prometheus.Desc {
	return prometheus.NewDesc(name, help, nil, nil)
}
func newInstanceMetricDesc(name, help string) *prometheus.Desc {
	return prometheus.NewDesc(name, help, labelsInstance(), nil)
}
func newInstanceMetricDescExtra(name, help string, extra ...string) *prometheus.Desc {
	return prometheus.NewDesc(name, help, labelsInstance(extra...), nil)
}

func newInstanceConntrackMetricDesc(name, help string) *prometheus.Desc {
	return prometheus.NewDesc(name, help, labelsInstance("ip", "family"), nil)
}
