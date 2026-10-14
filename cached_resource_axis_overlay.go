package main

import (
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

type cachedResourceInstance struct {
	labels [6]string
	out    resourceV2Output
	found  bool
}

func cachedMetricBaseLabels(metric prometheus.Metric) ([6]string, bool) {
	var labels [6]string
	if metric == nil {
		return labels, false
	}
	var encoded dto.Metric
	if err := metric.Write(&encoded); err != nil {
		return labels, false
	}
	byName := make(map[string]string, len(encoded.Label))
	for _, pair := range encoded.Label {
		byName[pair.GetName()] = pair.GetValue()
	}
	for index, name := range labelsInstanceBase {
		value, ok := byName[name]
		if !ok {
			return [6]string{}, false
		}
		labels[index] = value
	}
	return labels, labels[2] != ""
}

func cachedResourceInstanceKey(labels [6]string) string {
	return strings.Join(labels[:], "\x00")
}

func (mc *MetricsCollector) isResourceAxisLifecycleDesc(desc *prometheus.Desc) bool {
	return desc == mc.instanceResourceAxisFreshDesc ||
		desc == mc.instanceResourceAxisAvailableDesc ||
		desc == mc.instanceResourceAxisLastSuccessTimestampDesc ||
		desc == mc.instanceResourceAxisStaleSecondsDesc
}

// overlayCachedResourceMetrics ages lifecycle gauges while preserving last-good raw telemetry.
func (mc *MetricsCollector) overlayCachedResourceMetrics(cached []prometheus.Metric, now time.Time) ([]prometheus.Metric, []prometheus.Metric) {
	instances := make(map[string]*cachedResourceInstance)
	for _, metric := range cached {
		if metric == nil || !mc.isResourceAxisLifecycleDesc(metric.Desc()) {
			continue
		}
		labels, ok := cachedMetricBaseLabels(metric)
		if !ok {
			continue
		}
		key := cachedResourceInstanceKey(labels)
		if _, exists := instances[key]; !exists {
			instances[key] = &cachedResourceInstance{labels: labels}
		}
	}
	if len(instances) == 0 {
		return cached, nil
	}

	for _, instance := range instances {
		instance.out, instance.found = mc.snapshotResourceV2(instance.labels[2], now)
		if instance.found {
			mc.markResourceV2Missing(instance.labels[2])
		}
	}

	filtered := make([]prometheus.Metric, 0, len(cached))
	for _, metric := range cached {
		if metric == nil {
			continue
		}
		desc := metric.Desc()
		if mc.isResourceAxisLifecycleDesc(desc) {
			continue
		}
		filtered = append(filtered, metric)
	}

	overlay := make([]prometheus.Metric, 0, len(instances)*16)
	for _, instance := range instances {
		labels := instance.labels
		out := instance.out
		appendInstanceResourceAxisHealthMetrics(
			mc,
			&overlay,
			out,
			labels[0], labels[1], labels[2], labels[3], labels[4], labels[5],
		)
	}
	return filtered, overlay
}
