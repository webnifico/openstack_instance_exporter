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

func (mc *MetricsCollector) isResourceSeverityDesc(desc *prometheus.Desc) bool {
	return desc == mc.instanceResourceSeverityDesc ||
		desc == mc.instanceResourceCpuSeverityDesc ||
		desc == mc.instanceResourceMemSeverityDesc ||
		desc == mc.instanceResourceDiskSeverityDesc ||
		desc == mc.instanceResourceNetSeverityDesc
}

// overlayCachedResourceMetrics keeps Libvirt's last-good inventory while
// advancing resource-axis wall-clock state. Cached lifecycle gauges are always
// replaced. Cached severities are rebuilt only from axes still inside their
// bounded retention window, and attention is suppressed when its cached
// resource input can no longer be reproduced with the same axis membership.
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
		if mc.isResourceAxisLifecycleDesc(desc) || mc.isResourceSeverityDesc(desc) {
			continue
		}
		if desc == mc.instanceAttentionSeverityDesc && mc.scoring.ResourceWeight > 0 {
			labels, ok := cachedMetricBaseLabels(metric)
			if ok {
				if instance, exists := instances[cachedResourceInstanceKey(labels)]; exists &&
					(!instance.found || !instance.out.Available || instance.out.StructuralChange) {
					continue
				}
			}
		}
		filtered = append(filtered, metric)
	}

	overlay := make([]prometheus.Metric, 0, len(instances)*21)
	for _, instance := range instances {
		labels := instance.labels
		out := instance.out
		appendInstanceResourceAxisHealthMetrics(
			mc,
			&overlay,
			out,
			labels[0], labels[1], labels[2], labels[3], labels[4], labels[5],
		)
		base := labels[:]
		if out.Available {
			overlay = append(overlay, prometheus.MustNewConstMetric(mc.instanceResourceSeverityDesc, prometheus.GaugeValue, out.OverallFinal, base...))
		}
		axes := []struct {
			result resourceAxisResult
			desc   *prometheus.Desc
		}{
			{result: out.CPU, desc: mc.instanceResourceCpuSeverityDesc},
			{result: out.MEM, desc: mc.instanceResourceMemSeverityDesc},
			{result: out.DISK, desc: mc.instanceResourceDiskSeverityDesc},
			{result: out.NET, desc: mc.instanceResourceNetSeverityDesc},
		}
		for _, axis := range axes {
			if axis.result.Available {
				overlay = append(overlay, prometheus.MustNewConstMetric(axis.desc, prometheus.GaugeValue, axis.result.Sev, base...))
			}
		}
	}
	return filtered, overlay
}
