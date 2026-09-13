package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

type alertValidationAlertFixture struct {
	warmup                 time.Duration
	firstTrueMinute        int
	resolveDelay           time.Duration
	expected               map[string]string
	expectedForMode        func(alertValidationFixtureMode) []map[string]string
	testStaleLibvirt       bool
	testStaleConntrack     bool
	testRecoveredLibvirt   bool
	testRecoveredConntrack bool
	testFailedScrape       bool
	testFailedScrapeRange  bool
	testFeedStale          bool
	testDuplicate          bool
	testJobMismatch        bool
	testRetainedMissing    bool
	testCohortGap          bool
	build                  func(alertValidationFixtureMode, int, int) []alertValidationPromtoolInputSeries
}

type alertValidationFixtureMode uint8

const (
	alertValidationFixtureLifecycle alertValidationFixtureMode = iota
	alertValidationFixtureBelowThreshold
	alertValidationFixtureStaleLibvirt
	alertValidationFixtureStaleConntrack
	alertValidationFixtureMissingOptional
	alertValidationFixtureDuplicateSeries
	alertValidationFixtureFailedScrape
	alertValidationFixtureFailedScrapeRange
	alertValidationFixtureStaleFeed
	alertValidationFixtureRecoveredLibvirt
	alertValidationFixtureRecoveredConntrack
	alertValidationFixtureJobMismatch
	alertValidationFixtureRetainedMissing
	alertValidationFixtureCohortGap
)

type alertValidationPromtoolRuleFile struct {
	Groups []alertValidationPromtoolRuleGroup `yaml:"groups"`
}

type alertValidationPromtoolRuleGroup struct {
	Name  string                        `yaml:"name"`
	Rules []alertValidationPromtoolRule `yaml:"rules"`
}

type alertValidationPromtoolRule struct {
	Alert  string            `yaml:"alert"`
	Expr   string            `yaml:"expr"`
	For    string            `yaml:"for,omitempty"`
	Labels map[string]string `yaml:"labels,omitempty"`
}

type alertValidationPromtoolTestFile struct {
	RuleFiles          []string                           `yaml:"rule_files"`
	EvaluationInterval string                             `yaml:"evaluation_interval"`
	Tests              []alertValidationPromtoolTestGroup `yaml:"tests"`
}

type alertValidationPromtoolTestGroup struct {
	Name          string                               `yaml:"name"`
	Interval      string                               `yaml:"interval"`
	InputSeries   []alertValidationPromtoolInputSeries `yaml:"input_series"`
	AlertRuleTest []alertValidationPromtoolAlertTest   `yaml:"alert_rule_test"`
}

type alertValidationPromtoolInputSeries struct {
	Series string `yaml:"series"`
	Values string `yaml:"values"`
}

type alertValidationPromtoolAlertTest struct {
	EvalTime string                                 `yaml:"eval_time"`
	Alert    string                                 `yaml:"alertname"`
	Expected []alertValidationPromtoolExpectedAlert `yaml:"exp_alerts"`
}

type alertValidationPromtoolExpectedAlert struct {
	Labels map[string]string `yaml:"exp_labels"`
}

type alertValidationFixtureSignalKind uint8

const (
	alertValidationGaugeSignal alertValidationFixtureSignalKind = iota
	alertValidationCounterSignal
	alertValidationTimestampSignal
	alertValidationGrowingGaugeSignal
)

type alertValidationFixtureSignal struct {
	metric   string
	labels   map[string]string
	kind     alertValidationFixtureSignalKind
	active   float64
	inactive float64
}

type alertValidationFixtureSources uint8

const (
	alertValidationNoSource      alertValidationFixtureSources = 0
	alertValidationLibvirtSource alertValidationFixtureSources = 1 << iota
	alertValidationConntrackSource
	alertValidationScrapeSource
)

func alertValidationPromtoolPath(t *testing.T) string {
	t.Helper()
	if path := os.Getenv("PROMTOOL"); path != "" {
		return path
	}
	path, err := exec.LookPath("promtool")
	if err != nil {
		t.Skip("promtool is not installed")
	}
	return path
}

func alertValidationSeries(metric string, labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(metric)
	if len(keys) == 0 {
		return b.String()
	}
	b.WriteByte('{')
	for i, key := range keys {
		if i != 0 {
			b.WriteByte(',')
		}
		b.WriteString(key)
		b.WriteByte('=')
		b.WriteString(strconv.Quote(labels[key]))
	}
	b.WriteByte('}')
	return b.String()
}

func alertValidationValues(sampleCount int, value func(int) float64) string {
	values := make([]string, sampleCount)
	for i := range values {
		values[i] = strconv.FormatFloat(value(i), 'g', -1, 64)
	}
	return strings.Join(values, " ")
}

func alertValidationCopyLabels(labels map[string]string) map[string]string {
	out := make(map[string]string, len(labels)+1)
	for key, value := range labels {
		out[key] = value
	}
	return out
}

func alertValidationInstanceLabels() map[string]string {
	return map[string]string{
		"domain":        "d",
		"instance":      "node",
		"instance_uuid": "vm",
		"job":           "openstack-instance-exporter",
		"project_name":  "project",
		"project_uuid":  "p",
		"server_name":   "server",
		"user_uuid":     "u",
	}
}

func alertValidationInstanceExpected(severity string) map[string]string {
	return map[string]string{
		"domain":        "d",
		"instance_uuid": "vm",
		"project_uuid":  "p",
		"severity":      severity,
		"user_uuid":     "u",
	}
}

func alertValidationBehaviorExpected(severity string) map[string]string {
	labels := alertValidationInstanceExpected(severity)
	labels["project_name"] = "project"
	return labels
}

func alertValidationSignalInput(signal alertValidationFixtureSignal, mode alertValidationFixtureMode, samples, clearAt int, target string) alertValidationPromtoolInputSeries {
	labels := alertValidationCopyLabels(signal.labels)
	if mode == alertValidationFixtureJobMismatch {
		labels["job"] = "wrong-exporter-job"
	}
	if target != "" {
		labels["instance"] = target
	}
	values := alertValidationValues(samples, func(minute int) float64 {
		active := mode != alertValidationFixtureBelowThreshold && mode != alertValidationFixtureMissingOptional
		if mode == alertValidationFixtureLifecycle && minute >= clearAt {
			active = false
		}
		switch signal.kind {
		case alertValidationCounterSignal:
			var total float64
			for i := 1; i <= minute; i++ {
				stepAtI := signal.inactive
				activeAtI := mode != alertValidationFixtureBelowThreshold && mode != alertValidationFixtureMissingOptional
				if mode == alertValidationFixtureLifecycle && i >= clearAt {
					activeAtI = false
				}
				if activeAtI {
					stepAtI = signal.active
				}
				total += stepAtI
			}
			return total
		case alertValidationGrowingGaugeSignal:
			if active {
				return float64(minute) * signal.active
			}
			return signal.inactive
		default:
			if active {
				return signal.active
			}
			return signal.inactive
		}
	})
	if mode == alertValidationFixtureRetainedMissing {
		tokens := strings.Fields(values)
		from := len(tokens) - 4
		if from < 1 {
			from = 1
		}
		for index := from; index < len(tokens); index++ {
			tokens[index] = "_"
		}
		values = strings.Join(tokens, " ")
	}
	if mode == alertValidationFixtureCohortGap {
		tokens := strings.Fields(values)
		gap := len(tokens) - 3
		if gap >= 0 && gap < len(tokens) {
			tokens[gap] = "_"
		}
		values = strings.Join(tokens, " ")
	}
	return alertValidationPromtoolInputSeries{Series: alertValidationSeries(signal.metric, labels), Values: values}
}

func alertValidationSignalsFixture(warmup, resolveDelay time.Duration, expected map[string]string, sources alertValidationFixtureSources, signals ...alertValidationFixtureSignal) alertValidationAlertFixture {
	_, instanceScoped := expected["instance_uuid"]
	if resolveDelay == 0 && warmup > 0 {
		resolveDelay = warmup
	}
	firstTrueMinute := 0
	if len(signals) != 0 && (signals[0].kind == alertValidationCounterSignal || signals[0].kind == alertValidationGrowingGaugeSignal) {
		firstTrueMinute = 1
	}
	return alertValidationAlertFixture{
		warmup: warmup, firstTrueMinute: firstTrueMinute, resolveDelay: resolveDelay, expected: expected,
		testStaleLibvirt:       sources&alertValidationLibvirtSource != 0,
		testStaleConntrack:     sources&alertValidationConntrackSource != 0,
		testRecoveredLibvirt:   sources&alertValidationLibvirtSource != 0 && warmup > 0,
		testRecoveredConntrack: sources&alertValidationConntrackSource != 0 && warmup > 0,
		testFailedScrape:       sources != alertValidationNoSource,
		testFailedScrapeRange:  sources != alertValidationNoSource && warmup > 0,
		testDuplicate:          instanceScoped,
		testJobMismatch:        sources != alertValidationNoSource,
		testRetainedMissing:    sources != alertValidationNoSource,
		testCohortGap:          sources != alertValidationNoSource && warmup > 0,
		build: func(mode alertValidationFixtureMode, samples, clearAt int) []alertValidationPromtoolInputSeries {
			series := make([]alertValidationPromtoolInputSeries, 0, len(signals)*2+2)
			if mode != alertValidationFixtureMissingOptional {
				for signalIndex, signal := range signals {
					signalMode := mode
					if signalIndex > 0 && (mode == alertValidationFixtureRetainedMissing || mode == alertValidationFixtureCohortGap) {
						signalMode = alertValidationFixtureLifecycle
					}
					if mode == alertValidationFixtureDuplicateSeries {
						series = append(series,
							alertValidationSignalInput(signal, signalMode, samples, clearAt, "node-a"),
							alertValidationSignalInput(signal, signalMode, samples, clearAt, "node-b"),
						)
						continue
					}
					series = append(series, alertValidationSignalInput(signal, signalMode, samples, clearAt, ""))
				}
			}
			healthValue := func(metric string, minute int) float64 {
				staleMode := (metric == "oie_host_libvirt_ok" && mode == alertValidationFixtureStaleLibvirt) ||
					(metric == "oie_host_conntrack_raw_ok" && mode == alertValidationFixtureStaleConntrack)
				if staleMode {
					return 0
				}
				recoveredMode := (metric == "oie_host_libvirt_ok" && mode == alertValidationFixtureRecoveredLibvirt) ||
					(metric == "oie_host_conntrack_raw_ok" && mode == alertValidationFixtureRecoveredConntrack)
				if recoveredMode && minute == samples-3 {
					return 0
				}
				return 1
			}
			upValue := func(minute int) float64 {
				if mode == alertValidationFixtureFailedScrape {
					return 0
				}
				if mode == alertValidationFixtureFailedScrapeRange && minute == samples-3 {
					return 0
				}
				return 1
			}
			nodes := []string{"node"}
			if mode == alertValidationFixtureDuplicateSeries {
				nodes = []string{"node-a", "node-b"}
			}
			if sources != alertValidationNoSource {
				for _, node := range nodes {
					hostLabels := map[string]string{"instance": node, "job": "openstack-instance-exporter"}
					series = append(series, alertValidationPromtoolInputSeries{
						Series: alertValidationSeries("up", hostLabels),
						Values: alertValidationValues(samples, upValue),
					})
				}
			}
			for _, node := range nodes {
				hostLabels := map[string]string{"instance": node, "job": "openstack-instance-exporter"}
				if sources&alertValidationLibvirtSource != 0 {
					series = append(series, alertValidationPromtoolInputSeries{
						Series: alertValidationSeries("oie_host_libvirt_ok", hostLabels),
						Values: alertValidationValues(samples, func(minute int) float64 { return healthValue("oie_host_libvirt_ok", minute) }),
					})
				}
				if sources&alertValidationConntrackSource != 0 {
					series = append(series, alertValidationPromtoolInputSeries{
						Series: alertValidationSeries("oie_host_conntrack_raw_ok", hostLabels),
						Values: alertValidationValues(samples, func(minute int) float64 { return healthValue("oie_host_conntrack_raw_ok", minute) }),
					})
				}
			}
			return series
		},
	}
}

func alertValidationGauge(metric string, active, inactive float64, labels map[string]string) alertValidationFixtureSignal {
	return alertValidationFixtureSignal{metric: metric, labels: labels, kind: alertValidationGaugeSignal, active: active, inactive: inactive}
}

func alertValidationCounter(metric string, activeStep, inactiveStep float64, labels map[string]string) alertValidationFixtureSignal {
	return alertValidationFixtureSignal{metric: metric, labels: labels, kind: alertValidationCounterSignal, active: activeStep, inactive: inactiveStep}
}

func alertValidationGrowingGauge(metric string, activeStep, inactive float64, labels map[string]string) alertValidationFixtureSignal {
	return alertValidationFixtureSignal{metric: metric, labels: labels, kind: alertValidationGrowingGaugeSignal, active: activeStep, inactive: inactive}
}

func alertValidationLabels(extra map[string]string) map[string]string {
	labels := alertValidationInstanceLabels()
	for key, value := range extra {
		labels[key] = value
	}
	return labels
}

func alertValidationAxisFixture(metric, axis string, active float64, severity string, sources alertValidationFixtureSources) alertValidationAlertFixture {
	return alertValidationSignalsFixture(0, 0, alertValidationInstanceExpected(severity), sources,
		alertValidationGauge(metric, active, 0, alertValidationInstanceLabels()),
		alertValidationGauge("oie_instance_resource_axis_fresh", 1, 0, alertValidationLabels(map[string]string{"axis": axis})),
	)
}

func alertValidationCompositeFixture(metric string, active float64, severity string) alertValidationAlertFixture {
	return alertValidationSignalsFixture(0, 0, alertValidationInstanceExpected(severity), alertValidationLibvirtSource|alertValidationConntrackSource,
		alertValidationGauge(metric, active, 0, alertValidationInstanceLabels()),
		alertValidationGauge("oie_instance_resource_axis_fresh", 1, 0, alertValidationLabels(map[string]string{"axis": "cpu"})),
		alertValidationGauge("oie_instance_resource_axis_available", 1, 0, alertValidationLabels(map[string]string{"axis": "cpu"})),
	)
}

var alertValidationThreatFeedLists = []string{"TOREXIT", "TORRELAY", "spamhaus", "EMERGING", "CUSTOMLIST"}

func alertValidationThreatFeedSignals(selected string, selectedValue float64) []alertValidationFixtureSignal {
	signals := make([]alertValidationFixtureSignal, 0, len(alertValidationThreatFeedLists))
	for _, list := range alertValidationThreatFeedLists {
		value := float64(-1)
		if list == selected {
			value = selectedValue
		}
		signals = append(signals, alertValidationGauge("oie_host_threat_feed_fresh", value, value, map[string]string{
			"instance": "node", "job": "openstack-instance-exporter", "list": list,
		}))
	}
	return signals
}

func alertValidationAttentionFixture(metric string, active float64, severity string) alertValidationAlertFixture {
	signals := []alertValidationFixtureSignal{
		alertValidationGauge(metric, active, 0, alertValidationInstanceLabels()),
		alertValidationGauge("oie_instance_resource_axis_fresh", 1, 0, alertValidationLabels(map[string]string{"axis": "cpu"})),
		alertValidationGauge("oie_instance_resource_axis_available", 1, 0, alertValidationLabels(map[string]string{"axis": "cpu"})),
	}
	signals = append(signals, alertValidationThreatFeedSignals("", -1)...)
	fixture := alertValidationSignalsFixture(0, 0, alertValidationInstanceExpected(severity), alertValidationLibvirtSource|alertValidationConntrackSource, signals...)
	fixture.testFeedStale = true
	baseBuild := fixture.build
	fixture.build = func(mode alertValidationFixtureMode, samples, clearAt int) []alertValidationPromtoolInputSeries {
		if mode != alertValidationFixtureStaleFeed {
			return baseBuild(mode, samples, clearAt)
		}
		series := baseBuild(alertValidationFixtureLifecycle, samples, samples+1)
		for index := range series {
			if strings.Contains(series[index].Series, `list="TOREXIT"`) {
				series[index].Values = alertValidationValues(samples, func(int) float64 { return 0 })
			}
		}
		return series
	}
	return fixture
}

func alertValidationDiskIOPSFixture(metric, diskType string, active float64) alertValidationAlertFixture {
	expected := alertValidationInstanceExpected("warning")
	expected["disk_type"] = diskType
	return alertValidationSignalsFixture(0, 0, expected, alertValidationLibvirtSource,
		alertValidationGauge(metric, active, 0, alertValidationLabels(map[string]string{"disk_type": diskType, "disk_path": "vda", "volume_uuid": "volume"})),
	)
}

func alertValidationDiskLatencyFixture(metric string, active float64) alertValidationAlertFixture {
	expected := alertValidationInstanceExpected("warning")
	expected["disk_type"] = "volumes"
	expected["disk_path"] = "vda"
	expected["volume_uuid"] = "volume"
	return alertValidationSignalsFixture(0, 0, expected, alertValidationLibvirtSource,
		alertValidationGauge(metric, active, 0, alertValidationLabels(map[string]string{"disk_type": "volumes", "disk_path": "vda", "volume_uuid": "volume"})),
	)
}

func alertValidationBehaviorFixture(direction, name string, severity string) alertValidationAlertFixture {
	labels := alertValidationLabels(map[string]string{"family": "4", "ip": "192.0.2.10"})
	metric := func(suffix string) string { return "oie_instance_" + direction + "_" + suffix }
	var signals []alertValidationFixtureSignal
	warmup := 2 * time.Minute
	switch name {
	case "port_scan":
		signals = []alertValidationFixtureSignal{
			alertValidationGauge(metric("new_dst_ports"), 300, 0, labels),
			alertValidationGauge(metric("unique_remotes"), 40, 0, labels),
			alertValidationGauge(metric("flows"), 6000, 0, labels),
		}
	case "single_remote_flood":
		signals = []alertValidationFixtureSignal{
			alertValidationGauge(metric("max_flows_single_remote"), 30000, 0, labels),
			alertValidationGauge(metric("unique_remotes"), 2, 10, labels),
		}
	case "single_port_spray":
		signals = []alertValidationFixtureSignal{
			alertValidationGauge(metric("new_remotes"), 400, 0, labels),
			alertValidationGauge(metric("unique_dst_ports"), 2, 10, labels),
			alertValidationGauge(metric("flows"), 9000, 0, labels),
		}
	case "zombie":
		warmup = 30 * time.Minute
		signals = []alertValidationFixtureSignal{
			alertValidationGauge(metric("flows"), 6000, 0, labels),
			alertValidationGauge(metric("bytes_per_flow"), 1000, 3000, labels),
			alertValidationGauge(metric("packets_per_flow"), 10, 30, labels),
		}
	case "fanout":
		warmup = 5 * time.Minute
		signals = []alertValidationFixtureSignal{alertValidationGauge(metric("unique_remotes"), 2000, 0, labels)}
	default:
		panic("unknown Prometheus alert validation behavior fixture " + name)
	}
	return alertValidationSignalsFixture(warmup, 0, alertValidationBehaviorExpected(severity), alertValidationLibvirtSource|alertValidationConntrackSource, signals...)
}

func alertValidationThreatContactFixture(metric, list string) alertValidationAlertFixture {
	labels := alertValidationLabels(map[string]string{"direction": "outbound"})
	expected := alertValidationBehaviorExpected("warning")
	signals := []alertValidationFixtureSignal{
		alertValidationCounter(metric, 10, 0, labels),
		alertValidationCounter(alertValidationThreatRefreshErrorsMetric(list), 0, 0, map[string]string{"instance": "node", "job": "openstack-instance-exporter"}),
		alertValidationCounter("oie_host_conntrack_read_errors_total", 0, 0, map[string]string{"instance": "node", "job": "openstack-instance-exporter"}),
	}
	signals = append(signals, alertValidationThreatFeedSignals(list, 1)...)
	fixture := alertValidationSignalsFixture(5*time.Minute, 0, expected, alertValidationLibvirtSource|alertValidationConntrackSource, signals...)
	fixture.testFeedStale = true
	baseBuild := fixture.build
	fixture.build = func(mode alertValidationFixtureMode, samples, clearAt int) []alertValidationPromtoolInputSeries {
		if mode != alertValidationFixtureStaleFeed {
			return baseBuild(mode, samples, clearAt)
		}
		series := baseBuild(alertValidationFixtureLifecycle, samples, samples+1)
		for index := range series {
			if strings.Contains(series[index].Series, `list="`+list+`"`) {
				series[index].Values = alertValidationValues(samples, func(minute int) float64 {
					if minute == samples-3 {
						return 0
					}
					return 1
				})
			}
		}
		return series
	}
	return fixture
}

func alertValidationThreatRefreshErrorsMetric(list string) string {
	switch list {
	case "TOREXIT":
		return "oie_host_threat_tor_exit_refresh_errors_total"
	case "TORRELAY":
		return "oie_host_threat_tor_relay_refresh_errors_total"
	case "spamhaus":
		return "oie_host_threat_spamhaus_refresh_errors_total"
	case "EMERGING":
		return "oie_host_threat_emergingthreats_refresh_errors_total"
	case "CUSTOMLIST":
		return "oie_host_threat_customlist_refresh_errors_total"
	default:
		panic("unknown Prometheus alert validation threat list " + list)
	}
}

func alertValidationThreatScoreFixture(active float64, severity string) alertValidationAlertFixture {
	signals := []alertValidationFixtureSignal{
		alertValidationGauge("oie_instance_threat_list_severity", active, 0, alertValidationInstanceLabels()),
	}
	signals = append(signals, alertValidationThreatFeedSignals("TOREXIT", 1)...)
	fixture := alertValidationSignalsFixture(0, 0, alertValidationInstanceExpected(severity), alertValidationLibvirtSource|alertValidationConntrackSource, signals...)
	fixture.testFeedStale = true
	baseBuild := fixture.build
	fixture.build = func(mode alertValidationFixtureMode, samples, clearAt int) []alertValidationPromtoolInputSeries {
		if mode != alertValidationFixtureStaleFeed {
			return baseBuild(mode, samples, clearAt)
		}
		series := baseBuild(alertValidationFixtureLifecycle, samples, samples+1)
		for index := range series {
			if strings.HasPrefix(series[index].Series, "oie_host_threat_feed_fresh{") {
				series[index].Values = alertValidationValues(samples, func(int) float64 { return -1 })
				if strings.Contains(series[index].Series, `list="TOREXIT"`) {
					series[index].Values = alertValidationValues(samples, func(int) float64 { return 0 })
				}
			}
		}
		return series
	}
	return fixture
}

func alertValidationHostExpected(severity string) map[string]string {
	return map[string]string{"instance": "node", "job": "openstack-instance-exporter", "severity": severity}
}

func alertValidationHostGaugeFixture(metric string, active, inactive float64, severity string, sources alertValidationFixtureSources) alertValidationAlertFixture {
	labels := map[string]string{"instance": "node", "job": "openstack-instance-exporter"}
	return alertValidationSignalsFixture(0, 0, alertValidationHostExpected(severity), sources,
		alertValidationGauge(metric, active, inactive, labels),
	)
}

func alertValidationFeedStaleFixture(list string) alertValidationAlertFixture {
	labels := map[string]string{"instance": "node", "job": "openstack-instance-exporter", "list": list}
	signals := []alertValidationFixtureSignal{alertValidationGauge("oie_host_threat_feed_fresh", 0, 1, labels)}
	for _, other := range alertValidationThreatFeedLists {
		if other == list {
			continue
		}
		signals = append(signals, alertValidationGauge("oie_host_threat_feed_fresh", -1, -1, map[string]string{
			"instance": "node", "job": "openstack-instance-exporter", "list": other,
		}))
	}
	return alertValidationSignalsFixture(0, 0, alertValidationHostExpected("warning"), alertValidationScrapeSource, signals...)
}

func alertValidationExecutableAlertFixtures() map[string]alertValidationAlertFixture {
	fixtures := map[string]alertValidationAlertFixture{
		"OpenStackInstanceAttentionHigh":          alertValidationAttentionFixture("oie_instance_attention_severity", 70, "warning"),
		"OpenStackInstanceAttentionSevere":        alertValidationAttentionFixture("oie_instance_attention_severity", 90, "critical"),
		"OpenStackInstanceThreatScoreHigh":        alertValidationThreatScoreFixture(60, "warning"),
		"OpenStackInstanceThreatScoreSevere":      alertValidationThreatScoreFixture(90, "critical"),
		"OpenStackInstanceBehaviorScoreHigh":      alertValidationSignalsFixture(0, 0, alertValidationInstanceExpected("warning"), alertValidationLibvirtSource|alertValidationConntrackSource, alertValidationGauge("oie_instance_behavior_severity", 70, 0, alertValidationInstanceLabels())),
		"OpenStackInstanceBehaviorScoreCritical":  alertValidationSignalsFixture(0, 0, alertValidationInstanceExpected("critical"), alertValidationLibvirtSource|alertValidationConntrackSource, alertValidationGauge("oie_instance_behavior_severity", 90, 0, alertValidationInstanceLabels())),
		"OpenStackInstanceHighResourcePressure":   alertValidationCompositeFixture("oie_instance_resource_severity", 80, "warning"),
		"OpenStackInstanceSevereResourcePressure": alertValidationCompositeFixture("oie_instance_resource_severity", 90, "critical"),

		"OpenStackInstanceResourceCPUHigh":    alertValidationAxisFixture("oie_instance_resource_cpu_severity", "cpu", 80, "warning", alertValidationLibvirtSource),
		"OpenStackInstanceResourceCPUSevere":  alertValidationAxisFixture("oie_instance_resource_cpu_severity", "cpu", 90, "critical", alertValidationLibvirtSource),
		"OpenStackInstanceResourceMemHigh":    alertValidationAxisFixture("oie_instance_resource_mem_severity", "mem", 80, "warning", alertValidationLibvirtSource),
		"OpenStackInstanceResourceMemSevere":  alertValidationAxisFixture("oie_instance_resource_mem_severity", "mem", 90, "critical", alertValidationLibvirtSource),
		"OpenStackInstanceResourceDiskHigh":   alertValidationAxisFixture("oie_instance_resource_disk_severity", "disk", 80, "warning", alertValidationLibvirtSource),
		"OpenStackInstanceResourceDiskSevere": alertValidationAxisFixture("oie_instance_resource_disk_severity", "disk", 90, "critical", alertValidationLibvirtSource),
		"OpenStackInstanceResourceNetHigh":    alertValidationAxisFixture("oie_instance_resource_net_severity", "net", 80, "warning", alertValidationLibvirtSource|alertValidationConntrackSource),
		"OpenStackInstanceResourceNetSevere":  alertValidationAxisFixture("oie_instance_resource_net_severity", "net", 90, "critical", alertValidationLibvirtSource|alertValidationConntrackSource),

		"OpenStackInstanceHighCPUUsage": alertValidationSignalsFixture(0, 0, alertValidationInstanceExpected("warning"), alertValidationLibvirtSource,
			alertValidationGauge("oie_instance_cpu_vcpu_percent", 90, 0, alertValidationInstanceLabels())),
		"OpenStackInstanceHighStealRate": func() alertValidationAlertFixture {
			fixture := alertValidationSignalsFixture(5*time.Minute, 0, alertValidationInstanceExpected("warning"), alertValidationLibvirtSource,
				alertValidationCounter("oie_instance_cpu_steal_seconds_total", 6, 0, alertValidationInstanceLabels()))
			fixture.firstTrueMinute = 3
			return fixture
		}(),
		"OpenStackInstanceHighMemorySwapInRate": func() alertValidationAlertFixture {
			fixture := alertValidationSignalsFixture(5*time.Minute, 0, alertValidationInstanceExpected("warning"), alertValidationLibvirtSource,
				alertValidationCounter("oie_instance_mem_swap_in_bytes_total", 6e9, 0, alertValidationInstanceLabels()))
			fixture.firstTrueMinute = 4
			return fixture
		}(),
		"OpenStackInstanceHighMajorFaultRate": func() alertValidationAlertFixture {
			fixture := alertValidationSignalsFixture(5*time.Minute, 0, alertValidationInstanceExpected("warning"), alertValidationLibvirtSource,
				alertValidationCounter("oie_instance_mem_major_faults_total", 24000, 0, alertValidationInstanceLabels()))
			fixture.firstTrueMinute = 3
			return fixture
		}(),

		"OpenStackInstanceHighDiskReadIOPSLocal":    alertValidationDiskIOPSFixture("oie_instance_disk_read_iops", "local", 9000),
		"OpenStackInstanceHighDiskReadIOPSVolumes":  alertValidationDiskIOPSFixture("oie_instance_disk_read_iops", "volumes", 3000),
		"OpenStackInstanceHighDiskReadIOPSPremium":  alertValidationDiskIOPSFixture("oie_instance_disk_read_iops", "premium", 7000),
		"OpenStackInstanceHighDiskReadIOPSUltra":    alertValidationDiskIOPSFixture("oie_instance_disk_read_iops", "ultra", 13000),
		"OpenStackInstanceHighDiskWriteIOPSLocal":   alertValidationDiskIOPSFixture("oie_instance_disk_write_iops", "local", 9000),
		"OpenStackInstanceHighDiskWriteIOPSVolumes": alertValidationDiskIOPSFixture("oie_instance_disk_write_iops", "volumes", 3000),
		"OpenStackInstanceHighDiskWriteIOPSPremium": alertValidationDiskIOPSFixture("oie_instance_disk_write_iops", "premium", 7000),
		"OpenStackInstanceHighDiskWriteIOPSUltra":   alertValidationDiskIOPSFixture("oie_instance_disk_write_iops", "ultra", 13000),
		"OpenStackInstanceDiskReadLatencyHigh":      alertValidationDiskLatencyFixture("oie_instance_disk_read_latency_seconds", 0.2),
		"OpenStackInstanceDiskWriteLatencyHigh":     alertValidationDiskLatencyFixture("oie_instance_disk_write_latency_seconds", 0.2),
		"OpenStackInstanceDiskFlushLatencyHigh":     alertValidationDiskLatencyFixture("oie_instance_disk_flush_latency_seconds", 0.1),
		"OpenStackInstanceHighDiskGBReadTotalLongTerm": func() alertValidationAlertFixture {
			fixture := alertValidationSignalsFixture(6*time.Hour, 0, alertValidationInstanceExpected("warning"), alertValidationLibvirtSource,
				alertValidationCounter("oie_instance_disk_read_gbytes_total", 100, 0, alertValidationLabels(map[string]string{"disk_type": "volumes", "disk_path": "vda", "volume_uuid": "volume"})))
			fixture.firstTrueMinute = 3
			return fixture
		}(),
		"OpenStackInstanceHighDiskGBWriteTotalLongTerm": func() alertValidationAlertFixture {
			fixture := alertValidationSignalsFixture(6*time.Hour, 0, alertValidationInstanceExpected("warning"), alertValidationLibvirtSource,
				alertValidationCounter("oie_instance_disk_write_gbytes_total", 100, 0, alertValidationLabels(map[string]string{"disk_type": "volumes", "disk_path": "vda", "volume_uuid": "volume"})))
			fixture.firstTrueMinute = 3
			return fixture
		}(),

		"OpenStackInstanceHighIncomingPacketRate": alertValidationSignalsFixture(4*time.Minute, 0, alertValidationInstanceExpected("warning"), alertValidationLibvirtSource,
			alertValidationCounter("oie_instance_net_rx_packets_total", 1e6, 0, alertValidationLabels(map[string]string{"ifname": "tap0"}))),
		"OpenStackInstanceHighOutgoingPacketRate": alertValidationSignalsFixture(4*time.Minute, 0, alertValidationInstanceExpected("warning"), alertValidationLibvirtSource,
			alertValidationCounter("oie_instance_net_tx_packets_total", 1e6, 0, alertValidationLabels(map[string]string{"ifname": "tap0"}))),
		"OpenStackInstanceHighBandwidthRateRX": alertValidationSignalsFixture(time.Minute, 0, alertValidationInstanceExpected("warning"), alertValidationLibvirtSource,
			alertValidationCounter("oie_instance_net_rx_gbytes_total", 60, 0, alertValidationLabels(map[string]string{"ifname": "tap0"}))),
		"OpenStackInstanceHighBandwidthRateTX": alertValidationSignalsFixture(time.Minute, 0, alertValidationInstanceExpected("warning"), alertValidationLibvirtSource,
			alertValidationCounter("oie_instance_net_tx_gbytes_total", 60, 0, alertValidationLabels(map[string]string{"ifname": "tap0"}))),
		"OpenStackInstanceNetworkReceiveDropRatioHigh": alertValidationSignalsFixture(5*time.Minute, 0, alertValidationInstanceExpected("warning"), alertValidationLibvirtSource,
			alertValidationCounter("oie_instance_net_rx_dropped_total", 10, 0, alertValidationLabels(map[string]string{"ifname": "tap0"})),
			alertValidationCounter("oie_instance_net_rx_packets_total", 10, 100, alertValidationLabels(map[string]string{"ifname": "tap0"}))),
		"OpenStackInstanceNetworkTransmitDropRatioHigh": alertValidationSignalsFixture(5*time.Minute, 0, alertValidationInstanceExpected("warning"), alertValidationLibvirtSource,
			alertValidationCounter("oie_instance_net_tx_dropped_total", 10, 0, alertValidationLabels(map[string]string{"ifname": "tap0"})),
			alertValidationCounter("oie_instance_net_tx_packets_total", 10, 100, alertValidationLabels(map[string]string{"ifname": "tap0"}))),

		"OpenStackInstanceConntrackFlowsBurst": alertValidationSignalsFixture(time.Minute, 0, alertValidationInstanceExpected("warning"), alertValidationLibvirtSource|alertValidationConntrackSource,
			alertValidationGauge("oie_instance_conntrack_ip_flows", 30000, 0, alertValidationLabels(map[string]string{"family": "4", "ip": "192.0.2.10"}))),
		"OpenStackInstanceHighConntrackFlowsSustained": alertValidationSignalsFixture(0, 0, alertValidationInstanceExpected("warning"), alertValidationLibvirtSource|alertValidationConntrackSource,
			alertValidationGauge("oie_instance_conntrack_ip_flows", 60000, 0, alertValidationLabels(map[string]string{"family": "4", "ip": "192.0.2.10"}))),
		"OpenStackInstanceZombieFlowWarning": alertValidationSignalsFixture(0, 0, alertValidationInstanceExpected("info"), alertValidationLibvirtSource|alertValidationConntrackSource,
			alertValidationGauge("oie_instance_conntrack_ip_flows", 6000, 0, alertValidationLabels(map[string]string{"family": "4", "ip": "192.0.2.10"}))),
		"OpenStackInstanceOutboundPortScanBurst":           alertValidationBehaviorFixture("outbound", "port_scan", "warning"),
		"OpenStackInstanceInboundPortScanBurst":            alertValidationBehaviorFixture("inbound", "port_scan", "warning"),
		"OpenStackInstanceOutboundSingleTargetFlood":       alertValidationBehaviorFixture("outbound", "single_remote_flood", "warning"),
		"OpenStackInstanceInboundSingleSourceFlood":        alertValidationBehaviorFixture("inbound", "single_remote_flood", "warning"),
		"OpenStackInstanceOutboundSprayOnSinglePort":       alertValidationBehaviorFixture("outbound", "single_port_spray", "warning"),
		"OpenStackInstanceInboundSprayOnSinglePort":        alertValidationBehaviorFixture("inbound", "single_port_spray", "warning"),
		"OpenStackInstanceOutboundZombieFlowLowThroughput": alertValidationBehaviorFixture("outbound", "zombie", "info"),
		"OpenStackInstanceInboundZombieFlowLowThroughput":  alertValidationBehaviorFixture("inbound", "zombie", "warning"),
		"OpenStackInstanceOutboundExtremeRemoteFanout":     alertValidationBehaviorFixture("outbound", "fanout", "warning"),
		"OpenStackInstanceInboundExtremeRemoteFanout":      alertValidationBehaviorFixture("inbound", "fanout", "warning"),
		"OpenStackInstanceConntrackFlowsGrowthRate": alertValidationSignalsFixture(time.Minute, 0, alertValidationInstanceExpected("warning"), alertValidationLibvirtSource|alertValidationConntrackSource,
			alertValidationGrowingGauge("oie_instance_conntrack_ip_flows", 360000, 0, alertValidationLabels(map[string]string{"family": "4", "ip": "192.0.2.10"}))),

		"OpenStackInstanceTorExitRepeatedContact":         alertValidationThreatContactFixture("oie_instance_threat_tor_exit_contacts_total", "TOREXIT"),
		"OpenStackInstanceSpamhausRepeatedContact":        alertValidationThreatContactFixture("oie_instance_threat_spamhaus_contacts_total", "spamhaus"),
		"OpenStackInstanceTorRelayRepeatedContact":        alertValidationThreatContactFixture("oie_instance_threat_tor_relay_contacts_total", "TORRELAY"),
		"OpenStackInstanceEmergingThreatsRepeatedContact": alertValidationThreatContactFixture("oie_instance_threat_emergingthreats_contacts_total", "EMERGING"),
		"OpenStackInstanceCustomListRepeatedContact":      alertValidationThreatContactFixture("oie_instance_threat_customlist_contacts_total", "CUSTOMLIST"),

		"OpenStackInstanceExporterProcessCPUHigh": func() alertValidationAlertFixture {
			fixture := alertValidationSignalsFixture(5*time.Minute, 5*time.Minute, alertValidationHostExpected("warning"), alertValidationScrapeSource,
				alertValidationCounter("process_cpu_seconds_total", 600, 0, map[string]string{"instance": "node", "job": "openstack-instance-exporter"}))
			fixture.firstTrueMinute = 1
			return fixture
		}(),
		"OpenStackInstanceExporterHostThreatListed": func() alertValidationAlertFixture {
			expected := map[string]string{"family": "4", "instance": "node", "ip": "192.0.2.1", "job": "openstack-instance-exporter", "severity": "warning"}
			fixture := alertValidationSignalsFixture(0, 0, expected, alertValidationScrapeSource,
				alertValidationGauge("oie_host_threat_provider_ip_listed", 1, 0, map[string]string{"family": "4", "instance": "node", "ip": "192.0.2.1", "job": "openstack-instance-exporter", "list": "TOREXIT"}),
				alertValidationGauge("oie_host_threat_feed_fresh", 1, 1, map[string]string{"instance": "node", "job": "openstack-instance-exporter", "list": "TOREXIT"}))
			fixture.testFeedStale = true
			baseBuild := fixture.build
			fixture.build = func(mode alertValidationFixtureMode, samples, clearAt int) []alertValidationPromtoolInputSeries {
				if mode != alertValidationFixtureStaleFeed {
					return baseBuild(mode, samples, clearAt)
				}
				series := baseBuild(alertValidationFixtureLifecycle, samples, samples+1)
				for index := range series {
					if strings.HasPrefix(series[index].Series, "oie_host_threat_feed_fresh{") {
						series[index].Values = alertValidationValues(samples, func(int) float64 { return 0 })
					}
				}
				return series
			}
			return fixture
		}(),
		"OpenStackInstanceExporterHostConntrackUtilizationHigh": alertValidationHostGaugeFixture("oie_host_conntrack_utilization", 0.9, 0, "warning", alertValidationConntrackSource),
		"OpenStackInstanceExporterHostConntrackReadErrors": alertValidationSignalsFixture(10*time.Minute, 10*time.Minute, alertValidationHostExpected("warning"), alertValidationScrapeSource,
			alertValidationCounter("oie_host_conntrack_read_errors_total", 10, 0, map[string]string{"instance": "node", "job": "openstack-instance-exporter"}),
			alertValidationGauge("oie_host_conntrack_raw_ok", 1, 1, map[string]string{"instance": "node", "job": "openstack-instance-exporter"})),
		"OpenStackInstanceExporterConntrackRawReaderFailed": alertValidationSignalsFixture(0, 0, alertValidationHostExpected("warning"), alertValidationScrapeSource,
			alertValidationGauge("oie_host_conntrack_raw_ok", 0, 1, map[string]string{"instance": "node", "job": "openstack-instance-exporter"}),
			alertValidationGauge("oie_host_conntrack_stale_seconds", 0, 0, map[string]string{"instance": "node", "job": "openstack-instance-exporter"})),
		"OpenStackInstanceExporterConntrackReadStale": alertValidationSignalsFixture(0, 0, alertValidationHostExpected("warning"), alertValidationScrapeSource,
			alertValidationGauge("oie_host_conntrack_stale_seconds", 300, 0, map[string]string{"instance": "node", "job": "openstack-instance-exporter"})),
		"OpenStackInstanceExporterTorExitListRefreshStale":         alertValidationFeedStaleFixture("TOREXIT"),
		"OpenStackInstanceExporterSpamhausListRefreshStale":        alertValidationFeedStaleFixture("spamhaus"),
		"OpenStackInstanceExporterEmergingThreatsListRefreshStale": alertValidationFeedStaleFixture("EMERGING"),
		"OpenStackInstanceExporterCustomListRefreshStale":          alertValidationFeedStaleFixture("CUSTOMLIST"),
	}
	alertValidationRegisterProjectFixture(fixtures)
	alertValidationRegisterMiningFixtures(fixtures)
	alertValidationRegisterNewHealthFixtures(fixtures)
	return fixtures
}

func alertValidationRegisterProjectFixture(fixtures map[string]alertValidationAlertFixture) {
	expected := map[string]string{
		"project_name": "project",
		"project_uuid": "p",
		"severity":     "warning",
	}
	fixture := alertValidationAlertFixture{
		warmup: 0, expected: expected,
		testStaleLibvirt: true, testStaleConntrack: true, testFailedScrape: true,
		testFeedStale: true, testDuplicate: true, testJobMismatch: true, testRetainedMissing: true,
	}
	fixture.expectedForMode = func(mode alertValidationFixtureMode) []map[string]string {
		if mode == alertValidationFixtureLifecycle {
			return []map[string]string{expected}
		}
		return nil
	}
	fixture.build = func(mode alertValidationFixtureMode, samples, clearAt int) []alertValidationPromtoolInputSeries {
		series := make([]alertValidationPromtoolInputSeries, 0, 40)
		instances := 10
		if mode == alertValidationFixtureBelowThreshold || mode == alertValidationFixtureDuplicateSeries {
			instances = 9
		}
		if mode != alertValidationFixtureMissingOptional {
			for i := 0; i < instances; i++ {
				labels := alertValidationInstanceLabels()
				labels["instance_uuid"] = fmt.Sprintf("vm-%02d", i)
				signal := alertValidationGauge("oie_instance_attention_severity", 70, 0, labels)
				series = append(series, alertValidationSignalInput(signal, mode, samples, clearAt, ""))
				for _, axisMetric := range []string{"oie_instance_resource_axis_fresh", "oie_instance_resource_axis_available"} {
					axisLabels := alertValidationCopyLabels(labels)
					axisLabels["axis"] = "cpu"
					axisMode := mode
					if mode == alertValidationFixtureRetainedMissing || mode == alertValidationFixtureCohortGap {
						axisMode = alertValidationFixtureLifecycle
					}
					series = append(series, alertValidationSignalInput(alertValidationGauge(axisMetric, 1, 0, axisLabels), axisMode, samples, clearAt, ""))
				}
			}
			if mode == alertValidationFixtureDuplicateSeries {
				labels := alertValidationInstanceLabels()
				labels["instance"] = "node-b"
				labels["instance_uuid"] = "vm-00"
				series = append(series, alertValidationSignalInput(alertValidationGauge("oie_instance_attention_severity", 70, 0, labels), mode, samples, clearAt, ""))
				for _, axisMetric := range []string{"oie_instance_resource_axis_fresh", "oie_instance_resource_axis_available"} {
					axisLabels := alertValidationCopyLabels(labels)
					axisLabels["axis"] = "cpu"
					series = append(series, alertValidationSignalInput(alertValidationGauge(axisMetric, 1, 0, axisLabels), mode, samples, clearAt, ""))
				}
			}
		}
		nodes := []string{"node"}
		if mode == alertValidationFixtureDuplicateSeries {
			nodes = append(nodes, "node-b")
		}
		for _, node := range nodes {
			labels := map[string]string{"instance": node, "job": "openstack-instance-exporter"}
			for _, healthMetric := range []string{"oie_host_libvirt_ok", "oie_host_conntrack_raw_ok"} {
				series = append(series, alertValidationPromtoolInputSeries{
					Series: alertValidationSeries(healthMetric, labels),
					Values: alertValidationValues(samples, func(int) float64 {
						if healthMetric == "oie_host_libvirt_ok" && mode == alertValidationFixtureStaleLibvirt {
							return 0
						}
						if healthMetric == "oie_host_conntrack_raw_ok" && mode == alertValidationFixtureStaleConntrack {
							return 0
						}
						return 1
					}),
				})
			}
			series = append(series, alertValidationPromtoolInputSeries{
				Series: alertValidationSeries("up", labels),
				Values: alertValidationValues(samples, func(minute int) float64 {
					if mode == alertValidationFixtureFailedScrape {
						return 0
					}
					if mode == alertValidationFixtureFailedScrapeRange && minute == samples-3 {
						return 0
					}
					return 1
				}),
			})
			for _, list := range alertValidationThreatFeedLists {
				value := float64(-1)
				if mode == alertValidationFixtureStaleFeed && list == "TOREXIT" {
					value = 0
				}
				feedLabels := alertValidationCopyLabels(labels)
				feedLabels["list"] = list
				series = append(series, alertValidationPromtoolInputSeries{
					Series: alertValidationSeries("oie_host_threat_feed_fresh", feedLabels),
					Values: alertValidationValues(samples, func(int) float64 { return value }),
				})
			}
		}
		return series
	}
	fixtures["OpenStackProjectManyHotInstances"] = fixture
}

func alertValidationMiningLabels(confidence string) map[string]string {
	return alertValidationLabels(map[string]string{
		"confidence": confidence,
		"family":     "4",
		"ip":         "192.0.2.10",
		"port":       "3333",
		"port_name":  "stratum",
		"priority":   "P2",
	})
}

func alertValidationMiningExpected(confidence, severity string) map[string]string {
	return alertValidationInstanceExpected(severity)
}

func alertValidationRegisterMiningFixtures(fixtures map[string]alertValidationAlertFixture) {
	warningExpected := alertValidationMiningExpected("high", "warning")
	warning := alertValidationSignalsFixture(0, 0, warningExpected, alertValidationLibvirtSource|alertValidationConntrackSource,
		alertValidationGauge("oie_instance_mining_suspected", 1, 0, alertValidationMiningLabels("high")),
	)
	warning.expectedForMode = func(mode alertValidationFixtureMode) []map[string]string {
		if mode == alertValidationFixtureLifecycle || mode == alertValidationFixtureDuplicateSeries || mode == alertValidationFixtureMissingOptional {
			return []map[string]string{warningExpected}
		}
		return nil
	}
	warningBuild := warning.build
	warning.build = func(mode alertValidationFixtureMode, samples, clearAt int) []alertValidationPromtoolInputSeries {
		if mode != alertValidationFixtureMissingOptional {
			return warningBuild(mode, samples, clearAt)
		}
		return warningBuild(alertValidationFixtureLifecycle, samples, samples+1)
	}
	fixtures["OpenStackInstanceMiningSuspected"] = warning

	candidateExpected := alertValidationMiningExpected("high_persistent", "info")
	candidate := alertValidationSignalsFixture(0, 0, candidateExpected, alertValidationLibvirtSource|alertValidationConntrackSource,
		alertValidationGauge("oie_instance_mining_suspected", 1, 0, alertValidationMiningLabels("high_persistent")),
	)
	candidate.expectedForMode = func(mode alertValidationFixtureMode) []map[string]string {
		if mode == alertValidationFixtureLifecycle || mode == alertValidationFixtureDuplicateSeries || mode == alertValidationFixtureMissingOptional {
			return []map[string]string{candidateExpected}
		}
		return nil
	}
	candidateBuild := candidate.build
	candidate.build = func(mode alertValidationFixtureMode, samples, clearAt int) []alertValidationPromtoolInputSeries {
		if mode != alertValidationFixtureMissingOptional {
			return candidateBuild(mode, samples, clearAt)
		}
		return candidateBuild(alertValidationFixtureLifecycle, samples, samples+1)
	}
	fixtures["OpenStackInstanceMiningCandidatePersistent"] = candidate
}

func alertValidationRegisterNewHealthFixtures(fixtures map[string]alertValidationAlertFixture) {
	fixtures["OpenStackInstanceExporterUnavailable"] = alertValidationHostGaugeFixture("up", 0, 1, "critical", alertValidationNoSource)
	fixtures["OpenStackInstanceExporterLibvirtCollectionUnhealthy"] = alertValidationSignalsFixture(0, 0, alertValidationHostExpected("warning"), alertValidationScrapeSource,
		alertValidationGauge("oie_host_libvirt_ok", 0, 1, map[string]string{"instance": "node", "job": "openstack-instance-exporter"}),
		alertValidationGauge("oie_host_libvirt_stale_seconds", 0, 0, map[string]string{"instance": "node", "job": "openstack-instance-exporter"}))
	fixtures["OpenStackInstanceExporterLibvirtDataStale"] = alertValidationSignalsFixture(0, 0, alertValidationHostExpected("warning"), alertValidationScrapeSource,
		alertValidationGauge("oie_host_libvirt_stale_seconds", 300, 0, map[string]string{"instance": "node", "job": "openstack-instance-exporter"}))
	fixtures["OpenStackInstanceExporterTorRelayListRefreshStale"] = alertValidationFeedStaleFixture("TORRELAY")
	fixtures["OpenStackInstanceExporterCollectionCycleNearInterval"] = alertValidationSignalsFixture(0, 0, alertValidationHostExpected("warning"), alertValidationScrapeSource,
		alertValidationGauge("oie_host_collection_cycle_duration_seconds", 14, 0, map[string]string{"instance": "node", "job": "openstack-instance-exporter"}),
		alertValidationGauge("oie_host_collection_interval_seconds", 15, 15, map[string]string{"instance": "node", "job": "openstack-instance-exporter"}))
	fixtures["OpenStackInstanceExporterHostCPUPressureSustained"] = alertValidationHostGaugeFixture("oie_host_cpu_usage_percent", 97, 0, "warning", alertValidationScrapeSource)
	fixtures["OpenStackInstanceExporterHostMemoryPressureSustained"] = alertValidationSignalsFixture(0, 0, alertValidationHostExpected("warning"), alertValidationScrapeSource,
		alertValidationGauge("oie_host_mem_available_mb", 100, 10000, map[string]string{"instance": "node", "job": "openstack-instance-exporter"}),
		alertValidationGauge("oie_host_mem_mb_total", 10000, 10000, map[string]string{"instance": "node", "job": "openstack-instance-exporter"}),
	)
}

func alertValidationFixtureExpected(fixture alertValidationAlertFixture, mode alertValidationFixtureMode, ruleLabels map[string]string) []alertValidationPromtoolExpectedAlert {
	var labels []map[string]string
	if fixture.expectedForMode != nil {
		labels = fixture.expectedForMode(mode)
	} else if mode == alertValidationFixtureLifecycle || mode == alertValidationFixtureDuplicateSeries {
		labels = []map[string]string{fixture.expected}
	}
	expected := make([]alertValidationPromtoolExpectedAlert, 0, len(labels))
	for _, labelSet := range labels {
		merged := alertValidationCopyLabels(labelSet)
		for key, value := range ruleLabels {
			merged[key] = value
		}
		expected = append(expected, alertValidationPromtoolExpectedAlert{Labels: merged})
	}
	return expected
}

func alertValidationDurationMinutes(t *testing.T, value string) int {
	t.Helper()
	if value == "" {
		return 0
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		t.Fatalf("invalid alert duration %q: %v", value, err)
	}
	if duration%time.Minute != 0 {
		t.Fatalf("alert duration %q is not an integral minute", value)
	}
	return int(duration / time.Minute)
}

func alertValidationRuleInventory(t *testing.T) (map[string]dataIntegrityAlertRule, []string) {
	t.Helper()
	rules := make(map[string]dataIntegrityAlertRule)
	order := make([]string, 0)
	for _, group := range dataIntegrityLoadAlertContract(t).Groups {
		for _, rule := range group.Rules {
			if _, duplicate := rules[rule.Alert]; duplicate {
				t.Fatalf("duplicate bundled alert %q", rule.Alert)
			}
			rules[rule.Alert] = rule
			order = append(order, rule.Alert)
		}
	}
	return rules, order
}

func TestAlertValidationEveryBundledAlertHasExecutableLifecycleFixture(t *testing.T) {
	rules, _ := alertValidationRuleInventory(t)
	fixtures := alertValidationExecutableAlertFixtures()
	missing := make([]string, 0)
	stale := make([]string, 0)
	for name := range rules {
		if _, ok := fixtures[name]; !ok {
			missing = append(missing, name)
		}
	}
	for name := range fixtures {
		if _, ok := rules[name]; !ok {
			stale = append(stale, name)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	if len(missing) != 0 || len(stale) != 0 {
		t.Fatalf("Prometheus alert validation executable alert fixture inventory differs from bundled rules: missing=%v stale=%v", missing, stale)
	}
	if len(rules) != 78 {
		t.Fatalf("bundled Prometheus alert validation alert count=%d, want 78", len(rules))
	}
	for name, fixture := range fixtures {
		if fixture.build == nil || fixture.expected == nil {
			t.Fatalf("alert %q has an incomplete executable fixture", name)
		}
	}
}

func TestAlertValidationEveryBundledAlertLifecycleWithPromtool(t *testing.T) {
	promtool := alertValidationPromtoolPath(t)
	rules, order := alertValidationRuleInventory(t)
	fixtures := alertValidationExecutableAlertFixtures()
	dir := t.TempDir()
	for index, name := range order {
		rule := rules[name]
		fixture, ok := fixtures[name]
		if !ok {
			t.Fatalf("no lifecycle fixture for %q", name)
		}
		native := alertValidationPromtoolRuleFile{Groups: []alertValidationPromtoolRuleGroup{{
			Name: "alert-validation-complete-lifecycle",
			Rules: []alertValidationPromtoolRule{{
				Alert: rule.Alert, Expr: normalizedAlertExpression(rule.Expr), For: rule.For, Labels: rule.Labels,
			}},
		}}}
		ruleBytes, err := yaml.Marshal(native)
		if err != nil {
			t.Fatal(err)
		}
		rulesPath := filepath.Join(dir, fmt.Sprintf("rules-%02d.yml", index))
		if err := os.WriteFile(rulesPath, ruleBytes, 0o600); err != nil {
			t.Fatal(err)
		}
		testFile := alertValidationPromtoolTestFile{RuleFiles: []string{rulesPath}, EvaluationInterval: "1m"}

		forMinutes := alertValidationDurationMinutes(t, rule.For)
		fireMinute := fixture.firstTrueMinute + forMinutes
		if fireMinute == 0 {
			fireMinute = 1
		}
		clearMinute := fireMinute + 1
		resolveMinute := clearMinute + int(fixture.resolveDelay/time.Minute)
		endMinute := resolveMinute + 1

		lifecycleTests := []alertValidationPromtoolAlertTest{}
		if forMinutes > 0 {
			pendingMinute := fixture.firstTrueMinute + forMinutes - 1
			lifecycleTests = append(lifecycleTests, alertValidationPromtoolAlertTest{
				EvalTime: fmt.Sprintf("%dm", pendingMinute), Alert: name, Expected: []alertValidationPromtoolExpectedAlert{},
			})
		}
		lifecycleTests = append(lifecycleTests,
			alertValidationPromtoolAlertTest{EvalTime: fmt.Sprintf("%dm", fireMinute), Alert: name, Expected: alertValidationFixtureExpected(fixture, alertValidationFixtureLifecycle, rule.Labels)},
			alertValidationPromtoolAlertTest{EvalTime: fmt.Sprintf("%dm", resolveMinute), Alert: name, Expected: []alertValidationPromtoolExpectedAlert{}},
		)
		testFile.Tests = append(testFile.Tests, alertValidationPromtoolTestGroup{
			Name: "lifecycle " + name, Interval: "1m",
			InputSeries:   fixture.build(alertValidationFixtureLifecycle, endMinute+1, clearMinute),
			AlertRuleTest: lifecycleTests,
		})

		for _, modeCase := range []struct {
			name    string
			mode    alertValidationFixtureMode
			include bool
		}{
			{name: "below threshold", mode: alertValidationFixtureBelowThreshold, include: true},
			{name: "Libvirt source unhealthy", mode: alertValidationFixtureStaleLibvirt, include: fixture.testStaleLibvirt},
			{name: "conntrack source unhealthy", mode: alertValidationFixtureStaleConntrack, include: fixture.testStaleConntrack},
			{name: "recovered Libvirt source remains in range", mode: alertValidationFixtureRecoveredLibvirt, include: fixture.testRecoveredLibvirt},
			{name: "recovered conntrack source remains in range", mode: alertValidationFixtureRecoveredConntrack, include: fixture.testRecoveredConntrack},
			{name: "current scrape failed", mode: alertValidationFixtureFailedScrape, include: fixture.testFailedScrape},
			{name: "failed scrape remains in range", mode: alertValidationFixtureFailedScrapeRange, include: fixture.testFailedScrapeRange},
			{name: "stale threat feed", mode: alertValidationFixtureStaleFeed, include: fixture.testFeedStale},
			{name: "missing optional metrics", mode: alertValidationFixtureMissingOptional, include: true},
			{name: "duplicate series", mode: alertValidationFixtureDuplicateSeries, include: fixture.testDuplicate},
			{name: "job mismatch", mode: alertValidationFixtureJobMismatch, include: fixture.testJobMismatch},
			{name: "retained primary absent from current scrape", mode: alertValidationFixtureRetainedMissing, include: fixture.testRetainedMissing},
			{name: "range cohort contains a missing primary sample", mode: alertValidationFixtureCohortGap, include: fixture.testCohortGap},
		} {
			if !modeCase.include {
				continue
			}
			interval := "1m"
			evalMinute := fireMinute
			samples := fireMinute + 2
			if modeCase.mode == alertValidationFixtureCohortGap {
				// A 30-second source cadence places the missing sample strictly
				// inside even a left-open one-minute PromQL range while retaining
				// a current primary sample at evaluation time.
				interval = "30s"
				evalMinute = fireMinute + 1
				samples = evalMinute*2 + 2
			}
			testFile.Tests = append(testFile.Tests, alertValidationPromtoolTestGroup{
				Name: modeCase.name + " " + name, Interval: interval,
				InputSeries: fixture.build(modeCase.mode, samples, samples),
				AlertRuleTest: []alertValidationPromtoolAlertTest{{
					EvalTime: fmt.Sprintf("%dm", evalMinute), Alert: name,
					Expected: alertValidationFixtureExpected(fixture, modeCase.mode, rule.Labels),
				}},
			})
		}

		testBytes, err := yaml.Marshal(testFile)
		if err != nil {
			t.Fatal(err)
		}
		testPath := filepath.Join(dir, fmt.Sprintf("tests-%02d.yml", index))
		if err := os.WriteFile(testPath, testBytes, 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(promtool, "test", "rules", testPath)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("promtool rejected Prometheus alert validation lifecycle matrix for %s: %v\n%s", name, err, output)
		}
	}
}

func alertValidationRunSelectedPromtool(t *testing.T, testName string, alertNames []string, groups []alertValidationPromtoolTestGroup) {
	t.Helper()
	rules, _ := alertValidationRuleInventory(t)
	selected := make([]alertValidationPromtoolRule, 0, len(alertNames))
	for _, name := range alertNames {
		rule, ok := rules[name]
		if !ok {
			t.Fatalf("selected Prometheus alert validation rule %q is missing", name)
		}
		selected = append(selected, alertValidationPromtoolRule{
			Alert: name, Expr: normalizedAlertExpression(rule.Expr), For: rule.For, Labels: rule.Labels,
		})
	}
	alertValidationRunPromtoolRules(t, testName, selected, groups)
}

func alertValidationRunPromtoolRules(t *testing.T, testName string, rules []alertValidationPromtoolRule, groups []alertValidationPromtoolTestGroup) {
	t.Helper()
	promtool := alertValidationPromtoolPath(t)
	native := alertValidationPromtoolRuleFile{Groups: []alertValidationPromtoolRuleGroup{{Name: testName, Rules: rules}}}
	dir := t.TempDir()
	ruleBytes, err := yaml.Marshal(native)
	if err != nil {
		t.Fatal(err)
	}
	rulesPath := filepath.Join(dir, "rules.yml")
	if err := os.WriteFile(rulesPath, ruleBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	testBytes, err := yaml.Marshal(alertValidationPromtoolTestFile{
		RuleFiles: []string{rulesPath}, EvaluationInterval: "1m", Tests: groups,
	})
	if err != nil {
		t.Fatal(err)
	}
	testPath := filepath.Join(dir, "tests.yml")
	if err := os.WriteFile(testPath, testBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(promtool, "test", "rules", testPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("promtool rejected %s: %v\n%s", testName, err, output)
	}
}

func alertValidationExpectedForRule(t *testing.T, fixture alertValidationAlertFixture, mode alertValidationFixtureMode, alertName string) []alertValidationPromtoolExpectedAlert {
	t.Helper()
	rules, _ := alertValidationRuleInventory(t)
	rule, ok := rules[alertName]
	if !ok {
		t.Fatalf("Prometheus alert validation rule %q is missing", alertName)
	}
	return alertValidationFixtureExpected(fixture, mode, rule.Labels)
}

func TestAlertValidationAlertGroupPolicyAndPendingContract(t *testing.T) {
	contract := dataIntegrityLoadAlertContract(t)
	wantGroups := []struct {
		name     string
		count    int
		optional bool
	}{
		{name: "OpenStack Instance Exporter - Exporter and Source Health", count: 11},
		{name: "OpenStack Instance Exporter - Host Capacity and Shared-Resource Danger", count: 12},
		{name: "OpenStack Instance Exporter - High-Confidence Security Evidence", count: 10},
		{name: "OpenStack Instance Exporter - OPTIONAL Environment-Tuned Workload Heuristics", count: 45, optional: true},
	}
	if len(contract.Groups) != len(wantGroups) {
		t.Fatalf("Prometheus alert validation alert group count=%d, want %d", len(contract.Groups), len(wantGroups))
	}
	for index, want := range wantGroups {
		group := contract.Groups[index]
		if group.Name != want.name || len(group.Rules) != want.count {
			t.Fatalf("Prometheus alert validation alert group %d=%q/%d, want %q/%d", index, group.Name, len(group.Rules), want.name, want.count)
		}
		for _, rule := range group.Rules {
			if alertValidationDurationMinutes(t, rule.For) <= 0 {
				t.Fatalf("Prometheus alert validation alert %q has no nonzero pending interval", rule.Alert)
			}
			policy, hasPolicy := rule.Labels["policy"]
			if want.optional {
				if !hasPolicy || policy != "environment-tuned" {
					t.Fatalf("optional alert %q lacks environment-tuned policy label", rule.Alert)
				}
			} else if hasPolicy {
				t.Fatalf("default alert %q unexpectedly carries optional policy %q", rule.Alert, policy)
			}
		}
	}
}

func alertValidationOverrideMetric(series []alertValidationPromtoolInputSeries, metric string, value float64) []alertValidationPromtoolInputSeries {
	out := append([]alertValidationPromtoolInputSeries(nil), series...)
	for index := range out {
		if out[index].Series == metric || strings.HasPrefix(out[index].Series, metric+"{") {
			count := len(strings.Fields(out[index].Values))
			out[index].Values = alertValidationValues(count, func(int) float64 { return value })
		}
	}
	return out
}

func TestAlertValidationSeverityTiersAreMutuallyExclusiveWithPromtool(t *testing.T) {
	fixtures := alertValidationExecutableAlertFixtures()
	pairs := []struct {
		high, severe string
		metric       string
		highValue    float64
		severeValue  float64
	}{
		{high: "OpenStackInstanceAttentionHigh", severe: "OpenStackInstanceAttentionSevere", metric: "oie_instance_attention_severity", highValue: 60, severeValue: 85},
		{high: "OpenStackInstanceThreatScoreHigh", severe: "OpenStackInstanceThreatScoreSevere", metric: "oie_instance_threat_list_severity", highValue: 40, severeValue: 85},
		{high: "OpenStackInstanceBehaviorScoreHigh", severe: "OpenStackInstanceBehaviorScoreCritical", metric: "oie_instance_behavior_severity", highValue: 60, severeValue: 80},
		{high: "OpenStackInstanceHighResourcePressure", severe: "OpenStackInstanceSevereResourcePressure", metric: "oie_instance_resource_severity", highValue: 70, severeValue: 85},
		{high: "OpenStackInstanceResourceCPUHigh", severe: "OpenStackInstanceResourceCPUSevere", metric: "oie_instance_resource_cpu_severity", highValue: 70, severeValue: 85},
		{high: "OpenStackInstanceResourceMemHigh", severe: "OpenStackInstanceResourceMemSevere", metric: "oie_instance_resource_mem_severity", highValue: 70, severeValue: 85},
		{high: "OpenStackInstanceResourceDiskHigh", severe: "OpenStackInstanceResourceDiskSevere", metric: "oie_instance_resource_disk_severity", highValue: 70, severeValue: 85},
		{high: "OpenStackInstanceResourceNetHigh", severe: "OpenStackInstanceResourceNetSevere", metric: "oie_instance_resource_net_severity", highValue: 70, severeValue: 85},
	}
	alertNames := make([]string, 0, len(pairs)*2)
	groups := make([]alertValidationPromtoolTestGroup, 0, len(pairs)*2)
	for _, pair := range pairs {
		alertNames = append(alertNames, pair.high, pair.severe)
		for _, scenario := range []struct {
			name       string
			value      float64
			expected   string
			fixtureKey string
		}{
			{name: "high boundary", value: pair.highValue, expected: pair.high, fixtureKey: pair.high},
			{name: "severe boundary", value: pair.severeValue, expected: pair.severe, fixtureKey: pair.severe},
		} {
			fixture := fixtures[scenario.fixtureKey]
			inputs := alertValidationOverrideMetric(fixture.build(alertValidationFixtureLifecycle, 8, 99), pair.metric, scenario.value)
			highExpected := []alertValidationPromtoolExpectedAlert{}
			severeExpected := []alertValidationPromtoolExpectedAlert{}
			if scenario.expected == pair.high {
				highExpected = alertValidationExpectedForRule(t, fixtures[pair.high], alertValidationFixtureLifecycle, pair.high)
			} else {
				severeExpected = alertValidationExpectedForRule(t, fixtures[pair.severe], alertValidationFixtureLifecycle, pair.severe)
			}
			groups = append(groups, alertValidationPromtoolTestGroup{
				Name: scenario.name + " " + pair.metric, Interval: "1m", InputSeries: inputs,
				AlertRuleTest: []alertValidationPromtoolAlertTest{
					{EvalTime: "6m", Alert: pair.high, Expected: highExpected},
					{EvalTime: "6m", Alert: pair.severe, Expected: severeExpected},
				},
			})
		}
	}
	alertValidationRunSelectedPromtool(t, "Prometheus alert validation mutually exclusive severity tiers", alertNames, groups)
}

func TestAlertValidationConntrackCountBandsDoNotOverlapWithPromtool(t *testing.T) {
	const (
		burst     = "OpenStackInstanceConntrackFlowsBurst"
		sustained = "OpenStackInstanceHighConntrackFlowsSustained"
		zombie    = "OpenStackInstanceZombieFlowWarning"
	)
	fixtures := alertValidationExecutableAlertFixtures()
	base := fixtures[sustained].build(alertValidationFixtureLifecycle, 35, 99)
	groups := make([]alertValidationPromtoolTestGroup, 0, 6)
	for _, scenario := range []struct {
		name     string
		value    float64
		expected string
	}{
		{name: "at benign upper bound", value: 5000},
		{name: "zombie lower band", value: 5001, expected: zombie},
		{name: "zombie upper boundary", value: 20000, expected: zombie},
		{name: "burst lower band", value: 20001, expected: burst},
		{name: "burst upper boundary", value: 50000, expected: burst},
		{name: "sustained lower band", value: 50001, expected: sustained},
	} {
		expect := func(alert string) []alertValidationPromtoolExpectedAlert {
			if scenario.expected != alert {
				return []alertValidationPromtoolExpectedAlert{}
			}
			return alertValidationExpectedForRule(t, fixtures[alert], alertValidationFixtureLifecycle, alert)
		}
		groups = append(groups, alertValidationPromtoolTestGroup{
			Name: scenario.name, Interval: "1m",
			InputSeries: alertValidationOverrideMetric(base, "oie_instance_conntrack_ip_flows", scenario.value),
			AlertRuleTest: []alertValidationPromtoolAlertTest{
				{EvalTime: "31m", Alert: burst, Expected: expect(burst)},
				{EvalTime: "31m", Alert: sustained, Expected: expect(sustained)},
				{EvalTime: "31m", Alert: zombie, Expected: expect(zombie)},
			},
		})
	}
	alertValidationRunSelectedPromtool(t, "Prometheus alert validation exclusive conntrack count bands", []string{burst, sustained, zombie}, groups)
}

func TestAlertValidationMiningDefaultAndOptionalAlertsDoNotOverlapWithPromtool(t *testing.T) {
	const (
		warning   = "OpenStackInstanceMiningSuspected"
		candidate = "OpenStackInstanceMiningCandidatePersistent"
	)
	fixtures := alertValidationExecutableAlertFixtures()
	host := map[string]string{"instance": "node", "job": "openstack-instance-exporter"}
	health := func(samples int) []alertValidationPromtoolInputSeries {
		series := make([]alertValidationPromtoolInputSeries, 0, 3)
		for _, metric := range []string{"up", "oie_host_libvirt_ok", "oie_host_conntrack_raw_ok"} {
			series = append(series, alertValidationPromtoolInputSeries{
				Series: alertValidationSeries(metric, host), Values: alertValidationValues(samples, func(int) float64 { return 1 }),
			})
		}
		return series
	}
	mining := func(confidence string, samples int) alertValidationPromtoolInputSeries {
		return alertValidationPromtoolInputSeries{
			Series: alertValidationSeries("oie_instance_mining_suspected", alertValidationMiningLabels(confidence)),
			Values: alertValidationValues(samples, func(int) float64 { return 1 }),
		}
	}

	const samples = 22
	direct := append(health(samples), mining("high", samples))
	persistentNoCPU := append(health(samples), mining("high_persistent", samples))
	persistentHot := append(health(samples), mining("high_persistent", samples))
	persistentHot = append(persistentHot,
		alertValidationPromtoolInputSeries{Series: alertValidationSeries("oie_instance_cpu_vcpu_percent", alertValidationInstanceLabels()), Values: alertValidationValues(samples, func(int) float64 { return 60 })},
		alertValidationPromtoolInputSeries{Series: alertValidationSeries("oie_instance_resource_axis_fresh", alertValidationLabels(map[string]string{"axis": "cpu"})), Values: alertValidationValues(samples, func(int) float64 { return 1 })},
		alertValidationPromtoolInputSeries{Series: alertValidationSeries("oie_instance_resource_axis_last_success_timestamp_seconds", alertValidationLabels(map[string]string{"axis": "cpu"})), Values: alertValidationValues(samples, func(minute int) float64 { return float64(minute * 60) })},
	)
	mixed := append(health(samples), mining("high", samples))
	mixedLabels := alertValidationMiningLabels("high_persistent")
	mixedLabels["ip"] = "192.0.2.11"
	mixedLabels["port"] = "4444"
	mixed = append(mixed, alertValidationPromtoolInputSeries{
		Series: alertValidationSeries("oie_instance_mining_suspected", mixedLabels),
		Values: alertValidationValues(samples, func(int) float64 { return 1 }),
	})

	warningExpected := alertValidationExpectedForRule(t, fixtures[warning], alertValidationFixtureLifecycle, warning)
	candidateExpected := alertValidationExpectedForRule(t, fixtures[candidate], alertValidationFixtureLifecycle, candidate)
	groups := []alertValidationPromtoolTestGroup{
		{
			Name: "direct high confidence owns the incident", Interval: "1m", InputSeries: direct,
			AlertRuleTest: []alertValidationPromtoolAlertTest{
				{EvalTime: "16m", Alert: warning, Expected: warningExpected},
				{EvalTime: "16m", Alert: candidate, Expected: []alertValidationPromtoolExpectedAlert{}},
			},
		},
		{
			Name: "CPU corroboration promotes persistent evidence", Interval: "1m", InputSeries: persistentHot,
			AlertRuleTest: []alertValidationPromtoolAlertTest{
				{EvalTime: "16m", Alert: warning, Expected: warningExpected},
				{EvalTime: "16m", Alert: candidate, Expected: []alertValidationPromtoolExpectedAlert{}},
			},
		},
		{
			Name: "uncorroborated persistent evidence remains optional", Interval: "1m", InputSeries: persistentNoCPU,
			AlertRuleTest: []alertValidationPromtoolAlertTest{
				{EvalTime: "16m", Alert: warning, Expected: []alertValidationPromtoolExpectedAlert{}},
				{EvalTime: "16m", Alert: candidate, Expected: candidateExpected},
			},
		},
		{
			Name: "default evidence suppresses optional evidence for the same instance", Interval: "1m", InputSeries: mixed,
			AlertRuleTest: []alertValidationPromtoolAlertTest{
				{EvalTime: "16m", Alert: warning, Expected: warningExpected},
				{EvalTime: "16m", Alert: candidate, Expected: []alertValidationPromtoolExpectedAlert{}},
			},
		},
	}
	alertValidationRunSelectedPromtool(t, "Prometheus alert validation mining alert ownership", []string{warning, candidate}, groups)
}

func TestAlertValidationReplicaValuesCannotMultiplyAcrossTargetsWithPromtool(t *testing.T) {
	contacts := []struct {
		alert, metric, list string
	}{
		{alert: "OpenStackInstanceTorExitRepeatedContact", metric: "oie_instance_threat_tor_exit_contacts_total", list: "TOREXIT"},
		{alert: "OpenStackInstanceSpamhausRepeatedContact", metric: "oie_instance_threat_spamhaus_contacts_total", list: "spamhaus"},
		{alert: "OpenStackInstanceTorRelayRepeatedContact", metric: "oie_instance_threat_tor_relay_contacts_total", list: "TORRELAY"},
		{alert: "OpenStackInstanceEmergingThreatsRepeatedContact", metric: "oie_instance_threat_emergingthreats_contacts_total", list: "EMERGING"},
		{alert: "OpenStackInstanceCustomListRepeatedContact", metric: "oie_instance_threat_customlist_contacts_total", list: "CUSTOMLIST"},
	}
	contactAlerts := make([]string, 0, len(contacts))
	contactGroups := make([]alertValidationPromtoolTestGroup, 0, len(contacts))
	for _, contact := range contacts {
		contactAlerts = append(contactAlerts, contact.alert)
		series := make([]alertValidationPromtoolInputSeries, 0, 8)
		for _, node := range []string{"node-a", "node-b"} {
			labels := alertValidationLabels(map[string]string{"direction": "outbound"})
			labels["instance"] = node
			series = append(series, alertValidationPromtoolInputSeries{
				Series: alertValidationSeries(contact.metric, labels),
				Values: alertValidationValues(9, func(minute int) float64 { return float64(minute) * 0.6 }),
			})
			host := map[string]string{"instance": node, "job": "openstack-instance-exporter"}
			for _, metric := range []string{"up", "oie_host_libvirt_ok", "oie_host_conntrack_raw_ok"} {
				series = append(series, alertValidationPromtoolInputSeries{Series: alertValidationSeries(metric, host), Values: alertValidationValues(9, func(int) float64 { return 1 })})
			}
			freshLabels := alertValidationCopyLabels(host)
			freshLabels["list"] = contact.list
			series = append(series, alertValidationPromtoolInputSeries{Series: alertValidationSeries("oie_host_threat_feed_fresh", freshLabels), Values: alertValidationValues(9, func(int) float64 { return 1 })})
			series = append(series, alertValidationPromtoolInputSeries{Series: alertValidationSeries(alertValidationThreatRefreshErrorsMetric(contact.list), host), Values: alertValidationValues(9, func(int) float64 { return 0 })})
			series = append(series, alertValidationPromtoolInputSeries{Series: alertValidationSeries("oie_host_conntrack_read_errors_total", host), Values: alertValidationValues(9, func(int) float64 { return 0 })})
		}
		contactGroups = append(contactGroups, alertValidationPromtoolTestGroup{
			Name: contact.alert + " replicas remain individually below threshold", Interval: "1m", InputSeries: series,
			AlertRuleTest: []alertValidationPromtoolAlertTest{{EvalTime: "7m", Alert: contact.alert, Expected: []alertValidationPromtoolExpectedAlert{}}},
		})
	}
	alertValidationRunSelectedPromtool(t, "Prometheus alert validation repeated-contact replica lower bounds", contactAlerts, contactGroups)

	disks := []struct {
		alert, metric string
	}{
		{alert: "OpenStackInstanceHighDiskGBReadTotalLongTerm", metric: "oie_instance_disk_read_gbytes_total"},
		{alert: "OpenStackInstanceHighDiskGBWriteTotalLongTerm", metric: "oie_instance_disk_write_gbytes_total"},
	}
	diskAlerts := make([]string, 0, len(disks))
	diskGroups := make([]alertValidationPromtoolTestGroup, 0, len(disks))
	for _, disk := range disks {
		diskAlerts = append(diskAlerts, disk.alert)
		series := make([]alertValidationPromtoolInputSeries, 0, 6)
		for _, node := range []string{"node-a", "node-b"} {
			labels := alertValidationLabels(map[string]string{"disk_path": "vda", "disk_type": "volumes", "volume_uuid": "volume"})
			labels["instance"] = node
			series = append(series, alertValidationPromtoolInputSeries{
				Series: alertValidationSeries(disk.metric, labels),
				Values: alertValidationValues(724, func(minute int) float64 { return float64(minute) * 0.5 }),
			})
			host := map[string]string{"instance": node, "job": "openstack-instance-exporter"}
			for _, metric := range []string{"up", "oie_host_libvirt_ok"} {
				series = append(series, alertValidationPromtoolInputSeries{Series: alertValidationSeries(metric, host), Values: alertValidationValues(724, func(int) float64 { return 1 })})
			}
		}
		diskGroups = append(diskGroups, alertValidationPromtoolTestGroup{
			Name: disk.alert + " replicas remain individually below threshold", Interval: "1m", InputSeries: series,
			AlertRuleTest: []alertValidationPromtoolAlertTest{{EvalTime: "721m", Alert: disk.alert, Expected: []alertValidationPromtoolExpectedAlert{}}},
		})

		distinct := make([]alertValidationPromtoolInputSeries, 0, 4)
		for _, identity := range []struct{ path, volume string }{{path: "vda", volume: "volume-a"}, {path: "vdb", volume: "volume-b"}} {
			labels := alertValidationLabels(map[string]string{"disk_path": identity.path, "disk_type": "volumes", "volume_uuid": identity.volume})
			distinct = append(distinct, alertValidationPromtoolInputSeries{
				Series: alertValidationSeries(disk.metric, labels),
				Values: alertValidationValues(724, func(minute int) float64 { return float64(minute) * 0.5 }),
			})
		}
		host := map[string]string{"instance": "node", "job": "openstack-instance-exporter"}
		for _, metric := range []string{"up", "oie_host_libvirt_ok"} {
			distinct = append(distinct, alertValidationPromtoolInputSeries{
				Series: alertValidationSeries(metric, host), Values: alertValidationValues(724, func(int) float64 { return 1 }),
			})
		}
		diskGroups = append(diskGroups, alertValidationPromtoolTestGroup{
			Name: disk.alert + " sums distinct stable disk identities", Interval: "1m", InputSeries: distinct,
			AlertRuleTest: []alertValidationPromtoolAlertTest{{
				EvalTime: "721m", Alert: disk.alert,
				Expected: alertValidationExpectedForRule(t, alertValidationExecutableAlertFixtures()[disk.alert], alertValidationFixtureLifecycle, disk.alert),
			}},
		})
	}
	alertValidationRunSelectedPromtool(t, "Prometheus alert validation long-term disk replica lower bounds", diskAlerts, diskGroups)
}

func TestAlertValidationRepeatedContactRejectsHiddenSourceOutagesAndCounterResetsWithPromtool(t *testing.T) {
	contacts := []struct {
		alert, metric, list string
	}{
		{alert: "OpenStackInstanceTorExitRepeatedContact", metric: "oie_instance_threat_tor_exit_contacts_total", list: "TOREXIT"},
		{alert: "OpenStackInstanceSpamhausRepeatedContact", metric: "oie_instance_threat_spamhaus_contacts_total", list: "spamhaus"},
		{alert: "OpenStackInstanceTorRelayRepeatedContact", metric: "oie_instance_threat_tor_relay_contacts_total", list: "TORRELAY"},
		{alert: "OpenStackInstanceEmergingThreatsRepeatedContact", metric: "oie_instance_threat_emergingthreats_contacts_total", list: "EMERGING"},
		{alert: "OpenStackInstanceCustomListRepeatedContact", metric: "oie_instance_threat_customlist_contacts_total", list: "CUSTOMLIST"},
	}
	const samples = 9
	host := map[string]string{"instance": "node", "job": "openstack-instance-exporter"}
	alerts := make([]string, 0, len(contacts))
	groups := make([]alertValidationPromtoolTestGroup, 0, len(contacts)*3)
	for _, contact := range contacts {
		alerts = append(alerts, contact.alert)
		build := func(contactValues, refreshErrorValues, conntrackErrorValues string) []alertValidationPromtoolInputSeries {
			series := []alertValidationPromtoolInputSeries{{
				Series: alertValidationSeries(contact.metric, alertValidationLabels(map[string]string{"direction": "outbound"})), Values: contactValues,
			}}
			for _, metric := range []string{"up", "oie_host_libvirt_ok", "oie_host_conntrack_raw_ok"} {
				series = append(series, alertValidationPromtoolInputSeries{
					Series: alertValidationSeries(metric, host), Values: alertValidationValues(samples, func(int) float64 { return 1 }),
				})
			}
			for _, list := range alertValidationThreatFeedLists {
				value := float64(-1)
				if list == contact.list {
					value = 1
				}
				labels := alertValidationCopyLabels(host)
				labels["list"] = list
				series = append(series, alertValidationPromtoolInputSeries{
					Series: alertValidationSeries("oie_host_threat_feed_fresh", labels), Values: alertValidationValues(samples, func(int) float64 { return value }),
				})
			}
			series = append(series,
				alertValidationPromtoolInputSeries{Series: alertValidationSeries(alertValidationThreatRefreshErrorsMetric(contact.list), host), Values: refreshErrorValues},
				alertValidationPromtoolInputSeries{Series: alertValidationSeries("oie_host_conntrack_read_errors_total", host), Values: conntrackErrorValues},
			)
			return series
		}
		qualifyingContacts := alertValidationValues(samples, func(minute int) float64 { return float64(minute * 10) })
		zeroErrors := alertValidationValues(samples, func(int) float64 { return 0 })
		recentError := "0 0 0 0 1 1 1 1 1"
		for _, scenario := range []struct {
			name, contacts, refreshErrors, conntrackErrors string
		}{
			{name: "feed refresh error inside contact lookback", contacts: qualifyingContacts, refreshErrors: recentError, conntrackErrors: zeroErrors},
			{name: "conntrack read error inside contact lookback", contacts: qualifyingContacts, refreshErrors: zeroErrors, conntrackErrors: recentError},
			{name: "exporter counter reset cannot manufacture contact growth", contacts: "100 101 102 0 0 1 2 2 2", refreshErrors: "10 10 10 0 0 0 0 0 0", conntrackErrors: "10 10 10 0 0 0 0 0 0"},
		} {
			groups = append(groups, alertValidationPromtoolTestGroup{
				Name: contact.alert + " " + scenario.name, Interval: "1m",
				InputSeries:   build(scenario.contacts, scenario.refreshErrors, scenario.conntrackErrors),
				AlertRuleTest: []alertValidationPromtoolAlertTest{{EvalTime: "7m", Alert: contact.alert, Expected: []alertValidationPromtoolExpectedAlert{}}},
			})
		}
	}
	alertValidationRunSelectedPromtool(t, "Prometheus alert validation repeated-contact hidden outage and reset rejection", alerts, groups)
}

func TestAlertValidationThreatFeedTriStateAndRestartSemanticsWithPromtool(t *testing.T) {
	const (
		attention = "OpenStackInstanceAttentionHigh"
		threat    = "OpenStackInstanceThreatScoreHigh"
		host      = "OpenStackInstanceExporterHostThreatListed"
		contact   = "OpenStackInstanceTorExitRepeatedContact"
		stale     = "OpenStackInstanceExporterTorExitListRefreshStale"
	)
	fixtures := alertValidationExecutableAlertFixtures()
	setFeed := func(series []alertValidationPromtoolInputSeries, list, values string) []alertValidationPromtoolInputSeries {
		out := append([]alertValidationPromtoolInputSeries(nil), series...)
		for index := range out {
			if strings.HasPrefix(out[index].Series, "oie_host_threat_feed_fresh{") && strings.Contains(out[index].Series, `list="`+list+`"`) {
				out[index].Values = values
			}
		}
		return out
	}
	constant := func(samples int, value float64) string {
		return alertValidationValues(samples, func(int) float64 { return value })
	}
	retained := func(samples, presentSamples int, value float64) string {
		values := strings.Fields(constant(samples, value))
		for index := presentSamples; index < len(values); index++ {
			values[index] = "_"
		}
		return strings.Join(values, " ")
	}

	groups := make([]alertValidationPromtoolTestGroup, 0, 9)
	for _, scenario := range []struct {
		name, alert string
		samples     int
		eval        string
		oldValue    float64
		present     int
	}{
		{name: "retained fresh feed cannot enable attention", alert: attention, samples: 8, eval: "6m", oldValue: 1, present: 4},
		{name: "retained fresh feed cannot enable threat score", alert: threat, samples: 8, eval: "6m", oldValue: 1, present: 4},
		{name: "retained fresh feed cannot enable host membership", alert: host, samples: 4, eval: "2m", oldValue: 1, present: 1},
		{name: "retained fresh feed cannot enable repeated contact", alert: contact, samples: 9, eval: "7m", oldValue: 1, present: 5},
		{name: "retained stale feed cannot alert after disable", alert: stale, samples: 13, eval: "11m", oldValue: 0, present: 9},
	} {
		inputs := fixtures[scenario.alert].build(alertValidationFixtureLifecycle, scenario.samples, scenario.samples+1)
		inputs = setFeed(inputs, "TOREXIT", retained(scenario.samples, scenario.present, scenario.oldValue))
		groups = append(groups, alertValidationPromtoolTestGroup{
			Name: scenario.name, Interval: "1m", InputSeries: inputs,
			AlertRuleTest: []alertValidationPromtoolAlertTest{{EvalTime: scenario.eval, Alert: scenario.alert, Expected: []alertValidationPromtoolExpectedAlert{}}},
		})
	}

	for _, scenario := range []struct {
		name, alert string
	}{
		{name: "one fresh feed keeps attention eligible despite another stale feed", alert: attention},
		{name: "one fresh feed keeps threat score eligible despite another stale feed", alert: threat},
	} {
		inputs := fixtures[scenario.alert].build(alertValidationFixtureLifecycle, 8, 99)
		inputs = setFeed(inputs, "TOREXIT", constant(8, 1))
		inputs = setFeed(inputs, "spamhaus", constant(8, 0))
		groups = append(groups, alertValidationPromtoolTestGroup{
			Name: scenario.name, Interval: "1m", InputSeries: inputs,
			AlertRuleTest: []alertValidationPromtoolAlertTest{{
				EvalTime: "6m", Alert: scenario.alert,
				Expected: alertValidationExpectedForRule(t, fixtures[scenario.alert], alertValidationFixtureLifecycle, scenario.alert),
			}},
		})
	}

	for _, scenario := range []struct {
		name, alert string
		samples     int
		eval        string
	}{
		{name: "disabled feed cannot enable host membership", alert: host, samples: 4, eval: "2m"},
		{name: "disabled feed cannot enable repeated contact", alert: contact, samples: 9, eval: "7m"},
		{name: "disabled feed is not stale", alert: stale, samples: 13, eval: "11m"},
	} {
		inputs := fixtures[scenario.alert].build(alertValidationFixtureLifecycle, scenario.samples, scenario.samples+1)
		inputs = setFeed(inputs, "TOREXIT", constant(scenario.samples, -1))
		groups = append(groups, alertValidationPromtoolTestGroup{
			Name: scenario.name, Interval: "1m", InputSeries: inputs,
			AlertRuleTest: []alertValidationPromtoolAlertTest{{EvalTime: scenario.eval, Alert: scenario.alert, Expected: []alertValidationPromtoolExpectedAlert{}}},
		})
	}

	alertValidationRunSelectedPromtool(t, "Prometheus alert validation threat-feed tri-state and restart semantics", []string{attention, threat, host, contact, stale}, groups)
}

func TestAlertValidationSourceHealthStagesArePointDisjointWithPromtool(t *testing.T) {
	pairs := []struct {
		early, stale          string
		okMetric, staleMetric string
	}{
		{
			early: "OpenStackInstanceExporterConntrackRawReaderFailed", stale: "OpenStackInstanceExporterConntrackReadStale",
			okMetric: "oie_host_conntrack_raw_ok", staleMetric: "oie_host_conntrack_stale_seconds",
		},
		{
			early: "OpenStackInstanceExporterLibvirtCollectionUnhealthy", stale: "OpenStackInstanceExporterLibvirtDataStale",
			okMetric: "oie_host_libvirt_ok", staleMetric: "oie_host_libvirt_stale_seconds",
		},
	}
	fixtures := alertValidationExecutableAlertFixtures()
	alerts := make([]string, 0, len(pairs)*2)
	groups := make([]alertValidationPromtoolTestGroup, 0, len(pairs))
	for _, pair := range pairs {
		alerts = append(alerts, pair.early, pair.stale)
		host := map[string]string{"instance": "node", "job": "openstack-instance-exporter"}
		series := []alertValidationPromtoolInputSeries{
			{Series: alertValidationSeries(pair.okMetric, host), Values: "0 0 0 0 0 0 0"},
			{Series: alertValidationSeries(pair.staleMetric, host), Values: "0 61 121 181 241 301 361"},
			{Series: alertValidationSeries("up", host), Values: "1 1 1 1 1 1 1"},
		}
		earlyExpected := alertValidationExpectedForRule(t, fixtures[pair.early], alertValidationFixtureLifecycle, pair.early)
		staleExpected := alertValidationExpectedForRule(t, fixtures[pair.stale], alertValidationFixtureLifecycle, pair.stale)
		groups = append(groups, alertValidationPromtoolTestGroup{
			Name: pair.early + " and stale stages are point-disjoint", Interval: "1m", InputSeries: series,
			AlertRuleTest: []alertValidationPromtoolAlertTest{
				{EvalTime: "1m", Alert: pair.early, Expected: []alertValidationPromtoolExpectedAlert{}},
				{EvalTime: "1m", Alert: pair.stale, Expected: []alertValidationPromtoolExpectedAlert{}},
				{EvalTime: "2m", Alert: pair.early, Expected: earlyExpected},
				{EvalTime: "2m", Alert: pair.stale, Expected: []alertValidationPromtoolExpectedAlert{}},
				{EvalTime: "3m", Alert: pair.early, Expected: earlyExpected},
				{EvalTime: "3m", Alert: pair.stale, Expected: []alertValidationPromtoolExpectedAlert{}},
				{EvalTime: "4m", Alert: pair.early, Expected: []alertValidationPromtoolExpectedAlert{}},
				{EvalTime: "4m", Alert: pair.stale, Expected: []alertValidationPromtoolExpectedAlert{}},
				{EvalTime: "5m", Alert: pair.early, Expected: []alertValidationPromtoolExpectedAlert{}},
				{EvalTime: "5m", Alert: pair.stale, Expected: []alertValidationPromtoolExpectedAlert{}},
				{EvalTime: "6m", Alert: pair.early, Expected: []alertValidationPromtoolExpectedAlert{}},
				{EvalTime: "6m", Alert: pair.stale, Expected: staleExpected},
			},
		})
	}
	alertValidationRunSelectedPromtool(t, "Prometheus alert validation point-disjoint source-health stages", alerts, groups)
}
