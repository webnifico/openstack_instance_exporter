package main

import (
	"fmt"
	"testing"
)

func alertValidationPartialDisabledFeedInputs(attentionSeverity float64) []alertValidationPromtoolInputSeries {
	const samples = 13
	series := make([]alertValidationPromtoolInputSeries, 0, 40)
	for index := 0; index < 10; index++ {
		labels := alertValidationInstanceLabels()
		labels["instance_uuid"] = fmt.Sprintf("vm-%02d", index)
		series = append(series, alertValidationPromtoolInputSeries{
			Series: alertValidationSeries("oie_instance_attention_severity", labels),
			Values: alertValidationValues(samples, func(int) float64 { return attentionSeverity }),
		})
		for _, metric := range []string{"oie_instance_resource_axis_fresh", "oie_instance_resource_axis_available"} {
			axisLabels := alertValidationCopyLabels(labels)
			axisLabels["axis"] = "cpu"
			series = append(series, alertValidationPromtoolInputSeries{
				Series: alertValidationSeries(metric, axisLabels),
				Values: alertValidationValues(samples, func(int) float64 { return 1 }),
			})
		}
	}

	host := map[string]string{"instance": "node", "job": "openstack-instance-exporter"}
	for _, metric := range []string{"up", "oie_host_libvirt_ok", "oie_host_conntrack_raw_ok"} {
		series = append(series, alertValidationPromtoolInputSeries{
			Series: alertValidationSeries(metric, host),
			Values: alertValidationValues(samples, func(int) float64 { return 1 }),
		})
	}
	// CUSTOMLIST is deliberately missing. Four current disabled series must not
	// be mistaken for the fixed five-series "all feeds disabled" state.
	for _, list := range []string{"TOREXIT", "TORRELAY", "spamhaus", "EMERGING"} {
		labels := alertValidationCopyLabels(host)
		labels["list"] = list
		series = append(series, alertValidationPromtoolInputSeries{
			Series: alertValidationSeries("oie_host_threat_feed_fresh", labels),
			Values: alertValidationValues(samples, func(int) float64 { return -1 }),
		})
	}
	return series
}

func TestAlertValidationPartialDisabledFeedFamilyCannotEnableAttentionWithPromtool(t *testing.T) {
	const (
		high    = "OpenStackInstanceAttentionHigh"
		severe  = "OpenStackInstanceAttentionSevere"
		project = "OpenStackProjectManyHotInstances"
	)
	empty := []alertValidationPromtoolExpectedAlert{}
	alertValidationRunSelectedPromtool(t, "Prometheus alert validation fixed five disabled feed gate", []string{high, severe, project}, []alertValidationPromtoolTestGroup{
		{
			Name:        "four disabled and one missing cannot enable high attention",
			Interval:    "1m",
			InputSeries: alertValidationPartialDisabledFeedInputs(70),
			AlertRuleTest: []alertValidationPromtoolAlertTest{
				{EvalTime: "11m", Alert: high, Expected: empty},
				{EvalTime: "11m", Alert: project, Expected: empty},
			},
		},
		{
			Name:        "four disabled and one missing cannot enable severe attention",
			Interval:    "1m",
			InputSeries: alertValidationPartialDisabledFeedInputs(90),
			AlertRuleTest: []alertValidationPromtoolAlertTest{
				{EvalTime: "11m", Alert: severe, Expected: empty},
				{EvalTime: "11m", Alert: project, Expected: empty},
			},
		},
	})
}
