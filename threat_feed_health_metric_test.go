package main

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func alertValidationThreatFeedFreshValues(t *testing.T, metrics []prometheus.Metric) map[string]float64 {
	t.Helper()
	values := make(map[string]float64)
	for _, metric := range metrics {
		if !strings.Contains(metric.Desc().String(), `fqName: "oie_host_threat_feed_fresh"`) {
			continue
		}
		var encoded dto.Metric
		if err := metric.Write(&encoded); err != nil {
			t.Fatal(err)
		}
		list := ""
		for _, label := range encoded.Label {
			if label.GetName() == "list" {
				list = label.GetValue()
			}
		}
		if list == "" {
			t.Fatalf("feed freshness sample has no list label: %s", encoded.String())
		}
		if _, duplicate := values[list]; duplicate {
			t.Fatalf("duplicate feed freshness sample for %q", list)
		}
		values[list] = encoded.GetGauge().GetValue()
	}
	return values
}

func TestAlertValidationThreatFeedFreshMetricMirrorsUsableSnapshotContract(t *testing.T) {
	now := time.Now()
	fresh := newThreatStateTestProvider("TorExit")
	fresh.LogTag = "TOREXIT"
	fresh.EntryCount = 10
	fresh.LastSuccess = float64(now.Add(-time.Minute).Unix())

	stale := newThreatStateTestProvider("TorRelay")
	stale.LogTag = "TORRELAY"
	stale.EntryCount = 10
	stale.LastSuccess = float64(now.Add(-3 * time.Hour).Unix())

	oneShot := newThreatStateTestProvider("CustomList")
	oneShot.LogTag = "CUSTOMLIST"
	oneShot.RefreshInterval = 0
	oneShot.EntryCount = 1
	oneShot.LastSuccess = float64(now.Add(-30 * 24 * time.Hour).Unix())

	empty := newThreatStateTestProvider("EmergingThreats")
	empty.LogTag = "EMERGING"
	empty.EntryCount = 0
	empty.LastSuccess = float64(now.Unix())

	disabled := newThreatStateTestProvider("Disabled")
	disabled.LogTag = "DISABLED"
	disabled.Enabled = false
	disabled.EntryCount = 1
	disabled.LastSuccess = float64(now.Unix())

	tm := newThreatStateTestManager(fresh, stale, oneShot, empty, disabled)
	tm.spamEnabled = true
	tm.spamRefresh = 6 * time.Hour
	tm.spamEntries = 1
	tm.spamLastSuccessUnix = float64(now.Add(-13 * time.Hour).Unix())

	metrics := make([]prometheus.Metric, 0, 32)
	tm.collectHostThreatMetrics(&metrics)
	values := alertValidationThreatFeedFreshValues(t, metrics)
	want := map[string]float64{
		"TOREXIT":    1,
		"TORRELAY":   0,
		"CUSTOMLIST": 1,
		"EMERGING":   0,
		"spamhaus":   0,
	}
	if len(values) != len(want) {
		t.Fatalf("feed freshness samples=%v, want %v", values, want)
	}
	for list, expected := range want {
		if got, ok := values[list]; !ok || got != expected {
			t.Errorf("feed freshness %s=(%v,%v), want (%v,true)", list, got, ok, expected)
		}
	}
	if _, exists := values["DISABLED"]; exists {
		t.Fatal("unknown feed emitted a freshness series")
	}
}

func TestAlertValidationThreatFeedFreshMetricUsesFixedTriStateSeries(t *testing.T) {
	tm := newThreatStateTestManager()
	metrics := make([]prometheus.Metric, 0, 16)
	tm.collectHostThreatMetrics(&metrics)
	values := alertValidationThreatFeedFreshValues(t, metrics)
	want := map[string]float64{
		"TOREXIT":    -1,
		"TORRELAY":   -1,
		"EMERGING":   -1,
		"CUSTOMLIST": -1,
		"spamhaus":   -1,
	}
	if len(values) != len(want) {
		t.Fatalf("feed state samples=%v, want fixed set %v", values, want)
	}
	for list, expected := range want {
		if got, ok := values[list]; !ok || got != expected {
			t.Errorf("feed state %s=(%v,%v), want (%v,true)", list, got, ok, expected)
		}
	}
}

func TestAlertValidationThreatFeedFreshMetricRejectsNeverLoadedAndFutureSnapshots(t *testing.T) {
	now := time.Now()
	neverLoaded := newThreatStateTestProvider("TorExit")
	neverLoaded.LogTag = "TOREXIT"
	neverLoaded.EntryCount = 1
	neverLoaded.LastSuccess = 0

	future := newThreatStateTestProvider("TorRelay")
	future.LogTag = "TORRELAY"
	future.EntryCount = 1
	future.LastSuccess = float64(now.Add(6 * time.Minute).Unix())

	tm := newThreatStateTestManager(neverLoaded, future)
	metrics := make([]prometheus.Metric, 0, 16)
	tm.collectHostThreatMetrics(&metrics)
	values := alertValidationThreatFeedFreshValues(t, metrics)
	if values["TOREXIT"] != 0 || values["TORRELAY"] != 0 {
		t.Fatalf("invalid feed snapshots reported fresh: %v", values)
	}
}

func TestAlertValidationThreatSourceSetChangeSilentlyRebaselinesEWMA(t *testing.T) {
	mc := &MetricsCollector{
		intelHistory:  make(map[string]*IntelHistory),
		threatEWMATau: 150 * time.Second,
	}
	if got := mc.updateIntelHistoryForSourceSet("vm", 0.8, 100, "TOREXIT"); got != 0.8 {
		t.Fatalf("initial EWMA=%v, want 0.8", got)
	}
	if got := mc.updateIntelHistoryForSourceSet("vm", 0.2, 115, "spamhaus"); got != 0.2 {
		t.Fatalf("changed-source EWMA=%v, want silent 0.2 rebaseline", got)
	}
	got := mc.updateIntelHistoryForSourceSet("vm", 0.8, 130, "spamhaus")
	want := 0.2 + ewmaAlpha(15, 150)*(0.8-0.2)
	if math.Abs(got-want) > 1e-12 {
		t.Fatalf("same-source EWMA=%v, want elapsed-time update %v", got, want)
	}
	history := mc.intelHistory["vm"]
	if history == nil || !history.SourceSetKnown || history.SourceSet != "spamhaus" {
		t.Fatalf("source-set history=%#v", history)
	}
}

func TestAlertValidationThreatSourceSetFingerprintIsDeterministicAndBounded(t *testing.T) {
	agg := &ConntrackAgg{
		SpamhausSourceIncluded: true,
		ProviderSourcesIncluded: map[string]struct{}{
			"TorExit":         {},
			"EmergingThreats": {},
		},
	}
	want := "EmergingThreats\x00TorExit\x00spamhaus"
	for i := 0; i < 20; i++ {
		if got := threatSourceSetFingerprint(agg); got != want {
			t.Fatalf("source-set fingerprint=%q, want %q", got, want)
		}
	}
	if got := threatSourceSetFingerprint(nil); got != "" {
		t.Fatalf("nil aggregate fingerprint=%q, want empty", got)
	}
}
