package main

import (
	"context"
	"net"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	libvirt "github.com/digitalocean/go-libvirt"
	"github.com/prometheus/client_golang/prometheus"
)

func newCollectorOrchestrationTestCollector(t *testing.T) *MetricsCollector {
	t.Helper()
	mc, err := NewMetricsCollector(CollectorConfig{
		LibvirtURI:          "qemu:///system",
		WorkerCount:         2,
		CollectionInterval:  time.Hour,
		ConntrackIPv4Enable: false,
		ConntrackIPv6Enable: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { close(mc.shutdownChan) })
	return mc
}

func TestCollectionLagHandlesFirstFutureAndPastCycles(t *testing.T) {
	mc := &MetricsCollector{}
	if got := mc.collectionLagSeconds(); got != 0 {
		t.Fatalf("first collection lag=%v, want 0", got)
	}
	mc.lastCycleEndUnixNano = time.Now().Add(time.Minute).UnixNano()
	if got := mc.collectionLagSeconds(); got != 0 {
		t.Fatalf("future collection lag=%v, want 0", got)
	}
	mc.lastCycleEndUnixNano = time.Now().Add(-50 * time.Millisecond).UnixNano()
	if got := mc.collectionLagSeconds(); got < 0.04 || got > 0.5 {
		t.Fatalf("past collection lag=%v, want approximately 0.05", got)
	}
}

func TestCollectHeavyPreservesCachedCycleOnLibvirtFailure(t *testing.T) {
	desc := prometheus.NewDesc("test_collect_heavy_cached", "test", nil, nil)
	want := prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, 7)
	mc, err := NewMetricsCollector(CollectorConfig{
		LibvirtURI:          filepath.Join(t.TempDir(), "missing-libvirt.sock"),
		CollectionInterval:  time.Hour,
		ConntrackIPv4Enable: false,
		ConntrackIPv6Enable: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer close(mc.shutdownChan)
	mc.cachedMetrics = []prometheus.Metric{want}
	ch := make(chan prometheus.Metric, 128)
	mc.collectHeavy(ch)
	foundCached := false
	for len(ch) > 0 {
		if <-ch == want {
			foundCached = true
		}
	}
	if !foundCached {
		t.Fatal("libvirt failure did not preserve the last-good domain metric")
	}
	if mc.lastCycleEndUnixNano <= 0 || mc.hostCollectionErrors != 1 {
		t.Fatalf("fallback state last_end=%d errors=%d", mc.lastCycleEndUnixNano, mc.hostCollectionErrors)
	}
}

func TestCollectHeavyOverlaysLiveHealthOnCachedLibvirtFallback(t *testing.T) {
	desc := prometheus.NewDesc("test_cached_domain_metric", "test", nil, nil)
	mc, err := NewMetricsCollector(CollectorConfig{
		LibvirtURI:          filepath.Join(t.TempDir(), "missing-libvirt.sock"),
		CollectionInterval:  time.Hour,
		ConntrackIPv4Enable: true,
		ConntrackIPv6Enable: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer close(mc.shutdownChan)

	lastConntrackSuccess := time.Now().Add(-30 * time.Second).Unix()
	atomic.StoreUint64(&mc.cm.conntrackRawOK, 1)
	atomic.StoreUint64(&mc.cm.conntrackReadErrors, 3)
	atomic.StoreUint64(&mc.cm.conntrackRawENOBUFSTotal, 4)
	atomic.StoreUint64(&mc.cm.conntrackRawParseErrorsTotal, 5)
	atomic.StoreInt64(&mc.cm.conntrackLastSuccessUnix, lastConntrackSuccess)
	provider := mc.tm.Providers[0]
	provider.Enabled = true
	provider.LastSuccess = 1234
	provider.LastDuration = 2
	provider.EntryCount = 3
	atomic.StoreUint64(&provider.ErrorCount, 4)
	mc.tm.spamEnabled = true
	mc.tm.spamLastSuccessUnix = 2345
	mc.tm.spamLastRefreshSeconds = 5
	mc.tm.spamEntries = 6
	atomic.StoreUint64(&mc.tm.spamRefreshErrors, 7)
	mc.tm.hostThreatsEnabled = true
	mc.tm.hostThreatHits = nil
	mc.hostCpuState.initialized = true
	mc.hostCpuState.prevTotal = 0
	mc.hostCpuState.prevIdle = 0
	mc.cachedMetrics = []prometheus.Metric{
		prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, 7),
		prometheus.MustNewConstMetric(mc.hostCollectionErrorsTotalDesc, prometheus.CounterValue, 0),
		prometheus.MustNewConstMetric(mc.hostCollectionCycleDurationSecondsDesc, prometheus.GaugeValue, 99),
		prometheus.MustNewConstMetric(mc.hostCollectionCycleLagSecondsDesc, prometheus.GaugeValue, 99),
		prometheus.MustNewConstMetric(mc.hostLibvirtListDurationSecondsDesc, prometheus.GaugeValue, 99),
		prometheus.MustNewConstMetric(mc.hostConntrackReadDurationSecondsDesc, prometheus.GaugeValue, 99),
		prometheus.MustNewConstMetric(mc.hostCacheCleanupDurationSecondsDesc, prometheus.GaugeValue, 99),
		prometheus.MustNewConstMetric(mc.hostConntrackRawOkDesc, prometheus.GaugeValue, 0),
		prometheus.MustNewConstMetric(mc.hostConntrackRawENOBUFSTotalDesc, prometheus.CounterValue, 0),
		prometheus.MustNewConstMetric(mc.hostConntrackRawParseErrorsTotalDesc, prometheus.CounterValue, 0),
		prometheus.MustNewConstMetric(mc.hostConntrackReadErrorsTotalDesc, prometheus.CounterValue, 0),
		prometheus.MustNewConstMetric(mc.hostConntrackLastSuccessTimestampDesc, prometheus.GaugeValue, float64(lastConntrackSuccess)),
		prometheus.MustNewConstMetric(mc.hostConntrackStaleSecondsDesc, prometheus.GaugeValue, 0),
		prometheus.MustNewConstMetric(mc.hostGoHeapAllocBytesDesc, prometheus.GaugeValue, 0),
		prometheus.MustNewConstMetric(mc.hostMemTotalMBDesc, prometheus.GaugeValue, -1),
		prometheus.MustNewConstMetric(mc.hostCpuUsagePercentDesc, prometheus.GaugeValue, -1),
		prometheus.MustNewConstMetric(mc.hostMemFreeMBDesc, prometheus.GaugeValue, -1),
		prometheus.MustNewConstMetric(mc.hostMemAvailableMBDesc, prometheus.GaugeValue, -1),
		prometheus.MustNewConstMetric(provider.HostRefreshLastSuccessDesc, prometheus.GaugeValue, 0),
		prometheus.MustNewConstMetric(provider.HostRefreshDurationDesc, prometheus.GaugeValue, 0),
		prometheus.MustNewConstMetric(provider.HostRefreshErrorsDesc, prometheus.CounterValue, 0),
		prometheus.MustNewConstMetric(provider.HostEntriesDesc, prometheus.GaugeValue, 0),
		prometheus.MustNewConstMetric(mc.tm.hostSpamhausRefreshLastSuccessTimestampDesc, prometheus.GaugeValue, 0),
		prometheus.MustNewConstMetric(mc.tm.hostSpamhausRefreshDurationSecondsDesc, prometheus.GaugeValue, 0),
		prometheus.MustNewConstMetric(mc.tm.hostSpamhausRefreshErrorsTotalDesc, prometheus.CounterValue, 0),
		prometheus.MustNewConstMetric(mc.tm.hostSpamhausEntriesDesc, prometheus.GaugeValue, 0),
		prometheus.MustNewConstMetric(mc.tm.hostThreatListedDesc, prometheus.GaugeValue, 1, "stale", "192.0.2.1", "ipv4"),
	}

	ch := make(chan prometheus.Metric, 64)
	mc.collectHeavy(ch)
	close(ch)
	metrics := make([]prometheus.Metric, 0, len(ch))
	for metric := range ch {
		metrics = append(metrics, metric)
	}
	registry := prometheus.NewRegistry()
	registry.MustRegister(staticMetricCollector{metrics: metrics})
	families, err := registry.Gather()
	if err != nil {
		t.Fatalf("cached fallback emitted duplicate or invalid metrics: %v", err)
	}
	values := make(map[string]float64, len(families))
	for _, family := range families {
		if len(family.Metric) != 1 {
			t.Fatalf("metric family %s has %d samples, want 1", family.GetName(), len(family.Metric))
		}
		sample := family.Metric[0]
		var value float64
		switch {
		case sample.Gauge != nil:
			value = sample.GetGauge().GetValue()
		case sample.Counter != nil:
			value = sample.GetCounter().GetValue()
		default:
			t.Fatalf("metric family %s has no scalar value", family.GetName())
		}
		values[family.GetName()] = value
	}

	if values["test_cached_domain_metric"] != 7 {
		t.Fatalf("last-good domain metric=%v, want 7", values["test_cached_domain_metric"])
	}
	if values["oie_host_collection_errors_total"] != 1 {
		t.Fatalf("collection error counter=%v, want current value 1", values["oie_host_collection_errors_total"])
	}
	for _, name := range []string{
		"oie_host_collection_cycle_duration_seconds",
		"oie_host_collection_cycle_lag_seconds",
		"oie_host_libvirt_list_duration_seconds",
		"oie_host_conntrack_read_duration_seconds",
		"oie_host_cache_cleanup_duration_seconds",
	} {
		if value := values[name]; value < 0 || value >= 5 {
			t.Fatalf("%s=%v, want live failed-cycle timing instead of cached value 99", name, value)
		}
	}
	if values["oie_host_conntrack_raw_ok"] != 1 ||
		values["oie_host_conntrack_raw_enobufs_total"] != 4 ||
		values["oie_host_conntrack_raw_parse_errors_total"] != 5 ||
		values["oie_host_conntrack_read_errors_total"] != 3 {
		t.Fatalf("conntrack health overlay is stale: %#v", values)
	}
	if stale := values["oie_host_conntrack_stale_seconds"]; stale < 20 || stale > 60 {
		t.Fatalf("conntrack stale seconds=%v, want current age around 30 seconds", stale)
	}
	for name, want := range map[string]float64{
		"oie_host_threat_tor_exit_refresh_last_success_timestamp_seconds": 1234,
		"oie_host_threat_tor_exit_refresh_duration_seconds":               2,
		"oie_host_threat_tor_exit_refresh_errors_total":                   4,
		"oie_host_threat_tor_exit_entries":                                3,
		"oie_host_threat_spamhaus_refresh_last_success_timestamp_seconds": 2345,
		"oie_host_threat_spamhaus_refresh_duration_seconds":               5,
		"oie_host_threat_spamhaus_refresh_errors_total":                   7,
		"oie_host_threat_spamhaus_entries":                                6,
	} {
		if got := values[name]; got != want {
			t.Errorf("%s=%v, want independently refreshed value %v", name, got, want)
		}
	}
	if _, exists := values["oie_host_threat_provider_ip_listed"]; exists {
		t.Fatal("cached host threat-list membership remained after the current set became empty")
	}
	if heap := values["oie_host_go_heap_alloc_bytes"]; heap <= 0 {
		t.Fatalf("Go heap remained cached at %v, want a live positive value", heap)
	}
	for _, name := range []string{
		"oie_host_mem_mb_total",
		"oie_host_cpu_usage_percent",
		"oie_host_mem_free_mb",
		"oie_host_mem_available_mb",
	} {
		if value := values[name]; value < 0 {
			t.Errorf("%s retained unavailable cached sentinel %v despite a live host read", name, value)
		}
	}
}

func TestCollectHeavyWithoutCacheEmitsDegradedHostCycle(t *testing.T) {
	mc, err := NewMetricsCollector(CollectorConfig{
		LibvirtURI:          filepath.Join(t.TempDir(), "missing-libvirt.sock"),
		CollectionInterval:  time.Hour,
		ConntrackIPv4Enable: false,
		ConntrackIPv6Enable: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer close(mc.shutdownChan)
	mc.im.setActiveInstances(map[string]struct{}{"cached-vm": {}})
	ch := make(chan prometheus.Metric, 512)
	mc.collectHeavy(ch)
	if len(ch) == 0 {
		t.Fatal("degraded collection emitted no host metrics")
	}
	if !mc.im.isInstanceActive("cached-vm") {
		t.Fatal("libvirt failure replaced the cached active set")
	}
	if mc.hostCollectionErrors != 1 || mc.lastCycleEndUnixNano <= 0 {
		t.Fatalf("degraded state errors=%d last_end=%d", mc.hostCollectionErrors, mc.lastCycleEndUnixNano)
	}
	if atomic.LoadUint64(&mc.cm.conntrackRawOK) != 0 || atomic.LoadUint64(&mc.cm.conntrackReadErrors) != 0 {
		t.Fatal("disabled conntrack families were reported as a successful dump or read failure")
	}
}

func TestRunCollectionCycleDefaultPathDrainsCollectorChannel(t *testing.T) {
	mc, err := NewMetricsCollector(CollectorConfig{
		LibvirtURI:          filepath.Join(t.TempDir(), "missing-libvirt.sock"),
		CollectionInterval:  time.Hour,
		ConntrackIPv4Enable: false,
		ConntrackIPv6Enable: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer close(mc.shutdownChan)
	metrics := mc.runCollectionCycle()
	if len(metrics) == 0 {
		t.Fatal("default collection cycle did not drain degraded host metrics")
	}
}

func TestBuildActiveAndVMIPSetsUsesDomainInventorySnapshot(t *testing.T) {
	mc := newCollectorOrchestrationTestCollector(t)
	uuid := libvirt.UUID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	instanceUUID := uuidBytesToString(uuid[:])
	ip := IPStrToKey("192.0.2.10")
	mc.im.updateVMIPIndex(instanceUUID, []IP{{Address: "192.0.2.10"}})

	active, ipSet, byIP := mc.buildActiveAndVMIPSets([]libvirt.DomainStatsRecord{
		{Dom: libvirt.Domain{Name: "domain", UUID: uuid}},
	})
	if len(active) != 1 {
		t.Fatalf("active set=%v, want one domain", active)
	}
	if _, ok := active[instanceUUID]; !ok {
		t.Fatalf("active set is missing %q", instanceUUID)
	}
	if _, ok := ipSet[ip]; !ok || byIP[ip] != instanceUUID {
		t.Fatalf("VM IP snapshot set=%v map=%v", ipSet, byIP)
	}

	active, _, _ = mc.buildActiveAndVMIPSets(nil)
	if len(active) != 0 {
		t.Fatalf("empty domain stats produced active set %v", active)
	}
}

func TestCollectorHostIPMapAndIntelCleanup(t *testing.T) {
	if got := (&MetricsCollector{}).buildHostIPMap(); len(got) != 0 {
		t.Fatalf("collector without threat manager host IPs=%v", got)
	}
	mc := newCollectorOrchestrationTestCollector(t)
	behaviorHostIPs := mc.buildHostIPMap()
	mc.tm.hostInterfaces = map[string]struct{}{"definitely-not-an-interface": {}}
	got := mc.buildHostIPMap()
	if len(got) != len(behaviorHostIPs) {
		t.Fatalf("behavior host IP map changed after setting the host-threat interface whitelist: before=%v after=%v", behaviorHostIPs, got)
	}
	for address := range behaviorHostIPs {
		if _, ok := got[address]; !ok {
			t.Fatalf("behavior host IP map lost %q after setting the host-threat interface whitelist: before=%v after=%v", address, behaviorHostIPs, got)
		}
	}

	mc.intelHistory["active"] = &IntelHistory{EWMA: 0.5, Initialized: true}
	mc.intelHistory["stale"] = &IntelHistory{EWMA: 0.7, Initialized: true}
	mc.cleanupIntelHistory(map[string]struct{}{"active": {}})
	if len(mc.intelHistory) != 1 || mc.intelHistory["active"] == nil {
		t.Fatalf("intel cleanup result=%v", mc.intelHistory)
	}
}

func TestCollectorCleanupCachesCoordinatesEveryStateStore(t *testing.T) {
	mc := newCollectorOrchestrationTestCollector(t)
	mc.im.setActiveInstances(map[string]struct{}{"active": {}})
	mc.im.domainMeta["active"] = &DomainStatic{InstanceUUID: "active"}
	mc.im.domainMeta["stale"] = &DomainStatic{InstanceUUID: "stale"}
	mc.intelHistory["active"] = &IntelHistory{Initialized: true}
	mc.intelHistory["stale"] = &IntelHistory{Initialized: true}
	mc.getResourceV2State("active")
	mc.getResourceV2State("stale")
	p := mc.tm.Providers[0]
	p.CountMap["active"] = 1
	p.CountMap["stale"] = 1
	p.PrevHits["active"] = map[string]struct{}{"a": {}}
	p.PrevHits["stale"] = map[string]struct{}{"s": {}}
	mc.tm.spamCount["active"] = 1
	mc.tm.spamCount["stale"] = 1
	mc.tm.spamPrevHits["active"] = map[string]struct{}{"a": {}}
	mc.tm.spamPrevHits["stale"] = map[string]struct{}{"s": {}}

	if elapsed := mc.cleanupCaches(map[string]struct{}{"active": {}}); elapsed < 0 {
		t.Fatalf("cleanup duration=%v", elapsed)
	}
	if _, ok := mc.im.domainMeta["stale"]; ok {
		t.Fatal("cache cleanup retained stale domain metadata")
	}
	if _, ok := mc.intelHistory["stale"]; ok {
		t.Fatal("cache cleanup retained stale intel history")
	}
	if _, ok := mc.resourceV2["stale"]; ok {
		t.Fatal("cache cleanup retained stale resource state")
	}
	if _, ok := p.CountMap["stale"]; ok {
		t.Fatal("cache cleanup retained stale provider count")
	}
	if _, ok := mc.tm.spamCount["stale"]; ok {
		t.Fatal("cache cleanup retained stale Spamhaus count")
	}
}

func TestCollectDomainStatsParallelEmptyAndPopulated(t *testing.T) {
	mc := newCollectorOrchestrationTestCollector(t)
	if agg := mc.collectDomainStatsParallel(nil, nil, nil, 0, false, false, false); agg == nil || len(agg.projects) != 0 || len(agg.metrics) != 0 {
		t.Fatalf("empty parallel collection=%+v", agg)
	}

	uuid := libvirt.UUID{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
	instanceUUID := uuidBytesToString(uuid[:])
	mc.im.domainMeta[instanceUUID] = &DomainStatic{
		Name:         "server",
		InstanceUUID: instanceUUID,
		ProjectUUID:  "project",
		ProjectName:  "project-name",
		UserUUID:     "user",
		VCPUCount:    2,
		MemMB:        2048,
		FixedIPs:     []IP{{Address: "192.0.2.30", Family: "ipv4"}},
		Disks:        []DomainDisk{{TargetDev: "vda"}},
		LastUpdated:  time.Now(),
	}
	stats := []libvirt.DomainStatsRecord{{
		Dom: libvirt.Domain{Name: "domain", UUID: uuid},
		Params: []libvirt.TypedParam{
			typedParam("state.state", int32(libvirt.DomainRunning)),
			typedParam("cpu.time", uint64(1)),
			typedParam("balloon.current", uint64(2*1024*1024)),
			typedParam("balloon.usable", uint64(1024*1024)),
			typedParam("block.0.name", "vda"),
		},
	}}
	agg := mc.collectDomainStatsParallel(stats, nil, nil, 0, false, false, true)
	if agg.vcpus != 2 || agg.disks != 1 || agg.fixedIPs != 1 || len(agg.projects) != 1 || len(agg.metrics) == 0 {
		t.Fatalf("parallel aggregate vcpus=%d disks=%d ips=%d projects=%v metrics=%d", agg.vcpus, agg.disks, agg.fixedIPs, agg.projects, len(agg.metrics))
	}
}

func TestEmitHostAndAggregateMetricsHonorsAvailabilityFlags(t *testing.T) {
	mc := newCollectorOrchestrationTestCollector(t)
	mc.cm.conntrackIPv4Enable = true
	desc := prometheus.NewDesc("test_aggregate_metric", "test", nil, nil)
	agg := &hostAgg{
		projects: map[string]struct{}{"project": {}},
		metrics:  []prometheus.Metric{prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, 1)},
	}
	ch := make(chan prometheus.Metric, 256)
	mc.emitHostAndAggMetrics(ch, nil, agg, 1, 2, 3, 4, 5, 100, 0.05, 6, false, false, false)
	close(ch)

	required := map[string]struct{}{
		"oie_host_cpu_threads":                              {},
		"oie_host_collection_errors_total":                  {},
		"oie_host_collection_cycle_duration_seconds":        {},
		"oie_host_collection_cycle_lag_seconds":             {},
		"oie_host_libvirt_list_duration_seconds":            {},
		"oie_host_conntrack_read_duration_seconds":          {},
		"oie_host_conntrack_raw_ok":                         {},
		"oie_host_conntrack_raw_enobufs_total":              {},
		"oie_host_conntrack_raw_parse_errors_total":         {},
		"oie_host_conntrack_last_success_timestamp_seconds": {},
		"oie_host_conntrack_stale_seconds":                  {},
		"oie_host_conntrack_read_errors_total":              {},
		"oie_host_go_heap_alloc_bytes":                      {},
		"oie_host_cache_cleanup_duration_seconds":           {},
		"test_aggregate_metric":                             {},
	}
	optionalLiveHost := map[string]struct{}{
		"oie_host_mem_mb_total":      {},
		"oie_host_cpu_usage_percent": {},
		"oie_host_mem_free_mb":       {},
		"oie_host_mem_available_mb":  {},
	}
	forbidden := map[string]struct{}{
		"oie_host_libvirt_active_vms":    {},
		"oie_host_cpu_active_vcpus":      {},
		"oie_host_active_disks":          {},
		"oie_host_active_fixed_ips":      {},
		"oie_host_active_projects":       {},
		"oie_host_conntrack_entries":     {},
		"oie_host_conntrack_max":         {},
		"oie_host_conntrack_utilization": {},
	}

	counts := make(map[string]int, len(required)+len(optionalLiveHost))
	for metric := range ch {
		match := descNameRE.FindStringSubmatch(metric.Desc().String())
		if len(match) != 2 {
			t.Fatalf("cannot parse emitted metric descriptor: %s", metric.Desc())
		}
		name := match[1]
		counts[name]++
		if _, denied := forbidden[name]; denied {
			t.Errorf("unavailable metric family %s was emitted", name)
		}
		if _, mandatory := required[name]; !mandatory {
			if _, optional := optionalLiveHost[name]; !optional {
				t.Errorf("unexpected metric family %s was emitted", name)
			}
		}
	}
	for name := range required {
		if counts[name] != 1 {
			t.Errorf("required metric family %s emitted %d times, want exactly once", name, counts[name])
		}
	}
	for name := range optionalLiveHost {
		if counts[name] > 1 {
			t.Errorf("optional live-host metric family %s emitted %d times, want at most once", name, counts[name])
		}
	}
}

func TestBackgroundCollectorRunsCachesAndStops(t *testing.T) {
	calls := make(chan struct{}, 4)
	desc := prometheus.NewDesc("test_background_cycle", "test", nil, nil)
	mc := &MetricsCollector{
		shutdownChan:       make(chan struct{}),
		collectionInterval: 5 * time.Millisecond,
		collectionRunner: func() []prometheus.Metric {
			calls <- struct{}{}
			return []prometheus.Metric{prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, 1)}
		},
	}
	done := make(chan struct{})
	go func() {
		mc.startBackgroundCollector()
		close(done)
	}()
	select {
	case <-calls:
	case <-time.After(time.Second):
		close(mc.shutdownChan)
		t.Fatal("background collection did not run")
	}
	close(mc.shutdownChan)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("background collector did not stop")
	}
	mc.cacheMu.RLock()
	initialized := mc.cacheInitialized
	cachedCount := len(mc.cachedMetrics)
	mc.cacheMu.RUnlock()
	if !initialized || cachedCount != 1 {
		t.Fatalf("background cache initialized=%v metrics=%d", initialized, cachedCount)
	}
}

func TestLibvirtURIAndConnectionHelpers(t *testing.T) {
	defaultSocket := "/var/run/libvirt/libvirt-sock"
	for _, tc := range []struct {
		uri  string
		want string
	}{
		{"", defaultSocket},
		{"  ", defaultSocket},
		{"/run/custom/libvirt.sock", "/run/custom/libvirt.sock"},
		{"qemu:///system", defaultSocket},
		{"qemu+unix:///system?socket=/run/query.sock", "/run/query.sock"},
		{"qemu+unix:///run/path.sock", "/run/path.sock"},
		{"qemu+unix://host", defaultSocket},
	} {
		got, err := libvirtSocketPathFromURI(tc.uri)
		if err != nil || got != tc.want {
			t.Fatalf("libvirtSocketPathFromURI(%q)=(%q,%v), want (%q,nil)", tc.uri, got, err, tc.want)
		}
	}
	for _, uri := range []string{"qemu+ssh://host/system", "not a supported uri"} {
		if _, err := libvirtSocketPathFromURI(uri); err == nil {
			t.Fatalf("unsupported libvirt URI %q was accepted", uri)
		}
	}

	cached := &libvirt.Libvirt{}
	mc := &MetricsCollector{im: &InstanceManager{libvirtURI: "unsupported://host"}, libvirtConn: cached}
	if got, err := mc.getLibvirtConn(); err != nil || got != cached {
		t.Fatalf("cached libvirt connection=(%p,%v), want %p", got, err, cached)
	}
	mc.libvirtConn = nil
	if got, err := mc.getLibvirtConn(); err == nil || got != nil {
		t.Fatalf("unsupported connection=(%p,%v), want nil,error", got, err)
	}

	dialer := &LocalDialer{SocketPath: filepath.Join(t.TempDir(), "missing.sock")}
	if conn, err := dialer.Dial(); err == nil || conn != nil {
		t.Fatalf("dialing missing libvirt socket=(%v,%v), want nil,error", conn, err)
	}
}

func TestTelemetryPathAndAdditionalHTTPLifecycleErrors(t *testing.T) {
	for _, path := range []string{"/metrics", "/custom/metrics"} {
		if err := validateTelemetryPath(path); err != nil {
			t.Fatalf("valid telemetry path %q rejected: %v", path, err)
		}
	}
	for _, path := range []string{"", "metrics", "/debug/log-level", "/debug/%6cog-level", "/debug/log%2dlevel", "/metrics/{"} {
		if err := validateTelemetryPath(path); err == nil {
			t.Fatalf("invalid telemetry path %q accepted", path)
		}
	}

	ctx := context.Background()
	srv := &http.Server{}
	if err := serveHTTPUntilShutdown(nil, srv, nil, time.Second); err == nil {
		t.Fatal("nil HTTP lifecycle inputs were accepted")
	}
	if err := serveHTTPUntilShutdown(ctx, nil, nil, time.Second); err == nil {
		t.Fatal("nil HTTP server was accepted")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := serveHTTPUntilShutdown(ctx, srv, listener, time.Second); err == nil {
		t.Fatal("server failure on a closed listener was ignored")
	}
}
