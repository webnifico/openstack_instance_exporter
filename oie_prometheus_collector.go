package main

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/digitalocean/go-libvirt"
	"github.com/prometheus/client_golang/prometheus"
)

// -----------------------------------------------------------------------------
// Compatibility Constants
// -----------------------------------------------------------------------------
const (
	_domainStatsState                   = 1
	_domainStatsCpuTotal                = 2
	_domainStatsBalloon                 = 4
	_domainStatsVcpu                    = 8
	_domainStatsInterface               = 16
	_domainStatsBlock                   = 32
	_connectGetAllDomainStatsActiveOnly = 1
	_connectGetAllDomainStatsInactive   = 2
)

// -----------------------------------------------------------------------------
// Dialer Implementation for go-libvirt
// -----------------------------------------------------------------------------

type LocalDialer struct {
	SocketPath string
}

func (d *LocalDialer) Dial() (net.Conn, error) {
	return net.DialTimeout("unix", d.SocketPath, 2*time.Second)
}

// -----------------------------------------------------------------------------
// MetricsCollector Creation
// -----------------------------------------------------------------------------

func NewMetricsCollector(cfg CollectorConfig) (*MetricsCollector, error) {
	if cfg.LibvirtURI == "" {
		return nil, fmt.Errorf("LibvirtURI is required")
	}

	mc := &MetricsCollector{
		shutdownChan:       make(chan struct{}),
		scoring:            cfg.Severity,
		collectionInterval: cfg.CollectionInterval,
		intelHistory:       make(map[string]*IntelHistory),
	}

	mc.im = &InstanceManager{
		libvirtURI:         cfg.LibvirtURI,
		workerCount:        cfg.WorkerCount,
		domainMeta:         make(map[string]*DomainStatic),
		activeInstances:    make(map[string]struct{}),
		vmIPSet:            make(map[IPKey]struct{}),
		vmIPToInstance:     make(map[IPKey]string),
		vmIPKeysByInstance: make(map[string][]IPKey),
	}

	xmlMaxConcurrent := cfg.WorkerCount
	if xmlMaxConcurrent <= 0 {
		xmlMaxConcurrent = runtime.NumCPU()
	}
	if xmlMaxConcurrent < 1 {
		xmlMaxConcurrent = 1
	}
	if xmlMaxConcurrent > 8 {
		xmlMaxConcurrent = 8
	}
	mc.im.xmlInflight = make(map[string]*domainXMLInflight, 256)
	mc.im.xmlRPCSem = make(chan struct{}, xmlMaxConcurrent)

	for i := 0; i < shardCount; i++ {
		mc.im.cpuSamples[i] = make(map[string]cpuSample)
		mc.im.diskSamples[i] = make(map[string]diskSample)
		mc.im.memSamples[i] = make(map[string]memSample)
		mc.im.netSamples[i] = make(map[string]netSample)
	}

	mc.tm = &ThreatManager{
		shutdownChan: mc.shutdownChan,
		httpClient:   &http.Client{Timeout: 15 * time.Second},

		hostThreatsEnabled:  cfg.HostThreats.Enable,
		hostIPsAllowPrivate: cfg.HostThreats.IPsAllowPrivate,
		hostInterfaces:      cfg.HostThreats.Interfaces,

		spamEnabled:   cfg.Spamhaus.Enable,
		spamURL:       cfg.Spamhaus.URLv4,
		spamV6URL:     cfg.Spamhaus.URLv6,
		spamRefresh:   cfg.Spamhaus.Refresh,
		spamNetsV4:    make([]*net.IPNet, 0),
		spamNetsV6:    make([]*net.IPNet, 0),
		spamWideV4:    make([]*net.IPNet, 0),
		spamWideV6:    make([]*net.IPNet, 0),
		spamBucketsV4: make(map[uint16][]*net.IPNet),
		spamBucketsV6: make(map[uint32][]*net.IPNet),
		spamDir:       cfg.Spamhaus.Direction,
		spamCount:     make(map[string]float64),

		// Initialize State Diff Maps
		spamPrevHits: make(map[string]map[string]struct{}),

		threatLogMinInterval: cfg.ThreatLogMinInterval,
		threatLastHit:        make(map[string]time.Time),
	}

	mc.tm.Providers = []*IPThreatProvider{
		{
			Name:                          "TorExit",
			Enabled:                       cfg.TorExit.Enable,
			URL:                           cfg.TorExit.URL,
			RefreshInterval:               cfg.TorExit.Refresh,
			Direction:                     cfg.TorExit.Direction,
			LogTag:                        "TOREXIT",
			Logger:                        logTorexitThreat,
			Set:                           make(map[IPKey]struct{}),
			CountMap:                      make(map[string]float64),
			PrevHits:                      make(map[string]map[string]struct{}),
			InstanceContactsMetricName:    "oie_instance_threat_tor_exit_contacts_total",
			InstanceActiveMetricName:      "oie_instance_threat_tor_exit_active_flows",
			HostRefreshLastMetricName:     "oie_host_threat_tor_exit_refresh_last_success_timestamp_seconds",
			HostRefreshDurationMetricName: "oie_host_threat_tor_exit_refresh_duration_seconds",
			HostRefreshErrorsMetricName:   "oie_host_threat_tor_exit_refresh_errors_total",
			HostEntriesMetricName:         "oie_host_threat_tor_exit_entries",
			Fetcher:                       func() (map[IPKey]struct{}, error) { return mc.tm.fetchOnionoo(cfg.TorExit.URL) },
		},
		{
			Name:                          "TorRelay",
			Enabled:                       cfg.TorRelay.Enable,
			URL:                           cfg.TorRelay.URL,
			RefreshInterval:               cfg.TorRelay.Refresh,
			Direction:                     cfg.TorRelay.Direction,
			LogTag:                        "TORRELAY",
			Logger:                        logTorrelayThreat,
			Set:                           make(map[IPKey]struct{}),
			CountMap:                      make(map[string]float64),
			PrevHits:                      make(map[string]map[string]struct{}),
			InstanceContactsMetricName:    "oie_instance_threat_tor_relay_contacts_total",
			InstanceActiveMetricName:      "oie_instance_threat_tor_relay_active_flows",
			HostRefreshLastMetricName:     "oie_host_threat_tor_relay_refresh_last_success_timestamp_seconds",
			HostRefreshDurationMetricName: "oie_host_threat_tor_relay_refresh_duration_seconds",
			HostRefreshErrorsMetricName:   "oie_host_threat_tor_relay_refresh_errors_total",
			HostEntriesMetricName:         "oie_host_threat_tor_relay_entries",
			Fetcher:                       func() (map[IPKey]struct{}, error) { return mc.tm.fetchOnionoo(cfg.TorRelay.URL) },
		},
		{
			Name:                          "EmergingThreats",
			Enabled:                       cfg.Emerging.Enable,
			URL:                           cfg.Emerging.URL,
			RefreshInterval:               cfg.Emerging.Refresh,
			Direction:                     cfg.Emerging.Direction,
			LogTag:                        "EMERGING",
			Logger:                        logEmergingthreatsThreat,
			Set:                           make(map[IPKey]struct{}),
			CountMap:                      make(map[string]float64),
			PrevHits:                      make(map[string]map[string]struct{}),
			InstanceContactsMetricName:    "oie_instance_threat_emergingthreats_contacts_total",
			InstanceActiveMetricName:      "oie_instance_threat_emergingthreats_active_flows",
			HostRefreshLastMetricName:     "oie_host_threat_emergingthreats_refresh_last_success_timestamp_seconds",
			HostRefreshDurationMetricName: "oie_host_threat_emergingthreats_refresh_duration_seconds",
			HostRefreshErrorsMetricName:   "oie_host_threat_emergingthreats_refresh_errors_total",
			HostEntriesMetricName:         "oie_host_threat_emergingthreats_entries",
			Fetcher:                       func() (map[IPKey]struct{}, error) { return mc.tm.fetchURLLines(cfg.Emerging.URL) },
		},
		{
			Name:                          "CustomList",
			Enabled:                       cfg.Custom.Enable,
			URL:                           cfg.Custom.Path,
			RefreshInterval:               cfg.Custom.Refresh,
			Direction:                     cfg.Custom.Direction,
			LogTag:                        "CUSTOMLIST",
			Logger:                        logCustomlistThreat,
			Set:                           make(map[IPKey]struct{}),
			CountMap:                      make(map[string]float64),
			PrevHits:                      make(map[string]map[string]struct{}),
			InstanceContactsMetricName:    "oie_instance_threat_customlist_contacts_total",
			InstanceActiveMetricName:      "oie_instance_threat_customlist_active_flows",
			HostRefreshLastMetricName:     "oie_host_threat_customlist_refresh_last_success_timestamp_seconds",
			HostRefreshDurationMetricName: "oie_host_threat_customlist_refresh_duration_seconds",
			HostRefreshErrorsMetricName:   "oie_host_threat_customlist_refresh_errors_total",
			HostEntriesMetricName:         "oie_host_threat_customlist_entries",
			Fetcher:                       func() (map[IPKey]struct{}, error) { return mc.tm.fetchFileLines(cfg.Custom.Path) },
		},
	}

	for _, p := range mc.tm.Providers {
		p.SetAtomic.Store(p.Set)
	}

	mc.cm = &ConntrackManager{
		outboundBehaviorEnabled:   cfg.OutboundBehaviorEnable,
		inboundBehaviorEnabled:    cfg.InboundBehaviorEnable,
		behaviorThresholds:        cfg.BehaviorThresholds,
		conntrackAcctEnabled:      cfg.ConntrackAcctEnabled,
		behaviorSensitivity:       cfg.BehaviorSensitivity,
		behaviorInboundPortNames:  cfg.BehaviorPortsInboundMonitored,
		behaviorOutboundPortNames: cfg.BehaviorPortsOutboundMonitored,
		externalBehaviorRules:     cfg.BehaviorExternalRules,
		conntrackRawRcvBufBytes:   cfg.ConntrackRawRcvBufBytes,
		conntrackIPv4Enable:       cfg.ConntrackIPv4Enable,
		conntrackIPv6Enable:       cfg.ConntrackIPv6Enable,
		ovnMapper:                 NewOVNMapper(),
	}
	if mc.cm.behaviorInboundPortNames == nil {
		mc.cm.behaviorInboundPortNames = builtinBehaviorInboundMonitoredPorts()
	}
	if mc.cm.behaviorOutboundPortNames == nil {
		mc.cm.behaviorOutboundPortNames = builtinBehaviorOutboundMonitoredPorts()
	}

	for i := 0; i < shardCount; i++ {
		mc.cm.outboundPrev[i] = make(map[BehaviorKey]outboundPrev)
		mc.cm.outboundPrevDstPorts[i] = make(map[BehaviorKey]outboundPrevDstPorts)
		mc.cm.outboundPrevLastSeen[i] = make(map[BehaviorKey]int64)
		mc.cm.inboundPrev[i] = make(map[BehaviorKey]outboundPrev)
		mc.cm.inboundPrevDstPorts[i] = make(map[BehaviorKey]outboundPrevDstPorts)
		mc.cm.inboundPrevLastSeen[i] = make(map[BehaviorKey]int64)
		mc.cm.behaviorEWMA[i] = make(map[behaviorIdentityKey]*behaviorEWMAState)
	}

	mc.cm.behaviorPersist = make(map[behaviorAlertKey]*behaviorPersistState)
	mc.cm.behaviorEmit = make(map[behaviorEmitKey]*behaviorEmitState)

	mc.cm.LogThreat = mc.tm.logThreatEvent

	initHostMetrics(mc)
	initInstanceMetrics(mc.im)
	initInstanceSeverityMetrics(mc)
	initThreatMetrics(mc.tm)
	initConntrackMetrics(mc.cm)

	for _, p := range mc.tm.Providers {
		if p.Enabled {
			provider := p
			go mc.tm.runProviderRefresher(provider)
		}
	}

	if mc.tm.spamEnabled {
		go mc.tm.startSpamhausRefresher()
	}

	return mc, nil
}

func (mc *MetricsCollector) getLibvirtConn() (*libvirt.Libvirt, error) {
	mc.libvirtMu.Lock()
	defer mc.libvirtMu.Unlock()

	if mc.libvirtConn != nil {
		return mc.libvirtConn, nil
	}

	sockPath, err := libvirtSocketPathFromURI(mc.im.libvirtURI)
	if err != nil {
		return nil, err
	}
	dialer := &LocalDialer{SocketPath: sockPath}
	l := libvirt.NewWithDialer(dialer)

	if err := l.Connect(); err != nil {
		l.Disconnect() // Ensure clean state
		return nil, fmt.Errorf("failed to connect to libvirt rpc: %v", err)
	}

	mc.libvirtConn = l
	return mc.libvirtConn, nil
}

func (mc *MetricsCollector) Describe(ch chan<- *prometheus.Desc) {
	mc.im.describeInstanceMetrics(ch)
	mc.tm.describeThreatMetrics(ch)
	mc.cm.describeConntrackMetrics(ch)

	ch <- mc.instanceResourceSeverityDesc

	ch <- mc.instanceResourceCpuSeverityDesc
	ch <- mc.instanceResourceMemSeverityDesc
	ch <- mc.instanceResourceDiskSeverityDesc
	ch <- mc.instanceResourceNetSeverityDesc
	ch <- mc.instanceThreatListSeverityDesc
	ch <- mc.instanceAttentionSeverityDesc
	ch <- mc.instanceBehaviorSeverityDesc

	mc.describeHostMetrics(ch)
}

func (mc *MetricsCollector) describeHostMetrics(ch chan<- *prometheus.Desc) {
	ch <- mc.hostMemTotalMBDesc
	ch <- mc.hostLibvirtActiveVMsDesc
	ch <- mc.hostCpuActiveVcpusDesc
	ch <- mc.hostActiveDisksDesc
	ch <- mc.hostActiveFixedIPsDesc
	ch <- mc.hostActiveProjectsDesc
	ch <- mc.hostCpuThreadsDesc
	ch <- mc.hostCollectionErrorsTotalDesc
	ch <- mc.hostCollectionCycleDurationSecondsDesc
	ch <- mc.hostCollectionCycleLagSecondsDesc
	ch <- mc.hostLibvirtListDurationSecondsDesc
	ch <- mc.hostConntrackReadDurationSecondsDesc
	ch <- mc.hostConntrackEntriesDesc
	ch <- mc.hostGoHeapAllocBytesDesc
	ch <- mc.hostConntrackReadErrorsTotalDesc
	ch <- mc.hostConntrackRawOkDesc
	ch <- mc.hostConntrackRawENOBUFSTotalDesc
	ch <- mc.hostConntrackRawParseErrorsTotalDesc
	ch <- mc.hostConntrackLastSuccessTimestampDesc
	ch <- mc.hostConntrackStaleSecondsDesc
	ch <- mc.hostConntrackMaxDesc
	ch <- mc.hostConntrackUtilizationDesc
	ch <- mc.hostCacheCleanupDurationSecondsDesc

	ch <- mc.hostCpuUsagePercentDesc
	ch <- mc.hostMemFreeMBDesc
	ch <- mc.hostMemAvailableMBDesc

	mc.tm.describeHostMetrics(ch)
}

func (mc *MetricsCollector) collectHeavy(ch chan<- prometheus.Metric) {
	cycleStart := time.Now()
	cycleID := atomic.AddUint64(&mc.cycleSeq, 1)
	lagSeconds := mc.collectionLagSeconds()

	logCollectorMetric.Debug("scrapetime_collection_start", "cycle_id", cycleID, "lag_seconds", lagSeconds)

	domainStats, libvirtSeconds, errLibvirt := mc.fetchDomainStats()

	if errLibvirt != nil {
		atomic.AddUint64(&mc.hostCollectionErrors, 1)
		logCollectorMetric.Error("domain_stats_failed", "cycle_id", cycleID, "err", errLibvirt)
		logCollectorMetric.Notice("collection_degraded", "cycle_id", cycleID, "stage", "libvirt", "fallback", "use_cached_active_set", "impact", "per-instance metrics may be missing or stale", "err", errLibvirt)
	} else {
		logCollectorMetric.Debug("domain_stats_success", "cycle_id", cycleID, "active_domains", len(domainStats))
	}

	var activeSet map[string]struct{}
	if errLibvirt == nil {
		activeSet, _, _ = mc.buildActiveAndVMIPSets(domainStats)
		mc.im.setActiveInstances(activeSet)
	} else {
		activeSet = mc.im.snapshotActiveInstances()
	}

	vmIPs := mc.im.snapshotVMIPIdentities(activeSet)
	ovnPortToInstance := mc.im.snapshotOVNPortToInstance(activeSet)
	ovnPortToIPs := mc.im.snapshotOVNPortToIPKeys(activeSet)

	hostIPMap := mc.buildHostIPMap()

	var (
		cacheCleanupSeconds float64
		conntrackSeconds    float64
		ctCount             int
		errConntrack        error
		connAgg             *ConntrackAgg
		wg                  sync.WaitGroup
	)

	wg.Add(1)
	if errLibvirt == nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cacheCleanupSeconds = mc.cleanupCaches(activeSet)
		}()
	}

	go func() {
		defer wg.Done()
		cStart := time.Now()
		if mc.cm.ovnMapper != nil && len(ovnPortToInstance) > 0 {
			if err := mc.cm.ovnMapper.Refresh(ovnPortToInstance, ovnPortToIPs); err != nil {
				logConntrackMetric.Error("ovn_refresh_failed", "err", err)
			}
		}
		connAgg, ctCount, errConntrack = mc.cm.readAndAggregateConntrack(vmIPs, mc.tm)
		conntrackSeconds = time.Since(cStart).Seconds()
	}()
	wg.Wait()

	if errConntrack != nil {
		atomic.AddUint64(&mc.hostCollectionErrors, 1)
		atomic.AddUint64(&mc.cm.conntrackReadErrors, 1)
		logConntrackMetric.Error("conntrack_read_failed", "cycle_id", cycleID, "ct_entries", ctCount, "err", errConntrack)
		logConntrackMetric.Notice("collection_degraded", "cycle_id", cycleID, "stage", "conntrack", "fallback", "skip_conntrack_agg", "impact", "per-vm network attribution missing", "err", errConntrack)
		connAgg = nil
	}

	ctMax := hostConntrackMax()
	var ctUtil float64
	if ctMax > 0 {
		ctUtil = float64(ctCount) / float64(ctMax)
	}

	agg := mc.collectDomainStatsParallel(domainStats, connAgg, hostIPMap, ctMax)

	cycleEnd := time.Now()
	cycleSeconds := cycleEnd.Sub(cycleStart).Seconds()

	mc.emitHostAndAggMetrics(
		ch,
		domainStats,
		agg,
		lagSeconds,
		libvirtSeconds,
		conntrackSeconds,
		cacheCleanupSeconds,
		ctCount,
		ctMax,
		ctUtil,
		cycleSeconds,
	)

	summaryArgs := []interface{}{
		"cycle_id", cycleID,
		"duration_seconds", cycleSeconds,
		"lag_seconds", lagSeconds,
		"libvirt_ok", errLibvirt == nil,
		"libvirt_duration_seconds", libvirtSeconds,
		"active_domains", len(domainStats),
		"active_instances", len(activeSet),
		"vm_ip_identities", len(vmIPs),
		"conntrack_ok", errConntrack == nil,
		"conntrack_duration_seconds", conntrackSeconds,
		"conntrack_entries", ctCount,
		"conntrack_max", ctMax,
		"conntrack_utilization", ctUtil,
		"cache_cleanup_seconds", cacheCleanupSeconds,
		"degraded", errLibvirt != nil || errConntrack != nil,
	}
	degradedStages := make([]string, 0, 2)
	if errLibvirt != nil {
		degradedStages = append(degradedStages, "libvirt")
		summaryArgs = append(summaryArgs, "libvirt_err", errLibvirt)
	}
	if errConntrack != nil {
		degradedStages = append(degradedStages, "conntrack")
		summaryArgs = append(summaryArgs, "conntrack_err", errConntrack)
	}
	if len(degradedStages) > 0 {
		summaryArgs = append(summaryArgs, "degraded_stages", strings.Join(degradedStages, ","))
	}
	logCollectorMetric.Debug("collection_cycle_summary", summaryArgs...)

	atomic.StoreInt64(&mc.lastCycleEndUnixNano, cycleEnd.UnixNano())
	logCollectorMetric.Debug("scrapetime_collection_end", "cycle_id", cycleID, "duration_seconds", cycleSeconds)
}

func (mc *MetricsCollector) collectionLagSeconds() float64 {
	prevEnd := atomic.LoadInt64(&mc.lastCycleEndUnixNano)
	if prevEnd <= 0 {
		return 0
	}
	lagDur := time.Since(time.Unix(0, prevEnd)).Seconds()
	if lagDur <= 0 {
		return 0
	}
	return lagDur
}

func libvirtSocketPathFromURI(uri string) (string, error) {
	defaultSock := "/var/run/libvirt/libvirt-sock"
	uri = strings.TrimSpace(uri)
	if uri == "" {
		return defaultSock, nil
	}
	if strings.HasPrefix(uri, "/") {
		return uri, nil
	}
	if uri == "qemu:///system" {
		return defaultSock, nil
	}

	u, err := url.Parse(uri)
	if err != nil {
		return "", fmt.Errorf("unsupported libvirt.uri for go-libvirt dialer: %s (use qemu:///system or a unix socket URI with ?socket=/path)", uri)
	}

	if sock := u.Query().Get("socket"); sock != "" {
		return sock, nil
	}

	if strings.Contains(u.Scheme, "unix") && u.Path != "" {
		return u.Path, nil
	}

	if strings.Contains(u.Scheme, "unix") {
		return defaultSock, nil
	}

	return "", fmt.Errorf("unsupported libvirt.uri for go-libvirt dialer: %s (use qemu:///system or a unix socket URI with ?socket=/path)", uri)
}

func (mc *MetricsCollector) fetchDomainStats() ([]libvirt.DomainStatsRecord, float64, error) {
	lStart := time.Now()

	conn, err := mc.getLibvirtConn()
	if err != nil {
		return nil, 0, err
	}

	statsFlags := uint32(_domainStatsState | _domainStatsCpuTotal | _domainStatsBalloon | _domainStatsVcpu | _domainStatsInterface | _domainStatsBlock)
	fetchFlags := uint32(_connectGetAllDomainStatsActiveOnly | _connectGetAllDomainStatsInactive)
	domainStats, errLibvirt := conn.ConnectGetAllDomainStats(nil, statsFlags, fetchFlags)

	if errLibvirt != nil {
		mc.libvirtMu.Lock()
		if mc.libvirtConn == conn {
			mc.libvirtConn.Disconnect()
			mc.libvirtConn = nil
		}
		mc.libvirtMu.Unlock()
	}

	libvirtSeconds := time.Since(lStart).Seconds()
	return domainStats, libvirtSeconds, errLibvirt
}

func (mc *MetricsCollector) buildActiveAndVMIPSets(domainStats []libvirt.DomainStatsRecord) (map[string]struct{}, map[IPKey]struct{}, map[IPKey]string) {
	activeSet := make(map[string]struct{}, len(domainStats))

	mc.libvirtMu.Lock()
	preScanConn := mc.libvirtConn
	mc.libvirtMu.Unlock()

	if preScanConn != nil && len(domainStats) > 0 {
		numWorkers := mc.im.workerCount
		if numWorkers <= 0 {
			numWorkers = runtime.NumCPU()
		}
		if numWorkers > 64 {
			numWorkers = 64
		}

		jobs := make(chan libvirt.Domain, len(domainStats))
		var wg sync.WaitGroup
		for i := 0; i < numWorkers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for dom := range jobs {
					_, _ = mc.im.getDomainMeta(dom, preScanConn)
				}
			}()
		}

		for _, stat := range domainStats {
			uuidBytes := stat.Dom.UUID
			uuid := fmt.Sprintf("%x-%x-%x-%x-%x", uuidBytes[0:4], uuidBytes[4:6], uuidBytes[6:8], uuidBytes[8:10], uuidBytes[10:])

			activeSet[uuid] = struct{}{}
			jobs <- stat.Dom
		}

		close(jobs)
		wg.Wait()
	} else {
		for _, stat := range domainStats {
			uuidBytes := stat.Dom.UUID
			uuid := fmt.Sprintf("%x-%x-%x-%x-%x", uuidBytes[0:4], uuidBytes[4:6], uuidBytes[6:8], uuidBytes[8:10], uuidBytes[10:])

			activeSet[uuid] = struct{}{}
		}
	}

	vmIPSet, vmIPToInstance := mc.im.getVMIPIndexSnapshot()
	return activeSet, vmIPSet, vmIPToInstance
}

func (mc *MetricsCollector) buildHostIPMap() map[string]struct{} {
	hostIPs := mc.tm.getHostIPs()
	hostIPMap := make(map[string]struct{}, len(hostIPs))
	for _, hip := range hostIPs {
		hostIPMap[hip.Address] = struct{}{}
	}
	return hostIPMap
}

func (mc *MetricsCollector) cleanupCaches(activeSet map[string]struct{}) float64 {
	cleanupStart := time.Now()
	mc.im.cleanupDomainMeta()
	mc.im.cleanupResourceSamples()
	mc.cleanupResourceV2(activeSet)
	mc.cm.cleanupBehaviorMaps(activeSet)
	mc.cm.cleanupBehaviorState(activeSet)
	mc.tm.cleanupThreatCounts(activeSet)
	mc.tm.cleanupThreatLastHit()
	mc.cleanupIntelHistory(activeSet)
	return time.Since(cleanupStart).Seconds()
}

func (mc *MetricsCollector) cleanupIntelHistory(activeSet map[string]struct{}) {
	mc.intelMu.Lock()
	for instanceUUID := range mc.intelHistory {
		if _, ok := activeSet[instanceUUID]; !ok {
			delete(mc.intelHistory, instanceUUID)
		}
	}
	mc.intelMu.Unlock()
}

func (mc *MetricsCollector) collectDomainStatsParallel(domainStats []libvirt.DomainStatsRecord, connAgg *ConntrackAgg, hostIPMap map[string]struct{}, ctMax uint64) *hostAgg {
	agg := &hostAgg{projects: make(map[string]struct{})}

	if len(domainStats) == 0 {
		return agg
	}

	numWorkers := mc.im.workerCount
	if numWorkers <= 0 {
		numWorkers = runtime.NumCPU()
	}
	if numWorkers > 64 {
		numWorkers = 64
	}

	jobs := make(chan libvirt.DomainStatsRecord, len(domainStats))
	aggCh := make(chan *hostAgg, numWorkers)
	var wgWorkers sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		wgWorkers.Add(1)
		go func() {
			defer wgWorkers.Done()
			localAgg := &hostAgg{projects: make(map[string]struct{})}
			for stat := range jobs {
				mc.collectDomainMetrics(stat, connAgg, hostIPMap, localAgg, ctMax)
			}
			aggCh <- localAgg
		}()
	}

	for _, s := range domainStats {
		jobs <- s
	}
	close(jobs)
	wgWorkers.Wait()
	close(aggCh)

	var allAggs []*hostAgg
	metricsCap := 0
	for a := range aggCh {
		allAggs = append(allAggs, a)
		metricsCap += len(a.metrics)
	}

	agg.metrics = make([]prometheus.Metric, 0, metricsCap)

	for _, a := range allAggs {
		agg.vcpus += a.vcpus
		agg.disks += a.disks
		agg.fixedIPs += a.fixedIPs
		for p := range a.projects {
			agg.projects[p] = struct{}{}
		}
		agg.metrics = append(agg.metrics, a.metrics...)
	}

	return agg
}

func (mc *MetricsCollector) emitHostAndAggMetrics(
	ch chan<- prometheus.Metric,
	domainStats []libvirt.DomainStatsRecord,
	agg *hostAgg,
	lagSeconds float64,
	libvirtSeconds float64,
	conntrackSeconds float64,
	cacheCleanupSeconds float64,
	ctCount int,
	ctMax uint64,
	ctUtil float64,
	cycleSeconds float64,
) {
	totalMemBytes := hostTotalMemBytes()
	totalMemMB := float64(totalMemBytes) * bytesToMegabytes

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	heapAllocBytes := float64(ms.HeapAlloc)

	errorsTotal := atomic.LoadUint64(&mc.hostCollectionErrors)
	conntrackErrors := atomic.LoadUint64(&mc.cm.conntrackReadErrors)

	cpuPercent := mc.getHostCPUPercent()
	memFreeMB, memAvailMB := mc.getHostMemInfo()

	hostMetrics := []prometheus.Metric{
		prometheus.MustNewConstMetric(mc.hostLibvirtActiveVMsDesc, prometheus.GaugeValue, float64(len(domainStats))),
		prometheus.MustNewConstMetric(mc.hostCpuActiveVcpusDesc, prometheus.GaugeValue, float64(agg.vcpus)),
		prometheus.MustNewConstMetric(mc.hostActiveDisksDesc, prometheus.GaugeValue, float64(agg.disks)),
		prometheus.MustNewConstMetric(mc.hostActiveFixedIPsDesc, prometheus.GaugeValue, float64(agg.fixedIPs)),
		prometheus.MustNewConstMetric(mc.hostActiveProjectsDesc, prometheus.GaugeValue, float64(len(agg.projects))),
		prometheus.MustNewConstMetric(mc.hostCpuThreadsDesc, prometheus.GaugeValue, float64(runtime.NumCPU())),
		prometheus.MustNewConstMetric(mc.hostMemTotalMBDesc, prometheus.GaugeValue, totalMemMB),
		prometheus.MustNewConstMetric(mc.hostCollectionErrorsTotalDesc, prometheus.CounterValue, float64(errorsTotal)),
		prometheus.MustNewConstMetric(mc.hostCollectionCycleDurationSecondsDesc, prometheus.GaugeValue, cycleSeconds),
		prometheus.MustNewConstMetric(mc.hostCollectionCycleLagSecondsDesc, prometheus.GaugeValue, lagSeconds),
		prometheus.MustNewConstMetric(mc.hostLibvirtListDurationSecondsDesc, prometheus.GaugeValue, libvirtSeconds),
		prometheus.MustNewConstMetric(mc.hostConntrackReadDurationSecondsDesc, prometheus.GaugeValue, conntrackSeconds),
		prometheus.MustNewConstMetric(mc.hostConntrackRawOkDesc, prometheus.GaugeValue, float64(atomic.LoadUint64(&mc.cm.conntrackRawOK))),
		prometheus.MustNewConstMetric(mc.hostConntrackRawENOBUFSTotalDesc, prometheus.CounterValue, float64(atomic.LoadUint64(&mc.cm.conntrackRawENOBUFSTotal))),
		prometheus.MustNewConstMetric(mc.hostConntrackRawParseErrorsTotalDesc, prometheus.CounterValue, float64(atomic.LoadUint64(&mc.cm.conntrackRawParseErrorsTotal))),
		prometheus.MustNewConstMetric(mc.hostConntrackLastSuccessTimestampDesc, prometheus.GaugeValue, float64(atomic.LoadInt64(&mc.cm.conntrackLastSuccessUnix))),
		prometheus.MustNewConstMetric(mc.hostConntrackStaleSecondsDesc, prometheus.GaugeValue, mc.cm.conntrackStaleSeconds()),
		prometheus.MustNewConstMetric(mc.hostConntrackEntriesDesc, prometheus.GaugeValue, float64(ctCount)),
		prometheus.MustNewConstMetric(mc.hostConntrackReadErrorsTotalDesc, prometheus.CounterValue, float64(conntrackErrors)),
		prometheus.MustNewConstMetric(mc.hostConntrackMaxDesc, prometheus.GaugeValue, float64(ctMax)),
		prometheus.MustNewConstMetric(mc.hostConntrackUtilizationDesc, prometheus.GaugeValue, ctUtil),
		prometheus.MustNewConstMetric(mc.hostGoHeapAllocBytesDesc, prometheus.GaugeValue, heapAllocBytes),
		prometheus.MustNewConstMetric(mc.hostCacheCleanupDurationSecondsDesc, prometheus.GaugeValue, cacheCleanupSeconds),
		prometheus.MustNewConstMetric(mc.hostCpuUsagePercentDesc, prometheus.GaugeValue, cpuPercent),
		prometheus.MustNewConstMetric(mc.hostMemFreeMBDesc, prometheus.GaugeValue, memFreeMB),
		prometheus.MustNewConstMetric(mc.hostMemAvailableMBDesc, prometheus.GaugeValue, memAvailMB),
	}

	mc.tm.collectHostThreatMetrics(&hostMetrics)

	for _, metric := range hostMetrics {
		ch <- metric
	}

	for _, metric := range agg.metrics {
		ch <- metric
	}
}

func (mc *MetricsCollector) runCollectionCycle() []prometheus.Metric {
	mc.collectionMu.Lock()
	defer mc.collectionMu.Unlock()

	ch := make(chan prometheus.Metric, 1024)
	metrics := make([]prometheus.Metric, 0, 1024)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for m := range ch {
			metrics = append(metrics, m)
		}
	}()
	mc.collectHeavy(ch)
	close(ch)
	wg.Wait()
	return metrics
}

func (mc *MetricsCollector) startBackgroundCollector() {
	interval := mc.collectionInterval
	if interval <= 0 {
		interval = 15 * time.Second
	}

	for {
		t := time.NewTimer(interval)
		select {
		case <-mc.shutdownChan:
			t.Stop()
			logCollectorMetric.Info("background_collector_shutdown")
			return
		case <-t.C:
		}

		metrics := mc.runCollectionCycle()
		mc.cacheMu.Lock()
		mc.cachedMetrics = metrics
		mc.cacheMu.Unlock()
	}
}

func (mc *MetricsCollector) Collect(ch chan<- prometheus.Metric) {
	mc.backgroundOnce.Do(func() {
		go mc.startBackgroundCollector()
	})
	mc.cacheMu.RLock()
	cached := mc.cachedMetrics
	mc.cacheMu.RUnlock()
	if len(cached) == 0 {
		cached = mc.runCollectionCycle()
		mc.cacheMu.Lock()
		mc.cachedMetrics = cached
		mc.cacheMu.Unlock()
	}
	for _, m := range cached {
		ch <- m
	}
}
