package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"libvirt.org/go/libvirt"
)

// -----------------------------------------------------------------------------
// MetricsCollector Creation
// -----------------------------------------------------------------------------

func NewMetricsCollector(cfg CollectorConfig) (*MetricsCollector, error) {
	if cfg.LibvirtURI == "" {
		return nil, fmt.Errorf("LibvirtURI is required")
	}

	mc := &MetricsCollector{
		shutdownChan:       make(chan struct{}),
		minAttentionScore:  cfg.MinAttentionScore,
		scoring:            cfg.Scoring,
		collectionInterval: cfg.CollectionInterval,
	}

	// Initialize Instance Manager
	mc.im = &InstanceManager{
		libvirtURI:            cfg.LibvirtURI,
		workerCount:           cfg.WorkerCount,
		readThreshold:         cfg.Threshold.Read,
		writeThreshold:        cfg.Threshold.Write,
		defaultReadThreshold:  cfg.Threshold.DefaultRead,
		defaultWriteThreshold: cfg.Threshold.DefaultWrite,
		domainMeta:            make(map[string]*DomainStatic),
		activeInstances:       make(map[string]struct{}),
		cpuSamples:            make(map[string]cpuSample),
		diskSamples:           make(map[string]diskSample),
	}

	// Initialize Threat Manager
	mc.tm = &ThreatManager{
		shutdownChan: mc.shutdownChan,
		httpClient:   &http.Client{Timeout: 15 * time.Second},

		hostThreatsEnabled:  cfg.HostThreats.Enable,
		hostIPsAllowPrivate: cfg.HostThreats.IPsAllowPrivate,
		hostInterfaces:      cfg.HostThreats.Interfaces,

		torExitEnabled: cfg.TorExit.Enable,
		torExitURL:     cfg.TorExit.URL,
		torExitRefresh: cfg.TorExit.Refresh,
		torExitSet:     make(map[string]struct{}),
		torExitDir:     cfg.TorExit.Direction,

		torRelayEnabled: cfg.TorRelay.Enable,
		torRelayURL:     cfg.TorRelay.URL,
		torRelayRefresh: cfg.TorRelay.Refresh,
		torRelaySet:     make(map[string]struct{}),
		torRelayDir:     cfg.TorRelay.Direction,

		spamEnabled:   cfg.Spamhaus.Enable,
		spamURL:       cfg.Spamhaus.URLv4,
		spamV6URL:     cfg.Spamhaus.URLv6,
		spamRefresh:   cfg.Spamhaus.Refresh,
		spamNets:      make([]*net.IPNet, 0),
		spamBucketsV4: make(map[string][]*net.IPNet),
		spamBucketsV6: make(map[string][]*net.IPNet),
		spamDir:       cfg.Spamhaus.Direction,

		emThreatsEnabled: cfg.Emerging.Enable,
		emThreatsURL:     cfg.Emerging.URL,
		emThreatsRefresh: cfg.Emerging.Refresh,
		emThreatsSet:     make(map[string]struct{}),
		emThreatsDir:     cfg.Emerging.Direction,

		customListEnabled: cfg.Custom.Enable,
		customListPath:    cfg.Custom.Path,
		customListRefresh: cfg.Custom.Refresh,
		customListSet:     make(map[string]struct{}),
		customListDir:     cfg.Custom.Direction,

		threatFileEnabled:     cfg.ThreatFileEnable,
		threatFilePath:        cfg.ThreatFilePath,
		threatFileMinInterval: cfg.ThreatFileMinInterval,
		threatLastHit:         make(map[string]time.Time),

		torExitCount:    make(map[string]float64),
		torRelayCount:   make(map[string]float64),
		spamCount:       make(map[string]float64),
		emThreatsCount:  make(map[string]float64),
		customListCount: make(map[string]float64),
	}

	// Initialize Conntrack Manager
	mc.cm = &ConntrackManager{
		outboundBehaviorEnabled: cfg.OutboundBehaviorEnable,
		inboundBehaviorEnabled:  cfg.InboundBehaviorEnable,
		behaviorThresholds:      cfg.BehaviorThresholds,
		// FIX: Use struct keys for map initialization
		outboundPrev:         make(map[BehaviorKey]outboundPrev),
		outboundPrevDstPorts: make(map[BehaviorKey]outboundPrevDstPorts),
		inboundPrev:          make(map[BehaviorKey]outboundPrev),
		inboundPrevDstPorts:  make(map[BehaviorKey]outboundPrevDstPorts),
		behaviorState:        make(map[AnomalyKey]*AnomalyState),
	}

	// WIRE UP THE LOGGER CALLBACK
	mc.cm.LogThreat = mc.tm.logThreatEventToFile

	mc.shutdownEvents = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "oie_exporter_shutdown_total",
		Help: "shutdown events",
	})

	// Open Threat File
	if mc.tm.threatFileEnabled && mc.tm.threatFilePath != "" {
		f, err := os.OpenFile(mc.tm.threatFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			logThreatfileThreat.Error("threatfile_open_failed", "path", mc.tm.threatFilePath, "err", err)
		} else {
			mc.tm.threatFile = f
			logThreatfileThreat.Info("threatfile_enabled", "path", mc.tm.threatFilePath)
		}
	}

	// Initialize Metric Descriptors
	initHostMetrics(mc)
	initInstanceMetrics(mc.im)
	initInstanceScoreMetrics(mc)
	initThreatMetrics(mc.tm)
	initConntrackMetrics(mc.cm)

	// Start Background Refreshers
	if mc.tm.torExitEnabled {
		go mc.tm.startTorExitRefresher()
	}
	if mc.tm.torRelayEnabled {
		go mc.tm.startTorRelayRefresher()
	}
	if mc.tm.spamEnabled {
		go mc.tm.startSpamhausRefresher()
	}
	if mc.tm.emThreatsEnabled {
		go mc.tm.startEmThreatsRefresher()
	}
	if mc.tm.customListEnabled && mc.tm.customListPath != "" {
		go mc.tm.startCustomListRefresher()
	}

	return mc, nil
}

// -----------------------------------------------------------------------------
// Persistent Libvirt Connection Logic
// -----------------------------------------------------------------------------

func (mc *MetricsCollector) getLibvirtConn() (*libvirt.Connect, error) {
	mc.libvirtMu.Lock()
	defer mc.libvirtMu.Unlock()

	// 1. Check if existing connection is alive
	if mc.libvirtConn != nil {
		// GetLibVersion is a lightweight call to check if the connection is active
		if _, err := mc.libvirtConn.GetLibVersion(); err == nil {
			return mc.libvirtConn, nil
		}
		// If dead, close and cleanup
		mc.libvirtConn.Close()
		mc.libvirtConn = nil
	}

	// 2. Establish new connection
	conn, err := libvirt.NewConnect(mc.im.libvirtURI)
	if err != nil {
		return nil, err
	}
	mc.libvirtConn = conn
	return mc.libvirtConn, nil
}

// -----------------------------------------------------------------------------
// Prometheus Collector Implementation
// -----------------------------------------------------------------------------

func (mc *MetricsCollector) Describe(ch chan<- *prometheus.Desc) {
	mc.im.describeInstanceMetrics(ch)
	mc.tm.describeThreatMetrics(ch)
	mc.cm.describeConntrackMetrics(ch)

	ch <- mc.instanceResourceScoreDesc
	ch <- mc.instanceThreatScoreDesc
	ch <- mc.instanceAttentionScoreDesc

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
	ch <- mc.hostConntrackMaxDesc
	ch <- mc.hostConntrackUtilizationDesc
	ch <- mc.hostCacheCleanupDurationSecondsDesc

	// Threat Manager Host Metrics
	mc.tm.describeHostMetrics(ch)
}

func (mc *MetricsCollector) collectHeavy(ch chan<- prometheus.Metric) {
	cycleStart := time.Now()

	prevEnd := atomic.LoadInt64(&mc.lastCycleEndUnixNano)
	var lagSeconds float64
	if prevEnd > 0 {
		lagDur := time.Since(time.Unix(0, prevEnd)).Seconds()
		if lagDur > 0 {
			lagSeconds = lagDur
		}
	}

	logCollectorMetric.Debug("scrapetime_collection_start")

	// -------------------------------------------------------------------------
	// PHASE 1: Parallel Data Fetching
	// -------------------------------------------------------------------------

	var (
		domainStats      []libvirt.DomainStats
		ctEntries        []ConntrackEntry
		errLibvirt       error
		errConntrack     error
		libvirtSeconds   float64
		conntrackSeconds float64
		wg               sync.WaitGroup
	)

	wg.Add(2)

	// Goroutine A: Fetch Libvirt Stats
	go func() {
		defer wg.Done()
		lStart := time.Now()

		conn, err := mc.getLibvirtConn()
		if err != nil {
			errLibvirt = err
			return
		}

		// Flags for bulk stats
		flags := libvirt.CONNECT_GET_ALL_DOMAINS_STATS_RUNNING
		statsTypes := libvirt.DOMAIN_STATS_CPU_TOTAL | libvirt.DOMAIN_STATS_BALLOON | libvirt.DOMAIN_STATS_VCPU | libvirt.DOMAIN_STATS_INTERFACE | libvirt.DOMAIN_STATS_BLOCK

		domainStats, errLibvirt = conn.GetAllDomainStats(nil, statsTypes, flags)
		if errLibvirt != nil {
			// If call fails, assume connection might be bad; force reconnect next time
			mc.libvirtMu.Lock()
			if mc.libvirtConn == conn {
				mc.libvirtConn.Close()
				mc.libvirtConn = nil
			}
			mc.libvirtMu.Unlock()
		}

		libvirtSeconds = time.Since(lStart).Seconds()
	}()

	// Goroutine B: Fetch Conntrack
	go func() {
		defer wg.Done()
		cStart := time.Now()

		// PASS NIL to fetch ALL flows immediately (Optimized for parallelism).
		// Filtering will happen in userspace logic later.
		ctEntries, errConntrack = mc.cm.readConntrack()
		conntrackSeconds = time.Since(cStart).Seconds()
	}()

	// Wait for IO completion
	wg.Wait()

	// -------------------------------------------------------------------------
	// PHASE 2: Data Processing & Metrics
	// -------------------------------------------------------------------------

	// Handle Errors
	if errLibvirt != nil {
		atomic.AddUint64(&mc.hostCollectionErrors, 1)
		logCollectorMetric.Error("domain_stats_failed", "err", errLibvirt)
	} else {
		logCollectorMetric.Debug("domain_stats_success", "active_domains", len(domainStats))
	}

	if errConntrack != nil {
		atomic.AddUint64(&mc.hostCollectionErrors, 1)
		atomic.AddUint64(&mc.cm.conntrackReadErrors, 1)
		logConntrackMetric.Error("conntrack_read_failed", "err", errConntrack)
	}
	ctCount := len(ctEntries)

	// Build active VM Instance set
	activeSet := make(map[string]struct{}, len(domainStats))
	vmIPSet := make(map[string]struct{})

	for _, stat := range domainStats {
		if stat.Domain != nil {
			uuid, err := stat.Domain.GetUUIDString()
			if err == nil {
				activeSet[uuid] = struct{}{}
				if meta, err := mc.im.getDomainMeta(stat.Domain); err == nil {
					for _, ip := range meta.FixedIPs {
						vmIPSet[ip.Address] = struct{}{}
					}
				}
			}
		}
	}

	// Sync active instances to managers
	mc.im.setActiveInstances(activeSet)

	// Fetch Host IPs for Infrastructure Protection
	hostIPs := mc.tm.getHostIPs()
	hostIPStrings := make([]string, 0, len(hostIPs))
	for _, hip := range hostIPs {
		hostIPStrings = append(hostIPStrings, hip.Address)
	}

	// Run Cleanups
	cleanupStart := time.Now()
	mc.im.cleanupDomainMeta()
	mc.im.cleanupResourceSamples()
	mc.cm.cleanupBehaviorMaps(activeSet)
	mc.cm.cleanupBehaviorState(activeSet)
	mc.tm.cleanupThreatCounts(activeSet)
	mc.tm.cleanupThreatLastHit()
	cacheCleanupSeconds := time.Since(cleanupStart).Seconds()

	// Map Conntrack Flows to VMs
	usePerIPConntrack := mc.cm.outboundBehaviorEnabled ||
		mc.cm.inboundBehaviorEnabled ||
		mc.tm.anyThreatsEnabled()

	var ipFlows map[string][]ConntrackEntry
	if usePerIPConntrack && ctCount > 0 && len(vmIPSet) > 0 {
		ipFlows = make(map[string][]ConntrackEntry)
		for _, ct := range ctEntries {
			// In-memory Filtering
			_, srcOk := vmIPSet[ct.Src]
			_, dstOk := vmIPSet[ct.Dst]

			if srcOk {
				ipFlows[ct.Src] = append(ipFlows[ct.Src], ct)
			}
			if dstOk && ct.Dst != ct.Src {
				ipFlows[ct.Dst] = append(ipFlows[ct.Dst], ct)
			}
		}
	}

	// Aggregate and collect domain metrics
	agg := &hostAgg{projects: make(map[string]struct{})}
	if len(domainStats) > 0 {
		numWorkers := mc.im.workerCount
		if numWorkers <= 0 {
			numWorkers = runtime.NumCPU()
		}
		if numWorkers > 64 {
			numWorkers = 64
		}

		jobs := make(chan libvirt.DomainStats, len(domainStats))
		var wgWorkers sync.WaitGroup

		for i := 0; i < numWorkers; i++ {
			wgWorkers.Add(1)
			go func() {
				defer wgWorkers.Done()
				for stat := range jobs {
					// Delegate metric collection to InstanceManager
					mc.collectDomainMetrics(stat, ipFlows, hostIPStrings, agg)
					if stat.Domain != nil {
						stat.Domain.Free()
					}
				}
			}()
		}

		for _, s := range domainStats {
			jobs <- s
		}
		close(jobs)
		wgWorkers.Wait()
	}

	cycleEnd := time.Now()
	cycleSeconds := cycleEnd.Sub(cycleStart).Seconds()

	// Host-level Metrics
	ctMax := hostConntrackMax()
	var ctUtil float64
	if ctMax > 0 {
		ctUtil = float64(ctCount) / float64(ctMax)
	}

	totalMemBytes := hostTotalMemBytes()
	totalMemMB := float64(totalMemBytes) * bytesToMegabytes

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	heapAllocBytes := float64(ms.HeapAlloc)

	errorsTotal := atomic.LoadUint64(&mc.hostCollectionErrors)
	conntrackErrors := atomic.LoadUint64(&mc.cm.conntrackReadErrors)

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
		prometheus.MustNewConstMetric(mc.hostConntrackEntriesDesc, prometheus.GaugeValue, float64(ctCount)),
		prometheus.MustNewConstMetric(mc.hostConntrackReadErrorsTotalDesc, prometheus.CounterValue, float64(conntrackErrors)),
		prometheus.MustNewConstMetric(mc.hostConntrackMaxDesc, prometheus.GaugeValue, float64(ctMax)),
		prometheus.MustNewConstMetric(mc.hostConntrackUtilizationDesc, prometheus.GaugeValue, ctUtil),
		prometheus.MustNewConstMetric(mc.hostGoHeapAllocBytesDesc, prometheus.GaugeValue, heapAllocBytes),
		prometheus.MustNewConstMetric(mc.hostCacheCleanupDurationSecondsDesc, prometheus.GaugeValue, cacheCleanupSeconds),
	}

	mc.tm.collectHostThreatMetrics(&hostMetrics)

	for _, metric := range hostMetrics {
		ch <- metric
	}

	agg.mu.Lock()
	for _, metric := range agg.metrics {
		ch <- metric
	}
	agg.mu.Unlock()

	atomic.StoreInt64(&mc.lastCycleEndUnixNano, cycleEnd.UnixNano())
	logCollectorMetric.Debug("scrapetime_collection_end", "duration_seconds", cycleSeconds)
}

// runCollectionCycle executes a full collection cycle and returns the produced metrics.
func (mc *MetricsCollector) runCollectionCycle() []prometheus.Metric {
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

// startBackgroundCollector runs collection cycles on a fixed interval and updates the cache.
func (mc *MetricsCollector) startBackgroundCollector() {
	interval := mc.collectionInterval
	if interval <= 0 {
		interval = 15 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-mc.shutdownChan:
			logCollectorMetric.Info("background_collector_shutdown")
			return
		case <-ticker.C:
			metrics := mc.runCollectionCycle()
			mc.cacheMu.Lock()
			mc.cachedMetrics = metrics
			mc.cacheMu.Unlock()
		}
	}
}

// Collect implements the prometheus.Collector interface using cached metrics.
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
