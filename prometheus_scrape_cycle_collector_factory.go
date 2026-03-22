package main

import (
	"fmt"
	libvirt "github.com/digitalocean/go-libvirt"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"
)

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
		outboundBehaviorEnabled:     cfg.OutboundBehaviorEnable,
		inboundBehaviorEnabled:      cfg.InboundBehaviorEnable,
		behaviorThresholds:          cfg.BehaviorThresholds,
		conntrackAcctEnabled:        cfg.ConntrackAcctEnabled,
		behaviorSensitivity:         cfg.BehaviorSensitivity,
		behaviorEWMATauFast:         cfg.BehaviorEWMATauFast,
		behaviorEWMATauSlow:         cfg.BehaviorEWMATauSlow,
		behaviorInboundPortNames:    cfg.BehaviorPortsInboundMonitored,
		behaviorOutboundPortNames:   cfg.BehaviorPortsOutboundMonitored,
		externalBehaviorRules:       cfg.BehaviorExternalRules,
		conntrackRawRcvBufBytes:     cfg.ConntrackRawRcvBufBytes,
		conntrackNetlinkRecvTimeout: cfg.ConntrackNetlinkRecvTimeout,
		conntrackIPv4Enable:         cfg.ConntrackIPv4Enable,
		conntrackIPv6Enable:         cfg.ConntrackIPv6Enable,
		ovnMapper:                   NewOVNMapper(),
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
