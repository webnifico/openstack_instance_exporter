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
	if _, err := libvirtSocketPathFromURI(cfg.LibvirtURI); err != nil {
		return nil, err
	}

	mc := &MetricsCollector{
		shutdownChan:       make(chan struct{}),
		scoring:            cfg.Severity,
		collectionInterval: cfg.CollectionInterval,
		intelHistory:       make(map[string]*IntelHistory),
	}

	mc.im = newInstanceManager(cfg)
	mc.tm = newThreatManager(cfg, mc.shutdownChan)
	mc.cm = newConntrackManager(cfg)
	mc.cm.LogThreat = mc.tm.logThreatEvent

	initializeCollectorMetricDescriptors(mc)
	startThreatRefreshers(mc.tm)

	return mc, nil
}

func newInstanceManager(cfg CollectorConfig) *InstanceManager {
	im := &InstanceManager{
		libvirtURI:         cfg.LibvirtURI,
		workerCount:        cfg.WorkerCount,
		domainMeta:         make(map[string]*DomainStatic),
		activeInstances:    make(map[string]struct{}),
		vmIPSet:            make(map[IPKey]struct{}),
		vmIPToInstance:     make(map[IPKey]string),
		vmIPOwners:         make(map[IPKey]map[string]struct{}),
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
	im.xmlInflight = make(map[string]*domainXMLInflight, 256)
	im.xmlRPCSem = make(chan struct{}, xmlMaxConcurrent)
	initializeInstanceSampleState(im)

	return im
}

func initializeInstanceSampleState(im *InstanceManager) {
	for i := 0; i < shardCount; i++ {
		im.cpuSamples[i] = make(map[string]cpuSample)
		im.diskSamples[i] = make(map[string]diskSample)
		im.memSamples[i] = make(map[string]memSample)
		im.netSamples[i] = make(map[string]netSample)
	}
}

func newThreatManager(cfg CollectorConfig, shutdownChan chan struct{}) *ThreatManager {
	tm := &ThreatManager{
		shutdownChan: shutdownChan,
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

	tm.Providers = newThreatProviders(tm, cfg)
	for _, p := range tm.Providers {
		p.SetAtomic.Store(p.Set)
	}

	return tm
}

func newThreatProviders(tm *ThreatManager, cfg CollectorConfig) []*IPThreatProvider {
	return []*IPThreatProvider{
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
			Fetcher:                       func() (map[IPKey]struct{}, error) { return tm.fetchOnionoo(cfg.TorExit.URL) },
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
			Fetcher:                       func() (map[IPKey]struct{}, error) { return tm.fetchOnionoo(cfg.TorRelay.URL) },
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
			Fetcher:                       func() (map[IPKey]struct{}, error) { return tm.fetchURLLines(cfg.Emerging.URL) },
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
			Fetcher:                       func() (map[IPKey]struct{}, error) { return tm.fetchFileLines(cfg.Custom.Path) },
		},
	}
}

func newConntrackManager(cfg CollectorConfig) *ConntrackManager {
	cm := &ConntrackManager{
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
	if cm.behaviorInboundPortNames == nil {
		cm.behaviorInboundPortNames = builtinBehaviorInboundMonitoredPorts()
	}
	if cm.behaviorOutboundPortNames == nil {
		cm.behaviorOutboundPortNames = builtinBehaviorOutboundMonitoredPorts()
	}
	initializeConntrackState(cm)

	return cm
}

func initializeConntrackState(cm *ConntrackManager) {
	for i := 0; i < shardCount; i++ {
		cm.outboundPrev[i] = make(map[BehaviorKey]outboundPrev)
		cm.outboundPrevDstPorts[i] = make(map[BehaviorKey]outboundPrevDstPorts)
		cm.outboundPrevLastSeen[i] = make(map[BehaviorKey]int64)
		cm.inboundPrev[i] = make(map[BehaviorKey]outboundPrev)
		cm.inboundPrevDstPorts[i] = make(map[BehaviorKey]outboundPrevDstPorts)
		cm.inboundPrevLastSeen[i] = make(map[BehaviorKey]int64)
		cm.behaviorEWMA[i] = make(map[behaviorIdentityKey]*behaviorEWMAState)
		cm.behaviorLastSeverity[i] = make(map[behaviorIdentityKey]float64)
	}

	cm.behaviorPersist = make(map[behaviorAlertKey]*behaviorPersistState)
	cm.behaviorEmit = make(map[behaviorEmitKey]*behaviorEmitState)
	cm.miningAlerts = make(map[behaviorIdentityKey]*miningAlertState)
}

func initializeCollectorMetricDescriptors(mc *MetricsCollector) {
	initHostMetrics(mc)
	initInstanceMetrics(mc.im)
	initInstanceSeverityMetrics(mc)
	initThreatMetrics(mc.tm)
	initConntrackMetrics(mc.cm)
}

func startThreatRefreshers(tm *ThreatManager) {
	for _, p := range tm.Providers {
		if p.Enabled {
			provider := p
			go tm.runProviderRefresher(provider)
		}
	}

	if tm.spamEnabled {
		go tm.startSpamhausRefresher()
	}
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
