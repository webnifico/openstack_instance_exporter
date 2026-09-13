package main

import (
	"fmt"
	libvirt "github.com/digitalocean/go-libvirt"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"time"
)

const defaultLibvirtRPCTimeout = 10 * time.Second

type LocalDialer struct {
	SocketPath string
	mu         sync.Mutex
	conn       net.Conn
	closed     bool
}

func (d *LocalDialer) Dial() (net.Conn, error) {
	conn, err := net.DialTimeout("unix", d.SocketPath, 2*time.Second)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		_ = conn.Close()
		return nil, net.ErrClosed
	}
	d.conn = conn
	d.mu.Unlock()
	return conn, nil
}

func (d *LocalDialer) Close() error {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	conn := d.conn
	d.conn = nil
	d.closed = true
	d.mu.Unlock()
	if conn == nil {
		return nil
	}
	return conn.Close()
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
		shutdownChan:        make(chan struct{}),
		scoring:             cfg.Severity,
		collectionInterval:  cfg.CollectionInterval,
		intelHistory:        make(map[string]*IntelHistory),
		threatEWMATau:       cfg.ThreatEWMATau,
		libvirtRPCTimeout:   defaultLibvirtRPCTimeout,
		volumeRetypeEnabled: cfg.VolumeRetypeEnable,
	}
	if cfg.VolumeRetypeEnable {
		mc.volumeRetypeJobs = make(map[volumeRetypeKey]volumeRetypeJob)
		mc.volumeRetypeCompleted = make(map[volumeRetypeCompletionKey]volumeRetypeCompletion)
		mc.volumeRetypeRPCInflight = make(map[string]struct{})
	}

	mc.im = newInstanceManager(cfg)
	mc.libvirtSafety = &libvirtReadSafety{runtimeStateDir: "/run/libvirt/qemu"}
	mc.im.libvirtSafety = mc.libvirtSafety
	mc.tm = newThreatManager(cfg, mc.shutdownChan)
	mc.cm = newConntrackManager(cfg)
	mc.cm.LogThreat = mc.tm.logThreatEvent

	initializeCollectorMetricDescriptors(mc)
	startThreatRefreshers(mc.tm)

	return mc, nil
}

func newInstanceManager(cfg CollectorConfig) *InstanceManager {
	im := &InstanceManager{
		libvirtURI:           cfg.LibvirtURI,
		workerCount:          cfg.WorkerCount,
		resourceSampleMaxAge: resourceAxisMaxRetainedAge(cfg.CollectionInterval),
		domainMeta:           make(map[string]*DomainStatic),
		activeInstances:      make(map[string]struct{}),
		vmIPSet:              make(map[IPKey]struct{}),
		vmIPToInstance:       make(map[IPKey]string),
		vmIPOwners:           make(map[IPKey]map[string]struct{}),
		vmIPKeysByInstance:   make(map[string][]IPKey),
		libvirtRPCTimeout:    defaultLibvirtRPCTimeout,
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
	im.domainXMLRPCInflight = make(map[string]struct{}, 256)
	im.xmlRPCSem = make(chan struct{}, xmlMaxConcurrent)
	initializeInstanceSampleState(im)

	return im
}

func initializeInstanceSampleState(im *InstanceManager) {
	if im.resourceGeneration == nil {
		im.resourceGeneration = make(map[string]int32)
	}
	if im.resourceGenerationCPUTime == nil {
		im.resourceGenerationCPUTime = make(map[string]uint64)
	}
	if im.resourceGenerationToken == nil {
		im.resourceGenerationToken = make(map[string]string)
	}
	if im.resourceDimensions == nil {
		im.resourceDimensions = make(map[string]resourceDimensions)
	}
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
	cm.behaviorLifecycleFreeze = make(map[string]*behaviorLifecycleFreezeState)
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
	if err := mc.libvirtSafety.available(time.Now()); err != nil {
		return nil, err
	}
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

	connectResult := make(chan error, 1)
	go func() { connectResult <- l.Connect() }()
	timeout := mc.effectiveLibvirtRPCTimeout()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	var connectErr error
	select {
	case connectErr = <-connectResult:
	case <-timer.C:
		mc.libvirtSafety.pause(time.Now())
		_ = dialer.Close()
		return nil, fmt.Errorf("timed out connecting to libvirt rpc after %s", timeout)
	}
	if connectErr != nil {
		_ = dialer.Close()
		return nil, fmt.Errorf("failed to connect to libvirt rpc: %v", connectErr)
	}

	mc.libvirtConn = l
	mc.libvirtDialer = dialer
	return mc.libvirtConn, nil
}

func (mc *MetricsCollector) effectiveLibvirtRPCTimeout() time.Duration {
	if mc != nil && mc.libvirtRPCTimeout > 0 {
		return mc.libvirtRPCTimeout
	}
	return defaultLibvirtRPCTimeout
}

func libvirtSocketPathFromURI(uri string) (string, error) {
	const defaultSock = "/var/run/libvirt/libvirt-sock"
	invalid := func() (string, error) {
		return "", fmt.Errorf(
			"unsupported libvirt.uri for go-libvirt dialer: %s (use qemu:///system, an absolute socket path, or a local qemu+unix URI)",
			uri,
		)
	}

	if uri == "" || uri != strings.TrimSpace(uri) || strings.IndexByte(uri, 0) >= 0 {
		return invalid()
	}
	if strings.HasPrefix(uri, "/") {
		return uri, nil
	}
	if uri == "qemu:///system" {
		return defaultSock, nil
	}

	u, err := url.Parse(uri)
	if err != nil || u.User != nil || u.Host != "" || u.Fragment != "" || u.Opaque != "" {
		return invalid()
	}
	if u.Scheme != "qemu+unix" && u.Scheme != "unix" {
		return invalid()
	}

	query, queryErr := url.ParseQuery(u.RawQuery)
	if queryErr != nil {
		return invalid()
	}
	if len(query) != 0 {
		values, ok := query["socket"]
		if !ok || len(query) != 1 || len(values) != 1 || values[0] == "" ||
			!strings.HasPrefix(values[0], "/") || strings.IndexByte(values[0], 0) >= 0 ||
			(u.Path != "" && u.Path != "/system") {
			return invalid()
		}
		return values[0], nil
	}
	if u.RawQuery != "" {
		return invalid()
	}
	if u.Path == "/system" {
		return defaultSock, nil
	}
	if u.Path == "" || !strings.HasPrefix(u.Path, "/") || strings.IndexByte(u.Path, 0) >= 0 {
		return invalid()
	}
	return u.Path, nil
}
