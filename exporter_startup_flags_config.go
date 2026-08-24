package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	os.Exit(runMain())
}

func validateStartupScalarFlags(behaviorSensitivity, resourceWeight, behaviorWeight, threatWeight float64) error {
	for _, value := range []struct {
		name  string
		value float64
	}{
		{name: "behavior.sensitivity", value: behaviorSensitivity},
		{name: "severity.weight.resource", value: resourceWeight},
		{name: "severity.weight.behavior", value: behaviorWeight},
		{name: "severity.weight.threat_list", value: threatWeight},
	} {
		if math.IsNaN(value.value) || math.IsInf(value.value, 0) {
			return fmt.Errorf("%s must be finite", value.name)
		}
	}
	return nil
}

type startupRuntimeFlags struct {
	listenAddress               string
	collectionInterval          time.Duration
	workerCount                 int
	behaviorEWMATauFast         time.Duration
	behaviorEWMATauSlow         time.Duration
	conntrackRawRcvBufBytes     int
	conntrackNetlinkRecvTimeout time.Duration
	threatLogMinInterval        time.Duration
	threats                     CollectorConfig
}

func validateThreatFeedURL(name, rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil {
		return fmt.Errorf("%s must be an HTTP(S) URL without embedded credentials", name)
	}
	return nil
}

func validateStartupRuntimeFlags(values startupRuntimeFlags) error {
	if strings.TrimSpace(values.listenAddress) == "" {
		return fmt.Errorf("web.listen-address must not be empty")
	}
	if values.collectionInterval <= 0 {
		return fmt.Errorf("collection.interval must be greater than zero")
	}
	if values.workerCount < 0 {
		return fmt.Errorf("worker.count must be zero or greater")
	}
	if values.behaviorEWMATauFast <= 0 {
		return fmt.Errorf("behavior.ewma_fast_tau must be greater than zero")
	}
	if values.behaviorEWMATauSlow <= 0 {
		return fmt.Errorf("behavior.ewma_slow_tau must be greater than zero")
	}
	if values.behaviorEWMATauFast >= values.behaviorEWMATauSlow {
		return fmt.Errorf("behavior.ewma_fast_tau must be less than behavior.ewma_slow_tau")
	}
	if values.conntrackRawRcvBufBytes < 0 {
		return fmt.Errorf("conntrack.raw.rcvbuf_bytes must be zero or greater")
	}
	if values.conntrackNetlinkRecvTimeout <= 0 {
		return fmt.Errorf("conntrack.raw.rcv_timeout must be greater than zero")
	}
	if values.threatLogMinInterval < 0 {
		return fmt.Errorf("threat.log.min_interval must be zero or greater")
	}

	validateProvider := func(enabled bool, prefix, urlFlag, rawURL string, refresh time.Duration) error {
		if !enabled {
			return nil
		}
		if refresh < 0 {
			return fmt.Errorf("%s.refresh must be zero or greater", prefix)
		}
		return validateThreatFeedURL(urlFlag, rawURL)
	}
	if err := validateProvider(values.threats.TorExit.Enable, "tor.exit", "tor.exit.url", values.threats.TorExit.URL, values.threats.TorExit.Refresh); err != nil {
		return err
	}
	if err := validateProvider(values.threats.TorRelay.Enable, "tor.relay", "tor.relay.url", values.threats.TorRelay.URL, values.threats.TorRelay.Refresh); err != nil {
		return err
	}
	if err := validateProvider(values.threats.Emerging.Enable, "emergingthreats", "emergingthreats.url", values.threats.Emerging.URL, values.threats.Emerging.Refresh); err != nil {
		return err
	}
	if values.threats.Spamhaus.Enable {
		if values.threats.Spamhaus.Refresh < 0 {
			return fmt.Errorf("spamhaus refresh interval must be zero or greater")
		}
		configured := 0
		if strings.TrimSpace(values.threats.Spamhaus.URLv4) != "" {
			configured++
			if err := validateThreatFeedURL("spamhaus.url", values.threats.Spamhaus.URLv4); err != nil {
				return err
			}
		}
		if strings.TrimSpace(values.threats.Spamhaus.URLv6) != "" {
			configured++
			if err := validateThreatFeedURL("spamhaus.ipv6.url", values.threats.Spamhaus.URLv6); err != nil {
				return err
			}
		}
		if configured == 0 {
			return fmt.Errorf("spamhaus requires at least one configured feed URL")
		}
	}
	if values.threats.Custom.Enable {
		if values.threats.Custom.Refresh < 0 {
			return fmt.Errorf("customlist refresh interval must be zero or greater")
		}
		if strings.TrimSpace(values.threats.Custom.Path) == "" {
			return fmt.Errorf("customlist.path must not be empty when customlist is enabled")
		}
		if strings.IndexByte(values.threats.Custom.Path, 0) >= 0 {
			return fmt.Errorf("customlist.path contains a NUL byte")
		}
	}
	return nil
}

func runMain() int {
	var (
		listenAddress, metricsPath, libvirtURI, logLevelFlag, logFilePath          string
		hostInterfacesCSV, contactsDirection                                       string
		workerCount                                                                int
		collectionInterval, threatLogMinInterval                                   time.Duration
		behaviorEWMATauFast, behaviorEWMATauSlow                                   time.Duration
		behaviorSensitivity                                                        float64
		behaviorPortsConfigPath                                                    string
		behaviorRulesConfigPath                                                    string
		logFileEnable, outboundBehavior, inboundBehavior, hostThreats, hostPrivate bool

		conntrackRawRcvBufBytes     int
		conntrackNetlinkRecvTimeout time.Duration
		conntrackIPv4Enable         bool
		conntrackIPv6Enable         bool

		// Weights
		wResource, wBehavior, wThreat float64
	)

	// Config Structs to be populated
	cfg := CollectorConfig{}

	// ───────────────────────────────────────────────────────────────
	//	WEB / PROCESS / LIBVIRT
	// ───────────────────────────────────────────────────────────────
	flag.StringVar(&listenAddress, "web.listen-address", "0.0.0.0:9120", "Address to listen on")
	flag.StringVar(&metricsPath, "web.telemetry-path", "/metrics", "Path under which to expose metrics")
	flag.StringVar(&libvirtURI, "libvirt.uri", "qemu:///system", "Libvirt URI")
	flag.DurationVar(&collectionInterval, "collection.interval", 15*time.Second, "Background collection interval")
	flag.IntVar(&workerCount, "worker.count", 0, "Number of concurrent workers (0 = NumCPU)")

	// ───────────────────────────────────────────────────────────────
	//	THRESHOLDS & BEHAVIOR
	// ───────────────────────────────────────────────────────────────
	flag.StringVar(&contactsDirection, "contacts.direction", "out", "Default direction: out, in, any")

	// Dynamic Resource Thresholds

	flag.BoolVar(&outboundBehavior, "outbound.behavior.enable", false, "Enable outbound behavior metrics")
	flag.BoolVar(&inboundBehavior, "inbound.behavior.enable", false, "Enable inbound behavior metrics")
	flag.Float64Var(&behaviorSensitivity, "behavior.sensitivity", 1.0, "Behavior sensitivity (>1 more sensitive)")
	flag.DurationVar(&behaviorEWMATauFast, "behavior.ewma_fast_tau", 3*time.Minute, "Behavior EWMA fast tau (time constant)")
	flag.DurationVar(&behaviorEWMATauSlow, "behavior.ewma_slow_tau", 2*time.Hour, "Behavior EWMA slow tau (time constant)")
	flag.StringVar(&behaviorPortsConfigPath, "behavior.ports_config", "", "Path to behavior ports YAML (optional)")
	flag.StringVar(&behaviorRulesConfigPath, "behavior.rules_config", "", "Path to optional behavior external rules YAML (loaded once)")

	flag.DurationVar(&conntrackNetlinkRecvTimeout, "conntrack.raw.rcv_timeout", 15*time.Second, "SO_RCVTIMEO timeout for raw conntrack reader")
	flag.IntVar(&conntrackRawRcvBufBytes, "conntrack.raw.rcvbuf_bytes", 33554432, "SO_RCVBUF bytes for raw conntrack reader")
	flag.BoolVar(&conntrackIPv4Enable, "conntrack.ipv4.enable", true, "Enable IPv4 conntrack reads")
	flag.BoolVar(&conntrackIPv6Enable, "conntrack.ipv6.enable", true, "Enable IPv6 conntrack reads")

	// ───────────────────────────────────────────────────────────────
	//	SEVERITY SCORING
	// ───────────────────────────────────────────────────────────────
	flag.Float64Var(&wResource, "severity.weight.resource", 0.45, "Weight: Resource Pressure")
	flag.Float64Var(&wBehavior, "severity.weight.behavior", 0.45, "Weight: Behavior Anomalies")
	flag.Float64Var(&wThreat, "severity.weight.threat_list", 0.10, "Weight: Threat List Matches")

	// ───────────────────────────────────────────────────────────────
	//  THREAT LISTS
	// ───────────────────────────────────────────────────────────────
	var dirTorExit, dirTorRelay, dirSpam, dirEmerging, dirCustom string

	bindThreat := func(prefix, urlDef string, refreshDef time.Duration, enable *bool, url *string, refresh *time.Duration, dir *string) {
		flag.BoolVar(enable, prefix+".enable", false, "Enable "+prefix+" detection")
		flag.StringVar(url, prefix+".url", urlDef, prefix+" list URL/Path")
		flag.DurationVar(refresh, prefix+".refresh", refreshDef, "Refresh interval")
		flag.StringVar(dir, prefix+".direction", "", "Direction override (out, in, any)")
	}

	bindThreat("tor.exit", "https://onionoo.torproject.org/details?search=flag:exit&fields=or_addresses", time.Hour, &cfg.TorExit.Enable, &cfg.TorExit.URL, &cfg.TorExit.Refresh, &dirTorExit)
	bindThreat("tor.relay", "https://onionoo.torproject.org/details?search=flag:running&fields=or_addresses", time.Hour, &cfg.TorRelay.Enable, &cfg.TorRelay.URL, &cfg.TorRelay.Refresh, &dirTorRelay)
	bindThreat("emergingthreats", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", 6*time.Hour, &cfg.Emerging.Enable, &cfg.Emerging.URL, &cfg.Emerging.Refresh, &dirEmerging)

	flag.BoolVar(&cfg.Custom.Enable, "customlist.enable", false, "Enable custom IP list")
	flag.StringVar(&cfg.Custom.Path, "customlist.path", "", "Path to custom IP list")
	flag.DurationVar(&cfg.Custom.Refresh, "customlist.refresh", 10*time.Minute, "Custom list refresh interval")
	flag.StringVar(&dirCustom, "customlist.direction", "", "Direction override")

	bindThreat("spamhaus", "https://www.spamhaus.org/drop/drop.txt", 6*time.Hour, &cfg.Spamhaus.Enable, &cfg.Spamhaus.URLv4, &cfg.Spamhaus.Refresh, &dirSpam)
	flag.StringVar(&cfg.Spamhaus.URLv6, "spamhaus.ipv6.url", "https://www.spamhaus.org/drop/dropv6.txt", "Spamhaus IPv6 list")

	flag.BoolVar(&hostThreats, "host.threats.enable", false, "Enable host NIC checks")
	flag.BoolVar(&hostPrivate, "host.ips.allow-private", false, "Include private IPs")
	flag.StringVar(&hostInterfacesCSV, "host.interfaces", "", "NIC whitelist")

	flag.BoolVar(&logFileEnable, "log.file.enable", false, "Enable file logging")
	flag.StringVar(&logFilePath, "log.file.path", "/var/log/openstack_instance_exporter.log", "Log file path")
	flag.StringVar(&logLevelFlag, "log.level", "info", "Log level (debug, info, warn, error; notice is accepted as an alias for warn)")
	flag.DurationVar(&threatLogMinInterval, "threat.log.min_interval", 5*time.Minute, "Throttle repeated threat/behavior notice logs")

	if err := flag.CommandLine.Parse(os.Args[1:]); err != nil {
		return 2
	}
	if err := validateStartupScalarFlags(behaviorSensitivity, wResource, wBehavior, wThreat); err != nil {
		InitLogging(logLevelFlag, logFilePath, logFileEnable)
		logMain.Error("invalid_startup_configuration", "err", err)
		return 2
	}
	if err := validateStartupRuntimeFlags(startupRuntimeFlags{
		listenAddress:               listenAddress,
		collectionInterval:          collectionInterval,
		workerCount:                 workerCount,
		behaviorEWMATauFast:         behaviorEWMATauFast,
		behaviorEWMATauSlow:         behaviorEWMATauSlow,
		conntrackRawRcvBufBytes:     conntrackRawRcvBufBytes,
		conntrackNetlinkRecvTimeout: conntrackNetlinkRecvTimeout,
		threatLogMinInterval:        threatLogMinInterval,
		threats:                     cfg,
	}); err != nil {
		InitLogging(logLevelFlag, logFilePath, logFileEnable)
		logMain.Error("invalid_startup_configuration", "err", err)
		return 2
	}
	if behaviorSensitivity < 0.1 {
		behaviorSensitivity = 0.1
	}
	if behaviorSensitivity > 10.0 {
		behaviorSensitivity = 10.0
	}

	cfg.ThreatLogMinInterval = threatLogMinInterval

	// ───────────────────────────────────────────────────────────────
	//  LOGGING INITIALIZATION (Slog)
	// ───────────────────────────────────────────────────────────────
	appliedLogLevel := InitLogging(logLevelFlag, logFilePath, logFileEnable)
	logMain.Info("exporter_startup", "log_level_requested", logLevelFlag, "log_level_applied", appliedLogLevel)

	effectiveWorkers := effectiveDomainWorkerCount(workerCount)
	logMain.Info("startup_config",
		"listen_address", listenAddress,
		"metrics_path", metricsPath,
		"libvirt_uri", libvirtURI,
		"collection_interval", collectionInterval.String(),
		"worker_count", workerCount,
		"worker_count_effective", effectiveWorkers,
		"contacts_direction", contactsDirection,
		"log_level_requested", logLevelFlag,
		"log_level_applied", appliedLogLevel,
		"log_file_enabled", logFileEnable,
		"log_file_path", logFilePath,
		"outbound_behavior_enabled", outboundBehavior,
		"inbound_behavior_enabled", inboundBehavior,
		"behavior_sensitivity", behaviorSensitivity,
		"behavior_ewma_fast_tau", behaviorEWMATauFast.String(),
		"behavior_ewma_slow_tau", behaviorEWMATauSlow.String(),
		"behavior_ports_config", behaviorPortsConfigPath,
		"behavior_rules_config", behaviorRulesConfigPath,
		"host_threats_enabled", hostThreats,
		"host_private_enabled", hostPrivate,
		"conntrack_ipv4_enabled", conntrackIPv4Enable,
		"conntrack_ipv6_enabled", conntrackIPv6Enable,
		"conntrack_raw_rcvbuf_bytes", conntrackRawRcvBufBytes,
		"conntrack_raw_rcv_timeout", conntrackNetlinkRecvTimeout,
		"threat_log_min_interval", threatLogMinInterval.String(),
		"tor_exit_enabled", cfg.TorExit.Enable,
		"tor_exit_refresh", cfg.TorExit.Refresh.String(),
		"tor_relay_enabled", cfg.TorRelay.Enable,
		"tor_relay_refresh", cfg.TorRelay.Refresh.String(),
		"spamhaus_enabled", cfg.Spamhaus.Enable,
		"spamhaus_refresh", cfg.Spamhaus.Refresh.String(),
		"emergingthreats_enabled", cfg.Emerging.Enable,
		"emergingthreats_refresh", cfg.Emerging.Refresh.String(),
		"customlist_enabled", cfg.Custom.Enable,
		"customlist_refresh", cfg.Custom.Refresh.String(),
	)

	inPorts, outPorts, portsStatus := BuildBehaviorPortMaps(behaviorPortsConfigPath)
	cfg.BehaviorPortsConfigPath = behaviorPortsConfigPath
	cfg.BehaviorPortsInboundMonitored = inPorts
	cfg.BehaviorPortsOutboundMonitored = outPorts
	if portsStatus.Status == "loaded" || portsStatus.Status == "not_configured" {
		logMain.Info("behavior_ports_config",
			"event", "behavior_ports_config",
			"path", portsStatus.Path,
			"status", portsStatus.Status,
			"using", portsStatus.Using,
			"inbound_ports", portsStatus.InboundPorts,
			"outbound_ports", portsStatus.OutboundPorts,
			"err", portsStatus.Err,
		)
	} else {
		logMain.Error("behavior_ports_config",
			"event", "behavior_ports_config",
			"path", portsStatus.Path,
			"status", portsStatus.Status,
			"using", portsStatus.Using,
			"inbound_ports", portsStatus.InboundPorts,
			"outbound_ports", portsStatus.OutboundPorts,
			"err", portsStatus.Err,
		)
		return 2
	}

	externalRules, rulesStatus := LoadBehaviorExternalRules(behaviorRulesConfigPath)
	cfg.BehaviorRulesConfigPath = behaviorRulesConfigPath
	cfg.BehaviorExternalRules = externalRules
	if rulesStatus.Status == "loaded" || rulesStatus.Status == "not_configured" {
		logMain.Info("behavior_rules_config",
			"event", "behavior_rules_config",
			"path", rulesStatus.Path,
			"status", rulesStatus.Status,
			"rules", rulesStatus.Rules,
			"port_sets", rulesStatus.PortSets,
			"err", rulesStatus.Err,
		)
	} else {
		logMain.Error("behavior_rules_config",
			"event", "behavior_rules_config",
			"path", rulesStatus.Path,
			"status", rulesStatus.Status,
			"rules", rulesStatus.Rules,
			"port_sets", rulesStatus.PortSets,
			"err", rulesStatus.Err,
		)
		return 2
	}

	defaultDir, err := parseContactDirection(contactsDirection)
	if err != nil {
		logMain.Error("invalid_contact_direction",
			"field", "contacts_direction",
			"value", contactsDirection,
			"err", err,
		)
		return 2
	}
	resolveDir := func(field, s string) (ContactDirection, error) {
		if s == "" {
			return defaultDir, nil
		}
		d, err := parseContactDirection(s)
		if err != nil {
			logMain.Error("invalid_contact_direction",
				"field", field,
				"value", s,
				"err", err,
			)
			return ContactAny, err
		}
		return d, nil
	}

	var directionErr error
	if cfg.TorExit.Direction, directionErr = resolveDir("dir_tor_exit", dirTorExit); directionErr != nil {
		return 2
	}
	if cfg.TorRelay.Direction, directionErr = resolveDir("dir_tor_relay", dirTorRelay); directionErr != nil {
		return 2
	}
	if cfg.Emerging.Direction, directionErr = resolveDir("dir_emerging", dirEmerging); directionErr != nil {
		return 2
	}
	if cfg.Custom.Direction, directionErr = resolveDir("dir_custom", dirCustom); directionErr != nil {
		return 2
	}
	if cfg.Spamhaus.Direction, directionErr = resolveDir("dir_spam", dirSpam); directionErr != nil {
		return 2
	}

	if hostThreats && hostInterfacesCSV == "" {
		hostInterfacesCSV = "bgp-nic"
	}

	cfg.LibvirtURI = libvirtURI
	cfg.CollectionInterval = collectionInterval
	cfg.Severity = SeverityConfig{
		ResourceWeight: wResource,
		BehaviorWeight: wBehavior,
		ThreatWeight:   wThreat,
	}
	cfg.HostThreats = HostThreatsConfig{
		Enable: hostThreats, IPsAllowPrivate: hostPrivate, Interfaces: parseInterfaceList(hostInterfacesCSV),
	}
	cfg.BehaviorThresholds = BehaviorThresholds{
		OutboundFlowsTotal: int(2000.0 / behaviorSensitivity),
		InboundFlowsTotal:  int(2000.0 / behaviorSensitivity),
	}
	cfg.BehaviorSensitivity = behaviorSensitivity
	cfg.BehaviorEWMATauFast = behaviorEWMATauFast
	cfg.BehaviorEWMATauSlow = behaviorEWMATauSlow
	cfg.WorkerCount = workerCount
	cfg.OutboundBehaviorEnable = outboundBehavior
	cfg.InboundBehaviorEnable = inboundBehavior

	cfg.ConntrackRawRcvBufBytes = conntrackRawRcvBufBytes
	cfg.ConntrackNetlinkRecvTimeout = conntrackNetlinkRecvTimeout
	cfg.ConntrackIPv4Enable = conntrackIPv4Enable
	cfg.ConntrackIPv6Enable = conntrackIPv6Enable

	// Detect nf_conntrack_acct once at startup for behavior engine.
	cfg.ConntrackAcctEnabled = false
	if data, err := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_acct"); err == nil {
		val := strings.TrimSpace(string(data))
		if val == "1" {
			cfg.ConntrackAcctEnabled = true
			logMain.Info("conntrack_acct_status", "enabled", true)
		} else {
			logMain.Info("conntrack_acct_status", "enabled", false, "value", val)
		}
	} else {
		logMain.Error("conntrack_acct_status_read_failed", "err", err)
	}

	if err := validateTelemetryPath(metricsPath); err != nil {
		logHttpApp.Error("invalid_telemetry_path", "path", metricsPath, "err", err)
		return 2
	}

	collector, err := NewMetricsCollector(cfg)
	if err != nil {
		logCollectorApp.Error("collector_create_failed", "err", err)
		return 1
	}
	if collector == nil {
		logCollectorApp.Error("collector_create_failed", "err", "collector is nil")
		return 1
	}
	var stopCollector sync.Once
	defer stopCollector.Do(func() { close(collector.shutdownChan) })

	shutdownCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	registry := prometheus.NewRegistry()
	registry.MustRegister(collector)
	registry.MustRegister(defaultRuntimeCollectors()...)

	mux := http.NewServeMux()
	mux.Handle(metricsPath, promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/debug/log-level", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if levelStr := r.URL.Query().Get("level"); levelStr != "" {
			appliedLevel := InitLogging(levelStr, logFilePath, logFileEnable)
			fmt.Fprintf(w, "log level set to %s\n", appliedLevel)
		} else {
			fmt.Fprintf(w, "current log level: %s\n", CurrentLogLevel())
		}
	})

	listener, err := listenForHTTP(listenAddress)
	if err != nil {
		logHttpApp.Error("http_listen_failed", "addr", listenAddress, "err", err)
		return 1
	}
	srv := &http.Server{Addr: listenAddress, Handler: mux}
	logHttpApp.Info("http_listen_start", "addr", listener.Addr().String())
	if err := serveHTTPUntilShutdown(shutdownCtx, srv, listener, 10*time.Second); err != nil {
		logHttpApp.Error("http_server_failed", "err", err)
		return 1
	}
	logMain.Info("exporter_shutdown", "signal", shutdownCtx.Err())
	return 0
}

func defaultRuntimeCollectors() []prometheus.Collector {
	return []prometheus.Collector{
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		collectors.NewGoCollector(),
		collectors.NewBuildInfoCollector(),
	}
}

func validateTelemetryPath(path string) (err error) {
	if path == "" || !strings.HasPrefix(path, "/") {
		return fmt.Errorf("telemetry path must begin with /")
	}
	if path == "/" || strings.HasSuffix(path, "/") {
		return fmt.Errorf("telemetry path must identify one exact endpoint")
	}
	if strings.ContainsAny(path, "?#{}") {
		return fmt.Errorf("telemetry path must not contain a query, fragment, or wildcard pattern")
	}
	decoded, decodeErr := url.PathUnescape(path)
	if decodeErr != nil || decoded != path {
		return fmt.Errorf("telemetry path must be a literal unescaped URL path")
	}
	if path == "/debug/log-level" {
		return fmt.Errorf("telemetry path conflicts with debug endpoint")
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("invalid telemetry path pattern: %v", recovered)
		}
	}()
	probeMux := http.NewServeMux()
	matched := false
	probeMux.Handle(path, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		matched = true
	}))
	probeMux.Handle("/debug/log-level", http.NotFoundHandler())
	request := httptest.NewRequest(http.MethodGet, path, nil)
	probeMux.ServeHTTP(httptest.NewRecorder(), request)
	if !matched {
		return fmt.Errorf("telemetry path is not directly reachable without URL cleaning or query/fragment removal")
	}
	return nil
}

func listenForHTTP(address string) (net.Listener, error) {
	return net.Listen("tcp", address)
}

func serveHTTPUntilShutdown(ctx context.Context, srv *http.Server, listener net.Listener, timeout time.Duration) error {
	if ctx == nil || srv == nil || listener == nil {
		return fmt.Errorf("HTTP lifecycle received nil input")
	}
	serveErr := make(chan error, 1)
	go func() {
		err := srv.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serveErr <- err
	}()

	select {
	case err := <-serveErr:
		if err == nil {
			return fmt.Errorf("HTTP server stopped unexpectedly")
		}
		return err
	case <-ctx.Done():
	}

	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		_ = srv.Close()
		<-serveErr
		return err
	}
	if err := <-serveErr; err != nil {
		return err
	}
	return nil
}

// -----------------------------------------------------------------------------
// Logging Logic (Powered by log/slog)
// -----------------------------------------------------------------------------
const (
	LogLevelError LogLevel = iota
	LogLevelNotice
	LogLevelInfo
	LogLevelDebug
)

var (
	logMu         sync.Mutex
	rootLoggerVal atomic.Value

	// Component Loggers (Backwards Compatible)
	logMain                  = NewComponentLogger("app", "app")
	logCollectorApp          = NewComponentLogger("app", "collector")
	logCollectorMetric       = NewComponentLogger("metric", "collector")
	logConntrackMetric       = NewComponentLogger("metric", "conntrack")
	logCustomlistThreat      = NewComponentLogger("threat", "customlist")
	logEmergingthreatsThreat = NewComponentLogger("threat", "emergingthreats")
	logHttpApp               = NewComponentLogger("app", "http")
	logSpamhausThreat        = NewComponentLogger("threat", "spamhaus")
	logTorexitThreat         = NewComponentLogger("threat", "torexit")
	logTorrelayThreat        = NewComponentLogger("threat", "torrelay")
)

func init() {
	rl := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	rootLoggerVal.Store(rl)
	slog.SetDefault(rl)
}
func (l ComponentLogger) argsToAttrs(_ string, kvpairs []interface{}) []interface{} {
	args := make([]interface{}, 0, len(kvpairs)+4)
	args = append(args, "category", l.category, "component", l.component)
	args = append(args, kvpairs...)
	return args
}
