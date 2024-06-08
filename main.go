package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
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

		conntrackRawRcvBufBytes int
		conntrackIPv4Enable     bool
		conntrackIPv6Enable     bool

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
	flag.StringVar(&logLevelFlag, "log.level", "error", "Log level")
	flag.DurationVar(&threatLogMinInterval, "threat.log.min_interval", 5*time.Minute, "Throttle repeated threat/behavior notice logs")

	flag.Parse()

	cfg.ThreatLogMinInterval = threatLogMinInterval

	// ───────────────────────────────────────────────────────────────
	//  LOGGING INITIALIZATION (Slog)
	// ───────────────────────────────────────────────────────────────
	InitLogging(logLevelFlag, logFilePath, logFileEnable)
	logMain.Info("exporter_startup", "log_level", logLevelFlag)

	effectiveWorkers := workerCount
	if effectiveWorkers <= 0 {
		effectiveWorkers = runtime.NumCPU()
	}
	logMain.Info("startup_config",
		"listen_address", listenAddress,
		"metrics_path", metricsPath,
		"libvirt_uri", libvirtURI,
		"collection_interval", collectionInterval.String(),
		"worker_count", workerCount,
		"worker_count_effective", effectiveWorkers,
		"contacts_direction", contactsDirection,
		"log_level", logLevelFlag,
		"log_file_enabled", logFileEnable,
		"log_file_path", logFilePath,
		"outbound_behavior_enabled", outboundBehavior,
		"inbound_behavior_enabled", inboundBehavior,
		"behavior_sensitivity", behaviorSensitivity,
		"behavior_ports_config", behaviorPortsConfigPath,
		"behavior_rules_config", behaviorRulesConfigPath,
		"host_threats_enabled", hostThreats,
		"host_private_enabled", hostPrivate,
		"conntrack_ipv4_enabled", conntrackIPv4Enable,
		"conntrack_ipv6_enabled", conntrackIPv6Enable,
		"conntrack_raw_rcvbuf_bytes", conntrackRawRcvBufBytes,
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
	}

	defaultDir := parseContactDirection(contactsDirection)
	resolveDir := func(s string) ContactDirection {
		if s != "" {
			return parseContactDirection(s)
		}
		return defaultDir
	}

	cfg.TorExit.Direction = resolveDir(dirTorExit)
	cfg.TorRelay.Direction = resolveDir(dirTorRelay)
	cfg.Emerging.Direction = resolveDir(dirEmerging)
	cfg.Custom.Direction = resolveDir(dirCustom)
	cfg.Spamhaus.Direction = resolveDir(dirSpam)

	if hostThreats && hostInterfacesCSV == "" {
		hostInterfacesCSV = "bgp-nic"
	}

	if behaviorSensitivity < 0.1 {
		behaviorSensitivity = 0.1
	}
	if behaviorSensitivity > 10.0 {
		behaviorSensitivity = 10.0
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

	collector, err := NewMetricsCollector(cfg)
	if err != nil {
		logCollectorApp.Error("collector_create_failed", "err", err)
		return
	}
	if collector == nil {
		return
	}

	shutdownCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	registry := prometheus.NewRegistry()
	registry.MustRegister(collector, collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}), collectors.NewGoCollector(), collectors.NewBuildInfoCollector())

	http.Handle(metricsPath, promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	http.HandleFunc("/debug/log-level", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if levelStr := r.URL.Query().Get("level"); levelStr != "" {
			InitLogging(levelStr, logFilePath, logFileEnable)
			fmt.Fprintf(w, "log level set to %s\n", levelStr)
		} else {
			fmt.Fprintf(w, "current log level: %v\n", "unknown")
		}
	})

	srv := &http.Server{Addr: listenAddress}
	go func() {
		logHttpApp.Info("http_listen_start", "addr", listenAddress)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logHttpApp.Error("http_listen_failed", "err", err)
		}
	}()

	<-shutdownCtx.Done()
	logMain.Info("exporter_shutdown", "signal", shutdownCtx.Err())
	close(collector.shutdownChan)
	srv.Shutdown(context.Background())
}

// -----------------------------------------------------------------------------
// Logging Logic (Powered by log/slog)
// -----------------------------------------------------------------------------

type LogLevel int

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

func getRootLogger() *slog.Logger {
	v := rootLoggerVal.Load()
	if v == nil {
		return slog.Default()
	}
	return v.(*slog.Logger)
}

// InitLogging sets up slog with JSON output.
func InitLogging(logLevelStr, logFilePath string, enableFile bool) {
	logMu.Lock()
	defer logMu.Unlock()

	var level slog.Level
	switch strings.ToLower(strings.TrimSpace(logLevelStr)) {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn", "notice":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: level,
	}

	var writer io.Writer = os.Stdout

	if enableFile && logFilePath != "" {
		// O_APPEND support for copytruncate rotation
		f, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			slog.Error("failed_to_open_logfile", "err", err)
		} else {
			writer = io.MultiWriter(os.Stdout, f)
		}
	}

	handler := slog.NewJSONHandler(writer, opts)
	rl := slog.New(handler)
	rootLoggerVal.Store(rl)
	slog.SetDefault(rl)
}

// -----------------------------------------------------------------------------
// Component Logger Adapter
// -----------------------------------------------------------------------------

type ComponentLogger struct {
	category  string
	component string
}

func NewComponentLogger(category, component string) ComponentLogger {
	return ComponentLogger{category: category, component: component}
}

func (l ComponentLogger) argsToAttrs(_ string, kvpairs []interface{}) []interface{} {
	args := make([]interface{}, 0, len(kvpairs)+4)
	args = append(args, "category", l.category, "component", l.component)
	args = append(args, kvpairs...)
	return args
}

func (l ComponentLogger) Debug(msg string, kvpairs ...interface{}) {
	getRootLogger().Debug(msg, l.argsToAttrs(msg, kvpairs)...)
}

func (l ComponentLogger) Info(msg string, kvpairs ...interface{}) {
	getRootLogger().Info(msg, l.argsToAttrs(msg, kvpairs)...)
}

func (l ComponentLogger) Notice(msg string, kvpairs ...interface{}) {
	getRootLogger().Info(msg, l.argsToAttrs(msg, kvpairs)...)
}

func (l ComponentLogger) Error(msg string, kvpairs ...interface{}) {
	getRootLogger().Error(msg, l.argsToAttrs(msg, kvpairs)...)
}

// -----------------------------------------------------------------------------
// Compatibility Helpers
// -----------------------------------------------------------------------------

// logKV is used by metrics_engine.go
func logKV(level LogLevel, category, msg string, kvpairs ...interface{}) {
	args := make([]interface{}, 0, len(kvpairs)+2)
	args = append(args, "category", category)
	args = append(args, kvpairs...)

	ctx := context.Background()
	switch level {
	case LogLevelDebug:
		getRootLogger().DebugContext(ctx, msg, args...)
	case LogLevelInfo, LogLevelNotice:
		getRootLogger().InfoContext(ctx, msg, args...)
	case LogLevelError:
		getRootLogger().ErrorContext(ctx, msg, args...)
	default:
		getRootLogger().InfoContext(ctx, msg, args...)
	}
}
