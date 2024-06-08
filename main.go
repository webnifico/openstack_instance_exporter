package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	var listenAddress string
	var metricsPath string
	var libvirtURI string
	var readThresholds string
	var writeThresholds string
	var defaultReadThreshold int
	var defaultWriteThreshold int
	var contactsDirection string
	var torExitEnable bool
	var torExitURL string
	var torExitRefresh time.Duration
	var torExitDirection string
	var torRelayEnable bool
	var torRelayURL string
	var torRelayRefresh time.Duration
	var torRelayDirection string
	var spamEnable bool
	var spamURL string
	var spamRefresh time.Duration
	var spamV6URL string
	var spamDirection string
	var emThreatsEnable bool
	var emThreatsURL string
	var emThreatsRefresh time.Duration
	var emThreatsDirection string
	var customListEnable bool
	var customListPath string
	var customListRefresh time.Duration
	var customListDirection string
	var threatFileEnable bool
	var threatFilePath string
	var threatFileMinInterval time.Duration
	var logFileEnable bool
	var logFilePath string
	var logLevelFlag string
	var outboundBehaviorEnable bool
	var inboundBehaviorEnable bool
	var hostThreatsEnable bool
	var hostIPsAllowPrivate bool
	var hostInterfacesCSV string
	var minAttentionScore float64
	var behaviorSensitivity float64
	var collectionInterval time.Duration
	var workerCount int

	// Weights Flags
	var wResource float64
	var wThreat float64
	var wTor float64
	var wRelay float64
	var wSpam float64
	var wEmerging float64
	var wCustom float64
	var wBehavior float64

	// ───────────────────────────────────────────────────────────────
	//	WEB / PROCESS
	// ───────────────────────────────────────────────────────────────
	flag.StringVar(&listenAddress, "web.listen-address", "0.0.0.0:9120", "Address to listen on for web interface and telemetry.")
	flag.StringVar(&metricsPath, "web.telemetry-path", "/metrics", "Path under which to expose metrics.")

	// ───────────────────────────────────────────────────────────────
	//	LIBVIRT & COLLECTION ENGINE
	// ───────────────────────────────────────────────────────────────
	flag.StringVar(&libvirtURI, "libvirt.uri", "qemu:///system", "Libvirt URI from which to extract metrics.")
	flag.DurationVar(&collectionInterval, "collection.interval", 15*time.Second, "Background collection interval")
	flag.IntVar(&workerCount, "worker.count", 0, "Number of concurrent workers for metric collection (0 = NumCPU)")

	// ───────────────────────────────────────────────────────────────
	//	DISK THRESHOLDS
	// ───────────────────────────────────────────────────────────────
	flag.StringVar(&readThresholds, "read.thresholds", "", "Comma-separated list of read thresholds. eg 'default:500,local:200,ceph:1000'")
	flag.StringVar(&writeThresholds, "write.thresholds", "", "Comma-separated list of write thresholds. eg 'default:500,local:200,ceph:1000'")
	flag.IntVar(&defaultReadThreshold, "default.read.threshold", 100, "Default read threshold if none provided")
	flag.IntVar(&defaultWriteThreshold, "default.write.threshold", 100, "Default write threshold if none provided")

	// ───────────────────────────────────────────────────────────────
	//	CONTACT DIRECTION (GLOBAL DEFAULT)
	// ───────────────────────────────────────────────────────────────
	flag.StringVar(&contactsDirection, "contacts.direction", "out", "Default direction for contact matching: out, in, any")

	// ───────────────────────────────────────────────────────────────
	//	BEHAVIOR ANALYTICS
	// ───────────────────────────────────────────────────────────────
	flag.BoolVar(&outboundBehaviorEnable, "outbound.behavior.enable", false, "Enable outbound behavior metrics")
	flag.BoolVar(&inboundBehaviorEnable, "inbound.behavior.enable", false, "Enable inbound behavior metrics")
	flag.Float64Var(&behaviorSensitivity, "behavior.sensitivity", 1.0, "Behavior threshold scale factor; <1 more sensitive, >1 less sensitive")

	// ───────────────────────────────────────────────────────────────
	//	SCORING / ATTENTION
	// ───────────────────────────────────────────────────────────────
	flag.Float64Var(&minAttentionScore, "attention.min_score", 0.0, "Minimum attention score required before exporting scores and logs")

	flag.Float64Var(&wResource, "score.weight.resource", 0.5, "Weight for resource score (0.0-1.0)")
	flag.Float64Var(&wThreat, "score.weight.threat", 0.5, "Weight for threat score (0.0-1.0)")
	flag.Float64Var(&wBehavior, "score.weight.behavior", 100.0, "Signal weight for Behavioral anomalies")

	flag.Float64Var(&wTor, "score.weight.tor", 25.0, "Signal weight for Tor Exit hits")
	flag.Float64Var(&wRelay, "score.weight.relay", 5.0, "Signal weight for Tor Relay hits")
	flag.Float64Var(&wSpam, "score.weight.spam", 40.0, "Signal weight for Spamhaus hits")
	flag.Float64Var(&wEmerging, "score.weight.emerging", 40.0, "Signal weight for EmergingThreats hits")
	flag.Float64Var(&wCustom, "score.weight.custom", 5.0, "Signal weight for Custom List hits")

	// ───────────────────────────────────────────────────────────────
	//  THREAT LIST CONFIGS
	// ───────────────────────────────────────────────────────────────

	// TOR EXIT
	flag.BoolVar(&torExitEnable, "tor.exit.enable", false, "Enable Tor exit-node detection")
	flag.StringVar(&torExitURL, "tor.exit.url", "https://onionoo.torproject.org/details?search=flag:exit&fields=or_addresses", "Tor exit list URL")
	flag.DurationVar(&torExitRefresh, "tor.exit.refresh", time.Hour, "Refresh interval for Tor exit list")
	flag.StringVar(&torExitDirection, "tor.exit.direction", "", "Direction override for Tor exit: out, in, any")

	// TOR RELAY
	flag.BoolVar(&torRelayEnable, "tor.relay.enable", false, "Enable Tor relay detection")
	flag.StringVar(&torRelayURL, "tor.relay.url", "https://onionoo.torproject.org/details?search=flag:running&fields=or_addresses", "Tor relay list URL")
	flag.DurationVar(&torRelayRefresh, "tor.relay.refresh", time.Hour, "Refresh interval for Tor relay list")
	flag.StringVar(&torRelayDirection, "tor.relay.direction", "", "Direction override for Tor relay: out, in, any")

	// SPAMHAUS
	flag.BoolVar(&spamEnable, "spamhaus.enable", false, "Enable Spamhaus DROP CIDR matching")
	flag.StringVar(&spamURL, "spamhaus.url", "https://www.spamhaus.org/drop/drop.txt", "Spamhaus IPv4 list")
	flag.StringVar(&spamV6URL, "spamhaus.ipv6.url", "https://www.spamhaus.org/drop/dropv6.txt", "Spamhaus IPv6 list")
	flag.DurationVar(&spamRefresh, "spamhaus.refresh", 6*time.Hour, "Spamhaus refresh interval")
	flag.StringVar(&spamDirection, "spamhaus.direction", "", "Direction override: out, in, any")

	// EMERGING THREATS
	flag.BoolVar(&emThreatsEnable, "emergingthreats.enable", false, "Enable EmergingThreats compromised IP matching")
	flag.StringVar(&emThreatsURL, "emergingthreats.url", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", "EmergingThreats URL")
	flag.DurationVar(&emThreatsRefresh, "emergingthreats.refresh", 6*time.Hour, "Refresh interval")
	flag.StringVar(&emThreatsDirection, "emergingthreats.direction", "", "Direction override")

	// CUSTOM LIST
	flag.BoolVar(&customListEnable, "customlist.enable", false, "Enable custom IP list")
	flag.StringVar(&customListPath, "customlist.path", "", "Path to custom IP list")
	flag.DurationVar(&customListRefresh, "customlist.refresh", 10*time.Minute, "Custom list refresh interval")
	flag.StringVar(&customListDirection, "customlist.direction", "", "Direction override")

	// HOST THREAT MATCHING
	flag.BoolVar(&hostThreatsEnable, "host.threats.enable", false, "Enable threat checks for host NICs")
	flag.BoolVar(&hostIPsAllowPrivate, "host.ips.allow-private", false, "Include private & loopback host IPs")
	flag.StringVar(&hostInterfacesCSV, "host.interfaces", "", "Comma-separated NIC list for host threats")

	// ───────────────────────────────────────────────────────────────
	//	LOGGING
	// ───────────────────────────────────────────────────────────────
	flag.BoolVar(&logFileEnable, "log.file.enable", false, "Enable logging to file")
	flag.StringVar(&logFilePath, "log.file.path", "/var/log/openstack_instance_exporter.log", "Log file path")
	flag.StringVar(&logLevelFlag, "log.level", "error", "Log level: error, notice, info, debug")

	flag.BoolVar(&threatFileEnable, "threatfile.enable", false, "Enable threat hit logging")
	flag.StringVar(&threatFilePath, "threatfile.path", "/var/log/openstack_instance_exporter.threat.log", "Threat log file")
	flag.DurationVar(&threatFileMinInterval, "threatfile.min_interval", 5*time.Minute, "Min interval between repeated threat logs")

	flag.Parse()

	log.SetOutput(os.Stdout)
	log.SetFlags(0)

	setLogLevel(parseLogLevel(logLevelFlag))
	logAppApp.Info("exporter_startup", "log_level", logLevelFlag)

	if logFileEnable && logFilePath != "" {
		f, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			logLoggingApp.Error("logfile_open_failed", "path", logFilePath, "err", err)
		} else {
			log.SetOutput(io.MultiWriter(os.Stdout, f))
			logLoggingApp.Info("logfile_enabled", "path", logFilePath)
		}
	}

	readThresholdMap := parseThresholds(readThresholds, defaultReadThreshold)
	writeThresholdMap := parseThresholds(writeThresholds, defaultWriteThreshold)
	defaultDir := parseContactDirection(contactsDirection)

	torExitDir := defaultDir
	if torExitDirection != "" {
		torExitDir = parseContactDirection(torExitDirection)
	}
	torRelayDir := defaultDir
	if torRelayDirection != "" {
		torRelayDir = parseContactDirection(torRelayDirection)
	}
	spamDir := defaultDir
	if spamDirection != "" {
		spamDir = parseContactDirection(spamDirection)
	}
	emDir := defaultDir
	if emThreatsDirection != "" {
		emDir = parseContactDirection(emThreatsDirection)
	}
	customDir := defaultDir
	if customListDirection != "" {
		customDir = parseContactDirection(customListDirection)
	}

	hostInterfaces := parseInterfaceList(hostInterfacesCSV)
	if hostThreatsEnable && len(hostInterfaces) == 0 {
		hostInterfaces["bgp-nic"] = struct{}{}
	}

	if behaviorSensitivity < 0.1 {
		behaviorSensitivity = 0.1
	}
	if behaviorSensitivity > 10.0 {
		behaviorSensitivity = 10.0
	}

	// ───────────────────────────────────────────────────────────────
	//	CLEANED BEHAVIOR CONFIG
	// ───────────────────────────────────────────────────────────────

	// Default base reference is 2000 flows (100% Load).
	// Tuning is done via behaviorSensitivity flag.
	baseBehavior := BehaviorThresholds{
		OutboundFlowsTotal: 2000,
		InboundFlowsTotal:  2000,
	}

	scale := behaviorSensitivity

	scaledBehavior := BehaviorThresholds{
		OutboundFlowsTotal: int(float64(baseBehavior.OutboundFlowsTotal) * scale),
		InboundFlowsTotal:  int(float64(baseBehavior.InboundFlowsTotal) * scale),
	}

	collectorCfg := CollectorConfig{
		LibvirtURI: libvirtURI,
		Threshold: ThresholdConfig{
			Read:         readThresholdMap,
			Write:        writeThresholdMap,
			DefaultRead:  defaultReadThreshold,
			DefaultWrite: defaultWriteThreshold,
		},
		Scoring: ScoringConfig{
			ResourceWeight: wResource,
			ThreatWeight:   wThreat,
			TorSignal:      wTor,
			RelaySignal:    wRelay,
			SpamSignal:     wSpam,
			EmergingSignal: wEmerging,
			CustomSignal:   wCustom,
			BehaviorSignal: wBehavior,
		},
		WorkerCount:            workerCount,
		CollectionInterval:     collectionInterval,
		BehaviorThresholds:     scaledBehavior,
		OutboundBehaviorEnable: outboundBehaviorEnable,
		InboundBehaviorEnable:  inboundBehaviorEnable,
		ThreatFileEnable:       threatFileEnable,
		ThreatFilePath:         threatFilePath,
		ThreatFileMinInterval:  threatFileMinInterval,
		MinAttentionScore:      minAttentionScore,
		HostThreats: HostThreatsConfig{
			Enable:          hostThreatsEnable,
			IPsAllowPrivate: hostIPsAllowPrivate,
			Interfaces:      hostInterfaces,
		},
		TorExit: ThreatListConfig{
			Enable:    torExitEnable,
			URL:       torExitURL,
			Refresh:   torExitRefresh,
			Direction: torExitDir,
		},
		TorRelay: ThreatListConfig{
			Enable:    torRelayEnable,
			URL:       torRelayURL,
			Refresh:   torRelayRefresh,
			Direction: torRelayDir,
		},
		Spamhaus: SpamhausConfig{
			Enable:    spamEnable,
			URLv4:     spamURL,
			URLv6:     spamV6URL,
			Refresh:   spamRefresh,
			Direction: spamDir,
		},
		Emerging: ThreatListConfig{
			Enable:    emThreatsEnable,
			URL:       emThreatsURL,
			Refresh:   emThreatsRefresh,
			Direction: emDir,
		},
		Custom: CustomListConfig{
			Enable:    customListEnable,
			Path:      customListPath,
			Refresh:   customListRefresh,
			Direction: customDir,
		},
	}

	collector, err := NewMetricsCollector(collectorCfg)
	if err != nil {
		logCollectorApp.Error("collector_create_failed", "err", err)
		return
	}

	if collector == nil {
		logCollectorApp.Error("collector_create_failed_nil_return", "err", fmt.Errorf("NewMetricsCollector returned a nil collector object"))
		return
	}

	if collector.tm != nil && collector.tm.threatFile != nil {
		defer collector.tm.threatFile.Close()
	}

	shutdownCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	registry := prometheus.NewRegistry()
	registry.MustRegister(
		collector,
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		collectors.NewGoCollector(),
		collectors.NewBuildInfoCollector(),
	)

	handler := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	http.Handle(metricsPath, handler)

	http.HandleFunc("/debug/log-level", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		levelStr := r.URL.Query().Get("level")
		if levelStr == "" {
			fmt.Fprintf(w, "current log level: %v\n", getLogLevel())
			return
		}
		lvl := parseLogLevel(levelStr)
		setLogLevel(lvl)
		fmt.Fprintf(w, "log level set to %s\n", levelStr)
	})

	srv := &http.Server{
		Addr:    listenAddress,
		Handler: nil,
	}

	go func() {
		logHttpApp.Info("http_listen_start", "listen_address", listenAddress)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logHttpApp.Error("http_listen_failed", "listen_address", listenAddress, "err", err)
		}
	}()

	<-shutdownCtx.Done()

	logAppApp.Info("exporter_shutdown", "signal", shutdownCtx.Err())
	collector.shutdownEvents.Inc()
	close(collector.shutdownChan)
	srv.Shutdown(context.Background())
}
