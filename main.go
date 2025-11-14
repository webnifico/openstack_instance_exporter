package main

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"libvirt.org/go/libvirt"
)

//
// ============================================================================
// HIGH-LEVEL OVERVIEW + WORKFLOW DIAGRAM
// ============================================================================
//
// This exporter does three main things:
//
//   1. Connects to libvirt on the hypervisor.
//   2. Periodically collects metrics for all active instances (domains).
//   3. Exposes those metrics to Prometheus via an HTTP endpoint (/metrics).
//
// The key design choice: **collection is done in a background loop**, and
// **Prometheus scrapes only read from an in-memory cache**. Scrapes do NOT
// talk to libvirt directly. That keeps scrape latency predictable and avoids
// hitting libvirt under load every time Prometheus pulls.
//
// --------------------------------------------------------------------------
// TEXT WORKFLOW DIAGRAM
// --------------------------------------------------------------------------
//
//                ┌─────────────────────────────────────────┐
//                │   Background Collection Goroutine       │
//                │   (runs every collection.interval)      │
//                └─────────────────────────────────────────┘
//                                   │
//                                   │ 1) List all active domains from libvirt
//                                   ▼
//                       ┌──────────────────────────┐
/* ...snip box art alignment, functional content below is intact... */
//                       │   Active libvirt VMs     │
//                       └──────────────────────────┘
//                                   │
//                                   │ 2) Run `conntrack -L` ONCE per cycle
//                                   ▼
//                     ┌────────────────────────────────┐
//                     │ Parsed conntrack flow entries │
//                     └────────────────────────────────┘
//                                   │
//                                   │ 3) For each domain:
//                                   │    - Parse XML / Nova metadata
//                                   │    - Collect disk, CPU, network stats
//                                   │    - Match conntrack flows to fixed IPs
//                                   ▼
//                      ┌───────────────────────────────────┐
//                      │ []prometheus.Metric per instance  │
//                      └───────────────────────────────────┘
//                                   │
//                                   │ 4) Store metrics slice in dynamic cache
//                                   ▼
//                 ┌──────────────────────────────────────────────┐
//                 │ dynamicCache[instanceUUID] = []Metric        │
//                 └──────────────────────────────────────────────┘
//
//                                  (in parallel)
//
//   Prometheus scrape path:
//
//   Prometheus ──> /metrics ──> Collect() ──> collectCachedMetrics()
//                                         └─> read from static/dynamic cache
//
//   No libvirt calls happen in Collect(). It simply streams the last known
//   metrics that the background goroutine wrote.
//
// --------------------------------------------------------------------------
// ZERO-SUPPRESSION LOGIC (to protect Prometheus TSDB)
// --------------------------------------------------------------------------
//
// The exporter intentionally avoids emitting metrics that are "just zeros" or
// that never change. The goal is to reduce TSDB size while still giving useful
// visibility and preserving alerts.
//
// Rules:
//
//   DISK:
//     - Disk *thresholds* are always exported (these are configuration-like).
//     - Disk I/O counters (bytes/requests) are exported *only if there is some
//       activity*:
//           RdBytes > 0 OR WrBytes > 0 OR RdReq > 0 OR WrReq > 0
//
//   NETWORK:
//     - For each interface, if **all** of these are 0:
//           RxBytes, TxBytes,
//           RxPackets, TxPackets,
//           RxErrors, TxErrors,
//           RxDropped, TxDropped
//       then no metrics for that interface are exported for this cycle.
//
//   CONNTRACK:
//     - For each fixed IP, we only export `oie_conntrack_ip_total` if the
//       matched flow count for that IP is ≥ 1.
//       IPs with zero flows simply don't appear in the metrics.
//
//   CPU:
//     - We compute CPU usage from deltas over time and then apply:
//         * "0-collapse": if last export was 0 AND current value is 0,
//                        we do not export a new sample.
//         * unchanged suppression: if last exported CPU value is the same
//                        as the current value, we do not export a new sample.
//       This means only changes (including first non-zero or first zero after
//       non-zero) result in new samples.
//
// These rules significantly cut down the number of samples stored by Prometheus
// without losing meaningful observability.
//
// ============================================================================
// LOGGING HELPERS
// ============================================================================

type LogLevel int

const (
	LogLevelError LogLevel = iota
	LogLevelInfo
	LogLevelDebug
)

var (
	currentLogLevel = LogLevelError
	logLevelMu      sync.RWMutex
)

func parseLogLevel(s string) LogLevel {
	switch strings.ToLower(s) {
	case "debug":
		return LogLevelDebug
	case "info":
		return LogLevelInfo
	default:
		return LogLevelError
	}
}

func setLogLevel(l LogLevel) {
	logLevelMu.Lock()
	defer logLevelMu.Unlock()
	currentLogLevel = l
}

func getLogLevel() LogLevel {
	logLevelMu.RLock()
	defer logLevelMu.RUnlock()
	return currentLogLevel
}

func logDebug(format string, args ...interface{}) {
	if getLogLevel() >= LogLevelDebug {
		log.Printf("[DEBUG] "+format, args...)
	}
}

func logInfo(format string, args ...interface{}) {
	if getLogLevel() >= LogLevelInfo {
		log.Printf("[INFO] "+format, args...)
	}
}

func logError(format string, args ...interface{}) {
	log.Printf("[ERROR] "+format, args...)
}

// logThreat logs threat IP hits regardless of log level.
// This is intentionally not gated by currentLogLevel.
func logThreat(format string, args ...interface{}) {
	log.Printf("[THREAT] "+format, args...)
}

// ============================================================================
// GENERIC HELPERS
// ============================================================================

// UnmarshalProto validates JSON and unmarshals into a protobuf message.
// This is kept for potential future use; the exporter currently does not
// rely on protobuf configs, but you can use this helper where needed.
func UnmarshalProto(jsonData []byte, pb proto.Message) error {
	if !json.Valid(jsonData) {
		return fmt.Errorf("invalid JSON")
	}
	return protojson.Unmarshal(jsonData, pb)
}

// ============================================================================
// LIBVIRT DOMAIN XML STRUCTURES
// ============================================================================
//
// We only model the parts of the libvirt XML that we need:
//
//   - Nova metadata for name, flavor (and vCPUs), owner (user/project), ports.
//   - Devices for disks and interfaces.
//
// We don't attempt to describe the full libvirt schema.

type DomainXML struct {
	UUID     string `xml:"uuid"`
	Metadata struct {
		NovaInstance struct {
			NovaName   string `xml:"name"`
			NovaFlavor struct {
				FlavorName string `xml:"name,attr"`
				VCPUs      int    `xml:"vcpus"`
			} `xml:"flavor"`
			NovaOwner struct {
				NovaUser struct {
					UserName string `xml:",chardata"`
					UserUUID string `xml:"uuid,attr"`
				} `xml:"user"`
				NovaProject struct {
					ProjectName string `xml:",chardata"`
					ProjectUUID string `xml:"uuid,attr"`
				} `xml:"project"`
			} `xml:"owner"`
			NovaRoot struct {
				RootType string `xml:"type,attr"`
				RootUUID string `xml:"uuid,attr"`
			} `xml:"root"`
			NovaPorts struct {
				Ports []struct {
					PortUUID string `xml:"uuid,attr"`
					IPs      []struct {
						Address   string `xml:"address,attr"`
						IPVersion string `xml:"ipVersion,attr"`
					} `xml:"ip"`
				} `xml:",any"`
			} `xml:"ports"`
		} `xml:"instance"`
	} `xml:"metadata"`
	Devices struct {
		Disks      []Disk      `xml:"disk"`
		Interfaces []Interface `xml:"interface"`
	} `xml:"devices"`
}

// Disk describes a libvirt <disk> element under <devices>.
type Disk struct {
	Device string `xml:"device,attr"` // e.g. "disk", "cdrom"
	Type   string `xml:"type,attr"`   // e.g. "file", "network"
	Source struct {
		Protocol string `xml:"protocol,attr"` // e.g. "rbd"
		File     string `xml:"file,attr"`     // for file-backed disks
		Name     string `xml:"name,attr"`     // e.g. "pool/volume"
	} `xml:"source"`
	Target struct {
		Dev string `xml:"dev,attr"` // e.g. "vda"
	} `xml:"target"`
}

// Interface describes a libvirt <interface> element.
type Interface struct {
	Target struct {
		Dev string `xml:"dev,attr"` // tap device name on the host
	} `xml:"target"`
	IPs []IP `xml:"ip"`
}

// IP describes an address attached to an interface or Nova port.
type IP struct {
	Address string `xml:"address,attr"`
	Family  string `xml:"family,attr"`
	Prefix  string `xml:"prefix,attr"`
}

// ConntrackEntry represents a single conntrack flow, with only src/dst tracked.
// We don't care about ports or protocol here, just endpoint IPs.
type ConntrackEntry struct {
	Src string
	Dst string
}

// ----------------------------------------------------------------------
// TOR Onionoo JSON structures
//
// The Onionoo "details" API returns data like:
//
// {
//   "relays": [
//     { "or_addresses": ["204.137.14.106:443", "[2a0e:bfc0::8a62]:443"] },
//     { "or_addresses": ["185.220.101.33:10133"] },
//     ...
//   ]
// }
//
// We only care about IPv4/IPv6 addresses, and must strip the port.
// ----------------------------------------------------------------------

// Onionoo unified Tor exit-node JSON
type OnionooSummary struct {
	Relays []struct {
		OrAddresses []string `json:"or_addresses"`
	} `json:"relays"`
}

// ============================================================================
// IN-MEMORY CACHE SUPPORT
// ============================================================================
//
// We use a small generic cache abstraction to store arbitrary values (mostly
// []prometheus.Metric slices) with an expiration. The cache is used for:
//   - dynamic metrics: per-instance metrics that are updated periodically
//   - static metrics: future use for rarely-changing data like labels/config

// CacheEntry wraps stored data with a timestamp for expiry checks.
type CacheEntry struct {
	data        interface{}
	lastUpdated time.Time
}

// Cache is a simple key → CacheEntry map with a lock and TTL logic.
// It is not fancy, just enough for this exporter.
type Cache struct {
	mu         sync.RWMutex
	data       map[string]CacheEntry
	expiration time.Duration
}

// NewCache creates a cache with a given expiration duration.
func NewCache(expiration time.Duration) *Cache {
	return &Cache{
		data:       make(map[string]CacheEntry),
		expiration: expiration,
	}
}

// Get returns the cached value for a key, if present and not expired.
// If the entry is expired or missing, it returns (nil, false).
func (c *Cache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.data[key]
	if !ok || time.Since(entry.lastUpdated) > c.expiration {
		return nil, false
	}

	return entry.data, true
}

// Set updates/creates an entry with the given data and the current timestamp.
func (c *Cache) Set(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.data[key] = CacheEntry{
		data:        value,
		lastUpdated: time.Now(),
	}
}

// Cleanup removes entries that have expired AND belong to instances that are
// no longer active. This keeps the cache from growing forever with dead VMs.
func (c *Cache) Cleanup(mc *MetricsCollector) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for key, entry := range c.data {
		if now.Sub(entry.lastUpdated) > c.expiration && !mc.isInstanceActive(key) {
			delete(c.data, key)
		}
	}
}

// ============================================================================
// CONNTRACK PARSING
// ============================================================================
//
// We run `conntrack -L -o extended` once per collection cycle and parse the
// output line-by-line. From each line we only extract src= and dst= fields.
// This means we don't track ports or protocol, just IP endpoints.
//
// This is cheap enough for typical conntrack sizes but avoids doing this per
// instance, which would be very expensive.

// readConntrack runs the conntrack command and parses src/dst fields
// for each entry. It returns a slice of ConntrackEntry.
func readConntrack() ([]ConntrackEntry, error) {
	cmd := exec.Command("conntrack", "-L", "-o", "extended")

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	// Wait() will be called after scanning is complete.
	defer cmd.Wait()

	scanner := bufio.NewScanner(stdout)
	entries := make([]ConntrackEntry, 0, 4096)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var e ConntrackEntry
		fields := strings.Fields(line)
		for _, f := range fields {
			if strings.HasPrefix(f, "src=") && e.Src == "" {
				e.Src = strings.TrimPrefix(f, "src=")
			} else if strings.HasPrefix(f, "dst=") && e.Dst == "" {
				e.Dst = strings.TrimPrefix(f, "dst=")
			}
		}

		if e.Src != "" || e.Dst != "" {
			entries = append(entries, e)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return entries, nil
}

// Unified Tor refresher (IPv4 + IPv6)
func (mc *MetricsCollector) startTorRefresher() {
	for {
		mc.refreshTorListUnified()
		time.Sleep(mc.torRefresh)
	}
}

func (mc *MetricsCollector) refreshTorListUnified() {
	resp, err := http.Get(mc.torURL)
	if err != nil {
		logError("TOR: failed to download list: %v", err)
		return
	}
	defer resp.Body.Close()

	var data OnionooSummary
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&data); err != nil {
		logError("TOR: JSON decode error: %v", err)
		return
	}

	fresh := make(map[string]struct{})

	for _, r := range data.Relays {
		for _, raw := range r.OrAddresses {

			// strip port
			host := raw
			if strings.HasPrefix(host, "[") {
				// IPv6 like: [2a03:xxxx]:443
				end := strings.Index(host, "]")
				if end > 0 {
					host = host[1:end]
				}
			} else {
				// IPv4 like: 185.220.101.33:9001
				if h, _, err := net.SplitHostPort(host); err == nil {
					host = h
				}
			}

			ip := net.ParseIP(host)
			if ip == nil {
				continue
			}

			// canonical string — v4/v6 handled equally
			fresh[ip.String()] = struct{}{}
		}
	}

	mc.torMu.Lock()
	mc.torSet = fresh
	mc.torMu.Unlock()

	logInfo("TOR: loaded %d exit-node IPs", len(fresh))
}

// startSpamhausRefresher periodically downloads the Spamhaus DROP lists
// (IPv4 + IPv6) and builds unified lookup buckets.
func (mc *MetricsCollector) startSpamhausRefresher() {
	for {
		mc.refreshSpamhausList()
		time.Sleep(mc.spamRefresh)
	}
}

// refreshSpamhausList updates the in-memory Spamhaus CIDR lists (IPv4 + IPv6)
// and builds /16 buckets for IPv4 and /48-style buckets for IPv6.
func (mc *MetricsCollector) refreshSpamhausList() {
	allNets := make([]*net.IPNet, 0, 8192)

	// IPv4 DROP
	resp4, err := http.Get(mc.spamURL)
	if err != nil {
		logError("SPAMHAUS: Failed to download IPv4 list: %v", err)
	} else {
		defer resp4.Body.Close()
		nets4, err := parseSpamhausCIDRs(resp4.Body)
		if err != nil {
			logError("SPAMHAUS: IPv4 parse error: %v", err)
		} else {
			allNets = append(allNets, nets4...)
		}
	}

	// IPv6 DROP
	resp6, err := http.Get(mc.spamV6URL)
	if err != nil {
		logError("SPAMHAUS: Failed to download IPv6 list: %v", err)
	} else {
		defer resp6.Body.Close()
		nets6, err := parseSpamhausCIDRs(resp6.Body)
		if err != nil {
			logError("SPAMHAUS: IPv6 parse error: %v", err)
		} else {
			allNets = append(allNets, nets6...)
		}
	}

	if len(allNets) == 0 {
		return
	}

	bucketsV4 := make(map[string][]*net.IPNet)
	bucketsV6 := make(map[string][]*net.IPNet)

	var v4Count, v6Count int

	for _, n := range allNets {
		if n == nil || n.IP == nil {
			continue
		}

		if ip4 := n.IP.To4(); ip4 != nil {
			key := fmt.Sprintf("%d.%d", ip4[0], ip4[1])
			bucketsV4[key] = append(bucketsV4[key], n)
			v4Count++
			continue
		}

		ip16 := n.IP.To16()
		if ip16 == nil {
			continue
		}

		key := fmt.Sprintf("%x:%x:%x",
			uint16(ip16[0])<<8|uint16(ip16[1]),
			uint16(ip16[2])<<8|uint16(ip16[3]),
			uint16(ip16[4])<<8|uint16(ip16[5]),
		)

		bucketsV6[key] = append(bucketsV6[key], n)
		v6Count++
	}

	mc.spamMu.Lock()
	mc.spamNets = allNets
	mc.spamBucketsV4 = bucketsV4
	mc.spamBucketsV6 = bucketsV6
	mc.spamMu.Unlock()

	logInfo("SPAMHAUS: %d CIDRs (%d IPv4, %d IPv6) in %d /16 IPv4 buckets and %d /48 IPv6 buckets",
		len(allNets), v4Count, v6Count, len(bucketsV4), len(bucketsV6))
}

// ============================================================================
// SPAMHAUS DROP CIDR PARSER
// ============================================================================
//
// Spamhaus DROP lists contain CIDR ranges like:
//
//   207.105.108.0/22 ; SBL624906
//   208.98.64.0/18 ; SBL642249
//
// Format: "<CIDR> ; <comment>"
//
// We ignore the comment and parse only the CIDR.
// ============================================================================

func parseSpamhausCIDRs(r io.Reader) ([]*net.IPNet, error) {
	scanner := bufio.NewScanner(r)
	nets := make([]*net.IPNet, 0, 4096)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Split at ";" (comment ignored)
		parts := strings.Split(line, ";")
		cidrStr := strings.TrimSpace(parts[0])

		// Parse CIDR
		if _, netIP, err := net.ParseCIDR(cidrStr); err == nil {
			nets = append(nets, netIP)
		}
	}

	return nets, scanner.Err()
}

// startEmThreatsRefresher runs forever in its own goroutine.
// It periodically refreshes the EmergingThreats compromised IP list
// according to the configured refresh interval.
//
// This keeps the in-memory set current without blocking any scrape path.
func (mc *MetricsCollector) startEmThreatsRefresher() {
	for {
		mc.refreshEmergingThreatsList()
		time.Sleep(mc.emThreatsRefresh)
	}
}

// refreshEmergingThreatsList downloads the EmergingThreats "compromised-ips.txt"
// list and replaces the internal map with a fresh copy.
//
// The list is a plain text file containing one IPv4 per line:
//
//	185.244.195.109
//	45.134.144.96
//	...
//
// We treat all valid lines as direct IP addresses to match against
// conntrack entries in collectDomainMetrics().
func (mc *MetricsCollector) refreshEmergingThreatsList() {
	resp, err := http.Get(mc.emThreatsURL)
	if err != nil {
		logError("EMTHREATS: Failed to download list: %v", err)
		return
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	fresh := make(map[string]struct{})

	for scanner.Scan() {
		ip := strings.TrimSpace(scanner.Text())
		if ip == "" || strings.HasPrefix(ip, "#") {
			continue // skip empty lines or comments
		}
		fresh[ip] = struct{}{} // store IP as a set key
	}

	// Atomically swap in the new set
	mc.emThreatsMu.Lock()
	mc.emThreatsSet = fresh
	mc.emThreatsMu.Unlock()

	logInfo("EMTHREATS: Loaded %d compromised IPs", len(fresh))
}

// ============================================================================
// CUSTOM USER-PROVIDED IP LIST SUPPORT
// ============================================================================
//
// This allows operators to point the exporter at a local file containing one
// IP address per line (IPv4 or IPv6). Any instance that communicates with one
// of these IPs during the collection interval will be flagged via a dedicated
// metric oie_customlist_contact.
//
// The file format is simple:
//
//   # comments allowed
//   1.2.3.4
//   2001:db8::1
//
// This list is periodically reloaded so operators can update it on disk
// without restarting the exporter.
// ============================================================================

func (mc *MetricsCollector) startCustomListRefresher() {
	for {
		mc.refreshCustomList()
		time.Sleep(mc.customListRefresh)
	}
}

func (mc *MetricsCollector) refreshCustomList() {
	f, err := os.Open(mc.customListPath)
	if err != nil {
		logError("CUSTOMLIST: failed to open %s: %v", mc.customListPath, err)
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	fresh := make(map[string]struct{})

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if net.ParseIP(line) == nil {
			continue
		}
		fresh[line] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		logError("CUSTOMLIST: read error on %s: %v", mc.customListPath, err)
		return
	}

	mc.customListMu.Lock()
	mc.customListSet = fresh
	mc.customListMu.Unlock()

	logInfo("CUSTOMLIST: loaded %d IPs from %s", len(fresh), mc.customListPath)
}

// ============================================================================
// CPU SAMPLING SUPPORT
// ============================================================================
//
// Instead of sleeping for 1 second between CPU stats calls, we take samples
// every collection interval and compute usage from deltas over time.
//
// cpuSample stores a single raw CPU time and its timestamp.
type cpuSample struct {
	total uint64
	ts    time.Time
}

// ============================================================================
// MAIN METRICS COLLECTOR
// ============================================================================
//
// MetricsCollector owns:
//   - The libvirt connection.
//   - Prometheus metric descriptors.
//   - Caches for static/dynamic metrics.
//   - CPU sampling state.
//   - Configuration for thresholds and intervals.
//
// It implements Prometheus's Collector interface.

type MetricsCollector struct {
	// libvirt connection handle
	conn *libvirt.Connect

	// Per disk-type I/O thresholds and defaults
	readThreshold         map[string]int
	writeThreshold        map[string]int
	defaultReadThreshold  int
	defaultWriteThreshold int

	// Metric descriptors
	diskReadThresholds  *prometheus.Desc
	diskWriteThresholds *prometheus.Desc
	diskReadBytes       *prometheus.Desc
	diskWriteBytes      *prometheus.Desc
	diskReadRequests    *prometheus.Desc
	diskWriteRequests   *prometheus.Desc
	cpuUsage            *prometheus.Desc
	networkRxBytes      *prometheus.Desc
	networkTxBytes      *prometheus.Desc
	networkRxPackets    *prometheus.Desc
	networkTxPackets    *prometheus.Desc
	networkRxErrors     *prometheus.Desc
	networkTxErrors     *prometheus.Desc
	networkRxDropped    *prometheus.Desc
	networkTxDropped    *prometheus.Desc
	ctPerIP             *prometheus.Desc

	// Caches: static and dynamic. Static cache is reserved for future
	// rarely-changing metrics; dynamic cache holds metrics from the last
	// collection for each instance.
	staticCache  *Cache
	dynamicCache *Cache

	// Collection interval for background sampling
	collectionInterval time.Duration

	// CPU sampling state
	cpuMu         sync.Mutex
	cpuSamples    map[string]cpuSample // last raw CPU sample per instance
	cpuLastExport map[string]float64   // last exported CPU usage per instance
	cpuMin        float64
	// Minimum conntrack value before creating a metric
	conntrackMin int
	// TOR exit node detection
	torEnabled     bool
	torURL         string
	torRefresh     time.Duration
	torSet         map[string]struct{} // fast lookup of Tor IPs
	torMu          sync.RWMutex        // guard torSet
	torContactDesc *prometheus.Desc    // metric emitted if VM talks to Tor exits
	// Spamhaus DROP CIDR detection (IPv4 + IPv6)
	spamEnabled   bool
	spamURL       string
	spamV6URL     string
	spamRefresh   time.Duration
	spamNets      []*net.IPNet
	spamBucketsV4 map[string][]*net.IPNet
	spamBucketsV6 map[string][]*net.IPNet
	spamMu        sync.RWMutex

	spamContactDesc *prometheus.Desc
	// EmergingThreats compromised IP detection
	emThreatsEnabled     bool
	emThreatsURL         string
	emThreatsRefresh     time.Duration
	emThreatsSet         map[string]struct{}
	emThreatsMu          sync.RWMutex
	emThreatsContactDesc *prometheus.Desc

	// Custom user-provided IP list
	customListEnabled     bool
	customListPath        string
	customListRefresh     time.Duration
	customListSet         map[string]struct{}
	customListMu          sync.RWMutex
	customListContactDesc *prometheus.Desc
}

// NewMetricsCollector connects to libvirt, sets up metric descriptors, and
// starts the background collection and cache-cleanup goroutines.
func NewMetricsCollector(
	uri string,
	readThresholds map[string]int,
	writeThresholds map[string]int,
	defaultReadThreshold int,
	defaultWriteThreshold int,
	staticCacheExpiration time.Duration,
	dynamicCacheExpiration time.Duration,
	collectionInterval time.Duration,
	conntrackMin int,
	cpuMin float64,
	torEnable bool,
	torURL string,
	torRefresh time.Duration,
	spamEnable bool,
	spamURL string,
	spamV6URL string,
	spamRefresh time.Duration,
	emThreatsEnable bool,
	emThreatsURL string,
	emThreatsRefresh time.Duration,
	customListEnable bool,
	customListPath string,
	customListRefresh time.Duration,
) (*MetricsCollector, error) {
	// Connect to libvirt.
	conn, err := libvirt.NewConnect(uri)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to libvirt: %v", err)
	}

	mc := &MetricsCollector{
		conn:                  conn,
		readThreshold:         readThresholds,
		writeThreshold:        writeThresholds,
		conntrackMin:          conntrackMin,
		cpuMin:                cpuMin,
		defaultReadThreshold:  defaultReadThreshold,
		defaultWriteThreshold: defaultWriteThreshold,
		diskReadThresholds: prometheus.NewDesc(
			"oie_disk_r_alert_threshold",
			"Disk read alert threshold",
			[]string{"domain", "instance_uuid", "user_uuid", "project_uuid", "disk_uuid", "disk_type", "disk_path"},
			nil,
		),
		diskWriteThresholds: prometheus.NewDesc(
			"oie_disk_w_alert_threshold",
			"Disk write alert threshold",
			[]string{"domain", "instance_uuid", "user_uuid", "project_uuid", "disk_uuid", "disk_type", "disk_path"},
			nil,
		),
		diskReadBytes: prometheus.NewDesc(
			"oie_disk_r_gbytes",
			"Disk read gigabytes",
			[]string{"domain", "instance_uuid", "user_uuid", "project_uuid", "disk_uuid", "disk_type", "disk_path"},
			nil,
		),
		diskWriteBytes: prometheus.NewDesc(
			"oie_disk_w_gbytes",
			"Disk write gigabytes",
			[]string{"domain", "instance_uuid", "user_uuid", "project_uuid", "disk_uuid", "disk_type", "disk_path"},
			nil,
		),
		diskReadRequests: prometheus.NewDesc(
			"oie_disk_r_requests",
			"Disk read requests",
			[]string{"domain", "instance_uuid", "user_uuid", "project_uuid", "disk_uuid", "disk_type", "disk_path"},
			nil,
		),
		diskWriteRequests: prometheus.NewDesc(
			"oie_disk_w_requests",
			"Disk write requests",
			[]string{"domain", "instance_uuid", "user_uuid", "project_uuid", "disk_uuid", "disk_type", "disk_path"},
			nil,
		),
		cpuUsage: prometheus.NewDesc(
			"oie_cpu_percent",
			"CPU usage percentage",
			[]string{"domain", "instance_uuid", "user_uuid", "project_uuid"},
			nil,
		),
		networkRxBytes: prometheus.NewDesc(
			"oie_net_rx_gbytes",
			"Network receive gigabytes",
			[]string{"domain", "interface", "instance_uuid", "user_uuid", "project_uuid"},
			nil,
		),
		networkTxBytes: prometheus.NewDesc(
			"oie_net_tx_gbytes",
			"Network transmit gigabytes",
			[]string{"domain", "interface", "instance_uuid", "user_uuid", "project_uuid"},
			nil,
		),
		networkRxPackets: prometheus.NewDesc(
			"oie_net_rx_pkt_total",
			"Network receive packets",
			[]string{"domain", "interface", "instance_uuid", "user_uuid", "project_uuid"},
			nil,
		),
		networkTxPackets: prometheus.NewDesc(
			"oie_net_tx_pkt_total",
			"Network transmit packets",
			[]string{"domain", "interface", "instance_uuid", "user_uuid", "project_uuid"},
			nil,
		),
		networkRxErrors: prometheus.NewDesc(
			"oie_net_rx_er_total",
			"Network receive errors",
			[]string{"domain", "interface", "instance_uuid", "user_uuid", "project_uuid"},
			nil,
		),
		networkTxErrors: prometheus.NewDesc(
			"oie_net_tx_er_total",
			"Network transmit errors",
			[]string{"domain", "interface", "instance_uuid", "user_uuid", "project_uuid"},
			nil,
		),
		networkRxDropped: prometheus.NewDesc(
			"oie_net_rx_drp_total",
			"Network receive dropped packets",
			[]string{"domain", "interface", "instance_uuid", "user_uuid", "project_uuid"},
			nil,
		),
		networkTxDropped: prometheus.NewDesc(
			"oie_net_tx_drp_total",
			"Network transmit dropped packets",
			[]string{"domain", "interface", "instance_uuid", "user_uuid", "project_uuid"},
			nil,
		),
		ctPerIP: prometheus.NewDesc(
			"oie_conntrack_ip_total",
			"Conntrack entries matched to this fixed IP",
			[]string{"domain", "instance_uuid", "ip", "family", "project_uuid", "user_uuid"},
			nil,
		),
		staticCache:        NewCache(staticCacheExpiration),
		dynamicCache:       NewCache(dynamicCacheExpiration),
		collectionInterval: collectionInterval,
		cpuSamples:         make(map[string]cpuSample),
		cpuLastExport:      make(map[string]float64),
		// TOR configuration
		torEnabled: torEnable,
		torURL:     torURL,
		torRefresh: torRefresh,
		torSet:     make(map[string]struct{}),

		torContactDesc: prometheus.NewDesc(
			"oie_tor_contact",
			"1 if this instance communicated with a Tor exit node during the collection interval",
			[]string{"domain", "instance_uuid", "project_uuid", "user_uuid"},
			nil,
		),

		// SPAMHAUS configuration (IPv4 + IPv6 in one)
		spamEnabled:   spamEnable,
		spamURL:       spamURL,
		spamV6URL:     spamV6URL,
		spamRefresh:   spamRefresh,
		spamNets:      make([]*net.IPNet, 0),
		spamBucketsV4: make(map[string][]*net.IPNet),
		spamBucketsV6: make(map[string][]*net.IPNet),

		spamContactDesc: prometheus.NewDesc(
			"oie_spamhaus_contact",
			"1 if this instance communicated with a Spamhaus DROP-listed IP during the collection interval",
			[]string{"domain", "instance_uuid", "project_uuid", "user_uuid"},
			nil,
		),

		// EMERGINGTHREATS configuration
		emThreatsEnabled: emThreatsEnable,
		emThreatsURL:     emThreatsURL,
		emThreatsRefresh: emThreatsRefresh,
		emThreatsSet:     make(map[string]struct{}),

		emThreatsContactDesc: prometheus.NewDesc(
			"oie_emergingthreats_contact",
			"1 if this instance communicated with an IP listed in the EmergingThreats compromised IP feed",
			[]string{"domain", "instance_uuid", "project_uuid", "user_uuid"},
			nil,
		),

		// CUSTOM LIST configuration
		customListEnabled: customListEnable,
		customListPath:    customListPath,
		customListRefresh: customListRefresh,
		customListSet:     make(map[string]struct{}),

		customListContactDesc: prometheus.NewDesc(
			"oie_customlist_contact",
			"1 if this instance communicated with an IP from the user-provided custom list",
			[]string{"domain", "instance_uuid", "project_uuid", "user_uuid"},
			nil,
		),
	}
	// Start TOR exit node list refresher
	if mc.torEnabled {
		go mc.startTorRefresher()
	}
	// Start unified Spamhaus CIDR refresher (IPv4 + IPv6)
	if mc.spamEnabled {
		go mc.startSpamhausRefresher()
	}
	// Start EmergingThreats refresher
	if mc.emThreatsEnabled {
		go mc.startEmThreatsRefresher()
	}
	// Start custom user-list refresher
	if mc.customListEnabled && mc.customListPath != "" {
		go mc.startCustomListRefresher()
	}

	// Start periodic background collection of metrics.
	go mc.startBackgroundCollection()
	// Start periodic cache cleanup.
	go mc.startCacheCleanup()

	return mc, nil
}

// startCacheCleanup periodically prunes expired entries from both caches.
// It runs forever in its own goroutine.
func (mc *MetricsCollector) startCacheCleanup() {
	for {
		time.Sleep(time.Minute)
		mc.staticCache.Cleanup(mc)
		mc.dynamicCache.Cleanup(mc)
		logDebug("Performed cache cleanup")
	}
}

// Describe sends metric descriptors to Prometheus. It is part of the
// prometheus.Collector interface and is called once at registration time.
func (mc *MetricsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- mc.diskReadThresholds
	ch <- mc.diskWriteThresholds
	ch <- mc.diskReadBytes
	ch <- mc.diskWriteBytes
	ch <- mc.diskReadRequests
	ch <- mc.diskWriteRequests
	ch <- mc.cpuUsage
	ch <- mc.networkRxBytes
	ch <- mc.networkTxBytes
	ch <- mc.networkRxPackets
	ch <- mc.networkTxPackets
	ch <- mc.networkRxErrors
	ch <- mc.networkTxErrors
	ch <- mc.networkRxDropped
	ch <- mc.networkTxDropped
	ch <- mc.ctPerIP
	ch <- mc.torContactDesc
	ch <- mc.spamContactDesc
	ch <- mc.emThreatsContactDesc
	ch <- mc.customListContactDesc
}

// Collect is called every time Prometheus scrapes /metrics.
// IMPORTANT: this does not call libvirt. It simply reads whatever metrics
// are already in our caches from the last background collection run.
func (mc *MetricsCollector) Collect(ch chan<- prometheus.Metric) {
	logDebug("Serving metrics from cache")

	for _, metric := range mc.collectCachedMetrics() {
		ch <- metric
	}
}

// startBackgroundCollection runs in its own goroutine and drives actual
// metric collection from libvirt and conntrack:
//
//   - List active domains
//   - Run conntrack once
//   - Spawn a goroutine per domain to collect metrics
//   - Save all metrics in the dynamic cache
//   - Sleep until the next collection interval
func (mc *MetricsCollector) startBackgroundCollection() {
	for {
		logDebug("Background collection of metrics")

		// 1) List all active domains.
		domains, err := mc.conn.ListAllDomains(libvirt.CONNECT_LIST_DOMAINS_ACTIVE)
		if err != nil {
			logError("failed to list domains: %v", err)
			time.Sleep(mc.collectionInterval)
			continue
		}

		logDebug("Found %d active domains", len(domains))

		// 2) Read conntrack once per collection cycle (not per domain).
		ctEntries, err := readConntrack()
		if err != nil {
			logDebug("failed to read conntrack: %v", err)
		}

		// 3) Collect metrics concurrently per domain.
		var wg sync.WaitGroup
		for _, dom := range domains {
			domain := dom
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer domain.Free()
				mc.collectDomainMetrics(domain, ctEntries)
			}()
		}
		wg.Wait()

		// 4) Sleep until next collection.
		time.Sleep(mc.collectionInterval)
	}
}

// roundToTwoDecimals rounds a float64 to two decimal places.
// Used primarily to make GB counters nicer looking.
func roundToTwoDecimals(value float64) float64 {
	return math.Round(value*100) / 100
}

// parseDiskType splits a Ceph-style "pool/volume" into ("pool", "volume").
// If no "/" is found, it returns ("unknown", "unknown") as a safe fallback.
func parseDiskType(sourceName string) (string, string) {
	parts := strings.Split(sourceName, "/")
	if len(parts) > 1 {
		return parts[0], parts[1]
	}
	return "unknown", "unknown"
}

// calculateCPUUsage reads CPU stats for a domain and computes usage based on
// the delta from the previous sample, scaled by elapsed time and vCPU count.
//
// It does NOT sleep. It simply stores the last sample, and the background
// collector calls it again on the next run, allowing it to compute a rate.
func (mc *MetricsCollector) calculateCPUUsage(domain libvirt.Domain, uuid string, vcpuCount int) (float64, error) {
	if vcpuCount <= 0 {
		return 0, nil
	}

	stats, err := domain.GetCPUStats(-1, 0, 0)
	if err != nil {
		return 0, fmt.Errorf("failed to get CPU stats: %v", err)
	}
	if len(stats) == 0 {
		return 0, fmt.Errorf("CPU stats empty")
	}

	now := time.Now()
	total := stats[0].CpuTime

	mc.cpuMu.Lock()
	prev, ok := mc.cpuSamples[uuid]
	mc.cpuSamples[uuid] = cpuSample{
		total: total,
		ts:    now,
	}
	mc.cpuMu.Unlock()

	// First observation: cannot compute a delta yet, so we return 0.
	if !ok {
		return 0, nil
	}

	elapsed := now.Sub(prev.ts)
	if elapsed <= 0 {
		return 0, nil
	}

	delta := total - prev.total
	usage := (float64(delta) / float64(elapsed.Nanoseconds())) * 100 / float64(vcpuCount)

	if usage < 0 {
		usage = 0
	} else if usage > 100 {
		usage = 100
	}

	return usage, nil
}

// shouldExportCPU decides whether a CPU usage metric should be exported
// or suppressed, based on the last exported value for this VM.
//
// Rules:
//   - If this is the first time, we always export.
//   - If the previous export was 0 and the current is 0 → skip.
//   - If the previous export equals the current → skip.
//   - Otherwise → export and update last-export cache.
//
// This avoids flooding Prometheus with thousands of repeated 0s or
// repeated identical values that never change.
func (mc *MetricsCollector) shouldExportCPU(uuid string, usage float64) bool {
	if usage < mc.cpuMin {
		return false
	}

	mc.cpuMu.Lock()
	defer mc.cpuMu.Unlock()

	prev, ok := mc.cpuLastExport[uuid]
	if !ok {
		// First time we see this instance, always export.
		mc.cpuLastExport[uuid] = usage
		return true
	}

	// 0-collapse: suppress repeated 0% CPU samples.
	if usage == 0 && prev == 0 {
		return false
	}

	// Suppress if unchanged.
	if usage == prev {
		return false
	}

	// Update last export and allow emission.
	mc.cpuLastExport[uuid] = usage
	return true
}

const bytesToGigabytes = 1.0 / (1024 * 1024 * 1024)

// collectDomainMetrics collects all metrics for a single libvirt domain and
// stores them in the dynamic cache under its instance UUID.
//
// This is where the safe zero-suppression rules are applied for:
//   - Disk counters
//   - Network counters
//   - Conntrack matches
//   - CPU
func (mc *MetricsCollector) collectDomainMetrics(domain libvirt.Domain, ctEntries []ConntrackEntry) {
	name, err := domain.GetName()
	if err != nil {
		logError("failed to get domain name: %v", err)
		return
	}

	instanceUUID, err := domain.GetUUIDString()
	if err != nil {
		logError("failed to get domain UUID: %v", err)
		return
	}

	xmlDesc, err := domain.GetXMLDesc(0)
	if err != nil {
		logError("failed to get domain XML description: %v", err)
		return
	}

	var domainXML DomainXML
	if err := xml.Unmarshal([]byte(xmlDesc), &domainXML); err != nil {
		logError("failed to parse domain XML: %v", err)
		return
	}

	// Collect fixed IPs from Nova metadata for this instance.
	// These are used to match conntrack flows later.
	fixedIPs := make([]IP, 0)
	for _, p := range domainXML.Metadata.NovaInstance.NovaPorts.Ports {
		for _, ip := range p.IPs {
			fixedIPs = append(fixedIPs, IP{
				Address: ip.Address,
				Family:  "ipv" + ip.IPVersion,
				Prefix:  "",
			})
		}
	}

	// Build the IP set ONCE so all scanners can use it (TOR, Spamhaus, ET, Conntrack)
	ipSet := make(map[string]struct{}, len(fixedIPs))
	for _, ip := range fixedIPs {
		ipSet[ip.Address] = struct{}{}
	}

	userUUID := domainXML.Metadata.NovaInstance.NovaOwner.NovaUser.UserUUID
	projectUUID := domainXML.Metadata.NovaInstance.NovaOwner.NovaProject.ProjectUUID
	vcpuCount := domainXML.Metadata.NovaInstance.NovaFlavor.VCPUs

	// Accumulate metrics for this VM in a slice, then commit to cache in one go.
	dynamicMetrics := make([]prometheus.Metric, 0, 64)

	// ----------------------------------------------------------------------
	// DISK METRICS (with safe zero-suppression for I/O counters)
	// ----------------------------------------------------------------------
	seenDisks := make(map[string]struct{})
	for _, disk := range domainXML.Devices.Disks {
		if disk.Device != "disk" {
			continue
		}

		dev := disk.Target.Dev
		stats, err := domain.BlockStats(dev)
		if err != nil {
			logDebug("failed to get block stats for domain=%s dev=%s: %v", name, dev, err)
			continue
		}

		var diskType, volumeUUID string
		if disk.Type == "file" {
			diskType = "local"
			volumeUUID = disk.Source.File
		} else {
			diskType, volumeUUID = parseDiskType(disk.Source.Name)
		}
		diskPath := disk.Target.Dev

		// Protect against duplicates in XML by using diskType+diskPath as key.
		key := diskType + "-" + diskPath
		if _, exists := seenDisks[key]; exists {
			continue
		}
		seenDisks[key] = struct{}{}

		// Determine thresholds for this diskType, honoring both per-type and
		// default values if provided.
		readThreshold := mc.defaultReadThreshold
		if v, ok := mc.readThreshold["default"]; ok {
			readThreshold = v
		}
		if v, ok := mc.readThreshold[diskType]; ok {
			readThreshold = v
		}

		writeThreshold := mc.defaultWriteThreshold
		if v, ok := mc.writeThreshold["default"]; ok {
			writeThreshold = v
		}
		if v, ok := mc.writeThreshold[diskType]; ok {
			writeThreshold = v
		}

		// Build metrics for this disk in a local slice.
		diskMetrics := make([]prometheus.Metric, 0, 6)

		// Thresholds are always exported, even when there is no I/O.
		// They do not change often and carry configuration information.
		diskMetrics = append(diskMetrics,
			prometheus.MustNewConstMetric(
				mc.diskReadThresholds,
				prometheus.GaugeValue,
				float64(readThreshold),
				name, instanceUUID, userUUID, projectUUID, volumeUUID, diskType, diskPath,
			),
			prometheus.MustNewConstMetric(
				mc.diskWriteThresholds,
				prometheus.GaugeValue,
				float64(writeThreshold),
				name, instanceUUID, userUUID, projectUUID, volumeUUID, diskType, diskPath,
			),
		)

		// SAFE ZERO SUPPRESSION (disk):
		//
		// If *all* disk counters are zero, this disk has never seen I/O (or
		// has not seen I/O since boot). Re-exporting zeros every scrape
		// wastes Prometheus storage. In that case we skip all disk I/O
		// counters, but still export thresholds.
		if stats.RdBytes == 0 && stats.WrBytes == 0 && stats.RdReq == 0 && stats.WrReq == 0 {
			logDebug(
				"Domain=%s Disk=%s Type=%s has no I/O; exporting thresholds only",
				name, diskPath, diskType,
			)
		} else {
			// Only emit I/O counters if there is measurable activity.
			diskMetrics = append(diskMetrics,
				prometheus.MustNewConstMetric(
					mc.diskReadBytes,
					prometheus.CounterValue,
					roundToTwoDecimals(float64(stats.RdBytes)*bytesToGigabytes),
					name, instanceUUID, userUUID, projectUUID, volumeUUID, diskType, diskPath,
				),
				prometheus.MustNewConstMetric(
					mc.diskWriteBytes,
					prometheus.CounterValue,
					roundToTwoDecimals(float64(stats.WrBytes)*bytesToGigabytes),
					name, instanceUUID, userUUID, projectUUID, volumeUUID, diskType, diskPath,
				),
				prometheus.MustNewConstMetric(
					mc.diskReadRequests,
					prometheus.CounterValue,
					float64(stats.RdReq),
					name, instanceUUID, userUUID, projectUUID, volumeUUID, diskType, diskPath,
				),
				prometheus.MustNewConstMetric(
					mc.diskWriteRequests,
					prometheus.CounterValue,
					float64(stats.WrReq),
					name, instanceUUID, userUUID, projectUUID, volumeUUID, diskType, diskPath,
				),
			)
		}

		logDebug(
			"Domain=%s Disk=%s Type=%s RdBytes=%d WrBytes=%d RdReq=%d WrReq=%d RdThr=%d WrThr=%d",
			name, diskPath, diskType, stats.RdBytes, stats.WrBytes, stats.RdReq, stats.WrReq, readThreshold, writeThreshold,
		)

		dynamicMetrics = append(dynamicMetrics, diskMetrics...)
	}

	// ----------------------------------------------------------------------
	// CPU METRICS (with 0-collapse + unchanged suppression)
	// ----------------------------------------------------------------------
	cpuUsage, err := mc.calculateCPUUsage(domain, instanceUUID, vcpuCount)
	if err != nil {
		logDebug("failed to calculate CPU usage for domain=%s: %v", name, err)
	}

	// Decide whether CPU usage should be exported or suppressed.
	if mc.shouldExportCPU(instanceUUID, cpuUsage) {
		dynamicMetrics = append(dynamicMetrics,
			prometheus.MustNewConstMetric(
				mc.cpuUsage,
				prometheus.GaugeValue,
				roundToTwoDecimals(cpuUsage),
				name, instanceUUID, userUUID, projectUUID,
			),
		)

		logDebug("Domain=%s CPUUsage=%.2f%% (exported)", name, cpuUsage)
	} else {
		logDebug("Domain=%s CPUUsage=%.2f%% (suppressed: unchanged or below min/steady 0)", name, cpuUsage)
	}

	// ----------------------------------------------------------------------
	// NETWORK METRICS (safe zero-suppression per interface)
	// ----------------------------------------------------------------------
	for _, iface := range domainXML.Devices.Interfaces {
		interfaceName := iface.Target.Dev
		stats, err := domain.InterfaceStats(interfaceName)
		if err != nil {
			logDebug("failed to get interface stats for domain=%s iface=%s: %v", name, interfaceName, err)
			continue
		}

		netRxBytes := uint64(stats.RxBytes)
		netTxBytes := uint64(stats.TxBytes)
		netRxPackets := uint64(stats.RxPackets)
		netTxPackets := uint64(stats.TxPackets)
		netRxErrs := uint64(stats.RxErrs)
		netTxErrs := uint64(stats.TxErrs)
		netRxDrop := uint64(stats.RxDrop)
		netTxDrop := uint64(stats.TxDrop)

		// SAFE ZERO SUPPRESSION (network):
		//
		// An interface exposes 8 metrics. If a VM has multiple NICs, this
		// multiplies quickly. When a NIC has never seen traffic, exporting
		// 8 zeros every scrape is unnecessary.
		//
		// If all counters are 0, we skip exporting any metrics for this
		// interface in this cycle.
		if netRxBytes == 0 &&
			netTxBytes == 0 &&
			netRxPackets == 0 &&
			netTxPackets == 0 &&
			netRxErrs == 0 &&
			netTxErrs == 0 &&
			netRxDrop == 0 &&
			netTxDrop == 0 {
			logDebug("Domain=%s Iface=%s has no activity; skipping all network metrics for this interface", name, interfaceName)
			continue
		}

		logDebug(
			"Domain=%s Iface=%s RxBytes=%d TxBytes=%d RxPkts=%d TxPkts=%d RxErr=%d TxErr=%d RxDrop=%d TxDrop=%d",
			name, interfaceName, netRxBytes, netTxBytes, netRxPackets, netTxPackets, netRxErrs, netTxErrs, netRxDrop, netTxDrop,
		)

		dynamicMetrics = append(dynamicMetrics,
			prometheus.MustNewConstMetric(
				mc.networkRxBytes,
				prometheus.CounterValue,
				roundToTwoDecimals(float64(netRxBytes)*bytesToGigabytes),
				name, interfaceName, instanceUUID, userUUID, projectUUID,
			),
			prometheus.MustNewConstMetric(
				mc.networkTxBytes,
				prometheus.CounterValue,
				roundToTwoDecimals(float64(netTxBytes)*bytesToGigabytes),
				name, interfaceName, instanceUUID, userUUID, projectUUID,
			),
			prometheus.MustNewConstMetric(
				mc.networkRxPackets,
				prometheus.CounterValue,
				float64(netRxPackets),
				name, interfaceName, instanceUUID, userUUID, projectUUID,
			),
			prometheus.MustNewConstMetric(
				mc.networkTxPackets,
				prometheus.CounterValue,
				float64(netTxPackets),
				name, interfaceName, instanceUUID, userUUID, projectUUID,
			),
			prometheus.MustNewConstMetric(
				mc.networkRxErrors,
				prometheus.CounterValue,
				float64(netRxErrs),
				name, interfaceName, instanceUUID, userUUID, projectUUID,
			),
			prometheus.MustNewConstMetric(
				mc.networkTxErrors,
				prometheus.CounterValue,
				float64(netTxErrs),
				name, interfaceName, instanceUUID, userUUID, projectUUID,
			),
			prometheus.MustNewConstMetric(
				mc.networkRxDropped,
				prometheus.CounterValue,
				float64(netRxDrop),
				name, interfaceName, instanceUUID, userUUID, projectUUID,
			),
			prometheus.MustNewConstMetric(
				mc.networkTxDropped,
				prometheus.CounterValue,
				float64(netTxDrop),
				name, interfaceName, instanceUUID, userUUID, projectUUID,
			),
		)
	}

	// ----------------------------------------------------------------------
	// CONNTRACK MATCHING PER FIXED IP (safe zero-suppression)
	// ----------------------------------------------------------------------
	if len(ctEntries) > 0 && len(fixedIPs) > 0 {

		// Count conntrack matches per IP (only for fixed IPs of this instance).
		perIPCount := make(map[string]int, len(fixedIPs))

		for _, ct := range ctEntries {

			// Only count flows that belong to THIS VM
			if _, ok := ipSet[ct.Src]; ok {
				perIPCount[ct.Src]++
			}

			if ct.Dst != ct.Src {
				if _, ok := ipSet[ct.Dst]; ok {
					perIPCount[ct.Dst]++
				}
			}
		}

		for _, ip := range fixedIPs {
			count := perIPCount[ip.Address]

			// SAFE ZERO SUPPRESSION:
			// Emit conntrack metric ONLY when >= min threshold.
			if count < mc.conntrackMin {
				logDebug(
					"Domain=%s IP=%s conntrack=%d below threshold=%d; skipping",
					name, ip.Address, count, mc.conntrackMin,
				)
				continue
			}

			dynamicMetrics = append(dynamicMetrics,
				prometheus.MustNewConstMetric(
					mc.ctPerIP,
					prometheus.GaugeValue,
					float64(count),
					name,
					instanceUUID,
					ip.Address,
					ip.Family,
					projectUUID,
					userUUID,
				),
			)
		}
	}

	// TOR EXIT NODE DETECTION
	if mc.torEnabled {

		mc.torMu.RLock()
		torSnapshot := make(map[string]struct{}, len(mc.torSet))
		for k := range mc.torSet {
			torSnapshot[k] = struct{}{}
		}
		mc.torMu.RUnlock()

		contacted := false

		for _, ct := range ctEntries {

			// only flows belonging to this VM
			if _, ok := ipSet[ct.Src]; !ok {
				if _, ok2 := ipSet[ct.Dst]; !ok2 {
					continue
				}
			}

			// RAW STRING MATCH
			if _, ok := torSnapshot[ct.Src]; ok {
				contacted = true
				logThreat("TOR-HIT: domain=%s uuid=%s ip=%s direction=src",
					name, instanceUUID, ct.Src)
				break
			}

			if _, ok := torSnapshot[ct.Dst]; ok {
				contacted = true
				logThreat("TOR-HIT: domain=%s uuid=%s ip=%s direction=dst",
					name, instanceUUID, ct.Dst)
				break
			}
		}

		if contacted {
			dynamicMetrics = append(dynamicMetrics,
				prometheus.MustNewConstMetric(
					mc.torContactDesc,
					prometheus.GaugeValue,
					1.0,
					name,
					instanceUUID,
					projectUUID,
					userUUID,
				),
			)
		}
	}

	// ----------------------------------------------------------------------
	// SPAMHAUS DROP CIDR DETECTION (IPv4 + IPv6, ZERO-SUPPRESSION)
	// ----------------------------------------------------------------------
	if mc.spamEnabled {

		contacted := false

		mc.spamMu.RLock()
		for _, ct := range ctEntries {

			// Only flows belonging to this VM
			if _, ok := ipSet[ct.Src]; !ok {
				if _, ok2 := ipSet[ct.Dst]; !ok2 {
					continue
				}
			}

			srcIP := net.ParseIP(ct.Src)
			dstIP := net.ParseIP(ct.Dst)

			// IPv4 SRC
			if srcIP != nil {
				if src4 := srcIP.To4(); src4 != nil {
					key := fmt.Sprintf("%d.%d", src4[0], src4[1])
					for _, n := range mc.spamBucketsV4[key] {
						if n.Contains(src4) {
							contacted = true
							logThreat("SPAMHAUS-HIT: domain=%s uuid=%s ip=%s direction=src",
								name, instanceUUID, ct.Src)
							break
						}
					}
				} else {
					// IPv6 SRC
					src16 := srcIP.To16()
					if src16 != nil {
						key := fmt.Sprintf("%x:%x:%x",
							uint16(src16[0])<<8|uint16(src16[1]),
							uint16(src16[2])<<8|uint16(src16[3]),
							uint16(src16[4])<<8|uint16(src16[5]),
						)
						for _, n := range mc.spamBucketsV6[key] {
							if n.Contains(srcIP) {
								contacted = true
								logThreat("SPAMHAUS-HIT: domain=%s uuid=%s ip=%s direction=src",
									name, instanceUUID, ct.Src)
								break
							}
						}
					}
				}
			}

			if contacted {
				break
			}

			// IPv4 DST
			if dstIP != nil {
				if dst4 := dstIP.To4(); dst4 != nil {
					key := fmt.Sprintf("%d.%d", dst4[0], dst4[1])
					for _, n := range mc.spamBucketsV4[key] {
						if n.Contains(dst4) {
							contacted = true
							logThreat("SPAMHAUS-HIT: domain=%s uuid=%s ip=%s direction=dst",
								name, instanceUUID, ct.Dst)
							break
						}
					}
				} else {
					// IPv6 DST
					dst16 := dstIP.To16()
					if dst16 != nil {
						key := fmt.Sprintf("%x:%x:%x",
							uint16(dst16[0])<<8|uint16(dst16[1]),
							uint16(dst16[2])<<8|uint16(dst16[3]),
							uint16(dst16[4])<<8|uint16(dst16[5]),
						)
						for _, n := range mc.spamBucketsV6[key] {
							if n.Contains(dstIP) {
								contacted = true
								logThreat("SPAMHAUS-HIT: domain=%s uuid=%s ip=%s direction=dst",
									name, instanceUUID, ct.Dst)
								break
							}
						}
					}
				}
			}

			if contacted {
				break
			}
		}
		mc.spamMu.RUnlock()

		if contacted {
			dynamicMetrics = append(dynamicMetrics,
				prometheus.MustNewConstMetric(
					mc.spamContactDesc,
					prometheus.GaugeValue,
					1.0,
					name,
					instanceUUID,
					projectUUID,
					userUUID,
				),
			)
		}
	}

	// ----------------------------------------------------------------------
	// EMERGINGTHREATS COMPROMISED-IP DETECTION (ZERO-SUPPRESSION)
	// ----------------------------------------------------------------------
	if mc.emThreatsEnabled {

		mc.emThreatsMu.RLock()
		etSnapshot := make(map[string]struct{}, len(mc.emThreatsSet))
		for k := range mc.emThreatsSet {
			etSnapshot[k] = struct{}{}
		}
		mc.emThreatsMu.RUnlock()

		contacted := false

		for _, ct := range ctEntries {

			// Only flows belonging to this VM
			if _, ok := ipSet[ct.Src]; !ok {
				if _, ok2 := ipSet[ct.Dst]; !ok2 {
					continue // skip flows not belonging to this VM
				}
			}

			if _, ok := etSnapshot[ct.Src]; ok {
				contacted = true
				logThreat("EMTHREATS-HIT: domain=%s uuid=%s ip=%s direction=src",
					name, instanceUUID, ct.Src)
				break
			}

			if _, ok := etSnapshot[ct.Dst]; ok {
				contacted = true
				logThreat("EMTHREATS-HIT: domain=%s uuid=%s ip=%s direction=dst",
					name, instanceUUID, ct.Dst)
				break
			}
		}

		if contacted {
			dynamicMetrics = append(dynamicMetrics,
				prometheus.MustNewConstMetric(
					mc.emThreatsContactDesc,
					prometheus.GaugeValue,
					1.0,
					name,
					instanceUUID,
					projectUUID,
					userUUID,
				),
			)
		}
	}

	// ----------------------------------------------------------------------
	// CUSTOM USER LIST DETECTION (ZERO-SUPPRESSION)
	// ----------------------------------------------------------------------
	if mc.customListEnabled {

		mc.customListMu.RLock()
		clSnapshot := make(map[string]struct{}, len(mc.customListSet))
		for k := range mc.customListSet {
			clSnapshot[k] = struct{}{}
		}
		mc.customListMu.RUnlock()

		contacted := false

		for _, ct := range ctEntries {

			// Only flows belonging to this VM
			if _, ok := ipSet[ct.Src]; !ok {
				if _, ok2 := ipSet[ct.Dst]; !ok2 {
					continue
				}
			}

			if _, ok := clSnapshot[ct.Src]; ok {
				contacted = true
				logThreat("CUSTOMLIST-HIT: domain=%s uuid=%s ip=%s direction=src",
					name, instanceUUID, ct.Src)
				break
			}

			if _, ok := clSnapshot[ct.Dst]; ok {
				contacted = true
				logThreat("CUSTOMLIST-HIT: domain=%s uuid=%s ip=%s direction=dst",
					name, instanceUUID, ct.Dst)
				break
			}
		}

		if contacted {
			dynamicMetrics = append(dynamicMetrics,
				prometheus.MustNewConstMetric(
					mc.customListContactDesc,
					prometheus.GaugeValue,
					1.0,
					name,
					instanceUUID,
					projectUUID,
					userUUID,
				),
			)
		}
	}

	// Finally, store all dynamically collected metrics
	mc.dynamicCache.Set(instanceUUID, dynamicMetrics)
}

// collectCachedMetrics merges all metrics currently stored in the static
// and dynamic caches into a single slice. Collect() uses this as its output.
//
// This means Prometheus scrapes never perform direct libvirt calls and
// never trigger any heavy collection logic. They just stream whatever the
// last background collection cycle produced.
func (mc *MetricsCollector) collectCachedMetrics() []prometheus.Metric {
	results := make([]prometheus.Metric, 0, 256)

	mc.staticCache.mu.RLock()
	for _, entry := range mc.staticCache.data {
		if metrics, ok := entry.data.([]prometheus.Metric); ok {
			results = append(results, metrics...)
		}
	}
	mc.staticCache.mu.RUnlock()

	mc.dynamicCache.mu.RLock()
	for _, entry := range mc.dynamicCache.data {
		if metrics, ok := entry.data.([]prometheus.Metric); ok {
			results = append(results, metrics...)
		}
	}
	mc.dynamicCache.mu.RUnlock()

	return results
}

// isInstanceActive checks whether a libvirt domain with the given UUID
// currently exists. It is used by cache cleanup to avoid keeping metrics
// for instances that no longer exist.
func (mc *MetricsCollector) isInstanceActive(instanceUUID string) bool {
	domain, err := mc.conn.LookupDomainByUUIDString(instanceUUID)
	if err != nil || domain == nil {
		return false
	}
	defer domain.Free()
	return true
}

// parseThresholds parses CLI threshold strings like:
//
//	"default:500,local:200,ceph:1000"
//
// It returns a map of type → threshold, and ensures that there is at least
// a "default" entry, falling back to the provided defaultThreshold if needed.
func parseThresholds(thresholds string, defaultThreshold int) map[string]int {
	result := make(map[string]int)
	if thresholds == "" {
		return result
	}

	pairs := strings.Split(thresholds, ",")
	for _, pair := range pairs {
		kv := strings.Split(pair, ":")
		if len(kv) != 2 {
			continue
		}
		value, err := strconv.Atoi(kv[1])
		if err != nil {
			continue
		}
		result[kv[0]] = value
	}

	if _, ok := result["default"]; !ok {
		result["default"] = defaultThreshold
	}

	return result
}

// ============================================================================
// main: CLI, flags, and HTTP server
// ============================================================================
//
// main just wires everything together:
//
//   - Parses command-line flags
//   - Creates the MetricsCollector
//   - Registers it in a Prometheus registry
//   - Starts an HTTP server exposing /metrics

func main() {
	var listenAddress string
	var metricsPath string
	var libvirtURI string
	var readThresholds string
	var writeThresholds string
	var staticCacheExpiration time.Duration
	var dynamicCacheExpiration time.Duration
	var collectionInterval time.Duration
	var defaultReadThreshold int
	var defaultWriteThreshold int
	var conntrackMin int
	var cpuMin float64
	var torEnable bool
	var torURL string
	var torRefresh time.Duration
	var spamEnable bool
	var spamURL string
	var spamRefresh time.Duration
	var spamV6URL string
	var emThreatsEnable bool
	var emThreatsURL string
	var emThreatsRefresh time.Duration
	var customListEnable bool
	var customListPath string
	var customListRefresh time.Duration
	var logLevelFlag string

	// CLI flags controlling runtime behavior.
	flag.StringVar(&listenAddress, "web.listen-address", "0.0.0.0:9120", "Address to listen on for web interface and telemetry.")
	flag.StringVar(&metricsPath, "web.telemetry-path", "/metrics", "Path under which to expose metrics.")
	flag.StringVar(&libvirtURI, "libvirt.uri", "qemu:///system", "Libvirt URI from which to extract metrics.")
	flag.StringVar(&readThresholds, "read.thresholds", "", "Comma-separated list of read thresholds. eg -read.thresholds='default:500,local:200,ceph:1000'")
	flag.StringVar(&writeThresholds, "write.thresholds", "", "Comma-separated list of write thresholds. eg -write.thresholds='default:500,local:200,ceph:1000'")
	flag.DurationVar(&staticCacheExpiration, "static.cache.expiration", time.Hour, "Expiration duration for the cache of static values")
	flag.DurationVar(&dynamicCacheExpiration, "dynamic.cache.expiration", 10*time.Second, "Expiration duration for the cache of dynamic values")
	flag.DurationVar(&collectionInterval, "collection.interval", 10*time.Second, "Interval at which to collect metrics in the background")
	flag.IntVar(&defaultReadThreshold, "default.read.threshold", 100, "Default read threshold if none provided")
	flag.IntVar(&defaultWriteThreshold, "default.write.threshold", 100, "Default write threshold if none provided")
	flag.IntVar(&conntrackMin, "conntrack.min", 20, "Minimum conntrack flows required before exporting an IP")
	flag.Float64Var(&cpuMin, "cpu.min", 10.0, "Minimum CPU percent required before exporting")
	flag.BoolVar(&torEnable, "tor.enable", false, "Enable Tor exit-node detection")
	flag.StringVar(&torURL, "tor.url", "https://onionoo.torproject.org/details?search=flag:exit&fields=or_addresses", "Unified Tor exit-node JSON")
	flag.DurationVar(&torRefresh, "tor.refresh", time.Hour, "How often to refresh Tor exit-node list")
	flag.BoolVar(&spamEnable, "spamhaus.enable", false, "Enable Spamhaus DROP CIDR matching (IPv4 + IPv6)")
	flag.StringVar(&spamURL, "spamhaus.url", "https://www.spamhaus.org/drop/drop.txt", "Spamhaus DROP IPv4 CIDR list URL")
	flag.StringVar(&spamV6URL, "spamhaus.ipv6.url", "https://www.spamhaus.org/drop/dropv6.txt", "Spamhaus DROPv6 IPv6 CIDR list URL")
	flag.DurationVar(&spamRefresh, "spamhaus.refresh", 6*time.Hour, "Interval to refresh Spamhaus CIDR lists (IPv4 + IPv6)")
	flag.BoolVar(&emThreatsEnable, "emergingthreats.enable", false, "Enable EmergingThreats compromised IP detection")
	flag.StringVar(&emThreatsURL, "emergingthreats.url", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", "URL of EmergingThreats compromised IP list")
	flag.DurationVar(&emThreatsRefresh, "emergingthreats.refresh", 6*time.Hour, "Refresh interval for EmergingThreats compromised IP list")
	flag.BoolVar(&customListEnable, "customlist.enable", false, "Enable custom user IP list detection")
	flag.StringVar(&customListPath, "customlist.path", "", "Path to file with one IP per line (IPv4 or IPv6)")
	flag.DurationVar(&customListRefresh, "customlist.refresh", 10*time.Minute, "Refresh interval for custom user IP list")
	flag.StringVar(&logLevelFlag, "log.level", "error", "Log level: error, info, debug")
	flag.Parse()

	setLogLevel(parseLogLevel(logLevelFlag))

	// Parse thresholds from CLI strings into maps keyed by disk type.
	readThresholdMap := parseThresholds(readThresholds, defaultReadThreshold)
	writeThresholdMap := parseThresholds(writeThresholds, defaultWriteThreshold)

	// Create metrics collector.
	collector, err := NewMetricsCollector(
		libvirtURI,
		readThresholdMap,
		writeThresholdMap,
		defaultReadThreshold,
		defaultWriteThreshold,
		staticCacheExpiration,
		dynamicCacheExpiration,
		collectionInterval,
		conntrackMin,
		cpuMin,
		torEnable,
		torURL,
		torRefresh,
		spamEnable,
		spamURL,
		spamV6URL,
		spamRefresh,
		emThreatsEnable,
		emThreatsURL,
		emThreatsRefresh,
		customListEnable,
		customListPath,
		customListRefresh,
	)
	if err != nil {
		fmt.Printf("Error creating collector: %v\n", err)
		return
	}

	// Register collector with a dedicated registry.
	registry := prometheus.NewRegistry()
	registry.MustRegister(collector)

	// Expose metrics at the configured path.
	handler := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	http.Handle(metricsPath, handler)

	// Runtime log-level control endpoint
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

	fmt.Printf("Beginning to serve on %s\n", listenAddress)
	if err := http.ListenAndServe(listenAddress, nil); err != nil {
		fmt.Printf("Error starting HTTP server: %v\n", err)
	}
}
