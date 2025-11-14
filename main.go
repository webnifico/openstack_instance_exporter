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
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/vishvananda/netlink"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"libvirt.org/go/libvirt"
)

type LogLevel int

const (
	LogLevelError LogLevel = iota
	LogLevelNotice
	LogLevelInfo
	LogLevelDebug
)

var (
	currentLogLevel = LogLevelError
	logLevelMu      sync.RWMutex
)

func parseLogLevel(s string) LogLevel {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return LogLevelDebug
	case "info":
		return LogLevelInfo
	case "notice":
		return LogLevelNotice
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

func logNotice(format string, args ...interface{}) {
	if getLogLevel() >= LogLevelNotice {
		log.Printf("[NOTICE] "+format, args...)
	}
}

func logError(format string, args ...interface{}) {
	log.Printf("[ERROR] "+format, args...)
}

func logThreat(format string, args ...interface{}) {
	if getLogLevel() >= LogLevelNotice {
		log.Printf("[THREAT] "+format, args...)
	}
}

type ContactDirection int

const (
	ContactAny ContactDirection = iota
	ContactOut
	ContactIn
)

func parseContactDirection(s string) ContactDirection {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "any":
		return ContactAny
	case "in", "inbound", "dst":
		return ContactIn
	case "out", "outbound", "src":
		return ContactOut
	default:
		return ContactOut
	}
}

func (d ContactDirection) String() string {
	switch d {
	case ContactAny:
		return "any"
	case ContactIn:
		return "in"
	default:
		return "out"
	}
}

func flowDirection(ipSet map[string]struct{}, ct ConntrackEntry) string {
	_, isVMsrc := ipSet[ct.Src]
	_, isVMdst := ipSet[ct.Dst]
	if isVMsrc && !isVMdst {
		return "out"
	}
	if isVMdst && !isVMsrc {
		return "in"
	}
	return "any"
}

func UnmarshalProto(jsonData []byte, pb proto.Message) error {
	if !json.Valid(jsonData) {
		return fmt.Errorf("invalid JSON")
	}
	return protojson.Unmarshal(jsonData, pb)
}

type DomainXML struct {
	UUID     string `xml:"uuid"`
	Metadata struct {
		NovaInstance struct {
			NovaPackage struct {
				Version string `xml:"version,attr"`
			} `xml:"package"`
			NovaName     string `xml:"name"`
			CreationTime string `xml:"creationTime"`
			NovaFlavor   struct {
				FlavorName string `xml:"name,attr"`
				MemoryMB   int    `xml:"memory"`
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

type Disk struct {
	Device string `xml:"device,attr"`
	Type   string `xml:"type,attr"`
	Source struct {
		Protocol string `xml:"protocol,attr"`
		File     string `xml:"file,attr"`
		Name     string `xml:"name,attr"`
	} `xml:"source"`
	Target struct {
		Dev string `xml:"dev,attr"`
	} `xml:"target"`
}

type Interface struct {
	Target struct {
		Dev string `xml:"dev,attr"`
	} `xml:"target"`
	IPs []IP `xml:"ip"`
}

type IP struct {
	Address string `xml:"address,attr"`
	Family  string `xml:"family,attr"`
	Prefix  string `xml:"prefix,attr"`
}

type ConntrackEntry struct {
	Src     string
	Dst     string
	SrcPort uint16
	DstPort uint16
	Proto   uint8
}

type OnionooSummary struct {
	Relays []struct {
		OrAddresses []string `json:"or_addresses"`
	} `json:"relays"`
}

type CacheEntry struct {
	data        interface{}
	lastUpdated time.Time
}

type Cache struct {
	mu         sync.RWMutex
	data       map[string]CacheEntry
	expiration time.Duration
}

func NewCache(expiration time.Duration) *Cache {
	return &Cache{
		data:       make(map[string]CacheEntry),
		expiration: expiration,
	}
}

func (c *Cache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.data[key]
	if !ok || time.Since(entry.lastUpdated) > c.expiration {
		return nil, false
	}
	return entry.data, true
}

func (c *Cache) Set(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[key] = CacheEntry{
		data:        value,
		lastUpdated: time.Now(),
	}
}

func (c *Cache) Cleanup(mc *MetricsCollector) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	deleted := 0
	for key, entry := range c.data {
		if strings.HasPrefix(key, "host_") {
			continue
		}
		if now.Sub(entry.lastUpdated) > c.expiration && !mc.isInstanceActive(key) {
			delete(c.data, key)
			deleted++
		}
	}
	return deleted
}

func readConntrack() ([]ConntrackEntry, error) {
	flows4, err4 := netlink.ConntrackTableList(netlink.ConntrackTable, netlink.InetFamily(syscall.AF_INET))
	flows6, err6 := netlink.ConntrackTableList(netlink.ConntrackTable, netlink.InetFamily(syscall.AF_INET6))
	if err4 != nil && err6 != nil {
		return nil, fmt.Errorf("conntrack netlink read failed: %v %v", err4, err6)
	}
	capHint := 0
	if err4 == nil {
		capHint += len(flows4)
	}
	if err6 == nil {
		capHint += len(flows6)
	}
	if capHint < 4096 {
		capHint = 4096
	}
	entries := make([]ConntrackEntry, 0, capHint)
	if err4 == nil {
		for _, f := range flows4 {
			srcIP := f.Forward.SrcIP
			dstIP := f.Forward.DstIP
			e := ConntrackEntry{}
			if srcIP != nil {
				e.Src = srcIP.String()
			}
			if dstIP != nil {
				e.Dst = dstIP.String()
			}
			e.SrcPort = uint16(f.Forward.SrcPort)
			e.DstPort = uint16(f.Forward.DstPort)
			e.Proto = uint8(f.Forward.Protocol)
			if e.Src != "" || e.Dst != "" {
				entries = append(entries, e)
			}
		}
	}
	if err6 == nil {
		for _, f := range flows6 {
			srcIP := f.Forward.SrcIP
			dstIP := f.Forward.DstIP
			e := ConntrackEntry{}
			if srcIP != nil {
				e.Src = srcIP.String()
			}
			if dstIP != nil {
				e.Dst = dstIP.String()
			}
			e.SrcPort = uint16(f.Forward.SrcPort)
			e.DstPort = uint16(f.Forward.DstPort)
			e.Proto = uint8(f.Forward.Protocol)
			if e.Src != "" || e.Dst != "" {
				entries = append(entries, e)
			}
		}
	}
	return entries, nil
}

type cpuSample struct {
	total uint64
	ts    time.Time
}

type outboundPrev struct {
	remotes map[string]struct{}
}

type outboundPrevDstPorts struct {
	ports map[uint16]struct{}
}

type MetricsCollector struct {
	conn                              *libvirt.Connect
	readThreshold                     map[string]int
	writeThreshold                    map[string]int
	defaultReadThreshold              int
	defaultWriteThreshold             int
	diskReadThresholds                *prometheus.Desc
	diskWriteThresholds               *prometheus.Desc
	diskReadBytes                     *prometheus.Desc
	diskWriteBytes                    *prometheus.Desc
	diskReadRequests                  *prometheus.Desc
	diskWriteRequests                 *prometheus.Desc
	cpuUsage                          *prometheus.Desc
	networkRxBytes                    *prometheus.Desc
	networkTxBytes                    *prometheus.Desc
	networkRxPackets                  *prometheus.Desc
	networkTxPackets                  *prometheus.Desc
	networkRxErrors                   *prometheus.Desc
	networkTxErrors                   *prometheus.Desc
	networkRxDropped                  *prometheus.Desc
	networkTxDropped                  *prometheus.Desc
	ctPerIPFlows                      *prometheus.Desc
	outboundBehaviorEnabled           bool
	outboundUniqueDesc                *prometheus.Desc
	outboundNewRemotesDesc            *prometheus.Desc
	outboundFlowsDesc                 *prometheus.Desc
	outboundMaxFlowsSingleRemoteDesc  *prometheus.Desc
	outboundUniqueDstPortsDesc        *prometheus.Desc
	outboundNewDstPortsDesc           *prometheus.Desc
	outboundMaxFlowsSingleDstPortDesc *prometheus.Desc
	outboundMu                        sync.Mutex
	outboundPrev                      map[string]outboundPrev
	outboundPrevDstPorts              map[string]outboundPrevDstPorts
	staticCache                       *Cache
	dynamicCache                      *Cache
	collectionInterval                time.Duration
	cpuMu                             sync.Mutex
	cpuSamples                        map[string]cpuSample
	cpuLastExport                     map[string]float64
	cpuMin                            float64
	conntrackMin                      int

	torExitEnabled                bool
	torExitURL                    string
	torExitRefresh                time.Duration
	torExitSet                    map[string]struct{}
	torExitMu                     sync.RWMutex
	torExitDir                    ContactDirection
	torExitContactDesc            *prometheus.Desc
	torExitActiveDesc             *prometheus.Desc
	torExitRefreshLastSuccessDesc *prometheus.Desc
	torExitRefreshDurationDesc    *prometheus.Desc
	torExitRefreshErrorsDesc      *prometheus.Desc
	torExitEntriesDesc            *prometheus.Desc
	torExitLastSuccessUnix        float64
	torExitLastRefreshSeconds     float64
	torExitEntries                int
	torExitRefreshErrors          uint64

	torRelayEnabled                bool
	torRelayURL                    string
	torRelayRefresh                time.Duration
	torRelaySet                    map[string]struct{}
	torRelayMu                     sync.RWMutex
	torRelayDir                    ContactDirection
	torRelayContactDesc            *prometheus.Desc
	torRelayActiveDesc             *prometheus.Desc
	torRelayRefreshLastSuccessDesc *prometheus.Desc
	torRelayRefreshDurationDesc    *prometheus.Desc
	torRelayRefreshErrorsDesc      *prometheus.Desc
	torRelayEntriesDesc            *prometheus.Desc
	torRelayLastSuccessUnix        float64
	torRelayLastRefreshSeconds     float64
	torRelayEntries                int
	torRelayRefreshErrors          uint64

	spamEnabled                bool
	spamURL                    string
	spamV6URL                  string
	spamRefresh                time.Duration
	spamNets                   []*net.IPNet
	spamBucketsV4              map[string][]*net.IPNet
	spamBucketsV6              map[string][]*net.IPNet
	spamMu                     sync.RWMutex
	spamDir                    ContactDirection
	spamContactDesc            *prometheus.Desc
	spamActiveDesc             *prometheus.Desc
	spamRefreshLastSuccessDesc *prometheus.Desc
	spamRefreshDurationDesc    *prometheus.Desc
	spamRefreshErrorsDesc      *prometheus.Desc
	spamEntriesDesc            *prometheus.Desc
	spamLastSuccessUnix        float64
	spamLastRefreshSeconds     float64
	spamEntries                int
	spamRefreshErrors          uint64

	emThreatsEnabled                bool
	emThreatsURL                    string
	emThreatsRefresh                time.Duration
	emThreatsSet                    map[string]struct{}
	emThreatsMu                     sync.RWMutex
	emThreatsDir                    ContactDirection
	emThreatsContactDesc            *prometheus.Desc
	emThreatsActiveDesc             *prometheus.Desc
	emThreatsRefreshLastSuccessDesc *prometheus.Desc
	emThreatsRefreshDurationDesc    *prometheus.Desc
	emThreatsRefreshErrorsDesc      *prometheus.Desc
	emThreatsEntriesDesc            *prometheus.Desc
	emThreatsLastSuccessUnix        float64
	emThreatsLastRefreshSeconds     float64
	emThreatsEntries                int
	emThreatsRefreshErrors          uint64

	customListEnabled                bool
	customListPath                   string
	customListRefresh                time.Duration
	customListSet                    map[string]struct{}
	customListMu                     sync.RWMutex
	customListDir                    ContactDirection
	customListContactDesc            *prometheus.Desc
	customListActiveDesc             *prometheus.Desc
	customListRefreshLastSuccessDesc *prometheus.Desc
	customListRefreshDurationDesc    *prometheus.Desc
	customListRefreshErrorsDesc      *prometheus.Desc
	customListEntriesDesc            *prometheus.Desc
	customListLastSuccessUnix        float64
	customListLastRefreshSeconds     float64
	customListEntries                int
	customListRefreshErrors          uint64

	threatCountMu     sync.Mutex
	torExitCount      map[string]float64
	torRelayCount     map[string]float64
	spamCount         map[string]float64
	emThreatsCount    map[string]float64
	customListCount   map[string]float64
	threatFileEnabled bool
	threatFilePath    string
	threatFile        *os.File
	threatFileMu      sync.Mutex

	hostThreatsEnabled   bool
	hostIPsAllowPrivate  bool
	hostInterfaces       map[string]struct{}
	hostThreatListedDesc *prometheus.Desc
	httpClient           *http.Client

	hostActiveDomainsDesc         *prometheus.Desc
	hostActiveVcpusDesc           *prometheus.Desc
	hostActiveMemGBDesc           *prometheus.Desc
	hostCollectionErrorsDesc      *prometheus.Desc
	hostCollectionDurationDesc    *prometheus.Desc
	hostCollectionLagDesc         *prometheus.Desc
	hostLibvirtListDurationDesc   *prometheus.Desc
	hostConntrackReadDurationDesc *prometheus.Desc
	hostConntrackEntriesDesc      *prometheus.Desc
	hostDynamicCacheSeriesDesc    *prometheus.Desc
	hostGoHeapAllocDesc           *prometheus.Desc

	conntrackReadErrorsDesc     *prometheus.Desc
	hostConntrackReadErrorsDesc *prometheus.Desc
	conntrackReadErrors         uint64

	staticCacheEntriesDesc   *prometheus.Desc
	dynamicCacheEntriesDesc  *prometheus.Desc
	cacheCleanupDurationDesc *prometheus.Desc
	cacheEvictionsDesc       *prometheus.Desc
	cacheEvictions           uint64
	cacheCleanupMu           sync.Mutex
	cacheCleanupSeconds      float64

	hostCollectionErrors uint64
	lastCycleEndUnixNano int64

	instanceInfoDesc *prometheus.Desc
	diskInfoDesc     *prometheus.Desc
}

func (mc *MetricsCollector) addThreatCount(m map[string]float64, uuid string, delta float64) float64 {
	mc.threatCountMu.Lock()
	defer mc.threatCountMu.Unlock()
	prev := m[uuid]
	if delta > 0 {
		m[uuid] = prev + delta
	}
	return m[uuid]
}

func (mc *MetricsCollector) cleanupThreatCounts() {
	mc.threatCountMu.Lock()
	for uuid := range mc.torExitCount {
		if !mc.isInstanceActive(uuid) {
			delete(mc.torExitCount, uuid)
		}
	}
	for uuid := range mc.torRelayCount {
		if !mc.isInstanceActive(uuid) {
			delete(mc.torRelayCount, uuid)
		}
	}
	for uuid := range mc.spamCount {
		if !mc.isInstanceActive(uuid) {
			delete(mc.spamCount, uuid)
		}
	}
	for uuid := range mc.emThreatsCount {
		if !mc.isInstanceActive(uuid) {
			delete(mc.emThreatsCount, uuid)
		}
	}
	for uuid := range mc.customListCount {
		if !mc.isInstanceActive(uuid) {
			delete(mc.customListCount, uuid)
		}
	}
	mc.threatCountMu.Unlock()
}

func (mc *MetricsCollector) logThreatToFile(tag string, domain string, instanceUUID string, projectUUID string, userUUID string, ct ConntrackEntry, dirStr string, listDir ContactDirection) {
	if !mc.threatFileEnabled || mc.threatFile == nil || mc.threatFilePath == "" {
		return
	}
	if listDir != ContactAny && listDir.String() != dirStr {
		return
	}
	mc.threatFileMu.Lock()
	defer mc.threatFileMu.Unlock()
	fmt.Fprintf(mc.threatFile, "%s tag=%s domain=%s uuid=%s project=%s user=%s src=%s dst=%s direction=%s\n", time.Now().Format(time.RFC3339Nano), tag, domain, instanceUUID, projectUUID, userUUID, ct.Src, ct.Dst, dirStr)
}

func (mc *MetricsCollector) logThreatEventToFile(tag string, domain string, instanceUUID string, projectUUID string, userUUID string, detail string) {
	if !mc.threatFileEnabled || mc.threatFile == nil || mc.threatFilePath == "" {
		return
	}
	mc.threatFileMu.Lock()
	defer mc.threatFileMu.Unlock()
	fmt.Fprintf(mc.threatFile, "%s tag=%s domain=%s uuid=%s project=%s user=%s %s\n", time.Now().Format(time.RFC3339Nano), tag, domain, instanceUUID, projectUUID, userUUID, detail)
}

func isPrivateOrLocal(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		switch {
		case ip4[0] == 10:
			return true
		case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
			return true
		case ip4[0] == 192 && ip4[1] == 168:
			return true
		case ip4[0] == 169 && ip4[1] == 254:
			return true
		case ip4[0] == 127:
			return true
		}
		return false
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return true
	}
	if ip16[0]&0xfe == 0xfc {
		return true
	}
	return false
}

func (mc *MetricsCollector) getHostIPs() []IP {
	if !mc.hostThreatsEnabled {
		return nil
	}
	out := make([]IP, 0, 16)
	seen := make(map[string]struct{})
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, iface := range ifaces {
		if len(mc.hostInterfaces) > 0 {
			if _, ok := mc.hostInterfaces[iface.Name]; !ok {
				continue
			}
		}
		if (iface.Flags & net.FlagUp) == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				ip = ip4
			}
			if !mc.hostIPsAllowPrivate && isPrivateOrLocal(ip) {
				continue
			}
			s := ip.String()
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			family := "ipv6"
			if ip.To4() != nil {
				family = "ipv4"
			}
			out = append(out, IP{Address: s, Family: family})
		}
	}
	return out
}

func (mc *MetricsCollector) updateHostThreatsFromIPSet(listName string, ipSet map[string]struct{}) {
	if !mc.hostThreatsEnabled {
		mc.staticCache.Set("host_"+listName, []prometheus.Metric{})
		return
	}
	hostIPs := mc.getHostIPs()
	metrics := make([]prometheus.Metric, 0, len(hostIPs))
	for _, hip := range hostIPs {
		if _, ok := ipSet[hip.Address]; ok {
			metrics = append(metrics, prometheus.MustNewConstMetric(mc.hostThreatListedDesc, prometheus.GaugeValue, 1.0, listName, hip.Address, hip.Family))
			logNotice("METRIC host_threat list=%s ip=%s family=%s", listName, hip.Address, hip.Family)
			mc.logThreatEventToFile("HOST_THREAT", "", "", "", "", fmt.Sprintf("list=%s ip=%s family=%s", listName, hip.Address, hip.Family))
		}
	}
	mc.staticCache.Set("host_"+listName, metrics)
}

func (mc *MetricsCollector) updateHostThreatsFromCIDRs(listName string, nets []*net.IPNet) {
	if !mc.hostThreatsEnabled {
		mc.staticCache.Set("host_"+listName, []prometheus.Metric{})
		return
	}
	hostIPs := mc.getHostIPs()
	metrics := make([]prometheus.Metric, 0, len(hostIPs))
	for _, hip := range hostIPs {
		ip := net.ParseIP(hip.Address)
		if ip == nil {
			continue
		}
		listed := false
		for _, n := range nets {
			if n.Contains(ip) {
				listed = true
				break
			}
		}
		if listed {
			metrics = append(metrics, prometheus.MustNewConstMetric(mc.hostThreatListedDesc, prometheus.GaugeValue, 1.0, listName, hip.Address, hip.Family))
			logNotice("METRIC host_threat list=%s ip=%s family=%s", listName, hip.Address, hip.Family)
			mc.logThreatEventToFile("HOST_THREAT", "", "", "", "", fmt.Sprintf("list=%s ip=%s family=%s", listName, hip.Address, hip.Family))
		}
	}
	mc.staticCache.Set("host_"+listName, metrics)
}

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
	torExitEnable bool,
	torExitURL string,
	torExitRefresh time.Duration,
	torExitDir ContactDirection,
	torRelayEnable bool,
	torRelayURL string,
	torRelayRefresh time.Duration,
	torRelayDir ContactDirection,
	spamEnable bool,
	spamURL string,
	spamV6URL string,
	spamRefresh time.Duration,
	spamDir ContactDirection,
	emThreatsEnable bool,
	emThreatsURL string,
	emThreatsRefresh time.Duration,
	emThreatsDir ContactDirection,
	customListEnable bool,
	customListPath string,
	customListRefresh time.Duration,
	customListDir ContactDirection,
	threatFileEnable bool,
	threatFilePath string,
	outboundBehaviorEnable bool,
	hostThreatsEnable bool,
	hostIPsAllowPrivate bool,
	hostInterfaces map[string]struct{},
) (*MetricsCollector, error) {
	conn, err := libvirt.NewConnect(uri)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to libvirt: %v", err)
	}

	mc := &MetricsCollector{
		conn:                    conn,
		readThreshold:           readThresholds,
		writeThreshold:          writeThresholds,
		conntrackMin:            conntrackMin,
		cpuMin:                  cpuMin,
		defaultReadThreshold:    defaultReadThreshold,
		defaultWriteThreshold:   defaultWriteThreshold,
		diskReadThresholds:      prometheus.NewDesc("oie_disk_r_alert_threshold", "Disk read alert threshold", []string{"domain", "instance_uuid", "user_uuid", "project_uuid", "disk_uuid", "disk_type", "disk_path"}, nil),
		hostThreatsEnabled:      hostThreatsEnable,
		hostIPsAllowPrivate:     hostIPsAllowPrivate,
		hostInterfaces:          hostInterfaces,
		outboundBehaviorEnabled: outboundBehaviorEnable,
		outboundPrev:            make(map[string]outboundPrev),
		outboundPrevDstPorts:    make(map[string]outboundPrevDstPorts),
		httpClient:              &http.Client{Timeout: 15 * time.Second},

		instanceInfoDesc: prometheus.NewDesc(
			"oie_instance_info",
			"Static instance metadata (one series per active instance)",
			[]string{
				"domain",
				"instance_uuid",
				"project_uuid",
				"project_name",
				"user_uuid",
				"user_name",
				"flavor",
				"vcpus",
				"mem_mb",
				"root_type",
				"created_at",
				"metadata_version",
			},
			nil,
		),
		diskInfoDesc: prometheus.NewDesc(
			"oie_disk_info",
			"Static disk metadata (one series per disk per active instance)",
			[]string{
				"domain",
				"instance_uuid",
				"project_uuid",
				"user_uuid",
				"disk_uuid",
				"disk_type",
				"disk_path",
			},
			nil,
		),
	}

	mc.diskWriteThresholds = prometheus.NewDesc("oie_disk_w_alert_threshold", "Disk write alert threshold", []string{"domain", "instance_uuid", "user_uuid", "project_uuid", "disk_uuid", "disk_type", "disk_path"}, nil)
	mc.diskReadBytes = prometheus.NewDesc("oie_disk_r_gbytes", "Disk read gigabytes", []string{"domain", "instance_uuid", "user_uuid", "project_uuid", "disk_uuid", "disk_type", "disk_path"}, nil)
	mc.diskWriteBytes = prometheus.NewDesc("oie_disk_w_gbytes", "Disk write gigabytes", []string{"domain", "instance_uuid", "user_uuid", "project_uuid", "disk_uuid", "disk_type", "disk_path"}, nil)
	mc.diskReadRequests = prometheus.NewDesc("oie_disk_r_requests", "Disk read requests", []string{"domain", "instance_uuid", "user_uuid", "project_uuid", "disk_uuid", "disk_type", "disk_path"}, nil)
	mc.diskWriteRequests = prometheus.NewDesc("oie_disk_w_requests", "Disk write requests", []string{"domain", "instance_uuid", "user_uuid", "project_uuid", "disk_uuid", "disk_type", "disk_path"}, nil)
	mc.cpuUsage = prometheus.NewDesc("oie_cpu_percent", "CPU usage percentage", []string{"domain", "instance_uuid", "user_uuid", "project_uuid"}, nil)
	mc.networkRxBytes = prometheus.NewDesc("oie_net_rx_gbytes", "Network receive gigabytes", []string{"domain", "interface", "instance_uuid", "user_uuid", "project_uuid"}, nil)
	mc.networkTxBytes = prometheus.NewDesc("oie_net_tx_gbytes", "Network transmit gigabytes", []string{"domain", "interface", "instance_uuid", "user_uuid", "project_uuid"}, nil)
	mc.networkRxPackets = prometheus.NewDesc("oie_net_rx_pkt_total", "Network receive packets", []string{"domain", "interface", "instance_uuid", "user_uuid", "project_uuid"}, nil)
	mc.networkTxPackets = prometheus.NewDesc("oie_net_tx_pkt_total", "Network transmit packets", []string{"domain", "interface", "instance_uuid", "user_uuid", "project_uuid"}, nil)
	mc.networkRxErrors = prometheus.NewDesc("oie_net_rx_er_total", "Network receive errors", []string{"domain", "interface", "instance_uuid", "user_uuid", "project_uuid"}, nil)
	mc.networkTxErrors = prometheus.NewDesc("oie_net_tx_er_total", "Network transmit errors", []string{"domain", "interface", "instance_uuid", "user_uuid", "project_uuid"}, nil)
	mc.networkRxDropped = prometheus.NewDesc("oie_net_rx_drp_total", "Network receive dropped packets", []string{"domain", "interface", "instance_uuid", "user_uuid", "project_uuid"}, nil)
	mc.networkTxDropped = prometheus.NewDesc("oie_net_tx_drp_total", "Network transmit dropped packets", []string{"domain", "interface", "instance_uuid", "user_uuid", "project_uuid"}, nil)
	mc.ctPerIPFlows = prometheus.NewDesc("oie_conntrack_ip_flows_total", "Conntrack flow entries matched to this fixed IP", []string{"domain", "instance_uuid", "ip", "family", "project_uuid", "user_uuid"}, nil)
	mc.outboundUniqueDesc = prometheus.NewDesc("oie_outbound_unique_remotes", "Outbound unique remote IPs for this fixed IP in the current interval", []string{"domain", "instance_uuid", "ip", "family", "project_uuid", "user_uuid"}, nil)
	mc.outboundNewRemotesDesc = prometheus.NewDesc("oie_outbound_new_remotes", "Outbound new remote IPs discovered since previous interval", []string{"domain", "instance_uuid", "ip", "family", "project_uuid", "user_uuid"}, nil)
	mc.outboundFlowsDesc = prometheus.NewDesc("oie_outbound_flows", "Outbound conntrack flows initiated by this fixed IP in the current interval", []string{"domain", "instance_uuid", "ip", "family", "project_uuid", "user_uuid"}, nil)
	mc.outboundMaxFlowsSingleRemoteDesc = prometheus.NewDesc("oie_outbound_max_flows_single_remote", "Maximum outbound flows to a single remote IP in the current interval", []string{"domain", "instance_uuid", "ip", "family", "project_uuid", "user_uuid"}, nil)
	mc.outboundUniqueDstPortsDesc = prometheus.NewDesc("oie_outbound_unique_dst_ports", "Outbound unique destination ports in the current interval", []string{"domain", "instance_uuid", "ip", "family", "project_uuid", "user_uuid"}, nil)
	mc.outboundNewDstPortsDesc = prometheus.NewDesc("oie_outbound_new_dst_ports", "Outbound new destination ports discovered since previous interval", []string{"domain", "instance_uuid", "ip", "family", "project_uuid", "user_uuid"}, nil)
	mc.outboundMaxFlowsSingleDstPortDesc = prometheus.NewDesc("oie_outbound_max_flows_single_dst_port", "Maximum outbound flows to a single destination port in the current interval", []string{"domain", "instance_uuid", "ip", "family", "project_uuid", "user_uuid"}, nil)

	mc.staticCache = NewCache(staticCacheExpiration)
	mc.dynamicCache = NewCache(dynamicCacheExpiration)
	mc.collectionInterval = collectionInterval
	mc.cpuSamples = make(map[string]cpuSample)
	mc.cpuLastExport = make(map[string]float64)

	mc.torExitEnabled = torExitEnable
	mc.torExitURL = torExitURL
	mc.torExitRefresh = torExitRefresh
	mc.torExitSet = make(map[string]struct{})
	mc.torExitDir = torExitDir
	mc.torExitContactDesc = prometheus.NewDesc("oie_tor_exit_contact", "Total Tor exit-node contacts for this instance (presence over intervals)", []string{"domain", "instance_uuid", "project_uuid", "user_uuid", "direction"}, nil)
	mc.torExitActiveDesc = prometheus.NewDesc("oie_tor_exit_contact_active", "Active Tor exit-node flows for this instance", []string{"domain", "instance_uuid", "project_uuid", "user_uuid", "direction"}, nil)
	mc.torExitRefreshLastSuccessDesc = prometheus.NewDesc("oie_tor_exit_refresh_last_success_timestamp_seconds", "Last successful Tor exit-node list refresh (unix timestamp)", nil, nil)
	mc.torExitRefreshDurationDesc = prometheus.NewDesc("oie_tor_exit_refresh_duration_seconds", "Duration of last Tor exit-node list refresh in seconds", nil, nil)
	mc.torExitRefreshErrorsDesc = prometheus.NewDesc("oie_tor_exit_refresh_errors_total", "Total Tor exit-node list refresh errors", nil, nil)
	mc.torExitEntriesDesc = prometheus.NewDesc("oie_tor_exit_entries", "Number of Tor exit-node IPs currently loaded", nil, nil)

	mc.torRelayEnabled = torRelayEnable
	mc.torRelayURL = torRelayURL
	mc.torRelayRefresh = torRelayRefresh
	mc.torRelaySet = make(map[string]struct{})
	mc.torRelayDir = torRelayDir
	mc.torRelayContactDesc = prometheus.NewDesc("oie_tor_relay_contact", "Total Tor relay-node contacts for this instance (presence over intervals)", []string{"domain", "instance_uuid", "project_uuid", "user_uuid", "direction"}, nil)
	mc.torRelayActiveDesc = prometheus.NewDesc("oie_tor_relay_contact_active", "Active Tor relay-node flows for this instance", []string{"domain", "instance_uuid", "project_uuid", "user_uuid", "direction"}, nil)
	mc.torRelayRefreshLastSuccessDesc = prometheus.NewDesc("oie_tor_relay_refresh_last_success_timestamp_seconds", "Last successful Tor relay list refresh (unix timestamp)", nil, nil)
	mc.torRelayRefreshDurationDesc = prometheus.NewDesc("oie_tor_relay_refresh_duration_seconds", "Duration of last Tor relay list refresh in seconds", nil, nil)
	mc.torRelayRefreshErrorsDesc = prometheus.NewDesc("oie_tor_relay_refresh_errors_total", "Total Tor relay list refresh errors", nil, nil)
	mc.torRelayEntriesDesc = prometheus.NewDesc("oie_tor_relay_entries", "Number of Tor relay IPs currently loaded", nil, nil)

	mc.spamEnabled = spamEnable
	mc.spamURL = spamURL
	mc.spamV6URL = spamV6URL
	mc.spamRefresh = spamRefresh
	mc.spamNets = make([]*net.IPNet, 0)
	mc.spamBucketsV4 = make(map[string][]*net.IPNet)
	mc.spamBucketsV6 = make(map[string][]*net.IPNet)
	mc.spamDir = spamDir
	mc.spamContactDesc = prometheus.NewDesc("oie_spamhaus_contact", "Total Spamhaus DROP contacts for this instance (presence over intervals)", []string{"domain", "instance_uuid", "project_uuid", "user_uuid", "direction"}, nil)
	mc.spamActiveDesc = prometheus.NewDesc("oie_spamhaus_contact_active", "Active Spamhaus DROP flows for this instance", []string{"domain", "instance_uuid", "project_uuid", "user_uuid", "direction"}, nil)
	mc.spamRefreshLastSuccessDesc = prometheus.NewDesc("oie_spamhaus_refresh_last_success_timestamp_seconds", "Last successful Spamhaus list refresh (unix timestamp)", nil, nil)
	mc.spamRefreshDurationDesc = prometheus.NewDesc("oie_spamhaus_refresh_duration_seconds", "Duration of last Spamhaus list refresh in seconds", nil, nil)
	mc.spamRefreshErrorsDesc = prometheus.NewDesc("oie_spamhaus_refresh_errors_total", "Total Spamhaus list refresh errors", nil, nil)
	mc.spamEntriesDesc = prometheus.NewDesc("oie_spamhaus_entries", "Number of Spamhaus CIDRs currently loaded", nil, nil)

	mc.emThreatsEnabled = emThreatsEnable
	mc.emThreatsURL = emThreatsURL
	mc.emThreatsRefresh = emThreatsRefresh
	mc.emThreatsSet = make(map[string]struct{})
	mc.emThreatsDir = emThreatsDir
	mc.emThreatsContactDesc = prometheus.NewDesc("oie_emergingthreats_contact", "Total EmergingThreats contacts for this instance (presence over intervals)", []string{"domain", "instance_uuid", "project_uuid", "user_uuid", "direction"}, nil)
	mc.emThreatsActiveDesc = prometheus.NewDesc("oie_emergingthreats_contact_active", "Active EmergingThreats flows for this instance", []string{"domain", "instance_uuid", "project_uuid", "user_uuid", "direction"}, nil)
	mc.emThreatsRefreshLastSuccessDesc = prometheus.NewDesc("oie_emergingthreats_refresh_last_success_timestamp_seconds", "Last successful EmergingThreats list refresh (unix timestamp)", nil, nil)
	mc.emThreatsRefreshDurationDesc = prometheus.NewDesc("oie_emergingthreats_refresh_duration_seconds", "Duration of last EmergingThreats list refresh in seconds", nil, nil)
	mc.emThreatsRefreshErrorsDesc = prometheus.NewDesc("oie_emergingthreats_refresh_errors_total", "Total EmergingThreats list refresh errors", nil, nil)
	mc.emThreatsEntriesDesc = prometheus.NewDesc("oie_emergingthreats_entries", "Number of EmergingThreats IPs currently loaded", nil, nil)

	mc.customListEnabled = customListEnable
	mc.customListPath = customListPath
	mc.customListRefresh = customListRefresh
	mc.customListSet = make(map[string]struct{})
	mc.customListDir = customListDir
	mc.customListContactDesc = prometheus.NewDesc("oie_customlist_contact", "Total custom list contacts for this instance (presence over intervals)", []string{"domain", "instance_uuid", "project_uuid", "user_uuid", "direction"}, nil)
	mc.customListActiveDesc = prometheus.NewDesc("oie_customlist_contact_active", "Active custom list flows for this instance", []string{"domain", "instance_uuid", "project_uuid", "user_uuid", "direction"}, nil)
	mc.customListRefreshLastSuccessDesc = prometheus.NewDesc("oie_customlist_refresh_last_success_timestamp_seconds", "Last successful custom list refresh (unix timestamp)", nil, nil)
	mc.customListRefreshDurationDesc = prometheus.NewDesc("oie_customlist_refresh_duration_seconds", "Duration of last custom list refresh in seconds", nil, nil)
	mc.customListRefreshErrorsDesc = prometheus.NewDesc("oie_customlist_refresh_errors_total", "Total custom list refresh errors", nil, nil)
	mc.customListEntriesDesc = prometheus.NewDesc("oie_customlist_entries", "Number of custom list IPs currently loaded", nil, nil)

	mc.torExitCount = make(map[string]float64)
	mc.torRelayCount = make(map[string]float64)
	mc.spamCount = make(map[string]float64)
	mc.emThreatsCount = make(map[string]float64)
	mc.customListCount = make(map[string]float64)

	mc.threatFileEnabled = threatFileEnable
	mc.threatFilePath = threatFilePath

	mc.hostThreatListedDesc = prometheus.NewDesc("oie_host_threat_listed", "Host IP is listed in threat list", []string{"list", "ip", "family"}, nil)
	mc.hostActiveDomainsDesc = prometheus.NewDesc("oie_host_active_vms", "Active libvirt domains on this hypervisor", nil, nil)
	mc.hostActiveVcpusDesc = prometheus.NewDesc("oie_host_active_vcpus", "Sum of vCPUs allocated to active domains on this hypervisor", nil, nil)
	mc.hostActiveMemGBDesc = prometheus.NewDesc("oie_host_active_mem_gbytes", "Sum of max memory allocated to active domains on this hypervisor (GB)", nil, nil)
	mc.hostCollectionErrorsDesc = prometheus.NewDesc("oie_host_collection_errors_total", "Total background collection errors on this host", nil, nil)
	mc.hostCollectionDurationDesc = prometheus.NewDesc("oie_host_collection_duration_seconds", "Duration of last background collection cycle on this host (seconds)", nil, nil)
	mc.hostCollectionLagDesc = prometheus.NewDesc("oie_host_collection_lag_seconds", "Seconds since prior background collection cycle ended on this host", nil, nil)
	mc.hostLibvirtListDurationDesc = prometheus.NewDesc("oie_host_libvirt_list_duration_seconds", "Seconds spent listing active libvirt domains on this host", nil, nil)
	mc.hostConntrackReadDurationDesc = prometheus.NewDesc("oie_host_conntrack_read_duration_seconds", "Seconds spent reading conntrack tables on this host", nil, nil)
	mc.hostConntrackEntriesDesc = prometheus.NewDesc("oie_host_conntrack_entries_total", "Conntrack entries observed in last snapshot on this host", nil, nil)
	mc.hostDynamicCacheSeriesDesc = prometheus.NewDesc("oie_host_dynamic_cache_series_total", "Number of instance series currently cached on this host", nil, nil)
	mc.hostGoHeapAllocDesc = prometheus.NewDesc("oie_host_go_heap_alloc_bytes", "Current Go heap allocation in bytes on this host", nil, nil)

	mc.conntrackReadErrorsDesc = prometheus.NewDesc("oie_conntrack_read_errors_total", "Conntrack read errors on this host", nil, nil)
	mc.hostConntrackReadErrorsDesc = prometheus.NewDesc("oie_host_conntrack_read_errors_total", "Conntrack read errors on this host", nil, nil)

	mc.staticCacheEntriesDesc = prometheus.NewDesc("oie_static_cache_entries", "Number of static cache entries", nil, nil)
	mc.dynamicCacheEntriesDesc = prometheus.NewDesc("oie_dynamic_cache_entries", "Number of dynamic cache entries", nil, nil)
	mc.cacheCleanupDurationDesc = prometheus.NewDesc("oie_cache_cleanup_duration_seconds", "Duration of last cache cleanup cycle on this host (seconds)", nil, nil)
	mc.cacheEvictionsDesc = prometheus.NewDesc("oie_cache_evictions_total", "Total cache entries evicted on this host", nil, nil)

	if mc.threatFileEnabled && mc.threatFilePath != "" {
		f, err := os.OpenFile(mc.threatFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			logError("THREATFILE: failed to open %s: %v", mc.threatFilePath, err)
		} else {
			mc.threatFile = f
			logInfo("THREATFILE: enabled path=%s", mc.threatFilePath)
		}
	}
	if mc.torExitEnabled {
		go mc.startTorExitRefresher()
	}
	if mc.torRelayEnabled {
		go mc.startTorRelayRefresher()
	}
	if mc.spamEnabled {
		go mc.startSpamhausRefresher()
	}
	if mc.emThreatsEnabled {
		go mc.startEmThreatsRefresher()
	}
	if mc.customListEnabled && mc.customListPath != "" {
		go mc.startCustomListRefresher()
	}
	go mc.startBackgroundCollection()
	go mc.startCacheCleanup()
	return mc, nil
}

func (mc *MetricsCollector) startCacheCleanup() {
	for {
		time.Sleep(time.Minute)

		cleanupStart := time.Now()
		staticEv := mc.staticCache.Cleanup(mc)
		dynamicEv := mc.dynamicCache.Cleanup(mc)
		ev := staticEv + dynamicEv
		if ev > 0 {
			atomic.AddUint64(&mc.cacheEvictions, uint64(ev))
		}
		cleanupSeconds := time.Since(cleanupStart).Seconds()
		mc.cacheCleanupMu.Lock()
		mc.cacheCleanupSeconds = cleanupSeconds
		mc.cacheCleanupMu.Unlock()

		mc.cleanupThreatCounts()
		mc.cpuMu.Lock()
		for uuid := range mc.cpuSamples {
			if !mc.isInstanceActive(uuid) {
				delete(mc.cpuSamples, uuid)
				delete(mc.cpuLastExport, uuid)
			}
		}
		mc.cpuMu.Unlock()
		mc.outboundMu.Lock()
		for k := range mc.outboundPrev {
			parts := strings.SplitN(k, "|", 2)
			if len(parts) > 0 && !mc.isInstanceActive(parts[0]) {
				delete(mc.outboundPrev, k)
			}
		}
		for k := range mc.outboundPrevDstPorts {
			parts := strings.SplitN(k, "|", 2)
			if len(parts) > 0 && !mc.isInstanceActive(parts[0]) {
				delete(mc.outboundPrevDstPorts, k)
			}
		}
		mc.outboundMu.Unlock()
		logDebug("Performed cache cleanup")
	}
}

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
	ch <- mc.ctPerIPFlows
	ch <- mc.outboundUniqueDesc
	ch <- mc.outboundNewRemotesDesc
	ch <- mc.outboundFlowsDesc
	ch <- mc.outboundMaxFlowsSingleRemoteDesc
	ch <- mc.outboundUniqueDstPortsDesc
	ch <- mc.outboundNewDstPortsDesc
	ch <- mc.outboundMaxFlowsSingleDstPortDesc
	ch <- mc.torExitContactDesc
	ch <- mc.torExitActiveDesc
	ch <- mc.torRelayContactDesc
	ch <- mc.torRelayActiveDesc
	ch <- mc.spamContactDesc
	ch <- mc.spamActiveDesc
	ch <- mc.emThreatsContactDesc
	ch <- mc.emThreatsActiveDesc
	ch <- mc.customListContactDesc
	ch <- mc.customListActiveDesc
	ch <- mc.hostThreatListedDesc
	ch <- mc.hostActiveDomainsDesc
	ch <- mc.hostActiveVcpusDesc
	ch <- mc.hostActiveMemGBDesc
	ch <- mc.hostCollectionErrorsDesc
	ch <- mc.hostCollectionDurationDesc
	ch <- mc.hostCollectionLagDesc
	ch <- mc.hostLibvirtListDurationDesc
	ch <- mc.hostConntrackReadDurationDesc
	ch <- mc.hostConntrackEntriesDesc
	ch <- mc.hostDynamicCacheSeriesDesc
	ch <- mc.hostGoHeapAllocDesc

	ch <- mc.conntrackReadErrorsDesc
	ch <- mc.hostConntrackReadErrorsDesc
	ch <- mc.staticCacheEntriesDesc
	ch <- mc.dynamicCacheEntriesDesc
	ch <- mc.cacheCleanupDurationDesc
	ch <- mc.cacheEvictionsDesc

	ch <- mc.torExitRefreshLastSuccessDesc
	ch <- mc.torExitRefreshDurationDesc
	ch <- mc.torExitRefreshErrorsDesc
	ch <- mc.torExitEntriesDesc

	ch <- mc.torRelayRefreshLastSuccessDesc
	ch <- mc.torRelayRefreshDurationDesc
	ch <- mc.torRelayRefreshErrorsDesc
	ch <- mc.torRelayEntriesDesc

	ch <- mc.spamRefreshLastSuccessDesc
	ch <- mc.spamRefreshDurationDesc
	ch <- mc.spamRefreshErrorsDesc
	ch <- mc.spamEntriesDesc

	ch <- mc.emThreatsRefreshLastSuccessDesc
	ch <- mc.emThreatsRefreshDurationDesc
	ch <- mc.emThreatsRefreshErrorsDesc
	ch <- mc.emThreatsEntriesDesc

	ch <- mc.customListRefreshLastSuccessDesc
	ch <- mc.customListRefreshDurationDesc
	ch <- mc.customListRefreshErrorsDesc
	ch <- mc.customListEntriesDesc

	ch <- mc.instanceInfoDesc
	ch <- mc.diskInfoDesc
}

func (mc *MetricsCollector) Collect(ch chan<- prometheus.Metric) {
	logDebug("Serving metrics from cache")
	for _, metric := range mc.collectCachedMetrics() {
		ch <- metric
	}
}

func (mc *MetricsCollector) startTorExitRefresher() {
	for {
		mc.refreshTorExitListUnified()
		time.Sleep(mc.torExitRefresh)
	}
}

func (mc *MetricsCollector) refreshTorExitListUnified() {
	start := time.Now()
	resp, err := mc.httpClient.Get(mc.torExitURL)
	if err != nil {
		atomic.AddUint64(&mc.torExitRefreshErrors, 1)
		logError("TOREXIT: failed to download list: %v", err)
		return
	}
	defer resp.Body.Close()
	var data OnionooSummary
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&data); err != nil {
		atomic.AddUint64(&mc.torExitRefreshErrors, 1)
		logError("TOREXIT: JSON decode error: %v", err)
		return
	}
	fresh := make(map[string]struct{})
	for _, r := range data.Relays {
		for _, raw := range r.OrAddresses {
			host := raw
			if strings.HasPrefix(host, "[") {
				end := strings.Index(host, "]")
				if end > 0 {
					host = host[1:end]
				}
			} else {
				if h, _, err := net.SplitHostPort(host); err == nil {
					host = h
				}
			}
			ip := net.ParseIP(host)
			if ip == nil {
				continue
			}
			fresh[ip.String()] = struct{}{}
		}
	}
	dur := time.Since(start).Seconds()
	nowUnix := float64(time.Now().Unix())
	mc.torExitMu.Lock()
	mc.torExitSet = fresh
	mc.torExitLastSuccessUnix = nowUnix
	mc.torExitLastRefreshSeconds = dur
	mc.torExitEntries = len(fresh)
	mc.torExitMu.Unlock()
	logInfo("TOREXIT: loaded %d exit-node IPs", len(fresh))
	mc.updateHostThreatsFromIPSet("tor_exit", fresh)
}

func (mc *MetricsCollector) startTorRelayRefresher() {
	for {
		mc.refreshTorRelayListUnified()
		time.Sleep(mc.torRelayRefresh)
	}
}

func (mc *MetricsCollector) refreshTorRelayListUnified() {
	start := time.Now()
	resp, err := mc.httpClient.Get(mc.torRelayURL)
	if err != nil {
		atomic.AddUint64(&mc.torRelayRefreshErrors, 1)
		logError("TORRELAY: failed to download list: %v", err)
		return
	}
	defer resp.Body.Close()
	var data OnionooSummary
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&data); err != nil {
		atomic.AddUint64(&mc.torRelayRefreshErrors, 1)
		logError("TORRELAY: JSON decode error: %v", err)
		return
	}
	fresh := make(map[string]struct{})
	for _, r := range data.Relays {
		for _, raw := range r.OrAddresses {
			host := raw
			if strings.HasPrefix(host, "[") {
				end := strings.Index(host, "]")
				if end > 0 {
					host = host[1:end]
				}
			} else {
				if h, _, err := net.SplitHostPort(host); err == nil {
					host = h
				}
			}
			ip := net.ParseIP(host)
			if ip == nil {
				continue
			}
			fresh[ip.String()] = struct{}{}
		}
	}
	dur := time.Since(start).Seconds()
	nowUnix := float64(time.Now().Unix())
	mc.torRelayMu.Lock()
	mc.torRelaySet = fresh
	mc.torRelayLastSuccessUnix = nowUnix
	mc.torRelayLastRefreshSeconds = dur
	mc.torRelayEntries = len(fresh)
	mc.torRelayMu.Unlock()
	logInfo("TORRELAY: loaded %d relay IPs", len(fresh))
	mc.updateHostThreatsFromIPSet("tor_relay", fresh)
}

func (mc *MetricsCollector) startSpamhausRefresher() {
	for {
		mc.refreshSpamhausList()
		time.Sleep(mc.spamRefresh)
	}
}

func (mc *MetricsCollector) refreshSpamhausList() {
	start := time.Now()
	allNets := make([]*net.IPNet, 0, 8192)
	resp4, err := mc.httpClient.Get(mc.spamURL)
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
	resp6, err := mc.httpClient.Get(mc.spamV6URL)
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
		atomic.AddUint64(&mc.spamRefreshErrors, 1)
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
		key := fmt.Sprintf("%x:%x:%x", uint16(ip16[0])<<8|uint16(ip16[1]), uint16(ip16[2])<<8|uint16(ip16[3]), uint16(ip16[4])<<8|uint16(ip16[5]))
		bucketsV6[key] = append(bucketsV6[key], n)
		v6Count++
	}
	dur := time.Since(start).Seconds()
	nowUnix := float64(time.Now().Unix())
	mc.spamMu.Lock()
	mc.spamNets = allNets
	mc.spamBucketsV4 = bucketsV4
	mc.spamBucketsV6 = bucketsV6
	mc.spamLastSuccessUnix = nowUnix
	mc.spamLastRefreshSeconds = dur
	mc.spamEntries = len(allNets)
	mc.spamMu.Unlock()
	logInfo("SPAMHAUS: %d CIDRs (%d IPv4, %d IPv6) in %d /16 IPv4 buckets and %d /48 IPv6 buckets", len(allNets), v4Count, v6Count, len(bucketsV4), len(bucketsV6))
	mc.updateHostThreatsFromCIDRs("spamhaus", allNets)
}

func parseSpamhausCIDRs(r io.Reader) ([]*net.IPNet, error) {
	scanner := bufio.NewScanner(r)
	nets := make([]*net.IPNet, 0, 4096)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ";")
		cidrStr := strings.TrimSpace(parts[0])
		if _, netIP, err := net.ParseCIDR(cidrStr); err == nil {
			nets = append(nets, netIP)
		}
	}
	return nets, scanner.Err()
}

func (mc *MetricsCollector) startEmThreatsRefresher() {
	for {
		mc.refreshEmergingThreatsList()
		time.Sleep(mc.emThreatsRefresh)
	}
}

func (mc *MetricsCollector) refreshEmergingThreatsList() {
	start := time.Now()
	resp, err := mc.httpClient.Get(mc.emThreatsURL)
	if err != nil {
		atomic.AddUint64(&mc.emThreatsRefreshErrors, 1)
		logError("EMTHREATS: Failed to download list: %v", err)
		return
	}
	defer resp.Body.Close()
	scanner := bufio.NewScanner(resp.Body)
	fresh := make(map[string]struct{})
	for scanner.Scan() {
		ip := strings.TrimSpace(scanner.Text())
		if ip == "" || strings.HasPrefix(ip, "#") {
			continue
		}
		fresh[ip] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		atomic.AddUint64(&mc.emThreatsRefreshErrors, 1)
		logError("EMTHREATS: read error: %v", err)
		return
	}
	dur := time.Since(start).Seconds()
	nowUnix := float64(time.Now().Unix())
	mc.emThreatsMu.Lock()
	mc.emThreatsSet = fresh
	mc.emThreatsLastSuccessUnix = nowUnix
	mc.emThreatsLastRefreshSeconds = dur
	mc.emThreatsEntries = len(fresh)
	mc.emThreatsMu.Unlock()
	logInfo("EMTHREATS: Loaded %d compromised IPs", len(fresh))
	mc.updateHostThreatsFromIPSet("emergingthreats", fresh)
}

func (mc *MetricsCollector) startCustomListRefresher() {
	for {
		mc.refreshCustomList()
		time.Sleep(mc.customListRefresh)
	}
}

func (mc *MetricsCollector) refreshCustomList() {
	start := time.Now()
	f, err := os.Open(mc.customListPath)
	if err != nil {
		atomic.AddUint64(&mc.customListRefreshErrors, 1)
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
		atomic.AddUint64(&mc.customListRefreshErrors, 1)
		logError("CUSTOMLIST: read error on %s: %v", mc.customListPath, err)
		return
	}
	dur := time.Since(start).Seconds()
	nowUnix := float64(time.Now().Unix())
	mc.customListMu.Lock()
	mc.customListSet = fresh
	mc.customListLastSuccessUnix = nowUnix
	mc.customListLastRefreshSeconds = dur
	mc.customListEntries = len(fresh)
	mc.customListMu.Unlock()
	logInfo("CUSTOMLIST: loaded %d IPs from %s", len(fresh), mc.customListPath)
	mc.updateHostThreatsFromIPSet("customlist", fresh)
}

func (mc *MetricsCollector) startBackgroundCollection() {
	for {
		cycleStart := time.Now()

		prevEnd := atomic.LoadInt64(&mc.lastCycleEndUnixNano)
		lagSeconds := 0.0
		if prevEnd > 0 {
			lagDur := time.Since(time.Unix(0, prevEnd)).Seconds()
			if lagDur > 0 {
				lagSeconds = lagDur
			}
		}

		logDebug("Background collection of metrics")

		libvirtListStart := time.Now()
		domains, err := mc.conn.ListAllDomains(libvirt.CONNECT_LIST_DOMAINS_ACTIVE)
		libvirtListSeconds := time.Since(libvirtListStart).Seconds()
		if err != nil {
			atomic.AddUint64(&mc.hostCollectionErrors, 1)
			logError("failed to list domains: %v", err)
			time.Sleep(mc.collectionInterval)
			continue
		}
		logDebug("Found %d active domains", len(domains))

		countActive := len(domains)
		vcpuSum := 0
		memBytesSum := uint64(0)

		for _, dom := range domains {
			info, err := dom.GetInfo()
			if err != nil {
				continue
			}
			vcpuSum += int(info.NrVirtCpu)
			if info.MaxMem > 0 {
				memBytesSum += uint64(info.MaxMem) * 1024
			}
		}

		conntrackStart := time.Now()
		ctEntries, err := readConntrack()
		conntrackSeconds := time.Since(conntrackStart).Seconds()
		if err != nil {
			atomic.AddUint64(&mc.hostCollectionErrors, 1)
			atomic.AddUint64(&mc.conntrackReadErrors, 1)
			logDebug("failed to read conntrack: %v", err)
		}
		ctCount := 0
		if ctEntries != nil {
			ctCount = len(ctEntries)
		}

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

		mc.dynamicCache.mu.RLock()
		dynSeries := len(mc.dynamicCache.data)
		mc.dynamicCache.mu.RUnlock()

		mc.staticCache.mu.RLock()
		staticEntries := len(mc.staticCache.data)
		mc.staticCache.mu.RUnlock()

		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		heapAllocBytes := float64(ms.HeapAlloc)

		errorsTotal := atomic.LoadUint64(&mc.hostCollectionErrors)
		conntrackErrors := atomic.LoadUint64(&mc.conntrackReadErrors)

		mc.cacheCleanupMu.Lock()
		cleanupSecondsLast := mc.cacheCleanupSeconds
		mc.cacheCleanupMu.Unlock()
		cacheEvictions := atomic.LoadUint64(&mc.cacheEvictions)

		var torExitLast, torExitDur float64
		var torExitEntries int
		mc.torExitMu.RLock()
		torExitLast = mc.torExitLastSuccessUnix
		torExitDur = mc.torExitLastRefreshSeconds
		torExitEntries = mc.torExitEntries
		mc.torExitMu.RUnlock()
		torExitErrs := atomic.LoadUint64(&mc.torExitRefreshErrors)

		var torRelayLast, torRelayDur float64
		var torRelayEntries int
		mc.torRelayMu.RLock()
		torRelayLast = mc.torRelayLastSuccessUnix
		torRelayDur = mc.torRelayLastRefreshSeconds
		torRelayEntries = mc.torRelayEntries
		mc.torRelayMu.RUnlock()
		torRelayErrs := atomic.LoadUint64(&mc.torRelayRefreshErrors)

		var spamLast, spamDur float64
		var spamEntries int
		mc.spamMu.RLock()
		spamLast = mc.spamLastSuccessUnix
		spamDur = mc.spamLastRefreshSeconds
		spamEntries = mc.spamEntries
		mc.spamMu.RUnlock()
		spamErrs := atomic.LoadUint64(&mc.spamRefreshErrors)

		var emLast, emDur float64
		var emEntries int
		mc.emThreatsMu.RLock()
		emLast = mc.emThreatsLastSuccessUnix
		emDur = mc.emThreatsLastRefreshSeconds
		emEntries = mc.emThreatsEntries
		mc.emThreatsMu.RUnlock()
		emErrs := atomic.LoadUint64(&mc.emThreatsRefreshErrors)

		var clLast, clDur float64
		var clEntries int
		mc.customListMu.RLock()
		clLast = mc.customListLastSuccessUnix
		clDur = mc.customListLastRefreshSeconds
		clEntries = mc.customListEntries
		mc.customListMu.RUnlock()
		clErrs := atomic.LoadUint64(&mc.customListRefreshErrors)

		cycleSeconds := time.Since(cycleStart).Seconds()

		hostMetrics := []prometheus.Metric{
			prometheus.MustNewConstMetric(mc.hostActiveDomainsDesc, prometheus.GaugeValue, float64(countActive)),
			prometheus.MustNewConstMetric(mc.hostActiveVcpusDesc, prometheus.GaugeValue, float64(vcpuSum)),
			prometheus.MustNewConstMetric(mc.hostActiveMemGBDesc, prometheus.GaugeValue, roundToFiveDecimals(float64(memBytesSum)*bytesToGigabytes)),
			prometheus.MustNewConstMetric(mc.hostCollectionErrorsDesc, prometheus.CounterValue, float64(errorsTotal)),
			prometheus.MustNewConstMetric(mc.hostCollectionDurationDesc, prometheus.GaugeValue, roundToFiveDecimals(cycleSeconds)),
			prometheus.MustNewConstMetric(mc.hostCollectionLagDesc, prometheus.GaugeValue, roundToFiveDecimals(lagSeconds)),
			prometheus.MustNewConstMetric(mc.hostLibvirtListDurationDesc, prometheus.GaugeValue, roundToFiveDecimals(libvirtListSeconds)),
			prometheus.MustNewConstMetric(mc.hostConntrackReadDurationDesc, prometheus.GaugeValue, roundToFiveDecimals(conntrackSeconds)),
			prometheus.MustNewConstMetric(mc.hostConntrackEntriesDesc, prometheus.GaugeValue, float64(ctCount)),
			prometheus.MustNewConstMetric(mc.hostDynamicCacheSeriesDesc, prometheus.GaugeValue, float64(dynSeries)),
			prometheus.MustNewConstMetric(mc.hostGoHeapAllocDesc, prometheus.GaugeValue, heapAllocBytes),

			prometheus.MustNewConstMetric(mc.conntrackReadErrorsDesc, prometheus.CounterValue, float64(conntrackErrors)),
			prometheus.MustNewConstMetric(mc.hostConntrackReadErrorsDesc, prometheus.CounterValue, float64(conntrackErrors)),
			prometheus.MustNewConstMetric(mc.staticCacheEntriesDesc, prometheus.GaugeValue, float64(staticEntries)),
			prometheus.MustNewConstMetric(mc.dynamicCacheEntriesDesc, prometheus.GaugeValue, float64(dynSeries)),
			prometheus.MustNewConstMetric(mc.cacheCleanupDurationDesc, prometheus.GaugeValue, roundToFiveDecimals(cleanupSecondsLast)),
			prometheus.MustNewConstMetric(mc.cacheEvictionsDesc, prometheus.CounterValue, float64(cacheEvictions)),
		}

		if mc.torExitEnabled {
			hostMetrics = append(hostMetrics,
				prometheus.MustNewConstMetric(mc.torExitRefreshLastSuccessDesc, prometheus.GaugeValue, torExitLast),
				prometheus.MustNewConstMetric(mc.torExitRefreshDurationDesc, prometheus.GaugeValue, roundToFiveDecimals(torExitDur)),
				prometheus.MustNewConstMetric(mc.torExitRefreshErrorsDesc, prometheus.CounterValue, float64(torExitErrs)),
				prometheus.MustNewConstMetric(mc.torExitEntriesDesc, prometheus.GaugeValue, float64(torExitEntries)),
			)
		}
		if mc.torRelayEnabled {
			hostMetrics = append(hostMetrics,
				prometheus.MustNewConstMetric(mc.torRelayRefreshLastSuccessDesc, prometheus.GaugeValue, torRelayLast),
				prometheus.MustNewConstMetric(mc.torRelayRefreshDurationDesc, prometheus.GaugeValue, roundToFiveDecimals(torRelayDur)),
				prometheus.MustNewConstMetric(mc.torRelayRefreshErrorsDesc, prometheus.CounterValue, float64(torRelayErrs)),
				prometheus.MustNewConstMetric(mc.torRelayEntriesDesc, prometheus.GaugeValue, float64(torRelayEntries)),
			)
		}
		if mc.spamEnabled {
			hostMetrics = append(hostMetrics,
				prometheus.MustNewConstMetric(mc.spamRefreshLastSuccessDesc, prometheus.GaugeValue, spamLast),
				prometheus.MustNewConstMetric(mc.spamRefreshDurationDesc, prometheus.GaugeValue, roundToFiveDecimals(spamDur)),
				prometheus.MustNewConstMetric(mc.spamRefreshErrorsDesc, prometheus.CounterValue, float64(spamErrs)),
				prometheus.MustNewConstMetric(mc.spamEntriesDesc, prometheus.GaugeValue, float64(spamEntries)),
			)
		}
		if mc.emThreatsEnabled {
			hostMetrics = append(hostMetrics,
				prometheus.MustNewConstMetric(mc.emThreatsRefreshLastSuccessDesc, prometheus.GaugeValue, emLast),
				prometheus.MustNewConstMetric(mc.emThreatsRefreshDurationDesc, prometheus.GaugeValue, roundToFiveDecimals(emDur)),
				prometheus.MustNewConstMetric(mc.emThreatsRefreshErrorsDesc, prometheus.CounterValue, float64(emErrs)),
				prometheus.MustNewConstMetric(mc.emThreatsEntriesDesc, prometheus.GaugeValue, float64(emEntries)),
			)
		}
		if mc.customListEnabled {
			hostMetrics = append(hostMetrics,
				prometheus.MustNewConstMetric(mc.customListRefreshLastSuccessDesc, prometheus.GaugeValue, clLast),
				prometheus.MustNewConstMetric(mc.customListRefreshDurationDesc, prometheus.GaugeValue, roundToFiveDecimals(clDur)),
				prometheus.MustNewConstMetric(mc.customListRefreshErrorsDesc, prometheus.CounterValue, float64(clErrs)),
				prometheus.MustNewConstMetric(mc.customListEntriesDesc, prometheus.GaugeValue, float64(clEntries)),
			)
		}

		mc.staticCache.Set("host_active", hostMetrics)
		atomic.StoreInt64(&mc.lastCycleEndUnixNano, time.Now().UnixNano())

		time.Sleep(mc.collectionInterval)
	}
}

func roundToFiveDecimals(value float64) float64 {
	return math.Round(value*100000) / 100000
}

func parseDiskType(sourceName string) (string, string) {
	parts := strings.Split(sourceName, "/")
	if len(parts) > 1 {
		return parts[0], parts[1]
	}
	return "unknown", "unknown"
}

func (mc *MetricsCollector) calculateCPUUsage(domain libvirt.Domain, uuid string, vcpuCount int) (float64, error) {
	if vcpuCount <= 0 {
		info, err := domain.GetInfo()
		if err == nil {
			vcpuCount = int(info.NrVirtCpu)
		}
	}
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
	mc.cpuSamples[uuid] = cpuSample{total: total, ts: now}
	mc.cpuMu.Unlock()
	if !ok {
		return 0, nil
	}
	elapsed := now.Sub(prev.ts)
	if elapsed <= 0 {
		return 0, nil
	}
	var delta uint64
	if total >= prev.total {
		delta = total - prev.total
	} else {
		delta = 0
	}
	usage := (float64(delta) / float64(elapsed.Nanoseconds())) * 100 / float64(vcpuCount)
	if usage < 0 {
		usage = 0
	} else if usage > 100 {
		usage = 100
	}
	return usage, nil
}

func (mc *MetricsCollector) shouldExportCPU(uuid string, usage float64) bool {
	mc.cpuMu.Lock()
	defer mc.cpuMu.Unlock()
	prev, ok := mc.cpuLastExport[uuid]
	if usage >= mc.cpuMin {
		mc.cpuLastExport[uuid] = usage
		return true
	}
	if ok && prev >= mc.cpuMin {
		mc.cpuLastExport[uuid] = usage
		return true
	}
	if ok && usage == 0 && prev == 0 {
		return false
	}
	return false
}

const bytesToGigabytes = 1.0 / (1024 * 1024 * 1024)

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
	ipSet := make(map[string]struct{}, len(fixedIPs))
	for _, ip := range fixedIPs {
		ipSet[ip.Address] = struct{}{}
	}

	userUUID := domainXML.Metadata.NovaInstance.NovaOwner.NovaUser.UserUUID
	projectUUID := domainXML.Metadata.NovaInstance.NovaOwner.NovaProject.ProjectUUID
	vcpuCount := domainXML.Metadata.NovaInstance.NovaFlavor.VCPUs

	projectName := strings.TrimSpace(domainXML.Metadata.NovaInstance.NovaOwner.NovaProject.ProjectName)
	if projectName == "" {
		projectName = "unknown"
	}
	userName := strings.TrimSpace(domainXML.Metadata.NovaInstance.NovaOwner.NovaUser.UserName)
	if userName == "" {
		userName = "unknown"
	}
	flavorName := strings.TrimSpace(domainXML.Metadata.NovaInstance.NovaFlavor.FlavorName)
	if flavorName == "" {
		flavorName = "unknown"
	}
	memMB := domainXML.Metadata.NovaInstance.NovaFlavor.MemoryMB
	rootType := strings.TrimSpace(domainXML.Metadata.NovaInstance.NovaRoot.RootType)
	if rootType == "" {
		rootType = "unknown"
	}
	createdAt := strings.TrimSpace(domainXML.Metadata.NovaInstance.CreationTime)
	if createdAt == "" {
		createdAt = "unknown"
	}
	metadataVersion := strings.TrimSpace(domainXML.Metadata.NovaInstance.NovaPackage.Version)
	if metadataVersion == "" {
		metadataVersion = "unknown"
	}

	dynamicMetrics := make([]prometheus.Metric, 0, 64)

	dynamicMetrics = append(dynamicMetrics,
		prometheus.MustNewConstMetric(
			mc.instanceInfoDesc,
			prometheus.GaugeValue,
			1.0,
			name,
			instanceUUID,
			projectUUID,
			projectName,
			userUUID,
			userName,
			flavorName,
			strconv.Itoa(vcpuCount),
			strconv.Itoa(memMB),
			rootType,
			createdAt,
			metadataVersion,
		),
	)

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
		key := diskType + "-" + diskPath
		if _, exists := seenDisks[key]; exists {
			continue
		}
		seenDisks[key] = struct{}{}

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

		diskMetrics := make([]prometheus.Metric, 0, 7)

		diskMetrics = append(diskMetrics,
			prometheus.MustNewConstMetric(
				mc.diskInfoDesc,
				prometheus.GaugeValue,
				1.0,
				name,
				instanceUUID,
				projectUUID,
				userUUID,
				volumeUUID,
				diskType,
				diskPath,
			),
		)

		diskMetrics = append(diskMetrics,
			prometheus.MustNewConstMetric(mc.diskReadThresholds, prometheus.GaugeValue, float64(readThreshold), name, instanceUUID, userUUID, projectUUID, volumeUUID, diskType, diskPath),
			prometheus.MustNewConstMetric(mc.diskWriteThresholds, prometheus.GaugeValue, float64(writeThreshold), name, instanceUUID, userUUID, projectUUID, volumeUUID, diskType, diskPath),
		)
		if stats.RdBytes != 0 || stats.WrBytes != 0 || stats.RdReq != 0 || stats.WrReq != 0 {
			diskMetrics = append(diskMetrics,
				prometheus.MustNewConstMetric(mc.diskReadBytes, prometheus.CounterValue, roundToFiveDecimals(float64(stats.RdBytes)*bytesToGigabytes), name, instanceUUID, userUUID, projectUUID, volumeUUID, diskType, diskPath),
				prometheus.MustNewConstMetric(mc.diskWriteBytes, prometheus.CounterValue, roundToFiveDecimals(float64(stats.WrBytes)*bytesToGigabytes), name, instanceUUID, userUUID, projectUUID, volumeUUID, diskType, diskPath),
				prometheus.MustNewConstMetric(mc.diskReadRequests, prometheus.CounterValue, float64(stats.RdReq), name, instanceUUID, userUUID, projectUUID, volumeUUID, diskType, diskPath),
				prometheus.MustNewConstMetric(mc.diskWriteRequests, prometheus.CounterValue, float64(stats.WrReq), name, instanceUUID, userUUID, projectUUID, volumeUUID, diskType, diskPath),
			)
			logInfo("METRIC disk domain=%s uuid=%s disk=%s tier=%s rdB=%d wrB=%d rdReq=%d wrReq=%d", name, instanceUUID, diskPath, diskType, stats.RdBytes, stats.WrBytes, stats.RdReq, stats.WrReq)
		}
		dynamicMetrics = append(dynamicMetrics, diskMetrics...)
	}

	cpuUsage, err := mc.calculateCPUUsage(domain, instanceUUID, vcpuCount)
	if err != nil {
		logDebug("failed to calculate CPU usage for domain=%s: %v", name, err)
	}
	if mc.shouldExportCPU(instanceUUID, cpuUsage) {
		dynamicMetrics = append(dynamicMetrics, prometheus.MustNewConstMetric(mc.cpuUsage, prometheus.GaugeValue, roundToFiveDecimals(cpuUsage), name, instanceUUID, userUUID, projectUUID))
		logInfo("METRIC cpu domain=%s uuid=%s vcpus=%d usage=%.2f", name, instanceUUID, vcpuCount, cpuUsage)
	}

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
		if netRxBytes == 0 && netTxBytes == 0 && netRxPackets == 0 && netTxPackets == 0 && netRxErrs == 0 && netTxErrs == 0 && netRxDrop == 0 && netTxDrop == 0 {
			continue
		}
		emitted := false
		if netRxBytes != 0 {
			dynamicMetrics = append(dynamicMetrics, prometheus.MustNewConstMetric(mc.networkRxBytes, prometheus.CounterValue, roundToFiveDecimals(float64(netRxBytes)*bytesToGigabytes), name, interfaceName, instanceUUID, userUUID, projectUUID))
			emitted = true
		}
		if netTxBytes != 0 {
			dynamicMetrics = append(dynamicMetrics, prometheus.MustNewConstMetric(mc.networkTxBytes, prometheus.CounterValue, roundToFiveDecimals(float64(netTxBytes)*bytesToGigabytes), name, interfaceName, instanceUUID, userUUID, projectUUID))
			emitted = true
		}
		if netRxPackets != 0 {
			dynamicMetrics = append(dynamicMetrics, prometheus.MustNewConstMetric(mc.networkRxPackets, prometheus.CounterValue, float64(netRxPackets), name, interfaceName, instanceUUID, userUUID, projectUUID))
			emitted = true
		}
		if netTxPackets != 0 {
			dynamicMetrics = append(dynamicMetrics, prometheus.MustNewConstMetric(mc.networkTxPackets, prometheus.CounterValue, float64(netTxPackets), name, interfaceName, instanceUUID, userUUID, projectUUID))
			emitted = true
		}
		if netRxErrs != 0 {
			dynamicMetrics = append(dynamicMetrics, prometheus.MustNewConstMetric(mc.networkRxErrors, prometheus.CounterValue, float64(netRxErrs), name, interfaceName, instanceUUID, userUUID, projectUUID))
			emitted = true
		}
		if netTxErrs != 0 {
			dynamicMetrics = append(dynamicMetrics, prometheus.MustNewConstMetric(mc.networkTxErrors, prometheus.CounterValue, float64(netTxErrs), name, interfaceName, instanceUUID, userUUID, projectUUID))
			emitted = true
		}
		if netRxDrop != 0 {
			dynamicMetrics = append(dynamicMetrics, prometheus.MustNewConstMetric(mc.networkRxDropped, prometheus.CounterValue, float64(netRxDrop), name, interfaceName, instanceUUID, userUUID, projectUUID))
			emitted = true
		}
		if netTxDrop != 0 {
			dynamicMetrics = append(dynamicMetrics, prometheus.MustNewConstMetric(mc.networkTxDropped, prometheus.CounterValue, float64(netTxDrop), name, interfaceName, instanceUUID, userUUID, projectUUID))
			emitted = true
		}
		if emitted {
			logInfo("METRIC net domain=%s uuid=%s iface=%s rxB=%d txB=%d rxP=%d txP=%d rxE=%d txE=%d rxD=%d txD=%d", name, instanceUUID, interfaceName, netRxBytes, netTxBytes, netRxPackets, netTxPackets, netRxErrs, netTxErrs, netRxDrop, netTxDrop)
		}
	}

	if len(ctEntries) > 0 && len(fixedIPs) > 0 {
		perIPFlows := make(map[string]int, len(fixedIPs))

		var perIPOutboundRemotes map[string]map[string]struct{}
		var perIPOutboundFlows map[string]int
		var perIPOutboundPerRemoteFlows map[string]map[string]int
		var perIPOutboundDstPorts map[string]map[uint16]struct{}
		var perIPOutboundPerDstPortFlows map[string]map[uint16]int

		if mc.outboundBehaviorEnabled {
			perIPOutboundRemotes = make(map[string]map[string]struct{}, len(fixedIPs))
			perIPOutboundFlows = make(map[string]int, len(fixedIPs))
			perIPOutboundPerRemoteFlows = make(map[string]map[string]int, len(fixedIPs))
			perIPOutboundDstPorts = make(map[string]map[uint16]struct{}, len(fixedIPs))
			perIPOutboundPerDstPortFlows = make(map[string]map[uint16]int, len(fixedIPs))
		}

		for _, ip := range fixedIPs {
			perIPFlows[ip.Address] = 0
			if mc.outboundBehaviorEnabled {
				perIPOutboundRemotes[ip.Address] = make(map[string]struct{})
				perIPOutboundFlows[ip.Address] = 0
				perIPOutboundPerRemoteFlows[ip.Address] = make(map[string]int)
				perIPOutboundDstPorts[ip.Address] = make(map[uint16]struct{})
				perIPOutboundPerDstPortFlows[ip.Address] = make(map[uint16]int)
			}
		}

		for _, ct := range ctEntries {
			_, srcIsVM := ipSet[ct.Src]
			_, dstIsVM := ipSet[ct.Dst]

			if srcIsVM {
				perIPFlows[ct.Src]++
			}
			if dstIsVM && ct.Dst != ct.Src {
				perIPFlows[ct.Dst]++
			}

			if !mc.outboundBehaviorEnabled {
				continue
			}

			if srcIsVM && !dstIsVM {
				perIPOutboundFlows[ct.Src]++
				perIPOutboundRemotes[ct.Src][ct.Dst] = struct{}{}
				perIPOutboundPerRemoteFlows[ct.Src][ct.Dst]++
				if ct.DstPort != 0 {
					perIPOutboundDstPorts[ct.Src][ct.DstPort] = struct{}{}
					perIPOutboundPerDstPortFlows[ct.Src][ct.DstPort]++
				}
				continue
			}
		}

		for _, ip := range fixedIPs {
			flowCount := perIPFlows[ip.Address]
			if flowCount >= mc.conntrackMin {
				dynamicMetrics = append(dynamicMetrics, prometheus.MustNewConstMetric(mc.ctPerIPFlows, prometheus.GaugeValue, float64(flowCount), name, instanceUUID, ip.Address, ip.Family, projectUUID, userUUID))
				logInfo("METRIC conntrack_flows domain=%s uuid=%s ip=%s family=%s flows=%d", name, instanceUUID, ip.Address, ip.Family, flowCount)
			}

			if !mc.outboundBehaviorEnabled {
				continue
			}

			outU := len(perIPOutboundRemotes[ip.Address])
			outF := perIPOutboundFlows[ip.Address]
			dstPortsU := len(perIPOutboundDstPorts[ip.Address])

			maxSingle := 0
			for _, c := range perIPOutboundPerRemoteFlows[ip.Address] {
				if c > maxSingle {
					maxSingle = c
				}
			}

			maxFlowsSinglePort := 0
			for _, c := range perIPOutboundPerDstPortFlows[ip.Address] {
				if c > maxFlowsSinglePort {
					maxFlowsSinglePort = c
				}
			}

			newRemotes := 0
			key := instanceUUID + "|" + ip.Address
			mc.outboundMu.Lock()
			prev, okPrev := mc.outboundPrev[key]
			if okPrev {
				for r := range perIPOutboundRemotes[ip.Address] {
					if _, ok := prev.remotes[r]; !ok {
						newRemotes++
					}
				}
			} else {
				newRemotes = outU
			}
			mc.outboundPrev[key] = outboundPrev{remotes: perIPOutboundRemotes[ip.Address]}

			dstPortKey := instanceUUID + "|" + ip.Address + "|dstports"
			newDstPorts := 0
			prevPorts, okPrevPorts := mc.outboundPrevDstPorts[dstPortKey]
			if okPrevPorts {
				for p := range perIPOutboundDstPorts[ip.Address] {
					if _, ok := prevPorts.ports[p]; !ok {
						newDstPorts++
					}
				}
			} else {
				newDstPorts = dstPortsU
			}
			mc.outboundPrevDstPorts[dstPortKey] = outboundPrevDstPorts{ports: perIPOutboundDstPorts[ip.Address]}
			mc.outboundMu.Unlock()

			exportOutbound := outU >= mc.conntrackMin || outF >= mc.conntrackMin
			if exportOutbound {
				dynamicMetrics = append(dynamicMetrics, prometheus.MustNewConstMetric(mc.outboundUniqueDesc, prometheus.GaugeValue, float64(outU), name, instanceUUID, ip.Address, ip.Family, projectUUID, userUUID))
				dynamicMetrics = append(dynamicMetrics, prometheus.MustNewConstMetric(mc.outboundFlowsDesc, prometheus.GaugeValue, float64(outF), name, instanceUUID, ip.Address, ip.Family, projectUUID, userUUID))
				dynamicMetrics = append(dynamicMetrics, prometheus.MustNewConstMetric(mc.outboundNewRemotesDesc, prometheus.GaugeValue, float64(newRemotes), name, instanceUUID, ip.Address, ip.Family, projectUUID, userUUID))
				dynamicMetrics = append(dynamicMetrics, prometheus.MustNewConstMetric(mc.outboundMaxFlowsSingleRemoteDesc, prometheus.GaugeValue, float64(maxSingle), name, instanceUUID, ip.Address, ip.Family, projectUUID, userUUID))
				if dstPortsU > 0 {
					dynamicMetrics = append(dynamicMetrics, prometheus.MustNewConstMetric(mc.outboundUniqueDstPortsDesc, prometheus.GaugeValue, float64(dstPortsU), name, instanceUUID, ip.Address, ip.Family, projectUUID, userUUID))
					dynamicMetrics = append(dynamicMetrics, prometheus.MustNewConstMetric(mc.outboundNewDstPortsDesc, prometheus.GaugeValue, float64(newDstPorts), name, instanceUUID, ip.Address, ip.Family, projectUUID, userUUID))
					dynamicMetrics = append(dynamicMetrics, prometheus.MustNewConstMetric(mc.outboundMaxFlowsSingleDstPortDesc, prometheus.GaugeValue, float64(maxFlowsSinglePort), name, instanceUUID, ip.Address, ip.Family, projectUUID, userUUID))
				}
				logInfo("METRIC outbound domain=%s uuid=%s ip=%s family=%s uniq=%d new=%d flows=%d maxSingle=%d dstPortsU=%d newDstPorts=%d maxPortFlows=%d", name, instanceUUID, ip.Address, ip.Family, outU, newRemotes, outF, maxSingle, dstPortsU, newDstPorts, maxFlowsSinglePort)
				mc.logThreatEventToFile("OUTBOUND", name, instanceUUID, projectUUID, userUUID, fmt.Sprintf("ip=%s family=%s uniq_remotes=%d new_remotes=%d flows=%d max_single_remote=%d uniq_dst_ports=%d new_dst_ports=%d max_single_dst_port_flows=%d", ip.Address, ip.Family, outU, newRemotes, outF, maxSingle, dstPortsU, newDstPorts, maxFlowsSinglePort))
			}
		}
	}

	if mc.torExitEnabled {
		mc.torExitMu.RLock()
		torExitSnapshot := mc.torExitSet
		mc.torExitMu.RUnlock()
		hits := make(map[string]ConntrackEntry)
		seen := make(map[string]struct{})
		for _, ct := range ctEntries {
			_, isVMsrc := ipSet[ct.Src]
			_, isVMdst := ipSet[ct.Dst]
			if !isVMsrc && !isVMdst {
				continue
			}
			match := false
			switch mc.torExitDir {
			case ContactOut:
				if isVMsrc {
					if _, ok := torExitSnapshot[ct.Dst]; ok {
						match = true
					}
				}
			case ContactIn:
				if isVMdst {
					if _, ok := torExitSnapshot[ct.Src]; ok {
						match = true
					}
				}
			default:
				if _, ok := torExitSnapshot[ct.Src]; ok {
					match = true
				}
				if _, ok := torExitSnapshot[ct.Dst]; ok {
					match = true
				}
			}
			if !match {
				continue
			}
			a := ct.Src
			b := ct.Dst
			if a > b {
				a, b = b, a
			}
			k := a + "|" + b
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			hits[k] = ct
		}
		for _, ct := range hits {
			dirStr := flowDirection(ipSet, ct)
			logThreat("TOREXIT-HIT: domain=%s uuid=%s src=%s dst=%s direction=%s", name, instanceUUID, ct.Src, ct.Dst, dirStr)
			mc.logThreatToFile("TOR", name, instanceUUID, projectUUID, userUUID, ct, dirStr, mc.torExitDir)
		}
		activeVal := float64(len(hits))
		if activeVal > 0 {
			dynamicMetrics = append(dynamicMetrics, prometheus.MustNewConstMetric(mc.torExitActiveDesc, prometheus.GaugeValue, activeVal, name, instanceUUID, projectUUID, userUUID, mc.torExitDir.String()))
		}
		torVal := mc.addThreatCount(mc.torExitCount, instanceUUID, float64(len(hits)))
		if torVal > 0 {
			dynamicMetrics = append(dynamicMetrics, prometheus.MustNewConstMetric(mc.torExitContactDesc, prometheus.CounterValue, torVal, name, instanceUUID, projectUUID, userUUID, mc.torExitDir.String()))
		}
	}

	if mc.torRelayEnabled {
		mc.torRelayMu.RLock()
		torRelaySnapshot := mc.torRelaySet
		mc.torRelayMu.RUnlock()
		hits := make(map[string]ConntrackEntry)
		seen := make(map[string]struct{})
		for _, ct := range ctEntries {
			_, isVMsrc := ipSet[ct.Src]
			_, isVMdst := ipSet[ct.Dst]
			if !isVMsrc && !isVMdst {
				continue
			}
			match := false
			switch mc.torRelayDir {
			case ContactOut:
				if isVMsrc {
					if _, ok := torRelaySnapshot[ct.Dst]; ok {
						match = true
					}
				}
			case ContactIn:
				if isVMdst {
					if _, ok := torRelaySnapshot[ct.Src]; ok {
						match = true
					}
				}
			default:
				if _, ok := torRelaySnapshot[ct.Src]; ok {
					match = true
				}
				if _, ok := torRelaySnapshot[ct.Dst]; ok {
					match = true
				}
			}
			if !match {
				continue
			}
			a := ct.Src
			b := ct.Dst
			if a > b {
				a, b = b, a
			}
			k := a + "|" + b
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			hits[k] = ct
		}
		for _, ct := range hits {
			dirStr := flowDirection(ipSet, ct)
			logThreat("TORRELAY-HIT: domain=%s uuid=%s src=%s dst=%s direction=%s", name, instanceUUID, ct.Src, ct.Dst, dirStr)
			mc.logThreatToFile("TORRELAY", name, instanceUUID, projectUUID, userUUID, ct, dirStr, mc.torRelayDir)
		}
		activeVal := float64(len(hits))
		if activeVal > 0 {
			dynamicMetrics = append(dynamicMetrics, prometheus.MustNewConstMetric(mc.torRelayActiveDesc, prometheus.GaugeValue, activeVal, name, instanceUUID, projectUUID, userUUID, mc.torRelayDir.String()))
		}
		relayVal := mc.addThreatCount(mc.torRelayCount, instanceUUID, float64(len(hits)))
		if relayVal > 0 {
			dynamicMetrics = append(dynamicMetrics, prometheus.MustNewConstMetric(mc.torRelayContactDesc, prometheus.CounterValue, relayVal, name, instanceUUID, projectUUID, userUUID, mc.torRelayDir.String()))
		}
	}

	if mc.spamEnabled {
		hits := make(map[string]ConntrackEntry)
		seen := make(map[string]struct{})
		mc.spamMu.RLock()
		isSpamhausIP := func(ip net.IP) bool {
			if ip == nil {
				return false
			}
			if ip4 := ip.To4(); ip4 != nil {
				key := fmt.Sprintf("%d.%d", ip4[0], ip4[1])
				for _, n := range mc.spamBucketsV4[key] {
					if n.Contains(ip4) {
						return true
					}
				}
				return false
			}
			ip16 := ip.To16()
			if ip16 == nil {
				return false
			}
			key := fmt.Sprintf("%x:%x:%x", uint16(ip16[0])<<8|uint16(ip16[1]), uint16(ip16[2])<<8|uint16(ip16[3]), uint16(ip16[4])<<8|uint16(ip16[5]))
			for _, n := range mc.spamBucketsV6[key] {
				if n.Contains(ip16) {
					return true
				}
			}
			return false
		}
		for _, ct := range ctEntries {
			_, isVMsrc := ipSet[ct.Src]
			_, isVMdst := ipSet[ct.Dst]
			if !isVMsrc && !isVMdst {
				continue
			}
			srcIP := net.ParseIP(ct.Src)
			dstIP := net.ParseIP(ct.Dst)
			match := false
			switch mc.spamDir {
			case ContactOut:
				if isVMsrc && isSpamhausIP(dstIP) {
					match = true
				}
			case ContactIn:
				if isVMdst && isSpamhausIP(srcIP) {
					match = true
				}
			default:
				if isSpamhausIP(srcIP) || isSpamhausIP(dstIP) {
					match = true
				}
			}
			if !match {
				continue
			}
			a := ct.Src
			b := ct.Dst
			if a > b {
				a, b = b, a
			}
			k := a + "|" + b
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			hits[k] = ct
		}
		mc.spamMu.RUnlock()
		for _, ct := range hits {
			dirStr := flowDirection(ipSet, ct)
			logThreat("SPAMHAUS-HIT: domain=%s uuid=%s src=%s dst=%s direction=%s", name, instanceUUID, ct.Src, ct.Dst, dirStr)
			mc.logThreatToFile("SPAMHAUS", name, instanceUUID, projectUUID, userUUID, ct, dirStr, mc.spamDir)
		}
		activeVal := float64(len(hits))
		if activeVal > 0 {
			dynamicMetrics = append(dynamicMetrics, prometheus.MustNewConstMetric(mc.spamActiveDesc, prometheus.GaugeValue, activeVal, name, instanceUUID, projectUUID, userUUID, mc.spamDir.String()))
		}
		spamVal := mc.addThreatCount(mc.spamCount, instanceUUID, float64(len(hits)))
		if spamVal > 0 {
			dynamicMetrics = append(dynamicMetrics, prometheus.MustNewConstMetric(mc.spamContactDesc, prometheus.CounterValue, spamVal, name, instanceUUID, projectUUID, userUUID, mc.spamDir.String()))
		}
	}

	if mc.emThreatsEnabled {
		mc.emThreatsMu.RLock()
		etSnapshot := mc.emThreatsSet
		mc.emThreatsMu.RUnlock()
		hits := make(map[string]ConntrackEntry)
		seen := make(map[string]struct{})
		for _, ct := range ctEntries {
			_, isVMsrc := ipSet[ct.Src]
			_, isVMdst := ipSet[ct.Dst]
			if !isVMsrc && !isVMdst {
				continue
			}
			match := false
			switch mc.emThreatsDir {
			case ContactOut:
				if isVMsrc {
					if _, ok := etSnapshot[ct.Dst]; ok {
						match = true
					}
				}
			case ContactIn:
				if isVMdst {
					if _, ok := etSnapshot[ct.Src]; ok {
						match = true
					}
				}
			default:
				if _, ok := etSnapshot[ct.Src]; ok {
					match = true
				}
				if _, ok := etSnapshot[ct.Dst]; ok {
					match = true
				}
			}
			if !match {
				continue
			}
			a := ct.Src
			b := ct.Dst
			if a > b {
				a, b = b, a
			}
			k := a + "|" + b
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			hits[k] = ct
		}
		for _, ct := range hits {
			dirStr := flowDirection(ipSet, ct)
			logThreat("EMTHREATS-HIT: domain=%s uuid=%s src=%s dst=%s direction=%s", name, instanceUUID, ct.Src, ct.Dst, dirStr)
			mc.logThreatToFile("EMTHREATS", name, instanceUUID, projectUUID, userUUID, ct, dirStr, mc.emThreatsDir)
		}
		activeVal := float64(len(hits))
		if activeVal > 0 {
			dynamicMetrics = append(dynamicMetrics, prometheus.MustNewConstMetric(mc.emThreatsActiveDesc, prometheus.GaugeValue, activeVal, name, instanceUUID, projectUUID, userUUID, mc.emThreatsDir.String()))
		}
		emVal := mc.addThreatCount(mc.emThreatsCount, instanceUUID, float64(len(hits)))
		if emVal > 0 {
			dynamicMetrics = append(dynamicMetrics, prometheus.MustNewConstMetric(mc.emThreatsContactDesc, prometheus.CounterValue, emVal, name, instanceUUID, projectUUID, userUUID, mc.emThreatsDir.String()))
		}
	}

	if mc.customListEnabled {
		mc.customListMu.RLock()
		clSnapshot := mc.customListSet
		mc.customListMu.RUnlock()
		hits := make(map[string]ConntrackEntry)
		seen := make(map[string]struct{})
		for _, ct := range ctEntries {
			_, isVMsrc := ipSet[ct.Src]
			_, isVMdst := ipSet[ct.Dst]
			if !isVMsrc && !isVMdst {
				continue
			}
			match := false
			switch mc.customListDir {
			case ContactOut:
				if isVMsrc {
					if _, ok := clSnapshot[ct.Dst]; ok {
						match = true
					}
				}
			case ContactIn:
				if isVMdst {
					if _, ok := clSnapshot[ct.Src]; ok {
						match = true
					}
				}
			default:
				if _, ok := clSnapshot[ct.Src]; ok {
					match = true
				}
				if _, ok := clSnapshot[ct.Dst]; ok {
					match = true
				}
			}
			if !match {
				continue
			}
			a := ct.Src
			b := ct.Dst
			if a > b {
				a, b = b, a
			}
			k := a + "|" + b
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			hits[k] = ct
		}
		for _, ct := range hits {
			dirStr := flowDirection(ipSet, ct)
			logThreat("CUSTOMLIST-HIT: domain=%s uuid=%s src=%s dst=%s direction=%s", name, instanceUUID, ct.Src, ct.Dst, dirStr)
			mc.logThreatToFile("CUSTOMLIST", name, instanceUUID, projectUUID, userUUID, ct, dirStr, mc.customListDir)
		}
		activeVal := float64(len(hits))
		if activeVal > 0 {
			dynamicMetrics = append(dynamicMetrics, prometheus.MustNewConstMetric(mc.customListActiveDesc, prometheus.GaugeValue, activeVal, name, instanceUUID, projectUUID, userUUID, mc.customListDir.String()))
		}
		clVal := mc.addThreatCount(mc.customListCount, instanceUUID, float64(len(hits)))
		if clVal > 0 {
			dynamicMetrics = append(dynamicMetrics, prometheus.MustNewConstMetric(mc.customListContactDesc, prometheus.CounterValue, clVal, name, instanceUUID, projectUUID, userUUID, mc.customListDir.String()))
		}
	}

	mc.dynamicCache.Set(instanceUUID, dynamicMetrics)
}

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

func (mc *MetricsCollector) isInstanceActive(instanceUUID string) bool {
	domain, err := mc.conn.LookupDomainByUUIDString(instanceUUID)
	if err != nil || domain == nil {
		return false
	}
	defer domain.Free()
	return true
}

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

func parseInterfaceList(csv string) map[string]struct{} {
	m := make(map[string]struct{})
	for _, p := range strings.Split(csv, ",") {
		n := strings.TrimSpace(p)
		if n == "" {
			continue
		}
		m[n] = struct{}{}
	}
	return m
}

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
	var logFileEnable bool
	var logFilePath string
	var logLevelFlag string
	var outboundBehaviorEnable bool
	var hostThreatsEnable bool
	var hostIPsAllowPrivate bool
	var hostInterfacesCSV string

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
	flag.StringVar(&contactsDirection, "contacts.direction", "out", "Default direction for contact matching: out, in, any")
	flag.BoolVar(&torExitEnable, "tor.exit.enable", false, "Enable Tor exit-node detection")
	flag.StringVar(&torExitURL, "tor.exit.url", "https://onionoo.torproject.org/details?search=flag:exit&fields=or_addresses", "Unified Tor exit-node JSON")
	flag.DurationVar(&torExitRefresh, "tor.exit.refresh", time.Hour, "How often to refresh Tor exit-node list")
	flag.StringVar(&torExitDirection, "tor.exit.direction", "", "Override direction for Tor exit contacts: out, in, any (empty=default(out))")
	flag.BoolVar(&torRelayEnable, "tor.relay.enable", false, "Enable Tor relay detection")
	flag.StringVar(&torRelayURL, "tor.relay.url", "https://onionoo.torproject.org/details?search=flag:running&fields=or_addresses", "Tor relay JSON")
	flag.DurationVar(&torRelayRefresh, "tor.relay.refresh", time.Hour, "How often to refresh Tor relay list")
	flag.StringVar(&torRelayDirection, "tor.relay.direction", "", "Override direction for Tor relay contacts: out, in, any (empty=default(out))")
	flag.BoolVar(&spamEnable, "spamhaus.enable", false, "Enable Spamhaus DROP CIDR matching (IPv4 + IPv6)")
	flag.StringVar(&spamURL, "spamhaus.url", "https://www.spamhaus.org/drop/drop.txt", "Spamhaus DROP IPv4 CIDR list URL")
	flag.StringVar(&spamV6URL, "spamhaus.ipv6.url", "https://www.spamhaus.org/drop/dropv6.txt", "Spamhaus DROPv6 IPv6 CIDR list URL")
	flag.DurationVar(&spamRefresh, "spamhaus.refresh", 6*time.Hour, "Interval to refresh Spamhaus CIDR lists (IPv4 + IPv6)")
	flag.StringVar(&spamDirection, "spamhaus.direction", "", "Override direction for Spamhaus contacts: out, in, any (empty=default(out))")
	flag.BoolVar(&emThreatsEnable, "emergingthreats.enable", false, "Enable EmergingThreats compromised IP detection")
	flag.StringVar(&emThreatsURL, "emergingthreats.url", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", "URL of EmergingThreats compromised IP list")
	flag.DurationVar(&emThreatsRefresh, "emergingthreats.refresh", 6*time.Hour, "Refresh interval for EmergingThreats compromised IP list")
	flag.StringVar(&emThreatsDirection, "emergingthreats.direction", "", "Override direction for EmergingThreats contacts: out, in, any (empty=default(out))")
	flag.BoolVar(&customListEnable, "customlist.enable", false, "Enable custom user IP list detection")
	flag.StringVar(&customListPath, "customlist.path", "", "Path to file with one IP per line (IPv4 or IPv6)")
	flag.DurationVar(&customListRefresh, "customlist.refresh", 10*time.Minute, "Refresh interval for custom user IP list")
	flag.StringVar(&customListDirection, "customlist.direction", "", "Override direction for custom list contacts: out, in, any (empty=default(out))")
	flag.BoolVar(&threatFileEnable, "threatfile.enable", false, "Enable threat logging to file")
	flag.StringVar(&threatFilePath, "threatfile.path", "/var/log/openstack_instance_exporter.threat.log", "Threat log file path")
	flag.BoolVar(&logFileEnable, "log.file.enable", false, "Enable logging to file")
	flag.StringVar(&logFilePath, "log.file.path", "/var/log/openstack_instance_exporter.log", "Log file path")
	flag.StringVar(&logLevelFlag, "log.level", "error", "Log level: error, notice, info, debug")
	flag.BoolVar(&outboundBehaviorEnable, "outbound.behavior.enable", false, "Enable outbound behavior metrics")
	flag.BoolVar(&hostThreatsEnable, "host.threats.enable", false, "Enable host threat list matching on host interface IPs")
	flag.BoolVar(&hostIPsAllowPrivate, "host.ips.allow-private", false, "Include private/loopback/link-local host IPs in host threat matching")
	flag.StringVar(&hostInterfacesCSV, "host.interfaces", "", "Comma-separated interface names to check for host threat matching (default=bgp-nic when host.threats.enable)")
	flag.Parse()

	log.SetOutput(os.Stdout)
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.LUTC)

	setLogLevel(parseLogLevel(logLevelFlag))
	log.Printf("[INFO] exporter starting log.level=%s", logLevelFlag)

	if logFileEnable && logFilePath != "" {
		f, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			log.Printf("[ERROR] LOGFILE: failed to open %s: %v", logFilePath, err)
		} else {
			log.SetOutput(io.MultiWriter(os.Stdout, f))
			log.Printf("[INFO] LOGFILE: enabled path=%s", logFilePath)
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
		torExitEnable,
		torExitURL,
		torExitRefresh,
		torExitDir,
		torRelayEnable,
		torRelayURL,
		torRelayRefresh,
		torRelayDir,
		spamEnable,
		spamURL,
		spamV6URL,
		spamRefresh,
		spamDir,
		emThreatsEnable,
		emThreatsURL,
		emThreatsRefresh,
		emDir,
		customListEnable,
		customListPath,
		customListRefresh,
		customDir,
		threatFileEnable,
		threatFilePath,
		outboundBehaviorEnable,
		hostThreatsEnable,
		hostIPsAllowPrivate,
		hostInterfaces,
	)

	if err != nil {
		logError("Error creating collector: %v", err)
		return
	}

	registry := prometheus.NewRegistry()
	registry.MustRegister(
		collector,
		prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}),
		prometheus.NewGoCollector(),
		prometheus.NewBuildInfoCollector(),
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

	log.Printf("[INFO] Beginning to serve on %s", listenAddress)
	if err := http.ListenAndServe(listenAddress, nil); err != nil {
		logError("Error starting HTTP server: %v", err)
	}
}
