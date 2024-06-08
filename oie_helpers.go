package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/yaml.v3"
)

const bytesToGigabytes = 1.0 / (1024 * 1024 * 1024)
const bytesToMegabytes = 1.0 / (1024 * 1024)

func appendConstMetric(metrics *[]prometheus.Metric, desc *prometheus.Desc, valueType prometheus.ValueType, value float64, labels ...string) {
	*metrics = append(*metrics, prometheus.MustNewConstMetric(desc, valueType, value, labels...))
}

// -----------------------------------------------------------------------------
// Utility Functions
// -----------------------------------------------------------------------------

// shardIndex calculates a deterministic shard (0..shardCount-1) for a given string.
func shardIndex(s string) int {
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return int(h % uint32(shardCount))
}

// shardIndexBehavior calculates a deterministic shard (0..shardCount-1) for a behavior identity key.
func shardIndexBehavior(k behaviorIdentityKey) int {
	var h uint32 = 2166136261
	for i := 0; i < len(k.InstanceUUID); i++ {
		h ^= uint32(k.InstanceUUID[i])
		h *= 16777619
	}
	for i := 0; i < len(k.IP); i++ {
		h ^= uint32(k.IP[i])
		h *= 16777619
	}
	for i := 0; i < len(k.Direction); i++ {
		h ^= uint32(k.Direction[i])
		h *= 16777619
	}
	return int(h % uint32(shardCount))
}

func roundToFiveDecimals(value float64) float64 {
	return math.Round(value*100000) / 100000
}

func clamp01(value float64) float64 {
	if value < 0 {
		return 0
	}
	if value > 1 {
		return 1
	}
	return value
}

func clampInt01To100(value int) int {
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	return value
}

func ewmaAlpha(dtSeconds, tauSeconds float64) float64 {
	if dtSeconds <= 0 || tauSeconds <= 0 {
		return 1
	}
	return 1 - math.Exp(-dtSeconds/tauSeconds)
}

func parseDiskType(sourceName string) (string, string) {
	parts := strings.Split(sourceName, "/")
	if len(parts) > 1 {
		return parts[0], parts[1]
	}
	return "unknown", "unknown"
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
	if ip16[0]&0xfe == 0xfc { // Unique Local Unicast
		return true
	}
	return false
}

func MakePairKey(a, b IPKey) PairKey {
	if compareIPKey(a, b) <= 0 {
		return PairKey{A: a, B: b}
	}
	return PairKey{A: b, B: a}
}

func compareIPKey(a, b IPKey) int {
	for i := 0; i < 16; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

func PairKeyString(pk PairKey) string {
	// Use EncodeToString for broad Go version compatibility.
	return hex.EncodeToString(pk.A[:]) + "|" + hex.EncodeToString(pk.B[:])
}

func isPrivateOrLocalStr(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	return isPrivateOrLocal(ip)
}

// isInfrastructureIP checks for metadata/link-local and Host IPs
func isInfrastructureIP(ipStr string, hostIPs map[string]struct{}) bool {
	if _, ok := hostIPs[ipStr]; ok {
		return true
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 169 && ip4[1] == 254 {
			return true
		}
		return false
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return false
	}
	if ip16[0] == 0xfe && ip16[1] == 0x80 {
		return true
	}
	return false
}

func isInfrastructureKey(k IPKey, hostIPKeys map[IPKey]struct{}) bool {
	if hostIPKeys != nil {
		if _, ok := hostIPKeys[k]; ok {
			return true
		}
	}
	if isIPv4MappedKey(k) {
		if k[12] == 169 && k[13] == 254 {
			return true
		}
		return false
	}
	if k[0] == 0xfe && (k[1]&0xc0) == 0x80 {
		return true
	}
	return false
}

var metadataServiceKey = V4ToKey([4]byte{169, 254, 169, 254})

func metadataServiceIPKey() IPKey {
	return metadataServiceKey
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

// -----------------------------------------------------------------------------
// IP Key Helpers
// -----------------------------------------------------------------------------

func V4BytesToKey(b []byte) IPKey {
	var k IPKey
	if len(b) < 4 {
		return k
	}
	k[10] = 0xff
	k[11] = 0xff
	copy(k[12:16], b[:4])
	return k
}

func V4ToKey(b [4]byte) IPKey {
	return V4BytesToKey(b[:])
}

func V6BytesToKey(b []byte) IPKey {
	var k IPKey
	if len(b) < 16 {
		return k
	}
	copy(k[:], b[:16])
	return k
}

func V6ToKey(b [16]byte) IPKey {
	return V6BytesToKey(b[:])
}

func IPToKey(ip net.IP) IPKey {
	if ip == nil {
		return IPKey{}
	}
	if ip4 := ip.To4(); ip4 != nil {
		return V4BytesToKey(ip4)
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return IPKey{}
	}
	return V6BytesToKey(ip16)
}

func AddrToKey(addr netip.Addr) IPKey {
	if !addr.IsValid() {
		return IPKey{}
	}
	if addr.Is4() {
		v4 := addr.As4()
		return V4ToKey(v4)
	}
	v6 := addr.As16()
	return V6ToKey(v6)
}

func IPStrToKey(s string) IPKey {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return IPKey{}
	}
	return AddrToKey(addr)
}

func isIPv4MappedKey(k IPKey) bool {
	if k[10] != 0xff || k[11] != 0xff {
		return false
	}
	for i := 0; i < 10; i++ {
		if k[i] != 0 {
			return false
		}
	}
	return true
}

func IPKeyToAddr(k IPKey) netip.Addr {
	a := netip.AddrFrom16(k)
	if a.Is4In6() {
		a = a.Unmap()
	}
	return a
}

func IPKeyToString(k IPKey) string {
	return IPKeyToAddr(k).String()
}

func isPrivateOrLocalKey(k IPKey) bool {
	addr := IPKeyToAddr(k)
	if addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
		return true
	}
	if addr.IsPrivate() {
		return true
	}
	return false
}

func isLocalOnlyKey(k IPKey) bool {
	addr := IPKeyToAddr(k)
	if addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
		return true
	}
	return false
}

func isMulticastKey(k IPKey) bool {
	return IPKeyToAddr(k).IsMulticast()
}

// -----------------------------------------------------------------------------
// Metric Descriptor Helpers
// -----------------------------------------------------------------------------

var (
	instanceMetricLabels                      = []string{"domain", "instance_uuid", "user_uuid", "project_uuid", "project_name"}
	threatDomainInstanceDirectionMetricLabels = []string{"domain", "instance_uuid", "project_uuid", "project_name", "user_uuid", "direction"}
	instanceSeverityMetricLabels              = []string{"domain", "instance_uuid", "project_uuid", "project_name", "user_uuid"}
	instanceConntrackMetricLabels             = []string{"domain", "instance_uuid", "ip", "family", "project_uuid", "project_name", "user_uuid"}
)

func newHostMetricDesc(name, help string) *prometheus.Desc {
	return prometheus.NewDesc(name, help, nil, nil)
}

func newInstanceMetricDesc(name, help string) *prometheus.Desc {
	return prometheus.NewDesc(name, help, instanceMetricLabels, nil)
}

func newThreatDomainInstanceDirectionDesc(name, help string) *prometheus.Desc {
	return prometheus.NewDesc(name, help, threatDomainInstanceDirectionMetricLabels, nil)
}

func newInstanceSeverityMetricDesc(name, help string) *prometheus.Desc {
	return prometheus.NewDesc(name, help, instanceSeverityMetricLabels, nil)
}

func newInstanceConntrackMetricDesc(name, help string) *prometheus.Desc {
	return prometheus.NewDesc(name, help, instanceConntrackMetricLabels, nil)
}

type behaviorPortsConfigFile struct {
	Behavior struct {
		Ports struct {
			InboundMonitored  map[int]string `yaml:"inbound_monitored"`
			OutboundMonitored map[int]string `yaml:"outbound_monitored"`
		} `yaml:"ports"`
	} `yaml:"behavior"`
}

func copyPortNameMap(in map[uint16]string) map[uint16]string {
	out := make(map[uint16]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
func builtinBehaviorInboundMonitoredPorts() map[uint16]string {
	return map[uint16]string{
		// --- Remote Access & Infrastructure ---
		20:   "ftp_data",
		21:   "ftp",
		22:   "ssh",
		23:   "telnet",
		69:   "tftp",
		514:  "syslog",
		873:  "rsync",
		3389: "rdp",
		5900: "vnc",
		5601: "kibana",
		5985: "winrm",
		5986: "winrm_tls",

		// --- Active Directory & Windows Enterprise ---
		88:   "kerberos",
		135:  "msrpc",
		137:  "netbios_ns",
		138:  "netbios_dgm",
		139:  "netbios_ssn",
		389:  "ldap",
		445:  "smb",
		464:  "kpasswd",
		636:  "ldaps",
		3268: "ldap_gc",
		3269: "ldap_gc_ssl",

		// --- Cloud Native, Containers & Orchestration ---
		2375:  "docker",
		2376:  "docker_tls",
		2379:  "etcd_client",
		2380:  "etcd_server",
		4646:  "nomad_http",
		5000:  "docker_registry",
		6443:  "k8s_api",
		8200:  "vault",
		8500:  "consul",
		10250: "k8s_kubelet",
		10255: "k8s_kubelet_readonly",
		10256: "k8s_health",

		// --- Databases & Data Stores ---
		1433:  "mssql",
		1521:  "oracle",
		2049:  "nfs",
		2181:  "zookeeper",
		3306:  "mysql",
		4333:  "mnsql",
		5432:  "postgres",
		5672:  "rabbitmq",
		5984:  "couchdb",
		6379:  "redis",
		7000:  "cassandra_intra",
		7001:  "cassandra_tls",
		7474:  "neo4j",
		8086:  "influxdb",
		9042:  "cassandra_client",
		9092:  "kafka",
		9200:  "elasticsearch",
		9300:  "elasticsearch_transport",
		11211: "memcached",
		27017: "mongodb",

		// --- Web, Proxy & Load Balancing ---
		80:   "http",
		443:  "https",
		3128: "squid_proxy",
		8000: "http_alt_8000",
		8008: "http_alt_8008",
		8080: "http_alt",
		8443: "https_alt",
		8888: "http_alt_8888",
		9090: "prometheus",

		// --- Mail Services ---
		25:  "smtp",
		110: "pop3",
		143: "imap",
		465: "smtps",
		587: "submission",
		993: "imaps",
		995: "pop3s",

		// --- VPN, Tunneling & Network Services ---
		53:   "dns",
		179:  "bgp",
		111:  "rpcbind",
		123:  "ntp",
		161:  "snmp",
		500:  "ike",
		1194: "openvpn",
		1701: "l2tp",
		1723: "pptp",
		4500: "ipsec_nat",
		6081: "geneve",
		5353: "mdns",

		// --- High Risk / Reflection / Legacy ---
		19:   "chargen",
		1900: "ssdp",
		6667: "irc",
	}
}

func builtinBehaviorOutboundMonitoredPorts() map[uint16]string {
	return map[uint16]string{
		// --- Standard Outbound Traffic ---
		21:  "ftp",
		22:  "ssh",
		25:  "smtp",
		53:  "dns",
		179: "bgp",
		67:  "dhcp_server",
		68:  "dhcp_client",
		80:  "http",
		123: "ntp",
		443: "https",

		// --- Suspicious Indicators ---
		23:   "telnet",
		69:   "tftp",
		1080: "socks_proxy",
		3128: "squid_proxy",
		3389: "rdp",
		3333: "stratum",
		4444: "stratum_alt",
		5900: "vnc",
		6667: "irc",
		8080: "http_alt",
		8888: "http_alt_8888",
		9001: "tor_orport",
		9050: "tor_socks",
		9418: "git",
		6081: "geneve",
		8333: "stratum_alt_8333",

		// --- Lateral Movement Indicators ---
		88:    "kerberos",
		111:   "rpcbind",
		135:   "msrpc",
		137:   "netbios_ns",
		389:   "ldap",
		445:   "smb",
		514:   "syslog_exfil",
		5985:  "winrm",
		6443:  "k8s_api",
		10250: "k8s_kubelet",

		// --- Mail & Messaging ---
		110: "pop3",
		143: "imap",
		465: "smtps",
		587: "submission",
		993: "imaps",
		995: "pop3s",

		// --- Data Stores ---
		1433:  "mssql",
		1521:  "oracle",
		2049:  "nfs",
		3306:  "mysql",
		5432:  "postgres",
		6379:  "redis",
		9200:  "elasticsearch",
		27017: "mongodb",
	}
}

func validateBehaviorPortMap(in map[int]string) (map[uint16]string, error) {
	out := make(map[uint16]string, len(in))
	for port, name := range in {
		if port <= 0 || port > 65535 {
			return nil, fmt.Errorf("invalid port %d", port)
		}
		n := strings.TrimSpace(name)
		if n == "" {
			return nil, fmt.Errorf("empty name for port %d", port)
		}
		out[uint16(port)] = n
	}
	return out, nil
}

func BuildBehaviorPortMaps(path string) (map[uint16]string, map[uint16]string, BehaviorPortsConfigStatus) {
	builtinIn := builtinBehaviorInboundMonitoredPorts()
	builtinOut := builtinBehaviorOutboundMonitoredPorts()

	status := BehaviorPortsConfigStatus{Path: path}

	p := strings.TrimSpace(path)
	if p == "" {
		status.Status = "not_configured"
		status.Using = "builtin"
		status.InboundPorts = len(builtinIn)
		status.OutboundPorts = len(builtinOut)
		return builtinIn, builtinOut, status
	}

	b, err := os.ReadFile(p)
	if err != nil {
		status.Status = "missing"
		status.Using = "builtin"
		status.Err = err.Error()
		status.InboundPorts = len(builtinIn)
		status.OutboundPorts = len(builtinOut)
		return builtinIn, builtinOut, status
	}

	var cfg behaviorPortsConfigFile
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		status.Status = "parse_error"
		status.Using = "builtin"
		status.Err = err.Error()
		status.InboundPorts = len(builtinIn)
		status.OutboundPorts = len(builtinOut)
		return builtinIn, builtinOut, status
	}

	inProvided := len(cfg.Behavior.Ports.InboundMonitored) > 0
	outProvided := len(cfg.Behavior.Ports.OutboundMonitored) > 0

	if !inProvided && !outProvided {
		status.Status = "invalid"
		status.Using = "builtin"
		status.Err = "no inbound_monitored or outbound_monitored ports defined"
		status.InboundPorts = len(builtinIn)
		status.OutboundPorts = len(builtinOut)
		return builtinIn, builtinOut, status
	}

	inMap := builtinIn
	outMap := builtinOut

	if inProvided {
		parsed, err := validateBehaviorPortMap(cfg.Behavior.Ports.InboundMonitored)
		if err != nil {
			status.Status = "invalid"
			status.Using = "builtin"
			status.Err = err.Error()
			status.InboundPorts = len(builtinIn)
			status.OutboundPorts = len(builtinOut)
			return builtinIn, builtinOut, status
		}
		inMap = parsed
	}

	if outProvided {
		parsed, err := validateBehaviorPortMap(cfg.Behavior.Ports.OutboundMonitored)
		if err != nil {
			status.Status = "invalid"
			status.Using = "builtin"
			status.Err = err.Error()
			status.InboundPorts = len(builtinIn)
			status.OutboundPorts = len(builtinOut)
			return builtinIn, builtinOut, status
		}
		outMap = parsed
	}

	status.Status = "loaded"
	if inProvided && outProvided {
		status.Using = "file"
	} else {
		status.Using = "mixed"
	}
	status.InboundPorts = len(inMap)
	status.OutboundPorts = len(outMap)

	return inMap, outMap, status
}

// OVNMapper maps conntrack zones -> instance UUIDs
type OVNMapper struct {
	sync.RWMutex
	refreshMu      sync.Mutex
	zoneToInstance map[uint16]string
	zoneToIPs      map[uint16]map[IPKey]struct{}
	socketPath     string
	lastRefresh    time.Time
}

func NewOVNMapper() *OVNMapper {
	return &OVNMapper{
		zoneToInstance: make(map[uint16]string),
		zoneToIPs:      make(map[uint16]map[IPKey]struct{}),
	}
}

func (m *OVNMapper) Refresh(instanceByPort map[string]string, ipsByPort map[string][]IPKey) error {
	now := time.Now()

	m.RLock()
	last := m.lastRefresh
	m.RUnlock()

	if now.Sub(last) < 30*time.Second {
		return nil
	}

	m.refreshMu.Lock()
	defer m.refreshMu.Unlock()

	now = time.Now()

	m.RLock()
	last = m.lastRefresh
	sock := m.socketPath
	m.RUnlock()

	if now.Sub(last) < 30*time.Second {
		return nil
	}

	if sock == "" {
		found, err := pickOvnControllerCtlSocket()
		if err != nil {
			logCollectorMetric.Error("ovn_socket_lookup_failed", "err", err)
			return err
		}
		sock = found
		m.Lock()
		m.socketPath = sock
		m.Unlock()
		logCollectorMetric.Info("ovn_socket_found", "path", sock)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ovs-appctl", "-t", sock, "ct-zone-list")
	out, err := cmd.Output()
	if err != nil {
		m.Lock()
		m.socketPath = ""
		m.Unlock()

		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("ovn zone refresh timeout")
		}
		return fmt.Errorf("ovn zone refresh failed: %w", err)
	}

	newZones := make(map[uint16]string)
	newIPs := make(map[uint16]map[IPKey]struct{})

	for _, line := range bytes.Split(out, []byte{'\n'}) {
		fields := strings.Fields(string(line))
		if len(fields) != 2 {
			continue
		}

		portUUID := fields[0]
		if len(portUUID) != 36 {
			continue
		}

		instanceUUID, ok := instanceByPort[portUUID]
		if !ok {
			continue
		}

		zone := parseUint16(fields[1])
		if zone == 0 {
			continue
		}

		newZones[zone] = instanceUUID
		if len(ipsByPort) > 0 {
			if ips, okIPs := ipsByPort[portUUID]; okIPs && len(ips) > 0 {
				set := make(map[IPKey]struct{}, len(ips))
				for _, k := range ips {
					if k == (IPKey{}) {
						continue
					}
					set[k] = struct{}{}
				}
				if len(set) > 0 {
					newIPs[zone] = set
				}
			}
		}
	}

	logKV(LogLevelDebug, "ovn_mapper", "refresh_success", "zones_found", len(newZones))
	m.Lock()
	m.zoneToInstance = newZones
	m.zoneToIPs = newIPs
	now = time.Now()
	m.lastRefresh = now
	m.Unlock()

	return nil
}

func (m *OVNMapper) GetInstance(zone uint16) string {
	m.RLock()
	defer m.RUnlock()
	return m.zoneToInstance[zone]
}

func (m *OVNMapper) GetIPs(zone uint16) map[IPKey]struct{} {
	m.RLock()
	defer m.RUnlock()
	return m.zoneToIPs[zone]
}

func pickOvnControllerCtlSocket() (string, error) {
	dirs := []string{
		"/run/ovn",
		"/var/run/ovn",
		"/run/openvswitch",
		"/var/run/openvswitch",
	}

	for _, d := range dirs {
		p := filepath.Join(d, "ovn-controller.ctl")
		if isSocket(p) {
			return p, nil
		}
	}

	for _, d := range dirs {
		matches, _ := filepath.Glob(filepath.Join(d, "ovn-controller.*.ctl"))
		for _, p := range matches {
			if isSocket(p) {
				return p, nil
			}
		}
	}

	return "", errors.New("ovn-controller ctl socket not found")
}

func isSocket(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeSocket) != 0
}

func parseUint16(s string) uint16 {
	var v uint64
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0
		}
		v = v*10 + uint64(s[i]-'0')
		if v > 65535 {
			return 0
		}
	}
	return uint16(v)
}
