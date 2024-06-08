package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/vishvananda/netlink"
)

// Constants
const bytesToGigabytes = 1.0 / (1024 * 1024 * 1024)
const bytesToMegabytes = 1.0 / (1024 * 1024)

// -----------------------------------------------------------------------------
// Logging Logic
// -----------------------------------------------------------------------------

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

	logAppApp                = NewComponentLogger("app", "app")
	logCollectorApp          = NewComponentLogger("app", "collector")
	logCollectorMetric       = NewComponentLogger("metric", "collector")
	logConntrackMetric       = NewComponentLogger("metric", "conntrack")
	logCustomlistThreat      = NewComponentLogger("threat", "customlist")
	logEmergingthreatsThreat = NewComponentLogger("threat", "emergingthreats")
	logHttpApp               = NewComponentLogger("app", "http")
	logLoggingApp            = NewComponentLogger("app", "logging")
	logSpamhausThreat        = NewComponentLogger("threat", "spamhaus")
	logThreatfileThreat      = NewComponentLogger("threat", "threatfile")
	logTorexitThreat         = NewComponentLogger("threat", "torexit")
	logTorrelayThreat        = NewComponentLogger("threat", "torrelay")
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
	currentLogLevel = l
	logLevelMu.Unlock()
}

func getLogLevel() LogLevel {
	logLevelMu.RLock()
	defer logLevelMu.RUnlock()
	return currentLogLevel
}

func logLevelString(l LogLevel) string {
	switch l {
	case LogLevelDebug:
		return "debug"
	case LogLevelInfo:
		return "info"
	case LogLevelNotice:
		return "notice"
	default:
		return "error"
	}
}

func formatLogLine(level, category, msg string, kvpairs ...interface{}) string {
	b := &strings.Builder{}
	ts := time.Now().UTC().Format(time.RFC3339Nano)

	b.WriteString("ts=")
	b.WriteString(ts)
	b.WriteString(" level=")
	b.WriteString(level)
	b.WriteString(" category=")
	b.WriteString(category)
	b.WriteString(" msg=")
	b.WriteString(strconv.Quote(msg))

	for i := 0; i+1 < len(kvpairs); i += 2 {
		key, ok := kvpairs[i].(string)
		if !ok || key == "" {
			continue
		}
		v := kvpairs[i+1]
		b.WriteByte(' ')
		b.WriteString(key)
		b.WriteByte('=')

		switch val := v.(type) {
		case int, int8, int16, int32, int64,
			uint, uint8, uint16, uint32, uint64,
			float32, float64:
			b.WriteString(fmt.Sprint(val))
		case bool:
			if val {
				b.WriteString("true")
			} else {
				b.WriteString("false")
			}
		default:
			b.WriteString(strconv.Quote(fmt.Sprint(val)))
		}
	}

	return b.String()
}

func logEvent(level LogLevel, category string, msg string, kvpairs ...interface{}) {
	if getLogLevel() < level {
		return
	}
	hasTag := false
	hasEvent := false
	for i := 0; i+1 < len(kvpairs); i += 2 {
		key, ok := kvpairs[i].(string)
		if !ok {
			continue
		}
		if key == "tag" {
			hasTag = true
		}
		if key == "event" {
			hasEvent = true
		}
	}
	aug := make([]interface{}, 0, len(kvpairs)+4)
	aug = append(aug, kvpairs...)

	if !hasTag {
		var tag string
		switch category {
		case "metric":
			tag = "metric"
		case "threat", "threat_behavior":
			tag = "threat"
		default:
			tag = "app"
		}
		aug = append(aug, "tag", tag)
	}
	if !hasEvent {
		aug = append(aug, "event", msg)
	}
	line := formatLogLine(logLevelString(level), category, msg, aug...)
	log.Print(line)
}

func logKV(level LogLevel, category, msg string, kvpairs ...interface{}) {
	logEvent(level, category, msg, kvpairs...)
}

type ComponentLogger struct {
	category  string
	component string
}

func NewComponentLogger(category, component string) ComponentLogger {
	return ComponentLogger{category: category, component: component}
}

func (l ComponentLogger) Debug(msg string, kvpairs ...interface{}) {
	base := append([]interface{}{"component", l.component}, kvpairs...)
	logKV(LogLevelDebug, l.category, msg, base...)
}

func (l ComponentLogger) Info(msg string, kvpairs ...interface{}) {
	base := append([]interface{}{"component", l.component}, kvpairs...)
	logKV(LogLevelInfo, l.category, msg, base...)
}

func (l ComponentLogger) Notice(msg string, kvpairs ...interface{}) {
	base := append([]interface{}{"component", l.component}, kvpairs...)
	logKV(LogLevelNotice, l.category, msg, base...)
}

func (l ComponentLogger) Error(msg string, kvpairs ...interface{}) {
	base := append([]interface{}{"component", l.component}, kvpairs...)
	logKV(LogLevelError, l.category, msg, base...)
}

// -----------------------------------------------------------------------------
// Utility Functions
// -----------------------------------------------------------------------------

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

// isInfrastructureIP checks for metadata/link-local and Host IPs
func isInfrastructureIP(ipStr string, hostIPs []string) bool {
	// 1. FAST PATH: String Prefix Check

	// IPv4 Link-Local (169.254.x.x) - OVN Metadata
	if strings.HasPrefix(ipStr, "169.254.") {
		return true
	}

	// IPv6 Link-Local UNICAST (fe80:...)
	// We deliberately ignore ff02: (Multicast) here to allow chatty NDP traffic.
	// Multicast storms are handled by the generic storm check in Priority 4.
	if strings.HasPrefix(ipStr, "fe80:") || strings.HasPrefix(ipStr, "FE80:") {
		return true
	}

	// Check against Host IPs (String Match is fast)
	for _, h := range hostIPs {
		if h == ipStr {
			return true
		}
	}

	return false
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

// -----------------------------------------------------------------------------
// Host System Info & Conntrack Logic
// -----------------------------------------------------------------------------

func hostTotalMemBytes() uint64 {
	var si syscall.Sysinfo_t
	if err := syscall.Sysinfo(&si); err != nil {
		return 0
	}
	return si.Totalram * uint64(si.Unit)
}

func hostConntrackMax() uint64 {
	data, err := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_max")
	if err != nil {
		return 0
	}
	s := strings.TrimSpace(string(data))
	if s == "" {
		return 0
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0
	}
	return v
}

// Conntrack Manager Implementation

func (cm *ConntrackManager) readConntrack() ([]ConntrackEntry, error) {
	var (
		flows4 []*netlink.ConntrackFlow
		flows6 []*netlink.ConntrackFlow
		err4   error
		err6   error
		wg     sync.WaitGroup
	)

	wg.Add(2)
	go func() {
		defer wg.Done()
		flows4, err4 = netlink.ConntrackTableList(netlink.ConntrackTable, netlink.InetFamily(syscall.AF_INET))
	}()

	go func() {
		defer wg.Done()
		flows6, err6 = netlink.ConntrackTableList(netlink.ConntrackTable, netlink.InetFamily(syscall.AF_INET6))
	}()

	wg.Wait()

	if err4 != nil && err6 != nil {
		return nil, fmt.Errorf("conntrack netlink read failed: v4=%v v6=%v", err4, err6)
	}

	capHint := 0
	if err4 == nil {
		capHint += len(flows4)
	}
	if err6 == nil {
		capHint += len(flows6)
	}

	entries := make([]ConntrackEntry, 0, capHint)

	processFlows := func(flows []*netlink.ConntrackFlow) {
		for _, f := range flows {
			if f.Forward.SrcIP == nil && f.Forward.DstIP == nil {
				continue
			}

			// INFER STATUS via packet counts
			status := uint32(0)
			if f.Reverse.Packets > 0 {
				status |= IPS_SEEN_REPLY
			}
			if f.Forward.Packets > 0 && f.Reverse.Packets > 0 {
				status |= IPS_ASSURED
			}

			var src, dst string
			if f.Forward.SrcIP != nil {
				src = f.Forward.SrcIP.String()
			}
			if f.Forward.DstIP != nil {
				dst = f.Forward.DstIP.String()
			}

			e := ConntrackEntry{
				Src:     src,
				Dst:     dst,
				SrcPort: uint16(f.Forward.SrcPort),
				DstPort: uint16(f.Forward.DstPort),
				Proto:   uint8(f.Forward.Protocol),
				Status:  status,
				Zone:    0,
				Bytes:   f.Forward.Bytes,
				Packets: f.Forward.Packets,
			}
			entries = append(entries, e)
		}
	}

	if err4 == nil {
		processFlows(flows4)
	}
	if err6 == nil {
		processFlows(flows6)
	}

	return entries, nil
}

func (cm *ConntrackManager) cleanupBehaviorMaps(activeSet map[string]struct{}) {
	cm.outboundMu.Lock()
	for k := range cm.outboundPrev {
		// Optimization: Access struct field directly instead of string split
		if _, ok := activeSet[k.InstanceUUID]; !ok {
			delete(cm.outboundPrev, k)
		}
	}
	for k := range cm.outboundPrevDstPorts {
		if _, ok := activeSet[k.InstanceUUID]; !ok {
			delete(cm.outboundPrevDstPorts, k)
		}
	}
	cm.outboundMu.Unlock()

	cm.inboundMu.Lock()
	for k := range cm.inboundPrev {
		if _, ok := activeSet[k.InstanceUUID]; !ok {
			delete(cm.inboundPrev, k)
		}
	}
	for k := range cm.inboundPrevDstPorts {
		if _, ok := activeSet[k.InstanceUUID]; !ok {
			delete(cm.inboundPrevDstPorts, k)
		}
	}
	cm.inboundMu.Unlock()
}

func (cm *ConntrackManager) describeConntrackMetrics(ch chan<- *prometheus.Desc) {
	ch <- cm.instanceConntrackIPFlowsDesc
	ch <- cm.instanceConntrackIPFlowsInboundDesc
	ch <- cm.instanceConntrackIPFlowsOutboundDesc
	ch <- cm.instanceOutboundUniqueRemotesDesc
	ch <- cm.instanceOutboundNewRemotesDesc
	ch <- cm.instanceOutboundFlowsDesc
	ch <- cm.instanceOutboundMaxFlowsSingleRemoteDesc
	ch <- cm.instanceOutboundUniqueDstPortsDesc
	ch <- cm.instanceOutboundNewDstPortsDesc
	ch <- cm.instanceOutboundMaxFlowsSingleDstPortDesc
	ch <- cm.instanceInboundUniqueRemotesDesc
	ch <- cm.instanceInboundNewRemotesDesc
	ch <- cm.instanceInboundFlowsDesc
	ch <- cm.instanceInboundMaxFlowsSingleRemoteDesc
	ch <- cm.instanceInboundUniqueDstPortsDesc
	ch <- cm.instanceInboundNewDstPortsDesc
	ch <- cm.instanceInboundMaxFlowsSingleDstPortDesc
}

func (cm *ConntrackManager) calculateConntrackMetrics(
	fixedIPs []IP,
	ipFlows map[string][]ConntrackEntry,
	ipSet map[string]struct{},
	hostIPs []string,
	name, instanceUUID, projectUUID, projectName, userUUID string,
	dynamicMetrics *[]prometheus.Metric,
) (float64, float64, int) {

	var (
		outboundSignal float64
		inboundSignal  float64
		maxConntrack   int
		maxIn          int
		maxOut         int
	)

	outStatsMap := make(map[string]*behaviorStats)
	inStatsMap := make(map[string]*behaviorStats)

	for _, ip := range fixedIPs {
		addr := ip.Address
		if cm.outboundBehaviorEnabled {
			outStatsMap[addr] = newBehaviorStats()
		}
		if cm.inboundBehaviorEnabled {
			inStatsMap[addr] = newBehaviorStats()
		}
	}

	perIPFlowsIn := make(map[string]int)
	perIPFlowsOut := make(map[string]int)

	for _, ip := range fixedIPs {
		addr := ip.Address
		flows := ipFlows[addr]

		for _, ct := range flows {
			srcIsVM := ct.Src == addr
			dstIsVM := ct.Dst == addr

			if srcIsVM {
				perIPFlowsOut[addr]++
				if s, ok := outStatsMap[addr]; ok {
					s.updateDetailed(ct.Dst, ct.DstPort, ct.Proto, ct)
				}
			}
			if dstIsVM {
				perIPFlowsIn[addr]++
				if s, ok := inStatsMap[addr]; ok {
					s.updateDetailed(ct.Src, ct.DstPort, ct.Proto, ct)
				}
			}
		}

		if perIPFlowsIn[addr] > maxIn {
			maxIn = perIPFlowsIn[addr]
		}
		if perIPFlowsOut[addr] > maxOut {
			maxOut = perIPFlowsOut[addr]
		}
	}

	maxConntrack = maxIn
	if maxOut > maxConntrack {
		maxConntrack = maxOut
	}

	ctx := BehaviorContext{HostIPs: hostIPs}

	for _, ip := range fixedIPs {
		addr := ip.Address
		in := perIPFlowsIn[addr]
		out := perIPFlowsOut[addr]
		total := in + out

		if total > 0 {
			*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(cm.instanceConntrackIPFlowsDesc, prometheus.GaugeValue, float64(total), name, instanceUUID, addr, ip.Family, projectUUID, projectName, userUUID))
		}
		if in > 0 {
			*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(cm.instanceConntrackIPFlowsInboundDesc, prometheus.GaugeValue, float64(in), name, instanceUUID, addr, ip.Family, projectUUID, projectName, userUUID))
		}
		if out > 0 {
			*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(cm.instanceConntrackIPFlowsOutboundDesc, prometheus.GaugeValue, float64(out), name, instanceUUID, addr, ip.Family, projectUUID, projectName, userUUID))
		}

		if s, ok := outStatsMap[addr]; ok {
			descs := metricDescGroup{
				uniqueRemotes:      cm.instanceOutboundUniqueRemotesDesc,
				newRemotes:         cm.instanceOutboundNewRemotesDesc,
				flows:              cm.instanceOutboundFlowsDesc,
				maxSingleRemote:    cm.instanceOutboundMaxFlowsSingleRemoteDesc,
				uniqueDstPorts:     cm.instanceOutboundUniqueDstPortsDesc,
				newDstPorts:        cm.instanceOutboundNewDstPortsDesc,
				maxSingleDstPort:   cm.instanceOutboundMaxFlowsSingleDstPortDesc,
				thresholdConfigKey: "outbound",
			}
			// Passing ip.Family to analyzeBehavior
			sig := cm.analyzeBehavior(s, addr, ip.Family, name, instanceUUID, projectUUID, projectName, userUUID, dynamicMetrics, &cm.outboundMu, cm.outboundPrev, cm.outboundPrevDstPorts, descs, ipSet, ctx)
			outboundSignal = sig
		}

		if s, ok := inStatsMap[addr]; ok {
			descs := metricDescGroup{
				uniqueRemotes:      cm.instanceInboundUniqueRemotesDesc,
				newRemotes:         cm.instanceInboundNewRemotesDesc,
				flows:              cm.instanceInboundFlowsDesc,
				maxSingleRemote:    cm.instanceInboundMaxFlowsSingleRemoteDesc,
				uniqueDstPorts:     cm.instanceInboundUniqueDstPortsDesc,
				newDstPorts:        cm.instanceInboundNewDstPortsDesc,
				maxSingleDstPort:   cm.instanceInboundMaxFlowsSingleDstPortDesc,
				thresholdConfigKey: "inbound",
			}
			// Passing ip.Family to analyzeBehavior
			sig := cm.analyzeBehavior(s, addr, ip.Family, name, instanceUUID, projectUUID, projectName, userUUID, dynamicMetrics, &cm.inboundMu, cm.inboundPrev, cm.inboundPrevDstPorts, descs, ipSet, ctx)
			inboundSignal = sig
		}
	}

	return outboundSignal, inboundSignal, maxConntrack
}

// -----------------------------------------------------------------------------
// Behavior Logic
// -----------------------------------------------------------------------------

func newBehaviorStats() *behaviorStats {
	return &behaviorStats{
		remotes:    make(map[string]struct{}),
		perRemote:  make(map[string]int),
		dstPorts:   make(map[uint16]struct{}),
		perDstPort: make(map[uint16]int),
	}
}

func (b *behaviorStats) updateDetailed(remote string, port uint16, proto uint8, ct ConntrackEntry) {
	b.flows++
	b.bytes += ct.Bytes
	b.packets += ct.Packets

	if (ct.Status&IPS_SEEN_REPLY) == 0 && (ct.Status&IPS_ASSURED) == 0 {
		b.unreplied++
	}

	// MEMORY SAFETY: Saturating Counter Cap
	// If the map is full (5,000 IPs), stop adding new keys.
	// We still increment b.flows (above), so Volume Detection is 100% accurate.
	const maxRemoteMapSize = 5000

	if len(b.remotes) < maxRemoteMapSize {
		b.remotes[remote] = struct{}{}
		b.perRemote[remote]++
	} else {
		// Even if map is full, check if this specific remote ALREADY exists.
		if _, exists := b.remotes[remote]; exists {
			b.perRemote[remote]++
		}
	}

	if port != 0 {
		b.dstPorts[port] = struct{}{}
		b.perDstPort[port]++
	}

	ip := net.ParseIP(remote)
	if ip != nil && ip.IsMulticast() {
		b.multicastCount++
	}
	if proto == 1 || proto == 58 {
		b.icmpCount++
	}

	if b.sampleRemote == "" {
		b.sampleRemote = remote
		if port != 0 {
			b.sampleDstPort = port
		}
	}
}

func (cm *ConntrackManager) analyzeBehavior(
	s *behaviorStats,
	addr, family, name, instanceUUID, projectUUID, projectName, userUUID string,
	dynamicMetrics *[]prometheus.Metric,
	mu *sync.Mutex,
	prevRemotesMap map[BehaviorKey]outboundPrev,
	prevPortsMap map[BehaviorKey]outboundPrevDstPorts,
	descs metricDescGroup,
	ipSet map[string]struct{},
	ctx BehaviorContext,
) float64 {

	// 1. DYNAMIC IMPACT ASSESSMENT
	hostMax := hostConntrackMax()
	hostImpact := 0.0
	if hostMax > 0 {
		hostImpact = float64(s.flows) / float64(hostMax)
	}

	var tFlows int
	if descs.thresholdConfigKey == "outbound" {
		tFlows = cm.behaviorThresholds.OutboundFlowsTotal
	} else {
		tFlows = cm.behaviorThresholds.InboundFlowsTotal
	}

	significance := 0.0
	if tFlows > 0 {
		significance = float64(s.flows) / float64(tFlows)
		if significance > 1.0 {
			significance = 1.0
		}
	}

	unrepliedRatio := 0.0
	if s.flows > 0 {
		unrepliedRatio = float64(s.unreplied) / float64(s.flows)
	}

	// -------------------------------------------------------------------------
	// 1. REMOTE IP ANALYSIS
	// -------------------------------------------------------------------------
	uniqueRemotes := len(s.remotes)

	// Remotes Caching (Fan-out detection)
	newRemotes := 0

	// OPTIMIZATION: Use BehaviorKey struct instead of string concatenation
	key := BehaviorKey{InstanceUUID: instanceUUID, IP: addr}

	mu.Lock()
	if prev, ok := prevRemotesMap[key]; ok {
		for r := range s.remotes {
			if _, exists := prev.remotes[r]; !exists {
				newRemotes++
			}
		}
	} else {
		newRemotes = uniqueRemotes
	}
	prevRemotesMap[key] = outboundPrev{remotes: s.remotes}
	mu.Unlock()

	// Find Max Flows to Single Remote
	maxSingleRemote := 0
	for _, count := range s.perRemote {
		if count > maxSingleRemote {
			maxSingleRemote = count
		}
	}

	// -------------------------------------------------------------------------
	// 2. DESTINATION PORT ANALYSIS
	// -------------------------------------------------------------------------
	uniqueDstPorts := len(s.dstPorts)
	newDstPorts := 0

	// Ports Caching (New Port detection)
	mu.Lock()
	if prev, ok := prevPortsMap[key]; ok {
		for p := range s.dstPorts {
			if _, exists := prev.ports[p]; !exists {
				newDstPorts++
			}
		}
	} else {
		newDstPorts = uniqueDstPorts
	}
	prevPortsMap[key] = outboundPrevDstPorts{ports: s.dstPorts}
	mu.Unlock()

	// Find Max Flows to Single Port
	maxSingleDstPort := 0
	for _, count := range s.perDstPort {
		if count > maxSingleDstPort {
			maxSingleDstPort = count
		}
	}

	// -------------------------------------------------------------------------
	// 3. EXPORT METRICS
	// -------------------------------------------------------------------------
	if dynamicMetrics != nil {
		// Remote IP Metrics
		if descs.uniqueRemotes != nil {
			*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(descs.uniqueRemotes, prometheus.GaugeValue, float64(uniqueRemotes), name, instanceUUID, addr, family, projectUUID, projectName, userUUID))
		}
		if descs.newRemotes != nil {
			*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(descs.newRemotes, prometheus.GaugeValue, float64(newRemotes), name, instanceUUID, addr, family, projectUUID, projectName, userUUID))
		}
		if descs.maxSingleRemote != nil {
			*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(descs.maxSingleRemote, prometheus.GaugeValue, float64(maxSingleRemote), name, instanceUUID, addr, family, projectUUID, projectName, userUUID))
		}
		// Destination Port Metrics
		if descs.uniqueDstPorts != nil {
			*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(descs.uniqueDstPorts, prometheus.GaugeValue, float64(uniqueDstPorts), name, instanceUUID, addr, family, projectUUID, projectName, userUUID))
		}
		if descs.newDstPorts != nil {
			*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(descs.newDstPorts, prometheus.GaugeValue, float64(newDstPorts), name, instanceUUID, addr, family, projectUUID, projectName, userUUID))
		}
		if descs.maxSingleDstPort != nil {
			*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(descs.maxSingleDstPort, prometheus.GaugeValue, float64(maxSingleDstPort), name, instanceUUID, addr, family, projectUUID, projectName, userUUID))
		}
		// Flow Count Metric
		if descs.flows != nil {
			*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(descs.flows, prometheus.GaugeValue, float64(s.flows), name, instanceUUID, addr, family, projectUUID, projectName, userUUID))
		}
	}

	// EWMA Baseline Logic
	// OPTIMIZATION: Use AnomalyKey struct for behavior state lookup
	anomalyKey := AnomalyKey{BehaviorKey: key, ThresholdKey: descs.thresholdConfigKey}
	state := cm.getBehaviorState(anomalyKey)

	deviation := 0.0
	stdDev := 0.0
	if state.SampleCount > 5 {
		stdDev = math.Sqrt(state.FlowVariance)
		if stdDev > 0 {
			deviation = (float64(s.flows) - state.AvgFlows) / stdDev
		}
	}
	alpha := 0.1
	diff := float64(s.flows) - state.AvgFlows
	state.AvgFlows += alpha * diff
	state.FlowVariance = (1 - alpha) * (state.FlowVariance + alpha*diff*diff)
	state.SampleCount++

	// -------------------------------------------------------------------------
	// PRIORITY LOGIC ENGINE (Renumbered 0-5)
	// -------------------------------------------------------------------------
	impactFactor := hostImpact * 50.0
	weightedDeviation := deviation * impactFactor

	hitAlert := false
	kind := ""
	reason := ""
	priority := 0

	// P0: INFRASTRUCTURE ABUSE (Host/Metadata)
	if descs.thresholdConfigKey == "outbound" && s.flows > 10 {
		for r := range s.remotes {
			// OPTIMIZED CHECK: String prefix matching
			if isInfrastructureIP(r, ctx.HostIPs) {
				if s.perRemote[r] > 50 {
					hitAlert = true
					kind = "infrastructure_abuse_critical"
					reason = "targeting_host_control_plane"
					priority = 0
					break
				}
			}
		}
	}

	// P1: LOCAL AGGRESSION (Neighbor Scanning)
	if !hitAlert && descs.thresholdConfigKey == "outbound" && s.flows > 50 {
		localScanHits := 0
		for r := range s.remotes {
			if _, isLocal := ipSet[r]; isLocal {
				localScanHits++
			}
		}
		if localScanHits > 5 && unrepliedRatio > 0.5 {
			hitAlert = true
			kind = "local_aggression_east_west"
			reason = "neighbor_scan_unreplied"
			priority = 1 // Renumbered from 2
		}
	}

	// P2: PUBLIC SCANNING (Internet)
	if !hitAlert && descs.thresholdConfigKey == "outbound" {
		if unrepliedRatio > 0.80 && uniqueRemotes > 20 && s.flows > 100 {
			if significance > 0.1 {
				hitAlert = true
				kind = "public_network_scan_unreplied"
				reason = fmt.Sprintf("unreplied_ratio_%.2f", unrepliedRatio)
				priority = 2 // Renumbered from 3
			}
		}
	}

	// P3: CAPACITY BREACH (Boiling Frog / Hard Ceiling)
	if !hitAlert && significance > 2.0 {
		hitAlert = true
		kind = "capacity_limit_exceeded_200pct"
		reason = fmt.Sprintf("flows_%d_exceeds_limit_%d", s.flows, tFlows)
		priority = 3 // Renumbered from 3.5
	}

	// P4: FLOOD / ANOMALY (Statistical Volume)
	if !hitAlert && weightedDeviation > 3.0 {
		hitAlert = true
		kind = "traffic_anomaly_volume"
		reason = fmt.Sprintf("z_score_%.1f_impact_%.2f%%", deviation, hostImpact*100)
		priority = 4

		if s.icmpCount > 50 {
			kind = "icmp_flood"
		} else if s.multicastCount > 50 {
			kind = "multicast_storm"
		} else if descs.thresholdConfigKey == "inbound" {
			kind = "resource_pressure_inbound"
		} else if unrepliedRatio < 0.2 {
			// P5: ZOMBIE FLOW / APPLICATION LEAK (Low Throughput)
			avgBytes := float64(0)
			if s.flows > 0 {
				avgBytes = float64(s.bytes) / float64(s.flows)
			}
			if avgBytes < 1000 {
				kind = "application_connection_leak"
				reason = "high_volume_low_throughput_established"
				priority = 5
			}
		}
	}

	if hitAlert {
		msg := fmt.Sprintf("Alert: %s detected (Flows: %d, Unreplied: %.0f%%, Impact: %.2f%%)", kind, s.flows, unrepliedRatio*100, hostImpact*100)
		var srcIP, dstIP string
		if descs.thresholdConfigKey == "outbound" {
			srcIP = addr
			dstIP = s.sampleRemote
		} else {
			srcIP = s.sampleRemote
			dstIP = addr
		}

		if cm.LogThreat != nil {
			cm.LogThreat("BEHAVIOR", "behavior_alert",
				name, instanceUUID, projectUUID, projectName, userUUID,
				"kind", kind,
				"reason", reason,
				"msg", msg,
				"flows_current", s.flows,
				"host_impact_percent", roundToFiveDecimals(hostImpact*100),
				"sigma_deviation", roundToFiveDecimals(deviation),
				"src_ip", srcIP,
				"dst_ip", dstIP,
				"priority", priority,
			)
		} else {
			logThreatfileThreat.Notice("behavior_alert",
				"domain", name,
				"kind", kind,
				"msg", msg,
				"instance_uuid", instanceUUID,
				"flows_current", s.flows,
			)
		}
	}

	pressure := clamp01(math.Log10(1 + 9*hostImpact))
	finalDeviationScore := 0.0
	if deviation > 0 {
		rawZ := clamp01(0.1 * deviation)
		finalDeviationScore = rawZ * impactFactor
		if finalDeviationScore > 1.0 {
			finalDeviationScore = 1.0
		}
	}

	severity := clamp01(pressure + finalDeviationScore)
	return severity
}

func (cm *ConntrackManager) getBehaviorState(key AnomalyKey) *AnomalyState {
	cm.behaviorStateMu.Lock()
	defer cm.behaviorStateMu.Unlock()

	if s, ok := cm.behaviorState[key]; ok {
		return s
	}
	s := &AnomalyState{}
	cm.behaviorState[key] = s
	return s
}

func (cm *ConntrackManager) cleanupBehaviorState(activeSet map[string]struct{}) {
	cm.behaviorStateMu.Lock()
	defer cm.behaviorStateMu.Unlock()

	for k := range cm.behaviorState {
		// Optimization: Access struct field directly
		if _, ok := activeSet[k.BehaviorKey.InstanceUUID]; !ok {
			delete(cm.behaviorState, k)
		}
	}
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
