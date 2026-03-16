package main

import (
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func normalizeDirectionForLog(dir string) string {
	s := strings.ToLower(strings.TrimSpace(dir))
	switch s {
	case "out", "outbound", "src":
		return "outbound"
	case "in", "inbound", "dst":
		return "inbound"
	default:
		return s
	}
}

// -----------------------------------------------------------------------------
// Threat Metrics & Logging Logic
// -----------------------------------------------------------------------------
func (tm *ThreatManager) describeHostMetrics(ch chan<- *prometheus.Desc) {
	for _, p := range tm.Providers {
		ch <- p.HostRefreshLastSuccessDesc
		ch <- p.HostRefreshDurationDesc
		ch <- p.HostRefreshErrorsDesc
		ch <- p.HostEntriesDesc
	}
	ch <- tm.hostSpamhausRefreshLastSuccessTimestampDesc
	ch <- tm.hostSpamhausRefreshDurationSecondsDesc
	ch <- tm.hostSpamhausRefreshErrorsTotalDesc
	ch <- tm.hostSpamhausEntriesDesc
	ch <- tm.hostThreatListedDesc
}
func (tm *ThreatManager) collectHostThreatMetrics(hostMetrics *[]prometheus.Metric) {
	for _, p := range tm.Providers {
		appendThreatHostMetrics(hostMetrics, p.Enabled, &p.Mu, &p.LastSuccess, &p.LastDuration, &p.ErrorCount, &p.EntryCount, p.HostRefreshLastSuccessDesc, p.HostRefreshDurationDesc, p.HostRefreshErrorsDesc, p.HostEntriesDesc)
	}

	appendThreatHostMetrics(hostMetrics, tm.spamEnabled, &tm.spamMu, &tm.spamLastSuccessUnix, &tm.spamLastRefreshSeconds, &tm.spamRefreshErrors, &tm.spamEntries, tm.hostSpamhausRefreshLastSuccessTimestampDesc, tm.hostSpamhausRefreshDurationSecondsDesc, tm.hostSpamhausRefreshErrorsTotalDesc, tm.hostSpamhausEntriesDesc)

	if !tm.hostThreatsEnabled {
		return
	}

	tm.hostThreatHitsMu.RLock()
	defer tm.hostThreatHitsMu.RUnlock()

	for listName, ips := range tm.hostThreatHits {
		for ip, family := range ips {
			*hostMetrics = append(*hostMetrics,
				prometheus.MustNewConstMetric(
					tm.hostThreatListedDesc,
					prometheus.GaugeValue,
					1,
					listName,
					ip,
					family,
				),
			)
		}
	}
}
func (tm *ThreatManager) addThreatCount(m map[string]float64, mu *sync.Mutex, uuid string, delta float64) float64 {
	mu.Lock()
	defer mu.Unlock()
	prev := m[uuid]
	if delta > 0 {
		m[uuid] = prev + delta
	}
	return m[uuid]
}
func (tm *ThreatManager) shouldLogThreatHit(key string, now time.Time) bool {
	if tm.threatLogMinInterval <= 0 {
		return true
	}

	tm.threatLastHitMu.Lock()
	defer tm.threatLastHitMu.Unlock()

	last, ok := tm.threatLastHit[key]
	if !ok || now.Sub(last) >= tm.threatLogMinInterval {
		tm.threatLastHit[key] = now
		return true
	}
	return false
}
func (tm *ThreatManager) logThreatHit(
	tag string,
	domain string,
	serverName string,
	instanceUUID string,
	projectUUID string,
	projectName string,
	userUUID string,
	ct ConntrackEntry,
	dirStr string,
	listDir ContactDirection,
) {
	if listDir != ContactAny && listDir.String() != dirStr {
		return
	}
	key := fmt.Sprintf("%s|%s|%s|%s|%s", tag, instanceUUID, ct.Src, ct.Dst, dirStr)
	if !tm.shouldLogThreatHit(key, time.Now()) {
		return
	}
	logKV(LogLevelNotice, "threat", "threat", "threat_list_hit",
		"tag", tag,
		"kind", tag,
		"list", tag,
		"domain", domain,
		"server_name", serverName,
		"instance_uuid", instanceUUID,
		"project_uuid", projectUUID,
		"project_name", projectName,
		"user_uuid", userUUID,
		"src", ct.Src,
		"dst", ct.Dst,
		"direction", normalizeDirectionForLog(dirStr),
	)
}
func (tm *ThreatManager) logHostThreatHit(listName, ip, family string) {
	key := fmt.Sprintf("PROVIDER_IP_THREAT|%s|%s", listName, ip)
	if !tm.shouldLogThreatHit(key, time.Now()) {
		return
	}
	logKV(LogLevelNotice, "threat", "threat", "provider_ip_listed",
		"tag", "PROVIDER_IP_THREAT",
		"kind", listName,
		"list", listName,
		"ip", ip,
		"family", family,
	)
}
func (tm *ThreatManager) logThreatEvent(
	tag string,
	event string,
	domain string,
	instanceUUID string,
	projectUUID string,
	projectName string,
	userUUID string,
	kvpairs ...interface{},
) {
	key := fmt.Sprintf("%s|%s|%s|%s", tag, event, instanceUUID, domain)
	if !tm.shouldLogThreatHit(key, time.Now()) {
		return
	}
	category := "threat"
	if strings.EqualFold(tag, "BEHAVIOR") {
		category = "behavior"
	} else if strings.EqualFold(tag, "POLICY") {
		category = "policy"
	}
	args := make([]interface{}, 0, len(kvpairs)+12)
	args = append(args,
		"tag", tag,
		"domain", domain,
		"instance_uuid", instanceUUID,
		"project_uuid", projectUUID,
		"project_name", projectName,
		"user_uuid", userUUID,
	)
	args = append(args, kvpairs...)
	logKV(LogLevelNotice, category, "threat", event, args...)
}
func (tm *ThreatManager) cleanupThreatCounts(activeInstances map[string]struct{}) {
	for _, p := range tm.Providers {
		// Cleanup Counters
		p.CountMu.Lock()
		for uuid := range p.CountMap {
			if _, ok := activeInstances[uuid]; !ok {
				delete(p.CountMap, uuid)
			}
		}
		p.CountMu.Unlock()

		// Cleanup PrevHits (Diff State)
		p.PrevHitsMu.Lock()
		for uuid := range p.PrevHits {
			if _, ok := activeInstances[uuid]; !ok {
				delete(p.PrevHits, uuid)
			}
		}
		p.PrevHitsMu.Unlock()
	}

	// Cleanup Spamhaus Counters
	tm.spamCountMu.Lock()
	for uuid := range tm.spamCount {
		if _, ok := activeInstances[uuid]; !ok {
			delete(tm.spamCount, uuid)
		}
	}
	tm.spamCountMu.Unlock()

	// Cleanup Spamhaus PrevHits (Diff State)
	tm.spamPrevHitsMu.Lock()
	for uuid := range tm.spamPrevHits {
		if _, ok := activeInstances[uuid]; !ok {
			delete(tm.spamPrevHits, uuid)
		}
	}
	tm.spamPrevHitsMu.Unlock()
}
func (tm *ThreatManager) cleanupThreatLastHit() {
	minInterval := tm.threatLogMinInterval
	if minInterval <= 0 {
		minInterval = 5 * time.Minute
	}
	cutoff := time.Now().Add(-minInterval)
	tm.threatLastHitMu.Lock()
	for key, ts := range tm.threatLastHit {
		if ts.Before(cutoff) {
			delete(tm.threatLastHit, key)
		}
	}
	tm.threatLastHitMu.Unlock()
}
func (tm *ThreatManager) anyThreatsEnabled() bool {
	if tm.spamEnabled {
		return true
	}
	for _, p := range tm.Providers {
		if p.Enabled {
			return true
		}
	}
	return false
}

// -----------------------------------------------------------------------------
// Generic Threat Logic
// -----------------------------------------------------------------------------
func (tm *ThreatManager) exportThreatHitsCommon(
	logTag string,
	directionCfg ContactDirection,
	hits map[PairKey]ConntrackEntry,
	ipSet map[string]struct{},
	domain, serverName, instanceUUID, projectUUID, projectName, userUUID string,
	dynamicMetrics *[]prometheus.Metric,
	signal *float64,
	activeDesc *prometheus.Desc,
	totalDesc *prometheus.Desc,
	countMap map[string]float64,
	countMu *sync.Mutex,
	prevHits map[string]map[string]struct{},
	prevHitsMu *sync.Mutex,
) {
	if hits == nil {
		hits = map[PairKey]ConntrackEntry{}
	}

	ipKeySet := make(map[IPKey]struct{}, len(ipSet))
	for s := range ipSet {
		k := IPStrToKey(s)
		if k == (IPKey{}) {
			continue
		}
		ipKeySet[k] = struct{}{}
	}

	for _, ct := range hits {
		dirStr := flowDirection(ipKeySet, ct)
		tm.logThreatHit(logTag, domain, serverName, instanceUUID, projectUUID, projectName, userUUID, ct, dirStr, directionCfg)
	}

	hitCount := len(hits)

	*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(
		activeDesc,
		prometheus.GaugeValue,
		float64(hitCount),
		domain, serverName, instanceUUID, projectUUID, projectName, userUUID, directionCfg.String(),
	))

	currentKeys := make(map[string]struct{}, hitCount)
	for k := range hits {
		currentKeys[PairKeyString(k)] = struct{}{}
	}

	prevHitsMu.Lock()
	prev := prevHits[instanceUUID]
	prevHitsMu.Unlock()

	newContacts := 0
	for k := range currentKeys {
		if _, ok := prev[k]; !ok {
			newContacts++
		}
	}

	prevHitsMu.Lock()
	prevHits[instanceUUID] = currentKeys
	prevHitsMu.Unlock()

	val := tm.addThreatCount(countMap, countMu, instanceUUID, float64(newContacts))
	*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(
		totalDesc,
		prometheus.CounterValue,
		val,
		domain, serverName, instanceUUID, projectUUID, projectName, userUUID, directionCfg.String(),
	))

	if hitCount > 0 {
		*signal = clamp01(float64(hitCount) / 10.0)
	}
}
func (tm *ThreatManager) exportSpamhausHits(
	hits map[PairKey]ConntrackEntry,
	ipSet map[string]struct{},
	domain, serverName, instanceUUID, projectUUID, projectName, userUUID string,
	dynamicMetrics *[]prometheus.Metric,
	spamSignal *float64,
) {
	tm.exportThreatHitsCommon(
		"spamhaus",
		tm.spamDir,
		hits,
		ipSet,
		domain, serverName, instanceUUID, projectUUID, projectName, userUUID,
		dynamicMetrics,
		spamSignal,
		tm.instanceSpamhausActiveFlowsDesc,
		tm.instanceSpamhausContactsTotalDesc,
		tm.spamCount,
		&tm.spamCountMu,
		tm.spamPrevHits,
		&tm.spamPrevHitsMu,
	)
}
func (tm *ThreatManager) exportProviderHits(
	p *IPThreatProvider,
	hits map[PairKey]ConntrackEntry,
	ipSet map[string]struct{},
	domain, serverName, instanceUUID, projectUUID, projectName, userUUID string,
	dynamicMetrics *[]prometheus.Metric,
	signal *float64,
) {
	if p == nil {
		return
	}
	tm.exportThreatHitsCommon(
		p.LogTag,
		p.Direction,
		hits,
		ipSet,
		domain, serverName, instanceUUID, projectUUID, projectName, userUUID,
		dynamicMetrics,
		signal,
		p.InstanceActiveFlowsDesc,
		p.InstanceContactsTotalDesc,
		p.CountMap,
		&p.CountMu,
		p.PrevHits,
		&p.PrevHitsMu,
	)
}

// -----------------------------------------------------------------------------
// Threat List Checkers
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// Threat Refreshers
// -----------------------------------------------------------------------------
func appendThreatHostMetrics(
	metrics *[]prometheus.Metric,
	enabled bool,
	mu *sync.RWMutex,
	lastSuccess *float64,
	lastDuration *float64,
	errCount *uint64,
	entries *int,
	lastSuccessDesc *prometheus.Desc,
	lastDurationDesc *prometheus.Desc,
	errDesc *prometheus.Desc,
	entriesDesc *prometheus.Desc,
) {
	if !enabled {
		return
	}

	mu.RLock()
	ls := *lastSuccess
	dur := *lastDuration
	ent := *entries
	mu.RUnlock()

	ec := atomic.LoadUint64(errCount)

	*metrics = append(*metrics, prometheus.MustNewConstMetric(lastSuccessDesc, prometheus.GaugeValue, ls))
	*metrics = append(*metrics, prometheus.MustNewConstMetric(lastDurationDesc, prometheus.GaugeValue, dur))
	*metrics = append(*metrics, prometheus.MustNewConstMetric(errDesc, prometheus.GaugeValue, float64(ec)))
	*metrics = append(*metrics, prometheus.MustNewConstMetric(entriesDesc, prometheus.GaugeValue, float64(ent)))
}

// -----------------------------------------------------------------------------
// Fetcher Helpers (Extraction of original logic)
// -----------------------------------------------------------------------------
func (tm *ThreatManager) getHostIPs() []IP {
	if !tm.hostThreatsEnabled {
		return nil
	}
	out := make([]IP, 0, 16)
	seen := make(map[string]struct{})
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, iface := range ifaces {
		if len(tm.hostInterfaces) > 0 {
			if _, ok := tm.hostInterfaces[iface.Name]; !ok {
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
			if !tm.hostIPsAllowPrivate && isPrivateOrLocal(ip) {
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
func (tm *ThreatManager) setHostThreatHitsForList(listName string, hits map[string]string) {
	if !tm.hostThreatsEnabled {
		return
	}
	tm.hostThreatHitsMu.Lock()
	defer tm.hostThreatHitsMu.Unlock()
	if tm.hostThreatHits == nil {
		tm.hostThreatHits = make(map[string]map[string]string)
	}
	tm.hostThreatHits[listName] = hits
}
func (tm *ThreatManager) updateHostThreatsFromIPSet(listName string, ipSet map[IPKey]struct{}) {
	if !tm.hostThreatsEnabled {
		return
	}
	hostIPs := tm.getHostIPs()
	hits := make(map[string]string)
	for _, hip := range hostIPs {
		k := IPStrToKey(hip.Address)
		if k == (IPKey{}) {
			continue
		}
		if _, ok := ipSet[k]; ok {
			tm.logHostThreatHit(listName, hip.Address, hip.Family)
			hits[hip.Address] = hip.Family
		}
	}
	tm.setHostThreatHitsForList(listName, hits)
}
func (tm *ThreatManager) updateHostThreatsFromCIDRs(listName string, nets []*net.IPNet) {
	if !tm.hostThreatsEnabled {
		return
	}
	hostIPs := tm.getHostIPs()
	hits := make(map[string]string)
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
			tm.logHostThreatHit(listName, hip.Address, hip.Family)
			hits[hip.Address] = hip.Family
		}
	}
	tm.setHostThreatHitsForList(listName, hits)
}
