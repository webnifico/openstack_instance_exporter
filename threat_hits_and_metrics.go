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
	if !ok || now.Before(last) || now.Sub(last) >= tm.threatLogMinInterval {
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
	kind := ""
	for i := 0; i+1 < len(kvpairs); i += 2 {
		name, ok := kvpairs[i].(string)
		if ok && name == "kind" {
			kind = fmt.Sprint(kvpairs[i+1])
			break
		}
	}
	key := fmt.Sprintf("%s|%s|%s|%s|%s", tag, event, instanceUUID, domain, kind)
	if !tm.shouldLogThreatHit(key, time.Now()) {
		return
	}
	category := "threat"
	if strings.EqualFold(tag, "BEHAVIOR") {
		category = "behavior"
	} else if strings.EqualFold(tag, "POLICY") {
		category = "policy"
	}
	component := category
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
	logKV(LogLevelNotice, category, component, event, args...)
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

func (tm *ThreatManager) freshThreatSources(now time.Time) (bool, []*IPThreatProvider) {
	if tm == nil {
		return false, nil
	}
	tm.spamMu.RLock()
	spamFresh := tm.spamEnabled && tm.spamEntries > 0 && threatFeedFresh(tm.spamLastSuccessUnix, tm.spamRefresh, now)
	tm.spamMu.RUnlock()
	providers := make([]*IPThreatProvider, 0, len(tm.Providers))
	for _, p := range tm.Providers {
		if p == nil || !p.Enabled {
			continue
		}
		p.Mu.RLock()
		entries := p.EntryCount
		p.Mu.RUnlock()
		if entries > 0 && p.feedFresh(now) {
			providers = append(providers, p)
		}
	}
	return spamFresh, providers
}

// -----------------------------------------------------------------------------
// Generic Threat Logic
// -----------------------------------------------------------------------------
func (tm *ThreatManager) exportThreatHitsCommon(
	logTag string,
	directionCfg ContactDirection,
	hits map[PairKey]ConntrackEntry,
	droppedHits uint64,
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
	updateState bool,
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

	if updateState {
		for _, ct := range hits {
			dirStr := flowDirection(ipKeySet, ct)
			tm.logThreatHit(logTag, domain, serverName, instanceUUID, projectUUID, projectName, userUUID, ct, dirStr, directionCfg)
		}
	}

	activeHitCount := float64(len(hits)) + float64(droppedHits)

	*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(
		activeDesc,
		prometheus.GaugeValue,
		activeHitCount,
		domain, serverName, instanceUUID, projectUUID, projectName, userUUID, directionCfg.String(),
	))

	currentKeys := make(map[string]struct{}, len(hits))
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

	if updateState {
		prevHitsMu.Lock()
		prevHits[instanceUUID] = currentKeys
		prevHitsMu.Unlock()
	}

	if !updateState {
		newContacts = 0
	}
	val := tm.addThreatCount(countMap, countMu, instanceUUID, float64(newContacts))
	*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(
		totalDesc,
		prometheus.CounterValue,
		val,
		domain, serverName, instanceUUID, projectUUID, projectName, userUUID, directionCfg.String(),
	))

	if activeHitCount > 0 {
		*signal = clamp01(activeHitCount / 10.0)
	}
}
func (tm *ThreatManager) exportSpamhausHits(
	hits map[PairKey]ConntrackEntry,
	droppedHits uint64,
	ipSet map[string]struct{},
	domain, serverName, instanceUUID, projectUUID, projectName, userUUID string,
	dynamicMetrics *[]prometheus.Metric,
	spamSignal *float64,
	updateState bool,
) {
	tm.exportThreatHitsCommon(
		"spamhaus",
		tm.spamDir,
		hits,
		droppedHits,
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
		updateState,
	)
}
func (tm *ThreatManager) exportProviderHits(
	p *IPThreatProvider,
	hits map[PairKey]ConntrackEntry,
	droppedHits uint64,
	ipSet map[string]struct{},
	domain, serverName, instanceUUID, projectUUID, projectName, userUUID string,
	dynamicMetrics *[]prometheus.Metric,
	signal *float64,
	updateState bool,
) {
	if p == nil {
		return
	}
	tm.exportThreatHitsCommon(
		p.LogTag,
		p.Direction,
		hits,
		droppedHits,
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
		updateState,
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
	*metrics = append(*metrics, prometheus.MustNewConstMetric(errDesc, prometheus.CounterValue, float64(ec)))
	*metrics = append(*metrics, prometheus.MustNewConstMetric(entriesDesc, prometheus.GaugeValue, float64(ent)))
}

// -----------------------------------------------------------------------------
// Fetcher Helpers (Extraction of original logic)
// -----------------------------------------------------------------------------
func (tm *ThreatManager) getHostIPs() []IP {
	return tm.discoverHostIPs(tm.hostThreatsEnabled, tm.hostIPsAllowPrivate)
}

func (tm *ThreatManager) getBehaviorHostIPs() []IP {
	return tm.discoverHostIPsWithFilter(true, true, nil)
}

func (tm *ThreatManager) discoverHostIPs(enabled, allowPrivate bool) []IP {
	return tm.discoverHostIPsWithFilter(enabled, allowPrivate, tm.hostInterfaces)
}

func (tm *ThreatManager) discoverHostIPsWithFilter(enabled, allowPrivate bool, interfaceFilter map[string]struct{}) []IP {
	if !enabled {
		return nil
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return []IP{}
	}
	return discoverHostIPsFromInterfaces(ifaces, func(iface net.Interface) ([]net.Addr, error) {
		return iface.Addrs()
	}, allowPrivate, interfaceFilter)
}

func discoverHostIPsFromInterfaces(ifaces []net.Interface, interfaceAddrs func(net.Interface) ([]net.Addr, error), allowPrivate bool, interfaceFilter map[string]struct{}) []IP {
	out := make([]IP, 0, 16)
	seen := make(map[string]struct{})
	for _, iface := range ifaces {
		if len(interfaceFilter) > 0 {
			if _, ok := interfaceFilter[iface.Name]; !ok {
				continue
			}
		}
		if (iface.Flags & net.FlagUp) == 0 {
			continue
		}
		addrs, err := interfaceAddrs(iface)
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
			if !allowPrivate && isPrivateOrLocal(ip) {
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
