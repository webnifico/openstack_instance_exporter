package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
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

func initThreatMetrics(tm *ThreatManager) {
	// Initialize Generic Providers
	for _, p := range tm.Providers {
		p.InstanceContactsTotalDesc = newThreatDomainInstanceDirectionDesc(p.InstanceContactsMetricName, fmt.Sprintf("Total %s contacts for this instance (presence over intervals)", p.Name))
		p.InstanceActiveFlowsDesc = newThreatDomainInstanceDirectionDesc(p.InstanceActiveMetricName, fmt.Sprintf("Active %s flows for this instance", p.Name))
		p.HostRefreshLastSuccessDesc = newHostMetricDesc(p.HostRefreshLastMetricName, fmt.Sprintf("Last successful %s refresh (unix timestamp)", p.Name))
		p.HostRefreshDurationDesc = newHostMetricDesc(p.HostRefreshDurationMetricName, fmt.Sprintf("Duration of last %s refresh in seconds", p.Name))
		p.HostRefreshErrorsDesc = newHostMetricDesc(p.HostRefreshErrorsMetricName, fmt.Sprintf("Total %s refresh errors", p.Name))
		p.HostEntriesDesc = newHostMetricDesc(p.HostEntriesMetricName, fmt.Sprintf("Number of %s IPs currently loaded", p.Name))
	}

	// Initialize Spamhaus (Special Case: CIDRs)
	tm.instanceSpamhausContactsTotalDesc = newThreatDomainInstanceDirectionDesc("oie_instance_threat_spamhaus_contacts_total", "Total Spamhaus DROP contacts for this instance (presence over intervals)")
	tm.instanceSpamhausActiveFlowsDesc = newThreatDomainInstanceDirectionDesc("oie_instance_threat_spamhaus_active_flows", "Active Spamhaus DROP flows for this instance")
	tm.hostSpamhausRefreshLastSuccessTimestampDesc = newHostMetricDesc("oie_host_threat_spamhaus_refresh_last_success_timestamp_seconds", "Last successful Spamhaus list refresh (unix timestamp)")
	tm.hostSpamhausRefreshDurationSecondsDesc = newHostMetricDesc("oie_host_threat_spamhaus_refresh_duration_seconds", "Duration of last Spamhaus list refresh in seconds")
	tm.hostSpamhausRefreshErrorsTotalDesc = newHostMetricDesc("oie_host_threat_spamhaus_refresh_errors_total", "Total Spamhaus list refresh errors")
	tm.hostSpamhausEntriesDesc = newHostMetricDesc("oie_host_threat_spamhaus_entries", "Number of Spamhaus CIDRs currently loaded")

	tm.hostThreatListedDesc = prometheus.NewDesc("oie_host_threat_provider_ip_listed", "Provider-owned host IP present in a threat list (1 = member)", []string{"list", "ip", "family"}, nil)
}

func (tm *ThreatManager) describeThreatMetrics(ch chan<- *prometheus.Desc) {
	for _, p := range tm.Providers {
		ch <- p.InstanceContactsTotalDesc
		ch <- p.InstanceActiveFlowsDesc
	}
	ch <- tm.instanceSpamhausContactsTotalDesc
	ch <- tm.instanceSpamhausActiveFlowsDesc
}

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
	logKV(LogLevelNotice, "threat", "threat_list_hit",
		"tag", tag,
		"kind", tag,
		"list", tag,
		"domain", domain,
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
	logKV(LogLevelNotice, "threat", "provider_ip_listed",
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
	logKV(LogLevelNotice, category, event, args...)
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
	cutoff := time.Now().Add(-5 * time.Minute)
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
	domain, instanceUUID, projectUUID, projectName, userUUID string,
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

	for _, ct := range hits {
		dirStr := flowDirection(ipSet, ct)
		tm.logThreatHit(logTag, domain, instanceUUID, projectUUID, projectName, userUUID, ct, dirStr, directionCfg)
	}

	hitCount := len(hits)

	*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(
		activeDesc,
		prometheus.GaugeValue,
		float64(hitCount),
		domain, instanceUUID, projectUUID, projectName, userUUID, directionCfg.String(),
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
		domain, instanceUUID, projectUUID, projectName, userUUID, directionCfg.String(),
	))

	if hitCount > 0 {
		*signal = clamp01(float64(hitCount) / 10.0)
	}
}

func (tm *ThreatManager) exportSpamhausHits(
	hits map[PairKey]ConntrackEntry,
	ipSet map[string]struct{},
	domain, instanceUUID, projectUUID, projectName, userUUID string,
	dynamicMetrics *[]prometheus.Metric,
	spamSignal *float64,
) {
	tm.exportThreatHitsCommon(
		"spamhaus",
		tm.spamDir,
		hits,
		ipSet,
		domain, instanceUUID, projectUUID, projectName, userUUID,
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
	domain, instanceUUID, projectUUID, projectName, userUUID string,
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
		domain, instanceUUID, projectUUID, projectName, userUUID,
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

func (tm *ThreatManager) runProviderRefresher(p *IPThreatProvider) {
	refreshOnce := func() {
		start := time.Now()
		fresh, err := p.Fetcher()
		if err != nil {
			atomic.AddUint64(&p.ErrorCount, 1)
			p.Logger.Error(strings.ToLower(p.Name)+"_refresh_failed", "err", err)
			return
		}
		dur := time.Since(start).Seconds()
		nowUnix := float64(time.Now().Unix())
		p.Mu.Lock()
		p.Set = fresh
		p.SetAtomic.Store(fresh)
		p.LastSuccess = nowUnix
		p.LastDuration = dur
		p.EntryCount = len(fresh)
		p.Mu.Unlock()
		p.Logger.Info(strings.ToLower(p.Name)+"_refresh", "ips_total", len(fresh))
		tm.updateHostThreatsFromIPSet(p.LogTag, fresh)
	}

	refreshOnce()
	if p.RefreshInterval <= 0 {
		<-tm.shutdownChan
		return
	}

	for {
		t := time.NewTimer(p.RefreshInterval)
		select {
		case <-tm.shutdownChan:
			t.Stop()
			return
		case <-t.C:
		}
		refreshOnce()
	}
}
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

func (tm *ThreatManager) fetchOnionoo(url string) (map[IPKey]struct{}, error) {
	resp, err := tm.httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d for %s", resp.StatusCode, url)
	}
	var data OnionooSummary
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}
	fresh := make(map[IPKey]struct{})
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
			if i := strings.IndexByte(host, '%'); i >= 0 {
				host = host[:i]
			}
			addr, err := netip.ParseAddr(host)
			if err != nil {
				continue
			}
			fresh[AddrToKey(addr)] = struct{}{}
		}
	}
	return fresh, nil
}

func (tm *ThreatManager) fetchURLLines(url string) (map[IPKey]struct{}, error) {
	resp, err := tm.httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d for %s", resp.StatusCode, url)
	}
	return scanIPLines(resp.Body)
}

func (tm *ThreatManager) fetchFileLines(path string) (map[IPKey]struct{}, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return scanIPLines(f)
}

func scanIPLines(r io.Reader) (map[IPKey]struct{}, error) {
	scanner := bufio.NewScanner(r)
	fresh := make(map[IPKey]struct{})
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.IndexByte(line, '%'); i >= 0 {
			line = line[:i]
		}
		addr, err := netip.ParseAddr(line)
		if err != nil {
			continue
		}
		fresh[AddrToKey(addr)] = struct{}{}
	}
	return fresh, scanner.Err()
}

func (tm *ThreatManager) startSpamhausRefresher() {
	tm.refreshSpamhausList()
	if tm.spamRefresh <= 0 {
		<-tm.shutdownChan
		return
	}
	for {
		t := time.NewTimer(tm.spamRefresh)
		select {
		case <-tm.shutdownChan:
			t.Stop()
			return
		case <-t.C:
		}
		tm.refreshSpamhausList()
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

		_, netIP, err := net.ParseCIDR(cidrStr)
		if err != nil {
			continue
		}
		nets = append(nets, netIP)
	}

	return nets, scanner.Err()
}

func (tm *ThreatManager) refreshSpamhausList() {
	start := time.Now()

	fetchOne := func(url string) ([]*net.IPNet, error) {
		resp, err := tm.httpClient.Get(url)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("http %d for %s", resp.StatusCode, url)
		}
		nets, err := parseSpamhausCIDRs(resp.Body)
		if err != nil {
			return nil, err
		}
		if len(nets) == 0 {
			return nil, fmt.Errorf("empty list from %s", url)
		}
		return nets, nil
	}

	var (
		nets4 []*net.IPNet
		nets6 []*net.IPNet
		err4  error
		err6  error
	)

	if tm.spamURL != "" {
		nets4, err4 = fetchOne(tm.spamURL)
		if err4 != nil {
			atomic.AddUint64(&tm.spamRefreshErrors, 1)
			logSpamhausThreat.Error("spamhaus_v4_refresh_failed", "err", err4)
		}
	}
	if tm.spamV6URL != "" {
		nets6, err6 = fetchOne(tm.spamV6URL)
		if err6 != nil {
			atomic.AddUint64(&tm.spamRefreshErrors, 1)
			logSpamhausThreat.Error("spamhaus_v6_refresh_failed", "err", err6)
		}
	}

	if len(nets4) == 0 && len(nets6) == 0 {
		return
	}

	bucketsV4 := make(map[uint16][]*net.IPNet)
	wideV4 := make([]*net.IPNet, 0, 8)
	for _, n := range nets4 {
		ones, bits := n.Mask.Size()
		if bits != 32 {
			continue
		}
		if ones < 16 {
			wideV4 = append(wideV4, n)
			continue
		}
		ip4 := n.IP.To4()
		if ip4 == nil || len(ip4) != 4 {
			continue
		}
		key := uint16(ip4[0])<<8 | uint16(ip4[1])
		bucketsV4[key] = append(bucketsV4[key], n)
	}

	bucketsV6 := make(map[uint32][]*net.IPNet)
	wideV6 := make([]*net.IPNet, 0, 8)
	for _, n := range nets6 {
		ones, bits := n.Mask.Size()
		if bits != 128 {
			continue
		}
		if ones < 32 {
			wideV6 = append(wideV6, n)
			continue
		}
		ip16 := n.IP.To16()
		if ip16 == nil || len(ip16) != 16 {
			continue
		}
		key := (uint32(ip16[0]) << 24) | (uint32(ip16[1]) << 16) | (uint32(ip16[2]) << 8) | uint32(ip16[3])
		bucketsV6[key] = append(bucketsV6[key], n)
	}

	dur := time.Since(start).Seconds()
	nowUnix := float64(time.Now().Unix())

	var combined []*net.IPNet

	tm.spamMu.Lock()
	if len(nets4) > 0 {
		tm.spamNetsV4 = nets4
		tm.spamBucketsV4 = bucketsV4
		tm.spamWideV4 = wideV4
	}
	if len(nets6) > 0 {
		tm.spamNetsV6 = nets6
		tm.spamBucketsV6 = bucketsV6
		tm.spamWideV6 = wideV6
	}
	tm.spamLastSuccessUnix = nowUnix
	tm.spamLastRefreshSeconds = dur
	tm.spamEntries = len(tm.spamNetsV4) + len(tm.spamNetsV6)

	combined = make([]*net.IPNet, 0, tm.spamEntries)
	combined = append(combined, tm.spamNetsV4...)
	combined = append(combined, tm.spamNetsV6...)
	tm.spamMu.Unlock()

	tm.updateHostThreatsFromCIDRs("spamhaus", combined)
	logSpamhausThreat.Info("spamhaus_refresh", "v4_nets", len(nets4), "v6_nets", len(nets6), "nets_total", len(combined))
}

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
