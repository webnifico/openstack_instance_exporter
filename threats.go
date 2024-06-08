package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// -----------------------------------------------------------------------------
// Threat Metrics & Logging Logic
// -----------------------------------------------------------------------------

func initThreatMetrics(tm *ThreatManager) {
	tm.instanceTorExitContactsTotalDesc = prometheus.NewDesc("oie_instance_threat_tor_exit_contacts_total", "Total Tor exit-node contacts for this instance (presence over intervals)", []string{"domain", "instance_uuid", "project_uuid", "project_name", "user_uuid", "direction"}, nil)
	tm.instanceTorExitActiveFlowsDesc = prometheus.NewDesc("oie_instance_threat_tor_exit_active_flows", "Active Tor exit-node flows for this instance", []string{"domain", "instance_uuid", "project_uuid", "project_name", "user_uuid", "direction"}, nil)
	tm.instanceTorRelayContactsTotalDesc = prometheus.NewDesc("oie_instance_threat_tor_relay_contacts_total", "Total Tor relay-node contacts for this instance (presence over intervals)", []string{"domain", "instance_uuid", "project_uuid", "project_name", "user_uuid", "direction"}, nil)
	tm.instanceTorRelayActiveFlowsDesc = prometheus.NewDesc("oie_instance_threat_tor_relay_active_flows", "Active Tor relay-node flows for this instance", []string{"domain", "instance_uuid", "project_uuid", "project_name", "user_uuid", "direction"}, nil)
	tm.instanceSpamhausContactsTotalDesc = prometheus.NewDesc("oie_instance_threat_spamhaus_contacts_total", "Total Spamhaus DROP contacts for this instance (presence over intervals)", []string{"domain", "instance_uuid", "project_uuid", "project_name", "user_uuid", "direction"}, nil)
	tm.instanceSpamhausActiveFlowsDesc = prometheus.NewDesc("oie_instance_threat_spamhaus_active_flows", "Active Spamhaus DROP flows for this instance", []string{"domain", "instance_uuid", "project_uuid", "project_name", "user_uuid", "direction"}, nil)
	tm.instanceEmergingThreatsContactsTotalDesc = prometheus.NewDesc("oie_instance_threat_emergingthreats_contacts_total", "Total EmergingThreats contacts for this instance (presence over intervals)", []string{"domain", "instance_uuid", "project_uuid", "project_name", "user_uuid", "direction"}, nil)
	tm.instanceEmergingThreatsActiveFlowsDesc = prometheus.NewDesc("oie_instance_threat_emergingthreats_active_flows", "Active EmergingThreats flows for this instance", []string{"domain", "instance_uuid", "project_uuid", "project_name", "user_uuid", "direction"}, nil)
	tm.instanceCustomlistContactsTotalDesc = prometheus.NewDesc("oie_instance_threat_customlist_contacts_total", "Total custom list contacts for this instance (presence over intervals)", []string{"domain", "instance_uuid", "project_uuid", "project_name", "user_uuid", "direction"}, nil)
	tm.instanceCustomlistActiveFlowsDesc = prometheus.NewDesc("oie_instance_threat_customlist_active_flows", "Active custom list flows for this instance", []string{"domain", "instance_uuid", "project_uuid", "project_name", "user_uuid", "direction"}, nil)

	tm.hostTorExitRefreshLastSuccessTimestampDesc = prometheus.NewDesc("oie_host_threat_tor_exit_refresh_last_success_timestamp_seconds", "Last successful Tor exit-node list refresh (unix timestamp)", nil, nil)
	tm.hostTorExitRefreshDurationSecondsDesc = prometheus.NewDesc("oie_host_threat_tor_exit_refresh_duration_seconds", "Duration of last Tor exit-node list refresh in seconds", nil, nil)
	tm.hostTorExitRefreshErrorsTotalDesc = prometheus.NewDesc("oie_host_threat_tor_exit_refresh_errors_total", "Total Tor exit-node list refresh errors", nil, nil)
	tm.hostTorExitEntriesDesc = prometheus.NewDesc("oie_host_threat_tor_exit_entries", "Number of Tor exit-node IPs currently loaded", nil, nil)

	tm.hostTorRelayRefreshLastSuccessTimestampDesc = prometheus.NewDesc("oie_host_threat_tor_relay_refresh_last_success_timestamp_seconds", "Last successful Tor relay list refresh (unix timestamp)", nil, nil)
	tm.hostTorRelayRefreshDurationSecondsDesc = prometheus.NewDesc("oie_host_threat_tor_relay_refresh_duration_seconds", "Duration of last Tor relay list refresh in seconds", nil, nil)
	tm.hostTorRelayRefreshErrorsTotalDesc = prometheus.NewDesc("oie_host_threat_tor_relay_refresh_errors_total", "Total Tor relay list refresh errors", nil, nil)
	tm.hostTorRelayEntriesDesc = prometheus.NewDesc("oie_host_threat_tor_relay_entries", "Number of Tor relay IPs currently loaded", nil, nil)

	tm.hostSpamhausRefreshLastSuccessTimestampDesc = prometheus.NewDesc("oie_host_threat_spamhaus_refresh_last_success_timestamp_seconds", "Last successful Spamhaus list refresh (unix timestamp)", nil, nil)
	tm.hostSpamhausRefreshDurationSecondsDesc = prometheus.NewDesc("oie_host_threat_spamhaus_refresh_duration_seconds", "Duration of last Spamhaus list refresh in seconds", nil, nil)
	tm.hostSpamhausRefreshErrorsTotalDesc = prometheus.NewDesc("oie_host_threat_spamhaus_refresh_errors_total", "Total Spamhaus list refresh errors", nil, nil)
	tm.hostSpamhausEntriesDesc = prometheus.NewDesc("oie_host_threat_spamhaus_entries", "Number of Spamhaus CIDRs currently loaded", nil, nil)

	tm.hostEmergingThreatsRefreshLastSuccessTimestampDesc = prometheus.NewDesc("oie_host_threat_emergingthreats_refresh_last_success_timestamp_seconds", "Last successful EmergingThreats list refresh (unix timestamp)", nil, nil)
	tm.hostEmergingThreatsRefreshDurationSecondsDesc = prometheus.NewDesc("oie_host_threat_emergingthreats_refresh_duration_seconds", "Duration of last EmergingThreats list refresh in seconds", nil, nil)
	tm.hostEmergingThreatsRefreshErrorsTotalDesc = prometheus.NewDesc("oie_host_threat_emergingthreats_refresh_errors_total", "Total EmergingThreats list refresh errors", nil, nil)
	tm.hostEmergingThreatsEntriesDesc = prometheus.NewDesc("oie_host_threat_emergingthreats_entries", "Number of EmergingThreats IPs currently loaded", nil, nil)

	tm.hostCustomlistRefreshLastSuccessTimestampDesc = prometheus.NewDesc("oie_host_threat_customlist_refresh_last_success_timestamp_seconds", "Last successful custom list refresh (unix timestamp)", nil, nil)
	tm.hostCustomlistRefreshDurationSecondsDesc = prometheus.NewDesc("oie_host_threat_customlist_refresh_duration_seconds", "Duration of last custom list refresh in seconds", nil, nil)
	tm.hostCustomlistRefreshErrorsTotalDesc = prometheus.NewDesc("oie_host_threat_customlist_refresh_errors_total", "Total custom list refresh errors", nil, nil)
	tm.hostCustomlistEntriesDesc = prometheus.NewDesc("oie_host_threat_customlist_entries", "Number of custom list IPs currently loaded", nil, nil)

	tm.hostThreatListedDesc = prometheus.NewDesc("oie_host_threat_provider_ip_listed", "Provider-owned host IP present in a threat list (1 = member)", []string{"list", "ip", "family"}, nil)
}

func (tm *ThreatManager) describeThreatMetrics(ch chan<- *prometheus.Desc) {
	ch <- tm.instanceTorExitContactsTotalDesc
	ch <- tm.instanceTorExitActiveFlowsDesc
	ch <- tm.instanceTorRelayContactsTotalDesc
	ch <- tm.instanceTorRelayActiveFlowsDesc
	ch <- tm.instanceSpamhausContactsTotalDesc
	ch <- tm.instanceSpamhausActiveFlowsDesc
	ch <- tm.instanceEmergingThreatsContactsTotalDesc
	ch <- tm.instanceEmergingThreatsActiveFlowsDesc
	ch <- tm.instanceCustomlistContactsTotalDesc
	ch <- tm.instanceCustomlistActiveFlowsDesc
}

func (tm *ThreatManager) describeHostMetrics(ch chan<- *prometheus.Desc) {
	ch <- tm.hostTorExitRefreshLastSuccessTimestampDesc
	ch <- tm.hostTorExitRefreshDurationSecondsDesc
	ch <- tm.hostTorExitRefreshErrorsTotalDesc
	ch <- tm.hostTorExitEntriesDesc
	ch <- tm.hostTorRelayRefreshLastSuccessTimestampDesc
	ch <- tm.hostTorRelayRefreshDurationSecondsDesc
	ch <- tm.hostTorRelayRefreshErrorsTotalDesc
	ch <- tm.hostTorRelayEntriesDesc
	ch <- tm.hostSpamhausRefreshLastSuccessTimestampDesc
	ch <- tm.hostSpamhausRefreshDurationSecondsDesc
	ch <- tm.hostSpamhausRefreshErrorsTotalDesc
	ch <- tm.hostSpamhausEntriesDesc
	ch <- tm.hostEmergingThreatsRefreshLastSuccessTimestampDesc
	ch <- tm.hostEmergingThreatsRefreshDurationSecondsDesc
	ch <- tm.hostEmergingThreatsRefreshErrorsTotalDesc
	ch <- tm.hostEmergingThreatsEntriesDesc
	ch <- tm.hostCustomlistRefreshLastSuccessTimestampDesc
	ch <- tm.hostCustomlistRefreshDurationSecondsDesc
	ch <- tm.hostCustomlistRefreshErrorsTotalDesc
	ch <- tm.hostCustomlistEntriesDesc
	ch <- tm.hostThreatListedDesc
}

func (tm *ThreatManager) collectHostThreatMetrics(hostMetrics *[]prometheus.Metric) {
	appendThreatHostMetrics(hostMetrics, tm.torExitEnabled, &tm.torExitMu, tm.torExitLastSuccessUnix, tm.torExitLastRefreshSeconds, &tm.torExitRefreshErrors, tm.torExitEntries, tm.hostTorExitRefreshLastSuccessTimestampDesc, tm.hostTorExitRefreshDurationSecondsDesc, tm.hostTorExitRefreshErrorsTotalDesc, tm.hostTorExitEntriesDesc)
	appendThreatHostMetrics(hostMetrics, tm.torRelayEnabled, &tm.torRelayMu, tm.torRelayLastSuccessUnix, tm.torRelayLastRefreshSeconds, &tm.torRelayRefreshErrors, tm.torRelayEntries, tm.hostTorRelayRefreshLastSuccessTimestampDesc, tm.hostTorRelayRefreshDurationSecondsDesc, tm.hostTorRelayRefreshErrorsTotalDesc, tm.hostTorRelayEntriesDesc)
	appendThreatHostMetrics(hostMetrics, tm.spamEnabled, &tm.spamMu, tm.spamLastSuccessUnix, tm.spamLastRefreshSeconds, &tm.spamRefreshErrors, tm.spamEntries, tm.hostSpamhausRefreshLastSuccessTimestampDesc, tm.hostSpamhausRefreshDurationSecondsDesc, tm.hostSpamhausRefreshErrorsTotalDesc, tm.hostSpamhausEntriesDesc)
	appendThreatHostMetrics(hostMetrics, tm.emThreatsEnabled, &tm.emThreatsMu, tm.emThreatsLastSuccessUnix, tm.emThreatsLastRefreshSeconds, &tm.emThreatsRefreshErrors, tm.emThreatsEntries, tm.hostEmergingThreatsRefreshLastSuccessTimestampDesc, tm.hostEmergingThreatsRefreshDurationSecondsDesc, tm.hostEmergingThreatsRefreshErrorsTotalDesc, tm.hostEmergingThreatsEntriesDesc)
	appendThreatHostMetrics(hostMetrics, tm.customListEnabled, &tm.customListMu, tm.customListLastSuccessUnix, tm.customListLastRefreshSeconds, &tm.customListRefreshErrors, tm.customListEntries, tm.hostCustomlistRefreshLastSuccessTimestampDesc, tm.hostCustomlistRefreshDurationSecondsDesc, tm.hostCustomlistRefreshErrorsTotalDesc, tm.hostCustomlistEntriesDesc)

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

func (tm *ThreatManager) addThreatCount(m map[string]float64, uuid string, delta float64) float64 {
	tm.threatCountMu.Lock()
	defer tm.threatCountMu.Unlock()
	prev := m[uuid]
	if delta > 0 {
		m[uuid] = prev + delta
	}
	return m[uuid]
}

func (tm *ThreatManager) shouldLogThreatHit(key string, now time.Time) bool {
	if tm.threatFileMinInterval <= 0 {
		return true
	}

	tm.threatLastHitMu.Lock()
	defer tm.threatLastHitMu.Unlock()

	last, ok := tm.threatLastHit[key]
	if !ok || now.Sub(last) >= tm.threatFileMinInterval {
		tm.threatLastHit[key] = now
		return true
	}
	return false
}

func (tm *ThreatManager) logThreatToFile(
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
	if !tm.threatFileEnabled || tm.threatFile == nil || tm.threatFilePath == "" {
		return
	}
	if listDir != ContactAny && listDir.String() != dirStr {
		return
	}

	key := fmt.Sprintf("%s|%s|%s|%s|%s", tag, instanceUUID, ct.Src, ct.Dst, dirStr)
	if !tm.shouldLogThreatHit(key, time.Now()) {
		return
	}

	base := []interface{}{
		"tag", tag,
		"event", "list_hit",
		"list", tag,
		"domain", domain,
		"instance_uuid", instanceUUID,
		"project_uuid", projectUUID,
		"project_name", projectName,
		"user_uuid", userUUID,
	}
	all := append(base,
		"src", ct.Src,
		"dst", ct.Dst,
		"direction", dirStr,
	)

	line := formatLogLine(
		logLevelString(LogLevelNotice),
		"threat",
		"threat_list_hit",
		all...,
	)

	tm.threatFileMu.Lock()
	defer tm.threatFileMu.Unlock()
	fmt.Fprintln(tm.threatFile, line)
}

func (tm *ThreatManager) logThreatEventToFile(
	tag string,
	event string,
	domain string,
	instanceUUID string,
	projectUUID string,
	projectName string,
	userUUID string,
	kvpairs ...interface{},
) {
	if !tm.threatFileEnabled || tm.threatFile == nil || tm.threatFilePath == "" {
		return
	}

	key := fmt.Sprintf("%s|%s|%s|%s", tag, event, instanceUUID, domain)
	if !tm.shouldLogThreatHit(key, time.Now()) {
		return
	}

	base := []interface{}{
		"tag", tag,
		"event", event,
		"domain", domain,
		"instance_uuid", instanceUUID,
		"project_uuid", projectUUID,
		"project_name", projectName,
		"user_uuid", userUUID,
	}
	all := append(base, kvpairs...)

	line := formatLogLine(
		logLevelString(LogLevelNotice),
		"threat",
		event,
		all...,
	)

	tm.threatFileMu.Lock()
	defer tm.threatFileMu.Unlock()
	fmt.Fprintln(tm.threatFile, line)
}

func (tm *ThreatManager) cleanupThreatCounts(activeInstances map[string]struct{}) {
	tm.threatCountMu.Lock()
	for uuid := range tm.torExitCount {
		if _, ok := activeInstances[uuid]; !ok {
			delete(tm.torExitCount, uuid)
		}
	}
	for uuid := range tm.torRelayCount {
		if _, ok := activeInstances[uuid]; !ok {
			delete(tm.torRelayCount, uuid)
		}
	}
	for uuid := range tm.spamCount {
		if _, ok := activeInstances[uuid]; !ok {
			delete(tm.spamCount, uuid)
		}
	}
	for uuid := range tm.emThreatsCount {
		if _, ok := activeInstances[uuid]; !ok {
			delete(tm.emThreatsCount, uuid)
		}
	}
	for uuid := range tm.customListCount {
		if _, ok := activeInstances[uuid]; !ok {
			delete(tm.customListCount, uuid)
		}
	}
	tm.threatCountMu.Unlock()
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
	return tm.torExitEnabled || tm.torRelayEnabled || tm.spamEnabled || tm.emThreatsEnabled || tm.customListEnabled
}

// -----------------------------------------------------------------------------
// Generic Threat Logic
// -----------------------------------------------------------------------------

func (tm *ThreatManager) checkThreatMap(
	fixedIPs []IP,
	ipSet map[string]struct{},
	ipFlows map[string][]ConntrackEntry,
	name, instanceUUID, projectUUID, projectName, userUUID string,
	dynamicMetrics *[]prometheus.Metric,
	signal *float64,
	threatSnapshot map[string]struct{},
	directionCfg ContactDirection,
	logTag string,
	activeDesc *prometheus.Desc,
	totalDesc *prometheus.Desc,
	countMap map[string]float64,
) {
	hits := make(map[string]ConntrackEntry)
	seen := make(map[string]struct{})

	for _, ip := range fixedIPs {
		flows := ipFlows[ip.Address]
		for _, ct := range flows {
			_, isVMsrc := ipSet[ct.Src]
			_, isVMdst := ipSet[ct.Dst]

			if !isVMsrc && !isVMdst {
				continue
			}

			match := false
			switch directionCfg {
			case ContactOut:
				if isVMsrc {
					if _, ok := threatSnapshot[ct.Dst]; ok {
						match = true
					}
				}
			case ContactIn:
				if isVMdst {
					if _, ok := threatSnapshot[ct.Src]; ok {
						match = true
					}
				}
			default:
				if _, ok := threatSnapshot[ct.Src]; ok {
					match = true
				}
				if _, ok := threatSnapshot[ct.Dst]; ok {
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
	}

	hitCount := len(hits)
	for _, ct := range hits {
		dirStr := flowDirection(ipSet, ct)
		tm.logThreatToFile(logTag, name, instanceUUID, projectUUID, projectName, userUUID, ct, dirStr, directionCfg)
	}

	activeVal := float64(hitCount)
	if activeVal > 0 {
		*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(activeDesc, prometheus.GaugeValue, activeVal, name, instanceUUID, projectUUID, projectName, userUUID, directionCfg.String()))
	}

	cVal := tm.addThreatCount(countMap, instanceUUID, float64(hitCount))
	if cVal > 0 {
		*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(totalDesc, prometheus.CounterValue, cVal, name, instanceUUID, projectUUID, projectName, userUUID, directionCfg.String()))
	}

	*signal = clamp01(float64(hitCount) / 10.0)
}

// -----------------------------------------------------------------------------
// Threat List Checkers
// -----------------------------------------------------------------------------

func (tm *ThreatManager) checkTorExit(fixedIPs []IP, ipSet map[string]struct{}, ipFlows map[string][]ConntrackEntry, name, instanceUUID, projectUUID, projectName, userUUID string, dynamicMetrics *[]prometheus.Metric, torSignal *float64) {
	if !tm.torExitEnabled {
		return
	}
	tm.torExitMu.RLock()
	snapshot := tm.torExitSet
	tm.torExitMu.RUnlock()

	tm.checkThreatMap(
		fixedIPs, ipSet, ipFlows, name, instanceUUID, projectUUID, projectName, userUUID, dynamicMetrics, torSignal,
		snapshot, tm.torExitDir, "TOR",
		tm.instanceTorExitActiveFlowsDesc, tm.instanceTorExitContactsTotalDesc, tm.torExitCount,
	)
}

func (tm *ThreatManager) checkTorRelay(fixedIPs []IP, ipSet map[string]struct{}, ipFlows map[string][]ConntrackEntry, name, instanceUUID, projectUUID, projectName, userUUID string, dynamicMetrics *[]prometheus.Metric, relaySignal *float64) {
	if !tm.torRelayEnabled {
		return
	}
	tm.torRelayMu.RLock()
	snapshot := tm.torRelaySet
	tm.torRelayMu.RUnlock()

	tm.checkThreatMap(
		fixedIPs, ipSet, ipFlows, name, instanceUUID, projectUUID, projectName, userUUID, dynamicMetrics, relaySignal,
		snapshot, tm.torRelayDir, "TORRELAY",
		tm.instanceTorRelayActiveFlowsDesc, tm.instanceTorRelayContactsTotalDesc, tm.torRelayCount,
	)
}

func (tm *ThreatManager) checkEmergingThreats(fixedIPs []IP, ipSet map[string]struct{}, ipFlows map[string][]ConntrackEntry, name, instanceUUID, projectUUID, projectName, userUUID string, dynamicMetrics *[]prometheus.Metric, emSignal *float64) {
	if !tm.emThreatsEnabled {
		return
	}
	tm.emThreatsMu.RLock()
	snapshot := tm.emThreatsSet
	tm.emThreatsMu.RUnlock()

	tm.checkThreatMap(
		fixedIPs, ipSet, ipFlows, name, instanceUUID, projectUUID, projectName, userUUID, dynamicMetrics, emSignal,
		snapshot, tm.emThreatsDir, "EMTHREATS",
		tm.instanceEmergingThreatsActiveFlowsDesc, tm.instanceEmergingThreatsContactsTotalDesc, tm.emThreatsCount,
	)
}

func (tm *ThreatManager) checkCustomList(fixedIPs []IP, ipSet map[string]struct{}, ipFlows map[string][]ConntrackEntry, name, instanceUUID, projectUUID, projectName, userUUID string, dynamicMetrics *[]prometheus.Metric, clSignal *float64) {
	if !tm.customListEnabled {
		return
	}
	tm.customListMu.RLock()
	snapshot := tm.customListSet
	tm.customListMu.RUnlock()

	tm.checkThreatMap(
		fixedIPs, ipSet, ipFlows, name, instanceUUID, projectUUID, projectName, userUUID, dynamicMetrics, clSignal,
		snapshot, tm.customListDir, "CUSTOMLIST",
		tm.instanceCustomlistActiveFlowsDesc, tm.instanceCustomlistContactsTotalDesc, tm.customListCount,
	)
}

func (tm *ThreatManager) checkSpamhaus(fixedIPs []IP, ipSet map[string]struct{}, ipFlows map[string][]ConntrackEntry, name, instanceUUID, projectUUID, projectName, userUUID string, dynamicMetrics *[]prometheus.Metric, spamSignal *float64) {
	if !tm.spamEnabled {
		return
	}
	hits := make(map[string]ConntrackEntry)
	seen := make(map[string]struct{})

	tm.spamMu.RLock()
	isSpamhausIP := func(ip net.IP) bool {
		if ip == nil {
			return false
		}
		if ip4 := ip.To4(); ip4 != nil {
			key := fmt.Sprintf("%d.%d", ip4[0], ip4[1])
			for _, n := range tm.spamBucketsV4[key] {
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
		for _, n := range tm.spamBucketsV6[key] {
			if n.Contains(ip16) {
				return true
			}
		}
		return false
	}

	for _, ip := range fixedIPs {
		flows := ipFlows[ip.Address]
		for _, ct := range flows {
			_, isVMsrc := ipSet[ct.Src]
			_, isVMdst := ipSet[ct.Dst]
			if !isVMsrc && !isVMdst {
				continue
			}

			srcIP := net.ParseIP(ct.Src)
			dstIP := net.ParseIP(ct.Dst)
			match := false

			switch tm.spamDir {
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
	}
	tm.spamMu.RUnlock()

	hitCount := len(hits)
	for _, ct := range hits {
		dirStr := flowDirection(ipSet, ct)
		tm.logThreatToFile("SPAMHAUS", name, instanceUUID, projectUUID, projectName, userUUID, ct, dirStr, tm.spamDir)
	}

	activeVal := float64(hitCount)
	if activeVal > 0 {
		*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(tm.instanceSpamhausActiveFlowsDesc, prometheus.GaugeValue, activeVal, name, instanceUUID, projectUUID, projectName, userUUID, tm.spamDir.String()))
	}
	spamVal := tm.addThreatCount(tm.spamCount, instanceUUID, float64(hitCount))
	if spamVal > 0 {
		*dynamicMetrics = append(*dynamicMetrics, prometheus.MustNewConstMetric(tm.instanceSpamhausContactsTotalDesc, prometheus.CounterValue, spamVal, name, instanceUUID, projectUUID, projectName, userUUID, tm.spamDir.String()))
	}
	*spamSignal = clamp01(float64(hitCount) / 10.0)
}

// -----------------------------------------------------------------------------
// Threat Refreshers
// -----------------------------------------------------------------------------

func (tm *ThreatManager) startTorExitRefresher() {
	for {
		select {
		case <-tm.shutdownChan:
			return
		default:
		}

		tm.refreshTorExitListUnified()
		time.Sleep(tm.torExitRefresh)
	}
}

func (tm *ThreatManager) refreshTorExitListUnified() {
	start := time.Now()
	resp, err := tm.httpClient.Get(tm.torExitURL)
	if err != nil {
		atomic.AddUint64(&tm.torExitRefreshErrors, 1)
		logTorexitThreat.Error("torexit_download_failed", "stage", "download", "err", err)
		return
	}
	defer resp.Body.Close()
	var data OnionooSummary
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&data); err != nil {
		atomic.AddUint64(&tm.torExitRefreshErrors, 1)
		logTorexitThreat.Error("torexit_decode_failed", "stage", "decode", "err", err)
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
	tm.torExitMu.Lock()
	tm.torExitSet = fresh
	tm.torExitLastSuccessUnix = nowUnix
	tm.torExitLastRefreshSeconds = dur
	tm.torExitEntries = len(fresh)
	tm.torExitMu.Unlock()
	logTorexitThreat.Info("torexit_refresh", "ips_total", len(fresh))

	tm.updateHostThreatsFromIPSet("tor_exit", fresh)
}

func (tm *ThreatManager) startTorRelayRefresher() {
	for {
		select {
		case <-tm.shutdownChan:
			return
		default:
		}

		tm.refreshTorRelayListUnified()
		time.Sleep(tm.torRelayRefresh)
	}
}

func (tm *ThreatManager) refreshTorRelayListUnified() {
	start := time.Now()
	resp, err := tm.httpClient.Get(tm.torRelayURL)
	if err != nil {
		atomic.AddUint64(&tm.torRelayRefreshErrors, 1)
		logTorrelayThreat.Error("torrelay_download_failed", "stage", "download", "err", err)
		return
	}
	defer resp.Body.Close()
	var data OnionooSummary
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&data); err != nil {
		atomic.AddUint64(&tm.torRelayRefreshErrors, 1)
		logTorrelayThreat.Error("torrelay_decode_failed", "stage", "decode", "err", err)
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
	tm.torRelayMu.Lock()
	tm.torRelaySet = fresh
	tm.torRelayLastSuccessUnix = nowUnix
	tm.torRelayLastRefreshSeconds = dur
	tm.torRelayEntries = len(fresh)
	tm.torRelayMu.Unlock()
	logTorrelayThreat.Info("torrelay_refresh", "ips_total", len(fresh))
	tm.updateHostThreatsFromIPSet("tor_relay", fresh)
}

func (tm *ThreatManager) startSpamhausRefresher() {
	for {
		select {
		case <-tm.shutdownChan:
			return
		default:
		}

		tm.refreshSpamhausList()
		time.Sleep(tm.spamRefresh)
	}
}

func (tm *ThreatManager) refreshSpamhausList() {
	start := time.Now()
	allNets := make([]*net.IPNet, 0, 8192)
	resp4, err := tm.httpClient.Get(tm.spamURL)
	if err != nil {
		logSpamhausThreat.Error("spamhaus_download_failed", "list", "ipv4", "stage", "download", "err", err)
	} else {
		defer resp4.Body.Close()
		nets4, err := parseSpamhausCIDRs(resp4.Body)
		if err != nil {
			logSpamhausThreat.Error("spamhaus_parse_failed", "list", "ipv4", "stage", "parse", "err", err)
		} else {
			allNets = append(allNets, nets4...)
		}
	}
	resp6, err := tm.httpClient.Get(tm.spamV6URL)
	if err != nil {
		logSpamhausThreat.Error("spamhaus_download_failed", "list", "ipv6", "stage", "download", "err", err)
	} else {
		defer resp6.Body.Close()
		nets6, err := parseSpamhausCIDRs(resp6.Body)
		if err != nil {
			logSpamhausThreat.Error("spamhaus_parse_failed", "list", "ipv6", "stage", "parse", "err", err)
		} else {
			allNets = append(allNets, nets6...)
		}
	}
	if len(allNets) == 0 {
		atomic.AddUint64(&tm.spamRefreshErrors, 1)
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
	tm.spamMu.Lock()
	tm.spamNets = allNets
	tm.spamBucketsV4 = bucketsV4
	tm.spamBucketsV6 = bucketsV6
	tm.spamLastSuccessUnix = nowUnix
	tm.spamLastRefreshSeconds = dur
	tm.spamEntries = len(allNets)
	tm.spamMu.Unlock()
	logSpamhausThreat.Info("spamhaus_refresh", "cidrs_total", len(allNets), "cidrs_ipv4", v4Count, "cidrs_ipv6", v6Count, "buckets_v4", len(bucketsV4), "buckets_v6", len(bucketsV6))
	tm.updateHostThreatsFromCIDRs("spamhaus", allNets)
}

func (tm *ThreatManager) startEmThreatsRefresher() {
	for {
		select {
		case <-tm.shutdownChan:
			return
		default:
		}

		tm.refreshEmergingThreatsList()
		time.Sleep(tm.emThreatsRefresh)
	}
}

func (tm *ThreatManager) refreshEmergingThreatsList() {
	start := time.Now()
	resp, err := tm.httpClient.Get(tm.emThreatsURL)
	if err != nil {
		atomic.AddUint64(&tm.emThreatsRefreshErrors, 1)
		logEmergingthreatsThreat.Error("emergingthreats_download_failed", "stage", "download", "err", err)
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
		atomic.AddUint64(&tm.emThreatsRefreshErrors, 1)
		logEmergingthreatsThreat.Error("emergingthreats_read_failed", "stage", "read", "err", err)
		return
	}
	dur := time.Since(start).Seconds()
	nowUnix := float64(time.Now().Unix())
	tm.emThreatsMu.Lock()
	tm.emThreatsSet = fresh
	tm.emThreatsLastSuccessUnix = nowUnix
	tm.emThreatsLastRefreshSeconds = dur
	tm.emThreatsEntries = len(fresh)
	tm.emThreatsMu.Unlock()
	logEmergingthreatsThreat.Info("emergingthreats_refresh", "ips_total", len(fresh))
	tm.updateHostThreatsFromIPSet("emergingthreats", fresh)
}

func (tm *ThreatManager) startCustomListRefresher() {
	for {
		select {
		case <-tm.shutdownChan:
			return
		default:
		}

		tm.refreshCustomList()
		time.Sleep(tm.customListRefresh)
	}
}

func (tm *ThreatManager) refreshCustomList() {
	start := time.Now()
	f, err := os.Open(tm.customListPath)
	if err != nil {
		atomic.AddUint64(&tm.customListRefreshErrors, 1)
		logCustomlistThreat.Error("customlist_open_failed", "stage", "open", "path", tm.customListPath, "err", err)
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
		atomic.AddUint64(&tm.customListRefreshErrors, 1)
		logCustomlistThreat.Error("customlist_read_failed", "stage", "read", "path", tm.customListPath, "err", err)
		return
	}
	dur := time.Since(start).Seconds()
	nowUnix := float64(time.Now().Unix())
	tm.customListMu.Lock()
	tm.customListSet = fresh
	tm.customListLastSuccessUnix = nowUnix
	tm.customListLastRefreshSeconds = dur
	tm.customListEntries = len(fresh)
	tm.customListMu.Unlock()
	logCustomlistThreat.Info("customlist_refresh", "ips_total", len(fresh), "path", tm.customListPath)
	tm.updateHostThreatsFromIPSet("customlist", fresh)
}

func appendThreatHostMetrics(
	metrics *[]prometheus.Metric,
	enabled bool,
	mu *sync.RWMutex,
	lastSuccess float64,
	lastDuration float64,
	errCount *uint64,
	entries int,
	descLast *prometheus.Desc,
	descDur *prometheus.Desc,
	descErr *prometheus.Desc,
	descEntries *prometheus.Desc,
) {
	if !enabled {
		return
	}
	mu.RLock()
	ls := lastSuccess
	dur := lastDuration
	ent := entries
	mu.RUnlock()
	ec := atomic.LoadUint64(errCount)

	*metrics = append(*metrics,
		prometheus.MustNewConstMetric(descLast, prometheus.GaugeValue, ls),
		prometheus.MustNewConstMetric(descDur, prometheus.GaugeValue, dur),
		prometheus.MustNewConstMetric(descErr, prometheus.CounterValue, float64(ec)),
		prometheus.MustNewConstMetric(descEntries, prometheus.GaugeValue, float64(ent)),
	)
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

func (tm *ThreatManager) updateHostThreatsFromIPSet(listName string, ipSet map[string]struct{}) {
	if !tm.hostThreatsEnabled {
		return
	}
	hostIPs := tm.getHostIPs()
	hits := make(map[string]string)

	for _, hip := range hostIPs {
		if _, ok := ipSet[hip.Address]; ok {
			tm.logThreatEventToFile("HOST_THREAT", "host_threat", "", "", "", "", "", "list", listName, "ip", hip.Address, "family", hip.Family)
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
			tm.logThreatEventToFile("HOST_THREAT", "host_threat", "", "", "", "", "", "list", listName, "ip", hip.Address, "family", hip.Family)
			hits[hip.Address] = hip.Family
		}
	}

	tm.setHostThreatHitsForList(listName, hits)
}
