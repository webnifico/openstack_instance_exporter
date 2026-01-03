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
	"sync/atomic"
	"time"
)

type OnionooSummary struct {
	Relays []struct {
		OrAddresses []string `json:"or_addresses"`
	} `json:"relays"`
}

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
