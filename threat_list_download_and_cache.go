package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	threatLineFeedMaxBytes = int64(8 << 20)
	threatJSONFeedMaxBytes = int64(32 << 20)
)

type OnionooSummary struct {
	Relays []struct {
		OrAddresses []string `json:"or_addresses"`
	} `json:"relays"`
}

func (tm *ThreatManager) runProviderRefresher(p *IPThreatProvider) {
	refreshOnce := func() {
		if err := tm.refreshProviderOnce(p); err != nil {
			atomic.AddUint64(&p.ErrorCount, 1)
			p.Logger.Error(strings.ToLower(p.Name)+"_refresh_failed", "err", err)
		}
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

func validateThreatIPSet(fresh map[IPKey]struct{}) error {
	if len(fresh) == 0 {
		return fmt.Errorf("threat feed contains no valid addresses")
	}
	for address := range fresh {
		if IPKeyToAddr(address).IsUnspecified() {
			return fmt.Errorf("threat feed contains an unspecified address")
		}
	}
	return nil
}

func (tm *ThreatManager) refreshProviderOnce(p *IPThreatProvider) error {
	if p == nil || p.Fetcher == nil {
		return fmt.Errorf("threat provider has no fetcher")
	}
	start := time.Now()
	fresh, err := p.Fetcher()
	if err != nil {
		return err
	}
	if err := validateThreatIPSet(fresh); err != nil {
		return err
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
	return nil
}

func threatFeedFresh(lastSuccess float64, refresh time.Duration, now time.Time) bool {
	if lastSuccess <= 0 {
		return false
	}
	loadedAt := time.Unix(int64(lastSuccess), 0)
	if loadedAt.After(now.Add(5 * time.Minute)) {
		return false
	}
	if refresh <= 0 {
		return true
	}
	const maxDuration = time.Duration(1<<63 - 1)
	maxAge := maxDuration
	if refresh <= maxDuration/2 {
		maxAge = 2 * refresh
	}
	if maxAge < time.Minute {
		maxAge = time.Minute
	}
	return !loadedAt.Before(now.Add(-maxAge))
}

func (p *IPThreatProvider) feedFresh(now time.Time) bool {
	if p == nil {
		return false
	}
	p.Mu.RLock()
	lastSuccess := p.LastSuccess
	refresh := p.RefreshInterval
	p.Mu.RUnlock()
	return threatFeedFresh(lastSuccess, refresh, now)
}

func (tm *ThreatManager) fetchHTTPBytes(rawURL string, maxBytes int64) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return nil, fmt.Errorf("invalid threat feed URL")
	}
	client := tm.httpClient
	if client == nil {
		return nil, fmt.Errorf("threat feed HTTP client is unavailable")
	}
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "openstack-instance-exporter/1.3.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, redactThreatHTTPRequestError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d from threat feed", resp.StatusCode)
	}
	if resp.ContentLength > maxBytes {
		return nil, fmt.Errorf("threat feed exceeds %d bytes", maxBytes)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, redactThreatHTTPRequestError(err)
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("threat feed exceeds %d bytes", maxBytes)
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, fmt.Errorf("threat feed is empty")
	}
	return body, nil
}

func redactThreatHTTPRequestError(err error) error {
	return threatHTTPRequestError{cause: err}
}

type threatHTTPRequestError struct {
	cause error
}

func (threatHTTPRequestError) Error() string {
	return "threat feed request failed"
}

func (err threatHTTPRequestError) Unwrap() error {
	return err.cause
}

func (tm *ThreatManager) fetchOnionoo(url string) (map[IPKey]struct{}, error) {
	body, err := tm.fetchHTTPBytes(url, threatJSONFeedMaxBytes)
	if err != nil {
		return nil, err
	}
	var data OnionooSummary
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&data); err != nil {
		return nil, err
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, err
	}
	fresh := make(map[IPKey]struct{})
	for _, r := range data.Relays {
		for _, raw := range r.OrAddresses {
			addr, err := parseOnionooORAddress(raw)
			if err != nil {
				return nil, fmt.Errorf("malformed Onionoo or_address: %w", err)
			}
			fresh[AddrToKey(addr)] = struct{}{}
		}
	}
	if err := validateThreatIPSet(fresh); err != nil {
		return nil, err
	}
	return fresh, nil
}

func parseOnionooORAddress(raw string) (netip.Addr, error) {
	if addrPort, err := netip.ParseAddrPort(raw); err == nil {
		addr := addrPort.Addr()
		if addr.Zone() != "" {
			addr = addr.WithZone("")
		}
		return addr, nil
	}

	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Addr{}, err
	}
	if addr.Zone() != "" {
		addr = addr.WithZone("")
	}
	return addr, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra interface{}
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("threat feed contains trailing JSON data")
		}
		return err
	}
	return nil
}

func (tm *ThreatManager) fetchURLLines(url string) (map[IPKey]struct{}, error) {
	body, err := tm.fetchHTTPBytes(url, threatLineFeedMaxBytes)
	if err != nil {
		return nil, err
	}
	return scanIPLines(bytes.NewReader(body))
}
func (tm *ThreatManager) fetchFileLines(path string) (map[IPKey]struct{}, error) {
	// Open nonblocking so a misconfigured FIFO or device cannot stall the
	// refresher before its file type can be validated. O_NONBLOCK is inert for
	// regular files, including regular files reached through a symlink.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("threat feed is not a regular file")
	}
	if info.Size() > threatLineFeedMaxBytes {
		return nil, fmt.Errorf("threat feed exceeds %d bytes", threatLineFeedMaxBytes)
	}
	body, err := readStableThreatFile(f, info, threatLineFeedMaxBytes)
	if err != nil {
		return nil, err
	}
	return scanIPLines(bytes.NewReader(body))
}

// readStableThreatFile is kept separate from parsing so changes to an open
// regular file can be rejected before any partial contents are accepted.
func readStableThreatFile(f *os.File, initial os.FileInfo, maxBytes int64) ([]byte, error) {
	if f == nil || initial == nil {
		return nil, fmt.Errorf("threat feed file metadata is unavailable")
	}
	body, err := readBoundedThreatFile(f, maxBytes)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) != initial.Size() {
		return nil, fmt.Errorf("threat feed changed while reading")
	}
	final, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(initial, final) || final.Size() != initial.Size() || !final.ModTime().Equal(initial.ModTime()) {
		return nil, fmt.Errorf("threat feed changed while reading")
	}
	return body, nil
}

func readBoundedThreatFile(r io.Reader, maxBytes int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("threat feed exceeds %d bytes", maxBytes)
	}
	return body, nil
}
func scanIPLines(r io.Reader) (map[IPKey]struct{}, error) {
	scanner := bufio.NewScanner(r)
	fresh := make(map[IPKey]struct{})
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		addr, err := netip.ParseAddr(line)
		if err != nil {
			return nil, fmt.Errorf("malformed threat feed address on line %d", lineNumber)
		}
		if addr.Zone() != "" {
			addr = addr.WithZone("")
		}
		if addr.IsUnspecified() {
			return nil, fmt.Errorf("malformed threat feed address on line %d", lineNumber)
		}
		fresh[AddrToKey(addr)] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if err := validateThreatIPSet(fresh); err != nil {
		return nil, err
	}
	return fresh, nil
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
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		parts := strings.Split(line, ";")
		cidrStr := strings.TrimSpace(parts[0])

		_, netIP, err := net.ParseCIDR(cidrStr)
		if err != nil {
			return nil, fmt.Errorf("malformed threat feed CIDR on line %d", lineNumber)
		}
		nets = append(nets, netIP)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(nets) == 0 {
		return nil, fmt.Errorf("threat feed contains no valid CIDRs")
	}
	return nets, nil
}

func validateSpamhausCIDRFamily(nets []*net.IPNet, expectedBits int) error {
	for _, network := range nets {
		if network == nil {
			return fmt.Errorf("threat feed contains an invalid CIDR")
		}
		ones, bits := network.Mask.Size()
		if bits != expectedBits {
			return fmt.Errorf("threat feed contains a CIDR from the wrong address family")
		}
		if ones == 0 || (ones == bits && network.IP.IsUnspecified()) {
			return fmt.Errorf("threat feed contains an unusable catch-all CIDR")
		}
	}
	return nil
}

func (tm *ThreatManager) refreshSpamhausList() {
	start := time.Now()

	fetchOne := func(url string, expectedBits int) ([]*net.IPNet, error) {
		body, err := tm.fetchHTTPBytes(url, threatLineFeedMaxBytes)
		if err != nil {
			return nil, err
		}
		nets, err := parseSpamhausCIDRs(bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		if len(nets) == 0 {
			return nil, fmt.Errorf("empty list from %s", url)
		}
		if err := validateSpamhausCIDRFamily(nets, expectedBits); err != nil {
			return nil, err
		}
		return nets, nil
	}

	var (
		nets4         []*net.IPNet
		nets6         []*net.IPNet
		err4          error
		err6          error
		configured    int
		refreshFailed bool
	)

	if tm.spamURL != "" {
		configured++
		nets4, err4 = fetchOne(tm.spamURL, 32)
		if err4 != nil {
			refreshFailed = true
			atomic.AddUint64(&tm.spamRefreshErrors, 1)
			logSpamhausThreat.Error("spamhaus_v4_refresh_failed", "err", err4)
		}
	}
	if tm.spamV6URL != "" {
		configured++
		nets6, err6 = fetchOne(tm.spamV6URL, 128)
		if err6 != nil {
			refreshFailed = true
			atomic.AddUint64(&tm.spamRefreshErrors, 1)
			logSpamhausThreat.Error("spamhaus_v6_refresh_failed", "err", err6)
		}
	}

	if configured == 0 || refreshFailed {
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
