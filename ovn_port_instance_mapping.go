package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func parseUint16(s string) (uint16, bool) {
	var v uint64
	if s == "" {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		v = v*10 + uint64(s[i]-'0')
		if v > 65535 {
			return 0, false
		}
	}
	return uint16(v), true
}

func looksLikeUUID36(s string) bool {
	if len(s) != 36 {
		return false
	}
	if s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return false
	}
	for i := 0; i < 36; i++ {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		c := s[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			continue
		}
		return false
	}
	return true
}

// OVNMapper maps conntrack zones -> instance UUIDs
type OVNMapper struct {
	sync.RWMutex
	refreshMu      sync.Mutex
	zoneToInstance map[uint16]string
	zoneToIPs      map[uint16]map[IPKey]struct{}
	socketPath     string
	lastRefresh    time.Time
	lastAttempt    time.Time
}

type ovnRefreshStats struct {
	linesTotal       int
	linesParsed      int
	linesNoUUID      int
	linesNoZone      int
	linesUnknownPort int
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
	lastSuccess := m.lastRefresh
	lastAttempt := m.lastAttempt
	m.RUnlock()

	if now.Sub(lastSuccess) < 30*time.Second {
		return nil
	}
	if now.Sub(lastAttempt) < 5*time.Second {
		return nil
	}

	m.refreshMu.Lock()
	defer m.refreshMu.Unlock()

	now = time.Now()

	m.RLock()
	lastSuccess = m.lastRefresh
	lastAttempt = m.lastAttempt
	sock := m.socketPath
	m.RUnlock()

	if now.Sub(lastSuccess) < 30*time.Second {
		return nil
	}
	if now.Sub(lastAttempt) < 5*time.Second {
		return nil
	}

	m.Lock()
	m.lastAttempt = now
	m.Unlock()

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

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
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

	return m.refreshFromOutput(out, instanceByPort, ipsByPort)
}

func parseOVNZoneList(out []byte, instanceByPort map[string]string, ipsByPort map[string][]IPKey) (map[uint16]string, map[uint16]map[IPKey]struct{}, ovnRefreshStats, error) {
	newZones := make(map[uint16]string)
	newIPs := make(map[uint16]map[IPKey]struct{})
	portZones := make(map[string]uint16)
	stats := ovnRefreshStats{}

	for _, raw := range bytes.Split(out, []byte{'\n'}) {
		s := strings.TrimSpace(string(raw))
		if s == "" {
			continue
		}
		stats.linesTotal++
		fields := strings.Fields(s)
		if len(fields) < 2 {
			return nil, nil, stats, fmt.Errorf("malformed OVN zone line %q", s)
		}

		portUUID := ""
		portField := -1
		zone := uint16(0)
		zoneOK := false

		for i, f := range fields {
			if portUUID == "" && looksLikeUUID36(f) {
				portUUID = f
				portField = i
				continue
			}
			if portUUID == "" && !zoneOK {
				if v, ok := parseUint16(f); ok {
					zone = v
					zoneOK = true
				}
			}
		}
		if portField >= 0 {
			zoneOK = false
			for _, f := range fields[portField+1:] {
				if v, ok := parseUint16(f); ok {
					zone = v
					zoneOK = true
					break
				}
			}
		}

		if portUUID == "" {
			stats.linesNoUUID++
			if !zoneOK {
				return nil, nil, stats, fmt.Errorf("OVN zone line has no port UUID: %q", s)
			}
			continue
		}
		if !zoneOK {
			stats.linesNoZone++
			return nil, nil, stats, fmt.Errorf("OVN zone line has no valid zone: %q", s)
		}

		instanceUUID, ok := instanceByPort[portUUID]
		if !ok {
			stats.linesUnknownPort++
			continue
		}
		if instanceUUID == "" {
			return nil, nil, stats, fmt.Errorf("OVN port %s has an empty instance mapping", portUUID)
		}
		if existingZone, exists := portZones[portUUID]; exists && existingZone != zone {
			return nil, nil, stats, fmt.Errorf("ambiguous OVN port %s maps to both zones %d and %d", portUUID, existingZone, zone)
		}
		portZones[portUUID] = zone

		if existing, exists := newZones[zone]; exists && existing != instanceUUID {
			return nil, nil, stats, fmt.Errorf("ambiguous OVN zone %d maps to both %s and %s", zone, existing, instanceUUID)
		}
		newZones[zone] = instanceUUID

		if ips, okIPs := ipsByPort[portUUID]; okIPs && len(ips) > 0 {
			set := newIPs[zone]
			if set == nil {
				set = make(map[IPKey]struct{}, len(ips))
			}
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

		stats.linesParsed++
	}
	if stats.linesTotal == 0 || stats.linesParsed == 0 || len(newZones) == 0 {
		return nil, nil, stats, fmt.Errorf("OVN zone output contained no usable active-port mappings")
	}
	for zone := range newZones {
		if len(newIPs[zone]) == 0 {
			return nil, nil, stats, fmt.Errorf("OVN zone %d has no usable instance IPs", zone)
		}
	}
	return newZones, newIPs, stats, nil
}

func (m *OVNMapper) refreshFromOutput(out []byte, instanceByPort map[string]string, ipsByPort map[string][]IPKey) error {
	newZones, newIPs, stats, err := parseOVNZoneList(out, instanceByPort, ipsByPort)
	if err != nil {
		return err
	}

	logKV(LogLevelDebug, "mapping", "ovn_mapper", "refresh_success", "zones_found", len(newZones), "lines_total", stats.linesTotal, "lines_parsed", stats.linesParsed, "lines_no_uuid", stats.linesNoUUID, "lines_no_zone", stats.linesNoZone, "lines_unknown_port", stats.linesUnknownPort)

	m.Lock()
	m.zoneToInstance = newZones
	m.zoneToIPs = newIPs
	m.lastRefresh = time.Now()
	m.Unlock()

	return nil
}

func (m *OVNMapper) LastRefresh() time.Time {
	m.RLock()
	last := m.lastRefresh
	m.RUnlock()
	return last
}

func (m *OVNMapper) IsStale(now time.Time, maxAge time.Duration) bool {
	if maxAge <= 0 {
		return false
	}
	last := m.LastRefresh()
	return last.IsZero() || now.Sub(last) > maxAge
}
func (m *OVNMapper) GetInstance(zone uint16) string {
	m.RLock()
	defer m.RUnlock()
	return m.zoneToInstance[zone]
}
func (m *OVNMapper) GetIPs(zone uint16) map[IPKey]struct{} {
	m.RLock()
	src := m.zoneToIPs[zone]
	if src == nil {
		m.RUnlock()
		return nil
	}
	out := make(map[IPKey]struct{}, len(src))
	for k := range src {
		out[k] = struct{}{}
	}
	m.RUnlock()
	return out
}

func (m *OVNMapper) SnapshotRefs() (map[uint16]string, map[uint16]map[IPKey]struct{}) {
	m.RLock()
	zi := m.zoneToInstance
	zip := m.zoneToIPs
	m.RUnlock()
	return zi, zip
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
func (im *InstanceManager) snapshotOVNPortToInstance(activeSet map[string]struct{}) map[string]string {
	m := make(map[string]string, 64)
	im.domainMetaMu.RLock()
	defer im.domainMetaMu.RUnlock()
	for uuid := range activeSet {
		meta := im.domainMeta[uuid]
		if meta == nil {
			continue
		}
		for _, p := range meta.PortUUIDs {
			if len(p) == 36 {
				if previous, exists := m[p]; exists && previous != uuid {
					m[p] = ""
					continue
				}
				m[p] = uuid
			}
		}
	}
	return m
}
func (im *InstanceManager) snapshotOVNPortToIPKeys(activeSet map[string]struct{}) map[string][]IPKey {
	m := make(map[string][]IPKey, 64)
	im.domainMetaMu.RLock()
	defer im.domainMetaMu.RUnlock()
	for uuid := range activeSet {
		meta := im.domainMeta[uuid]
		if meta == nil || len(meta.PortUUIDs) == 0 || len(meta.PortIPsByUUID) == 0 {
			continue
		}
		for _, port := range meta.PortUUIDs {
			if len(port) != 36 {
				continue
			}
			ips := meta.PortIPsByUUID[port]
			keys := m[port]
			seen := make(map[IPKey]struct{}, len(keys)+len(ips))
			for _, key := range keys {
				seen[key] = struct{}{}
			}
			for _, ip := range ips {
				k := IPStrToKey(ip.Address)
				if k == (IPKey{}) {
					continue
				}
				if _, duplicate := seen[k]; duplicate {
					continue
				}
				seen[k] = struct{}{}
				keys = append(keys, k)
			}
			if len(keys) > 0 {
				m[port] = keys
			}
		}
	}
	return m
}
