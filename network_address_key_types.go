package main

import (
	"encoding/hex"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

func uuidBytesToString(uuidBytes []byte) string {
	if len(uuidBytes) != 16 {
		return ""
	}
	s := hex.EncodeToString(uuidBytes)
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32]
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
func MakePairKey(aIP IPKey, aPort uint16, bIP IPKey, bPort uint16, proto uint8) PairKey {
	if compareEndpoint(aIP, aPort, bIP, bPort) <= 0 {
		return PairKey{A: aIP, AP: aPort, B: bIP, BP: bPort, Proto: proto}
	}
	return PairKey{A: bIP, AP: bPort, B: aIP, BP: aPort, Proto: proto}
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
func compareEndpoint(ipA IPKey, portA uint16, ipB IPKey, portB uint16) int {
	c := compareIPKey(ipA, ipB)
	if c != 0 {
		return c
	}
	if portA < portB {
		return -1
	}
	if portA > portB {
		return 1
	}
	return 0
}
func PairKeyString(pk PairKey) string {
	return hex.EncodeToString(pk.A[:]) + ":" + strconv.Itoa(int(pk.AP)) + "|" + hex.EncodeToString(pk.B[:]) + ":" + strconv.Itoa(int(pk.BP)) + "|" + strconv.Itoa(int(pk.Proto))
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
	if ip16[0] == 0xfe && (ip16[1]&0xc0) == 0x80 {
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

func copyPortNameMap(in map[uint16]string) map[uint16]string {
	out := make(map[uint16]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// IPKey is a 16-byte array used as a map key to avoid string allocations.
// IPv4 addresses are stored as IPv4-mapped IPv6 (::ffff:1.2.3.4).
type IPKey [16]byte
type PairKey struct {
	A     IPKey
	AP    uint16
	B     IPKey
	BP    uint16
	Proto uint8
}
