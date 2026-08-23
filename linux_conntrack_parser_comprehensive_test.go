package main

import (
	"encoding/binary"
	"errors"
	"syscall"
	"testing"
)

func testTCPConntrackPayload(ne binary.ByteOrder, family int, proto uint8, includePorts bool, extra ...[]byte) []byte {
	var srcAttr, dstAttr []byte
	if family == syscall.AF_INET {
		srcAttr = testNLA(ne, ctaIPV4Src, []byte{192, 0, 2, 1})
		dstAttr = testNLA(ne, ctaIPV4Dst, []byte{198, 51, 100, 2})
	} else {
		src := make([]byte, 16)
		dst := make([]byte, 16)
		src[0], src[1], src[15] = 0x20, 0x01, 1
		dst[0], dst[1], dst[15] = 0x20, 0x01, 2
		srcAttr = testNLA(ne, ctaIPV6Src, src)
		dstAttr = testNLA(ne, ctaIPV6Dst, dst)
	}
	protoAttrs := testNLA(ne, ctaProtoNum, []byte{proto})
	if includePorts {
		srcPort := make([]byte, 2)
		dstPort := make([]byte, 2)
		binary.BigEndian.PutUint16(srcPort, 12345)
		binary.BigEndian.PutUint16(dstPort, 443)
		protoAttrs = append(protoAttrs, testNLA(ne, ctaProtoSrcPort, srcPort)...)
		protoAttrs = append(protoAttrs, testNLA(ne, ctaProtoDstPort, dstPort)...)
	}
	attrs := []byte{}
	attrs = append(attrs, testNestedNLA(ne, ctaTupleOrig,
		testNestedNLA(ne, ctaTupleIP, append(srcAttr, dstAttr...)),
		testNestedNLA(ne, ctaTupleProto, protoAttrs),
	)...)
	attrs = append(attrs, testStatusAttr(ne, IPS_SEEN_REPLY)...)
	for _, attr := range extra {
		attrs = append(attrs, attr...)
	}
	return testConntrackPayloadFromAttrs(family, attrs)
}

func TestNetlinkAttributeWalkerMalformedPaddingAndVisitorStop(t *testing.T) {
	ne := nativeEndian()
	for _, data := range [][]byte{
		{1, 2, 3},
		{3, 0, 1, 0},
		{5, 0, 1, 0, 9, 0},
	} {
		var parseErrs uint64
		if walkNetlinkAttributes(data, ne, &parseErrs, func(uint16, []byte) bool { return true }) || parseErrs != 1 {
			t.Fatalf("malformed attributes %v accepted with parseErrs=%d", data, parseErrs)
		}
	}

	// An unpadded final attribute is valid when its declared length consumes the
	// entire input exactly.
	unpadded := []byte{5, 0, 7, 0, 9}
	visits := 0
	var parseErrs uint64
	if !walkNetlinkAttributes(unpadded, ne, &parseErrs, func(typ uint16, value []byte) bool {
		visits++
		return typ == 7 && len(value) == 1 && value[0] == 9
	}) || visits != 1 || parseErrs != 0 {
		t.Fatalf("valid final unpadded attribute visits=%d parseErrs=%d", visits, parseErrs)
	}
	if walkNetlinkAttributes(testNLA(ne, 1, nil), ne, &parseErrs, func(uint16, []byte) bool { return false }) {
		t.Fatal("attribute visitor stop was ignored")
	}
}

func TestParseConntrackTCPUDPZoneAndSplitCounterCoverage(t *testing.T) {
	ne := nativeEndian()
	zone := make([]byte, 2)
	binary.BigEndian.PutUint16(zone, 42)
	packets := make([]byte, 8)
	bytesValue := make([]byte, 8)
	binary.BigEndian.PutUint64(packets, 7)
	binary.BigEndian.PutUint64(bytesValue, 700)
	payload := testTCPConntrackPayload(ne, syscall.AF_INET, 6, true,
		testNLA(ne, ctaZone, zone),
		testNestedNLA(ne, ctaCountersOrig, testNLA(ne, ctaCountersPackets, packets)),
		testNestedNLA(ne, ctaCountersReply, testNLA(ne, ctaCountersBytes, bytesValue)),
	)
	var parseErrs uint64
	flow, ok := parseConntrackMessageLite(payload, syscall.AF_INET, ne, &parseErrs)
	if !ok || parseErrs != 0 || flow.Proto != 6 || flow.SrcPort != 12345 || flow.DstPort != 443 || flow.Zone != 42 || flow.ForwardPackets != 7 || flow.ReverseBytes != 700 || flow.PacketsPresent || flow.BytesPresent {
		t.Fatalf("TCP parse ok=%v errors=%d flow=%+v", ok, parseErrs, flow)
	}

	for _, proto := range []uint8{6, 17} {
		parseErrs = 0
		if _, ok := parseConntrackMessageLite(testTCPConntrackPayload(ne, syscall.AF_INET6, proto, false), syscall.AF_INET6, ne, &parseErrs); ok || parseErrs == 0 {
			t.Fatalf("protocol %d without ports accepted: errors=%d", proto, parseErrs)
		}
	}
	parseErrs = 0
	if flow, ok := parseConntrackMessageLite(testTCPConntrackPayload(ne, syscall.AF_INET, 132, false), syscall.AF_INET, ne, &parseErrs); !ok || flow.Proto != 132 || parseErrs != 0 {
		t.Fatalf("portless non-TCP/UDP protocol parse ok=%v errors=%d flow=%+v", ok, parseErrs, flow)
	}
}

func TestParseConntrackRejectsWrongICMPAttributeFamily(t *testing.T) {
	ne := nativeEndian()
	tests := []struct {
		name     string
		family   int
		proto    uint8
		srcType  uint16
		dstType  uint16
		idType   uint16
		typeType uint16
		codeType uint16
		src      []byte
		dst      []byte
	}{
		{
			name: "IPv4 ICMP with IPv6 identity attributes", family: syscall.AF_INET, proto: 1,
			srcType: ctaIPV4Src, dstType: ctaIPV4Dst,
			idType: ctaProtoICMPv6ID, typeType: ctaProtoICMPv6Type, codeType: ctaProtoICMPv6Code,
			src: []byte{192, 0, 2, 1}, dst: []byte{198, 51, 100, 2},
		},
		{
			name: "IPv6 ICMP with IPv4 identity attributes", family: syscall.AF_INET6, proto: 58,
			srcType: ctaIPV6Src, dstType: ctaIPV6Dst,
			idType: ctaProtoICMPID, typeType: ctaProtoICMPType, codeType: ctaProtoICMPCode,
			src: append([]byte{0x20, 0x01}, make([]byte, 14)...),
			dst: append([]byte{0x20, 0x01}, append(make([]byte, 13), 1)...),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ipAttrs := append(testNLA(ne, tc.srcType, tc.src), testNLA(ne, tc.dstType, tc.dst)...)
			payload := testConntrackPayloadFromAttrs(tc.family,
				testNestedNLA(ne, ctaTupleOrig,
					testNestedNLA(ne, ctaTupleIP, ipAttrs),
					testNestedNLA(ne, ctaTupleProto, testICMPProtoAttrs(ne, tc.proto, tc.idType, tc.typeType, tc.codeType)),
				),
				testStatusAttr(ne, IPS_SEEN_REPLY),
			)
			var parseErrs uint64
			if _, ok := parseConntrackMessageLite(payload, tc.family, ne, &parseErrs); ok || parseErrs == 0 {
				t.Fatalf("wrong-family ICMP identity accepted: ok=%v parseErrs=%d", ok, parseErrs)
			}
		})
	}
}

func TestParseConntrackRejectsMixedOrNonICMPIdentityAttributes(t *testing.T) {
	ne := nativeEndian()
	ipAttrs := append(testNLA(ne, ctaIPV4Src, []byte{192, 0, 2, 1}), testNLA(ne, ctaIPV4Dst, []byte{198, 51, 100, 2})...)
	id := []byte{0, 1}
	port := []byte{0x01, 0xbb}
	tests := []struct {
		name       string
		protoAttrs []byte
	}{
		{
			name: "mixed ICMP identity families",
			protoAttrs: append(testNLA(ne, ctaProtoNum, []byte{1}),
				append(testNLA(ne, ctaProtoICMPID, id),
					append(testNLA(ne, ctaProtoICMPv6Type, []byte{8}), testNLA(ne, ctaProtoICMPCode, []byte{0})...)...)...),
		},
		{
			name: "ICMP identity on TCP tuple",
			protoAttrs: append(testNLA(ne, ctaProtoNum, []byte{6}),
				append(testNLA(ne, ctaProtoSrcPort, port),
					append(testNLA(ne, ctaProtoDstPort, port), testNLA(ne, ctaProtoICMPID, id)...)...)...),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			payload := testConntrackPayloadFromAttrs(syscall.AF_INET,
				testNestedNLA(ne, ctaTupleOrig,
					testNestedNLA(ne, ctaTupleIP, ipAttrs),
					testNestedNLA(ne, ctaTupleProto, tc.protoAttrs),
				),
				testStatusAttr(ne, IPS_SEEN_REPLY),
			)
			var parseErrs uint64
			if _, ok := parseConntrackMessageLite(payload, syscall.AF_INET, ne, &parseErrs); ok || parseErrs == 0 {
				t.Fatalf("invalid ICMP identity accepted: ok=%v parseErrs=%d", ok, parseErrs)
			}
		})
	}
}

func TestParseConntrackRejectsMixedAndAsymmetricProtocolIdentity(t *testing.T) {
	ne := nativeEndian()
	port := []byte{0x01, 0xbb}

	tests := []struct {
		name       string
		family     int
		ipAttrs    []byte
		protoAttrs []byte
	}{
		{
			name:   "IPv4 ICMP with ports",
			family: syscall.AF_INET,
			ipAttrs: append(testNLA(ne, ctaIPV4Src, []byte{192, 0, 2, 1}),
				testNLA(ne, ctaIPV4Dst, []byte{198, 51, 100, 2})...),
			protoAttrs: append(testICMPProtoAttrs(ne, 1, ctaProtoICMPID, ctaProtoICMPType, ctaProtoICMPCode),
				append(testNLA(ne, ctaProtoSrcPort, port), testNLA(ne, ctaProtoDstPort, port)...)...),
		},
		{
			name:   "IPv6 ICMP with ports",
			family: syscall.AF_INET6,
			ipAttrs: append(testNLA(ne, ctaIPV6Src, append([]byte{0x20, 0x01}, make([]byte, 14)...)),
				testNLA(ne, ctaIPV6Dst, append([]byte{0x20, 0x01}, append(make([]byte, 13), 1)...))...),
			protoAttrs: append(testICMPProtoAttrs(ne, 58, ctaProtoICMPv6ID, ctaProtoICMPv6Type, ctaProtoICMPv6Code),
				append(testNLA(ne, ctaProtoSrcPort, port), testNLA(ne, ctaProtoDstPort, port)...)...),
		},
		{
			name:   "non-TCP protocol with only source port",
			family: syscall.AF_INET,
			ipAttrs: append(testNLA(ne, ctaIPV4Src, []byte{192, 0, 2, 1}),
				testNLA(ne, ctaIPV4Dst, []byte{198, 51, 100, 2})...),
			protoAttrs: append(testNLA(ne, ctaProtoNum, []byte{132}),
				testNLA(ne, ctaProtoSrcPort, port)...),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			payload := testConntrackPayloadFromAttrs(tc.family,
				testNestedNLA(ne, ctaTupleOrig,
					testNestedNLA(ne, ctaTupleIP, tc.ipAttrs),
					testNestedNLA(ne, ctaTupleProto, tc.protoAttrs),
				),
				testStatusAttr(ne, IPS_SEEN_REPLY),
			)
			var parseErrs uint64
			if _, ok := parseConntrackMessageLite(payload, tc.family, ne, &parseErrs); ok || parseErrs == 0 {
				t.Fatalf("mixed protocol identity accepted: ok=%v parseErrs=%d", ok, parseErrs)
			}
		})
	}

	// Port-bearing protocols other than TCP/UDP remain forward-compatible when
	// both halves of the port identity are present.
	if flow, ok := parseConntrackMessageLite(testTCPConntrackPayload(ne, syscall.AF_INET, 132, true), syscall.AF_INET, ne, new(uint64)); !ok || flow.SrcPort == 0 || flow.DstPort == 0 {
		t.Fatalf("complete non-TCP/UDP port identity was rejected: ok=%v flow=%+v", ok, flow)
	}
}

func TestParseConntrackRejectsHeaderDuplicateAndAttributeErrors(t *testing.T) {
	ne := nativeEndian()
	valid := testTCPConntrackPayload(ne, syscall.AF_INET, 6, true)
	tests := []struct {
		name    string
		payload []byte
		family  int
	}{
		{"short payload", []byte{1, 2, 3}, syscall.AF_INET},
		{"wrong family", valid, syscall.AF_INET6},
		{"wrong nfnetlink version", append([]byte(nil), valid...), syscall.AF_INET},
		{"duplicate tuple", nil, syscall.AF_INET},
		{"duplicate status", nil, syscall.AF_INET},
		{"bad status length", nil, syscall.AF_INET},
		{"duplicate zone", nil, syscall.AF_INET},
		{"bad zone length", nil, syscall.AF_INET},
		{"duplicate original counters", nil, syscall.AF_INET},
		{"duplicate reply counters", nil, syscall.AF_INET},
		{"malformed original counter", nil, syscall.AF_INET},
		{"malformed reply counter", nil, syscall.AF_INET},
	}
	tests[2].payload[1] = 99
	baseAttrs := valid[4:]
	zone := []byte{0, 1}
	goodCounter := make([]byte, 8)
	tests[3].payload = testConntrackPayloadFromAttrs(syscall.AF_INET, baseAttrs, baseAttrs[:len(baseAttrs)-nlAlign(8)])
	tests[4].payload = testConntrackPayloadFromAttrs(syscall.AF_INET, baseAttrs, testStatusAttr(ne, 0))
	tests[5].payload = testConntrackPayloadFromAttrs(syscall.AF_INET, baseAttrs[:len(baseAttrs)-nlAlign(8)], testNLA(ne, ctaStatus, []byte{1}))
	tests[6].payload = testConntrackPayloadFromAttrs(syscall.AF_INET, baseAttrs, testNLA(ne, ctaZone, zone), testNLA(ne, ctaZone, zone))
	tests[7].payload = testConntrackPayloadFromAttrs(syscall.AF_INET, baseAttrs, testNLA(ne, ctaZone, []byte{1}))
	tests[8].payload = testConntrackPayloadFromAttrs(syscall.AF_INET, baseAttrs,
		testNestedNLA(ne, ctaCountersOrig, testNLA(ne, ctaCountersPackets, goodCounter)),
		testNestedNLA(ne, ctaCountersOrig, testNLA(ne, ctaCountersPackets, goodCounter)))
	tests[9].payload = testConntrackPayloadFromAttrs(syscall.AF_INET, baseAttrs,
		testNestedNLA(ne, ctaCountersReply, testNLA(ne, ctaCountersBytes, goodCounter)),
		testNestedNLA(ne, ctaCountersReply, testNLA(ne, ctaCountersBytes, goodCounter)))
	tests[10].payload = testConntrackPayloadFromAttrs(syscall.AF_INET, baseAttrs,
		testNestedNLA(ne, ctaCountersOrig, testNLA(ne, ctaCountersPackets, []byte{1})))
	tests[11].payload = testConntrackPayloadFromAttrs(syscall.AF_INET, baseAttrs,
		testNestedNLA(ne, ctaCountersReply, testNLA(ne, ctaCountersBytes, []byte{1})))

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var parseErrs uint64
			if _, ok := parseConntrackMessageLite(tc.payload, tc.family, ne, &parseErrs); ok || parseErrs == 0 {
				t.Fatalf("invalid payload accepted: ok=%v parseErrs=%d", ok, parseErrs)
			}
		})
	}
}

func TestTupleGroupIPProtocolAndCounterDuplicateValidation(t *testing.T) {
	ne := nativeEndian()
	ipAttrs := append(testNLA(ne, ctaIPV4Src, []byte{192, 0, 2, 1}), testNLA(ne, ctaIPV4Dst, []byte{198, 51, 100, 2})...)
	protoAttrs := testNLA(ne, ctaProtoNum, []byte{6})
	srcPort := []byte{0x30, 0x39}
	dstPort := []byte{0x01, 0xbb}
	protoAttrs = append(protoAttrs, testNLA(ne, ctaProtoSrcPort, srcPort)...)
	protoAttrs = append(protoAttrs, testNLA(ne, ctaProtoDstPort, dstPort)...)

	for _, val := range [][]byte{
		testNestedNLA(ne, ctaTupleIP, ipAttrs),
		testNestedNLA(ne, ctaTupleProto, protoAttrs),
		append(testNestedNLA(ne, ctaTupleIP, ipAttrs), testNestedNLA(ne, ctaTupleIP, ipAttrs)...),
		append(testNestedNLA(ne, ctaTupleProto, protoAttrs), testNestedNLA(ne, ctaTupleProto, protoAttrs)...),
	} {
		var state conntrackTupleParseState
		var parseErrs uint64
		if parseTupleOrig(val, syscall.AF_INET, ne, &state, &parseErrs) {
			t.Fatalf("invalid tuple group accepted: %+v", state)
		}
	}

	for _, attrs := range [][]byte{
		append(ipAttrs, testNLA(ne, ctaIPV4Src, []byte{192, 0, 2, 9})...),
		append(ipAttrs, testNLA(ne, ctaIPV4Dst, []byte{198, 51, 100, 9})...),
		testNLA(ne, ctaIPV6Src, make([]byte, 16)),
		testNLA(ne, ctaIPV4Src, []byte{1, 2, 3}),
	} {
		var state conntrackTupleParseState
		var parseErrs uint64
		if parseTupleIP(attrs, syscall.AF_INET, ne, &state, &parseErrs) || parseErrs == 0 {
			t.Fatalf("invalid IP tuple accepted: %+v errors=%d", state, parseErrs)
		}
	}

	protoCases := [][]byte{
		append(protoAttrs, testNLA(ne, ctaProtoNum, []byte{17})...),
		append(protoAttrs, testNLA(ne, ctaProtoSrcPort, srcPort)...),
		append(protoAttrs, testNLA(ne, ctaProtoDstPort, dstPort)...),
		testNLA(ne, ctaProtoNum, []byte{6, 7}),
		testNLA(ne, ctaProtoSrcPort, []byte{1}),
		testNLA(ne, ctaProtoICMPID, []byte{1}),
		testNLA(ne, ctaProtoICMPType, []byte{1, 2}),
		testNLA(ne, ctaProtoICMPCode, []byte{1, 2}),
	}
	for _, attrs := range protoCases {
		var state conntrackTupleParseState
		var parseErrs uint64
		if parseTupleProto(attrs, ne, &state, &parseErrs) || parseErrs == 0 {
			t.Fatalf("invalid protocol tuple accepted: %+v errors=%d", state, parseErrs)
		}
	}

	packets := make([]byte, 8)
	bytesValue := make([]byte, 8)
	for _, attrs := range [][]byte{
		append(testNLA(ne, ctaCountersPackets, packets), testNLA(ne, ctaCountersPackets, packets)...),
		append(testNLA(ne, ctaCountersBytes, bytesValue), testNLA(ne, ctaCountersBytes, bytesValue)...),
	} {
		var gotPackets, gotBytes uint64
		var parseErrs uint64
		parseCounters(attrs, ne, &gotPackets, &gotBytes, &parseErrs)
		if parseErrs == 0 {
			t.Fatal("duplicate counters were accepted")
		}
	}
}

func TestConntrackDatagramAllControlAndHeaderErrors(t *testing.T) {
	ne := nativeEndian()
	seq := uint32(77)
	validType := uint16((nfnlSubsysCtNetlink << 8) | ipctnlMsgCtNew)
	validPayload := testConntrackPayload(ne, IPS_SEEN_REPLY, false, 1)
	if _, _, _, err := parseConntrackNetlinkDatagram(make([]byte, 16), 0, 99, 0, seq, syscall.AF_INET, nil); err == nil {
		t.Fatal("non-kernel sender PID was accepted")
	}
	if _, _, parseErrs, err := parseConntrackNetlinkDatagram(make([]byte, 15), 0, 0, 0, seq, syscall.AF_INET, nil); err == nil || parseErrs != 1 {
		t.Fatalf("short datagram err=%v parseErrs=%d", err, parseErrs)
	}

	badLength := make([]byte, 16)
	ne.PutUint32(badLength[:4], 15)
	ne.PutUint32(badLength[8:12], seq)
	if _, _, _, err := parseConntrackNetlinkDatagram(badLength, 0, 0, 0, seq, syscall.AF_INET, nil); err == nil {
		t.Fatal("short declared message length was accepted")
	}
	missingPadding := make([]byte, 18)
	ne.PutUint32(missingPadding[:4], 17)
	ne.PutUint16(missingPadding[4:6], validType)
	ne.PutUint32(missingPadding[8:12], seq)
	if _, _, _, err := parseConntrackNetlinkDatagram(missingPadding, 0, 0, 0, seq, syscall.AF_INET, nil); err == nil {
		t.Fatal("missing message alignment padding was accepted")
	}

	headerPID := testNetlinkMessage(ne, validType, 0, seq, validPayload)
	ne.PutUint32(headerPID[12:16], 12)
	if _, _, _, err := parseConntrackNetlinkDatagram(headerPID, 0, 0, 0, seq, syscall.AF_INET, nil); err == nil {
		t.Fatal("nonzero netlink header PID was accepted")
	}
	unexpected := testNetlinkMessage(ne, 0x7fff, 0, seq, nil)
	if _, _, parseErrs, err := parseConntrackNetlinkDatagram(unexpected, 0, 0, 0, seq, syscall.AF_INET, nil); err == nil || parseErrs != 1 {
		t.Fatalf("unexpected message type err=%v parseErrs=%d", err, parseErrs)
	}

	done := testNetlinkMessage(ne, syscall.NLMSG_DONE, 0, seq, nil)
	if _, _, parseErrs, err := parseConntrackNetlinkDatagram(append(done, done...), 0, 0, 0, seq, syscall.AF_INET, nil); err == nil || parseErrs != 1 {
		t.Fatalf("messages after done err=%v parseErrs=%d", err, parseErrs)
	}
	for payloadLength := 1; payloadLength < 4; payloadLength++ {
		shortDone := testNetlinkMessage(ne, syscall.NLMSG_DONE, 0, seq, make([]byte, payloadLength))
		if _, _, parseErrs, err := parseConntrackNetlinkDatagram(shortDone, 0, 0, 0, seq, syscall.AF_INET, nil); err == nil || parseErrs != 1 {
			t.Fatalf("NLMSG_DONE with %d-byte payload err=%v parseErrs=%d", payloadLength, err, parseErrs)
		}
	}
	zeroDonePayload := make([]byte, 4)
	complete, count, parseErrs, err := parseConntrackNetlinkDatagram(testNetlinkMessage(ne, syscall.NLMSG_DONE, 0, seq, zeroDonePayload), 0, 0, 0, seq, syscall.AF_INET, nil)
	if err != nil || !complete || count != 0 || parseErrs != 0 {
		t.Fatalf("zero-error NLMSG_DONE complete=%v count=%d parseErrs=%d err=%v", complete, count, parseErrs, err)
	}
	doneErrorPayload := make([]byte, 4)
	doneErrno := int32(-int32(syscall.EPERM))
	ne.PutUint32(doneErrorPayload, uint32(doneErrno))
	doneError := testNetlinkMessage(ne, syscall.NLMSG_DONE, 0, seq, doneErrorPayload)
	if _, _, _, err := parseConntrackNetlinkDatagram(doneError, 0, 0, 0, seq, syscall.AF_INET, nil); !errors.Is(err, syscall.EPERM) {
		t.Fatalf("done errno=%v, want EPERM", err)
	}

	shortError := testNetlinkMessage(ne, syscall.NLMSG_ERROR, 0, seq, nil)
	if _, _, parseErrs, err := parseConntrackNetlinkDatagram(shortError, 0, 0, 0, seq, syscall.AF_INET, nil); err == nil || parseErrs != 1 {
		t.Fatalf("short NLMSG_ERROR err=%v parseErrs=%d", err, parseErrs)
	}
	errorPayload := make([]byte, 4)
	errorErrno := int32(-int32(syscall.ENOENT))
	ne.PutUint32(errorPayload, uint32(errorErrno))
	if _, _, _, err := parseConntrackNetlinkDatagram(testNetlinkMessage(ne, syscall.NLMSG_ERROR, 0, seq, errorPayload), 0, 0, 0, seq, syscall.AF_INET, nil); !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("NLMSG_ERROR errno=%v, want ENOENT", err)
	}
	ackPayload := make([]byte, 4)
	complete, count, parseErrs, err = parseConntrackNetlinkDatagram(testNetlinkMessage(ne, syscall.NLMSG_ERROR, 0, seq, ackPayload), 0, 0, 0, seq, syscall.AF_INET, nil)
	if err != nil || complete || count != 0 || parseErrs != 0 {
		t.Fatalf("netlink ACK complete=%v count=%d errors=%d err=%v", complete, count, parseErrs, err)
	}

	complete, count, parseErrs, err = parseConntrackNetlinkDatagram(testNetlinkMessage(ne, validType, 0, seq, validPayload), 0, 0, 0, seq, syscall.AF_INET, nil)
	if err != nil || complete || count != 1 || parseErrs != 0 {
		t.Fatalf("data-only datagram complete=%v count=%d errors=%d err=%v", complete, count, parseErrs, err)
	}
}
