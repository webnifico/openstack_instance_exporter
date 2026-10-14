package main

import (
	"encoding/binary"
	"syscall"
	"testing"
)

func testNLA(ne binary.ByteOrder, typ uint16, payload []byte) []byte {
	n := 4 + len(payload)
	out := make([]byte, nlAlign(n))
	ne.PutUint16(out[0:2], uint16(n))
	ne.PutUint16(out[2:4], typ)
	copy(out[4:], payload)
	return out
}

func testNestedNLA(ne binary.ByteOrder, typ uint16, attrs ...[]byte) []byte {
	payload := make([]byte, 0)
	for _, attr := range attrs {
		payload = append(payload, attr...)
	}
	return testNLA(ne, typ, payload)
}

func testConntrackPayload(ne binary.ByteOrder, status uint32, withCounters bool, icmpID uint16) []byte {
	ipAttrs := testNLA(ne, ctaIPV4Src, []byte{10, 0, 0, 1})
	ipAttrs = append(ipAttrs, testNLA(ne, ctaIPV4Dst, []byte{10, 0, 0, 2})...)

	protoAttrs := testNLA(ne, ctaProtoNum, []byte{1})
	id := make([]byte, 2)
	binary.BigEndian.PutUint16(id, icmpID)
	protoAttrs = append(protoAttrs, testNLA(ne, ctaProtoICMPID, id)...)
	protoAttrs = append(protoAttrs, testNLA(ne, ctaProtoICMPType, []byte{8})...)
	protoAttrs = append(protoAttrs, testNLA(ne, ctaProtoICMPCode, []byte{0})...)

	attrs := testNestedNLA(ne, ctaTupleOrig,
		testNestedNLA(ne, ctaTupleIP, ipAttrs),
		testNestedNLA(ne, ctaTupleProto, protoAttrs),
	)
	statusBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(statusBytes, status)
	attrs = append(attrs, testNLA(ne, ctaStatus, statusBytes)...)

	if withCounters {
		pkts := make([]byte, 8)
		bytes := make([]byte, 8)
		binary.BigEndian.PutUint64(pkts, 3)
		binary.BigEndian.PutUint64(bytes, 300)
		attrs = append(attrs, testNestedNLA(ne, ctaCountersOrig,
			testNLA(ne, ctaCountersPackets, pkts),
			testNLA(ne, ctaCountersBytes, bytes),
		)...)
		attrs = append(attrs, testNestedNLA(ne, ctaCountersReply,
			testNLA(ne, ctaCountersPackets, pkts),
			testNLA(ne, ctaCountersBytes, bytes),
		)...)
	}

	return append([]byte{syscall.AF_INET, nfnetlinkV0, 0, 0}, attrs...)
}

func testConntrackPayloadFromAttrs(family int, attrs ...[]byte) []byte {
	payload := []byte{byte(family), nfnetlinkV0, 0, 0}
	for _, attr := range attrs {
		payload = append(payload, attr...)
	}
	return payload
}

func testICMPProtoAttrs(ne binary.ByteOrder, proto uint8, idType, typeType, codeType uint16) []byte {
	id := make([]byte, 2)
	binary.BigEndian.PutUint16(id, 99)
	attrs := testNLA(ne, ctaProtoNum, []byte{proto})
	attrs = append(attrs, testNLA(ne, idType, id)...)
	attrs = append(attrs, testNLA(ne, typeType, []byte{128})...)
	attrs = append(attrs, testNLA(ne, codeType, []byte{0})...)
	return attrs
}

func testStatusAttr(ne binary.ByteOrder, status uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, status)
	return testNLA(ne, ctaStatus, b)
}

func testNetlinkMessage(ne binary.ByteOrder, typ, flags uint16, seq uint32, payload []byte) []byte {
	msgLen := 16 + len(payload)
	out := make([]byte, nlAlign(msgLen))
	ne.PutUint32(out[0:4], uint32(msgLen))
	ne.PutUint16(out[4:6], typ)
	ne.PutUint16(out[6:8], flags)
	ne.PutUint32(out[8:12], seq)
	ne.PutUint32(out[12:16], 0)
	copy(out[16:], payload)
	return out
}

func TestParseConntrackStatusAndICMPIdentityWithoutAccounting(t *testing.T) {
	ne := nativeEndian()
	var parseErrs uint64
	flow, ok := parseConntrackMessageLite(
		testConntrackPayload(ne, IPS_SEEN_REPLY|IPS_ASSURED, false, 1234),
		syscall.AF_INET,
		ne,
		&parseErrs,
	)
	if !ok || parseErrs != 0 {
		t.Fatalf("parse failed: ok=%v parse_errors=%d", ok, parseErrs)
	}
	if flow.Status != IPS_SEEN_REPLY|IPS_ASSURED {
		t.Fatalf("status=%#x", flow.Status)
	}
	if flow.ICMPID != 1234 || flow.ICMPType != 8 || flow.ICMPCode != 0 {
		t.Fatalf("unexpected ICMP identity: %+v", flow)
	}
	if flow.PacketsPresent || flow.BytesPresent {
		t.Fatalf("counter presence reported for a flow without counters: %+v", flow)
	}
}

func TestParseConntrackCounterPresence(t *testing.T) {
	ne := nativeEndian()
	var parseErrs uint64
	flow, ok := parseConntrackMessageLite(testConntrackPayload(ne, IPS_SEEN_REPLY, true, 1), syscall.AF_INET, ne, &parseErrs)
	if !ok || parseErrs != 0 {
		t.Fatalf("parse failed: ok=%v parse_errors=%d", ok, parseErrs)
	}
	if !flow.PacketsPresent || !flow.BytesPresent {
		t.Fatalf("counter presence missing: %+v", flow)
	}
}

func TestConntrackDatagramRejectsSequenceMismatch(t *testing.T) {
	ne := nativeEndian()
	msg := testNetlinkMessage(ne, uint16((nfnlSubsysCtNetlink<<8)|ipctnlMsgCtNew), 0, 12, testConntrackPayload(ne, 0, false, 1))
	_, _, _, err := parseConntrackNetlinkDatagram(msg, 0, 0, 0, 11, syscall.AF_INET, func(ConntrackFlowLite) {})
	if err == nil {
		t.Fatal("expected sequence mismatch error")
	}
}

func TestConntrackDatagramRejectsTruncationInterruptionAndOverrun(t *testing.T) {
	ne := nativeEndian()
	tests := []struct {
		name      string
		msg       []byte
		recvFlags int
	}{
		{name: "truncated", recvFlags: syscall.MSG_TRUNC, msg: make([]byte, 16)},
		{name: "interrupted", msg: testNetlinkMessage(ne, syscall.NLMSG_DONE, nlmFDumpIntr, 22, nil)},
		{name: "overrun", msg: testNetlinkMessage(ne, nlmsgOverrun, 0, 22, nil)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := parseConntrackNetlinkDatagram(tc.msg, tc.recvFlags, 0, 0, 22, syscall.AF_INET, func(ConntrackFlowLite) {})
			if err == nil {
				t.Fatal("expected incomplete dump error")
			}
		})
	}
}

func TestConntrackDatagramRejectsMalformedMessage(t *testing.T) {
	ne := nativeEndian()
	msg := make([]byte, 16)
	ne.PutUint32(msg[0:4], 64)
	ne.PutUint16(msg[4:6], uint16((nfnlSubsysCtNetlink<<8)|ipctnlMsgCtNew))
	ne.PutUint32(msg[8:12], 7)
	_, _, _, err := parseConntrackNetlinkDatagram(msg, 0, 0, 0, 7, syscall.AF_INET, func(ConntrackFlowLite) {})
	if err == nil {
		t.Fatal("expected malformed message error")
	}
}

func TestConntrackDatagramAcceptsOnlyCompleteSequence(t *testing.T) {
	ne := nativeEndian()
	seq := uint32(44)
	data := testNetlinkMessage(ne, uint16((nfnlSubsysCtNetlink<<8)|ipctnlMsgCtNew), 0, seq, testConntrackPayload(ne, IPS_SEEN_REPLY, false, 1))
	done := testNetlinkMessage(ne, syscall.NLMSG_DONE, 0, seq, nil)
	data = append(data, done...)
	consumed := 0
	complete, count, parseErrs, err := parseConntrackNetlinkDatagram(data, 0, 0, 0, seq, syscall.AF_INET, func(ConntrackFlowLite) {
		consumed++
	})
	if err != nil || !complete || count != 1 || consumed != 1 || parseErrs != 0 {
		t.Fatalf("unexpected parse result: complete=%v count=%d consumed=%d parse_errors=%d err=%v", complete, count, consumed, parseErrs, err)
	}
}

func TestParseConntrackRejectsMissingStatusAndProtocol(t *testing.T) {
	ne := nativeEndian()
	ipAttrs := append(testNLA(ne, ctaIPV4Src, []byte{10, 0, 0, 1}), testNLA(ne, ctaIPV4Dst, []byte{10, 0, 0, 2})...)
	validProto := testICMPProtoAttrs(ne, 1, ctaProtoICMPID, ctaProtoICMPType, ctaProtoICMPCode)

	tests := []struct {
		name    string
		payload []byte
	}{
		{
			name: "missing status",
			payload: testConntrackPayloadFromAttrs(syscall.AF_INET,
				testNestedNLA(ne, ctaTupleOrig,
					testNestedNLA(ne, ctaTupleIP, ipAttrs),
					testNestedNLA(ne, ctaTupleProto, validProto),
				),
			),
		},
		{
			name: "missing protocol number",
			payload: testConntrackPayloadFromAttrs(syscall.AF_INET,
				testNestedNLA(ne, ctaTupleOrig,
					testNestedNLA(ne, ctaTupleIP, ipAttrs),
					testNestedNLA(ne, ctaTupleProto, testNLA(ne, ctaProtoICMPID, []byte{0, 1})),
				),
				testStatusAttr(ne, 0),
			),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var parseErrs uint64
			if _, ok := parseConntrackMessageLite(tc.payload, syscall.AF_INET, ne, &parseErrs); ok || parseErrs == 0 {
				t.Fatalf("malformed payload accepted: ok=%v parse_errors=%d", ok, parseErrs)
			}
		})
	}
}

func TestParseConntrackRejectsPartialIPv4AndIPv6Addresses(t *testing.T) {
	ne := nativeEndian()
	tests := []struct {
		name   string
		family int
		src    []byte
		dst    []byte
		proto  []byte
		srcTyp uint16
		dstTyp uint16
	}{
		{
			name: "partial ipv4", family: syscall.AF_INET,
			src: []byte{10, 0, 0}, dst: []byte{10, 0, 0, 2},
			proto:  testICMPProtoAttrs(ne, 1, ctaProtoICMPID, ctaProtoICMPType, ctaProtoICMPCode),
			srcTyp: ctaIPV4Src, dstTyp: ctaIPV4Dst,
		},
		{
			name: "partial ipv6", family: syscall.AF_INET6,
			src: make([]byte, 15), dst: append(make([]byte, 15), 1),
			proto:  testICMPProtoAttrs(ne, 58, ctaProtoICMPv6ID, ctaProtoICMPv6Type, ctaProtoICMPv6Code),
			srcTyp: ctaIPV6Src, dstTyp: ctaIPV6Dst,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ipAttrs := append(testNLA(ne, tc.srcTyp, tc.src), testNLA(ne, tc.dstTyp, tc.dst)...)
			payload := testConntrackPayloadFromAttrs(tc.family,
				testNestedNLA(ne, ctaTupleOrig,
					testNestedNLA(ne, ctaTupleIP, ipAttrs),
					testNestedNLA(ne, ctaTupleProto, tc.proto),
				),
				testStatusAttr(ne, IPS_SEEN_REPLY),
			)
			var parseErrs uint64
			if _, ok := parseConntrackMessageLite(payload, tc.family, ne, &parseErrs); ok || parseErrs == 0 {
				t.Fatalf("partial address accepted: ok=%v parse_errors=%d", ok, parseErrs)
			}
		})
	}
}

func TestParseIPv6ICMPIdentity(t *testing.T) {
	ne := nativeEndian()
	src := make([]byte, 16)
	dst := make([]byte, 16)
	src[0], src[15] = 0x20, 1
	dst[0], dst[15] = 0x20, 2
	ipAttrs := append(testNLA(ne, ctaIPV6Src, src), testNLA(ne, ctaIPV6Dst, dst)...)
	payload := testConntrackPayloadFromAttrs(syscall.AF_INET6,
		testNestedNLA(ne, ctaTupleOrig,
			testNestedNLA(ne, ctaTupleIP, ipAttrs),
			testNestedNLA(ne, ctaTupleProto, testICMPProtoAttrs(ne, 58, ctaProtoICMPv6ID, ctaProtoICMPv6Type, ctaProtoICMPv6Code)),
		),
		testStatusAttr(ne, IPS_ASSURED),
	)
	var parseErrs uint64
	flow, ok := parseConntrackMessageLite(payload, syscall.AF_INET6, ne, &parseErrs)
	if !ok || parseErrs != 0 || flow.Proto != 58 || flow.ICMPID != 99 || flow.ICMPType != 128 || flow.ICMPCode != 0 {
		t.Fatalf("unexpected IPv6 ICMP parse: ok=%v parse_errors=%d flow=%+v", ok, parseErrs, flow)
	}
}

func TestPairKeyKeepsICMPConnectionsDistinct(t *testing.T) {
	a := IPStrToKey("192.0.2.1")
	b := IPStrToKey("198.51.100.2")
	one := MakeConntrackPairKey(a, 0, b, 0, 1, 100, 8, 0)
	two := MakeConntrackPairKey(a, 0, b, 0, 1, 101, 8, 0)
	if one == two {
		t.Fatal("distinct ICMP IDs collapsed to the same flow identity")
	}
}
