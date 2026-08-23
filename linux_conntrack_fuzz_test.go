package main

import (
	"syscall"
	"testing"
)

func FuzzParseConntrackMessageLite(f *testing.F) {
	ne := nativeEndian()
	f.Add(testConntrackPayload(ne, IPS_SEEN_REPLY|IPS_ASSURED, true, 42), uint8(4))
	f.Add([]byte{}, uint8(4))
	f.Fuzz(func(t *testing.T, payload []byte, familySelector uint8) {
		family := syscall.AF_INET
		if familySelector%2 != 0 {
			family = syscall.AF_INET6
		}
		var parseErrs uint64
		_, _ = parseConntrackMessageLite(payload, family, ne, &parseErrs)
	})
}

func FuzzParseConntrackNetlinkDatagram(f *testing.F) {
	ne := nativeEndian()
	seq := uint32(91)
	seed := testNetlinkMessage(ne, uint16((nfnlSubsysCtNetlink<<8)|ipctnlMsgCtNew), 0, seq, testConntrackPayload(ne, IPS_SEEN_REPLY, false, 5))
	seed = append(seed, testNetlinkMessage(ne, syscall.NLMSG_DONE, 0, seq, nil)...)
	f.Add(seed, uint32(91), uint8(4), 0)
	f.Add([]byte{}, uint32(0), uint8(4), 0)
	f.Fuzz(func(t *testing.T, data []byte, requestedSeq uint32, familySelector uint8, recvFlags int) {
		family := syscall.AF_INET
		if familySelector%2 != 0 {
			family = syscall.AF_INET6
		}
		_, _, _, _ = parseConntrackNetlinkDatagram(data, recvFlags, 0, 0, requestedSeq, family, func(ConntrackFlowLite) {})
	})
}
