package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

var conntrackReadBufPool = sync.Pool{
	New: func() any { return make([]byte, 512<<10) },
}

var errConntrackFamiliesDisabled = errors.New("conntrack collection has no enabled address families")

const (
	netlinkNetfilter = 12
	nlmsgOverrun     = 4
	nlmFDumpIntr     = 0x10

	nfnlSubsysCtNetlink = 1
	ipctnlMsgCtNew      = 0
	ipctnlMsgCtGet      = 1

	nfnetlinkV0 = 0

	nlaTypeMask = 0x3fff
)
const (
	ctaTupleOrig     = 1
	ctaStatus        = 3
	ctaCountersOrig  = 9
	ctaCountersReply = 10
	ctaZone          = 18

	ctaTupleIP    = 1
	ctaTupleProto = 2

	ctaIPV4Src = 1
	ctaIPV4Dst = 2
	ctaIPV6Src = 3
	ctaIPV6Dst = 4

	ctaProtoNum        = 1
	ctaProtoSrcPort    = 2
	ctaProtoDstPort    = 3
	ctaProtoICMPID     = 4
	ctaProtoICMPType   = 5
	ctaProtoICMPCode   = 6
	ctaProtoICMPv6ID   = 7
	ctaProtoICMPv6Type = 8
	ctaProtoICMPv6Code = 9

	ctaCountersPackets = 1
	ctaCountersBytes   = 2
)

func (cm *ConntrackManager) conntrackStaleSeconds() float64 {
	last := atomic.LoadInt64(&cm.conntrackLastSuccessUnix)
	if last <= 0 {
		return -1
	}
	stale := time.Since(time.Unix(last, 0)).Seconds()
	if stale < 0 {
		return 0
	}
	return stale
}
func (cm *ConntrackManager) readConntrackRawLite() ([]ConntrackFlowLite, []ConntrackFlowLite, error) {
	if !cm.conntrackIPv4Enable && !cm.conntrackIPv6Enable {
		atomic.StoreUint64(&cm.conntrackRawOK, 0)
		return nil, nil, errConntrackFamiliesDisabled
	}

	var (
		v4    []ConntrackFlowLite
		v6    []ConntrackFlowLite
		errV4 error
		errV6 error
		wg    sync.WaitGroup
	)

	dump := func(enabled bool, family int, out *[]ConntrackFlowLite, errp *error) {
		if !enabled {
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			var parseErrs, enobufs uint64
			*out, parseErrs, enobufs, *errp = conntrackDumpFamilyLite(family, cm.conntrackRawRcvBufBytes, cm.conntrackNetlinkRecvTimeout)
			if parseErrs > 0 {
				atomic.AddUint64(&cm.conntrackRawParseErrorsTotal, parseErrs)
			}
			if enobufs > 0 {
				atomic.AddUint64(&cm.conntrackRawENOBUFSTotal, enobufs)
			}
		}()
	}

	dump(cm.conntrackIPv4Enable, syscall.AF_INET, &v4, &errV4)
	dump(cm.conntrackIPv6Enable, syscall.AF_INET6, &v6, &errV6)

	wg.Wait()

	readErr := newConntrackAggregateError(cm.conntrackIPv4Enable, cm.conntrackIPv6Enable, errV4, errV6)
	if readErr != nil {
		atomic.StoreUint64(&cm.conntrackRawOK, 0)
		if readErr.Partial {
			if cm.conntrackIPv4Enable && errV4 != nil {
				logKV(LogLevelNotice, "metric", "conntrack", "conntrack_raw_partial_failure", "family", "v4", "err", errV4)
			}
			if cm.conntrackIPv6Enable && errV6 != nil {
				logKV(LogLevelNotice, "metric", "conntrack", "conntrack_raw_partial_failure", "family", "v6", "err", errV6)
			}
		}
		return nil, nil, readErr
	}

	atomic.StoreUint64(&cm.conntrackRawOK, 1)
	atomic.StoreInt64(&cm.conntrackLastSuccessUnix, time.Now().Unix())
	return v4, v6, nil

}
func nativeEndian() binary.ByteOrder {
	var x uint16 = 1
	if *(*byte)(unsafe.Pointer(&x)) == 1 {
		return binary.LittleEndian
	}
	return binary.BigEndian
}
func nlAlign(n int) int {
	return (n + 3) &^ 3
}
func conntrackDumpFamilyLiteConsume(
	family int,
	rcvBufBytes int,
	rcvTimeout time.Duration,
	consume func(ConntrackFlowLite),
) (uint64, uint64, uint64, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, netlinkNetfilter)
	if err != nil {
		return 0, 0, 0, err
	}
	defer syscall.Close(fd)

	if rcvBufBytes > 0 {
		_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, rcvBufBytes)
	}

	if rcvTimeout <= 0 {
		rcvTimeout = 15 * time.Second
	}

	tv := syscall.NsecToTimeval(rcvTimeout.Nanoseconds())
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return 0, 0, 0, err
	}

	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return 0, 0, 0, err
	}
	boundAddr, err := syscall.Getsockname(fd)
	if err != nil {
		return 0, 0, 0, err
	}
	boundNetlink, ok := boundAddr.(*syscall.SockaddrNetlink)
	if !ok {
		return 0, 0, 0, fmt.Errorf("unexpected bound netlink address type %T", boundAddr)
	}
	localPID := boundNetlink.Pid
	if localPID == 0 {
		return 0, 0, 0, fmt.Errorf("kernel did not assign a netlink port id")
	}

	ne := nativeEndian()

	seq := uint32(time.Now().UnixNano())
	reqType := uint16((nfnlSubsysCtNetlink << 8) | ipctnlMsgCtGet)

	nlHdr := make([]byte, 16)
	ne.PutUint32(nlHdr[0:4], uint32(16+4))
	ne.PutUint16(nlHdr[4:6], reqType)
	ne.PutUint16(nlHdr[6:8], uint16(syscall.NLM_F_REQUEST|syscall.NLM_F_ROOT|syscall.NLM_F_MATCH))
	ne.PutUint32(nlHdr[8:12], seq)
	ne.PutUint32(nlHdr[12:16], localPID)

	nfHdr := make([]byte, 4)
	nfHdr[0] = byte(family)
	nfHdr[1] = nfnetlinkV0
	binary.BigEndian.PutUint16(nfHdr[2:4], 0)

	req := append(nlHdr, nfHdr...)
	if err := syscall.Sendto(fd, req, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return 0, 0, 0, err
	}

	buf := conntrackReadBufPool.Get().([]byte)
	buf = buf[:cap(buf)]
	defer conntrackReadBufPool.Put(buf)

	var (
		count     uint64
		parseErrs uint64
		enobufs   uint64
	)

	for {
		n, _, recvFlags, from, err := syscall.Recvmsg(fd, buf, nil, 0)
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			if errors.Is(err, syscall.ENOBUFS) {
				enobufs++
				return count, parseErrs, enobufs, err
			}
			return count, parseErrs, enobufs, err
		}
		var senderPID uint32
		if from != nil {
			sender, ok := from.(*syscall.SockaddrNetlink)
			if !ok {
				return count, parseErrs, enobufs, fmt.Errorf("unexpected netlink sender type %T", from)
			}
			senderPID = sender.Pid
		}
		done, parsed, datagramParseErrs, err := parseConntrackNetlinkDatagram(buf[:n], recvFlags, senderPID, localPID, seq, family, consume)
		count += parsed
		parseErrs += datagramParseErrs
		if err != nil {
			return count, parseErrs, enobufs, err
		}
		if done {
			return count, parseErrs, enobufs, nil
		}
	}
}

func parseConntrackNetlinkDatagram(data []byte, recvFlags int, senderPID, localPID, seq uint32, family int, consume func(ConntrackFlowLite)) (bool, uint64, uint64, error) {
	if recvFlags&syscall.MSG_TRUNC != 0 {
		return false, 0, 0, fmt.Errorf("truncated netlink datagram")
	}
	if senderPID != 0 {
		return false, 0, 0, fmt.Errorf("unexpected netlink sender pid %d", senderPID)
	}
	if len(data) < 16 {
		return false, 0, 1, fmt.Errorf("short netlink datagram: %d bytes", len(data))
	}

	ne := nativeEndian()
	var count uint64
	var parseErrs uint64
	for offset := 0; offset < len(data); {
		if len(data)-offset < 16 {
			return false, count, parseErrs + 1, fmt.Errorf("trailing short netlink header: %d bytes", len(data)-offset)
		}
		msgLen := int(ne.Uint32(data[offset : offset+4]))
		if msgLen < 16 || offset+msgLen > len(data) {
			return false, count, parseErrs + 1, fmt.Errorf("malformed netlink message length %d", msgLen)
		}
		next := offset + nlAlign(msgLen)
		if next > len(data) {
			if offset+msgLen != len(data) {
				return false, count, parseErrs + 1, fmt.Errorf("missing netlink alignment padding")
			}
			next = len(data)
		}

		msgType := ne.Uint16(data[offset+4 : offset+6])
		msgFlags := ne.Uint16(data[offset+6 : offset+8])
		msgSeq := ne.Uint32(data[offset+8 : offset+12])
		msgPID := ne.Uint32(data[offset+12 : offset+16])
		if msgSeq != seq {
			return false, count, parseErrs, fmt.Errorf("netlink sequence mismatch: got %d want %d", msgSeq, seq)
		}
		// Conntrack dumps address reply headers to the requesting netlink
		// port on current kernels. Accept zero as well for kernel-version and
		// family compatibility; the recvmsg sockaddr must still identify the
		// kernel (PID 0) and the sequence must match exactly.
		if msgPID != 0 && msgPID != localPID {
			return false, count, parseErrs, fmt.Errorf("netlink header pid mismatch: got %d want %d", msgPID, localPID)
		}
		if msgFlags&nlmFDumpIntr != 0 {
			return false, count, parseErrs, fmt.Errorf("netlink dump interrupted")
		}

		switch msgType {
		case syscall.NLMSG_NOOP:
			// NLMSG_NOOP is a valid netlink control message and carries no
			// conntrack data. Header sequence, PID and interruption flags have
			// already been validated above.
		case syscall.NLMSG_DONE:
			if next != len(data) {
				return false, count, parseErrs + 1, fmt.Errorf("messages found after NLMSG_DONE")
			}
			if msgLen > 16 && msgLen < 20 {
				return false, count, parseErrs + 1, fmt.Errorf("NLMSG_DONE has truncated error payload")
			}
			if msgLen >= 20 {
				errno := int32(ne.Uint32(data[offset+16 : offset+20]))
				if errno != 0 {
					return false, count, parseErrs, syscall.Errno(-errno)
				}
			}
			return true, count, parseErrs, nil
		case syscall.NLMSG_ERROR:
			if msgLen < 20 {
				return false, count, parseErrs + 1, fmt.Errorf("NLMSG_ERROR too short")
			}
			errno := int32(ne.Uint32(data[offset+16 : offset+20]))
			if errno != 0 {
				return false, count, parseErrs, syscall.Errno(-errno)
			}
		case nlmsgOverrun:
			return false, count, parseErrs, fmt.Errorf("netlink overrun")
		default:
			subsystem := msgType >> 8
			operation := msgType & 0xff
			if subsystem != nfnlSubsysCtNetlink || (operation != ipctnlMsgCtNew && operation != ipctnlMsgCtGet) {
				return false, count, parseErrs + 1, fmt.Errorf("unexpected conntrack netlink message type %#x", msgType)
			}
			payload := data[offset+16 : offset+msgLen]
			before := parseErrs
			flow, ok := parseConntrackMessageLite(payload, family, ne, &parseErrs)
			if !ok || parseErrs != before {
				if parseErrs == before {
					parseErrs++
				}
				return false, count, parseErrs, fmt.Errorf("malformed conntrack payload")
			}
			if consume != nil {
				consume(flow)
			}
			count++
		}
		offset = next
	}
	return false, count, parseErrs, nil
}
func conntrackDumpFamilyLite(family int, rcvBufBytes int, rcvTimeout time.Duration) ([]ConntrackFlowLite, uint64, uint64, error) {
	var (
		flows     = make([]ConntrackFlowLite, 0, 4096)
		parseErrs uint64
		enobufs   uint64
	)

	_, parseErrs, enobufs, err := conntrackDumpFamilyLiteConsume(family, rcvBufBytes, rcvTimeout, func(flow ConntrackFlowLite) {
		flows = append(flows, flow)
	})
	return flows, parseErrs, enobufs, err
}

type conntrackTupleParseState struct {
	srcKey IPKey
	dstKey IPKey

	srcPort        uint16
	dstPort        uint16
	proto          uint8
	icmpID         uint16
	icmpType       uint8
	icmpCode       uint8
	icmpAttrFamily uint8

	srcPresent      bool
	dstPresent      bool
	protoPresent    bool
	srcPortPresent  bool
	dstPortPresent  bool
	icmpIDPresent   bool
	icmpTypePresent bool
	icmpCodePresent bool
}

func walkNetlinkAttributes(data []byte, ne binary.ByteOrder, parseErrs *uint64, visit func(uint16, []byte) bool) bool {
	for offset := 0; offset < len(data); {
		if len(data)-offset < 4 {
			(*parseErrs)++
			return false
		}
		nlaLen := int(ne.Uint16(data[offset : offset+2]))
		if nlaLen < 4 || offset+nlaLen > len(data) {
			(*parseErrs)++
			return false
		}
		nlaType := ne.Uint16(data[offset+2:offset+4]) & nlaTypeMask
		if !visit(nlaType, data[offset+4:offset+nlaLen]) {
			return false
		}
		next := offset + nlAlign(nlaLen)
		if next > len(data) {
			if offset+nlaLen != len(data) {
				(*parseErrs)++
				return false
			}
			next = len(data)
		}
		offset = next
	}
	return true
}

func parseConntrackMessageLite(payload []byte, family int, ne binary.ByteOrder, parseErrs *uint64) (ConntrackFlowLite, bool) {
	if len(payload) < 4 {
		(*parseErrs)++
		return ConntrackFlowLite{}, false
	}
	if int(payload[0]) != family || payload[1] != nfnetlinkV0 {
		(*parseErrs)++
		return ConntrackFlowLite{}, false
	}

	var (
		tuple  conntrackTupleParseState
		zone   uint16
		status uint32

		tuplePresent         bool
		statusPresent        bool
		zonePresent          bool
		origCountersPresent  bool
		replyCountersPresent bool

		origPkts            uint64
		origBytes           uint64
		replyPkts           uint64
		replyBytes          uint64
		origPacketsPresent  bool
		origBytesPresent    bool
		replyPacketsPresent bool
		replyBytesPresent   bool
	)

	if !walkNetlinkAttributes(payload[4:], ne, parseErrs, func(nlaType uint16, val []byte) bool {
		switch nlaType {
		case ctaTupleOrig:
			if tuplePresent {
				(*parseErrs)++
				return false
			}
			tuplePresent = true
			return parseTupleOrig(val, family, ne, &tuple, parseErrs)
		case ctaStatus:
			if statusPresent || len(val) != 4 {
				(*parseErrs)++
				return false
			}
			statusPresent = true
			status = binary.BigEndian.Uint32(val)
		case ctaZone:
			if zonePresent || len(val) != 2 {
				(*parseErrs)++
				return false
			}
			zonePresent = true
			zone = binary.BigEndian.Uint16(val)
		case ctaCountersOrig:
			if origCountersPresent {
				(*parseErrs)++
				return false
			}
			origCountersPresent = true
			before := *parseErrs
			origPacketsPresent, origBytesPresent = parseCounters(val, ne, &origPkts, &origBytes, parseErrs)
			return *parseErrs == before
		case ctaCountersReply:
			if replyCountersPresent {
				(*parseErrs)++
				return false
			}
			replyCountersPresent = true
			before := *parseErrs
			replyPacketsPresent, replyBytesPresent = parseCounters(val, ne, &replyPkts, &replyBytes, parseErrs)
			return *parseErrs == before
		}
		return true
	}) {
		return ConntrackFlowLite{}, false
	}

	if !tuplePresent || !statusPresent || !tuple.srcPresent || !tuple.dstPresent || !tuple.protoPresent {
		(*parseErrs)++
		return ConntrackFlowLite{}, false
	}
	if tuple.srcPortPresent != tuple.dstPortPresent {
		(*parseErrs)++
		return ConntrackFlowLite{}, false
	}
	if (tuple.proto == 6 || tuple.proto == 17) && (!tuple.srcPortPresent || !tuple.dstPortPresent) {
		(*parseErrs)++
		return ConntrackFlowLite{}, false
	}
	switch tuple.proto {
	case 1:
		if family != syscall.AF_INET || tuple.srcPortPresent || tuple.icmpAttrFamily != 4 || !tuple.icmpIDPresent || !tuple.icmpTypePresent || !tuple.icmpCodePresent {
			(*parseErrs)++
			return ConntrackFlowLite{}, false
		}
	case 58:
		if family != syscall.AF_INET6 || tuple.srcPortPresent || tuple.icmpAttrFamily != 6 || !tuple.icmpIDPresent || !tuple.icmpTypePresent || !tuple.icmpCodePresent {
			(*parseErrs)++
			return ConntrackFlowLite{}, false
		}
	default:
		if tuple.icmpIDPresent || tuple.icmpTypePresent || tuple.icmpCodePresent {
			(*parseErrs)++
			return ConntrackFlowLite{}, false
		}
	}

	return ConntrackFlowLite{
		SrcIP:          tuple.srcKey,
		DstIP:          tuple.dstKey,
		SrcPort:        tuple.srcPort,
		DstPort:        tuple.dstPort,
		Proto:          tuple.proto,
		Zone:           zone,
		Status:         status,
		ICMPID:         tuple.icmpID,
		ICMPType:       tuple.icmpType,
		ICMPCode:       tuple.icmpCode,
		ForwardPackets: origPkts,
		ForwardBytes:   origBytes,
		ReversePackets: replyPkts,
		ReverseBytes:   replyBytes,
		PacketsPresent: origPacketsPresent && replyPacketsPresent,
		BytesPresent:   origBytesPresent && replyBytesPresent,
	}, true
}

func parseTupleOrig(val []byte, family int, ne binary.ByteOrder, tuple *conntrackTupleParseState, parseErrs *uint64) bool {
	ipPresent := false
	protoGroupPresent := false
	if !walkNetlinkAttributes(val, ne, parseErrs, func(nlaType uint16, v []byte) bool {
		switch nlaType {
		case ctaTupleIP:
			if ipPresent {
				(*parseErrs)++
				return false
			}
			ipPresent = true
			return parseTupleIP(v, family, ne, tuple, parseErrs)
		case ctaTupleProto:
			if protoGroupPresent {
				(*parseErrs)++
				return false
			}
			protoGroupPresent = true
			return parseTupleProto(v, ne, tuple, parseErrs)
		}
		return true
	}) {
		return false
	}
	return ipPresent && protoGroupPresent
}

func parseTupleIP(val []byte, family int, ne binary.ByteOrder, tuple *conntrackTupleParseState, parseErrs *uint64) bool {
	return walkNetlinkAttributes(val, ne, parseErrs, func(nlaType uint16, v []byte) bool {
		switch nlaType {
		case ctaIPV4Src:
			if family != syscall.AF_INET || tuple.srcPresent || len(v) != 4 {
				(*parseErrs)++
				return false
			}
			tuple.srcKey = V4BytesToKey(v)
			tuple.srcPresent = true
		case ctaIPV4Dst:
			if family != syscall.AF_INET || tuple.dstPresent || len(v) != 4 {
				(*parseErrs)++
				return false
			}
			tuple.dstKey = V4BytesToKey(v)
			tuple.dstPresent = true
		case ctaIPV6Src:
			if family != syscall.AF_INET6 || tuple.srcPresent || len(v) != 16 {
				(*parseErrs)++
				return false
			}
			tuple.srcKey = V6BytesToKey(v)
			tuple.srcPresent = true
		case ctaIPV6Dst:
			if family != syscall.AF_INET6 || tuple.dstPresent || len(v) != 16 {
				(*parseErrs)++
				return false
			}
			tuple.dstKey = V6BytesToKey(v)
			tuple.dstPresent = true
		}
		return true
	})
}

func parseTupleProto(val []byte, ne binary.ByteOrder, tuple *conntrackTupleParseState, parseErrs *uint64) bool {
	recordICMPFamily := func(family uint8) bool {
		if tuple.icmpAttrFamily != 0 && tuple.icmpAttrFamily != family {
			(*parseErrs)++
			return false
		}
		tuple.icmpAttrFamily = family
		return true
	}
	return walkNetlinkAttributes(val, ne, parseErrs, func(nlaType uint16, v []byte) bool {
		switch nlaType {
		case ctaProtoNum:
			if tuple.protoPresent || len(v) != 1 {
				(*parseErrs)++
				return false
			}
			tuple.proto = v[0]
			tuple.protoPresent = true
		case ctaProtoSrcPort:
			if tuple.srcPortPresent || len(v) != 2 {
				(*parseErrs)++
				return false
			}
			tuple.srcPort = binary.BigEndian.Uint16(v)
			tuple.srcPortPresent = true
		case ctaProtoDstPort:
			if tuple.dstPortPresent || len(v) != 2 {
				(*parseErrs)++
				return false
			}
			tuple.dstPort = binary.BigEndian.Uint16(v)
			tuple.dstPortPresent = true
		case ctaProtoICMPID, ctaProtoICMPv6ID:
			if tuple.icmpIDPresent || len(v) != 2 {
				(*parseErrs)++
				return false
			}
			family := uint8(4)
			if nlaType == ctaProtoICMPv6ID {
				family = 6
			}
			if !recordICMPFamily(family) {
				return false
			}
			tuple.icmpID = binary.BigEndian.Uint16(v)
			tuple.icmpIDPresent = true
		case ctaProtoICMPType, ctaProtoICMPv6Type:
			if tuple.icmpTypePresent || len(v) != 1 {
				(*parseErrs)++
				return false
			}
			family := uint8(4)
			if nlaType == ctaProtoICMPv6Type {
				family = 6
			}
			if !recordICMPFamily(family) {
				return false
			}
			tuple.icmpType = v[0]
			tuple.icmpTypePresent = true
		case ctaProtoICMPCode, ctaProtoICMPv6Code:
			if tuple.icmpCodePresent || len(v) != 1 {
				(*parseErrs)++
				return false
			}
			family := uint8(4)
			if nlaType == ctaProtoICMPv6Code {
				family = 6
			}
			if !recordICMPFamily(family) {
				return false
			}
			tuple.icmpCode = v[0]
			tuple.icmpCodePresent = true
		}
		return true
	})
}

func parseCounters(val []byte, ne binary.ByteOrder, packets *uint64, bytes *uint64, parseErrs *uint64) (bool, bool) {
	packetsPresent := false
	bytesPresent := false
	walkNetlinkAttributes(val, ne, parseErrs, func(nlaType uint16, v []byte) bool {
		switch nlaType {
		case ctaCountersPackets:
			if packetsPresent || len(v) != 8 {
				(*parseErrs)++
				return false
			}
			*packets = binary.BigEndian.Uint64(v)
			packetsPresent = true
		case ctaCountersBytes:
			if bytesPresent || len(v) != 8 {
				(*parseErrs)++
				return false
			}
			*bytes = binary.BigEndian.Uint64(v)
			bytesPresent = true
		}
		return true
	})
	return packetsPresent, bytesPresent
}
