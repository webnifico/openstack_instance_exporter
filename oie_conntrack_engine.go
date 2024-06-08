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

const (
	netlinkNetfilter = 12

	nfnlSubsysCtNetlink = 1
	ipctnlMsgCtNew      = 0
	ipctnlMsgCtGet      = 1

	nfnetlinkV0 = 0

	nlaTypeMask = 0x3fff
)

const (
	ctaTupleOrig     = 1
	ctaCountersOrig  = 9
	ctaCountersReply = 10
	ctaZone          = 18

	ctaTupleIP    = 1
	ctaTupleProto = 2

	ctaIPV4Src = 1
	ctaIPV4Dst = 2
	ctaIPV6Src = 3
	ctaIPV6Dst = 4

	ctaProtoNum     = 1
	ctaProtoSrcPort = 2
	ctaProtoDstPort = 3

	ctaCountersPackets = 1
	ctaCountersBytes   = 2
)

func (cm *ConntrackManager) conntrackStaleSeconds() float64 {
	last := atomic.LoadInt64(&cm.conntrackLastSuccessUnix)
	if last <= 0 {
		return -1
	}
	return time.Since(time.Unix(last, 0)).Seconds()
}

func (cm *ConntrackManager) readConntrackRawLite() ([]ConntrackFlowLite, []ConntrackFlowLite, error) {
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
			*out, parseErrs, enobufs, *errp = conntrackDumpFamilyLite(family, cm.conntrackRawRcvBufBytes)
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

	if errV4 != nil || errV6 != nil {
		return v4, v6, fmt.Errorf("conntrack raw read errors: v4=%v v6=%v", errV4, errV6)
	}

	atomic.StoreUint64(&cm.conntrackRawOK, 1)
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

	tv := syscall.NsecToTimeval((5 * time.Second).Nanoseconds())
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return 0, 0, 0, err
	}

	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return 0, 0, 0, err
	}

	ne := nativeEndian()

	seq := uint32(time.Now().UnixNano())
	reqType := uint16((nfnlSubsysCtNetlink << 8) | ipctnlMsgCtGet)

	nlHdr := make([]byte, 16)
	ne.PutUint32(nlHdr[0:4], uint32(16+4))
	ne.PutUint16(nlHdr[4:6], reqType)
	ne.PutUint16(nlHdr[6:8], uint16(syscall.NLM_F_REQUEST|syscall.NLM_F_ROOT|syscall.NLM_F_MATCH))
	ne.PutUint32(nlHdr[8:12], seq)
	ne.PutUint32(nlHdr[12:16], 0)

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
		n, _, err := syscall.Recvfrom(fd, buf, 0)
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
		if n < 16 {
			continue
		}

		offset := 0
		for offset+16 <= n {
			msgLen := int(ne.Uint32(buf[offset : offset+4]))
			if msgLen < 16 || offset+msgLen > n {
				parseErrs++
				break
			}
			msgType := ne.Uint16(buf[offset+4 : offset+6])

			if msgType == syscall.NLMSG_DONE {
				return count, parseErrs, enobufs, nil
			}
			if msgType == syscall.NLMSG_ERROR {
				if msgLen < 16+4 {
					return count, parseErrs, enobufs, fmt.Errorf("nlmsg_error too short")
				}
				errno := int32(ne.Uint32(buf[offset+16 : offset+20]))
				if errno == 0 {
					offset += nlAlign(msgLen)
					continue
				}
				return count, parseErrs, enobufs, syscall.Errno(-errno)
			}

			payload := buf[offset+16 : offset+msgLen]
			if len(payload) < 4 {
				parseErrs++
				offset += nlAlign(msgLen)
				continue
			}

			flow, ok := parseConntrackMessageLite(payload, family, ne, &parseErrs)
			if ok {
				consume(flow)
				count++
			}

			offset += nlAlign(msgLen)
		}
	}
}

func conntrackDumpFamilyLite(family int, rcvBufBytes int) ([]ConntrackFlowLite, uint64, uint64, error) {
	var (
		flows     = make([]ConntrackFlowLite, 0, 4096)
		parseErrs uint64
		enobufs   uint64
	)

	_, parseErrs, enobufs, err := conntrackDumpFamilyLiteConsume(family, rcvBufBytes, func(flow ConntrackFlowLite) {
		flows = append(flows, flow)
	})
	return flows, parseErrs, enobufs, err
}

func parseConntrackMessageLite(payload []byte, family int, ne binary.ByteOrder, parseErrs *uint64) (ConntrackFlowLite, bool) {
	if len(payload) < 4 {
		(*parseErrs)++
		return ConntrackFlowLite{}, false
	}
	attrs := payload[4:]

	var (
		srcKey IPKey
		dstKey IPKey

		srcPort uint16
		dstPort uint16
		proto   uint8
		zone    uint16

		origPkts  uint64
		origBytes uint64
		replyPkts uint64
	)

	for i := 0; i+4 <= len(attrs); {
		nlaLen := int(ne.Uint16(attrs[i : i+2]))
		nlaType := ne.Uint16(attrs[i+2:i+4]) & nlaTypeMask
		if nlaLen < 4 || i+nlaLen > len(attrs) {
			(*parseErrs)++
			break
		}
		val := attrs[i+4 : i+nlaLen]
		switch nlaType {
		case ctaTupleOrig:
			parseTupleOrig(val, family, ne, &srcKey, &dstKey, &srcPort, &dstPort, &proto, parseErrs)
		case ctaZone:
			if len(val) >= 2 {
				zone = binary.BigEndian.Uint16(val[:2])
			}
		case ctaCountersOrig:
			parseCounters(val, ne, &origPkts, &origBytes, parseErrs)
		case ctaCountersReply:
			parseCountersReply(val, ne, &replyPkts, parseErrs)
		}
		i += nlAlign(nlaLen)
	}

	if srcKey == (IPKey{}) || dstKey == (IPKey{}) {
		return ConntrackFlowLite{}, false
	}

	return ConntrackFlowLite{
		SrcIP:          srcKey,
		DstIP:          dstKey,
		SrcPort:        srcPort,
		DstPort:        dstPort,
		Proto:          proto,
		Zone:           zone,
		ForwardPackets: origPkts,
		ForwardBytes:   origBytes,
		ReversePackets: replyPkts,
	}, true
}

func parseTupleOrig(val []byte, family int, ne binary.ByteOrder, srcKey *IPKey, dstKey *IPKey, srcPort *uint16, dstPort *uint16, proto *uint8, parseErrs *uint64) {
	for i := 0; i+4 <= len(val); {
		nlaLen := int(ne.Uint16(val[i : i+2]))
		nlaType := ne.Uint16(val[i+2:i+4]) & nlaTypeMask
		if nlaLen < 4 || i+nlaLen > len(val) {
			(*parseErrs)++
			break
		}
		v := val[i+4 : i+nlaLen]
		switch nlaType {
		case ctaTupleIP:
			parseTupleIP(v, family, ne, srcKey, dstKey, parseErrs)
		case ctaTupleProto:
			parseTupleProto(v, ne, srcPort, dstPort, proto, parseErrs)
		}
		i += nlAlign(nlaLen)
	}
}

func parseTupleIP(val []byte, family int, ne binary.ByteOrder, srcKey *IPKey, dstKey *IPKey, parseErrs *uint64) {
	for i := 0; i+4 <= len(val); {
		nlaLen := int(ne.Uint16(val[i : i+2]))
		nlaType := ne.Uint16(val[i+2:i+4]) & nlaTypeMask
		if nlaLen < 4 || i+nlaLen > len(val) {
			(*parseErrs)++
			break
		}
		v := val[i+4 : i+nlaLen]
		switch {
		case family == syscall.AF_INET && nlaType == ctaIPV4Src && len(v) >= 4:
			*srcKey = V4BytesToKey(v)
		case family == syscall.AF_INET && nlaType == ctaIPV4Dst && len(v) >= 4:
			*dstKey = V4BytesToKey(v)
		case family == syscall.AF_INET6 && nlaType == ctaIPV6Src && len(v) >= 16:
			*srcKey = V6BytesToKey(v)
		case family == syscall.AF_INET6 && nlaType == ctaIPV6Dst && len(v) >= 16:
			*dstKey = V6BytesToKey(v)
		}
		i += nlAlign(nlaLen)
	}
}

func parseTupleProto(val []byte, ne binary.ByteOrder, srcPort *uint16, dstPort *uint16, proto *uint8, parseErrs *uint64) {
	for i := 0; i+4 <= len(val); {
		nlaLen := int(ne.Uint16(val[i : i+2]))
		nlaType := ne.Uint16(val[i+2:i+4]) & nlaTypeMask
		if nlaLen < 4 || i+nlaLen > len(val) {
			(*parseErrs)++
			break
		}
		v := val[i+4 : i+nlaLen]
		switch nlaType {
		case ctaProtoNum:
			if len(v) >= 1 {
				*proto = v[0]
			}
		case ctaProtoSrcPort:
			if len(v) >= 2 {
				*srcPort = binary.BigEndian.Uint16(v[:2])
			}
		case ctaProtoDstPort:
			if len(v) >= 2 {
				*dstPort = binary.BigEndian.Uint16(v[:2])
			}
		}
		i += nlAlign(nlaLen)
	}
}

func parseCounters(val []byte, ne binary.ByteOrder, packets *uint64, bytes *uint64, parseErrs *uint64) {
	for i := 0; i+4 <= len(val); {
		nlaLen := int(ne.Uint16(val[i : i+2]))
		nlaType := ne.Uint16(val[i+2:i+4]) & nlaTypeMask
		if nlaLen < 4 || i+nlaLen > len(val) {
			(*parseErrs)++
			break
		}
		v := val[i+4 : i+nlaLen]
		switch nlaType {
		case ctaCountersPackets:
			if len(v) >= 8 {
				*packets = binary.BigEndian.Uint64(v[:8])
			}
		case ctaCountersBytes:
			if len(v) >= 8 {
				*bytes = binary.BigEndian.Uint64(v[:8])
			}
		}
		i += nlAlign(nlaLen)
	}
}

func parseCountersReply(val []byte, ne binary.ByteOrder, packets *uint64, parseErrs *uint64) {
	for i := 0; i+4 <= len(val); {
		nlaLen := int(ne.Uint16(val[i : i+2]))
		nlaType := ne.Uint16(val[i+2:i+4]) & nlaTypeMask
		if nlaLen < 4 || i+nlaLen > len(val) {
			(*parseErrs)++
			break
		}
		v := val[i+4 : i+nlaLen]
		if nlaType == ctaCountersPackets {
			if len(v) >= 8 {
				*packets = binary.BigEndian.Uint64(v[:8])
			}
		}
		i += nlAlign(nlaLen)
	}
}
