package main

import (
	"os"
	"strconv"
	"strings"
	"syscall"
)

func hostTotalMemBytes() uint64 {
	var si syscall.Sysinfo_t
	if err := syscall.Sysinfo(&si); err != nil {
		return 0
	}
	return si.Totalram * uint64(si.Unit)
}

func hostConntrackMax() uint64 {
	data, err := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_max")
	if err != nil {
		return 0
	}
	s := strings.TrimSpace(string(data))
	if s == "" {
		return 0
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0
	}
	return v
}
