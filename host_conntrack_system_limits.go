package main

import (
	"os"
	"strconv"
	"strings"
	"syscall"
)

func hostTotalMemBytes() uint64 {
	value, _ := hostTotalMemBytesWithAvailability()
	return value
}

func hostTotalMemBytesWithAvailability() (uint64, bool) {
	var si syscall.Sysinfo_t
	if err := syscall.Sysinfo(&si); err != nil {
		return 0, false
	}
	if si.Totalram == 0 || si.Unit == 0 {
		return 0, false
	}
	return si.Totalram * uint64(si.Unit), true
}

func hostConntrackMax() uint64 {
	value, _ := hostConntrackMaxWithAvailability()
	return value
}

func hostConntrackMaxWithAvailability() (uint64, bool) {
	data, err := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_max")
	if err != nil {
		return 0, false
	}
	s := strings.TrimSpace(string(data))
	if s == "" {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil || v == 0 {
		return 0, false
	}
	return v, true
}
