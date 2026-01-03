package main

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

func (mc *MetricsCollector) getHostMemInfo() (freeMB, availMB float64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	found := 0
	for scanner.Scan() && found < 2 {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemFree:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				v, _ := strconv.ParseFloat(parts[1], 64)
				freeMB = v / 1024.0
				found++
			}
		} else if strings.HasPrefix(line, "MemAvailable:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				v, _ := strconv.ParseFloat(parts[1], 64)
				availMB = v / 1024.0
				found++
			}
		}
	}
	return
}
func (mc *MetricsCollector) getHostCPUPercent() float64 {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		return 0
	}
	line := scanner.Text()
	parts := strings.Fields(line)
	if len(parts) < 8 {
		return 0
	}

	user, _ := strconv.ParseFloat(parts[1], 64)
	nice, _ := strconv.ParseFloat(parts[2], 64)
	system, _ := strconv.ParseFloat(parts[3], 64)
	idle, _ := strconv.ParseFloat(parts[4], 64)
	iowait, _ := strconv.ParseFloat(parts[5], 64)
	irq, _ := strconv.ParseFloat(parts[6], 64)
	softirq, _ := strconv.ParseFloat(parts[7], 64)
	steal := 0.0
	if len(parts) > 8 {
		steal, _ = strconv.ParseFloat(parts[8], 64)
	}

	currentIdle := idle + iowait
	currentTotal := user + nice + system + idle + iowait + irq + softirq + steal

	mc.hostCpuState.mu.Lock()
	defer mc.hostCpuState.mu.Unlock()

	usagePercent := 0.0

	if mc.hostCpuState.initialized {
		deltaTotal := currentTotal - mc.hostCpuState.prevTotal
		deltaIdle := currentIdle - mc.hostCpuState.prevIdle

		if deltaTotal > 0 {
			usagePercent = ((deltaTotal - deltaIdle) / deltaTotal) * 100.0
		}
	} else {
		mc.hostCpuState.initialized = true
	}

	mc.hostCpuState.prevTotal = currentTotal
	mc.hostCpuState.prevIdle = currentIdle

	return clamp01(usagePercent/100.0) * 100.0
}
