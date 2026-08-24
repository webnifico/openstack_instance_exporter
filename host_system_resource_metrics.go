package main

import (
	"bufio"
	"io"
	"os"
	"strconv"
	"strings"
)

func (mc *MetricsCollector) getHostMemInfo() (freeMB, availMB float64) {
	freeMB, availMB, _, _ = mc.getHostMemInfoWithAvailability()
	return freeMB, availMB
}

func (mc *MetricsCollector) getHostMemInfoWithAvailability() (freeMB, availMB float64, freeAvailable, availAvailable bool) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, false, false
	}
	defer f.Close()
	return parseHostMemInfo(f)
}

func parseHostMemInfo(r io.Reader) (freeMB, availMB float64, freeAvailable, availAvailable bool) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() && (!freeAvailable || !availAvailable) {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemFree:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				if v, err := strconv.ParseFloat(parts[1], 64); err == nil && v >= 0 {
					freeMB = v / 1024.0
					freeAvailable = true
				}
			}
		} else if strings.HasPrefix(line, "MemAvailable:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				if v, err := strconv.ParseFloat(parts[1], 64); err == nil && v >= 0 {
					availMB = v / 1024.0
					availAvailable = true
				}
			}
		}
	}
	return
}
func (mc *MetricsCollector) getHostCPUPercent() float64 {
	value, _ := mc.getHostCPUPercentWithAvailability()
	return value
}

func (mc *MetricsCollector) getHostCPUPercentWithAvailability() (float64, bool) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		return 0, false
	}
	line := scanner.Text()
	parts := strings.Fields(line)
	if len(parts) < 8 || parts[0] != "cpu" {
		return 0, false
	}

	values := make([]float64, 8)
	for i := 1; i < len(parts) && i <= len(values); i++ {
		value, err := strconv.ParseFloat(parts[i], 64)
		if err != nil || value < 0 {
			return 0, false
		}
		values[i-1] = value
	}
	user, nice, system := values[0], values[1], values[2]
	idle, iowait, irq, softirq := values[3], values[4], values[5], values[6]
	steal := 0.0
	if len(parts) > 8 {
		steal = values[7]
	}

	currentIdle := idle + iowait
	currentTotal := user + nice + system + idle + iowait + irq + softirq + steal
	return mc.hostCPUPercentFromTotals(currentTotal, currentIdle)
}

func (mc *MetricsCollector) hostCPUPercentFromTotals(currentTotal, currentIdle float64) (float64, bool) {
	mc.hostCpuState.mu.Lock()
	defer mc.hostCpuState.mu.Unlock()

	if !mc.hostCpuState.initialized {
		mc.hostCpuState.initialized = true
		mc.hostCpuState.prevTotal = currentTotal
		mc.hostCpuState.prevIdle = currentIdle
		return 0, false
	}

	deltaTotal := currentTotal - mc.hostCpuState.prevTotal
	deltaIdle := currentIdle - mc.hostCpuState.prevIdle
	mc.hostCpuState.prevTotal = currentTotal
	mc.hostCpuState.prevIdle = currentIdle
	if deltaTotal <= 0 || deltaIdle < 0 || deltaIdle > deltaTotal {
		return 0, false
	}

	usagePercent := ((deltaTotal - deltaIdle) / deltaTotal) * 100.0
	return clamp01(usagePercent/100.0) * 100.0, true
}
