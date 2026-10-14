package main

import (
	"fmt"

	libvirt "github.com/digitalocean/go-libvirt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func (mc *MetricsCollector) snapshotQEMUProcessIncarnations() (map[string]string, error) {
	if mc.qemuProcessSnapshotOverride != nil {
		return mc.qemuProcessSnapshotOverride()
	}
	return scanQEMUProcessIncarnations(defaultProcRoot, defaultBootIDPath)
}

const (
	defaultProcRoot   = "/proc"
	defaultBootIDPath = "/proc/sys/kernel/random/boot_id"
)

func qemuUUIDFromArgv(argv []string) (string, bool) {
	if len(argv) == 0 || !strings.Contains(strings.ToLower(filepath.Base(argv[0])), "qemu") {
		return "", false
	}
	for index := 1; index < len(argv); index++ {
		value := ""
		switch {
		case argv[index] == "-uuid" && index+1 < len(argv):
			value = argv[index+1]
		case strings.HasPrefix(argv[index], "-uuid="):
			value = strings.TrimPrefix(argv[index], "-uuid=")
		}
		value = strings.ToLower(strings.TrimSpace(value))
		if looksLikeUUID36(value) {
			return value, true
		}
	}
	return "", false
}

func procStatStartTime(stat string) (uint64, bool) {
	// The comm field is parenthesized and may itself contain spaces or closing
	// parentheses. Everything after its final ')' begins with field 3 (state);
	// starttime is field 22, hence index 19 in the remaining fields.
	closing := strings.LastIndexByte(stat, ')')
	if closing < 0 || closing+1 >= len(stat) {
		return 0, false
	}
	fields := strings.Fields(stat[closing+1:])
	if len(fields) <= 19 {
		return 0, false
	}
	startTime, err := strconv.ParseUint(fields[19], 10, 64)
	return startTime, err == nil
}

func readProcProcessToken(procRoot, bootID string, pid int, expectedUUID string) (string, bool) {
	if pid <= 0 || bootID == "" || !looksLikeUUID36(expectedUUID) {
		return "", false
	}
	processDir := filepath.Join(procRoot, strconv.Itoa(pid))
	statBefore, err := os.ReadFile(filepath.Join(processDir, "stat"))
	if err != nil {
		return "", false
	}
	startBefore, ok := procStatStartTime(string(statBefore))
	if !ok {
		return "", false
	}
	cmdline, err := os.ReadFile(filepath.Join(processDir, "cmdline"))
	if err != nil {
		return "", false
	}
	rawArgs := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
	actualUUID, ok := qemuUUIDFromArgv(rawArgs)
	if !ok || actualUUID != strings.ToLower(expectedUUID) {
		return "", false
	}
	statAfter, err := os.ReadFile(filepath.Join(processDir, "stat"))
	if err != nil {
		return "", false
	}
	startAfter, ok := procStatStartTime(string(statAfter))
	if !ok || startAfter != startBefore {
		return "", false
	}
	return bootID + ":" + strconv.Itoa(pid) + ":" + strconv.FormatUint(startBefore, 10), true
}

func scanQEMUProcessIncarnations(procRoot, bootIDPath string) (map[string]string, error) {
	bootIDBytes, err := os.ReadFile(bootIDPath)
	if err != nil {
		return nil, fmt.Errorf("read host boot ID: %w", err)
	}
	bootID := strings.TrimSpace(string(bootIDBytes))
	if bootID == "" {
		return nil, fmt.Errorf("host boot ID is empty")
	}
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, fmt.Errorf("scan process table: %w", err)
	}
	result := make(map[string]string)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		cmdline, err := os.ReadFile(filepath.Join(procRoot, entry.Name(), "cmdline"))
		if err != nil {
			// Processes can exit while /proc is being traversed. Such entries are
			// simply absent from this instantaneous snapshot.
			continue
		}
		argv := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
		instanceUUID, ok := qemuUUIDFromArgv(argv)
		if !ok {
			continue
		}
		token, ok := readProcProcessToken(procRoot, bootID, pid, instanceUUID)
		if !ok {
			continue
		}
		if previous, duplicate := result[instanceUUID]; duplicate && previous != token {
			return nil, fmt.Errorf("multiple QEMU processes claim domain UUID %s", instanceUUID)
		}
		result[instanceUUID] = token
	}
	return result, nil
}

func stableQEMUProcessTokens(records []libvirt.DomainStatsRecord, before, after map[string]string) (map[string]string, error) {
	tokens := make(map[string]string, len(records))
	for _, record := range records {
		instanceUUID := validLibvirtDomainUUID(record.Dom.UUID)
		if instanceUUID == "" {
			return nil, fmt.Errorf("cannot resolve process incarnation for an invalid domain UUID")
		}
		beforeToken, beforeOK := before[instanceUUID]
		afterToken, afterOK := after[instanceUUID]
		if record.Dom.ID < 0 {
			if beforeOK || afterOK {
				return nil, fmt.Errorf("inactive domain UUID %s changed runtime during collection", instanceUUID)
			}
			continue
		}
		if !beforeOK || !afterOK || beforeToken == "" || afterToken == "" {
			return nil, fmt.Errorf("QEMU process incarnation unavailable for domain UUID %s", instanceUUID)
		}
		if beforeToken != afterToken {
			return nil, fmt.Errorf("QEMU process incarnation changed during collection for domain UUID %s", instanceUUID)
		}
		tokens[instanceUUID] = beforeToken
	}
	return tokens, nil
}
