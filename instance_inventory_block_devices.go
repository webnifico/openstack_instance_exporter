package main

import (
	"path"
	"regexp"
	"strings"
)

// DomainDisk retains only stable XML identity, not guest filesystem contents.
type DomainDisk struct {
	Device         string
	Type           string
	SourceProtocol string
	SourceName     string
	SourceFile     string
	SourceDev      string
	SourcePool     string
	SourceVolume   string
	TargetDev      string
}

func parseDiskType(sourceName string) (string, string) {
	parts := strings.SplitN(sourceName, "/", 2)
	if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
		return parts[0], parts[1]
	}
	return "unknown", "unknown"
}

func diskMetricSource(d DomainDisk) (string, string) {
	switch {
	case d.SourceFile != "":
		return "local", d.SourceFile
	case d.SourceName != "":
		// RBD names are pool/image. Other protocols do not have RBD pool
		// semantics. The empty-protocol fallback preserves in-memory callers.
		if d.SourceProtocol == "rbd" || d.SourceProtocol == "" {
			return parseDiskType(d.SourceName)
		}
		return d.SourceProtocol, d.SourceName
	case d.SourceDev != "":
		return "block", d.SourceDev
	case d.SourceVolume != "":
		return "volume", strings.Trim(d.SourcePool+"/"+d.SourceVolume, "/")
	default:
		return "unknown", "unknown"
	}
}

func blockDeviceType(d DomainDisk) string {
	if d.Device == "" {
		return "disk"
	}
	return d.Device
}

// Recognize Nova's exact local basename or UUID-prefixed RBD image name.
// This is a configuration convention, never proof of a guest mount/swapon.
var novaSpecialBlockImage = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}_disk\.(config|swap)$`)

func blockDeviceRole(d DomainDisk) string {
	var source string
	switch {
	case d.SourceFile != "":
		source = path.Base(d.SourceFile)
	case d.SourceProtocol == "rbd" && d.SourceName != "":
		source = path.Base(d.SourceName)
	}
	novaSource := source == "disk.config" || source == "disk.swap" || novaSpecialBlockImage.MatchString(source)
	device := blockDeviceType(d)
	if novaSource && strings.HasSuffix(source, "disk.config") && (device == "disk" || device == "cdrom") {
		return "config_drive"
	}
	if device == "disk" || device == "lun" {
		if novaSource && strings.HasSuffix(source, "disk.swap") {
			return "swap"
		}
		return "storage"
	}
	return "other"
}

func isResourceDisk(d DomainDisk) bool {
	device := blockDeviceType(d)
	return (device == "disk" || device == "lun") && blockDeviceRole(d) != "config_drive"
}

func isInventoryOnlyBlockDevice(d DomainDisk) bool {
	device := blockDeviceType(d)
	return device == "cdrom" || device == "floppy" || blockDeviceRole(d) == "config_drive"
}

// Only known inventory-only devices may be absent from block statistics or
// excluded from completeness. Unknown/duplicate/unnamed targets and genuinely
// missing resource disks remain non-authoritative. block.count describes all
// returned block devices, not just performance-eligible disks.
func resourceDiskTargetsComplete(configured []DomainDisk, runtimeTargets []string, blockCount uint64, countPresent bool) bool {
	if countPresent && blockCount != uint64(len(runtimeTargets)) {
		return false
	}
	byTarget := make(map[string]DomainDisk, len(configured))
	for _, d := range configured {
		if d.TargetDev == "" {
			return false
		}
		if _, duplicate := byTarget[d.TargetDev]; duplicate {
			return false
		}
		if !isResourceDisk(d) && !isInventoryOnlyBlockDevice(d) {
			return false
		}
		byTarget[d.TargetDev] = d
	}
	seen := make(map[string]struct{}, len(runtimeTargets))
	for _, target := range runtimeTargets {
		if _, known := byTarget[target]; !known || target == "" {
			return false
		}
		if _, duplicate := seen[target]; duplicate {
			return false
		}
		seen[target] = struct{}{}
	}
	for target, d := range byTarget {
		if isResourceDisk(d) {
			if _, present := seen[target]; !present {
				return false
			}
		}
	}
	return true
}
