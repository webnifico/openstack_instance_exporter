package main

import (
	"strconv"
	"strings"

	libvirt "github.com/digitalocean/go-libvirt"
	"github.com/prometheus/client_golang/prometheus"
)

type XMLConfiguredMemory struct {
	Value float64 `xml:",chardata"`
	Unit  string  `xml:"unit,attr"`
}

func (m XMLConfiguredMemory) mebibytes() float64 {
	factors := map[string]float64{"": 1.0 / 1024, "kib": 1.0 / 1024, "b": 1.0 / 1048576, "bytes": 1.0 / 1048576, "kb": 1000.0 / 1048576, "k": 1000.0 / 1048576, "mib": 1, "mb": 1000000.0 / 1048576, "m": 1000000.0 / 1048576, "gib": 1024, "gb": 1000000000.0 / 1048576, "g": 1000000000.0 / 1048576, "tib": 1048576, "tb": 1000000000000.0 / 1048576, "t": 1000000000000.0 / 1048576}
	return m.Value * factors[strings.ToLower(m.Unit)]
}

func activeDomainRecords(records []libvirt.DomainStatsRecord) []libvirt.DomainStatsRecord {
	active := make([]libvirt.DomainStatsRecord, 0, len(records))
	for _, record := range records {
		if record.Dom.ID >= 0 {
			active = append(active, record)
		}
	}
	return active
}

func inventoryStateDescription(stat *ParsedStats) string {
	if !stat.StatePresent {
		return "unavailable"
	}
	states := [...]string{"nostate", "running", "blocked", "paused", "shutdown", "shutoff", "crashed", "pmsuspended"}
	if stat.State < 0 || stat.State >= len(states) {
		return "unrecognized(" + strconv.Itoa(stat.State) + ")"
	}
	return states[stat.State]
}

func inventoryDimension(value float64) string {
	if value <= 0 {
		return ""
	}
	return strconv.FormatFloat(value, 'f', -1, 64)
}

func (mc *MetricsCollector) inventoryMetricBatch(records []libvirt.DomainStatsRecord, metadata map[string]*DomainStatic) []prometheus.Metric {
	metrics := make([]prometheus.Metric, 0, len(records)*4)
	for _, record := range records {
		meta := metadata[validLibvirtDomainUUID(record.Dom.UUID)]
		if meta == nil {
			continue
		}
		labels := []string{strings.TrimSpace(record.Dom.Name), meta.Name, meta.InstanceUUID, meta.ProjectUUID, meta.ProjectName, meta.UserUUID}
		active := "0"
		if record.Dom.ID >= 0 {
			active = "1"
		}
		info := append(append([]string{}, labels...), meta.UserName, meta.FlavorName, inventoryDimension(float64(meta.ConfiguredVCPUs)), inventoryDimension(meta.ConfiguredMemMB), meta.RootType, meta.CreatedAt, meta.MetadataVersion, active, inventoryStateDescription(parseLibvirtStats(record.Params)))
		metrics = append(metrics, prometheus.MustNewConstMetric(mc.im.instanceInventoryInfoDesc, prometheus.GaugeValue, 1, info...))
		seenDisks := make(map[string]bool)
		for _, disk := range meta.Disks {
			if disk.TargetDev == "" || seenDisks[disk.TargetDev] {
				continue
			}
			seenDisks[disk.TargetDev] = true
			diskType, volume := "unknown", "unknown"
			switch {
			case disk.SourceFile != "":
				diskType, volume = "local", disk.SourceFile
			case disk.SourceName != "":
				diskType, volume = parseDiskType(disk.SourceName)
			case disk.SourceDev != "":
				diskType, volume = "block", disk.SourceDev
			case disk.SourceVolume != "":
				diskType, volume = "volume", strings.Trim(disk.SourcePool+"/"+disk.SourceVolume, "/")
			}
			values := append(append([]string{}, labels...), volume, diskType, disk.TargetDev)
			metrics = append(metrics, prometheus.MustNewConstMetric(mc.im.instanceInventoryDiskInfoDesc, prometheus.GaugeValue, 1, values...))
		}
		for index, iface := range meta.ConfiguredInterfaces {
			attachment := iface.Source.Bridge
			if attachment == "" {
				attachment = iface.Source.Network
			}
			if attachment == "" {
				attachment = iface.Source.Dev
			}
			values := append(append([]string{}, labels...), strconv.Itoa(index), iface.Target.Dev, iface.MAC.Address, iface.Model.Type, iface.Type, attachment, iface.VirtualPort.Parameters.InterfaceID)
			metrics = append(metrics, prometheus.MustNewConstMetric(mc.im.instanceInventoryInterfaceInfoDesc, prometheus.GaugeValue, 1, values...))
		}
		seenAddresses := make(map[string]bool)
		for _, port := range meta.PortUUIDs {
			for _, ip := range deduplicateIPs(meta.PortIPsByUUID[port]) {
				key := port + "|" + ip.Address
				if seenAddresses[key] {
					continue
				}
				seenAddresses[key] = true
				values := append(append([]string{}, labels...), port, ip.Address, ip.Family)
				metrics = append(metrics, prometheus.MustNewConstMetric(mc.im.instanceInventoryAddressInfoDesc, prometheus.GaugeValue, 1, values...))
			}
		}
	}
	return metrics
}
