package main

import (
	"encoding/xml"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

func deduplicateIPs(ips []IP) []IP {
	out := make([]IP, 0, len(ips))
	seen := make(map[string]struct{}, len(ips))
	for _, item := range ips {
		parsed, err := netip.ParseAddr(strings.TrimSpace(item.Address))
		if err != nil {
			continue
		}
		parsed = parsed.Unmap()
		address := parsed.String()
		if _, ok := seen[address]; ok {
			continue
		}
		seen[address] = struct{}{}
		family := "6"
		if parsed.Is4() {
			family = "4"
		}
		out = append(out, IP{Address: address, Family: family, Prefix: item.Prefix})
	}
	return out
}

func parseDomainStaticFromXML(instanceUUID string, domName string, xmlDesc string) (*DomainStatic, error) {
	var domainXML DomainXML
	if err := xml.Unmarshal([]byte(xmlDesc), &domainXML); err != nil {
		return nil, fmt.Errorf("failed to parse domain XML: %v", err)
	}

	meta := &DomainStatic{
		Name:            strings.TrimSpace(domainXML.Metadata.NovaInstance.NovaName),
		InstanceUUID:    instanceUUID,
		UserUUID:        domainXML.Metadata.NovaInstance.NovaOwner.NovaUser.UserUUID,
		UserName:        strings.TrimSpace(domainXML.Metadata.NovaInstance.NovaOwner.NovaUser.UserName),
		ProjectUUID:     domainXML.Metadata.NovaInstance.NovaOwner.NovaProject.ProjectUUID,
		ProjectName:     strings.TrimSpace(domainXML.Metadata.NovaInstance.NovaOwner.NovaProject.ProjectName),
		FlavorName:      strings.TrimSpace(domainXML.Metadata.NovaInstance.NovaFlavor.FlavorName),
		VCPUCount:       domainXML.Metadata.NovaInstance.NovaFlavor.VCPUs,
		MemMB:           domainXML.Metadata.NovaInstance.NovaFlavor.MemoryMB,
		RootType:        strings.TrimSpace(domainXML.Metadata.NovaInstance.NovaRoot.RootType),
		CreatedAt:       strings.TrimSpace(domainXML.Metadata.NovaInstance.CreationTime),
		MetadataVersion: strings.TrimSpace(domainXML.Metadata.NovaInstance.NovaPackage.Version),
		LastUpdated:     time.Now(),
	}

	if meta.Name == "" {
		meta.Name = domName
	}

	seenPorts := make(map[string]struct{})
	seenFixedIPs := make(map[string]struct{})
	seenPortIPs := make(map[string]map[string]struct{})
	for _, p := range domainXML.Metadata.NovaInstance.NovaPorts.Ports {
		uuid := strings.TrimSpace(p.PortUUID)
		if uuid == "" {
			continue
		}
		if _, ok := seenPorts[uuid]; !ok {
			seenPorts[uuid] = struct{}{}
			meta.PortUUIDs = append(meta.PortUUIDs, uuid)
		}
		if meta.PortIPsByUUID == nil {
			meta.PortIPsByUUID = make(map[string][]IP, 4)
		}
		portSeen := seenPortIPs[uuid]
		if portSeen == nil {
			portSeen = make(map[string]struct{})
			seenPortIPs[uuid] = portSeen
		}
		for _, ip := range p.IPs {
			parsed, err := netip.ParseAddr(strings.TrimSpace(ip.Address))
			if err != nil {
				continue
			}
			parsed = parsed.Unmap()
			addr := parsed.String()
			family := "6"
			if parsed.Is4() {
				family = "4"
			}
			if _, ok := portSeen[addr]; !ok {
				portSeen[addr] = struct{}{}
				meta.PortIPsByUUID[uuid] = append(meta.PortIPsByUUID[uuid], IP{Address: addr, Family: family})
			}
			if _, ok := seenFixedIPs[addr]; !ok {
				seenFixedIPs[addr] = struct{}{}
				meta.FixedIPs = append(meta.FixedIPs, IP{Address: addr, Family: family})
			}
		}
	}

	for _, disk := range domainXML.Devices.Disks {
		if disk.Device != "disk" {
			continue
		}
		d := DomainDisk{
			Device: disk.Device,
			Type:   disk.Type,
		}
		d.TargetDev = strings.TrimSpace(disk.Target.Dev)
		d.SourceFile = strings.TrimSpace(disk.Source.File)
		d.SourceName = strings.TrimSpace(disk.Source.Name)
		meta.Disks = append(meta.Disks, d)
	}

	seenInterfaces := make(map[string]struct{})
	for _, iface := range domainXML.Devices.Interfaces {
		ifaceName := strings.TrimSpace(iface.Target.Dev)
		if ifaceName == "" {
			continue
		}
		if _, ok := seenInterfaces[ifaceName]; ok {
			continue
		}
		seenInterfaces[ifaceName] = struct{}{}
		meta.Interfaces = append(meta.Interfaces, ifaceName)
	}

	return meta, nil
}
