package main

import (
	"encoding/xml"
	"fmt"
	"strings"
	"time"
)

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

	for _, p := range domainXML.Metadata.NovaInstance.NovaPorts.Ports {
		uuid := strings.TrimSpace(p.PortUUID)
		if uuid == "" {
			continue
		}
		meta.PortUUIDs = append(meta.PortUUIDs, uuid)
		if meta.PortIPsByUUID == nil {
			meta.PortIPsByUUID = make(map[string][]IP, 4)
		}
		for _, ip := range p.IPs {
			addr := strings.TrimSpace(ip.Address)
			if addr == "" {
				continue
			}

			v := strings.TrimSpace(ip.IPVersion)
			if v == "" {
				v = "4"
			}

			meta.PortIPsByUUID[uuid] = append(meta.PortIPsByUUID[uuid], IP{
				Address: addr,
				Family:  v,
			})
			meta.FixedIPs = append(meta.FixedIPs, IP{
				Address: addr,
				Family:  v,
			})
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

	for _, iface := range domainXML.Devices.Interfaces {
		ifaceName := strings.TrimSpace(iface.Target.Dev)
		if ifaceName == "" {
			continue
		}
		meta.Interfaces = append(meta.Interfaces, ifaceName)
	}

	return meta, nil
}
