package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/digitalocean/go-libvirt"
)

func (im *InstanceManager) getDomainMeta(dom libvirt.Domain, conn *libvirt.Libvirt) (*DomainStatic, error) {
	uuidBytes := dom.UUID
	instanceUUID := uuidBytesToString(uuidBytes[:])
	if instanceUUID == "" {
		return nil, fmt.Errorf("invalid domain UUID length: %d", len(uuidBytes))
	}

	im.domainMetaMu.RLock()
	meta, ok := im.domainMeta[instanceUUID]
	im.domainMetaMu.RUnlock()

	if ok && meta != nil && time.Since(meta.LastUpdated) < 5*time.Minute {
		return meta, nil
	}

	im.xmlInflightMu.Lock()
	if c, ok := im.xmlInflight[instanceUUID]; ok && c != nil {
		im.xmlInflightMu.Unlock()
		c.wg.Wait()
		if c.err != nil {
			return c.meta, c.err
		}
		if c.meta != nil {
			return c.meta, nil
		}
		im.domainMetaMu.RLock()
		meta3, ok3 := im.domainMeta[instanceUUID]
		im.domainMetaMu.RUnlock()
		if ok3 && meta3 != nil {
			return meta3, nil
		}
		return nil, fmt.Errorf("domain meta singleflight returned no result for %s", instanceUUID)
	}

	c := &domainXMLInflight{}
	c.wg.Add(1)
	if im.xmlInflight == nil {
		im.xmlInflight = make(map[string]*domainXMLInflight, 256)
	}
	im.xmlInflight[instanceUUID] = c
	im.xmlInflightMu.Unlock()

	defer func() {
		im.xmlInflightMu.Lock()
		delete(im.xmlInflight, instanceUUID)
		im.xmlInflightMu.Unlock()
		c.wg.Done()
	}()

	im.domainMetaMu.RLock()
	meta2, ok2 := im.domainMeta[instanceUUID]
	im.domainMetaMu.RUnlock()
	if ok2 && meta2 != nil && time.Since(meta2.LastUpdated) < 5*time.Minute {
		c.meta = meta2
		return meta2, nil
	}

	var xmlDesc string
	var err error
	if im.xmlRPCSem != nil {
		im.xmlRPCSem <- struct{}{}
		xmlDesc, err = conn.DomainGetXMLDesc(dom, 0)
		<-im.xmlRPCSem
	} else {
		xmlDesc, err = conn.DomainGetXMLDesc(dom, 0)
	}
	if err != nil {
		c.err = fmt.Errorf("failed to get domain XML description: %v", err)
		return nil, c.err
	}

	meta, err = parseDomainStaticFromXML(instanceUUID, dom.Name, xmlDesc)
	if err != nil {
		c.err = err
		return nil, c.err
	}

	im.domainMetaMu.Lock()
	im.domainMeta[instanceUUID] = meta
	im.domainMetaMu.Unlock()

	im.updateVMIPIndex(instanceUUID, meta.FixedIPs)

	c.meta = meta
	return meta, nil
}
func (im *InstanceManager) setActiveInstances(activeSet map[string]struct{}) {
	im.activeInstancesMu.Lock()
	im.activeInstances = activeSet
	im.activeInstancesMu.Unlock()
}
func (im *InstanceManager) snapshotActiveInstances() map[string]struct{} {
	im.activeInstancesMu.RLock()
	defer im.activeInstancesMu.RUnlock()
	out := make(map[string]struct{}, len(im.activeInstances))
	for k := range im.activeInstances {
		out[k] = struct{}{}
	}
	return out
}
func (im *InstanceManager) getVMIPIndexSnapshot() (map[IPKey]struct{}, map[IPKey]string) {
	im.vmIPIndexMu.RLock()

	setCopy := make(map[IPKey]struct{}, len(im.vmIPSet))
	for k := range im.vmIPSet {
		setCopy[k] = struct{}{}
	}

	mapCopy := make(map[IPKey]string, len(im.vmIPToInstance))
	for k, v := range im.vmIPToInstance {
		mapCopy[k] = v
	}

	im.vmIPIndexMu.RUnlock()
	return setCopy, mapCopy
}
func (im *InstanceManager) updateVMIPIndex(instanceUUID string, fixedIPs []IP) {
	if instanceUUID == "" {
		return
	}
	keys := make([]IPKey, 0, len(fixedIPs))
	for _, ip := range fixedIPs {
		if ip.Address == "" {
			continue
		}
		k := IPStrToKey(ip.Address)
		if k == (IPKey{}) {
			continue
		}
		keys = append(keys, k)
	}

	im.vmIPIndexMu.Lock()
	old := im.vmIPKeysByInstance[instanceUUID]
	for _, k := range old {
		delete(im.vmIPSet, k)
		delete(im.vmIPToInstance, k)
	}
	for _, k := range keys {
		im.vmIPSet[k] = struct{}{}
		im.vmIPToInstance[k] = instanceUUID
	}
	im.vmIPKeysByInstance[instanceUUID] = keys
	im.vmIPIndexMu.Unlock()
}
func (im *InstanceManager) removeVMIPIndex(instanceUUID string) {
	if instanceUUID == "" {
		return
	}
	im.vmIPIndexMu.Lock()
	old := im.vmIPKeysByInstance[instanceUUID]
	for _, k := range old {
		delete(im.vmIPSet, k)
		delete(im.vmIPToInstance, k)
	}
	delete(im.vmIPKeysByInstance, instanceUUID)
	im.vmIPIndexMu.Unlock()
}
func (im *InstanceManager) isInstanceActive(instanceUUID string) bool {
	im.activeInstancesMu.RLock()
	defer im.activeInstancesMu.RUnlock()
	_, ok := im.activeInstances[instanceUUID]
	return ok
}
func (im *InstanceManager) cleanupDomainMeta() {
	im.domainMetaMu.Lock()
	for uuid := range im.domainMeta {
		if !im.isInstanceActive(uuid) {
			delete(im.domainMeta, uuid)
			im.removeVMIPIndex(uuid)
		}
	}
	im.domainMetaMu.Unlock()
}
func (im *InstanceManager) cleanupResourceSamples() {
	for i := 0; i < shardCount; i++ {
		im.cpuMu[i].Lock()
		for uuid := range im.cpuSamples[i] {
			if !im.isInstanceActive(uuid) {
				delete(im.cpuSamples[i], uuid)
			}
		}
		im.cpuMu[i].Unlock()

		im.diskMu[i].Lock()
		for key := range im.diskSamples[i] {
			parts := strings.SplitN(key, "|", 2)
			if len(parts) > 0 && !im.isInstanceActive(parts[0]) {
				delete(im.diskSamples[i], key)
			}
		}
		im.diskMu[i].Unlock()

		im.memMu[i].Lock()
		for uuid := range im.memSamples[i] {
			if !im.isInstanceActive(uuid) {
				delete(im.memSamples[i], uuid)
			}
		}
		im.memMu[i].Unlock()

		im.netMu[i].Lock()
		for uuid := range im.netSamples[i] {
			if !im.isInstanceActive(uuid) {
				delete(im.netSamples[i], uuid)
			}
		}
		im.netMu[i].Unlock()
	}
}
func (im *InstanceManager) snapshotVMIPIdentities(activeSet map[string]struct{}) []VMIPIdentity {
	out := make([]VMIPIdentity, 0, 256)
	seen := make(map[VMIPIdentity]struct{}, 256)
	im.domainMetaMu.RLock()
	defer im.domainMetaMu.RUnlock()
	for uuid := range activeSet {
		meta := im.domainMeta[uuid]
		if meta == nil {
			continue
		}
		for _, ip := range meta.FixedIPs {
			k := IPStrToKey(ip.Address)
			if k == (IPKey{}) {
				continue
			}
			id := VMIPIdentity{InstanceUUID: uuid, IP: k}
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			out = append(out, id)
		}
	}
	return out
}
