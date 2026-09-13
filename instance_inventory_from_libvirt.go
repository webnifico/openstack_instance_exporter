package main

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/digitalocean/go-libvirt"
)

var errDomainXMLRPCAlreadyInFlight = errors.New("Libvirt domain XML RPC already in flight")

type libvirtRPCTimeoutError struct {
	Operation  string
	Wait       time.Duration
	RPCStarted bool
	Detail     string
}

func (err *libvirtRPCTimeoutError) Error() string {
	if err == nil {
		return "Libvirt RPC timed out"
	}
	if err.Detail != "" {
		return fmt.Sprintf("%s %s", err.Operation, err.Detail)
	}
	return fmt.Sprintf("%s timed out after %s", err.Operation, err.Wait)
}

func (im *InstanceManager) getDomainMeta(dom libvirt.Domain, conn *libvirt.Libvirt) (*DomainStatic, error) {
	meta, _, err := im.getDomainMetaForCollection(dom, conn)
	if meta != nil {
		// Callers that only need the best available static identity retain the
		// historical last-good fallback. Complete-cycle collection uses the
		// freshness-aware method below and treats the same fallback as degraded.
		return meta, nil
	}
	return nil, err
}

func (im *InstanceManager) getDomainMetaForCollection(dom libvirt.Domain, conn *libvirt.Libvirt) (*DomainStatic, bool, error) {
	return im.getDomainMetaForCollectionMode(dom, conn, true, time.Time{})
}

func (im *InstanceManager) getDomainMetaCandidateForCollection(dom libvirt.Domain, conn *libvirt.Libvirt) (*DomainStatic, bool, error) {
	return im.getDomainMetaCandidateForCollectionBefore(dom, conn, time.Time{})
}

func (im *InstanceManager) getDomainMetaCandidateForCollectionBefore(dom libvirt.Domain, conn *libvirt.Libvirt, deadline time.Time) (*DomainStatic, bool, error) {
	return im.getDomainMetaForCollectionMode(dom, conn, false, deadline)
}

func (im *InstanceManager) getDomainMetaForCollectionMode(dom libvirt.Domain, conn *libvirt.Libvirt, commit bool, deadline time.Time) (*DomainStatic, bool, error) {
	instanceUUID := validLibvirtDomainUUID(dom.UUID)
	if instanceUUID == "" {
		return nil, false, fmt.Errorf("invalid all-zero domain UUID")
	}

	im.domainMetaMu.RLock()
	meta, ok := im.domainMeta[instanceUUID]
	if dom.ID < 0 {
		meta, ok = im.inactiveDomainMeta[instanceUUID]
	}
	im.domainMetaMu.RUnlock()

	if ok && meta != nil && time.Since(meta.LastUpdated) < 5*time.Minute {
		return meta, true, nil
	}
	if conn == nil && im.domainXMLDescOverride == nil {
		if meta != nil {
			return meta, false, fmt.Errorf("domain metadata refresh unavailable for %s: libvirt connection is nil", instanceUUID)
		}
		return nil, false, fmt.Errorf("domain metadata unavailable for %s: libvirt connection is nil", instanceUUID)
	}

	inflightKey := instanceUUID
	if !commit {
		inflightKey += "|staged"
	}
	im.xmlInflightMu.Lock()
	if c, ok := im.xmlInflight[inflightKey]; ok && c != nil {
		im.xmlInflightMu.Unlock()
		c.wg.Wait()
		if c.err != nil {
			return c.meta, false, c.err
		}
		if c.meta != nil {
			return c.meta, true, nil
		}
		im.domainMetaMu.RLock()
		meta3, ok3 := im.domainMeta[instanceUUID]
		if dom.ID < 0 {
			meta3, ok3 = im.inactiveDomainMeta[instanceUUID]
		}
		im.domainMetaMu.RUnlock()
		if ok3 && meta3 != nil {
			return meta3, true, nil
		}
		return nil, false, fmt.Errorf("domain meta singleflight returned no result for %s", instanceUUID)
	}

	c := &domainXMLInflight{}
	c.wg.Add(1)
	if im.xmlInflight == nil {
		im.xmlInflight = make(map[string]*domainXMLInflight, 256)
	}
	im.xmlInflight[inflightKey] = c
	im.xmlInflightMu.Unlock()

	defer func() {
		im.xmlInflightMu.Lock()
		delete(im.xmlInflight, inflightKey)
		im.xmlInflightMu.Unlock()
		c.wg.Done()
	}()

	im.domainMetaMu.RLock()
	meta2, ok2 := im.domainMeta[instanceUUID]
	if dom.ID < 0 {
		meta2, ok2 = im.inactiveDomainMeta[instanceUUID]
	}
	im.domainMetaMu.RUnlock()
	if ok2 && meta2 != nil && time.Since(meta2.LastUpdated) < 5*time.Minute {
		c.meta = meta2
		return meta2, true, nil
	}

	xmlDesc, err := im.readDomainXMLDesc(dom, conn, deadline)
	if err != nil {
		c.err = fmt.Errorf("failed to get domain XML description: %v", err)
		if meta2 != nil {
			c.meta = meta2
			return meta2, false, c.err
		}
		return nil, false, c.err
	}

	meta, err = parseDomainStaticFromXML(instanceUUID, dom.Name, xmlDesc)
	if err != nil {
		c.err = err
		if meta2 != nil {
			c.meta = meta2
			return meta2, false, c.err
		}
		return nil, false, c.err
	}

	if commit {
		im.domainMetaMu.Lock()
		im.domainMeta[instanceUUID] = meta
		im.domainMetaMu.Unlock()

		im.updateVMIPIndex(instanceUUID, meta.FixedIPs)
	}

	c.meta = meta
	return meta, true, nil
}

func (im *InstanceManager) effectiveLibvirtRPCTimeout() time.Duration {
	if im != nil && im.libvirtRPCTimeout > 0 {
		return im.libvirtRPCTimeout
	}
	return defaultLibvirtRPCTimeout
}

func domainXMLRPCKey(dom libvirt.Domain) string {
	if uuid := validLibvirtDomainUUID(dom.UUID); uuid != "" {
		return uuid
	}
	return strings.TrimSpace(dom.Name)
}

func (im *InstanceManager) beginDomainXMLRPC(dom libvirt.Domain) error {
	key := domainXMLRPCKey(dom)
	if key == "" {
		return fmt.Errorf("Libvirt domain XML RPC domain identity is empty")
	}
	im.domainXMLRPCMu.Lock()
	defer im.domainXMLRPCMu.Unlock()
	if im.domainXMLRPCInflight == nil {
		im.domainXMLRPCInflight = make(map[string]struct{})
	}
	if _, exists := im.domainXMLRPCInflight[key]; exists {
		return errDomainXMLRPCAlreadyInFlight
	}
	im.domainXMLRPCInflight[key] = struct{}{}
	return nil
}

func (im *InstanceManager) endDomainXMLRPC(dom libvirt.Domain) {
	key := domainXMLRPCKey(dom)
	if key == "" {
		return
	}
	im.domainXMLRPCMu.Lock()
	delete(im.domainXMLRPCInflight, key)
	im.domainXMLRPCMu.Unlock()
}

func (im *InstanceManager) readDomainXMLDesc(dom libvirt.Domain, conn *libvirt.Libvirt, deadline time.Time) (string, error) {
	xmlDescription, _, err := im.readDomainXMLDescWithRPCState(dom, conn, deadline)
	return xmlDescription, err
}

func (im *InstanceManager) readDomainXMLDescWithRPCState(
	dom libvirt.Domain,
	conn *libvirt.Libvirt,
	deadline time.Time,
) (string, bool, error) {
	if deadline.IsZero() {
		deadline = time.Now().Add(im.effectiveLibvirtRPCTimeout())
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return "", false, &libvirtRPCTimeoutError{
			Operation: "Libvirt domain XML RPC",
			Detail:    "deadline exceeded",
		}
	}
	if err := im.beginDomainXMLRPC(dom); err != nil {
		return "", false, err
	}

	workerSlotAcquired := false
	if im.xmlRPCSem != nil {
		acquireTimer := time.NewTimer(remaining)
		select {
		case im.xmlRPCSem <- struct{}{}:
			workerSlotAcquired = true
			// Go 1.24 timer channels are synchronous and Stop guarantees that a
			// later receive cannot observe a stale value. Draining after Stop can
			// therefore block at the semaphore/deadline boundary.
			acquireTimer.Stop()
		case <-acquireTimer.C:
			im.endDomainXMLRPC(dom)
			return "", false, &libvirtRPCTimeoutError{
				Operation: "Libvirt domain XML RPC",
				Detail:    "deadline exceeded while waiting for a worker slot",
			}
		}
	}

	// Acquiring a worker slot can consume the entire shared budget. Do not
	// start an RPC after its caller's deadline, and release the slot locally
	// because no underlying call exists to own it.
	remaining = time.Until(deadline)
	if remaining <= 0 {
		if workerSlotAcquired {
			<-im.xmlRPCSem
		}
		im.endDomainXMLRPC(dom)
		return "", false, &libvirtRPCTimeoutError{
			Operation: "Libvirt domain XML RPC",
			Detail:    "deadline exceeded before RPC start",
		}
	}

	type xmlResult struct {
		xml string
		err error
	}
	resultCh := make(chan xmlResult, 1)
	go func() {
		result := func() xmlResult {
			// A caller can time out while the Libvirt call is still blocked. Keep
			// both guards until the underlying RPC really exits so reconnects and
			// later collection cycles cannot accumulate duplicate raw goroutines.
			if workerSlotAcquired {
				defer func() { <-im.xmlRPCSem }()
			}
			defer im.endDomainXMLRPC(dom)
			if im.domainXMLDescOverride != nil {
				xmlDescription, err := im.domainXMLDescOverride(dom)
				return xmlResult{xml: xmlDescription, err: err}
			}
			if conn == nil {
				return xmlResult{err: fmt.Errorf("Libvirt connection is nil")}
			}
			xmlDescription, err := guardedDomainXML(conn, im.libvirtSafety, dom, deadline)
			return xmlResult{xml: xmlDescription, err: err}
		}()
		// Guards are released before the successful result becomes observable,
		// so a sequential retry cannot be rejected after the prior RPC finished.
		resultCh <- result
	}()

	remaining = time.Until(deadline)
	if remaining <= 0 {
		im.libvirtSafety.pause(time.Now())
		return "", true, &libvirtRPCTimeoutError{
			Operation:  "Libvirt domain XML RPC",
			RPCStarted: true,
			Detail:     "deadline exceeded",
		}
	}
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case result := <-resultCh:
		return result.xml, true, result.err
	case <-timer.C:
		im.libvirtSafety.pause(time.Now())
		return "", true, &libvirtRPCTimeoutError{
			Operation:  "Libvirt domain XML RPC",
			Wait:       remaining,
			RPCStarted: true,
		}
	}
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
	keys := vmIPKeys(fixedIPs)

	im.vmIPIndexMu.Lock()
	im.updateVMIPIndexLocked(instanceUUID, keys)
	im.vmIPIndexMu.Unlock()
}

func vmIPKeys(fixedIPs []IP) []IPKey {
	keys := make([]IPKey, 0, len(fixedIPs))
	seen := make(map[IPKey]struct{}, len(fixedIPs))
	for _, ip := range fixedIPs {
		if ip.Address == "" {
			continue
		}
		k := IPStrToKey(ip.Address)
		if k == (IPKey{}) {
			continue
		}
		if _, exists := seen[k]; exists {
			continue
		}
		seen[k] = struct{}{}
		keys = append(keys, k)
	}
	return keys
}

func (im *InstanceManager) updateVMIPIndexLocked(instanceUUID string, keys []IPKey) {
	if im.vmIPKeysByInstance == nil {
		im.vmIPKeysByInstance = make(map[string][]IPKey)
	}
	if im.vmIPOwners == nil {
		im.vmIPOwners = make(map[IPKey]map[string]struct{})
	}
	affected := make(map[IPKey]struct{}, len(im.vmIPKeysByInstance[instanceUUID])+len(keys))
	for _, k := range im.vmIPKeysByInstance[instanceUUID] {
		affected[k] = struct{}{}
		owners := im.vmIPOwners[k]
		delete(owners, instanceUUID)
		if len(owners) == 0 {
			delete(im.vmIPOwners, k)
		}
	}
	for _, k := range keys {
		affected[k] = struct{}{}
		owners := im.vmIPOwners[k]
		if owners == nil {
			owners = make(map[string]struct{})
			im.vmIPOwners[k] = owners
		}
		owners[instanceUUID] = struct{}{}
	}
	im.vmIPKeysByInstance[instanceUUID] = keys
	im.projectVMIPKeysLocked(affected)
}
func (im *InstanceManager) removeVMIPIndex(instanceUUID string) {
	if instanceUUID == "" {
		return
	}
	im.vmIPIndexMu.Lock()
	im.removeVMIPIndexLocked(instanceUUID)
	im.vmIPIndexMu.Unlock()
}

func (im *InstanceManager) removeVMIPIndexLocked(instanceUUID string) {
	affected := make(map[IPKey]struct{}, len(im.vmIPKeysByInstance[instanceUUID]))
	for _, k := range im.vmIPKeysByInstance[instanceUUID] {
		affected[k] = struct{}{}
		owners := im.vmIPOwners[k]
		delete(owners, instanceUUID)
		if len(owners) == 0 {
			delete(im.vmIPOwners, k)
		}
	}
	delete(im.vmIPKeysByInstance, instanceUUID)
	im.projectVMIPKeysLocked(affected)
}

// projectVMIPKeysLocked updates the read-optimized indexes for addresses
// changed by one instance. An empty projected owner marks an address as
// ambiguous; the full incremental owner set retains enough information to
// restore a sole owner when an overlap disappears.
func (im *InstanceManager) projectVMIPKeysLocked(affected map[IPKey]struct{}) {
	if im.vmIPSet == nil {
		im.vmIPSet = make(map[IPKey]struct{})
	}
	if im.vmIPToInstance == nil {
		im.vmIPToInstance = make(map[IPKey]string)
	}
	for affectedKey := range affected {
		owners := im.vmIPOwners[affectedKey]
		if len(owners) == 0 {
			delete(im.vmIPSet, affectedKey)
			delete(im.vmIPToInstance, affectedKey)
			continue
		}
		im.vmIPSet[affectedKey] = struct{}{}
		if len(owners) == 1 {
			for owner := range owners {
				im.vmIPToInstance[affectedKey] = owner
			}
		} else {
			im.vmIPToInstance[affectedKey] = ""
		}
	}
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

	im.resourceGenerationMu.Lock()
	for uuid := range im.resourceGeneration {
		if !im.isInstanceActive(uuid) {
			delete(im.resourceGeneration, uuid)
			delete(im.resourceGenerationCPUTime, uuid)
			delete(im.resourceGenerationToken, uuid)
		}
	}
	im.resourceGenerationMu.Unlock()

	im.resourceDimensionsMu.Lock()
	for uuid := range im.resourceDimensions {
		if !im.isInstanceActive(uuid) {
			delete(im.resourceDimensions, uuid)
		}
	}
	im.resourceDimensionsMu.Unlock()
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
