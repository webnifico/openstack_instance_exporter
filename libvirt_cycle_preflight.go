package main

import (
	"fmt"
	"sync"
	"time"

	libvirt "github.com/digitalocean/go-libvirt"
)

type preparedLibvirtCycle struct {
	activeSet     map[string]struct{}
	metadata      map[string]*DomainStatic
	runtimeTokens map[string]string
}

type domainMetadataPreflightResult struct {
	index        int
	instanceUUID string
	meta         *DomainStatic
	err          error
}

func validLibvirtDomainUUID(uuid libvirt.UUID) string {
	allZero := true
	for _, value := range uuid {
		if value != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return ""
	}
	return uuidBytesToString(uuid[:])
}

func (mc *MetricsCollector) prepareLibvirtCycle(domainStats []libvirt.DomainStatsRecord) (*preparedLibvirtCycle, error) {
	prepared := &preparedLibvirtCycle{
		activeSet: make(map[string]struct{}, len(domainStats)),
		metadata:  make(map[string]*DomainStatic, len(domainStats)),
	}
	if len(domainStats) == 0 {
		return prepared, nil
	}
	deadline := time.Now().Add(mc.im.effectiveLibvirtRPCTimeout())

	mc.libvirtMu.Lock()
	conn := mc.libvirtConn
	mc.libvirtMu.Unlock()

	type job struct {
		index int
		dom   libvirt.Domain
	}
	jobs := make(chan job, len(domainStats))
	results := make(chan domainMetadataPreflightResult, len(domainStats))
	workerCount := effectiveDomainWorkerCount(mc.im.workerCount)
	if workerCount > len(domainStats) {
		workerCount = len(domainStats)
	}

	var workers sync.WaitGroup
	for worker := 0; worker < workerCount; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for item := range jobs {
				instanceUUID := validLibvirtDomainUUID(item.dom.UUID)
				if instanceUUID == "" {
					results <- domainMetadataPreflightResult{
						index: item.index,
						err:   fmt.Errorf("invalid all-zero domain UUID"),
					}
					continue
				}
				meta, fresh := mc.pendingDomainMetadata[instanceUUID], true
				var err error
				if meta == nil {
					meta, fresh, err = mc.im.getDomainMetaCandidateForCollectionBefore(item.dom, conn, deadline)
				}
				if err == nil && (!fresh || meta == nil) {
					err = fmt.Errorf("domain metadata is not fresh")
				}
				results <- domainMetadataPreflightResult{
					index:        item.index,
					instanceUUID: instanceUUID,
					meta:         meta,
					err:          err,
				}
			}
		}()
	}
	for index, record := range domainStats {
		jobs <- job{index: index, dom: record.Dom}
	}
	close(jobs)
	workers.Wait()
	close(results)

	ordered := make([]domainMetadataPreflightResult, len(domainStats))
	for result := range results {
		ordered[result.index] = result
	}
	for index, result := range ordered {
		if result.err != nil {
			return nil, fmt.Errorf(
				"domain metadata preflight failed for %q: %w",
				domainStats[index].Dom.Name,
				result.err,
			)
		}
		if _, duplicate := prepared.metadata[result.instanceUUID]; duplicate {
			return nil, fmt.Errorf("duplicate domain UUID %s in libvirt stats cycle", result.instanceUUID)
		}
		if result.meta.InstanceUUID != result.instanceUUID {
			return nil, fmt.Errorf(
				"domain UUID %s does not match metadata instance UUID %q",
				result.instanceUUID,
				result.meta.InstanceUUID,
			)
		}
		if domainStats[index].Dom.ID >= 0 {
			prepared.activeSet[result.instanceUUID] = struct{}{}
		}
		prepared.metadata[result.instanceUUID] = result.meta
	}
	if mc.pendingRuntimeTokens != nil {
		after, err := mc.snapshotQEMUProcessIncarnations()
		if err != nil {
			return nil, fmt.Errorf("QEMU process incarnation postflight: %w", err)
		}
		stable, err := stableQEMUProcessTokens(domainStats, mc.pendingRuntimeTokens, after)
		if err != nil {
			return nil, err
		}
		prepared.runtimeTokens = stable
	}
	return prepared, nil
}

func (mc *MetricsCollector) applyPreparedRuntimeGenerations(domainStats []libvirt.DomainStatsRecord, prepared *preparedLibvirtCycle) {
	if prepared == nil || len(prepared.runtimeTokens) == 0 {
		return
	}
	for _, record := range domainStats {
		instanceUUID := validLibvirtDomainUUID(record.Dom.UUID)
		token, ok := prepared.runtimeTokens[instanceUUID]
		if !ok {
			continue
		}
		stat := parseLibvirtStats(record.Params)
		if mc.im.observeInstanceResourceGenerationWithToken(
			instanceUUID,
			record.Dom.ID,
			stat.CpuTime,
			stat.CpuTimePresent,
			token,
			true,
		) {
			mc.resetResourceV2ForTransition(instanceUUID)
			mc.cm.resetBehaviorStateForInstance(instanceUUID)
			mc.resetThreatStateForInstance(instanceUUID)
		}
	}
}

func (mc *MetricsCollector) commitPreparedLibvirtCycle(prepared *preparedLibvirtCycle) {
	if prepared == nil {
		return
	}
	// Keep inactive XML on the same bounded five-minute refresh policy. Publish
	// it only after a complete inventory preflight; do not put its IPs in runtime maps.
	inactive := make(map[string]*DomainStatic)
	for uuid, meta := range prepared.metadata {
		if _, active := prepared.activeSet[uuid]; !active {
			inactive[uuid] = meta
		}
	}
	mc.im.domainMetaMu.Lock()
	mc.im.inactiveDomainMeta = inactive
	mc.im.domainMetaMu.Unlock()
	activeMetadata := make(map[string]*DomainStatic, len(prepared.activeSet))
	for instanceUUID := range prepared.activeSet {
		activeMetadata[instanceUUID] = prepared.metadata[instanceUUID]
	}
	for _, instanceUUID := range mc.im.commitPreparedInventory(prepared.activeSet, activeMetadata) {
		mc.resetThreatStateForInstance(instanceUUID)
	}
}

func sameVMIPKeySet(left, right []IPKey) bool {
	if len(left) != len(right) {
		return false
	}
	if len(left) == 0 {
		return true
	}
	keys := make(map[IPKey]struct{}, len(left))
	for _, key := range left {
		keys[key] = struct{}{}
	}
	for _, key := range right {
		if _, ok := keys[key]; !ok {
			return false
		}
	}
	return true
}

// commitPreparedInventory returns active instance UUIDs whose authoritative
// fixed-IP membership changed. Callers use that boundary to prevent
// UUID-scoped threat history and evidence-diff state from spanning two IP
// ownership epochs.
func (im *InstanceManager) commitPreparedInventory(activeSet map[string]struct{}, metadata map[string]*DomainStatic) []string {
	keysByInstance := make(map[string][]IPKey, len(metadata))
	for instanceUUID, meta := range metadata {
		if meta != nil {
			keysByInstance[instanceUUID] = vmIPKeys(meta.FixedIPs)
		}
	}
	committedActive := make(map[string]struct{}, len(activeSet))
	for instanceUUID := range activeSet {
		committedActive[instanceUUID] = struct{}{}
	}

	// Match cleanupDomainMeta's lock order: metadata, active inventory, then
	// the projected IP index. Readers can observe either complete inventory,
	// never a partially refreshed set caused by one failed domain.
	im.domainMetaMu.Lock()
	im.activeInstancesMu.Lock()
	im.vmIPIndexMu.Lock()
	if im.domainMeta == nil {
		im.domainMeta = make(map[string]*DomainStatic)
	}
	changedIPMembership := make([]string, 0)
	for instanceUUID, keys := range keysByInstance {
		previous, observed := im.vmIPKeysByInstance[instanceUUID]
		if observed && !sameVMIPKeySet(previous, keys) {
			changedIPMembership = append(changedIPMembership, instanceUUID)
		}
	}
	for instanceUUID := range im.domainMeta {
		if _, active := committedActive[instanceUUID]; active {
			continue
		}
		delete(im.domainMeta, instanceUUID)
		im.removeVMIPIndexLocked(instanceUUID)
	}
	for instanceUUID, meta := range metadata {
		if meta == nil {
			continue
		}
		im.domainMeta[instanceUUID] = meta
		im.updateVMIPIndexLocked(instanceUUID, keysByInstance[instanceUUID])
	}
	im.activeInstances = committedActive
	im.vmIPIndexMu.Unlock()
	im.activeInstancesMu.Unlock()
	im.domainMetaMu.Unlock()
	return changedIPMembership
}
