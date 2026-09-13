package main

import (
	"time"

	libvirt "github.com/digitalocean/go-libvirt"
)

// behaviorLifecycleFreezeState owns the source-time boundary for one
// instance whose Libvirt state field is unavailable. Missing state is not an
// authoritative stop: the instance's last complete behavior state remains
// valid, but none of the unavailable interval may satisfy an elapsed-time,
// TTL, cooldown, or persistence rule.
type behaviorLifecycleFreezeState struct {
	FreezeStartUnix      int64
	Frozen               bool
	RecoveryRebaseline   bool
	RecoveryShiftSeconds int64
}

func conntrackObservationTime(aggregate *ConntrackAgg, fallback time.Time) time.Time {
	if aggregate != nil && (aggregate.ObservationTimeSet || aggregate.ObservationUnix != 0) {
		return time.Unix(aggregate.ObservationUnix, 0)
	}
	return fallback
}

// beginBehaviorLifecycleFreezesForMissingStates runs before TTL cleanup. The
// normal per-domain observer runs later, after conntrack collection, which is
// too late to protect old last-good state on the first unavailable cycle.
// Only missing state is pre-marked here; running recovery and authoritative
// non-running resets retain their normal per-domain ordering.
func (cm *ConntrackManager) beginBehaviorLifecycleFreezesForMissingStates(records []libvirt.DomainStatsRecord, now time.Time) {
	if cm == nil {
		return
	}
	for _, record := range records {
		stats := parseLibvirtStats(record.Params)
		if stats.StatePresent {
			continue
		}
		instanceUUID := validLibvirtDomainUUID(record.Dom.UUID)
		if instanceUUID == "" {
			continue
		}
		cm.observeBehaviorInstanceLifecycle(instanceUUID, false, false, now)
	}
}

func (cm *ConntrackManager) snapshotBehaviorFrozenInstances() map[string]struct{} {
	if cm == nil {
		return nil
	}
	cm.behaviorLifecycleMu.Lock()
	frozen := make(map[string]struct{})
	for instanceUUID, state := range cm.behaviorLifecycleFreeze {
		if state != nil && state.Frozen {
			frozen[instanceUUID] = struct{}{}
		}
	}
	cm.behaviorLifecycleMu.Unlock()
	return frozen
}

// resetBehaviorStateForInstance clears every conntrack-derived state family
// owned by an instance. It is used only at authoritative lifecycle boundaries
// (a QEMU incarnation change or a known non-running Libvirt state).
func (cm *ConntrackManager) resetBehaviorStateForInstance(instanceUUID string) {
	if cm == nil || instanceUUID == "" {
		return
	}

	cm.behaviorLifecycleMu.Lock()
	delete(cm.behaviorLifecycleFreeze, instanceUUID)
	cm.behaviorLifecycleMu.Unlock()

	for index := 0; index < shardCount; index++ {
		cm.outboundMu[index].Lock()
		for key := range cm.outboundPrev[index] {
			if key.InstanceUUID == instanceUUID {
				delete(cm.outboundPrev[index], key)
			}
		}
		for key := range cm.outboundPrevDstPorts[index] {
			if key.InstanceUUID == instanceUUID {
				delete(cm.outboundPrevDstPorts[index], key)
			}
		}
		for key := range cm.outboundPrevLastSeen[index] {
			if key.InstanceUUID == instanceUUID {
				delete(cm.outboundPrevLastSeen[index], key)
			}
		}
		cm.outboundMu[index].Unlock()

		cm.inboundMu[index].Lock()
		for key := range cm.inboundPrev[index] {
			if key.InstanceUUID == instanceUUID {
				delete(cm.inboundPrev[index], key)
			}
		}
		for key := range cm.inboundPrevDstPorts[index] {
			if key.InstanceUUID == instanceUUID {
				delete(cm.inboundPrevDstPorts[index], key)
			}
		}
		for key := range cm.inboundPrevLastSeen[index] {
			if key.InstanceUUID == instanceUUID {
				delete(cm.inboundPrevLastSeen[index], key)
			}
		}
		cm.inboundMu[index].Unlock()

		cm.behaviorEWMAMu[index].Lock()
		for key := range cm.behaviorEWMA[index] {
			if key.InstanceUUID == instanceUUID {
				delete(cm.behaviorEWMA[index], key)
			}
		}
		for key := range cm.behaviorLastSeverity[index] {
			if key.InstanceUUID == instanceUUID {
				delete(cm.behaviorLastSeverity[index], key)
			}
		}
		cm.behaviorEWMAMu[index].Unlock()
	}

	cm.behaviorAlertMu.Lock()
	for key := range cm.behaviorPersist {
		if key.InstanceUUID == instanceUUID {
			delete(cm.behaviorPersist, key)
		}
	}
	for key := range cm.behaviorEmit {
		if key.InstanceUUID == instanceUUID {
			delete(cm.behaviorEmit, key)
		}
	}
	for key := range cm.miningAlerts {
		if key.InstanceUUID == instanceUUID {
			delete(cm.miningAlerts, key)
		}
	}
	cm.behaviorAlertMu.Unlock()

	// The rule-log throttle owns its own mutex. Never acquire it while holding
	// behaviorAlertMu or a behavior shard lock.
	clearBehaviorRuleLogStateForInstance(instanceUUID)
}

// pruneBehaviorStateToVMIPIdentities applies an authoritative Libvirt
// inventory snapshot to behavior state. Ownership is the exact UUID+IP pair;
// an active UUID does not keep state for an IP that has been detached.
func (cm *ConntrackManager) pruneBehaviorStateToVMIPIdentities(activeSet map[string]struct{}, identities []VMIPIdentity) {
	if cm == nil {
		return
	}
	allowed := make(map[VMIPIdentity]struct{}, len(identities))
	for _, identity := range identities {
		if _, active := activeSet[identity.InstanceUUID]; active {
			allowed[identity] = struct{}{}
		}
	}
	retained := func(instanceUUID string, ip IPKey) bool {
		if _, active := activeSet[instanceUUID]; !active {
			return false
		}
		_, ok := allowed[VMIPIdentity{InstanceUUID: instanceUUID, IP: ip}]
		return ok
	}

	cm.behaviorLifecycleMu.Lock()
	for instanceUUID := range cm.behaviorLifecycleFreeze {
		if _, active := activeSet[instanceUUID]; !active {
			delete(cm.behaviorLifecycleFreeze, instanceUUID)
		}
	}
	cm.behaviorLifecycleMu.Unlock()

	for index := 0; index < shardCount; index++ {
		cm.outboundMu[index].Lock()
		for key := range cm.outboundPrev[index] {
			if !retained(key.InstanceUUID, key.IP) {
				delete(cm.outboundPrev[index], key)
			}
		}
		for key := range cm.outboundPrevDstPorts[index] {
			if !retained(key.InstanceUUID, key.IP) {
				delete(cm.outboundPrevDstPorts[index], key)
			}
		}
		for key := range cm.outboundPrevLastSeen[index] {
			if !retained(key.InstanceUUID, key.IP) {
				delete(cm.outboundPrevLastSeen[index], key)
			}
		}
		cm.outboundMu[index].Unlock()

		cm.inboundMu[index].Lock()
		for key := range cm.inboundPrev[index] {
			if !retained(key.InstanceUUID, key.IP) {
				delete(cm.inboundPrev[index], key)
			}
		}
		for key := range cm.inboundPrevDstPorts[index] {
			if !retained(key.InstanceUUID, key.IP) {
				delete(cm.inboundPrevDstPorts[index], key)
			}
		}
		for key := range cm.inboundPrevLastSeen[index] {
			if !retained(key.InstanceUUID, key.IP) {
				delete(cm.inboundPrevLastSeen[index], key)
			}
		}
		cm.inboundMu[index].Unlock()

		cm.behaviorEWMAMu[index].Lock()
		for key := range cm.behaviorEWMA[index] {
			if !retained(key.InstanceUUID, key.IP) {
				delete(cm.behaviorEWMA[index], key)
			}
		}
		for key := range cm.behaviorLastSeverity[index] {
			if !retained(key.InstanceUUID, key.IP) {
				delete(cm.behaviorLastSeverity[index], key)
			}
		}
		cm.behaviorEWMAMu[index].Unlock()
	}

	cm.behaviorAlertMu.Lock()
	for key := range cm.behaviorPersist {
		if !retained(key.InstanceUUID, key.IP) {
			delete(cm.behaviorPersist, key)
		}
	}
	for key := range cm.behaviorEmit {
		if !retained(key.InstanceUUID, key.IP) {
			delete(cm.behaviorEmit, key)
		}
	}
	for key := range cm.miningAlerts {
		if !retained(key.InstanceUUID, key.IP) {
			delete(cm.miningAlerts, key)
		}
	}
	cm.behaviorAlertMu.Unlock()

	pruneBehaviorRuleLogStateToVMIPIdentities(allowed, activeSet)
}

// observeBehaviorInstanceLifecycle returns true only for the first complete
// observation after this instance's Libvirt state was unavailable. Known
// non-running states are authoritative and clear state immediately.
func (cm *ConntrackManager) observeBehaviorInstanceLifecycle(instanceUUID string, stateKnown, running bool, now time.Time) bool {
	if cm == nil || instanceUUID == "" {
		return false
	}
	if stateKnown && !running {
		cm.resetBehaviorStateForInstance(instanceUUID)
		return false
	}

	nowUnix := now.Unix()
	if !stateKnown {
		cm.behaviorLifecycleMu.Lock()
		if cm.behaviorLifecycleFreeze == nil {
			cm.behaviorLifecycleFreeze = make(map[string]*behaviorLifecycleFreezeState)
		}
		state := cm.behaviorLifecycleFreeze[instanceUUID]
		if state == nil {
			state = &behaviorLifecycleFreezeState{}
			cm.behaviorLifecycleFreeze[instanceUUID] = state
		}
		if !state.Frozen {
			state.FreezeStartUnix = nowUnix
			state.Frozen = true
		}
		state.RecoveryRebaseline = false
		cm.behaviorLifecycleMu.Unlock()
		return false
	}

	cm.behaviorFreezeMu.Lock()
	globalFreezeStart := cm.behaviorFreezeStartUnix
	globalFreezeActive := cm.behaviorFreezeActive
	cm.behaviorFreezeMu.Unlock()

	var delta int64
	cm.behaviorLifecycleMu.Lock()
	state := cm.behaviorLifecycleFreeze[instanceUUID]
	if state == nil {
		cm.behaviorLifecycleMu.Unlock()
		return false
	}
	if state.Frozen {
		endUnix := nowUnix
		if globalFreezeActive && globalFreezeStart < endUnix {
			endUnix = globalFreezeStart
		}
		if endUnix > state.FreezeStartUnix {
			delta = endUnix - state.FreezeStartUnix
		}
		state.Frozen = false
		state.FreezeStartUnix = 0
		// An active global source freeze owns the remainder and supplies the
		// recovery marker when conntrack becomes complete again.
		state.RecoveryRebaseline = !globalFreezeActive
		state.RecoveryShiftSeconds += delta
	}
	rebaseline := state.RecoveryRebaseline
	if !state.Frozen && !state.RecoveryRebaseline && state.RecoveryShiftSeconds == 0 {
		delete(cm.behaviorLifecycleFreeze, instanceUUID)
	}
	cm.behaviorLifecycleMu.Unlock()

	cm.shiftBehaviorStateClockForInstance(instanceUUID, delta)
	return rebaseline
}

func (cm *ConntrackManager) behaviorInstanceNeedsRecoveryRebaseline(instanceUUID string) bool {
	if cm == nil || instanceUUID == "" {
		return false
	}
	cm.behaviorLifecycleMu.Lock()
	state := cm.behaviorLifecycleFreeze[instanceUUID]
	needsRebaseline := state != nil && state.RecoveryRebaseline
	cm.behaviorLifecycleMu.Unlock()
	return needsRebaseline
}

func (cm *ConntrackManager) behaviorInstanceStateFrozen(instanceUUID string) bool {
	if cm == nil || instanceUUID == "" {
		return false
	}
	cm.behaviorLifecycleMu.Lock()
	state := cm.behaviorLifecycleFreeze[instanceUUID]
	frozen := state != nil && state.Frozen
	cm.behaviorLifecycleMu.Unlock()
	return frozen
}

func (cm *ConntrackManager) takeBehaviorInstanceRecoveryShiftSeconds(instanceUUID string) int64 {
	if cm == nil || instanceUUID == "" {
		return 0
	}
	cm.behaviorLifecycleMu.Lock()
	state := cm.behaviorLifecycleFreeze[instanceUUID]
	var shift int64
	if state != nil {
		shift = state.RecoveryShiftSeconds
		state.RecoveryShiftSeconds = 0
		if !state.Frozen && !state.RecoveryRebaseline {
			delete(cm.behaviorLifecycleFreeze, instanceUUID)
		}
	}
	cm.behaviorLifecycleMu.Unlock()
	return shift
}

func (cm *ConntrackManager) finishBehaviorInstanceRecovery(instanceUUID string) {
	if cm == nil || instanceUUID == "" {
		return
	}
	cm.behaviorLifecycleMu.Lock()
	state := cm.behaviorLifecycleFreeze[instanceUUID]
	if state != nil {
		state.RecoveryRebaseline = false
		state.RecoveryShiftSeconds = 0
		if !state.Frozen {
			delete(cm.behaviorLifecycleFreeze, instanceUUID)
		}
	}
	cm.behaviorLifecycleMu.Unlock()
}

// prepareBehaviorLifecycleForGlobalResume accounts for the non-overlapping
// prefix of any per-instance outage, then moves its boundary to the end of the
// global conntrack outage. This makes the two clocks represent their union,
// never their sum.
func (cm *ConntrackManager) prepareBehaviorLifecycleForGlobalResume(globalStartUnix, nowUnix int64) map[string]int64 {
	if cm == nil || nowUnix <= globalStartUnix {
		return nil
	}
	cm.behaviorLifecycleMu.Lock()
	defer cm.behaviorLifecycleMu.Unlock()
	var prefixes map[string]int64
	for instanceUUID, state := range cm.behaviorLifecycleFreeze {
		if state == nil || !state.Frozen {
			continue
		}
		if state.FreezeStartUnix < globalStartUnix {
			if prefixes == nil {
				prefixes = make(map[string]int64)
			}
			prefixes[instanceUUID] = globalStartUnix - state.FreezeStartUnix
			state.RecoveryShiftSeconds += prefixes[instanceUUID]
		}
		state.FreezeStartUnix = nowUnix
		state.RecoveryRebaseline = false
	}
	return prefixes
}

func (cm *ConntrackManager) shiftBehaviorStateClockForInstance(instanceUUID string, delta int64) {
	if cm == nil || instanceUUID == "" || delta <= 0 {
		return
	}
	shift := func(value *int64) {
		if *value > 0 {
			*value += delta
		}
	}
	for index := 0; index < shardCount; index++ {
		cm.outboundMu[index].Lock()
		for key, value := range cm.outboundPrevLastSeen[index] {
			if key.InstanceUUID == instanceUUID && value > 0 {
				cm.outboundPrevLastSeen[index][key] = value + delta
			}
		}
		cm.outboundMu[index].Unlock()

		cm.inboundMu[index].Lock()
		for key, value := range cm.inboundPrevLastSeen[index] {
			if key.InstanceUUID == instanceUUID && value > 0 {
				cm.inboundPrevLastSeen[index][key] = value + delta
			}
		}
		cm.inboundMu[index].Unlock()

		cm.behaviorEWMAMu[index].Lock()
		for key, state := range cm.behaviorEWMA[index] {
			if key.InstanceUUID == instanceUUID && state != nil {
				shift(&state.LastSeenUnix)
			}
		}
		cm.behaviorEWMAMu[index].Unlock()
	}

	cm.behaviorAlertMu.Lock()
	for key, state := range cm.behaviorPersist {
		if key.InstanceUUID == instanceUUID && state != nil {
			shift(&state.FirstSeenUnix)
			shift(&state.LastSeenUnix)
		}
	}
	for key, state := range cm.behaviorEmit {
		if key.InstanceUUID == instanceUUID && state != nil {
			shift(&state.LastEpisodeStartUnix)
			shift(&state.LastEmitUnix)
		}
	}
	for key, state := range cm.miningAlerts {
		if key.InstanceUUID == instanceUUID && state != nil {
			shift(&state.FirstSeenUnix)
			shift(&state.LastSeenUnix)
			shift(&state.LastRecoveryObservationUnix)
			shift(&state.LastEpisodeStartUnix)
			shift(&state.LastEmitUnix)
		}
	}
	cm.behaviorAlertMu.Unlock()

	shiftBehaviorRuleLogStateForInstance(instanceUUID, delta)
}
