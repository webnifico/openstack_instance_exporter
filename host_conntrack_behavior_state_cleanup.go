package main

import (
	"sync"
	"time"
)

func miningAlertCleanupLastActivity(state *miningAlertState) int64 {
	if state == nil {
		return 0
	}
	lastActivity := state.LastSeenUnix
	if state.LastEmitUnix > lastActivity {
		lastActivity = state.LastEmitUnix
	}
	if state.LastRecoveryObservationUnix > lastActivity {
		lastActivity = state.LastRecoveryObservationUnix
	}
	return lastActivity
}

func miningAlertCleanupExpired(state *miningAlertState, now int64) bool {
	if state == nil {
		return true
	}
	lastActivity := miningAlertCleanupLastActivity(state)
	return lastActivity <= 0 || (now-lastActivity) > behaviorIdentityTTLSeconds
}

func (cm *ConntrackManager) cleanupBehaviorMaps(activeSet map[string]struct{}) {
	cm.cleanupBehaviorMapsWithAging(activeSet, false)
}

// freezeAging pauses source-time TTL expiry while still removing state owned by
// instances that Libvirt confirms are no longer active.
func (cm *ConntrackManager) cleanupBehaviorMapsWithAging(activeSet map[string]struct{}, freezeAging bool) {
	now := time.Now().Unix()
	frozenInstances := cm.snapshotBehaviorFrozenInstances()

	cleanupShard := func(mu *sync.Mutex, prevR map[BehaviorKey]outboundPrev, prevP map[BehaviorKey]outboundPrevDstPorts, seen map[BehaviorKey]int64) {
		mu.Lock()
		defer mu.Unlock()

		for k := range prevR {
			last, okSeen := seen[k]
			_, active := activeSet[k.InstanceUUID]
			_, instanceFrozen := frozenInstances[k.InstanceUUID]
			if !active || !okSeen || (!freezeAging && !instanceFrozen && (now-last) > behaviorPrevKeyTTLSeconds) {
				delete(prevR, k)
				delete(prevP, k)
				delete(seen, k)
			}
		}

		for k := range prevP {
			if _, ok := prevR[k]; ok {
				continue
			}
			last, okSeen := seen[k]
			_, active := activeSet[k.InstanceUUID]
			_, instanceFrozen := frozenInstances[k.InstanceUUID]
			if !active || !okSeen || (!freezeAging && !instanceFrozen && (now-last) > behaviorPrevKeyTTLSeconds) {
				delete(prevP, k)
				delete(seen, k)
			}
		}
	}

	for i := 0; i < shardCount; i++ {
		cleanupShard(&cm.outboundMu[i], cm.outboundPrev[i], cm.outboundPrevDstPorts[i], cm.outboundPrevLastSeen[i])
		cleanupShard(&cm.inboundMu[i], cm.inboundPrev[i], cm.inboundPrevDstPorts[i], cm.inboundPrevLastSeen[i])
	}
}

func (cm *ConntrackManager) cleanupBehaviorState(activeSet map[string]struct{}) {
	cm.cleanupBehaviorStateWithAging(activeSet, false)
}

// freezeAging pauses source-time TTL expiry while still removing state owned by
// instances that Libvirt confirms are no longer active.
func (cm *ConntrackManager) cleanupBehaviorStateWithAging(activeSet map[string]struct{}, freezeAging bool) {
	now := time.Now().Unix()
	frozenInstances := cm.snapshotBehaviorFrozenInstances()
	for i := 0; i < shardCount; i++ {
		cm.behaviorEWMAMu[i].Lock()
		for k, s := range cm.behaviorEWMA[i] {
			_, active := activeSet[k.InstanceUUID]
			_, instanceFrozen := frozenInstances[k.InstanceUUID]
			if !active || (!freezeAging && !instanceFrozen && (now-s.LastSeenUnix) > behaviorIdentityTTLSeconds) {
				delete(cm.behaviorEWMA[i], k)
				delete(cm.behaviorLastSeverity[i], k)
			}
		}
		for k := range cm.behaviorLastSeverity[i] {
			if _, ok := activeSet[k.InstanceUUID]; !ok {
				delete(cm.behaviorLastSeverity[i], k)
			}
		}
		cm.behaviorEWMAMu[i].Unlock()

		cm.outboundMu[i].Lock()
		for k, last := range cm.outboundPrevLastSeen[i] {
			_, active := activeSet[k.InstanceUUID]
			_, instanceFrozen := frozenInstances[k.InstanceUUID]
			if !active || (!freezeAging && !instanceFrozen && (now-last) > behaviorPrevKeyTTLSeconds) {
				delete(cm.outboundPrevLastSeen[i], k)
				delete(cm.outboundPrev[i], k)
				delete(cm.outboundPrevDstPorts[i], k)
			}
		}
		cm.outboundMu[i].Unlock()

		cm.inboundMu[i].Lock()
		for k, last := range cm.inboundPrevLastSeen[i] {
			_, active := activeSet[k.InstanceUUID]
			_, instanceFrozen := frozenInstances[k.InstanceUUID]
			if !active || (!freezeAging && !instanceFrozen && (now-last) > behaviorPrevKeyTTLSeconds) {
				delete(cm.inboundPrevLastSeen[i], k)
				delete(cm.inboundPrev[i], k)
				delete(cm.inboundPrevDstPorts[i], k)
			}
		}
		cm.inboundMu[i].Unlock()
	}

	cm.behaviorAlertMu.Lock()
	for k, st := range cm.behaviorPersist {
		_, active := activeSet[k.InstanceUUID]
		_, instanceFrozen := frozenInstances[k.InstanceUUID]
		if !active || (!freezeAging && !instanceFrozen && (now-st.LastSeenUnix) > 3600) {
			delete(cm.behaviorPersist, k)
		}
	}
	for k, st := range cm.behaviorEmit {
		_, active := activeSet[k.InstanceUUID]
		_, instanceFrozen := frozenInstances[k.InstanceUUID]
		if !active || (!freezeAging && !instanceFrozen && (now-st.LastEmitUnix) > behaviorPrevKeyTTLSeconds) {
			delete(cm.behaviorEmit, k)
		}
	}
	for k, st := range cm.miningAlerts {
		_, active := activeSet[k.InstanceUUID]
		_, instanceFrozen := frozenInstances[k.InstanceUUID]
		if !active || (!freezeAging && !instanceFrozen && miningAlertCleanupExpired(st, now)) {
			delete(cm.miningAlerts, k)
		}
	}
	cm.behaviorAlertMu.Unlock()
}
