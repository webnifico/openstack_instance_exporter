package main

import (
	"sync/atomic"
	"time"
)

// beginBehaviorStateFreeze records the first failed collection boundary. A
// repeated failure must not move the boundary, otherwise the outage would leak
// back into EWMA, persistence, cooldown, and TTL calculations on recovery.
func (cm *ConntrackManager) beginBehaviorStateFreeze(now time.Time) {
	if cm == nil {
		return
	}
	nowUnix := now.Unix()
	atomic.StoreUint64(&cm.behaviorRecoveryRebaseline, 0)
	cm.behaviorFreezeMu.Lock()
	if !cm.behaviorFreezeActive {
		cm.behaviorFreezeStartUnix = nowUnix
		cm.behaviorFreezeActive = true
	}
	cm.behaviorFreezeMu.Unlock()
}

// resumeBehaviorStateClock removes the time spent without a complete source
// snapshot from every conntrack-derived state clock. The recovery sample then
// advances state exactly once, using only the normal interval since the last
// complete sample instead of treating the outage as observed workload time.
func (cm *ConntrackManager) resumeBehaviorStateClock(now time.Time) int64 {
	if cm == nil {
		return 0
	}
	return cm.resumeBehaviorStateClockAt(now.Unix())
}

func (cm *ConntrackManager) resumeBehaviorStateClockAt(nowUnix int64) int64 {
	cm.behaviorFreezeMu.Lock()
	freezeStart := cm.behaviorFreezeStartUnix
	freezeActive := cm.behaviorFreezeActive
	cm.behaviorFreezeStartUnix = 0
	cm.behaviorFreezeActive = false
	cm.behaviorFreezeMu.Unlock()

	if !freezeActive {
		return 0
	}
	atomic.StoreUint64(&cm.behaviorRecoveryRebaseline, 1)
	delta := nowUnix - freezeStart
	if delta <= 0 {
		return 0
	}

	// A missing Libvirt state and a failed conntrack dump may overlap. Shift
	// each instance's non-overlapping prefix first, then shift the global
	// interval once for all identities. Active per-instance freezes restart at
	// now so their later recovery owns only the remaining suffix.
	for instanceUUID, prefix := range cm.prepareBehaviorLifecycleForGlobalResume(freezeStart, nowUnix) {
		cm.shiftBehaviorStateClockForInstance(instanceUUID, prefix)
	}
	shift := func(value *int64) {
		if *value > 0 {
			*value += delta
		}
	}

	for i := 0; i < shardCount; i++ {
		cm.outboundMu[i].Lock()
		for key, value := range cm.outboundPrevLastSeen[i] {
			if value > 0 {
				cm.outboundPrevLastSeen[i][key] = value + delta
			}
		}
		cm.outboundMu[i].Unlock()

		cm.inboundMu[i].Lock()
		for key, value := range cm.inboundPrevLastSeen[i] {
			if value > 0 {
				cm.inboundPrevLastSeen[i][key] = value + delta
			}
		}
		cm.inboundMu[i].Unlock()

		cm.behaviorEWMAMu[i].Lock()
		for _, state := range cm.behaviorEWMA[i] {
			if state != nil {
				shift(&state.LastSeenUnix)
			}
		}
		cm.behaviorEWMAMu[i].Unlock()
	}

	cm.behaviorAlertMu.Lock()
	for _, state := range cm.behaviorPersist {
		if state != nil {
			shift(&state.FirstSeenUnix)
			shift(&state.LastSeenUnix)
		}
	}
	for _, state := range cm.behaviorEmit {
		if state != nil {
			shift(&state.LastEpisodeStartUnix)
			shift(&state.LastEmitUnix)
		}
	}
	for _, state := range cm.miningAlerts {
		if state != nil {
			shift(&state.FirstSeenUnix)
			shift(&state.LastSeenUnix)
			shift(&state.LastRecoveryObservationUnix)
			shift(&state.LastEpisodeStartUnix)
			shift(&state.LastEmitUnix)
		}
	}
	cm.behaviorAlertMu.Unlock()
	shiftAllBehaviorRuleLogState(delta)
	return delta
}

func (cm *ConntrackManager) behaviorNeedsRecoveryRebaseline() bool {
	return cm != nil && atomic.LoadUint64(&cm.behaviorRecoveryRebaseline) != 0
}

func (cm *ConntrackManager) finishBehaviorRecoveryRebaseline() {
	if cm != nil {
		atomic.StoreUint64(&cm.behaviorRecoveryRebaseline, 0)
	}
}
