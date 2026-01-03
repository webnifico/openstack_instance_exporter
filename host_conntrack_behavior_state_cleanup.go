package main

import (
	"sync"
	"time"
)

func (cm *ConntrackManager) cleanupBehaviorMaps(activeSet map[string]struct{}) {
	now := time.Now().Unix()

	cleanupShard := func(mu *sync.Mutex, prevR map[BehaviorKey]outboundPrev, prevP map[BehaviorKey]outboundPrevDstPorts, seen map[BehaviorKey]int64) {
		mu.Lock()
		defer mu.Unlock()

		for k := range prevR {
			last, okSeen := seen[k]
			if _, ok := activeSet[k.InstanceUUID]; !ok || !okSeen || (now-last) > behaviorPrevKeyTTLSeconds {
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
			if _, ok := activeSet[k.InstanceUUID]; !ok || !okSeen || (now-last) > behaviorPrevKeyTTLSeconds {
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
	now := time.Now().Unix()
	for i := 0; i < shardCount; i++ {
		cm.behaviorEWMAMu[i].Lock()
		for k, s := range cm.behaviorEWMA[i] {
			if _, ok := activeSet[k.InstanceUUID]; !ok || (now-s.LastSeenUnix) > behaviorIdentityTTLSeconds {
				delete(cm.behaviorEWMA[i], k)
			}
		}
		cm.behaviorEWMAMu[i].Unlock()

		cm.outboundMu[i].Lock()
		for k, last := range cm.outboundPrevLastSeen[i] {
			if _, ok := activeSet[k.InstanceUUID]; !ok || (now-last) > behaviorPrevKeyTTLSeconds {
				delete(cm.outboundPrevLastSeen[i], k)
				delete(cm.outboundPrev[i], k)
				delete(cm.outboundPrevDstPorts[i], k)
			}
		}
		cm.outboundMu[i].Unlock()

		cm.inboundMu[i].Lock()
		for k, last := range cm.inboundPrevLastSeen[i] {
			if _, ok := activeSet[k.InstanceUUID]; !ok || (now-last) > behaviorPrevKeyTTLSeconds {
				delete(cm.inboundPrevLastSeen[i], k)
				delete(cm.inboundPrev[i], k)
				delete(cm.inboundPrevDstPorts[i], k)
			}
		}
		cm.inboundMu[i].Unlock()
	}

	cm.behaviorAlertMu.Lock()
	for k, st := range cm.behaviorPersist {
		if _, ok := activeSet[k.InstanceUUID]; !ok || (now-st.LastSeenUnix) > 3600 {
			delete(cm.behaviorPersist, k)
		}
	}
	for k, st := range cm.behaviorEmit {
		if _, ok := activeSet[k.InstanceUUID]; !ok || (now-st.LastEmitUnix) > 3600 {
			delete(cm.behaviorEmit, k)
		}
	}
	cm.behaviorAlertMu.Unlock()
}
