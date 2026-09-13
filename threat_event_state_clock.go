package main

import (
	"strings"
	"time"
)

const hostThreatThrottlePrefix = "PROVIDER_IP_THREAT|"

func (tm *ThreatManager) shiftThreatEventClock(deltaSeconds int64) {
	if tm == nil || deltaSeconds <= 0 {
		return
	}
	delta := time.Duration(deltaSeconds) * time.Second
	tm.threatLastHitMu.Lock()
	for key, timestamp := range tm.threatLastHit {
		if strings.HasPrefix(key, hostThreatThrottlePrefix) {
			continue
		}
		if !timestamp.IsZero() {
			tm.threatLastHit[key] = timestamp.Add(delta)
		}
	}
	tm.threatLastHitMu.Unlock()
}

func (tm *ThreatManager) shiftThreatEventClockForInstance(instanceUUID string, deltaSeconds int64) {
	if tm == nil || instanceUUID == "" || deltaSeconds <= 0 {
		return
	}
	delta := time.Duration(deltaSeconds) * time.Second
	tm.threatLastHitMu.Lock()
	for key, timestamp := range tm.threatLastHit {
		owner, ok := instanceThreatThrottleOwner(key)
		if !ok || owner != instanceUUID || timestamp.IsZero() {
			continue
		}
		tm.threatLastHit[key] = timestamp.Add(delta)
	}
	tm.threatLastHitMu.Unlock()
}

func (tm *ThreatManager) cleanupThreatLastHitWithConntrackFreeze(freezeConntrack bool) {
	tm.cleanupThreatLastHitWithFrozenInstances(freezeConntrack, nil)
}

func (tm *ThreatManager) cleanupThreatLastHitWithFrozenInstances(freezeConntrack bool, frozenInstances map[string]struct{}) {
	if tm == nil {
		return
	}
	minInterval := tm.threatLogMinInterval
	if minInterval <= 0 {
		minInterval = 5 * time.Minute
	}
	cutoff := time.Now().Add(-minInterval)
	tm.threatLastHitMu.Lock()
	for key, timestamp := range tm.threatLastHit {
		if !timestamp.Before(cutoff) {
			continue
		}
		if freezeConntrack && !strings.HasPrefix(key, hostThreatThrottlePrefix) {
			continue
		}
		if instanceUUID, ok := instanceThreatThrottleOwner(key); ok {
			if _, frozen := frozenInstances[instanceUUID]; frozen {
				continue
			}
		}
		delete(tm.threatLastHit, key)
	}
	tm.threatLastHitMu.Unlock()
}
