package main

import (
	"fmt"
	"testing"
	"time"
)

func TestCleanupBehaviorMapsRemovesInactiveExpiredAndOrphanedEntries(t *testing.T) {
	cm := newBehaviorStateTestManager()
	now := time.Now().Unix()
	activeKey := BehaviorKey{InstanceUUID: "active", IP: IPStrToKey("192.0.2.1")}
	expiredKey := BehaviorKey{InstanceUUID: "active", IP: IPStrToKey("192.0.2.2")}
	inactiveKey := BehaviorKey{InstanceUUID: "inactive", IP: IPStrToKey("192.0.2.3")}
	missingSeenKey := BehaviorKey{InstanceUUID: "active", IP: IPStrToKey("192.0.2.4")}
	orphanFreshKey := BehaviorKey{InstanceUUID: "active", IP: IPStrToKey("192.0.2.5")}
	orphanExpiredKey := BehaviorKey{InstanceUUID: "active", IP: IPStrToKey("192.0.2.6")}

	populate := func(prevR map[BehaviorKey]outboundPrev, prevP map[BehaviorKey]outboundPrevDstPorts, seen map[BehaviorKey]int64) {
		for _, key := range []BehaviorKey{activeKey, expiredKey, inactiveKey, missingSeenKey} {
			prevR[key] = outboundPrev{remotes: map[IPKey]struct{}{IPStrToKey("198.51.100.1"): {}}}
			prevP[key] = outboundPrevDstPorts{ports: map[uint16]struct{}{443: {}}}
		}
		seen[activeKey] = now
		seen[expiredKey] = now - behaviorPrevKeyTTLSeconds - 1
		seen[inactiveKey] = now
		prevP[orphanFreshKey] = outboundPrevDstPorts{ports: map[uint16]struct{}{80: {}}}
		seen[orphanFreshKey] = now
		prevP[orphanExpiredKey] = outboundPrevDstPorts{ports: map[uint16]struct{}{81: {}}}
		seen[orphanExpiredKey] = now - behaviorPrevKeyTTLSeconds - 1
	}

	idx := 0
	populate(cm.outboundPrev[idx], cm.outboundPrevDstPorts[idx], cm.outboundPrevLastSeen[idx])
	populate(cm.inboundPrev[idx], cm.inboundPrevDstPorts[idx], cm.inboundPrevLastSeen[idx])
	cm.cleanupBehaviorMaps(map[string]struct{}{"active": {}})

	check := func(name string, prevR map[BehaviorKey]outboundPrev, prevP map[BehaviorKey]outboundPrevDstPorts, seen map[BehaviorKey]int64) {
		t.Helper()
		if _, ok := prevR[activeKey]; !ok {
			t.Fatalf("%s active remote state was removed", name)
		}
		if _, ok := prevP[activeKey]; !ok {
			t.Fatalf("%s active port state was removed", name)
		}
		for _, key := range []BehaviorKey{expiredKey, inactiveKey, missingSeenKey} {
			if _, ok := prevR[key]; ok {
				t.Fatalf("%s stale remote state retained for %#v", name, key)
			}
			if _, ok := prevP[key]; ok {
				t.Fatalf("%s stale port state retained for %#v", name, key)
			}
		}
		if _, ok := prevP[orphanFreshKey]; !ok {
			t.Fatalf("%s fresh orphan port state was removed before its TTL", name)
		}
		if _, ok := prevP[orphanExpiredKey]; ok {
			t.Fatalf("%s expired orphan port state was retained", name)
		}
		if _, ok := seen[activeKey]; !ok {
			t.Fatalf("%s active last-seen state was removed", name)
		}
	}
	check("outbound", cm.outboundPrev[idx], cm.outboundPrevDstPorts[idx], cm.outboundPrevLastSeen[idx])
	check("inbound", cm.inboundPrev[idx], cm.inboundPrevDstPorts[idx], cm.inboundPrevLastSeen[idx])
}

func TestCleanupBehaviorStateCoversAllStateFamilies(t *testing.T) {
	cm := newBehaviorStateTestManager()
	now := time.Now().Unix()
	activeIP := IPStrToKey("192.0.2.10")
	staleIP := IPStrToKey("192.0.2.11")
	inactiveIP := IPStrToKey("192.0.2.12")
	activeIdent := behaviorIdentityKey{InstanceUUID: "active", IP: activeIP, Direction: "outbound"}
	staleIdent := behaviorIdentityKey{InstanceUUID: "active", IP: staleIP, Direction: "outbound"}
	inactiveIdent := behaviorIdentityKey{InstanceUUID: "inactive", IP: inactiveIP, Direction: "inbound"}
	orphanSeverity := behaviorIdentityKey{InstanceUUID: "inactive", IP: IPStrToKey("192.0.2.13"), Direction: "outbound"}

	for ident, lastSeen := range map[behaviorIdentityKey]int64{
		activeIdent:   now,
		staleIdent:    now - behaviorIdentityTTLSeconds - 1,
		inactiveIdent: now,
	} {
		idx := shardIndexBehavior(ident)
		cm.behaviorEWMA[idx][ident] = &behaviorEWMAState{LastSeenUnix: lastSeen}
		cm.behaviorLastSeverity[idx][ident] = 0.5
	}
	orphanIdx := shardIndexBehavior(orphanSeverity)
	cm.behaviorLastSeverity[orphanIdx][orphanSeverity] = 0.9

	activeKey := BehaviorKey{InstanceUUID: "active", IP: activeIP}
	staleKey := BehaviorKey{InstanceUUID: "active", IP: staleIP}
	inactiveKey := BehaviorKey{InstanceUUID: "inactive", IP: inactiveIP}
	for _, direction := range []string{"outbound", "inbound"} {
		ident := behaviorIdentityKey{InstanceUUID: "active", IP: activeIP, Direction: direction}
		idx := shardIndexBehavior(ident)
		var prevR map[BehaviorKey]outboundPrev
		var prevP map[BehaviorKey]outboundPrevDstPorts
		var seen map[BehaviorKey]int64
		if direction == "outbound" {
			prevR, prevP, seen = cm.outboundPrev[idx], cm.outboundPrevDstPorts[idx], cm.outboundPrevLastSeen[idx]
		} else {
			prevR, prevP, seen = cm.inboundPrev[idx], cm.inboundPrevDstPorts[idx], cm.inboundPrevLastSeen[idx]
		}
		for _, key := range []BehaviorKey{activeKey, staleKey, inactiveKey} {
			prevR[key] = outboundPrev{}
			prevP[key] = outboundPrevDstPorts{}
		}
		seen[activeKey] = now
		seen[staleKey] = now - behaviorPrevKeyTTLSeconds - 1
		seen[inactiveKey] = now
	}

	activeAlert := behaviorAlertKey{InstanceUUID: "active", IP: activeIP, Direction: "outbound", Kind: "scan"}
	staleAlert := behaviorAlertKey{InstanceUUID: "active", IP: staleIP, Direction: "outbound", Kind: "scan"}
	inactiveAlert := behaviorAlertKey{InstanceUUID: "inactive", IP: inactiveIP, Direction: "outbound", Kind: "scan"}
	cm.behaviorPersist[activeAlert] = &behaviorPersistState{LastSeenUnix: now}
	cm.behaviorPersist[staleAlert] = &behaviorPersistState{LastSeenUnix: now - 3601}
	cm.behaviorPersist[inactiveAlert] = &behaviorPersistState{LastSeenUnix: now}
	activeEmit := behaviorEmitKey{InstanceUUID: "active", IP: activeIP, Direction: "outbound"}
	staleEmit := behaviorEmitKey{InstanceUUID: "active", IP: staleIP, Direction: "outbound"}
	inactiveEmit := behaviorEmitKey{InstanceUUID: "inactive", IP: inactiveIP, Direction: "outbound"}
	cm.behaviorEmit[activeEmit] = &behaviorEmitState{LastEmitUnix: now}
	cm.behaviorEmit[staleEmit] = &behaviorEmitState{LastEmitUnix: now - behaviorPrevKeyTTLSeconds - 1}
	cm.behaviorEmit[inactiveEmit] = &behaviorEmitState{LastEmitUnix: now}
	cm.miningAlerts[activeIdent] = &miningAlertState{LastSeenUnix: now, Confirmed: true, Active: true}
	cm.miningAlerts[staleIdent] = &miningAlertState{LastSeenUnix: now - behaviorIdentityTTLSeconds - 1, Confirmed: true, Active: true}
	cm.miningAlerts[inactiveIdent] = &miningAlertState{LastSeenUnix: now, Confirmed: true, Active: true}

	cm.cleanupBehaviorState(map[string]struct{}{"active": {}})

	activeIdx := shardIndexBehavior(activeIdent)
	if _, ok := cm.behaviorEWMA[activeIdx][activeIdent]; !ok {
		t.Fatal("active EWMA state was removed")
	}
	if _, ok := cm.behaviorLastSeverity[activeIdx][activeIdent]; !ok {
		t.Fatal("active last severity was removed")
	}
	for _, ident := range []behaviorIdentityKey{staleIdent, inactiveIdent, orphanSeverity} {
		idx := shardIndexBehavior(ident)
		if _, ok := cm.behaviorEWMA[idx][ident]; ok {
			t.Fatalf("stale EWMA state retained for %#v", ident)
		}
		if _, ok := cm.behaviorLastSeverity[idx][ident]; ok {
			t.Fatalf("stale severity state retained for %#v", ident)
		}
	}
	if len(cm.behaviorPersist) != 1 || cm.behaviorPersist[activeAlert] == nil {
		t.Fatalf("persistence cleanup result=%v, want only active state", cm.behaviorPersist)
	}
	if len(cm.behaviorEmit) != 1 || cm.behaviorEmit[activeEmit] == nil {
		t.Fatalf("emit cleanup result=%v, want only active state", cm.behaviorEmit)
	}
	if len(cm.miningAlerts) != 1 || cm.miningAlerts[activeIdent] == nil {
		t.Fatalf("mining-alert cleanup result=%v, want only active state", cm.miningAlerts)
	}
}

func TestBehaviorEmitStateSurvivesUntilHeartbeatWindow(t *testing.T) {
	cm := newBehaviorStateTestManager()
	now := time.Now().Unix()
	key := behaviorEmitKey{
		InstanceUUID: "active",
		IP:           IPStrToKey("192.0.2.30"),
		Direction:    "outbound",
	}
	cm.behaviorEmit[key] = &behaviorEmitState{
		LastKind:     "outbound_stratum_mining_suspected",
		LastPriority: "P2",
		LastEmitUnix: now - behaviorAlertHeartbeatSeconds + 1,
	}

	cm.cleanupBehaviorState(map[string]struct{}{"active": {}})

	if _, ok := cm.behaviorEmit[key]; !ok {
		t.Fatal("behavior emit state was removed before its configured heartbeat window")
	}
}

func TestBehaviorEmitStateSurvivesCleanupLongEnoughToEmitHeartbeat(t *testing.T) {
	cm := newBehaviorStateTestManager()
	now := time.Now().Unix()
	key := behaviorEmitKey{
		InstanceUUID: "active",
		IP:           IPStrToKey("192.0.2.31"),
		Direction:    "outbound",
	}
	cm.behaviorEmit[key] = &behaviorEmitState{
		LastKind:         "outbound_single_remote_flood",
		LastPriority:     "P1",
		LastSeverityBand: "critical",
		LastTopRemote:    "198.51.100.20",
		LastTopDstPort:   443,
		LastEmitUnix:     now - behaviorAlertHeartbeatSeconds - 15,
	}

	cm.cleanupBehaviorState(map[string]struct{}{"active": {}})
	emission := cm.behaviorEmit[key]
	if emission == nil {
		t.Fatal("cleanup removed emission context before the next post-heartbeat evaluation")
	}

	transition := evaluateBehaviorAlertTransition(behaviorAlertTransitionInput{
		NowUnix: now,
		Kind:    "outbound_single_remote_flood",
		Feature: BehaviorFeature{
			Direction:         "outbound",
			Flows:             1000,
			UniqueRemotes:     1,
			MaxSingleRemote:   1000,
			UniqueDstPorts:    1,
			MaxSingleDstPort:  1000,
			TopDstPort:        443,
			UnrepliedRatio:    1,
			HostImpactPercent: 10,
		},
		Evidence: behaviorAlertEvidence{
			TopRemoteIP:    "198.51.100.20",
			TopDstPort:     443,
			TopRemoteShare: 1,
			TopPortShare:   1,
			EvidenceMode:   "dominant_remote",
		},
		Persistence: behaviorPersistState{Hits: 3, FirstSeenUnix: now - 900, LastSeenUnix: now - 15},
		Emission:    *emission,
	})
	if !transition.ShouldEmit || transition.EmitReason != "heartbeat" {
		t.Fatalf("post-cleanup transition=%+v, want heartbeat with prior context", transition)
	}
}

func TestBehaviorRuleLogStateThrottlingAndEviction(t *testing.T) {
	behaviorRuleLogMu.Lock()
	oldMap := behaviorRuleLogStateMap
	oldSeed := behaviorRuleLogEvictSeed
	behaviorRuleLogStateMap = make(map[behaviorEmitKey]*behaviorRuleLogState)
	behaviorRuleLogEvictSeed = 1
	behaviorRuleLogMu.Unlock()
	t.Cleanup(func() {
		behaviorRuleLogMu.Lock()
		behaviorRuleLogStateMap = oldMap
		behaviorRuleLogEvictSeed = oldSeed
		behaviorRuleLogMu.Unlock()
	})

	key := behaviorEmitKey{InstanceUUID: "vm-1", IP: IPStrToKey("192.0.2.20"), Direction: "outbound"}
	behaviorRuleLogMu.Lock()
	first := ensureRuleLogStateLocked(key)
	second := ensureRuleLogStateLocked(key)
	behaviorRuleLogMu.Unlock()
	if first != second {
		t.Fatal("ensureRuleLogStateLocked replaced existing state")
	}
	if !ruleLogStateMarkSuppressed(key, 100) || ruleLogStateMarkSuppressed(key, 159) || !ruleLogStateMarkSuppressed(key, 160) {
		t.Fatal("suppressed-log throttle boundary is incorrect")
	}
	if !ruleLogStateMarkSummary(key, 100) || ruleLogStateMarkSummary(key, 159) || !ruleLogStateMarkSummary(key, 160) {
		t.Fatal("summary-log throttle boundary is incorrect")
	}

	behaviorRuleLogMu.Lock()
	for i := 0; i < 2000; i++ {
		k := behaviorEmitKey{InstanceUUID: fmt.Sprintf("vm-%d", i), Direction: "inbound"}
		behaviorRuleLogStateMap[k] = &behaviorRuleLogState{}
	}
	before := len(behaviorRuleLogStateMap)
	if got := evictBehaviorRuleLogStateLocked(before); got != 0 {
		behaviorRuleLogMu.Unlock()
		t.Fatalf("eviction below maximum removed %d entries", got)
	}
	removed := evictBehaviorRuleLogStateLocked(0)
	after := len(behaviorRuleLogStateMap)
	behaviorRuleLogMu.Unlock()
	if removed != 1000 || after != before-1000 {
		t.Fatalf("eviction removed=%d size=%d, want removed=1000 size=%d", removed, after, before-1000)
	}
}

func TestBehaviorHostImpactFlowFallback(t *testing.T) {
	if got := behaviorHostImpactFlowTotal(BehaviorContext{InstanceFlowTotal: 12}, 3); got != 12 {
		t.Fatalf("host impact flow total=%d, want instance total", got)
	}
	if got := behaviorHostImpactFlowTotal(BehaviorContext{}, 3); got != 3 {
		t.Fatalf("host impact fallback=%d, want 3", got)
	}
}

func TestBehaviorRemoteMapSaturationReplacesMinimumEvidence(t *testing.T) {
	stats := newBehaviorStats(false)
	var victim IPKey
	for i := 0; i < maxRemoteMapSize; i++ {
		key := IPKey{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, byte(i >> 16), byte(i >> 8), byte(i), 1}
		stats.remotes[key] = struct{}{}
		stats.remoteZones[key] = 1
		stats.remoteIsPrivate[key] = false
		stats.perRemote[key] = 2
		if i == 0 {
			victim = key
			stats.perRemote[key] = 1
		}
	}
	newRemote := IPStrToKey("10.1.2.3")
	stats.updateRemoteDetailed(newRemote, 42, true)
	if !stats.remoteMapCapped || len(stats.remotes) != maxRemoteMapSize {
		t.Fatalf("saturated remote map capped=%v size=%d", stats.remoteMapCapped, len(stats.remotes))
	}
	if _, ok := stats.remotes[victim]; ok {
		t.Fatal("minimum-evidence remote was not evicted")
	}
	if stats.perRemote[newRemote] != 2 || stats.perRemoteUnreplied[newRemote] != 1 || stats.remoteZones[newRemote] != 42 || !stats.remoteIsPrivate[newRemote] {
		t.Fatalf("replacement remote state count=%d unreplied=%d zone=%d private=%v", stats.perRemote[newRemote], stats.perRemoteUnreplied[newRemote], stats.remoteZones[newRemote], stats.remoteIsPrivate[newRemote])
	}

	inconsistent := newBehaviorStats(false)
	for i := 0; i < maxRemoteMapSize; i++ {
		key := IPKey{byte(i >> 8), byte(i)}
		inconsistent.remotes[key] = struct{}{}
	}
	inconsistent.updateRemoteDetailed(IPStrToKey("192.0.2.1"), 1, false)
	if !inconsistent.remoteMapCapped || len(inconsistent.remotes) != maxRemoteMapSize {
		t.Fatal("empty victim-count map changed saturated remote membership")
	}
}

func TestBehaviorSetAndSaturationEdgeHelpers(t *testing.T) {
	if got := cloneIPKeySet(nil); got == nil || len(got) != 0 {
		t.Fatalf("nil IP set clone=%v, want independent empty map", got)
	}
	if got, saturated := saturatingCount(5, 0); got != 5 || saturated {
		t.Fatalf("disabled saturation=(%d,%v)", got, saturated)
	}
}
