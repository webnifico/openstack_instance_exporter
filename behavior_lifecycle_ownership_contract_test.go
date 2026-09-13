package main

import (
	"testing"
	"time"

	libvirt "github.com/digitalocean/go-libvirt"
)

type behaviorMiningBehaviorLifecycleSeed struct {
	instanceUUID string
	ip           IPKey
	behaviorKey  BehaviorKey
	outbound     behaviorIdentityKey
	inbound      behaviorIdentityKey
	alert        behaviorAlertKey
	emit         behaviorEmitKey
	ewma         *behaviorEWMAState
	persist      *behaviorPersistState
	emission     *behaviorEmitState
	mining       *miningAlertState
	ruleLog      *behaviorRuleLogState
}

func behaviorMiningIsolateBehaviorRuleLogState(t *testing.T) {
	t.Helper()
	behaviorRuleLogMu.Lock()
	previous := behaviorRuleLogStateMap
	behaviorRuleLogStateMap = make(map[behaviorEmitKey]*behaviorRuleLogState)
	behaviorRuleLogMu.Unlock()
	t.Cleanup(func() {
		behaviorRuleLogMu.Lock()
		behaviorRuleLogStateMap = previous
		behaviorRuleLogMu.Unlock()
	})
}

func behaviorMiningSeedBehaviorLifecycleState(cm *ConntrackManager, instanceUUID, address string, timestamp int64) behaviorMiningBehaviorLifecycleSeed {
	ip := IPStrToKey(address)
	seed := behaviorMiningBehaviorLifecycleSeed{
		instanceUUID: instanceUUID,
		ip:           ip,
		behaviorKey:  BehaviorKey{InstanceUUID: instanceUUID, IP: ip},
		outbound:     behaviorIdentityKey{InstanceUUID: instanceUUID, IP: ip, Direction: "outbound"},
		inbound:      behaviorIdentityKey{InstanceUUID: instanceUUID, IP: ip, Direction: "inbound"},
		alert:        behaviorAlertKey{InstanceUUID: instanceUUID, IP: ip, Direction: "outbound", Kind: "scan"},
		emit:         behaviorEmitKey{InstanceUUID: instanceUUID, IP: ip, Direction: "outbound"},
		ewma:         &behaviorEWMAState{LastSeenUnix: timestamp},
		persist:      &behaviorPersistState{Hits: 2, FirstSeenUnix: timestamp, LastSeenUnix: timestamp},
		emission:     &behaviorEmitState{LastKind: "scan", LastEpisodeStartUnix: timestamp, LastEmitUnix: timestamp},
		mining: &miningAlertState{
			Hits: 2, FirstSeenUnix: timestamp, LastSeenUnix: timestamp, LastRecoveryObservationUnix: timestamp,
			LastEpisodeStartUnix: timestamp, LastEmitUnix: timestamp,
			Confirmed: true, Active: true,
		},
		ruleLog: &behaviorRuleLogState{LastSuppressedUnix: timestamp, LastSummaryUnix: timestamp},
	}

	outboundShard := shardIndexBehavior(seed.outbound)
	cm.outboundPrev[outboundShard][seed.behaviorKey] = outboundPrev{remotes: map[IPKey]struct{}{IPStrToKey("198.51.100.10"): {}}}
	cm.outboundPrevDstPorts[outboundShard][seed.behaviorKey] = outboundPrevDstPorts{ports: map[uint16]struct{}{443: {}}}
	cm.outboundPrevLastSeen[outboundShard][seed.behaviorKey] = timestamp
	cm.behaviorEWMA[outboundShard][seed.outbound] = seed.ewma
	cm.behaviorLastSeverity[outboundShard][seed.outbound] = 0.8

	inboundShard := shardIndexBehavior(seed.inbound)
	cm.inboundPrev[inboundShard][seed.behaviorKey] = outboundPrev{remotes: map[IPKey]struct{}{IPStrToKey("203.0.113.10"): {}}}
	cm.inboundPrevDstPorts[inboundShard][seed.behaviorKey] = outboundPrevDstPorts{ports: map[uint16]struct{}{22: {}}}
	cm.inboundPrevLastSeen[inboundShard][seed.behaviorKey] = timestamp
	cm.behaviorEWMA[inboundShard][seed.inbound] = &behaviorEWMAState{LastSeenUnix: timestamp}
	cm.behaviorLastSeverity[inboundShard][seed.inbound] = 0.4

	cm.behaviorPersist[seed.alert] = seed.persist
	cm.behaviorEmit[seed.emit] = seed.emission
	cm.miningAlerts[seed.outbound] = seed.mining
	behaviorRuleLogMu.Lock()
	behaviorRuleLogStateMap[seed.emit] = seed.ruleLog
	behaviorRuleLogMu.Unlock()
	return seed
}

func behaviorMiningAssertBehaviorSeedPresent(t *testing.T, cm *ConntrackManager, seed behaviorMiningBehaviorLifecycleSeed, want bool) {
	t.Helper()
	outboundShard := shardIndexBehavior(seed.outbound)
	inboundShard := shardIndexBehavior(seed.inbound)
	checks := []struct {
		name string
		got  bool
	}{
		{"outbound previous remotes", mapHasBehaviorKey(cm.outboundPrev[outboundShard], seed.behaviorKey)},
		{"outbound previous ports", mapHasBehaviorPortKey(cm.outboundPrevDstPorts[outboundShard], seed.behaviorKey)},
		{"outbound previous timestamp", mapHasBehaviorTimestampKey(cm.outboundPrevLastSeen[outboundShard], seed.behaviorKey)},
		{"inbound previous remotes", mapHasBehaviorKey(cm.inboundPrev[inboundShard], seed.behaviorKey)},
		{"inbound previous ports", mapHasBehaviorPortKey(cm.inboundPrevDstPorts[inboundShard], seed.behaviorKey)},
		{"inbound previous timestamp", mapHasBehaviorTimestampKey(cm.inboundPrevLastSeen[inboundShard], seed.behaviorKey)},
	}
	_, outboundEWMA := cm.behaviorEWMA[outboundShard][seed.outbound]
	_, inboundEWMA := cm.behaviorEWMA[inboundShard][seed.inbound]
	_, outboundSeverity := cm.behaviorLastSeverity[outboundShard][seed.outbound]
	_, inboundSeverity := cm.behaviorLastSeverity[inboundShard][seed.inbound]
	_, persistence := cm.behaviorPersist[seed.alert]
	_, emission := cm.behaviorEmit[seed.emit]
	_, mining := cm.miningAlerts[seed.outbound]
	checks = append(checks,
		struct {
			name string
			got  bool
		}{"outbound EWMA", outboundEWMA},
		struct {
			name string
			got  bool
		}{"inbound EWMA", inboundEWMA},
		struct {
			name string
			got  bool
		}{"outbound severity", outboundSeverity},
		struct {
			name string
			got  bool
		}{"inbound severity", inboundSeverity},
		struct {
			name string
			got  bool
		}{"persistence", persistence},
		struct {
			name string
			got  bool
		}{"emission", emission},
		struct {
			name string
			got  bool
		}{"mining", mining},
	)
	behaviorRuleLogMu.Lock()
	_, ruleLog := behaviorRuleLogStateMap[seed.emit]
	behaviorRuleLogMu.Unlock()
	checks = append(checks, struct {
		name string
		got  bool
	}{"rule log", ruleLog})
	for _, check := range checks {
		if check.got != want {
			t.Errorf("%s presence=%v, want %v for %s/%s", check.name, check.got, want, seed.instanceUUID, IPKeyToString(seed.ip))
		}
	}
}

func mapHasBehaviorKey(values map[BehaviorKey]outboundPrev, key BehaviorKey) bool {
	_, ok := values[key]
	return ok
}

func mapHasBehaviorPortKey(values map[BehaviorKey]outboundPrevDstPorts, key BehaviorKey) bool {
	_, ok := values[key]
	return ok
}

func mapHasBehaviorTimestampKey(values map[BehaviorKey]int64, key BehaviorKey) bool {
	_, ok := values[key]
	return ok
}

func behaviorMiningAssertBehaviorSeedTimestamp(t *testing.T, cm *ConntrackManager, seed behaviorMiningBehaviorLifecycleSeed, want int64) {
	t.Helper()
	outboundShard := shardIndexBehavior(seed.outbound)
	inboundShard := shardIndexBehavior(seed.inbound)
	values := map[string]int64{
		"outbound previous": cm.outboundPrevLastSeen[outboundShard][seed.behaviorKey],
		"inbound previous":  cm.inboundPrevLastSeen[inboundShard][seed.behaviorKey],
		"EWMA":              seed.ewma.LastSeenUnix,
		"persist first":     seed.persist.FirstSeenUnix,
		"persist last":      seed.persist.LastSeenUnix,
		"episode":           seed.emission.LastEpisodeStartUnix,
		"emit":              seed.emission.LastEmitUnix,
		"mining first":      seed.mining.FirstSeenUnix,
		"mining last":       seed.mining.LastSeenUnix,
		"mining recovery":   seed.mining.LastRecoveryObservationUnix,
		"mining episode":    seed.mining.LastEpisodeStartUnix,
		"mining emit":       seed.mining.LastEmitUnix,
	}
	behaviorRuleLogMu.Lock()
	values["rule suppress"] = seed.ruleLog.LastSuppressedUnix
	values["rule summary"] = seed.ruleLog.LastSummaryUnix
	behaviorRuleLogMu.Unlock()
	for name, got := range values {
		if got != want {
			t.Errorf("%s timestamp=%d, want %d", name, got, want)
		}
	}
}

func TestBehaviorMiningBehaviorLifecycleResetClearsEveryOwnedState(t *testing.T) {
	behaviorMiningIsolateBehaviorRuleLogState(t)
	cm := newBehaviorStateTestManager()
	target := behaviorMiningSeedBehaviorLifecycleState(cm, "vm-reset", "192.0.2.10", 10)
	survivor := behaviorMiningSeedBehaviorLifecycleState(cm, "vm-survivor", "192.0.2.20", 20)
	cm.behaviorLifecycleFreeze = map[string]*behaviorLifecycleFreezeState{
		target.instanceUUID:   {FreezeStartUnix: 30, Frozen: true},
		survivor.instanceUUID: {FreezeStartUnix: 40, Frozen: true},
	}

	cm.resetBehaviorStateForInstance(target.instanceUUID)

	behaviorMiningAssertBehaviorSeedPresent(t, cm, target, false)
	behaviorMiningAssertBehaviorSeedPresent(t, cm, survivor, true)
	if _, exists := cm.behaviorLifecycleFreeze[target.instanceUUID]; exists {
		t.Fatal("reset retained target lifecycle freeze")
	}
	if _, exists := cm.behaviorLifecycleFreeze[survivor.instanceUUID]; !exists {
		t.Fatal("reset removed survivor lifecycle freeze")
	}
}

func TestBehaviorMiningAuthoritativeInventoryPrunesExactUUIDIPOwnership(t *testing.T) {
	behaviorMiningIsolateBehaviorRuleLogState(t)
	cm := newBehaviorStateTestManager()
	retained := behaviorMiningSeedBehaviorLifecycleState(cm, "vm-active", "192.0.2.30", 10)
	detached := behaviorMiningSeedBehaviorLifecycleState(cm, "vm-active", "192.0.2.31", 20)
	deleted := behaviorMiningSeedBehaviorLifecycleState(cm, "vm-deleted", "192.0.2.32", 30)
	cm.behaviorLifecycleFreeze = map[string]*behaviorLifecycleFreezeState{
		"vm-active":  {FreezeStartUnix: 40, Frozen: true},
		"vm-deleted": {FreezeStartUnix: 40, Frozen: true},
	}

	activeSet := map[string]struct{}{"vm-active": {}}
	cm.pruneBehaviorStateToVMIPIdentities(activeSet, []VMIPIdentity{{InstanceUUID: "vm-active", IP: retained.ip}})

	behaviorMiningAssertBehaviorSeedPresent(t, cm, retained, true)
	behaviorMiningAssertBehaviorSeedPresent(t, cm, detached, false)
	behaviorMiningAssertBehaviorSeedPresent(t, cm, deleted, false)
	if _, exists := cm.behaviorLifecycleFreeze["vm-active"]; !exists {
		t.Fatal("exact IP prune removed active instance lifecycle freeze")
	}
	if _, exists := cm.behaviorLifecycleFreeze["vm-deleted"]; exists {
		t.Fatal("authoritative inventory retained deleted instance lifecycle freeze")
	}
}

func TestBehaviorMiningMissingStateFreezesOnlyAffectedInstanceAndRecoversOnce(t *testing.T) {
	behaviorMiningIsolateBehaviorRuleLogState(t)
	cm := newBehaviorStateTestManager()
	target := behaviorMiningSeedBehaviorLifecycleState(cm, "vm-missing-state", "192.0.2.40", 10)
	survivor := behaviorMiningSeedBehaviorLifecycleState(cm, "vm-running", "192.0.2.41", 20)

	if cm.observeBehaviorInstanceLifecycle(target.instanceUUID, false, false, time.Unix(100, 0)) {
		t.Fatal("missing state reported a recovery")
	}
	cm.observeBehaviorInstanceLifecycle(target.instanceUUID, false, false, time.Unix(140, 0))
	behaviorMiningAssertBehaviorSeedTimestamp(t, cm, target, 10)
	behaviorMiningAssertBehaviorSeedTimestamp(t, cm, survivor, 20)
	if !cm.behaviorInstanceStateFrozen(target.instanceUUID) || cm.behaviorInstanceStateFrozen(survivor.instanceUUID) {
		t.Fatal("missing-state freeze was not scoped to exactly one instance")
	}

	if !cm.observeBehaviorInstanceLifecycle(target.instanceUUID, true, true, time.Unix(160, 0)) {
		t.Fatal("first known-running observation was not marked for silent recovery")
	}
	behaviorMiningAssertBehaviorSeedTimestamp(t, cm, target, 70)
	behaviorMiningAssertBehaviorSeedTimestamp(t, cm, survivor, 20)
	if !cm.behaviorInstanceNeedsRecoveryRebaseline(target.instanceUUID) {
		t.Fatal("per-instance recovery marker was not visible to behavior analysis")
	}
	cm.finishBehaviorInstanceRecovery(target.instanceUUID)
	if cm.behaviorInstanceNeedsRecoveryRebaseline(target.instanceUUID) {
		t.Fatal("per-instance recovery marker survived the complete recovery observation")
	}
}

func TestBehaviorMiningLifecycleRecoveryUsesCompleteSnapshotTimestamp(t *testing.T) {
	fallback := time.Unix(999, 0)
	if got := conntrackObservationTime(&ConntrackAgg{ObservationUnix: 160}, fallback); got.Unix() != 160 {
		t.Fatalf("complete snapshot time=%d, want 160", got.Unix())
	}
	for name, aggregate := range map[string]*ConntrackAgg{
		"nil":     nil,
		"missing": {},
	} {
		t.Run(name, func(t *testing.T) {
			if got := conntrackObservationTime(aggregate, fallback); !got.Equal(fallback) {
				t.Fatalf("fallback time=%v, want %v", got, fallback)
			}
		})
	}
}

func TestBehaviorMiningFirstMissingStateCycleExemptsOnlyActiveInstanceFromTTL(t *testing.T) {
	behaviorMiningIsolateBehaviorRuleLogState(t)
	cm := newBehaviorStateTestManager()
	const instanceUUID = "12345678-1234-5678-9abc-def012345678"
	staleTimestamp := time.Now().Unix() - behaviorPrevKeyTTLSeconds - 60
	seed := behaviorMiningSeedBehaviorLifecycleState(cm, instanceUUID, "192.0.2.45", staleTimestamp)
	uuid := libvirt.UUID{0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78}
	records := []libvirt.DomainStatsRecord{{Dom: libvirt.Domain{UUID: uuid}}}

	// This is the production order: pre-mark from the authoritative record,
	// then run cleanup before the domain worker observes that record again.
	cm.beginBehaviorLifecycleFreezesForMissingStates(records, time.Now())
	activeSet := map[string]struct{}{instanceUUID: {}}
	cm.cleanupBehaviorMapsWithAging(activeSet, false)
	cm.cleanupBehaviorStateWithAging(activeSet, false)
	behaviorMiningAssertBehaviorSeedPresent(t, cm, seed, true)

	// A freeze pauses time-based expiry only. Authoritative deletion always
	// wins, even during the same missing-state outage.
	cm.pruneBehaviorStateToVMIPIdentities(map[string]struct{}{}, nil)
	behaviorMiningAssertBehaviorSeedPresent(t, cm, seed, false)
}

func TestBehaviorMiningPerInstanceAndGlobalOutageClocksShiftTheirUnion(t *testing.T) {
	behaviorMiningIsolateBehaviorRuleLogState(t)
	cm := newBehaviorStateTestManager()
	target := behaviorMiningSeedBehaviorLifecycleState(cm, "vm-overlap", "192.0.2.50", 10)
	survivor := behaviorMiningSeedBehaviorLifecycleState(cm, "vm-global-only", "192.0.2.51", 20)

	cm.observeBehaviorInstanceLifecycle(target.instanceUUID, false, false, time.Unix(50, 0))
	cm.beginBehaviorStateFreeze(time.Unix(100, 0))
	if delta := cm.resumeBehaviorStateClockAt(130); delta != 30 {
		t.Fatalf("global recovery delta=%d, want 30", delta)
	}
	behaviorMiningAssertBehaviorSeedTimestamp(t, cm, target, 90)
	behaviorMiningAssertBehaviorSeedTimestamp(t, cm, survivor, 50)
	if !cm.behaviorInstanceStateFrozen(target.instanceUUID) {
		t.Fatal("global recovery incorrectly ended the still-missing per-instance freeze")
	}

	if !cm.observeBehaviorInstanceLifecycle(target.instanceUUID, true, true, time.Unix(145, 0)) {
		t.Fatal("per-instance suffix recovery was not marked for rebaseline")
	}
	// Target excludes [50,145] once: +95. Survivor excludes only [100,130]: +30.
	behaviorMiningAssertBehaviorSeedTimestamp(t, cm, target, 105)
	behaviorMiningAssertBehaviorSeedTimestamp(t, cm, survivor, 50)
}

func TestBehaviorMiningKnownPausedStateClearsBehaviorLifecycleInCollection(t *testing.T) {
	behaviorMiningIsolateBehaviorRuleLogState(t)
	mc := newCollectorOrchestrationTestCollector(t)
	const instanceUUID = "12345678-1234-5678-9abc-def012345678"
	seed := behaviorMiningSeedBehaviorLifecycleState(mc.cm, instanceUUID, "192.0.2.60", 10)
	mc.cm.behaviorLifecycleFreeze[instanceUUID] = &behaviorLifecycleFreezeState{FreezeStartUnix: 20, Frozen: true}
	meta := &DomainStatic{Name: "server", InstanceUUID: instanceUUID, FixedIPs: []IP{{Address: "192.0.2.60", Family: "ipv4"}}}
	uuid := libvirt.UUID{0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78}

	mc.collectDomainMetricsWithMetadata(
		libvirt.DomainStatsRecord{Dom: libvirt.Domain{Name: "domain", UUID: uuid, ID: 7}, Params: []libvirt.TypedParam{typedParam("state.state", int32(libvirt.DomainPaused))}},
		meta, nil, nil, &hostAgg{projects: make(map[string]struct{})}, 0, false, false,
	)

	behaviorMiningAssertBehaviorSeedPresent(t, mc.cm, seed, false)
	if mc.cm.behaviorInstanceStateFrozen(instanceUUID) {
		t.Fatal("known paused lifecycle boundary retained missing-state freeze")
	}
}

func TestBehaviorMiningKnownStoppedStateClearsBehaviorLifecycleInCollection(t *testing.T) {
	behaviorMiningIsolateBehaviorRuleLogState(t)
	mc := newCollectorOrchestrationTestCollector(t)
	const instanceUUID = "abcdefab-cdef-abcd-efab-cdefabcdefab"
	seed := behaviorMiningSeedBehaviorLifecycleState(mc.cm, instanceUUID, "192.0.2.61", 10)
	mc.cm.behaviorLifecycleFreeze[instanceUUID] = &behaviorLifecycleFreezeState{FreezeStartUnix: 20, Frozen: true}
	meta := &DomainStatic{Name: "server", InstanceUUID: instanceUUID, FixedIPs: []IP{{Address: "192.0.2.61", Family: "ipv4"}}}
	uuid := libvirt.UUID{0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab}

	mc.collectDomainMetricsWithMetadata(
		libvirt.DomainStatsRecord{Dom: libvirt.Domain{Name: "domain", UUID: uuid, ID: 7}, Params: []libvirt.TypedParam{typedParam("state.state", int32(libvirt.DomainShutoff))}},
		meta, nil, nil, &hostAgg{projects: make(map[string]struct{})}, 0, false, false,
	)

	behaviorMiningAssertBehaviorSeedPresent(t, mc.cm, seed, false)
	if mc.cm.behaviorInstanceStateFrozen(instanceUUID) {
		t.Fatal("known stopped lifecycle boundary retained missing-state freeze")
	}
}

func TestBehaviorMiningQEMUAndCPURollbackGenerationsClearBehaviorState(t *testing.T) {
	const instanceUUID = "00112233-4455-6677-8899-aabbccddeeff"
	uuid := libvirt.UUID{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

	t.Run("QEMU process token", func(t *testing.T) {
		behaviorMiningIsolateBehaviorRuleLogState(t)
		mc := newCollectorOrchestrationTestCollector(t)
		if mc.im.observeInstanceResourceGenerationWithToken(instanceUUID, 7, 100, true, "boot-a:7:100", true) {
			t.Fatal("initial process token reported a transition")
		}
		seed := behaviorMiningSeedBehaviorLifecycleState(mc.cm, instanceUUID, "192.0.2.70", 10)
		mc.applyPreparedRuntimeGenerations(
			[]libvirt.DomainStatsRecord{{Dom: libvirt.Domain{UUID: uuid, ID: 7}, Params: []libvirt.TypedParam{typedParam("cpu.time", uint64(200))}}},
			&preparedLibvirtCycle{runtimeTokens: map[string]string{instanceUUID: "boot-a:7:200"}},
		)
		behaviorMiningAssertBehaviorSeedPresent(t, mc.cm, seed, false)
	})

	t.Run("CPU lifetime rollback", func(t *testing.T) {
		behaviorMiningIsolateBehaviorRuleLogState(t)
		mc := newCollectorOrchestrationTestCollector(t)
		if mc.im.observeInstanceResourceGeneration(instanceUUID, 7, 200, true) {
			t.Fatal("initial CPU lifetime reported a transition")
		}
		seed := behaviorMiningSeedBehaviorLifecycleState(mc.cm, instanceUUID, "192.0.2.71", 10)
		mc.collectDomainMetricsWithMetadata(
			libvirt.DomainStatsRecord{
				Dom: libvirt.Domain{Name: "domain", UUID: uuid, ID: 7},
				Params: []libvirt.TypedParam{
					typedParam("state.state", int32(libvirt.DomainRunning)),
					typedParam("cpu.time", uint64(100)),
				},
			},
			&DomainStatic{Name: "server", InstanceUUID: instanceUUID, VCPUCount: 1, MemMB: 1024},
			nil, nil, &hostAgg{projects: make(map[string]struct{})}, 0, false, false,
		)
		behaviorMiningAssertBehaviorSeedPresent(t, mc.cm, seed, false)
	})
}

func TestBehaviorMiningMissingStateRetainsBehaviorAndConfirmedMiningObservability(t *testing.T) {
	behaviorMiningIsolateBehaviorRuleLogState(t)
	mc := newDataIntegrityRetainedSemanticsCollector(t)
	const (
		instanceUUID = "vm-missing-observability"
		vmIP         = "192.0.2.80"
	)
	vmKey := IPStrToKey(vmIP)
	ident := behaviorIdentityKey{InstanceUUID: instanceUUID, IP: vmKey, Direction: "outbound"}
	mc.cm.storeBehaviorSeverity(ident, 0.8)
	mc.cm.miningAlerts[ident] = &miningAlertState{
		Hits: 3, Confirmed: true, Active: true,
		Evidence: miningDetectionEvidence{
			Valid: true, Confidence: miningPortConfidenceHigh,
			miningTierSummary: miningTierSummary{Flows: 2, RepliedFlows: 2, UniqueRemotes: 1, UniquePorts: 1, TopPort: 10128, TopRemote: IPStrToKey("198.51.100.80")},
		},
		Priority: "P2",
	}
	outbound := newBehaviorStats(false)
	connAgg := &ConntrackAgg{
		VMIndex:            map[VMIPIdentity]uint32{{InstanceUUID: instanceUUID, IP: vmKey}: 0},
		InstanceFlowTotals: map[string]int{instanceUUID: 2},
		FlowsIn:            []int{0},
		FlowsOut:           []int{2},
		OutboundStats:      []*behaviorStats{outbound},
	}
	meta := dataIntegrityRetainedMeta(instanceUUID, vmIP)
	agg := &hostAgg{projects: make(map[string]struct{})}
	mc.collectDomainMetricsWithMetadata(
		libvirt.DomainStatsRecord{Dom: libvirt.Domain{Name: "domain"}},
		meta, connAgg, nil, agg, 100_000, true, true,
	)

	names := dataIntegrityRetainedMetricNames(agg.metrics)
	if _, ok := names["oie_instance_behavior_severity"]; !ok {
		t.Fatal("missing Libvirt state dropped retained behavior severity")
	}
	if _, ok := names["oie_instance_mining_suspected"]; !ok {
		t.Fatal("missing Libvirt state dropped confirmed mining observability")
	}
	if _, ok := names["oie_instance_attention_severity"]; ok {
		t.Fatal("missing Libvirt state reported attention severity as complete")
	}
	if !mc.cm.behaviorInstanceStateFrozen(instanceUUID) {
		t.Fatal("missing Libvirt state did not retain a per-instance freeze boundary")
	}
	if state := mc.cm.miningAlerts[ident]; state.Hits != 3 || !state.Active || !state.Confirmed {
		t.Fatalf("missing-state retained emission advanced or cleared mining state: %+v", state)
	}
}

func TestBehaviorMiningCleanRecoveryRebaselinesWithoutPromotingOrEmitting(t *testing.T) {
	behaviorMiningIsolateBehaviorRuleLogState(t)
	mc := newDataIntegrityRetainedSemanticsCollector(t)
	const (
		instanceUUID = "vm-clean-recovery"
		vmIP         = "192.0.2.90"
	)
	nowUnix := int64(100)
	mc.cm.conntrackNowOverride = func() time.Time { return time.Unix(nowUnix, 0) }
	seed := behaviorMiningSeedBehaviorLifecycleState(mc.cm, instanceUUID, vmIP, 10)
	meta := dataIntegrityRetainedMeta(instanceUUID, vmIP)
	connAgg := &ConntrackAgg{
		ObservationUnix:    nowUnix,
		VMIndex:            map[VMIPIdentity]uint32{{InstanceUUID: instanceUUID, IP: seed.ip}: 0},
		InstanceFlowTotals: map[string]int{instanceUUID: 0},
		FlowsIn:            []int{0},
		FlowsOut:           []int{0},
		OutboundStats:      []*behaviorStats{newBehaviorStats(false)},
	}

	mc.collectDomainMetricsWithMetadata(
		libvirt.DomainStatsRecord{Dom: libvirt.Domain{Name: "domain", ID: 7}},
		meta, connAgg, nil, &hostAgg{projects: make(map[string]struct{})}, 100_000, true, true,
	)
	behaviorMiningAssertBehaviorSeedTimestamp(t, mc.cm, seed, 10)
	if seed.persist.Hits != 2 || seed.mining.Hits != 2 || !seed.mining.Active || !seed.mining.Confirmed {
		t.Fatal("missing-state observation advanced or cleared alert state")
	}

	nowUnix = 999
	const recoveryObservationUnix int64 = 160
	connAgg.ObservationUnix = recoveryObservationUnix
	mc.collectDomainMetricsWithMetadata(
		libvirt.DomainStatsRecord{
			Dom:    libvirt.Domain{Name: "domain", ID: 7},
			Params: []libvirt.TypedParam{typedParam("state.state", int32(libvirt.DomainRunning))},
		},
		meta, connAgg, nil, &hostAgg{projects: make(map[string]struct{})}, 100_000, true, true,
	)

	if _, exists := mc.cm.behaviorPersist[seed.alert]; exists {
		t.Fatal("clean recovery retained the pre-outage generic candidate")
	}
	if seed.emission.LastEpisodeStartUnix != 70 || seed.emission.LastEmitUnix != 70 {
		t.Fatalf("clean recovery advanced emission state instead of only shifting its clock: %+v", seed.emission)
	}
	if seed.mining.Hits != 0 || seed.mining.FirstSeenUnix != 0 || seed.mining.LastSeenUnix != 0 ||
		seed.mining.LastRecoveryObservationUnix != 0 || seed.mining.Active || seed.mining.Confirmed {
		t.Fatalf("clean recovery promoted or retained mining candidate: %+v", seed.mining)
	}
	behaviorRuleLogMu.Lock()
	ruleLog := *seed.ruleLog
	behaviorRuleLogMu.Unlock()
	if ruleLog.LastSuppressedUnix != 70 || ruleLog.LastSummaryUnix != 70 {
		t.Fatalf("clean recovery emitted/suppressed a new rule log instead of only shifting its clock: %+v", ruleLog)
	}
	if got := mc.cm.behaviorEWMA[shardIndexBehavior(seed.outbound)][seed.outbound]; got == nil || got.LastSeenUnix != recoveryObservationUnix {
		t.Fatalf("clean recovery did not establish a fresh EWMA baseline: %+v", got)
	}
	if mc.cm.behaviorInstanceNeedsRecoveryRebaseline(instanceUUID) {
		t.Fatal("complete clean recovery retained its per-instance recovery marker")
	}
}
