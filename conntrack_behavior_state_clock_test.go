package main

import (
	"testing"
	"time"
)

func TestBehaviorStateClockExcludesRepeatedOutageTime(t *testing.T) {
	cm := newBehaviorStateTestManager()
	ip := IPStrToKey("192.0.2.70")
	ident := behaviorIdentityKey{InstanceUUID: "vm-clock", IP: ip, Direction: "outbound"}
	behaviorKey := BehaviorKey{InstanceUUID: ident.InstanceUUID, IP: ip}
	alertKey := behaviorAlertKey{InstanceUUID: ident.InstanceUUID, IP: ip, Direction: ident.Direction, Kind: "scan"}
	emitKey := behaviorEmitKey{InstanceUUID: ident.InstanceUUID, IP: ip, Direction: ident.Direction}
	shard := shardIndexBehavior(ident)

	cm.behaviorEWMA[shard][ident] = &behaviorEWMAState{LastSeenUnix: 90}
	cm.outboundPrevLastSeen[shard][behaviorKey] = 80
	cm.behaviorPersist[alertKey] = &behaviorPersistState{FirstSeenUnix: 70, LastSeenUnix: 90}
	cm.behaviorEmit[emitKey] = &behaviorEmitState{LastEpisodeStartUnix: 70, LastEmitUnix: 85}
	cm.miningAlerts[ident] = &miningAlertState{
		FirstSeenUnix: 65, LastSeenUnix: 90, LastRecoveryObservationUnix: 88,
		LastEpisodeStartUnix: 65, LastEmitUnix: 85,
	}

	cm.beginBehaviorStateFreeze(time.Unix(100, 0))
	cm.beginBehaviorStateFreeze(time.Unix(140, 0))
	if delta := cm.resumeBehaviorStateClockAt(160); delta != 60 {
		t.Fatalf("resumed delta=%d, want 60", delta)
	}

	if got := cm.behaviorEWMA[shard][ident].LastSeenUnix; got != 150 {
		t.Fatalf("EWMA last seen=%d, want 150", got)
	}
	if got := cm.outboundPrevLastSeen[shard][behaviorKey]; got != 140 {
		t.Fatalf("baseline last seen=%d, want 140", got)
	}
	if got := cm.behaviorPersist[alertKey]; got.FirstSeenUnix != 130 || got.LastSeenUnix != 150 {
		t.Fatalf("persistence clock=%+v, want first=130 last=150", got)
	}
	if got := cm.behaviorEmit[emitKey]; got.LastEpisodeStartUnix != 130 || got.LastEmitUnix != 145 {
		t.Fatalf("emission clock=%+v, want episode=130 emit=145", got)
	}
	if got := cm.miningAlerts[ident]; got.FirstSeenUnix != 125 || got.LastSeenUnix != 150 || got.LastRecoveryObservationUnix != 148 ||
		got.LastEpisodeStartUnix != 125 || got.LastEmitUnix != 145 {
		t.Fatalf("mining clock=%+v, want every timestamp shifted by 60", got)
	}
	if cm.behaviorFreezeStartUnix != 0 {
		t.Fatalf("freeze boundary=%d, want cleared", cm.behaviorFreezeStartUnix)
	}

	// A normal successful cycle without a preceding failure must not shift the
	// clocks a second time.
	if delta := cm.resumeBehaviorStateClockAt(180); delta != 0 {
		t.Fatalf("second recovery delta=%d, want 0", delta)
	}
	if got := cm.behaviorEWMA[shard][ident].LastSeenUnix; got != 150 {
		t.Fatalf("second recovery shifted EWMA to %d, want 150", got)
	}
}

func TestThreatEventClockExcludesOutageTime(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	tm := &ThreatManager{threatLastHit: map[string]time.Time{"hit": base}}
	tm.shiftThreatEventClock(75)
	if got := tm.threatLastHit["hit"]; !got.Equal(base.Add(75 * time.Second)) {
		t.Fatalf("shifted threat timestamp=%v, want %v", got, base.Add(75*time.Second))
	}
	zero := time.Time{}
	tm.threatLastHit["zero"] = zero
	tm.shiftThreatEventClock(15)
	if got := tm.threatLastHit["zero"]; !got.IsZero() {
		t.Fatalf("zero threat timestamp shifted to %v", got)
	}
}
