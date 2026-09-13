package main

import (
	"testing"
	"time"
)

func TestThreatIntelligenceFixedIPMembershipBoundaryResetsThreatEpisodeState(t *testing.T) {
	const instanceUUID = "vm-ip-boundary"
	active := map[string]struct{}{instanceUUID: {}}
	metadata := func(addresses ...string) map[string]*DomainStatic {
		fixedIPs := make([]IP, 0, len(addresses))
		for _, address := range addresses {
			fixedIPs = append(fixedIPs, IP{Address: address})
		}
		return map[string]*DomainStatic{
			instanceUUID: {InstanceUUID: instanceUUID, FixedIPs: fixedIPs},
		}
	}

	im := &InstanceManager{
		domainMeta:         make(map[string]*DomainStatic),
		activeInstances:    make(map[string]struct{}),
		vmIPSet:            make(map[IPKey]struct{}),
		vmIPToInstance:     make(map[IPKey]string),
		vmIPOwners:         make(map[IPKey]map[string]struct{}),
		vmIPKeysByInstance: make(map[string][]IPKey),
	}
	provider := newThreatStateTestProvider("ThreatIntelligenceIdentity")
	tm := newThreatStateTestManager(provider)
	tm.threatLogMinInterval = time.Hour
	tm.spamCount[instanceUUID] = 11
	provider.CountMap[instanceUUID] = 13
	tm.spamPrevHits[instanceUUID] = map[string]struct{}{"spam-old": {}}
	provider.PrevHits[instanceUUID] = map[string]struct{}{"provider-old": {}}
	tm.threatLastHit[instanceThreatThrottlePrefix+"THREAT_INTELLIGENCEIDENTITY|"+instanceUUID] = time.Now()
	mc := &MetricsCollector{
		im:           im,
		tm:           tm,
		intelHistory: make(map[string]*IntelHistory),
	}

	mc.commitPreparedLibvirtCycle(&preparedLibvirtCycle{
		activeSet: active,
		metadata:  metadata("10.0.0.10", "2001:db8::10"),
	})
	mc.updateIntelHistory(instanceUUID, 0.7, 100)

	// Metadata order is not an ownership boundary.
	mc.commitPreparedLibvirtCycle(&preparedLibvirtCycle{
		activeSet: active,
		metadata:  metadata("2001:db8::10", "10.0.0.10"),
	})
	if _, available := mc.snapshotIntelCombinedAvailable(instanceUUID); !available {
		t.Fatal("fixed-IP reordering reset threat history")
	}
	if _, ok := provider.PrevHits[instanceUUID]; !ok {
		t.Fatal("fixed-IP reordering reset provider contact-diff state")
	}

	// Replacing one authoritative address starts a new threat episode.
	mc.commitPreparedLibvirtCycle(&preparedLibvirtCycle{
		activeSet: active,
		metadata:  metadata("10.0.0.11", "2001:db8::10"),
	})
	if _, available := mc.snapshotIntelCombinedAvailable(instanceUUID); available {
		t.Fatal("fixed-IP replacement retained threat history")
	}
	if _, ok := provider.PrevHits[instanceUUID]; ok {
		t.Fatal("fixed-IP replacement retained provider contact-diff state")
	}
	if _, ok := tm.spamPrevHits[instanceUUID]; ok {
		t.Fatal("fixed-IP replacement retained Spamhaus contact-diff state")
	}
	if len(tm.threatLastHit) != 0 {
		t.Fatalf("fixed-IP replacement retained instance summary cooldown: %v", tm.threatLastHit)
	}
	if provider.CountMap[instanceUUID] != 13 || tm.spamCount[instanceUUID] != 11 {
		t.Fatalf("fixed-IP replacement reset cumulative counters: provider=%v spamhaus=%v", provider.CountMap[instanceUUID], tm.spamCount[instanceUUID])
	}

	// Detaching the final address is the same authoritative boundary.
	mc.updateIntelHistory(instanceUUID, 0.4, 200)
	provider.PrevHits[instanceUUID] = map[string]struct{}{"provider-new": {}}
	tm.spamPrevHits[instanceUUID] = map[string]struct{}{"spam-new": {}}
	tm.threatLastHit[instanceThreatThrottlePrefix+"THREAT_INTELLIGENCEIDENTITY|"+instanceUUID] = time.Now()
	mc.commitPreparedLibvirtCycle(&preparedLibvirtCycle{
		activeSet: active,
		metadata:  metadata(),
	})
	if _, available := mc.snapshotIntelCombinedAvailable(instanceUUID); available {
		t.Fatal("fixed-IP detachment retained threat history")
	}
	if _, ok := provider.PrevHits[instanceUUID]; ok {
		t.Fatal("fixed-IP detachment retained provider contact-diff state")
	}
	if _, ok := tm.spamPrevHits[instanceUUID]; ok {
		t.Fatal("fixed-IP detachment retained Spamhaus contact-diff state")
	}
	if len(tm.threatLastHit) != 0 {
		t.Fatalf("fixed-IP detachment retained instance summary cooldown: %v", tm.threatLastHit)
	}
	if provider.CountMap[instanceUUID] != 13 || tm.spamCount[instanceUUID] != 11 {
		t.Fatal("fixed-IP detachment reset cumulative counters")
	}
}
