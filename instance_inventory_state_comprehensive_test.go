package main

import (
	"testing"
	"time"

	"github.com/digitalocean/go-libvirt"
)

func newInventoryStateTestManager() *InstanceManager {
	im := &InstanceManager{
		domainMeta:         make(map[string]*DomainStatic),
		activeInstances:    make(map[string]struct{}),
		vmIPSet:            make(map[IPKey]struct{}),
		vmIPToInstance:     make(map[IPKey]string),
		vmIPOwners:         make(map[IPKey]map[string]struct{}),
		vmIPKeysByInstance: make(map[string][]IPKey),
		xmlInflight:        make(map[string]*domainXMLInflight),
	}
	for i := 0; i < shardCount; i++ {
		im.cpuSamples[i] = make(map[string]cpuSample)
		im.diskSamples[i] = make(map[string]diskSample)
		im.memSamples[i] = make(map[string]memSample)
		im.netSamples[i] = make(map[string]netSample)
	}
	return im
}

func TestInventoryActiveStateSnapshotsAreIndependent(t *testing.T) {
	im := newInventoryStateTestManager()
	active := map[string]struct{}{"active": {}}
	im.setActiveInstances(active)

	if !im.isInstanceActive("active") || im.isInstanceActive("missing") {
		t.Fatal("active-instance membership is incorrect")
	}
	snapshot := im.snapshotActiveInstances()
	delete(snapshot, "active")
	snapshot["other"] = struct{}{}
	if !im.isInstanceActive("active") || im.isInstanceActive("other") {
		t.Fatal("snapshot mutation changed manager state")
	}
}

func TestInventoryVMIPIndexReplaceRemoveAndSnapshot(t *testing.T) {
	im := newInventoryStateTestManager()
	im.updateVMIPIndex("", []IP{{Address: "192.0.2.1"}})
	if len(im.vmIPSet) != 0 {
		t.Fatal("blank instance UUID should be ignored")
	}

	im.updateVMIPIndex("vm-1", []IP{
		{Address: "192.0.2.10"},
		{Address: "2001:db8::10"},
		{Address: ""},
		{Address: "not-an-ip"},
	})
	v4 := IPStrToKey("192.0.2.10")
	v6 := IPStrToKey("2001:db8::10")
	setSnapshot, mapSnapshot := im.getVMIPIndexSnapshot()
	if len(setSnapshot) != 2 || mapSnapshot[v4] != "vm-1" || mapSnapshot[v6] != "vm-1" {
		t.Fatalf("unexpected initial VM IP index: set=%v map=%v", setSnapshot, mapSnapshot)
	}

	delete(setSnapshot, v4)
	delete(mapSnapshot, v6)
	setAgain, mapAgain := im.getVMIPIndexSnapshot()
	if _, ok := setAgain[v4]; !ok || mapAgain[v6] != "vm-1" {
		t.Fatal("snapshot mutation changed VM IP index")
	}

	im.updateVMIPIndex("vm-1", []IP{{Address: "198.51.100.20"}})
	newKey := IPStrToKey("198.51.100.20")
	setAgain, mapAgain = im.getVMIPIndexSnapshot()
	if len(setAgain) != 1 || mapAgain[newKey] != "vm-1" {
		t.Fatalf("replacement index is incorrect: set=%v map=%v", setAgain, mapAgain)
	}
	if _, ok := setAgain[v4]; ok {
		t.Fatal("replacement retained stale IPv4 address")
	}
	if _, ok := setAgain[v6]; ok {
		t.Fatal("replacement retained stale IPv6 address")
	}

	im.removeVMIPIndex("")
	im.removeVMIPIndex("missing")
	im.removeVMIPIndex("vm-1")
	setAgain, mapAgain = im.getVMIPIndexSnapshot()
	if len(setAgain) != 0 || len(mapAgain) != 0 || len(im.vmIPKeysByInstance) != 0 {
		t.Fatalf("VM IP removal left state behind: set=%v map=%v keys=%v", setAgain, mapAgain, im.vmIPKeysByInstance)
	}
}

func TestInventoryCleanupPreservesOnlyActiveState(t *testing.T) {
	im := newInventoryStateTestManager()
	im.setActiveInstances(map[string]struct{}{"active": {}})
	im.domainMeta["active"] = &DomainStatic{InstanceUUID: "active"}
	im.domainMeta["stale"] = &DomainStatic{InstanceUUID: "stale"}
	im.updateVMIPIndex("active", []IP{{Address: "192.0.2.1"}})
	im.updateVMIPIndex("stale", []IP{{Address: "192.0.2.2"}})

	for _, uuid := range []string{"active", "stale"} {
		idx := shardIndex(uuid)
		im.cpuSamples[idx][uuid] = cpuSample{total: 1}
		im.memSamples[idx][uuid] = memSample{swapIn: 1}
		im.netSamples[idx][uuid] = netSample{rxPkts: 1}
		im.diskSamples[idx][uuid+"|vda"] = diskSample{rdReq: 1}
	}
	// An unexpected disk key still belongs to its first component and must be cleaned.
	staleShard := shardIndex("stale")
	im.diskSamples[staleShard]["stale"] = diskSample{rdReq: 2}

	im.cleanupDomainMeta()
	im.cleanupResourceSamples()

	if _, ok := im.domainMeta["active"]; !ok {
		t.Fatal("active metadata was removed")
	}
	if _, ok := im.domainMeta["stale"]; ok {
		t.Fatal("stale metadata was retained")
	}
	set, byIP := im.getVMIPIndexSnapshot()
	if len(set) != 1 || byIP[IPStrToKey("192.0.2.1")] != "active" {
		t.Fatalf("metadata cleanup left incorrect IP index: set=%v map=%v", set, byIP)
	}

	for _, uuid := range []string{"active", "stale"} {
		idx := shardIndex(uuid)
		_, cpuOK := im.cpuSamples[idx][uuid]
		_, memOK := im.memSamples[idx][uuid]
		_, netOK := im.netSamples[idx][uuid]
		_, diskOK := im.diskSamples[idx][uuid+"|vda"]
		want := uuid == "active"
		if cpuOK != want || memOK != want || netOK != want || diskOK != want {
			t.Fatalf("resource cleanup mismatch for %q: cpu=%v mem=%v net=%v disk=%v", uuid, cpuOK, memOK, netOK, diskOK)
		}
	}
	if _, ok := im.diskSamples[staleShard]["stale"]; ok {
		t.Fatal("stale disk sample without a separator was retained")
	}
}

func TestInventoryVMIPIdentitySnapshotFiltersAndDeduplicates(t *testing.T) {
	im := newInventoryStateTestManager()
	im.domainMeta["vm-1"] = &DomainStatic{FixedIPs: []IP{
		{Address: "192.0.2.10"},
		{Address: "192.0.2.10"},
		{Address: "2001:db8::10"},
		{Address: "invalid"},
	}}
	im.domainMeta["nil"] = nil
	im.domainMeta["inactive"] = &DomainStatic{FixedIPs: []IP{{Address: "192.0.2.99"}}}

	identities := im.snapshotVMIPIdentities(map[string]struct{}{
		"vm-1":    {},
		"nil":     {},
		"missing": {},
	})
	if len(identities) != 2 {
		t.Fatalf("got %d identities, want two unique valid addresses: %#v", len(identities), identities)
	}
	want := map[IPKey]bool{
		IPStrToKey("192.0.2.10"):   false,
		IPStrToKey("2001:db8::10"): false,
	}
	for _, identity := range identities {
		if identity.InstanceUUID != "vm-1" {
			t.Fatalf("unexpected instance identity: %#v", identity)
		}
		if _, ok := want[identity.IP]; !ok {
			t.Fatalf("unexpected IP identity: %#v", identity)
		}
		want[identity.IP] = true
	}
	for key, seen := range want {
		if !seen {
			t.Fatalf("missing identity for %v", key)
		}
	}
}

func TestGetDomainMetaUsesFreshAndStaleCacheWithoutConnection(t *testing.T) {
	im := newInventoryStateTestManager()
	dom := libvirt.Domain{
		Name: "instance-00000001",
		UUID: [16]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
	}
	uuid := "00112233-4455-6677-8899-aabbccddeeff"
	fresh := &DomainStatic{InstanceUUID: uuid, LastUpdated: time.Now()}
	im.domainMeta[uuid] = fresh
	got, err := im.getDomainMeta(dom, nil)
	if err != nil || got != fresh {
		t.Fatalf("fresh cache lookup = (%p, %v), want (%p, nil)", got, err, fresh)
	}

	stale := &DomainStatic{InstanceUUID: uuid, LastUpdated: time.Now().Add(-10 * time.Minute)}
	im.domainMeta[uuid] = stale
	got, err = im.getDomainMeta(dom, nil)
	if err != nil || got != stale {
		t.Fatalf("stale fallback lookup = (%p, %v), want (%p, nil)", got, err, stale)
	}

	delete(im.domainMeta, uuid)
	if got, err = im.getDomainMeta(dom, nil); err == nil || got != nil {
		t.Fatalf("missing cache lookup = (%p, %v), want nil error result", got, err)
	}
}
