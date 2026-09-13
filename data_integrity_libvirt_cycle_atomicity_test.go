package main

import (
	"fmt"
	"testing"
	"time"

	libvirt "github.com/digitalocean/go-libvirt"
)

func dataIntegrityDomain(uuidByte byte, name string) (libvirt.Domain, string) {
	uuid := libvirt.UUID{
		uuidByte, uuidByte, uuidByte, uuidByte,
		uuidByte, uuidByte, uuidByte, uuidByte,
		uuidByte, uuidByte, uuidByte, uuidByte,
		uuidByte, uuidByte, uuidByte, uuidByte,
	}
	return libvirt.Domain{Name: name, UUID: uuid}, uuidBytesToString(uuid[:])
}

func TestDataIntegrityDomainMetadataFreshnessDistinguishesRetainedFallback(t *testing.T) {
	im := newInstanceManager(CollectorConfig{LibvirtURI: "qemu:///system", WorkerCount: 1})
	domain, instanceUUID := dataIntegrityDomain(0x31, "instance-data-integrity-retained-meta")
	retained := &DomainStatic{
		InstanceUUID: instanceUUID,
		LastUpdated:  time.Now().Add(-10 * time.Minute),
	}
	im.domainMeta[instanceUUID] = retained

	got, fresh, err := im.getDomainMetaForCollection(domain, nil)
	if got != retained || fresh || err == nil {
		t.Fatalf("stale metadata fallback=(%p,%v,%v), want retained pointer, fresh=false, error", got, fresh, err)
	}

	// The compatibility wrapper still serves retained metadata to callers that
	// do not make source-health decisions.
	got, err = im.getDomainMeta(domain, nil)
	if got != retained || err != nil {
		t.Fatalf("compatibility metadata fallback=(%p,%v), want retained pointer and nil error", got, err)
	}

	retained.LastUpdated = time.Now()
	got, fresh, err = im.getDomainMetaForCollection(domain, nil)
	if got != retained || !fresh || err != nil {
		t.Fatalf("valid cached metadata=(%p,%v,%v), want same pointer, fresh=true, nil error", got, fresh, err)
	}
}

func TestDataIntegrityPrepareLibvirtCycleIsAtomic(t *testing.T) {
	mc := newCollectorOrchestrationTestCollector(t)
	firstDomain, firstUUID := dataIntegrityDomain(0x41, "instance-data-integrity-first")
	secondDomain, secondUUID := dataIntegrityDomain(0x42, "instance-data-integrity-second")
	now := time.Now()
	mc.im.domainMeta[firstUUID] = &DomainStatic{InstanceUUID: firstUUID, LastUpdated: now}
	mc.im.domainMeta[secondUUID] = &DomainStatic{InstanceUUID: secondUUID, LastUpdated: now.Add(-10 * time.Minute)}
	mc.im.setActiveInstances(map[string]struct{}{"previous-instance": {}})

	records := []libvirt.DomainStatsRecord{{Dom: firstDomain}, {Dom: secondDomain}}
	prepared, err := mc.prepareLibvirtCycle(records)
	if err == nil || prepared != nil {
		t.Fatalf("partial metadata preflight=(%+v,%v), want nil prepared cycle and error", prepared, err)
	}
	if !mc.im.isInstanceActive("previous-instance") || mc.im.isInstanceActive(firstUUID) || mc.im.isInstanceActive(secondUUID) {
		t.Fatalf("failed preflight mutated active set: %v", mc.im.snapshotActiveInstances())
	}

	mc.im.domainMeta[secondUUID].LastUpdated = now
	prepared, err = mc.prepareLibvirtCycle(records)
	if err != nil || prepared == nil {
		t.Fatalf("complete metadata preflight=(%+v,%v), want prepared cycle", prepared, err)
	}
	if len(prepared.activeSet) != 2 || len(prepared.metadata) != 2 ||
		prepared.metadata[firstUUID] == nil || prepared.metadata[secondUUID] == nil {
		t.Fatalf("prepared cycle is incomplete: active=%v metadata=%v", prepared.activeSet, prepared.metadata)
	}
	if !mc.im.isInstanceActive("previous-instance") {
		t.Fatal("preparing a successful cycle committed active-instance state before the caller accepted it")
	}
}

func TestDataIntegrityMetadataRefreshIsStagedUntilWholeCycleSucceeds(t *testing.T) {
	mc := newCollectorOrchestrationTestCollector(t)
	firstDomain, firstUUID := dataIntegrityDomain(0x51, "instance-data-integrity-staged-first")
	secondDomain, secondUUID := dataIntegrityDomain(0x52, "instance-data-integrity-staged-second")
	oldIP := "192.0.2.51"
	newIP := "192.0.2.151"
	oldFirst := &DomainStatic{
		InstanceUUID: firstUUID,
		FixedIPs:     []IP{{Address: oldIP, Family: "4"}},
		LastUpdated:  time.Now().Add(-10 * time.Minute),
	}
	oldSecond := &DomainStatic{
		InstanceUUID: secondUUID,
		LastUpdated:  time.Now().Add(-10 * time.Minute),
	}
	mc.im.domainMeta[firstUUID] = oldFirst
	mc.im.domainMeta[secondUUID] = oldSecond
	mc.im.updateVMIPIndex(firstUUID, oldFirst.FixedIPs)
	mc.im.setActiveInstances(map[string]struct{}{"previous-instance": {}})

	xmlFor := func(name, address string) string {
		return `<domain><metadata><instance><name>` + name + `</name><ports>` +
			`<port uuid="port-` + name + `"><ip address="` + address + `"/></port>` +
			`</ports></instance></metadata></domain>`
	}
	secondFails := true
	mc.im.domainXMLDescOverride = func(domain libvirt.Domain) (string, error) {
		if domain.UUID == secondDomain.UUID && secondFails {
			return "", fmt.Errorf("second domain XML unavailable")
		}
		if domain.UUID == firstDomain.UUID {
			return xmlFor("first", newIP), nil
		}
		return xmlFor("second", "192.0.2.152"), nil
	}

	records := []libvirt.DomainStatsRecord{{Dom: firstDomain}, {Dom: secondDomain}}
	prepared, err := mc.prepareLibvirtCycle(records)
	if err == nil || prepared != nil {
		t.Fatalf("failed staged preflight=(%+v,%v), want nil,error", prepared, err)
	}
	if mc.im.domainMeta[firstUUID] != oldFirst || mc.im.domainMeta[secondUUID] != oldSecond {
		t.Fatal("failed preflight partially committed refreshed domain metadata")
	}
	vmIPSet, _ := mc.im.getVMIPIndexSnapshot()
	if _, ok := vmIPSet[IPStrToKey(oldIP)]; !ok {
		t.Fatal("failed preflight removed the retained VM IP")
	}
	if _, ok := vmIPSet[IPStrToKey(newIP)]; ok {
		t.Fatal("failed preflight exposed a partially refreshed VM IP")
	}
	if !mc.im.isInstanceActive("previous-instance") {
		t.Fatal("failed preflight changed the active inventory")
	}

	secondFails = false
	prepared, err = mc.prepareLibvirtCycle(records)
	if err != nil || prepared == nil {
		t.Fatalf("successful staged preflight=(%+v,%v), want prepared,nil", prepared, err)
	}
	if mc.im.domainMeta[firstUUID] != oldFirst {
		t.Fatal("successful preparation committed metadata before cycle acceptance")
	}
	mc.commitPreparedLibvirtCycle(prepared)
	if mc.im.domainMeta[firstUUID] == oldFirst || mc.im.domainMeta[firstUUID].FixedIPs[0].Address != newIP {
		t.Fatalf("accepted cycle did not commit staged first metadata: %+v", mc.im.domainMeta[firstUUID])
	}
	if !mc.im.isInstanceActive(firstUUID) || !mc.im.isInstanceActive(secondUUID) || mc.im.isInstanceActive("previous-instance") {
		t.Fatalf("accepted cycle active set=%v, want exactly staged domains", mc.im.snapshotActiveInstances())
	}
	vmIPSet, _ = mc.im.getVMIPIndexSnapshot()
	if _, ok := vmIPSet[IPStrToKey(oldIP)]; ok {
		t.Fatal("accepted cycle retained the replaced VM IP")
	}
	if _, ok := vmIPSet[IPStrToKey(newIP)]; !ok {
		t.Fatal("accepted cycle omitted the staged VM IP")
	}
}
