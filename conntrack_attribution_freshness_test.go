package main

import (
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestConntrackOverlappingIPsRequireCurrentZoneOwnership(t *testing.T) {
	now := time.Now()
	ip := IPStrToKey("10.0.0.10")
	identities := []VMIPIdentity{{InstanceUUID: "vm-a", IP: ip}, {InstanceUUID: "vm-b", IP: ip}}
	mapper := NewOVNMapper()
	mapper.lastRefresh = now
	mapper.zoneToInstance = map[uint16]string{7: "vm-a", 9: "vm-b"}
	mapper.zoneToIPs = map[uint16]map[IPKey]struct{}{7: {ip: {}}, 9: {ip: {}}}
	cm := newConntrackManager(CollectorConfig{ConntrackIPv4Enable: true, CollectionInterval: 15 * time.Second})
	cm.ovnMapper = mapper
	cm.conntrackNowOverride = func() time.Time { return now }
	dumps := 0
	cm.conntrackDumpFamilyOverride = func(_ int, _ int, _ time.Duration, consume func(ConntrackFlowLite)) (uint64, uint64, uint64, error) {
		dumps++
		consume(ConntrackFlowLite{SrcIP: ip, DstIP: IPStrToKey("198.51.100.1"), Zone: 7, Proto: 6})
		return 1, 0, 0, nil
	}
	first, _, err := cm.readAndAggregateConntrack(identities, nil)
	if err != nil || first.InstanceFlowTotals["vm-a"] != 1 {
		t.Fatalf("initial zone attribution failed: aggregate=%+v error=%v", first, err)
	}
	lastSuccess := atomic.LoadInt64(&cm.conntrackLastSuccessUnix)
	now = now.Add(2 * time.Minute)
	if got, _, err := cm.readAndAggregateConntrack(identities, nil); err == nil || got != nil {
		t.Fatalf("expired zone ownership was published as current: aggregate=%+v error=%v", got, err)
	}
	if atomic.LoadInt64(&cm.conntrackLastSuccessUnix) != lastSuccess || atomic.LoadUint64(&cm.conntrackRawOK) != 0 || dumps != 1 {
		t.Fatal("unavailable attribution advanced freshness or started a raw read")
	}
	if retained, _, ok := cm.snapshotLastGoodConntrack(); !ok || retained != first {
		t.Fatal("unavailable attribution replaced the last complete snapshot")
	}
	// A refresh observes that the zone now belongs to the other tenant.
	mapper.lastRefresh = now
	mapper.zoneToInstance = map[uint16]string{7: "vm-b", 9: "vm-a"}
	recovered, _, err := cm.readAndAggregateConntrack(identities, nil)
	if err != nil || recovered.InstanceFlowTotals["vm-b"] != 1 || recovered.InstanceFlowTotals["vm-a"] != 0 {
		t.Fatalf("refreshed zone owner was not used: aggregate=%+v error=%v", recovered, err)
	}
}

func TestConntrackOverlappingIPsRejectIncompleteZoneCoverage(t *testing.T) {
	ip := IPStrToKey("10.0.0.10")
	cm := newConntrackManager(CollectorConfig{ConntrackIPv4Enable: true})
	cm.ovnMapper.lastRefresh = time.Now()
	cm.ovnMapper.zoneToInstance = map[uint16]string{7: "vm-a"}
	cm.ovnMapper.zoneToIPs = map[uint16]map[IPKey]struct{}{7: {ip: {}}}
	cm.conntrackDumpFamilyOverride = func(_ int, _ int, _ time.Duration, _ func(ConntrackFlowLite)) (uint64, uint64, uint64, error) {
		t.Fatal("incomplete ownership must not publish a fresh zero-flow snapshot")
		return 0, 0, 0, nil
	}
	if _, _, err := cm.readAndAggregateConntrack([]VMIPIdentity{{InstanceUUID: "vm-a", IP: ip}, {InstanceUUID: "vm-b", IP: ip}}, nil); err == nil {
		t.Fatal("missing ownership for an overlapping IP was accepted")
	}
}

func TestConntrackUniqueIPsDoNotRequireOVN(t *testing.T) {
	ip := IPStrToKey("10.0.0.10")
	cm := newConntrackManager(CollectorConfig{ConntrackIPv4Enable: true})
	cm.ovnMapper = nil
	cm.conntrackDumpFamilyOverride = func(_ int, _ int, _ time.Duration, consume func(ConntrackFlowLite)) (uint64, uint64, uint64, error) {
		consume(ConntrackFlowLite{SrcIP: ip, DstIP: IPStrToKey("198.51.100.1"), Proto: 6})
		return 1, 0, 0, nil
	}
	agg, _, err := cm.readAndAggregateConntrack([]VMIPIdentity{{InstanceUUID: "vm-a", IP: ip}}, nil)
	if err != nil || agg.InstanceFlowTotals["vm-a"] != 1 {
		t.Fatalf("unique-IP fallback failed: aggregate=%+v error=%v", agg, err)
	}
}

func TestConntrackAttributionOnlyRequiresEnabledFamilies(t *testing.T) {
	v4 := IPStrToKey("10.0.0.10")
	v6 := IPStrToKey("2001:db8::10")
	cm := newConntrackManager(CollectorConfig{ConntrackIPv6Enable: true})
	cm.ovnMapper = nil
	cm.conntrackDumpFamilyOverride = func(_ int, _ int, _ time.Duration, consume func(ConntrackFlowLite)) (uint64, uint64, uint64, error) {
		consume(ConntrackFlowLite{SrcIP: v6, DstIP: IPStrToKey("2001:db8::1"), Proto: 6})
		return 1, 0, 0, nil
	}
	identities := []VMIPIdentity{{InstanceUUID: "vm-a", IP: v4}, {InstanceUUID: "vm-b", IP: v4}, {InstanceUUID: "vm-a", IP: v6}}
	agg, _, err := cm.readAndAggregateConntrack(identities, nil)
	if err != nil || agg.InstanceFlowTotals["vm-a"] != 1 {
		t.Fatalf("disabled-family overlap blocked IPv6 collection: aggregate=%+v error=%v", agg, err)
	}
}

func TestConntrackDisabledFamilyOmitsNetworkMetricsAndBehaviorState(t *testing.T) {
	for _, enabledFamily := range []int{syscall.AF_INET, syscall.AF_INET6} {
		name := "IPv4 only"
		if enabledFamily == syscall.AF_INET6 {
			name = "IPv6 only"
		}
		t.Run(name, func(t *testing.T) {
			fixedIPs := []IP{
				{Address: "10.0.0.10", Family: "ipv4"},
				{Address: "2001:db8::10", Family: "ipv6"},
			}
			identities := []VMIPIdentity{
				{InstanceUUID: "vm-a", IP: IPStrToKey(fixedIPs[0].Address)},
				{InstanceUUID: "vm-a", IP: IPStrToKey(fixedIPs[1].Address)},
			}
			enabledIndex := 0
			remote := IPStrToKey("198.51.100.10")
			if enabledFamily == syscall.AF_INET6 {
				enabledIndex = 1
				remote = IPStrToKey("2001:db8:1::10")
			}
			disabledIndex := 1 - enabledIndex
			cm := newConntrackManager(CollectorConfig{
				ConntrackIPv4Enable:    enabledFamily == syscall.AF_INET,
				ConntrackIPv6Enable:    enabledFamily == syscall.AF_INET6,
				OutboundBehaviorEnable: true,
				InboundBehaviorEnable:  true,
				BehaviorSensitivity:    1,
			})
			initConntrackMetrics(cm)
			dumps := 0
			cm.conntrackDumpFamilyOverride = func(family int, _ int, _ time.Duration, consume func(ConntrackFlowLite)) (uint64, uint64, uint64, error) {
				if family != enabledFamily {
					t.Fatalf("read disabled address family %d", family)
				}
				dumps++
				consume(ConntrackFlowLite{
					SrcIP: identities[enabledIndex].IP, DstIP: remote,
					SrcPort: 40000, DstPort: 443, Proto: 6, Status: IPS_SEEN_REPLY,
				})
				return 1, 0, 0, nil
			}
			agg, count, err := cm.readAndAggregateConntrack(identities, nil)
			if err != nil || count != 1 || dumps != 1 {
				t.Fatalf("enabled-family collection: count=%d dumps=%d error=%v", count, dumps, err)
			}
			if _, ok := agg.VMIndex[identities[disabledIndex]]; ok || len(agg.VMIndex) != 1 {
				t.Fatalf("disabled-family inventory was indexed as observed: %v", agg.VMIndex)
			}
			if _, ok := agg.VMIndex[identities[enabledIndex]]; !ok {
				t.Fatal("enabled-family identity was omitted")
			}

			metrics := make([]prometheus.Metric, 0, 32)
			cm.calculateConntrackMetrics(
				fixedIPs, agg, nil, nil, 1000, true,
				"domain", "server", "vm-a", "project", "project-name", "user", &metrics,
			)
			if len(metrics) < 3 {
				t.Fatalf("enabled-family measurements were omitted: %d metrics", len(metrics))
			}
			for _, metric := range metrics {
				var encoded dto.Metric
				if err := metric.Write(&encoded); err != nil {
					t.Fatal(err)
				}
				for _, label := range encoded.Label {
					if label.GetName() == "ip" && label.GetValue() != fixedIPs[enabledIndex].Address {
						t.Fatalf("unobserved disabled-family metric was emitted: %v", &encoded)
					}
				}
			}
			for _, direction := range []string{"outbound", "inbound"} {
				identity := behaviorIdentityKey{InstanceUUID: "vm-a", IP: identities[disabledIndex].IP, Direction: direction}
				if cm.behaviorObservationAvailable(identity) {
					t.Fatalf("disabled family advanced %s behavior state", direction)
				}
			}
		})
	}
}

func TestConntrackFreshZoneDoesNotAttributeOffHostAliasToAnotherTenant(t *testing.T) {
	src := IPStrToKey("10.0.0.10")
	remote := IPStrToKey("10.0.0.20")
	cm := newConntrackManager(CollectorConfig{ConntrackIPv4Enable: true, InboundBehaviorEnable: true, OutboundBehaviorEnable: true})
	cm.ovnMapper.lastRefresh = time.Now()
	cm.ovnMapper.zoneToInstance = map[uint16]string{7: "tenant-a-vm", 9: "tenant-b-vm"}
	cm.ovnMapper.zoneToIPs = map[uint16]map[IPKey]struct{}{7: {src: {}}, 9: {remote: {}}}
	cm.conntrackDumpFamilyOverride = func(_ int, _ int, _ time.Duration, consume func(ConntrackFlowLite)) (uint64, uint64, uint64, error) {
		// Tenant A's peer is off-host. Tenant B independently owns the same
		// destination address on this compute, but in a different OVN zone.
		consume(ConntrackFlowLite{SrcIP: src, DstIP: remote, SrcPort: 40000, DstPort: 443, Proto: 6, Zone: 7})
		return 1, 0, 0, nil
	}
	agg, _, err := cm.readAndAggregateConntrack([]VMIPIdentity{
		{InstanceUUID: "tenant-a-vm", IP: src},
		{InstanceUUID: "tenant-b-vm", IP: remote},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if agg.InstanceFlowTotals["tenant-a-vm"] != 1 || agg.InstanceFlowTotals["tenant-b-vm"] != 0 {
		t.Fatalf("known-zone flow was assigned to an unrelated tenant: %v", agg.InstanceFlowTotals)
	}
	bIndex := int(agg.VMIndex[VMIPIdentity{InstanceUUID: "tenant-b-vm", IP: remote}])
	if agg.FlowsIn[bIndex] != 0 || agg.InboundStats[bIndex] != nil {
		t.Fatal("off-host address alias created inbound behavior evidence for tenant B")
	}
}

func TestConntrackLocalVMEndpointsUseTheirOwnFreshZoneEntries(t *testing.T) {
	src := IPStrToKey("10.0.0.10")
	dst := IPStrToKey("10.0.0.20")
	cm := newConntrackManager(CollectorConfig{ConntrackIPv4Enable: true, InboundBehaviorEnable: true, OutboundBehaviorEnable: true})
	cm.ovnMapper.lastRefresh = time.Now()
	cm.ovnMapper.zoneToInstance = map[uint16]string{7: "vm-src", 9: "vm-dst"}
	cm.ovnMapper.zoneToIPs = map[uint16]map[IPKey]struct{}{7: {src: {}}, 9: {dst: {}}}
	cm.conntrackDumpFamilyOverride = func(_ int, _ int, _ time.Duration, consume func(ConntrackFlowLite)) (uint64, uint64, uint64, error) {
		for _, zone := range []uint16{7, 9} {
			consume(ConntrackFlowLite{SrcIP: src, DstIP: dst, SrcPort: 40000, DstPort: 443, Proto: 6, Zone: zone})
		}
		return 2, 0, 0, nil
	}
	agg, count, err := cm.readAndAggregateConntrack([]VMIPIdentity{
		{InstanceUUID: "vm-src", IP: src},
		{InstanceUUID: "vm-dst", IP: dst},
	}, nil)
	if err != nil || count != 2 {
		t.Fatalf("local connection collection: count=%d error=%v", count, err)
	}
	srcIndex := int(agg.VMIndex[VMIPIdentity{InstanceUUID: "vm-src", IP: src}])
	dstIndex := int(agg.VMIndex[VMIPIdentity{InstanceUUID: "vm-dst", IP: dst}])
	if agg.InstanceFlowTotals["vm-src"] != 1 || agg.InstanceFlowTotals["vm-dst"] != 1 || agg.FlowsOut[srcIndex] != 1 || agg.FlowsIn[dstIndex] != 1 {
		t.Fatalf("local zone entries lost or duplicated endpoint attribution: totals=%v inbound=%v outbound=%v", agg.InstanceFlowTotals, agg.FlowsIn, agg.FlowsOut)
	}
	if agg.OutboundStats[srcIndex] == nil || agg.InboundStats[dstIndex] == nil {
		t.Fatal("local zone entries omitted endpoint behavior evidence")
	}
}

func TestConntrackStaleUniqueIPZoneMappingDoesNotConstrainFallback(t *testing.T) {
	src := IPStrToKey("10.0.0.10")
	dst := IPStrToKey("10.0.0.20")
	cm := newConntrackManager(CollectorConfig{ConntrackIPv4Enable: true})
	cm.ovnMapper.lastRefresh = time.Now().Add(-2 * time.Minute)
	cm.ovnMapper.zoneToInstance = map[uint16]string{7: "vm-src"}
	cm.ovnMapper.zoneToIPs = map[uint16]map[IPKey]struct{}{7: {src: {}}}
	cm.conntrackDumpFamilyOverride = func(_ int, _ int, _ time.Duration, consume func(ConntrackFlowLite)) (uint64, uint64, uint64, error) {
		consume(ConntrackFlowLite{SrcIP: src, DstIP: dst, SrcPort: 40000, DstPort: 443, Proto: 6, Zone: 7})
		return 1, 0, 0, nil
	}
	agg, _, err := cm.readAndAggregateConntrack([]VMIPIdentity{
		{InstanceUUID: "vm-src", IP: src},
		{InstanceUUID: "vm-dst", IP: dst},
	}, nil)
	if err != nil || agg.InstanceFlowTotals["vm-src"] != 1 || agg.InstanceFlowTotals["vm-dst"] != 1 {
		t.Fatalf("stale mapping suppressed unique-IP fallback: aggregate=%+v error=%v", agg, err)
	}
}

func TestConntrackZoneExpiryDuringSnapshotConstructionRemainsUnavailable(t *testing.T) {
	base := time.Now()
	ip := IPStrToKey("10.0.0.10")
	cm := newConntrackManager(CollectorConfig{ConntrackIPv4Enable: true})
	cm.ovnMapper.lastRefresh = base
	cm.ovnMapper.zoneToInstance = map[uint16]string{7: "vm-a", 9: "vm-b"}
	cm.ovnMapper.zoneToIPs = map[uint16]map[IPKey]struct{}{7: {ip: {}}, 9: {ip: {}}}
	calls := 0
	cm.conntrackNowOverride = func() time.Time {
		calls++
		if calls == 1 {
			return base.Add(59 * time.Second)
		}
		return base.Add(61 * time.Second)
	}
	cm.conntrackDumpFamilyOverride = func(_ int, _ int, _ time.Duration, _ func(ConntrackFlowLite)) (uint64, uint64, uint64, error) {
		t.Fatal("expired overlapping-IP ownership must fail before any raw read")
		return 0, 0, 0, nil
	}
	agg, _, err := cm.readAndAggregateConntrack([]VMIPIdentity{
		{InstanceUUID: "vm-a", IP: ip}, {InstanceUUID: "vm-b", IP: ip},
	}, nil)
	if err == nil || agg != nil || atomic.LoadUint64(&cm.conntrackRawOK) != 0 {
		t.Fatalf("expiry during snapshot construction published fresh observations: aggregate=%+v error=%v", agg, err)
	}
}
