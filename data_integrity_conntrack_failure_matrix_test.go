package main

import (
	"errors"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	libvirt "github.com/digitalocean/go-libvirt"
	"github.com/prometheus/client_golang/prometheus"
)

func TestDataIntegrityConntrackFailureMatrixRetainsLastCompleteSnapshot(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	t1 := t0.Add(37 * time.Second)
	t2 := t1.Add(19 * time.Second)

	tests := []struct {
		name          string
		errV4         error
		errV6         error
		parseV4       uint64
		parseV6       uint64
		enobufsV4     uint64
		enobufsV6     uint64
		wantPartial   bool
		wantParse     uint64
		wantENOBUFS   uint64
		wantV4Failure bool
		wantV6Failure bool
	}{
		{
			name:          "timeout_eagain",
			errV4:         syscall.EAGAIN,
			errV6:         syscall.EAGAIN,
			wantV4Failure: true,
			wantV6Failure: true,
		},
		{
			name:          "enobufs",
			errV4:         syscall.ENOBUFS,
			errV6:         syscall.ENOBUFS,
			enobufsV4:     1,
			enobufsV6:     2,
			wantENOBUFS:   3,
			wantV4Failure: true,
			wantV6Failure: true,
		},
		{
			name:          "malformed_parse_error",
			errV4:         errors.New("malformed IPv4 conntrack payload"),
			errV6:         errors.New("malformed IPv6 conntrack payload"),
			parseV4:       2,
			parseV6:       3,
			wantParse:     5,
			wantV4Failure: true,
			wantV6Failure: true,
		},
		{
			name:          "truncated_dump",
			errV4:         errors.New("truncated IPv4 netlink datagram"),
			errV6:         errors.New("truncated IPv6 netlink datagram"),
			parseV4:       1,
			parseV6:       1,
			wantParse:     2,
			wantV4Failure: true,
			wantV6Failure: true,
		},
		{
			name:          "collection_interruption",
			errV4:         errors.New("IPv4 netlink dump interrupted"),
			errV6:         errors.New("IPv6 netlink dump interrupted"),
			wantV4Failure: true,
			wantV6Failure: true,
		},
		{
			name:          "ipv4_failure_ipv6_success",
			errV4:         syscall.EAGAIN,
			wantPartial:   true,
			wantV4Failure: true,
		},
		{
			name:          "ipv6_failure_ipv4_success",
			errV6:         syscall.EAGAIN,
			wantPartial:   true,
			wantV6Failure: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			vm4 := IPStrToKey("10.0.0.10")
			vm6 := IPStrToKey("2001:db8::10")
			vmIPs := []VMIPIdentity{
				{InstanceUUID: "vm-1", IP: vm4},
				{InstanceUUID: "vm-1", IP: vm6},
			}
			baselineFlow := ConntrackFlowLite{
				SrcIP: vm4, DstIP: IPStrToKey("198.51.100.10"),
				SrcPort: 41000, DstPort: 443, Proto: 6, Status: IPS_SEEN_REPLY,
			}
			transientV4 := ConntrackFlowLite{
				SrcIP: vm4, DstIP: IPStrToKey("198.51.100.99"),
				SrcPort: 42000, DstPort: 8443, Proto: 6,
			}
			transientV6 := ConntrackFlowLite{
				SrcIP: vm6, DstIP: IPStrToKey("2001:db8:ffff::99"),
				SrcPort: 43000, DstPort: 9443, Proto: 6,
			}
			recoveryV4 := ConntrackFlowLite{
				SrcIP: vm4, DstIP: IPStrToKey("203.0.113.10"),
				SrcPort: 44000, DstPort: 443, Proto: 6, Status: IPS_SEEN_REPLY,
			}
			recoveryV6 := ConntrackFlowLite{
				SrcIP: vm6, DstIP: IPStrToKey("2001:db8:ffff::10"),
				SrcPort: 45000, DstPort: 443, Proto: 6, Status: IPS_SEEN_REPLY,
			}

			phase := "baseline"
			now := t0
			cm := &ConntrackManager{
				conntrackIPv4Enable: true,
				conntrackIPv6Enable: true,
				conntrackNowOverride: func() time.Time {
					return now
				},
			}
			cm.conntrackDumpFamilyOverride = func(
				family int,
				_ int,
				_ time.Duration,
				consume func(ConntrackFlowLite),
			) (uint64, uint64, uint64, error) {
				switch phase {
				case "baseline":
					if family == syscall.AF_INET {
						consume(baselineFlow)
						return 1, 0, 0, nil
					}
					return 0, 0, 0, nil
				case "failure":
					if family == syscall.AF_INET {
						consume(transientV4)
						return 1, tc.parseV4, tc.enobufsV4, tc.errV4
					}
					consume(transientV6)
					return 1, tc.parseV6, tc.enobufsV6, tc.errV6
				case "recovery":
					if family == syscall.AF_INET {
						consume(recoveryV4)
					} else {
						consume(recoveryV6)
					}
					return 1, 0, 0, nil
				default:
					t.Fatalf("unknown conntrack test phase %q", phase)
					return 0, 0, 0, nil
				}
			}

			baseline, baselineCount, err := cm.readAndAggregateConntrack(vmIPs, nil)
			if err != nil {
				t.Fatalf("baseline read failed: %v", err)
			}
			if baseline == nil || baselineCount != 1 || baseline.InstanceFlowTotals["vm-1"] != 1 {
				t.Fatalf("baseline aggregate=%p count=%d totals=%v", baseline, baselineCount, baseline.InstanceFlowTotals)
			}
			if got := atomic.LoadUint64(&cm.conntrackRawOK); got != 1 {
				t.Fatalf("baseline raw health=%d, want 1", got)
			}
			if got := atomic.LoadInt64(&cm.conntrackLastSuccessUnix); got != t0.Unix() {
				t.Fatalf("baseline last success=%d, want %d", got, t0.Unix())
			}
			if got := cm.conntrackStaleSeconds(); got != 0 {
				t.Fatalf("baseline stale seconds=%v, want 0", got)
			}

			phase = "failure"
			now = t1
			failed, failedCount, err := cm.readAndAggregateConntrack(vmIPs, nil)
			if err == nil || failed != nil {
				t.Fatalf("failed read returned aggregate=%p count=%d err=%v", failed, failedCount, err)
			}
			if failedCount != 2 {
				t.Fatalf("failed read count=%d, want two transiently consumed flows", failedCount)
			}
			var aggregateErr *conntrackAggregateError
			if !errors.As(err, &aggregateErr) {
				t.Fatalf("failed read error type=%T, want *conntrackAggregateError", err)
			}
			if aggregateErr.Partial != tc.wantPartial {
				t.Fatalf("partial=%v, want %v", aggregateErr.Partial, tc.wantPartial)
			}
			if (aggregateErr.ErrV4 != nil) != tc.wantV4Failure || (aggregateErr.ErrV6 != nil) != tc.wantV6Failure {
				t.Fatalf("family errors v4=%v v6=%v", aggregateErr.ErrV4, aggregateErr.ErrV6)
			}

			lastGood, lastGoodCount, ok := cm.snapshotLastGoodConntrack()
			if !ok || lastGood != baseline || lastGoodCount != baselineCount {
				t.Fatalf("failure replaced last good: got=%p/%d/%v want=%p/%d/true", lastGood, lastGoodCount, ok, baseline, baselineCount)
			}
			if got := lastGood.InstanceFlowTotals["vm-1"]; got != 1 {
				t.Fatalf("transient partial flows leaked into last good: total=%d, want 1", got)
			}
			if got := atomic.LoadUint64(&cm.conntrackRawOK); got != 0 {
				t.Fatalf("failed raw health=%d, want 0", got)
			}
			if got := atomic.LoadInt64(&cm.conntrackLastSuccessUnix); got != t0.Unix() {
				t.Fatalf("failure moved last success=%d, want %d", got, t0.Unix())
			}
			if got := cm.conntrackStaleSeconds(); got != t1.Sub(t0).Seconds() {
				t.Fatalf("failure stale seconds=%v, want %v", got, t1.Sub(t0).Seconds())
			}
			if got := atomic.LoadUint64(&cm.conntrackRawParseErrorsTotal); got != tc.wantParse {
				t.Fatalf("parse errors=%d, want %d", got, tc.wantParse)
			}
			if got := atomic.LoadUint64(&cm.conntrackRawENOBUFSTotal); got != tc.wantENOBUFS {
				t.Fatalf("ENOBUFS=%d, want %d", got, tc.wantENOBUFS)
			}

			phase = "recovery"
			now = t2
			recovered, recoveredCount, err := cm.readAndAggregateConntrack(vmIPs, nil)
			if err != nil || recovered == nil {
				t.Fatalf("recovery aggregate=%p count=%d err=%v", recovered, recoveredCount, err)
			}
			if recovered == baseline || recoveredCount != 2 || recovered.InstanceFlowTotals["vm-1"] != 2 {
				t.Fatalf("recovery did not publish a fresh complete aggregate: got=%p count=%d totals=%v baseline=%p", recovered, recoveredCount, recovered.InstanceFlowTotals, baseline)
			}
			lastGood, lastGoodCount, ok = cm.snapshotLastGoodConntrack()
			if !ok || lastGood != recovered || lastGoodCount != recoveredCount {
				t.Fatalf("recovery last good=%p/%d/%v, want=%p/%d/true", lastGood, lastGoodCount, ok, recovered, recoveredCount)
			}
			if got := atomic.LoadUint64(&cm.conntrackRawOK); got != 1 {
				t.Fatalf("recovery raw health=%d, want 1", got)
			}
			if got := atomic.LoadInt64(&cm.conntrackLastSuccessUnix); got != t2.Unix() {
				t.Fatalf("recovery last success=%d, want %d", got, t2.Unix())
			}
			if got := cm.conntrackStaleSeconds(); got != 0 {
				t.Fatalf("recovery stale seconds=%v, want 0", got)
			}
			if got := atomic.LoadUint64(&cm.conntrackRawParseErrorsTotal); got != tc.wantParse {
				t.Fatalf("recovery reset cumulative parse errors=%d, want %d", got, tc.wantParse)
			}
			if got := atomic.LoadUint64(&cm.conntrackRawENOBUFSTotal); got != tc.wantENOBUFS {
				t.Fatalf("recovery reset cumulative ENOBUFS=%d, want %d", got, tc.wantENOBUFS)
			}
		})
	}
}

func TestDataIntegrityConntrackRecoveryRebaselinesBehaviorDeltas(t *testing.T) {
	cm := newBehaviorStateTestManager()
	cm.conntrackIPv4Enable = true
	cm.conntrackIPv6Enable = true

	now := time.Now().Truncate(time.Second)
	phase := "baseline"
	vmIP := IPStrToKey("10.0.0.50")
	vmIPs := []VMIPIdentity{{InstanceUUID: "vm-1", IP: vmIP}}
	baselineRemote := IPStrToKey("198.51.100.50")
	recoveryRemote := IPStrToKey("203.0.113.50")
	cm.conntrackNowOverride = func() time.Time { return now }
	cm.conntrackDumpFamilyOverride = func(
		family int,
		_ int,
		_ time.Duration,
		consume func(ConntrackFlowLite),
	) (uint64, uint64, uint64, error) {
		if family == syscall.AF_INET6 {
			if phase == "failure" {
				return 0, 0, 0, syscall.EAGAIN
			}
			return 0, 0, 0, nil
		}
		switch phase {
		case "baseline":
			consume(ConntrackFlowLite{SrcIP: vmIP, DstIP: baselineRemote, SrcPort: 41000, DstPort: 443, Proto: 6, Status: IPS_SEEN_REPLY})
			return 1, 0, 0, nil
		case "failure":
			consume(ConntrackFlowLite{SrcIP: vmIP, DstIP: IPStrToKey("192.0.2.50"), SrcPort: 42000, DstPort: 22, Proto: 6})
			return 1, 0, 0, syscall.EAGAIN
		case "recovery":
			consume(ConntrackFlowLite{SrcIP: vmIP, DstIP: recoveryRemote, SrcPort: 43000, DstPort: 8443, Proto: 6, Status: IPS_SEEN_REPLY})
			return 1, 0, 0, nil
		default:
			t.Fatalf("unknown conntrack test phase %q", phase)
			return 0, 0, 0, nil
		}
	}

	collectBehavior := func(agg *ConntrackAgg, fresh bool) map[string]float64 {
		metrics := make([]prometheus.Metric, 0, 32)
		cm.calculateConntrackMetrics(
			[]IP{{Address: "10.0.0.50", Family: "ipv4"}},
			agg,
			map[string]struct{}{"10.0.0.50": {}},
			nil,
			1000,
			fresh,
			"domain", "server", "vm-1", "project", "project-name", "user",
			&metrics,
		)
		return behaviorIntervalMetricValues(t, metrics)
	}

	baseline, _, err := cm.readAndAggregateConntrack(vmIPs, nil)
	if err != nil {
		t.Fatalf("baseline read failed: %v", err)
	}
	baselineValues := collectBehavior(baseline, true)
	if baselineValues["oie_instance_outbound_new_remotes"] != 1 || baselineValues["oie_instance_outbound_new_dst_ports"] != 1 {
		t.Fatalf("baseline deltas=%v, want initial remote and port", baselineValues)
	}

	key := BehaviorKey{InstanceUUID: "vm-1", IP: vmIP}
	idx := shardIndexBehavior(behaviorIdentityKey{InstanceUUID: "vm-1", IP: vmIP, Direction: "outbound"})
	if _, ok := cm.outboundPrev[idx][key].remotes[baselineRemote]; !ok {
		t.Fatal("baseline remote was not stored")
	}

	phase = "failure"
	now = now.Add(30 * time.Second)
	failed, _, err := cm.readAndAggregateConntrack(vmIPs, nil)
	if err == nil || failed != nil {
		t.Fatalf("failure aggregate=%p err=%v", failed, err)
	}
	cm.beginBehaviorStateFreeze(now)
	lastGood, _, ok := cm.snapshotLastGoodConntrack()
	if !ok || lastGood != baseline {
		t.Fatal("failure did not retain baseline aggregate")
	}
	frozenValues := collectBehavior(lastGood, false)
	if frozenValues["oie_instance_outbound_new_remotes"] != 1 || frozenValues["oie_instance_outbound_new_dst_ports"] != 1 {
		t.Fatalf("failure did not retain last fresh interval deltas: %v", frozenValues)
	}
	if _, ok := cm.outboundPrev[idx][key].remotes[baselineRemote]; !ok || len(cm.outboundPrev[idx][key].remotes) != 1 {
		t.Fatalf("failure mutated remote baseline: %v", cm.outboundPrev[idx][key].remotes)
	}
	alertKey := behaviorAlertKey{InstanceUUID: "vm-1", IP: vmIP, Direction: "outbound", Kind: "outbound_horizontal_scan_suspected"}
	cm.behaviorPersist[alertKey] = &behaviorPersistState{Hits: 2, FirstSeenUnix: now.Unix() - 10, LastSeenUnix: now.Unix()}
	ident := behaviorIdentityKey{InstanceUUID: "vm-1", IP: vmIP, Direction: "outbound"}
	cm.miningAlerts[ident] = &miningAlertState{Hits: 2, FirstSeenUnix: now.Unix() - 10, LastSeenUnix: now.Unix(), Active: true}
	behaviorEvents := 0
	cm.LogThreat = func(string, string, string, string, string, string, string, ...interface{}) {
		behaviorEvents++
	}

	phase = "recovery"
	now = now.Add(45 * time.Second)
	recovered, _, err := cm.readAndAggregateConntrack(vmIPs, nil)
	if err != nil || recovered == nil {
		t.Fatalf("recovery aggregate=%p err=%v", recovered, err)
	}
	if shifted := cm.resumeBehaviorStateClock(now); shifted != 45 {
		t.Fatalf("recovery clock shift=%d, want 45", shifted)
	}
	if !cm.behaviorNeedsRecoveryRebaseline() {
		t.Fatal("recovery did not request a one-sample behavior rebaseline")
	}
	recoveryValues := collectBehavior(recovered, true)
	if recoveryValues["oie_instance_outbound_new_remotes"] != 0 || recoveryValues["oie_instance_outbound_new_dst_ports"] != 0 {
		t.Fatalf("recovery produced an artificial delta spike: %v", recoveryValues)
	}
	if _, ok := cm.outboundPrev[idx][key].remotes[recoveryRemote]; !ok || len(cm.outboundPrev[idx][key].remotes) != 1 {
		t.Fatalf("recovery did not advance the remote baseline exactly to the fresh snapshot: %v", cm.outboundPrev[idx][key].remotes)
	}
	if _, ok := cm.outboundPrevDstPorts[idx][key].ports[8443]; !ok || len(cm.outboundPrevDstPorts[idx][key].ports) != 1 {
		t.Fatalf("recovery did not advance the port baseline exactly to the fresh snapshot: %v", cm.outboundPrevDstPorts[idx][key].ports)
	}
	if behaviorEvents != 0 {
		t.Fatalf("recovery rebaseline emitted %d behavior/mining events", behaviorEvents)
	}
	if got := cm.behaviorPersist[alertKey]; got != nil {
		t.Fatalf("changed recovery evidence retained generic persistence: %+v", got)
	}
	if got := cm.miningAlerts[ident]; got == nil || got.Hits != 0 || got.Active || got.Confirmed {
		t.Fatalf("clean recovery evidence retained mining candidate: %+v", got)
	}
	if _, available := cm.behaviorSeveritySnapshotAvailable(ident); available {
		t.Fatal("recovery rebaseline exposed a retained severity as a fresh observation")
	}
	ewma := cm.behaviorEWMA[idx][ident]
	if ewma == nil || ewma.Flows.Fast != 1 || ewma.Flows.Slow != 1 || ewma.UniqueRemotes.Fast != 1 || ewma.UniqueRemotes.Slow != 1 {
		t.Fatalf("recovery did not reset behavior EWMA to the fresh observation: %+v", ewma)
	}
	if ewma.LastInterval.NewRemotes != 0 || ewma.LastInterval.NewDstPorts != 0 || !ewma.LastInterval.Initialized {
		t.Fatalf("recovery interval baseline=%+v, want initialized zero deltas", ewma.LastInterval)
	}
	cm.finishBehaviorRecoveryRebaseline()
	if cm.behaviorNeedsRecoveryRebaseline() {
		t.Fatal("recovery rebaseline flag survived the completed sample")
	}
}

func TestDataIntegrityInitialConntrackFailureOmitsUnavailableWorkloadFamilies(t *testing.T) {
	mc, err := NewMetricsCollector(CollectorConfig{
		LibvirtURI:             "qemu:///system",
		WorkerCount:            1,
		CollectionInterval:     time.Hour,
		ConntrackIPv4Enable:    true,
		ConntrackIPv6Enable:    false,
		OutboundBehaviorEnable: true,
		Severity: SeverityConfig{
			ResourceWeight: 1,
			BehaviorWeight: 1,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { close(mc.shutdownChan) })

	domain, instanceUUID := dataIntegrityDomain(0x71, "instance-data-integrity-initial-conntrack-failure")
	mc.im.domainMeta[instanceUUID] = &DomainStatic{
		Name:         "server-initial-conntrack-failure",
		InstanceUUID: instanceUUID,
		ProjectUUID:  "project",
		ProjectName:  "project-name",
		UserUUID:     "user",
		VCPUCount:    1,
		MemMB:        1024,
		FixedIPs:     []IP{{Address: "10.0.0.71", Family: "ipv4"}},
		LastUpdated:  time.Now(),
	}
	record := libvirt.DomainStatsRecord{
		Dom: domain,
		Params: []libvirt.TypedParam{
			typedParam("state.state", int32(libvirt.DomainRunning)),
			typedParam("balloon.maximum", uint64(1024*1024)),
			typedParam("balloon.current", uint64(1024*1024)),
			typedParam("balloon.usable", uint64(256*1024)),
		},
	}
	mc.fetchDomainStatsOverride = func() ([]libvirt.DomainStatsRecord, float64, error) {
		return []libvirt.DomainStatsRecord{record}, 0.01, nil
	}
	mc.cm.conntrackDumpFamilyOverride = func(int, int, time.Duration, func(ConntrackFlowLite)) (uint64, uint64, uint64, error) {
		return 0, 0, 0, syscall.EAGAIN
	}

	metrics := dataIntegrityRunHeavyCollection(t, mc)
	for name, want := range map[string]float64{
		"oie_host_conntrack_raw_ok":                         0,
		"oie_host_conntrack_last_success_timestamp_seconds": 0,
		"oie_host_conntrack_stale_seconds":                  -1,
		"oie_host_conntrack_read_errors_total":              1,
		"oie_host_libvirt_ok":                               1,
		"oie_host_libvirt_active_vms":                       1,
	} {
		if got, ok := dataIntegrityMetricFamilyValue(t, metrics, name); !ok || got != want {
			t.Fatalf("%s=(%v,%v), want (%v,true)", name, got, ok, want)
		}
	}
	if !dataIntegrityHasMetricFamily(metrics, "oie_instance_info") || !dataIntegrityHasMetricFamily(metrics, "oie_instance_resource_severity") {
		t.Fatal("fresh Libvirt fixture did not emit its independent instance/resource families")
	}
	for _, name := range []string{
		"oie_host_conntrack_entries",
		"oie_host_conntrack_utilization",
		"oie_instance_conntrack_ip_flows",
		"oie_instance_outbound_flows",
		"oie_instance_outbound_new_remotes",
		"oie_instance_mining_suspected",
		"oie_instance_behavior_severity",
		"oie_instance_threat_list_severity",
		"oie_instance_attention_severity",
	} {
		if dataIntegrityHasMetricFamily(metrics, name) {
			t.Fatalf("initial Conntrack failure emitted unavailable family %s", name)
		}
	}
}
