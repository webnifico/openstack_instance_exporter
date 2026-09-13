package main

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type replayCalibrationReplayResult struct {
	Metrics               map[string]float64
	Severity              float64
	StateTransitions      []string
	Alert                 string
	DetectionDelaySeconds int64
	RecoveryBehavior      string
}

func replayCalibrationAppendTransition(transitions []string, value string) []string {
	if value == "" || (len(transitions) > 0 && transitions[len(transitions)-1] == value) {
		return transitions
	}
	return append(transitions, value)
}

func replayCalibrationBehaviorFeature(input replayCalibrationReplayInput) BehaviorFeature {
	topRemote := IPStrToKey("198.51.100.42")
	feature := BehaviorFeature{
		Direction:               input.Direction,
		ThresholdFlows:          input.ThresholdFlows,
		PublicRemotes:           input.UniqueRemotes,
		Flows:                   input.Flows,
		UniqueRemotes:           input.UniqueRemotes,
		NewRemotes:              input.NewRemotes,
		UniqueDstPorts:          input.UniqueDstPorts,
		NewDstPorts:             input.NewDstPorts,
		MaxSingleRemote:         input.MaxSingleRemote,
		MaxSingleDstPort:        input.MaxSingleDstPort,
		TopDstPort:              input.TopDstPort,
		UnrepliedRatio:          input.UnrepliedRatio,
		TCPCount:                input.TCPFlows,
		TCPUnrepliedRatio:       input.TCPUnrepliedRatio,
		TCPTopRemote:            topRemote,
		TCPTopRemoteFlows:       input.TCPTopRemoteFlows,
		TCPTopDstPort:           input.TopDstPort,
		TCPTopDstPortFlows:      input.TCPTopDstPortFlows,
		UDPCount:                input.UDPFlows,
		UDPUniqueRemotes:        input.UDPUniqueRemotes,
		UDPUnrepliedRatio:       input.UDPUnrepliedRatio,
		UDPTopRemote:            topRemote,
		UDPTopRemoteFlows:       input.UDPTopRemoteFlows,
		UDPTopDstPort:           input.TopDstPort,
		UDPTopDstPortFlows:      input.UDPTopDstPortFlows,
		SMTPFlows:               input.SMTPFlows,
		SMTPUniqueRemotes:       input.SMTPUniqueRemotes,
		SMTPUnrepliedRatio:      input.SMTPUnrepliedRatio,
		SMTPTopRemote:           topRemote,
		SMTPTopRemoteFlows:      input.MaxSingleRemote,
		SMTPTopDstPort:          input.TopDstPort,
		SMTPTopDstPortFlows:     input.SMTPFlows,
		AdminPortFlows:          input.AdminPortFlows,
		AdminUniqueRemotes:      input.AdminUniqueRemotes,
		AdminNewRemotes:         input.AdminNewRemotes,
		AdminUnrepliedRatio:     input.AdminUnrepliedRatio,
		AdminTopRemote:          topRemote,
		AdminTopRemoteFlows:     input.MaxSingleRemote,
		AdminTopDstPort:         input.TopDstPort,
		AdminTopDstPortFlows:    input.AdminPortFlows,
		HostImpactPercent:       input.HostImpactPercent,
		InstanceFlowTotal:       input.InstanceFlowTotal,
		HostPressureOwner:       input.HostPressureOwner,
		BytesPerFlowAvailable:   true,
		PacketsPerFlowAvailable: true,
		ConntrackAcct:           true,
	}
	if input.MiningPort != 0 {
		stats := newBehaviorStats(false)
		remotes := input.MiningUniqueRemotes
		if remotes <= 0 {
			remotes = 1
		}
		for index := 0; index < input.MiningFlows; index++ {
			remote := IPStrToKey(fmt.Sprintf("198.51.100.%d", 50+(index%remotes)))
			status := uint32(0)
			if index < input.MiningRepliedFlows {
				status = IPS_SEEN_REPLY | IPS_ASSURED
			}
			stats.updateOutboundMining(remote, input.MiningPort, 6, status, true)
		}
		feature.MiningHigh, feature.MiningShared = stats.summarizeMining(nil)
		feature.Mining = selectMiningDetectionEvidence(feature, newBehaviorScaler(1))
		feature.StratumFlows = feature.MiningHigh.Flows + feature.MiningShared.Flows
		feature.StratumRepliedFlows = feature.MiningHigh.RepliedFlows + feature.MiningShared.RepliedFlows
	}
	return feature
}

func replayCalibrationBehaviorMetricSet(input replayCalibrationReplayInput, severity float64) map[string]float64 {
	prefix := "oie_instance_" + input.Direction + "_"
	metrics := map[string]float64{
		prefix + "flows":                     float64(input.Flows),
		prefix + "unique_remotes":            float64(input.UniqueRemotes),
		prefix + "new_remotes":               float64(input.NewRemotes),
		prefix + "unique_dst_ports":          float64(input.UniqueDstPorts),
		prefix + "new_dst_ports":             float64(input.NewDstPorts),
		prefix + "max_flows_single_remote":   float64(input.MaxSingleRemote),
		prefix + "max_flows_single_dst_port": float64(input.MaxSingleDstPort),
		"oie_instance_behavior_severity":     severity,
	}
	if input.CPUPercent > 0 {
		metrics["oie_instance_cpu_vcpu_percent"] = input.CPUPercent
	}
	if input.DiskReadIOPS > 0 {
		metrics["oie_instance_disk_read_iops"] = input.DiskReadIOPS
	}
	if input.DiskWriteIOPS > 0 {
		metrics["oie_instance_disk_write_iops"] = input.DiskWriteIOPS
	}
	return metrics
}

func replayCalibrationRunBehaviorReplay(t *testing.T, fixture replayCalibrationReplayFixture) replayCalibrationReplayResult {
	t.Helper()
	input := fixture.Input
	if input.Direction != "outbound" && input.Direction != "inbound" {
		t.Fatalf("fixture %q behavior direction=%q", fixture.ID, input.Direction)
	}
	cm := newBehaviorStateTestManager()
	feature := replayCalibrationBehaviorFeature(input)
	ident := behaviorIdentityKey{InstanceUUID: "replay-vm", IP: IPStrToKey("192.0.2.10"), Direction: input.Direction}
	persistence := behaviorPersistState{}
	emission := behaviorEmitState{}
	result := replayCalibrationReplayResult{Alert: "none", DetectionDelaySeconds: -1}
	startUnix := int64(1_700_000_000)
	miningConditionStart := int64(-1)

	for cycle := 0; cycle < input.Cycles; cycle++ {
		nowUnix := startUnix + int64(cycle)*input.IntervalSeconds
		classification := cm.classifyBehavior(
			feature,
			input.HostImpactPercent/100,
			behaviorAnomalies{Signal: input.AnomalySignal},
			map[uint16]int{input.TopDstPort: input.MaxSingleDstPort},
		)
		miningOutcome := miningAlertOutcome{}
		if feature.Direction == "outbound" {
			miningOutcome = cm.updateMiningAlertState(feature, ident, nowUnix)
		}
		severity := float64(behaviorSeverityScore(feature)) / 100
		severity = applyConfirmedBehaviorPriorityFloor(severity, miningOutcome) * 100
		result.Severity = severity

		switch {
		case feature.Mining.Valid && classification.Kind == miningBehaviorKind:
			if miningOutcome.ShouldEmit {
				result.StateTransitions = replayCalibrationAppendTransition(result.StateTransitions, "alerted")
				if result.Alert == "none" {
					result.Alert = miningBehaviorKind
					result.DetectionDelaySeconds = nowUnix - startUnix
				}
			} else if miningOutcome.Confirmed {
				result.StateTransitions = replayCalibrationAppendTransition(result.StateTransitions, "corroboration_required")
			} else {
				result.StateTransitions = replayCalibrationAppendTransition(result.StateTransitions, "candidate")
			}
		case feature.Mining.Valid && feature.Direction == "outbound":
			if miningOutcome.Confirmed {
				result.StateTransitions = replayCalibrationAppendTransition(result.StateTransitions, "corroboration_required")
				if miningConditionStart < 0 {
					miningConditionStart = nowUnix
				}
				cpuThreshold := 35.0
				if feature.Mining.Confidence == miningPortConfidenceHighPersistent {
					cpuThreshold = 40
				} else if feature.Mining.Confidence == miningPortConfidenceSharedPersistent {
					cpuThreshold = 60
				}
				if input.CPUPercent >= cpuThreshold && nowUnix-miningConditionStart >= 60 {
					result.StateTransitions = replayCalibrationAppendTransition(result.StateTransitions, "prometheus_alerted")
					if result.Alert == "none" {
						result.Alert = "OpenStackInstanceMiningSuspected"
						result.DetectionDelaySeconds = nowUnix - startUnix
					}
				}
			} else {
				result.StateTransitions = replayCalibrationAppendTransition(result.StateTransitions, "candidate")
			}
		case classification.Hit:
			evidence := cm.buildBehaviorAlertEvidence(feature, IPStrToKey("198.51.100.42"), true, classification.Kind)
			transition := evaluateBehaviorAlertTransition(behaviorAlertTransitionInput{
				NowUnix: nowUnix, Kind: classification.Kind, Feature: feature, Evidence: evidence,
				Persistence: persistence, Emission: emission,
			})
			persistence = transition.Persistence
			emission = transition.Emission
			if transition.ShouldEmit {
				result.StateTransitions = replayCalibrationAppendTransition(result.StateTransitions, "alerted")
				if result.Alert == "none" {
					result.Alert = classification.Kind
					result.DetectionDelaySeconds = nowUnix - startUnix
				}
			} else if transition.PersistenceSatisfied {
				result.StateTransitions = replayCalibrationAppendTransition(result.StateTransitions, "active")
			} else {
				result.StateTransitions = replayCalibrationAppendTransition(result.StateTransitions, "candidate")
			}
		default:
			persistence = behaviorPersistState{}
			result.StateTransitions = replayCalibrationAppendTransition(result.StateTransitions, "clean")
		}
		if miningOutcome.Active && miningOutcome.Confirmed {
			if result.Metrics == nil {
				result.Metrics = make(map[string]float64)
			}
			result.Metrics["oie_instance_mining_suspected"] = 1
		}
	}

	baseMetrics := replayCalibrationBehaviorMetricSet(input, result.Severity)
	for name, value := range baseMetrics {
		if result.Metrics == nil {
			result.Metrics = make(map[string]float64)
		}
		result.Metrics[name] = value
	}
	clean := BehaviorFeature{Direction: input.Direction}
	if got := cm.classifyBehavior(clean, 0, behaviorAnomalies{}, nil); got.Hit {
		t.Fatalf("fixture %q clean recovery classified as %+v", fixture.ID, got)
	}
	if input.Direction == "outbound" {
		cm.updateMiningAlertState(clean, ident, startUnix+int64(input.Cycles)*input.IntervalSeconds)
		if snapshot := cm.miningAlertSnapshot(ident); snapshot.Active || snapshot.Confirmed {
			t.Fatalf("fixture %q clean recovery retained mining state: %+v", fixture.ID, snapshot)
		}
	}
	if replayCalibrationContainsString(result.StateTransitions, "candidate") || replayCalibrationContainsString(result.StateTransitions, "corroboration_required") || replayCalibrationContainsString(result.StateTransitions, "alerted") || replayCalibrationContainsString(result.StateTransitions, "prometheus_alerted") {
		result.RecoveryBehavior = "clean_cycle_resets_state"
	} else {
		result.RecoveryBehavior = "remains_clean"
	}
	return result
}

func replayCalibrationThreatMetricNames(source string) (string, string) {
	switch source {
	case "TOREXIT":
		return "oie_instance_threat_tor_exit_active_flows", "oie_instance_threat_tor_exit_contacts_total"
	case "TORRELAY":
		return "oie_instance_threat_tor_relay_active_flows", "oie_instance_threat_tor_relay_contacts_total"
	case "EMERGING":
		return "oie_instance_threat_emergingthreats_active_flows", "oie_instance_threat_emergingthreats_contacts_total"
	case "CUSTOMLIST":
		return "oie_instance_threat_customlist_active_flows", "oie_instance_threat_customlist_contacts_total"
	default:
		return "", ""
	}
}

func replayCalibrationThreatProvider(source string) *IPThreatProvider {
	provider := newThreatStateTestProvider(source)
	active, contacts := replayCalibrationThreatMetricNames(source)
	provider.InstanceActiveMetricName = active
	provider.InstanceContactsMetricName = contacts
	return provider
}

func replayCalibrationThreatHits(count int) map[PairKey]ConntrackEntry {
	vm := IPStrToKey("192.0.2.10")
	remote := IPStrToKey("198.51.100.200")
	hits := make(map[PairKey]ConntrackEntry, count)
	for index := 0; index < count; index++ {
		port := uint16(41000 + index)
		key := MakePairKey(vm, port, remote, 443, 6)
		hits[key] = ConntrackEntry{Src: "192.0.2.10", Dst: "198.51.100.200", SrcPort: port, DstPort: 443, Proto: 6, Status: IPS_SEEN_REPLY}
	}
	return hits
}

func replayCalibrationRunThreatReplay(t *testing.T, fixture replayCalibrationReplayFixture) replayCalibrationReplayResult {
	t.Helper()
	input := fixture.Input
	providers := make([]*IPThreatProvider, 0, len(input.ThreatSources))
	for _, source := range input.ThreatSources {
		provider := replayCalibrationThreatProvider(source)
		if provider.InstanceActiveMetricName == "" {
			t.Fatalf("fixture %q unknown threat source %q", fixture.ID, source)
		}
		providers = append(providers, provider)
	}
	tm := newThreatStateTestManager(providers...)
	mc := &MetricsCollector{tm: tm, intelHistory: make(map[string]*IntelHistory), threatEWMATau: defaultThreatEWMATau}
	hits := replayCalibrationThreatHits(input.ThreatActiveFlows)
	providerHits := make(map[string]map[string]map[PairKey]ConntrackEntry)
	included := make(map[string]struct{})
	for _, provider := range providers {
		providerHits[provider.Name] = map[string]map[PairKey]ConntrackEntry{"replay-vm": hits}
		included[provider.Name] = struct{}{}
	}
	agg := &ConntrackAgg{
		VMIndex:                 map[VMIPIdentity]uint32{{InstanceUUID: "replay-vm", IP: IPStrToKey("192.0.2.10")}: 0},
		ProviderSourcesIncluded: included,
		ProviderHits:            providerHits,
		CombinedThreatHits:      map[string]map[PairKey]ConntrackEntry{"replay-vm": hits},
	}
	if input.ThreatOverlapCopies > 0 && input.ThreatOverlapCopies != len(input.ThreatSources) {
		t.Fatalf("fixture %q overlap copies=%d sources=%d", fixture.ID, input.ThreatOverlapCopies, len(input.ThreatSources))
	}
	if got := combinedThreatActiveFlows(agg, "replay-vm"); got != uint64(input.ThreatActiveFlows) {
		t.Fatalf("fixture %q deduplicated active flows=%d, want %d", fixture.ID, got, input.ThreatActiveFlows)
	}

	result := replayCalibrationReplayResult{Metrics: make(map[string]float64), Alert: "none", DetectionDelaySeconds: -1}
	startUnix := int64(1_700_100_000)
	qualifyingSince := int64(-1)
	for cycle := 0; cycle < input.Cycles; cycle++ {
		nowUnix := startUnix + int64(cycle)*input.IntervalSeconds
		agg.ObservationUnix = nowUnix
		agg.ObservationTimeSet = true
		var metrics []prometheus.Metric
		severity, available := mc.collectDomainThreatSignals(
			agg,
			map[string]struct{}{"192.0.2.10": {}},
			"domain", "server", "replay-vm", "project", "project-name", "user",
			true, true, true, &metrics,
		)
		if !available {
			t.Fatalf("fixture %q fresh threat replay became unavailable", fixture.ID)
		}
		result.Severity = severity * 100
		result.StateTransitions = replayCalibrationAppendTransition(result.StateTransitions, "observed")
		if result.Severity >= 40 {
			if qualifyingSince < 0 {
				qualifyingSince = nowUnix
			}
			if nowUnix-qualifyingSince >= 300 {
				alert := "OpenStackInstanceThreatScoreHigh"
				if result.Severity >= 85 {
					alert = "OpenStackInstanceThreatScoreSevere"
				}
				result.StateTransitions = replayCalibrationAppendTransition(result.StateTransitions, "alerted")
				if result.Alert == "none" {
					result.Alert = alert
					result.DetectionDelaySeconds = nowUnix - startUnix
				}
			}
		} else {
			qualifyingSince = -1
		}
	}
	for _, source := range input.ThreatSources {
		active, contacts := replayCalibrationThreatMetricNames(source)
		result.Metrics[active] = float64(input.ThreatActiveFlows)
		result.Metrics[contacts] = float64(input.ThreatActiveFlows)
	}
	result.Metrics["oie_instance_threat_list_severity"] = result.Severity

	clean := &ConntrackAgg{
		VMIndex:                 map[VMIPIdentity]uint32{{InstanceUUID: "replay-vm", IP: IPStrToKey("192.0.2.10")}: 0},
		ObservationUnix:         startUnix + int64(input.Cycles)*input.IntervalSeconds,
		ObservationTimeSet:      true,
		ProviderSourcesIncluded: included,
		ProviderHits:            make(map[string]map[string]map[PairKey]ConntrackEntry),
		CombinedThreatHits:      map[string]map[PairKey]ConntrackEntry{"replay-vm": {}},
	}
	for _, provider := range providers {
		clean.ProviderHits[provider.Name] = map[string]map[PairKey]ConntrackEntry{"replay-vm": {}}
	}
	var cleanMetrics []prometheus.Metric
	if _, available := mc.collectDomainThreatSignals(
		clean, map[string]struct{}{"192.0.2.10": {}},
		"domain", "server", "replay-vm", "project", "project-name", "user",
		true, true, true, &cleanMetrics,
	); !available {
		t.Fatalf("fixture %q clean threat recovery became unavailable", fixture.ID)
	}
	for _, provider := range providers {
		if len(provider.PrevHits["replay-vm"]) != 0 {
			t.Fatalf("fixture %q clean threat recovery retained active identities", fixture.ID)
		}
	}
	result.RecoveryBehavior = "fresh_zero_replaces_active_hits"
	return result
}

func replayCalibrationConntrackFailureError(event string) (error, uint64, uint64) {
	switch event {
	case "truncated_dump":
		return errors.New("truncated Netlink dump"), 1, 0
	case "malformed_netlink_message":
		return errors.New("malformed Netlink message"), 1, 0
	case "enobufs":
		return syscall.ENOBUFS, 0, 1
	default:
		return syscall.EAGAIN, 0, 0
	}
}

func replayCalibrationRunConntrackFailure(t *testing.T, fixture replayCalibrationReplayFixture) replayCalibrationReplayResult {
	t.Helper()
	input := fixture.Input
	vm4 := IPStrToKey("192.0.2.10")
	vm6 := IPStrToKey("2001:db8::10")
	vmIPs := []VMIPIdentity{{InstanceUUID: "replay-vm", IP: vm4}, {InstanceUUID: "replay-vm", IP: vm6}}
	phase := "baseline"
	now := time.Unix(1_700_200_000, 0)
	cm := &ConntrackManager{conntrackIPv4Enable: true, conntrackIPv6Enable: true, conntrackNowOverride: func() time.Time { return now }}
	cm.conntrackDumpFamilyOverride = func(family int, _ int, _ time.Duration, consume func(ConntrackFlowLite)) (uint64, uint64, uint64, error) {
		if phase == "baseline" || phase == "recovery" {
			if family == syscall.AF_INET {
				consume(ConntrackFlowLite{SrcIP: vm4, DstIP: IPStrToKey("198.51.100.10"), SrcPort: 41000, DstPort: 443, Proto: 6, Status: IPS_SEEN_REPLY})
				return 1, 0, 0, nil
			}
			return 0, 0, 0, nil
		}
		errValue, parseErrors, enobufs := replayCalibrationConntrackFailureError(input.Event)
		failFamily := family == syscall.AF_INET || (input.Event != "ipv4_conntrack_failure" && family == syscall.AF_INET6)
		if input.Event == "ipv6_conntrack_failure" {
			failFamily = family == syscall.AF_INET6
		}
		if failFamily {
			return 0, parseErrors, enobufs, errValue
		}
		return 0, 0, 0, nil
	}
	baseline, baselineCount, err := cm.readAndAggregateConntrack(vmIPs, nil)
	if err != nil || baseline == nil || baselineCount != 1 {
		t.Fatalf("fixture %q baseline aggregate=%p count=%d err=%v", fixture.ID, baseline, baselineCount, err)
	}
	phase = "failure"
	failureCycles := input.FailureCycles
	if failureCycles <= 0 {
		failureCycles = 1
	}
	for cycle := 0; cycle < failureCycles; cycle++ {
		now = now.Add(time.Duration(input.IntervalSeconds) * time.Second)
		failed, _, err := cm.readAndAggregateConntrack(vmIPs, nil)
		if err == nil || failed != nil {
			t.Fatalf("fixture %q failure cycle %d aggregate=%p err=%v", fixture.ID, cycle, failed, err)
		}
		lastGood, count, ok := cm.snapshotLastGoodConntrack()
		if !ok || lastGood != baseline || count != baselineCount {
			t.Fatalf("fixture %q failure replaced last-good snapshot", fixture.ID)
		}
	}
	phase = "recovery"
	now = now.Add(time.Duration(input.IntervalSeconds) * time.Second)
	recovered, recoveredCount, err := cm.readAndAggregateConntrack(vmIPs, nil)
	if err != nil || recovered == nil || recovered == baseline || recoveredCount != 1 {
		t.Fatalf("fixture %q recovery aggregate=%p count=%d err=%v", fixture.ID, recovered, recoveredCount, err)
	}
	metrics := map[string]float64{
		"oie_host_conntrack_raw_ok":                         float64(atomic.LoadUint64(&cm.conntrackRawOK)),
		"oie_host_conntrack_last_success_timestamp_seconds": float64(atomic.LoadInt64(&cm.conntrackLastSuccessUnix)),
		"oie_host_conntrack_read_errors_total":              float64(failureCycles),
	}
	if got := atomic.LoadUint64(&cm.conntrackRawParseErrorsTotal); got > 0 {
		metrics["oie_host_conntrack_raw_parse_errors_total"] = float64(got)
	}
	if got := atomic.LoadUint64(&cm.conntrackRawENOBUFSTotal); got > 0 {
		metrics["oie_host_conntrack_raw_enobufs_total"] = float64(got)
	}
	return replayCalibrationReplayResult{
		Metrics: metrics, Severity: 0,
		StateTransitions: []string{"fresh", "unavailable_retained", "rebaseline", "fresh"},
		Alert:            "none", DetectionDelaySeconds: -1,
		RecoveryBehavior: "fresh_complete_snapshot_replaces_retained",
	}
}

func replayCalibrationRunLifecycleReplay(t *testing.T, fixture replayCalibrationReplayFixture) replayCalibrationReplayResult {
	t.Helper()
	input := fixture.Input
	if input.Event != fixture.ID {
		t.Fatalf("fixture %q event=%q", fixture.ID, input.Event)
	}
	if strings.Contains(fixture.ID, "conntrack_failure") || fixture.ID == "truncated_dump" || fixture.ID == "malformed_netlink_message" || fixture.ID == "enobufs" || fixture.ID == "timeout" {
		return replayCalibrationRunConntrackFailure(t, fixture)
	}
	base := replayCalibrationReplayResult{Metrics: make(map[string]float64), Alert: "none", DetectionDelaySeconds: -1}
	switch fixture.ID {
	case "libvirt_outage":
		mc := &MetricsCollector{}
		start := time.Unix(1_700_300_000, 0)
		mc.recordLibvirtCollectionResult(true, start)
		mc.recordLibvirtCollectionResult(false, start.Add(time.Duration(input.IntervalSeconds)*time.Second))
		ok, last, stale := mc.libvirtSourceHealthSnapshot(start.Add(time.Duration(input.IntervalSeconds) * time.Second))
		if ok != 0 || last != float64(start.Unix()) || stale <= 0 {
			t.Fatalf("libvirt outage health=(%v,%v,%v)", ok, last, stale)
		}
		mc.recordLibvirtCollectionResult(true, start.Add(2*time.Duration(input.IntervalSeconds)*time.Second))
		ok, last, stale = mc.libvirtSourceHealthSnapshot(start.Add(2 * time.Duration(input.IntervalSeconds) * time.Second))
		if ok != 1 || stale != 0 {
			t.Fatalf("libvirt recovery health=(%v,%v,%v)", ok, last, stale)
		}
		base.Metrics["oie_host_libvirt_ok"] = ok
		base.Metrics["oie_host_libvirt_last_success_timestamp_seconds"] = last
		base.Metrics["oie_host_libvirt_stale_seconds"] = stale
		base.StateTransitions = []string{"fresh", "source_unavailable", "retained", "fresh"}
		base.RecoveryBehavior = "fresh_cycle_replaces_retained_inventory"
	case "per_domain_libvirt_failure":
		cm := newBehaviorStateTestManager()
		start := time.Unix(1_700_310_000, 0)
		cm.observeBehaviorInstanceLifecycle("replay-vm", true, true, start)
		cm.observeBehaviorInstanceLifecycle("replay-vm", false, false, start.Add(15*time.Second))
		if _, frozen := cm.snapshotBehaviorFrozenInstances()["replay-vm"]; !frozen {
			t.Fatal("per-domain Libvirt failure did not freeze instance state")
		}
		if !cm.observeBehaviorInstanceLifecycle("replay-vm", true, true, start.Add(45*time.Second)) {
			t.Fatal("per-domain Libvirt recovery was not identified")
		}
		if shift := cm.takeBehaviorInstanceRecoveryShiftSeconds("replay-vm"); shift != 30 {
			t.Fatalf("per-domain recovery shift=%d, want 30", shift)
		}
		cm.finishBehaviorInstanceRecovery("replay-vm")
		base.Metrics["oie_host_libvirt_ok"] = 1
		base.Metrics["oie_instance_behavior_severity"] = 0
		base.StateTransitions = []string{"fresh", "instance_frozen", "rebaseline", "fresh"}
		base.RecoveryBehavior = "one_fresh_sample_rebaselines_instance"
	case "counter_reset":
		im := newResourceTelemetryDeviceSampleManager(time.Duration(input.IntervalSeconds) * time.Second)
		start := time.Unix(1_700_320_000, 0)
		if _, _, _, valid, _, _ := im.calculateCPUUsageWithDetailedAvailabilityAt(1000, 0, 0, true, true, "replay-vm", 1, start); valid {
			t.Fatal("first CPU sample was unexpectedly valid")
		}
		if _, _, _, valid, _, _ := im.calculateCPUUsageWithDetailedAvailabilityAt(2000, 0, 0, true, true, "replay-vm", 1, start.Add(time.Second)); !valid {
			t.Fatal("monotonic CPU sample was unavailable")
		}
		if _, _, _, valid, _, _ := im.calculateCPUUsageWithDetailedAvailabilityAt(100, 0, 0, true, true, "replay-vm", 1, start.Add(2*time.Second)); valid {
			t.Fatal("counter reset became a healthy zero")
		}
		if _, _, _, valid, _, _ := im.calculateCPUUsageWithDetailedAvailabilityAt(200, 0, 0, true, true, "replay-vm", 1, start.Add(3*time.Second)); !valid {
			t.Fatal("counter reset did not establish a new baseline")
		}
		base.Metrics["oie_instance_resource_axis_available"] = 1
		base.Metrics["oie_instance_resource_axis_fresh"] = 1
		base.StateTransitions = []string{"fresh", "sample_unavailable", "fresh"}
		base.RecoveryBehavior = "next_monotonic_sample_recovers"
	case "live_migration", "cold_migration", "instance_reboot":
		im := newResourceTelemetryDeviceSampleManager(time.Duration(input.IntervalSeconds) * time.Second)
		if im.observeInstanceResourceGenerationWithToken("replay-vm", 7, 1000, true, "boot-a:7:100", true) {
			t.Fatal("initial runtime generation was reported changed")
		}
		var changed bool
		switch fixture.ID {
		case "live_migration":
			changed = im.observeInstanceResourceGenerationWithToken("replay-vm", 19, 1100, true, "boot-b:19:200", true)
		case "cold_migration":
			changed = im.observeInstanceResourceGenerationWithToken("replay-vm", 21, 100, true, "boot-c:21:300", true)
		case "instance_reboot":
			changed = im.observeInstanceResourceGenerationWithToken("replay-vm", 7, 20, true, "boot-a:7:400", true)
		}
		if !changed {
			t.Fatalf("%s did not create a new runtime generation", fixture.ID)
		}
		base.Metrics["oie_instance_info"] = 1
		base.Metrics["oie_instance_resource_axis_available"] = 1
		if fixture.ID == "live_migration" {
			base.StateTransitions = []string{"fresh", "identity_reset", "fresh"}
			base.RecoveryBehavior = "destination_establishes_new_baseline"
		} else if fixture.ID == "cold_migration" {
			base.StateTransitions = []string{"fresh", "stopped_reset", "fresh"}
			base.RecoveryBehavior = "restart_establishes_new_baseline"
		} else {
			base.StateTransitions = []string{"fresh", "runtime_reset", "fresh"}
			base.RecoveryBehavior = "reboot_establishes_new_baseline"
		}
	case "instance_shutdown", "instance_deletion":
		cm := newBehaviorStateTestManager()
		ident := behaviorIdentityKey{InstanceUUID: "replay-vm", IP: IPStrToKey("192.0.2.10"), Direction: "outbound"}
		cm.storeBehaviorSeverity(ident, 0.8)
		cm.resetBehaviorStateForInstance("replay-vm")
		if _, available := cm.behaviorSeveritySnapshotAvailable(ident); available {
			t.Fatalf("%s retained behavior severity", fixture.ID)
		}
		if fixture.ID == "instance_shutdown" {
			base.Metrics["oie_instance_state_code"] = 5
			base.StateTransitions = []string{"fresh", "stopped_reset"}
			base.RecoveryBehavior = "running_state_requires_new_baseline"
		} else {
			base.Metrics["oie_host_libvirt_active_vms"] = 0
			base.StateTransitions = []string{"fresh", "deleted"}
			base.RecoveryBehavior = "all_instance_state_removed"
		}
	case "ip_reuse":
		im := newInventoryStateTestManager()
		cm := newBehaviorStateTestManager()
		ip := IPStrToKey("192.0.2.10")
		im.updateVMIPIndex("old-vm", []IP{{Address: "192.0.2.10", Family: "ipv4"}})
		oldIdent := behaviorIdentityKey{InstanceUUID: "old-vm", IP: ip, Direction: "outbound"}
		cm.storeBehaviorSeverity(oldIdent, 0.9)
		im.removeVMIPIndex("old-vm")
		cm.resetBehaviorStateForInstance("old-vm")
		im.updateVMIPIndex("new-vm", []IP{{Address: "192.0.2.10", Family: "ipv4"}})
		_, owners := im.getVMIPIndexSnapshot()
		if owners[ip] != "new-vm" {
			t.Fatalf("IP reuse owner=%q, want new-vm", owners[ip])
		}
		newIdent := behaviorIdentityKey{InstanceUUID: "new-vm", IP: ip, Direction: "outbound"}
		if _, available := cm.behaviorSeveritySnapshotAvailable(newIdent); available {
			t.Fatal("new IP owner inherited old behavior severity")
		}
		base.Metrics["oie_instance_conntrack_ip_flows"] = 0
		base.Metrics["oie_instance_info"] = 1
		base.StateTransitions = []string{"fresh", "identity_reset", "fresh"}
		base.RecoveryBehavior = "new_owner_starts_without_prior_evidence"
	case "duplicate_tenant_ips_separate_ovn_zones":
		ip := IPStrToKey("192.0.2.10")
		remote := IPStrToKey("198.51.100.10")
		vmIndex := map[VMIPIdentity]uint32{
			{InstanceUUID: "zone-a-vm", IP: ip}: 0,
			{InstanceUUID: "zone-b-vm", IP: ip}: 1,
		}
		zoneInfo := func(zone uint16) (string, map[IPKey]struct{}) {
			switch zone {
			case input.ZoneA:
				return "zone-a-vm", map[IPKey]struct{}{ip: {}}
			case input.ZoneB:
				return "zone-b-vm", map[IPKey]struct{}{ip: {}}
			default:
				return "", nil
			}
		}
		for _, test := range []struct {
			zone  uint16
			want  string
			index uint32
		}{{input.ZoneA, "zone-a-vm", 0}, {input.ZoneB, "zone-b-vm", 1}} {
			idx, _, matched, _, instance, _ := resolveFlowVMIndices(ConntrackFlowLite{SrcIP: ip, DstIP: remote, Zone: test.zone}, vmIndex, map[IPKey]string{}, zoneInfo)
			if !matched || idx != test.index || instance != test.want {
				t.Fatalf("zone %d attribution=(%d,%v,%q), want (%d,true,%q)", test.zone, idx, matched, instance, test.index, test.want)
			}
		}
		base.Metrics["oie_instance_conntrack_ip_flows_outbound"] = 1
		base.StateTransitions = []string{"zone_a_attributed", "zone_b_attributed"}
		base.RecoveryBehavior = "zone_identity_prevents_cross_tenant_carryover"
	case "exporter_restart":
		featureInput := replayCalibrationReplayInput{Direction: "outbound", MiningPort: 10128, MiningFlows: 2, MiningRepliedFlows: 2, MiningUniqueRemotes: 1}
		feature := replayCalibrationBehaviorFeature(featureInput)
		ident := behaviorIdentityKey{InstanceUUID: "replay-vm", IP: IPStrToKey("192.0.2.10"), Direction: "outbound"}
		before := newBehaviorStateTestManager().updateMiningAlertState(feature, ident, 100)
		after := newBehaviorStateTestManager().updateMiningAlertState(feature, ident, 115)
		if before.PersistenceHits != 1 || after.PersistenceHits != 1 || before.Confirmed || after.Confirmed {
			t.Fatalf("exporter restart borrowed persistence: before=%+v after=%+v", before, after)
		}
		base.Metrics["oie_instance_behavior_severity"] = 0
		base.StateTransitions = []string{"candidate", "restarted", "candidate"}
		base.RecoveryBehavior = "new_process_requires_new_persistence"
	case "threat_feed_outage", "threat_feed_recovery":
		provider := replayCalibrationThreatProvider("TOREXIT")
		tm := newThreatStateTestManager(provider)
		mc := &MetricsCollector{tm: tm, intelHistory: make(map[string]*IntelHistory), threatEWMATau: defaultThreatEWMATau}
		mc.updateIntelHistoryForSourceSet("replay-vm", 0.5, 100, "TOREXIT")
		empty := &ConntrackAgg{
			VMIndex:         map[VMIPIdentity]uint32{{InstanceUUID: "replay-vm", IP: IPStrToKey("192.0.2.10")}: 0},
			ObservationUnix: 115, ObservationTimeSet: true,
			ProviderSourcesIncluded: map[string]struct{}{},
		}
		var metrics []prometheus.Metric
		if _, available := mc.collectDomainThreatSignals(empty, map[string]struct{}{"192.0.2.10": {}}, "d", "s", "replay-vm", "p", "pn", "u", true, true, true, &metrics); available {
			t.Fatal("threat feed outage retained an available score")
		}
		base.Metrics["oie_host_threat_feed_fresh"] = 0
		if fixture.ID == "threat_feed_outage" {
			base.StateTransitions = []string{"fresh", "source_unavailable", "retained_unavailable"}
			base.RecoveryBehavior = "score_omitted_until_fresh_source_returns"
			break
		}
		hits := replayCalibrationThreatHits(2)
		recovered := &ConntrackAgg{
			VMIndex:         map[VMIPIdentity]uint32{{InstanceUUID: "replay-vm", IP: IPStrToKey("192.0.2.10")}: 0},
			ObservationUnix: 130, ObservationTimeSet: true,
			ProviderSourcesIncluded: map[string]struct{}{provider.Name: {}},
			ProviderHits:            map[string]map[string]map[PairKey]ConntrackEntry{provider.Name: {"replay-vm": hits}},
			CombinedThreatHits:      map[string]map[PairKey]ConntrackEntry{"replay-vm": hits},
		}
		metrics = nil
		severity, available := mc.collectDomainThreatSignals(recovered, map[string]struct{}{"192.0.2.10": {}}, "d", "s", "replay-vm", "p", "pn", "u", true, true, true, &metrics)
		if !available || math.Abs(severity-0.2) > 1e-12 {
			t.Fatalf("threat feed recovery severity=(%v,%v), want (0.2,true)", severity, available)
		}
		base.Metrics["oie_host_threat_feed_fresh"] = 1
		base.Metrics["oie_instance_threat_list_severity"] = severity * 100
		base.Severity = severity * 100
		base.StateTransitions = []string{"source_unavailable", "rebaseline", "fresh"}
		base.RecoveryBehavior = "first_fresh_source_snapshot_rebaselines_score"
	case "temporary_missing_resource_counters":
		interval := time.Duration(input.IntervalSeconds) * time.Second
		mc := &MetricsCollector{collectionInterval: interval, resourceV2: make(map[string]*resourceV2State)}
		start := time.Unix(1_700_330_000, 0)
		fresh, _ := mc.computeResourceV2("replay-vm", resourceV2Input{Now: start, CpuPRaw: 0.8, CpuConf: 1, CpuImpact: 1, CpuAvailable: true})
		retained, _ := mc.computeResourceV2("replay-vm", resourceV2Input{Now: start.Add(60 * time.Second)})
		expired, _ := mc.computeResourceV2("replay-vm", resourceV2Input{Now: start.Add(resourceAxisMaxRetainedAge(interval) + time.Second)})
		recovered, _ := mc.computeResourceV2("replay-vm", resourceV2Input{Now: start.Add(resourceAxisMaxRetainedAge(interval) + interval), CpuPRaw: 0.2, CpuConf: 1, CpuImpact: 1, CpuAvailable: true})
		if !fresh.CPU.Fresh || !retained.CPU.Available || retained.CPU.Fresh || expired.CPU.Available || !recovered.CPU.Fresh {
			t.Fatalf("temporary missing resource lifecycle fresh=%+v retained=%+v expired=%+v recovered=%+v", fresh.CPU, retained.CPU, expired.CPU, recovered.CPU)
		}
		base.Metrics["oie_instance_resource_axis_available"] = 1
		base.Metrics["oie_instance_resource_axis_fresh"] = 1
		base.Metrics["oie_instance_resource_axis_stale_seconds"] = 0
		base.Metrics["oie_instance_resource_severity"] = recovered.OverallFinal
		base.Severity = recovered.OverallFinal
		base.StateTransitions = []string{"fresh", "retained_stale", "expired_unavailable", "fresh"}
		base.RecoveryBehavior = "fresh_counter_sample_reestablishes_axis"
	default:
		t.Fatalf("unhandled lifecycle fixture %q", fixture.ID)
	}
	return base
}

func replayCalibrationRunReplayFixture(t *testing.T, fixture replayCalibrationReplayFixture) replayCalibrationReplayResult {
	t.Helper()
	switch fixture.Input.Engine {
	case "behavior":
		return replayCalibrationRunBehaviorReplay(t, fixture)
	case "threat":
		return replayCalibrationRunThreatReplay(t, fixture)
	case "lifecycle":
		return replayCalibrationRunLifecycleReplay(t, fixture)
	default:
		t.Fatalf("fixture %q engine=%q", fixture.ID, fixture.Input.Engine)
		return replayCalibrationReplayResult{}
	}
}

func replayCalibrationCompareReplayResult(t *testing.T, fixture replayCalibrationReplayFixture, result replayCalibrationReplayResult) {
	t.Helper()
	for _, name := range fixture.ExpectedMetrics {
		if _, ok := result.Metrics[name]; !ok {
			t.Errorf("missing expected metric %s; got %v", name, result.Metrics)
		}
	}
	for _, name := range fixture.ForbiddenMetrics {
		if _, ok := result.Metrics[name]; ok {
			t.Errorf("forbidden metric %s was emitted", name)
		}
	}
	if result.Severity < fixture.ExpectedSeverityRange.Min-1e-9 || result.Severity > fixture.ExpectedSeverityRange.Max+1e-9 {
		t.Errorf("severity=%v, want range [%v,%v]", result.Severity, fixture.ExpectedSeverityRange.Min, fixture.ExpectedSeverityRange.Max)
	}
	if !reflect.DeepEqual(result.StateTransitions, fixture.ExpectedStateTransitions) {
		t.Errorf("state transitions=%v, want %v", result.StateTransitions, fixture.ExpectedStateTransitions)
	}
	if result.Alert != fixture.ExpectedAlert {
		t.Errorf("alert=%q, want %q", result.Alert, fixture.ExpectedAlert)
	}
	for _, forbidden := range fixture.ForbiddenAlerts {
		switch forbidden {
		case "default_warning_security":
			if replayCalibrationContainsString(replayCalibrationDefaultWarningSecurityAlerts, result.Alert) {
				t.Errorf("default warning security alert %q was forbidden", result.Alert)
			}
		case "unrelated_security_alert":
			if result.Alert != "none" && result.Alert != fixture.ExpectedAlert {
				t.Errorf("unrelated alert %q was emitted", result.Alert)
			}
		default:
			if result.Alert == forbidden {
				t.Errorf("forbidden alert %q was emitted", forbidden)
			}
		}
	}
	if fixture.ExpectedAlert == "none" {
		if result.DetectionDelaySeconds != -1 {
			t.Errorf("non-alert fixture detection delay=%d, want -1", result.DetectionDelaySeconds)
		}
	} else if result.DetectionDelaySeconds < 0 || result.DetectionDelaySeconds > fixture.MaximumExpectedDetectionDelaySec {
		t.Errorf("detection delay=%d, want 0..%d", result.DetectionDelaySeconds, fixture.MaximumExpectedDetectionDelaySec)
	}
	if result.RecoveryBehavior != fixture.ExpectedRecoveryBehavior {
		t.Errorf("recovery=%q, want %q", result.RecoveryBehavior, fixture.ExpectedRecoveryBehavior)
	}
}

func TestReplayCalibrationReplayCorpusOutcomes(t *testing.T) {
	for _, fixture := range replayCalibrationAllReplayFixtures(t) {
		fixture := fixture
		t.Run(fixture.ID, func(t *testing.T) {
			replayCalibrationCompareReplayResult(t, fixture, replayCalibrationRunReplayFixture(t, fixture))
		})
	}
}

func replayCalibrationBenignPromtoolSeries(fixture replayCalibrationReplayFixture) []alertValidationPromtoolInputSeries {
	const samples = 12
	input := fixture.Input
	host := map[string]string{"instance": "node", "job": "openstack-instance-exporter"}
	series := []alertValidationPromtoolInputSeries{
		{Series: alertValidationSeries("up", host), Values: alertValidationValues(samples, func(int) float64 { return 1 })},
		{Series: alertValidationSeries("oie_host_libvirt_ok", host), Values: alertValidationValues(samples, func(int) float64 { return 1 })},
		{Series: alertValidationSeries("oie_host_conntrack_raw_ok", host), Values: alertValidationValues(samples, func(int) float64 { return 1 })},
	}
	labels := alertValidationLabels(map[string]string{"family": "4", "ip": "192.0.2.10"})
	prefix := "oie_instance_" + input.Direction + "_"
	for metric, value := range map[string]float64{
		prefix + "flows":                   float64(input.Flows),
		prefix + "unique_remotes":          float64(input.UniqueRemotes),
		prefix + "new_remotes":             float64(input.NewRemotes),
		prefix + "unique_dst_ports":        float64(input.UniqueDstPorts),
		prefix + "new_dst_ports":           float64(input.NewDstPorts),
		prefix + "max_flows_single_remote": float64(input.MaxSingleRemote),
	} {
		series = append(series, alertValidationPromtoolInputSeries{Series: alertValidationSeries(metric, labels), Values: alertValidationValues(samples, func(int) float64 { return value })})
	}
	feature := replayCalibrationBehaviorFeature(input)
	if feature.Mining.Valid && (fixture.ID == "alternate_port_web_service" || fixture.ID == "long_lived_ordinary_tcp_connection") {
		miningLabels := alertValidationMiningLabels(feature.Mining.Confidence.String())
		miningLabels["port"] = fmt.Sprintf("%d", input.MiningPort)
		miningLabels["port_name"] = builtinMiningPortName(input.MiningPort)
		series = append(series, alertValidationPromtoolInputSeries{Series: alertValidationSeries("oie_instance_mining_suspected", miningLabels), Values: alertValidationValues(samples, func(int) float64 { return 1 })})
	}
	if input.CPUPercent > 0 {
		series = append(series,
			alertValidationPromtoolInputSeries{Series: alertValidationSeries("oie_instance_cpu_vcpu_percent", alertValidationInstanceLabels()), Values: alertValidationValues(samples, func(int) float64 { return input.CPUPercent })},
			alertValidationPromtoolInputSeries{Series: alertValidationSeries("oie_instance_resource_axis_fresh", alertValidationLabels(map[string]string{"axis": "cpu"})), Values: alertValidationValues(samples, func(int) float64 { return 1 })},
			alertValidationPromtoolInputSeries{Series: alertValidationSeries("oie_instance_resource_axis_last_success_timestamp_seconds", alertValidationLabels(map[string]string{"axis": "cpu"})), Values: alertValidationValues(samples, func(minute int) float64 { return float64(minute * 60) })},
		)
	}
	return series
}

func TestReplayCalibrationBenignCorpusProducesNoDefaultWarningSecurityAlertWithPromtool(t *testing.T) {
	corpus := replayCalibrationLoadReplayCorpus(t, "testdata/replay/benign.yaml")
	groups := make([]alertValidationPromtoolTestGroup, 0, len(corpus.Fixtures))
	for _, fixture := range corpus.Fixtures {
		tests := make([]alertValidationPromtoolAlertTest, 0, len(replayCalibrationDefaultWarningSecurityAlerts))
		for _, alert := range replayCalibrationDefaultWarningSecurityAlerts {
			tests = append(tests, alertValidationPromtoolAlertTest{EvalTime: "10m", Alert: alert, Expected: []alertValidationPromtoolExpectedAlert{}})
		}
		groups = append(groups, alertValidationPromtoolTestGroup{
			Name: fixture.ID, Interval: "1m", InputSeries: replayCalibrationBenignPromtoolSeries(fixture), AlertRuleTest: tests,
		})
	}
	alertValidationRunSelectedPromtool(t, "Replay calibration benign replay security silence", replayCalibrationDefaultWarningSecurityAlerts, groups)
}
