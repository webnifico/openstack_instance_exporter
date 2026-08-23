package main

import (
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	libvirt "github.com/digitalocean/go-libvirt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	dto "github.com/prometheus/client_model/go"
)

type pass1E2EMetricCollector struct {
	metrics []prometheus.Metric
}

func (c pass1E2EMetricCollector) Describe(ch chan<- *prometheus.Desc) {
	prometheus.DescribeByCollect(c, ch)
}

func (c pass1E2EMetricCollector) Collect(ch chan<- prometheus.Metric) {
	for _, metric := range c.metrics {
		ch <- metric
	}
}

type pass1E2EBehaviorEvent struct {
	tag          string
	event        string
	domain       string
	instanceUUID string
	projectUUID  string
	projectName  string
	userUUID     string
	fields       map[string]interface{}
}

func pass1E2EUUID() (libvirt.UUID, string) {
	uuid := libvirt.UUID{
		0x10, 0x20, 0x30, 0x40,
		0x50, 0x60,
		0x70, 0x80,
		0x90, 0xa0,
		0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01,
	}
	return uuid, uuidBytesToString(uuid[:])
}

func pass1E2EFixture(t *testing.T) ([]*dto.MetricFamily, []pass1E2EBehaviorEvent) {
	t.Helper()

	mc, err := NewMetricsCollector(CollectorConfig{
		LibvirtURI:             "qemu:///system",
		WorkerCount:            1,
		CollectionInterval:     time.Hour,
		OutboundBehaviorEnable: true,
		BehaviorSensitivity:    1,
		BehaviorThresholds: BehaviorThresholds{
			OutboundFlowsTotal: 2000,
			InboundFlowsTotal:  2000,
		},
		BehaviorEWMATauFast: 3 * time.Minute,
		BehaviorEWMATauSlow: 2 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewMetricsCollector: %v", err)
	}
	t.Cleanup(func() { close(mc.shutdownChan) })

	events := make([]pass1E2EBehaviorEvent, 0, 1)
	mc.cm.LogThreat = func(tag, event, domain, instanceUUID, projectUUID, projectName, userUUID string, kvpairs ...interface{}) {
		fields := make(map[string]interface{}, len(kvpairs)/2)
		for i := 0; i+1 < len(kvpairs); i += 2 {
			key, ok := kvpairs[i].(string)
			if ok {
				fields[key] = kvpairs[i+1]
			}
		}
		events = append(events, pass1E2EBehaviorEvent{
			tag:          tag,
			event:        event,
			domain:       domain,
			instanceUUID: instanceUUID,
			projectUUID:  projectUUID,
			projectName:  projectName,
			userUUID:     userUUID,
			fields:       fields,
		})
	}

	uuid, instanceUUID := pass1E2EUUID()
	const (
		domainName  = "instance-00000042"
		serverName  = "pass1-miner-fixture"
		projectUUID = "project-pass1"
		projectName = "Pass One Project"
		userUUID    = "user-pass1"
		portUUID    = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
		zone        = uint16(4242)
		vmIP        = "10.20.30.40"
		remoteIP    = "198.51.100.44"
	)
	vmKey := IPStrToKey(vmIP)
	remoteKey := IPStrToKey(remoteIP)
	mc.im.domainMeta[instanceUUID] = &DomainStatic{
		Name:            serverName,
		InstanceUUID:    instanceUUID,
		UserUUID:        userUUID,
		UserName:        "fixture-user",
		ProjectUUID:     projectUUID,
		ProjectName:     projectName,
		FlavorName:      "fixture.medium",
		VCPUCount:       2,
		MemMB:           4096,
		RootType:        "volume",
		CreatedAt:       "2026-08-22T12:00:00Z",
		MetadataVersion: "1.2.0",
		FixedIPs:        []IP{{Address: vmIP, Family: "ipv4", Prefix: "24"}},
		PortUUIDs:       []string{portUUID},
		PortIPsByUUID:   map[string][]IP{portUUID: {{Address: vmIP, Family: "ipv4", Prefix: "24"}}},
		LastUpdated:     time.Now(),
	}

	instanceByPort := mc.im.snapshotOVNPortToInstance(map[string]struct{}{instanceUUID: {}})
	ipsByPort := mc.im.snapshotOVNPortToIPKeys(map[string]struct{}{instanceUUID: {}})
	if err := mc.cm.ovnMapper.refreshFromOutput(
		[]byte(fmt.Sprintf("%s %d\n", portUUID, zone)),
		instanceByPort,
		ipsByPort,
	); err != nil {
		t.Fatalf("refresh OVN fixture: %v", err)
	}

	// The fixed IP is deliberately ambiguous without a zone. Successful
	// attribution therefore proves that the OVN mapping participated in the
	// flow-to-instance decision rather than the global IP fallback.
	vmIdentities := []VMIPIdentity{
		{InstanceUUID: instanceUUID, IP: vmKey},
		{InstanceUUID: "ffffffff-eeee-dddd-cccc-bbbbbbbbbbbb", IP: vmKey},
	}
	flow := ConntrackFlowLite{
		SrcIP:          vmKey,
		DstIP:          remoteKey,
		SrcPort:        49152,
		DstPort:        10128,
		Proto:          6,
		Zone:           zone,
		Status:         IPS_SEEN_REPLY | IPS_ASSURED,
		ForwardPackets: 3,
		ReversePackets: 2,
		ForwardBytes:   4096,
		ReverseBytes:   1024,
		PacketsPresent: true,
		BytesPresent:   true,
	}
	secondFlow := flow
	secondFlow.SrcPort++
	connAgg := mc.cm.aggregateConntrackOnePassFamilies([]ConntrackFlowLite{flow, secondFlow}, nil, vmIdentities, nil)
	if got := connAgg.InstanceFlowTotals[instanceUUID]; got != 2 {
		t.Fatalf("OVN-attributed instance flow total=%d, want 2", got)
	}
	if got := connAgg.InstanceFlowTotals[vmIdentities[1].InstanceUUID]; got != 0 {
		t.Fatalf("ambiguous-IP fallback received OVN flow total=%d, want 0", got)
	}
	idx, ok := connAgg.VMIndex[VMIPIdentity{InstanceUUID: instanceUUID, IP: vmKey}]
	if !ok || connAgg.FlowsOut[int(idx)] != 2 {
		t.Fatalf("OVN-attributed outbound flow index=%d ok=%v flows=%v", idx, ok, connAgg.FlowsOut)
	}

	record := libvirt.DomainStatsRecord{
		Dom: libvirt.Domain{Name: domainName, UUID: uuid},
		Params: []libvirt.TypedParam{
			typedParam("state.state", int32(libvirt.DomainRunning)),
			typedParam("balloon.maximum", uint64(4096*1024)),
			typedParam("balloon.current", uint64(3072*1024)),
			typedParam("balloon.usable", uint64(1024*1024)),
			typedParam("balloon.rss", uint64(2048*1024)),
		},
	}

	var finalMetrics []prometheus.Metric
	for cycle := 1; cycle <= 3; cycle++ {
		agg := &hostAgg{projects: make(map[string]struct{})}
		mc.collectDomainMetrics(record, connAgg, nil, agg, 100000, true, true, true)
		if cycle < 3 {
			for _, metric := range agg.metrics {
				if strings.Contains(metric.Desc().String(), `fqName: "oie_instance_mining_suspected"`) {
					t.Fatalf("cycle %d emitted mining metric before persistence gate", cycle)
				}
			}
			continue
		}
		finalMetrics = agg.metrics
	}

	registry := prometheus.NewRegistry()
	registry.MustRegister(pass1E2EMetricCollector{metrics: finalMetrics})
	families, err := registry.Gather()
	if err != nil {
		t.Fatalf("real Prometheus registry gather rejected fixture metrics: %v", err)
	}
	return families, events
}

func pass1MetricValue(metric *dto.Metric) (float64, bool) {
	switch {
	case metric.Gauge != nil:
		return metric.GetGauge().GetValue(), true
	case metric.Counter != nil:
		return metric.GetCounter().GetValue(), true
	case metric.Untyped != nil:
		return metric.GetUntyped().GetValue(), true
	default:
		return 0, false
	}
}

func pass1MetricLabels(metric *dto.Metric) string {
	labels := make([]string, 0, len(metric.Label))
	for _, pair := range metric.Label {
		labels = append(labels, pair.GetName()+"="+strconv.Quote(pair.GetValue()))
	}
	sort.Strings(labels)
	return strings.Join(labels, ",")
}

func pass1SelectedMetricContract(t *testing.T, families []*dto.MetricFamily) string {
	t.Helper()
	selected := map[string]struct{}{
		"oie_instance_info":                               {},
		"oie_instance_state_code":                         {},
		"oie_instance_cpu_vcpu_count":                     {},
		"oie_instance_mem_allocated_mb":                   {},
		"oie_instance_conntrack_ip_flows":                 {},
		"oie_instance_conntrack_ip_flows_inbound":         {},
		"oie_instance_conntrack_ip_flows_outbound":        {},
		"oie_instance_outbound_unique_remotes":            {},
		"oie_instance_outbound_new_remotes":               {},
		"oie_instance_outbound_flows":                     {},
		"oie_instance_outbound_max_flows_single_remote":   {},
		"oie_instance_outbound_unique_dst_ports":          {},
		"oie_instance_outbound_new_dst_ports":             {},
		"oie_instance_outbound_max_flows_single_dst_port": {},
		"oie_instance_outbound_bytes_per_flow":            {},
		"oie_instance_outbound_packets_per_flow":          {},
		"oie_instance_mining_suspected":                   {},
	}
	lines := make([]string, 0, len(selected))
	for _, family := range families {
		name := family.GetName()
		if _, ok := selected[name]; !ok {
			continue
		}
		if len(family.Metric) != 1 {
			t.Fatalf("selected family %s has %d samples, want 1", name, len(family.Metric))
		}
		value, ok := pass1MetricValue(family.Metric[0])
		if !ok {
			t.Fatalf("selected family %s has unsupported type %s", name, family.GetType())
		}
		lines = append(lines, fmt.Sprintf(
			"%s|type=%s|help=%s|labels=%s|value=%s",
			name,
			family.GetType().String(),
			family.GetHelp(),
			pass1MetricLabels(family.Metric[0]),
			strconv.FormatFloat(value, 'g', -1, 64),
		))
		delete(selected, name)
	}
	if len(selected) != 0 {
		missing := make([]string, 0, len(selected))
		for name := range selected {
			missing = append(missing, name)
		}
		sort.Strings(missing)
		t.Fatalf("end-to-end fixture did not emit selected metric families: %v", missing)
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n") + "\n"
}

func pass1EmittedMetricSchemaContract(families []*dto.MetricFamily) string {
	lines := make([]string, 0, len(families))
	for _, family := range families {
		labelNames := make(map[string]struct{})
		for _, metric := range family.Metric {
			for _, pair := range metric.Label {
				labelNames[pair.GetName()] = struct{}{}
			}
		}
		labels := make([]string, 0, len(labelNames))
		for name := range labelNames {
			labels = append(labels, name)
		}
		sort.Strings(labels)
		lines = append(lines, fmt.Sprintf(
			"%s|type=%s|help=%s|labels=%s",
			family.GetName(), family.GetType().String(), family.GetHelp(), strings.Join(labels, ","),
		))
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n") + "\n"
}

func TestPass1PrometheusEndToEndMetricContract(t *testing.T) {
	families, events := pass1E2EFixture(t)

	seenIdentities := make(map[string]struct{}, 128)
	for _, family := range families {
		for _, metric := range family.Metric {
			identity := family.GetName() + "{" + pass1MetricLabels(metric) + "}"
			if _, duplicate := seenIdentities[identity]; duplicate {
				t.Fatalf("duplicate emitted Prometheus metric identity %s", identity)
			}
			seenIdentities[identity] = struct{}{}
			if value, ok := pass1MetricValue(metric); ok && (math.IsNaN(value) || math.IsInf(value, 0)) {
				t.Fatalf("non-finite emitted metric %s=%v", identity, value)
			}
		}
	}

	got := pass1SelectedMetricContract(t, families)
	wantBytes, err := os.ReadFile("testdata/pass1-prometheus-e2e-contract.golden")
	if err != nil {
		t.Fatal(err)
	}
	want := string(wantBytes)
	if got != want {
		t.Fatalf("selected end-to-end metric contract changed\nwant:\n%s\ngot:\n%s", want, got)
	}

	gotSchema := pass1EmittedMetricSchemaContract(families)
	wantSchemaBytes, err := os.ReadFile("testdata/pass1-prometheus-emitted-schema-contract.golden")
	if err != nil {
		t.Fatal(err)
	}
	wantSchema := string(wantSchemaBytes)
	if gotSchema != wantSchema {
		t.Fatalf("end-to-end emitted metric schema changed\nwant:\n%s\ngot:\n%s", wantSchema, gotSchema)
	}

	if len(events) != 1 {
		t.Fatalf("structured behavior events=%d, want 1: %#v", len(events), events)
	}
	event := events[0]
	_, instanceUUID := pass1E2EUUID()
	if event.tag != "BEHAVIOR" || event.event != "behavior_alert" ||
		event.domain != "instance-00000042" || event.instanceUUID != instanceUUID ||
		event.projectUUID != "project-pass1" || event.projectName != "Pass One Project" || event.userUUID != "user-pass1" {
		t.Fatalf("structured behavior identity contract changed: %#v", event)
	}
	for field, want := range map[string]interface{}{
		"kind":                   miningBehaviorKind,
		"direction":              "outbound",
		"top_dst_port":           10128,
		"top_dst_port_name":      "moneroocean_randomx_stratum",
		"top_remote_ip":          "198.51.100.44",
		"src_ip":                 "10.20.30.40",
		"dst_ip":                 "198.51.100.44",
		"persistence_hits":       3,
		"persistence_required":   3,
		"emit_reason":            "new_kind",
		"mining_port_confidence": "high",
		"mining_flows":           2,
		"mining_replied_flows":   2,
		"mining_unique_remotes":  1,
		"mining_unique_ports":    1,
		"priority":               "P4",
	} {
		if got := event.fields[field]; got != want {
			t.Fatalf("structured behavior field %s=%#v, want %#v; event=%#v", field, got, want, event)
		}
	}
}

func pass1FullRegistryFixture(t *testing.T) ([]*dto.MetricFamily, map[string]struct{}) {
	t.Helper()

	mc, err := NewMetricsCollector(CollectorConfig{
		LibvirtURI:             "qemu:///system",
		WorkerCount:            1,
		CollectionInterval:     time.Minute,
		OutboundBehaviorEnable: true,
		InboundBehaviorEnable:  true,
		ConntrackIPv4Enable:    true,
		ConntrackAcctEnabled:   true,
		BehaviorSensitivity:    1,
		BehaviorThresholds: BehaviorThresholds{
			OutboundFlowsTotal: 2000,
			InboundFlowsTotal:  2000,
		},
		BehaviorEWMATauFast: 3 * time.Minute,
		BehaviorEWMATauSlow: 2 * time.Hour,
		Severity: SeverityConfig{
			BehaviorWeight: 1,
			ResourceWeight: 1,
			ThreatWeight:   1,
		},
	})
	if err != nil {
		t.Fatalf("NewMetricsCollector: %v", err)
	}
	t.Cleanup(func() { close(mc.shutdownChan) })

	// Describe is the authoritative inventory of exporter-owned descriptors.
	// The rich fixture below must drive the normal metric emitters far enough
	// that every one of those descriptors reaches a real registry gather.
	descriptorNames := make(map[string]struct{}, 128)
	descCh := make(chan *prometheus.Desc, 256)
	mc.Describe(descCh)
	close(descCh)
	for desc := range descCh {
		match := descNameRE.FindStringSubmatch(desc.String())
		if len(match) != 2 {
			t.Fatalf("cannot parse exporter descriptor: %s", desc)
		}
		if _, duplicate := descriptorNames[match[1]]; duplicate {
			t.Fatalf("duplicate exporter descriptor name %s", match[1])
		}
		descriptorNames[match[1]] = struct{}{}
	}

	_, instanceUUID := pass1E2EUUID()
	const (
		domainName  = "instance-pass1-full-registry"
		serverName  = "pass1-full-registry"
		projectUUID = "project-full-registry"
		projectName = "Pass One Full Registry"
		userUUID    = "user-full-registry"
		vmIP        = "10.42.0.10"
		remoteIP    = "198.51.100.99"
		ifname      = "tap-pass1"
		volumeUUID  = "volume-pass1"
		diskPath    = "vda"
	)

	now := time.Now()
	for _, provider := range mc.tm.Providers {
		provider.Enabled = true
		provider.Direction = ContactAny
		provider.RefreshInterval = time.Hour
		provider.LastSuccess = float64(now.Unix())
		provider.LastDuration = 0.25
		provider.EntryCount = 1
	}
	mc.tm.spamEnabled = true
	mc.tm.spamDir = ContactAny
	mc.tm.spamRefresh = time.Hour
	mc.tm.spamLastSuccessUnix = float64(now.Unix())
	mc.tm.spamLastRefreshSeconds = 0.5
	mc.tm.spamEntries = 1
	mc.tm.hostThreatsEnabled = true
	mc.tm.hostThreatHits = map[string]map[string]string{
		"PASS1": {remoteIP: "ipv4"},
	}

	mc.im.domainMeta[instanceUUID] = &DomainStatic{
		Name:            serverName,
		InstanceUUID:    instanceUUID,
		UserUUID:        userUUID,
		UserName:        "fixture-user",
		ProjectUUID:     projectUUID,
		ProjectName:     projectName,
		FlavorName:      "fixture.full",
		VCPUCount:       1,
		MemMB:           4096,
		RootType:        "volume",
		CreatedAt:       "2026-08-22T12:00:00Z",
		MetadataVersion: "1.2.0",
		FixedIPs:        []IP{{Address: vmIP, Family: "ipv4", Prefix: "24"}},
		Interfaces:      []string{ifname},
		Disks: []DomainDisk{{
			Device:     "disk",
			Type:       "network",
			SourceName: "rbd/" + volumeUUID,
			TargetDev:  diskPath,
		}},
		LastUpdated: now,
	}

	const (
		cpuTime     = uint64(2_000_000_000)
		vcpuDelay   = uint64(200_000_000)
		vcpuWait    = uint64(100_000_000)
		swapIn      = uint64(20)
		swapOut     = uint64(10)
		majorFaults = uint64(30)
		minorFaults = uint64(300)
		rdReqs      = uint64(200)
		wrReqs      = uint64(120)
		rdBytes     = uint64(16 << 20)
		wrBytes     = uint64(8 << 20)
		rdTime      = uint64(2_000_000_000)
		wrTime      = uint64(1_200_000_000)
		flushReqs   = uint64(20)
		flushTime   = uint64(200_000_000)
		rxPkts      = uint64(200)
		txPkts      = uint64(150)
		rxDrop      = uint64(4)
		txDrop      = uint64(2)
	)

	params := []libvirt.TypedParam{
		typedParam("state.state", int32(libvirt.DomainRunning)),
		typedParam("cpu.time", cpuTime),
		typedParam("balloon.maximum", uint64(4096*1024)),
		typedParam("balloon.current", uint64(3072*1024)),
		typedParam("balloon.usable", uint64(1024*1024)),
		typedParam("balloon.rss", uint64(2048*1024)),
		typedParam("balloon.swap_in", swapIn),
		typedParam("balloon.swap_out", swapOut),
		typedParam("balloon.major_fault", majorFaults),
		typedParam("balloon.minor_fault", minorFaults),
		typedParam("balloon.hugetlb_pgalloc", uint64(5)),
		typedParam("balloon.hugetlb_pgfail", uint64(1)),
		typedParam("vcpu.0.state", uint64(1)),
		typedParam("vcpu.0.time", cpuTime),
		typedParam("vcpu.0.delay", vcpuDelay),
		typedParam("vcpu.0.wait", vcpuWait),
		typedParam("block.0.name", diskPath),
		typedParam("block.0.rd.reqs", rdReqs),
		typedParam("block.0.rd.bytes", rdBytes),
		typedParam("block.0.rd.times", rdTime),
		typedParam("block.0.wr.reqs", wrReqs),
		typedParam("block.0.wr.bytes", wrBytes),
		typedParam("block.0.wr.times", wrTime),
		typedParam("block.0.fl.reqs", flushReqs),
		typedParam("block.0.fl.times", flushTime),
		typedParam("block.0.capacity", uint64(64<<30)),
		typedParam("block.0.allocation", uint64(32<<30)),
		typedParam("net.0.name", ifname),
		typedParam("net.0.rx.bytes", uint64(32<<20)),
		typedParam("net.0.rx.pkts", rxPkts),
		typedParam("net.0.rx.errs", uint64(1)),
		typedParam("net.0.rx.drop", rxDrop),
		typedParam("net.0.tx.bytes", uint64(16<<20)),
		typedParam("net.0.tx.pkts", txPkts),
		typedParam("net.0.tx.errs", uint64(2)),
		typedParam("net.0.tx.drop", txDrop),
	}

	sampleAt := now.Add(-time.Second)
	shard := shardIndex(instanceUUID)
	mc.im.cpuSamples[shard][instanceUUID] = cpuSample{
		total: cpuTime - 1_000_000_000, steal: vcpuDelay - 100_000_000, wait: vcpuWait - 50_000_000,
		vcpuCount: 1, stealPresent: true, waitPresent: true, ts: sampleAt,
	}
	diskKey := instanceUUID + "|" + volumeUUID + "|" + diskPath
	mc.im.diskSamples[shard][diskKey] = diskSample{
		rdReq: rdReqs - 100, wrReq: wrReqs - 60,
		rdBytes: rdBytes - (8 << 20), wrBytes: wrBytes - (4 << 20),
		rdTime: rdTime - 1_000_000_000, wrTime: wrTime - 600_000_000,
		flReq: flushReqs - 10, flTime: flushTime - 100_000_000,
		rwPresent: true, flushPresent: true, ts: sampleAt,
	}
	mc.im.memSamples[shard][instanceUUID] = memSample{
		swapIn: swapIn - 10, swapOut: swapOut - 5, majorFault: majorFaults - 10, minorFault: minorFaults - 100,
		swapInPresent: true, swapOutPresent: true, majorFaultPresent: true, minorFaultPresent: true, ts: sampleAt,
	}
	mc.im.netSamples[shard][instanceUUID] = netSample{
		rxPkts: rxPkts - 100, txPkts: txPkts - 75, rxDrop: rxDrop - 2, txDrop: txDrop - 1, interfaceSet: ifname, ts: sampleAt,
	}

	vmKey := IPStrToKey(vmIP)
	remoteKey := IPStrToKey(remoteIP)
	outbound := newBehaviorStats(true)
	outbound.updateDetailed(remoteKey, 10128, 6, IPS_SEEN_REPLY|IPS_ASSURED, 0, 4096, 4)
	outbound.updateOutboundMining(remoteKey, 10128, 6, IPS_SEEN_REPLY|IPS_ASSURED, true)
	inbound := newBehaviorStats(true)
	inbound.updateDetailed(remoteKey, 8443, 6, IPS_SEEN_REPLY|IPS_ASSURED, 0, 2048, 2)
	connAgg := &ConntrackAgg{
		VMIndex:            map[VMIPIdentity]uint32{{InstanceUUID: instanceUUID, IP: vmKey}: 0},
		InstanceFlowTotals: map[string]int{instanceUUID: 2},
		FlowsIn:            []int{1},
		FlowsOut:           []int{1},
		OutboundStats:      []*behaviorStats{outbound},
		InboundStats:       []*behaviorStats{inbound},
		SpamhausHits:       make(map[string]map[PairKey]ConntrackEntry),
		ProviderHits:       make(map[string]map[string]map[PairKey]ConntrackEntry),
	}
	entry := ConntrackEntry{
		Src: vmIP, Dst: remoteIP, SrcPort: 49152, DstPort: 10128,
		Proto: 6, Status: IPS_SEEN_REPLY | IPS_ASSURED, Bytes: 4096, Packets: 4,
	}
	pair := MakePairKey(vmKey, entry.SrcPort, remoteKey, entry.DstPort, entry.Proto)
	connAgg.SpamhausHits[instanceUUID] = map[PairKey]ConntrackEntry{pair: entry}
	for _, provider := range mc.tm.Providers {
		connAgg.ProviderHits[provider.Name] = map[string]map[PairKey]ConntrackEntry{
			instanceUUID: {pair: entry},
		}
	}
	mc.cm.miningAlerts[behaviorIdentityKey{InstanceUUID: instanceUUID, IP: vmKey, Direction: "outbound"}] = &miningAlertState{
		Hits:      3,
		Confirmed: true,
		Active:    true,
		Evidence: miningDetectionEvidence{
			Valid: true, Confidence: miningPortConfidenceHigh,
			miningTierSummary: miningTierSummary{Flows: 1, RepliedFlows: 1, UniqueRemotes: 1, UniquePorts: 1, TopPort: 10128, TopRemote: remoteKey},
		},
		Priority: "P4",
	}

	agg := &hostAgg{projects: make(map[string]struct{})}
	uuid, _ := pass1E2EUUID()
	record := libvirt.DomainStatsRecord{
		Dom:    libvirt.Domain{Name: domainName, UUID: uuid},
		Params: params,
	}
	mc.collectDomainMetrics(record, connAgg, nil, agg, 100000, true, false, true)

	// Force the first production host CPU read to be a valid delta while still
	// using the production host metric emitter for the family and value type.
	mc.hostCpuState = HostCpuState{initialized: true, prevTotal: -1, prevIdle: -1}
	metricCh := make(chan prometheus.Metric, 512)
	mc.emitHostAndAggMetrics(
		metricCh,
		[]libvirt.DomainStatsRecord{record},
		agg,
		1, 1, 1, 1,
		2, 100000, 0.00002, 1,
		true, true, true,
	)
	close(metricCh)
	metrics := make([]prometheus.Metric, 0, 160)
	for metric := range metricCh {
		metrics = append(metrics, metric)
	}

	registry := prometheus.NewRegistry()
	registry.MustRegister(pass1E2EMetricCollector{metrics: metrics})
	runtimeCollectors := defaultRuntimeCollectors()
	runtimeDescriptorNames := make(map[string]struct{}, 48)
	for _, collector := range runtimeCollectors {
		runtimeDescCh := make(chan *prometheus.Desc, 64)
		collector.Describe(runtimeDescCh)
		close(runtimeDescCh)
		for desc := range runtimeDescCh {
			match := descNameRE.FindStringSubmatch(desc.String())
			if len(match) != 2 {
				t.Fatalf("cannot parse default runtime descriptor: %s", desc)
			}
			if strings.HasPrefix(match[1], "go_") || strings.HasPrefix(match[1], "process_") {
				runtimeDescriptorNames[match[1]] = struct{}{}
			}
		}
	}
	for _, required := range []string{"go_build_info", "go_gc_duration_seconds", "process_cpu_seconds_total"} {
		if _, ok := runtimeDescriptorNames[required]; !ok {
			t.Fatalf("default runtime collector descriptor %s is missing", required)
		}
	}
	registry.MustRegister(runtimeCollectors...)
	families, err := registry.Gather()
	if err != nil {
		t.Fatalf("full production-shape Prometheus gather failed: %v", err)
	}

	// Some containerized test sandboxes expose a host-mounted /proc while
	// os.Getpid reports a namespace PID that is absent from that mount. The
	// production process collector is still registered and described there,
	// but cannot emit samples. In that specific case, gather the same library
	// collector against /proc/self's visible PID so its real types and schema
	// remain part of the compatibility contract.
	hasProcessFamily := false
	for _, family := range families {
		if strings.HasPrefix(family.GetName(), "process_") {
			hasProcessFamily = true
			break
		}
	}
	if !hasProcessFamily {
		visiblePID, err := os.Readlink("/proc/self")
		if err != nil {
			t.Fatalf("production process collector emitted no metrics and /proc/self is unavailable: %v", err)
		}
		pid, err := strconv.Atoi(strings.TrimSpace(visiblePID))
		if err != nil || pid <= 0 {
			t.Fatalf("production process collector emitted no metrics and /proc/self target %q is not a PID", visiblePID)
		}
		processRegistry := prometheus.NewRegistry()
		processRegistry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{
			PidFn: func() (int, error) { return pid, nil },
		}))
		processFamilies, err := processRegistry.Gather()
		if err != nil {
			t.Fatalf("fallback real process metric gather failed: %v", err)
		}
		families = append(families, processFamilies...)
	}
	gatheredRuntime := make(map[string]struct{}, len(runtimeDescriptorNames))
	for _, family := range families {
		name := family.GetName()
		if strings.HasPrefix(name, "go_") || strings.HasPrefix(name, "process_") {
			gatheredRuntime[name] = struct{}{}
		}
	}
	missingRuntime := make([]string, 0)
	for name := range runtimeDescriptorNames {
		if _, ok := gatheredRuntime[name]; !ok {
			missingRuntime = append(missingRuntime, name)
		}
	}
	sort.Strings(missingRuntime)
	if len(missingRuntime) != 0 {
		t.Fatalf("default runtime descriptor families were not gathered: %v", missingRuntime)
	}

	gatheredExporter := make(map[string]struct{}, len(descriptorNames))
	for _, family := range families {
		if strings.HasPrefix(family.GetName(), "oie_") {
			gatheredExporter[family.GetName()] = struct{}{}
		}
	}
	missing := make([]string, 0)
	for name := range descriptorNames {
		if _, ok := gatheredExporter[name]; !ok {
			missing = append(missing, name)
		}
	}
	unexpected := make([]string, 0)
	for name := range gatheredExporter {
		if _, ok := descriptorNames[name]; !ok {
			unexpected = append(unexpected, name)
		}
	}
	sort.Strings(missing)
	sort.Strings(unexpected)
	if len(missing) != 0 || len(unexpected) != 0 {
		t.Fatalf("full exporter metric coverage mismatch: missing=%v unexpected=%v", missing, unexpected)
	}

	return families, descriptorNames
}

func TestPass1FullPrometheusRegistrySchemaContract(t *testing.T) {
	families, descriptorNames := pass1FullRegistryFixture(t)

	contractFamilies := make([]*dto.MetricFamily, 0, len(families))
	for _, family := range families {
		name := family.GetName()
		if strings.HasPrefix(name, "oie_") || strings.HasPrefix(name, "go_") || strings.HasPrefix(name, "process_") {
			contractFamilies = append(contractFamilies, family)
		}
	}

	got := pass1EmittedMetricSchemaContract(contractFamilies)
	wantBytes, err := os.ReadFile("testdata/pass1-prometheus-full-registry-schema.golden")
	if err != nil {
		t.Fatal(err)
	}
	want := string(wantBytes)
	if got != want {
		t.Fatalf("full Prometheus registry schema changed\nexporter_descriptors=%d registry_families=%d\nwant:\n%s\ngot:\n%s", len(descriptorNames), len(contractFamilies), want, got)
	}
}
