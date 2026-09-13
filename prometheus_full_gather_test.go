package main

import (
	"strings"
	"testing"
	"time"

	libvirt "github.com/digitalocean/go-libvirt"
	"github.com/prometheus/client_golang/prometheus"
)

type staticMetricCollector struct {
	metrics []prometheus.Metric
}

func TestEveryExporterDescriptorCanConstructAndGatherConstMetric(t *testing.T) {
	mc, err := NewMetricsCollector(CollectorConfig{LibvirtURI: "qemu:///system", CollectionInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer close(mc.shutdownChan)

	descCh := make(chan *prometheus.Desc, 512)
	mc.Describe(descCh)
	close(descCh)
	metrics := make([]prometheus.Metric, 0, 128)
	seenNames := make(map[string]struct{}, 128)
	for desc := range descCh {
		descText := desc.String()
		nameMatch := descNameRE.FindStringSubmatch(descText)
		if len(nameMatch) != 2 {
			t.Fatalf("cannot parse descriptor name: %s", descText)
		}
		name := nameMatch[1]
		if _, duplicate := seenNames[name]; duplicate {
			t.Fatalf("duplicate descriptor name %s", name)
		}
		seenNames[name] = struct{}{}

		labelValues := []string{}
		if labelMatch := descLabelsRE.FindStringSubmatch(descText); len(labelMatch) == 2 && strings.TrimSpace(labelMatch[1]) != "" {
			labels := strings.Split(labelMatch[1], ",")
			labelValues = make([]string, len(labels))
			for i := range labels {
				labelValues[i] = "test"
			}
		}
		valueType := prometheus.GaugeValue
		if strings.HasSuffix(name, "_total") {
			valueType = prometheus.CounterValue
		}
		metric, err := prometheus.NewConstMetric(desc, valueType, 0, labelValues...)
		if err != nil {
			t.Fatalf("descriptor %s cannot create a metric: %v", name, err)
		}
		metrics = append(metrics, metric)
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(staticMetricCollector{metrics: metrics})
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("full descriptor gather failed: %v", err)
	}
	if len(families) != len(seenNames) {
		t.Fatalf("gathered metric families = %d, descriptors = %d", len(families), len(seenNames))
	}
}

func (c staticMetricCollector) Describe(ch chan<- *prometheus.Desc) {
	prometheus.DescribeByCollect(c, ch)
}

func (c staticMetricCollector) Collect(ch chan<- prometheus.Metric) {
	for _, metric := range c.metrics {
		ch <- metric
	}
}

func TestFullRegistryGatherRejectsNoDuplicateFixedIPOrInterfaceSeries(t *testing.T) {
	mc, err := NewMetricsCollector(CollectorConfig{
		LibvirtURI:          "qemu:///system",
		WorkerCount:         1,
		CollectionInterval:  time.Second,
		ConntrackIPv4Enable: false,
		ConntrackIPv6Enable: false,
	})
	if err != nil {
		t.Fatalf("NewMetricsCollector: %v", err)
	}
	var uuid libvirt.UUID
	for i := range uuid {
		uuid[i] = byte(i + 1)
	}
	instanceUUID := uuidBytesToString(uuid[:])
	mc.im.domainMeta[instanceUUID] = &DomainStatic{
		Name:         "server",
		InstanceUUID: instanceUUID,
		ProjectUUID:  "project",
		ProjectName:  "project-name",
		UserUUID:     "user",
		VCPUCount:    1,
		MemMB:        1024,
		FixedIPs: []IP{
			{Address: "10.0.0.10", Family: "4"},
			{Address: "10.0.0.10", Family: "ipv4"},
		},
		Interfaces:  []string{"tap0", "tap0"},
		LastUpdated: time.Now(),
	}
	params := []libvirt.TypedParam{
		typedParam("state.state", int32(libvirt.DomainRunning)),
		typedParam("balloon.current", uint64(1024*1024)),
		typedParam("balloon.usable", uint64(512*1024)),
	}
	for _, index := range []string{"0", "1"} {
		params = append(params,
			typedParam("net."+index+".name", "tap0"),
			typedParam("net."+index+".rx.bytes", uint64(100)),
			typedParam("net."+index+".tx.bytes", uint64(100)),
			typedParam("net."+index+".rx.pkts", uint64(10)),
			typedParam("net."+index+".tx.pkts", uint64(10)),
			typedParam("net."+index+".rx.errs", uint64(0)),
			typedParam("net."+index+".tx.errs", uint64(0)),
			typedParam("net."+index+".rx.drop", uint64(0)),
			typedParam("net."+index+".tx.drop", uint64(0)),
		)
	}
	ip := IPStrToKey("10.0.0.10")
	connAgg := &ConntrackAgg{
		VMIndex:            map[VMIPIdentity]uint32{{InstanceUUID: instanceUUID, IP: ip}: 0},
		InstanceFlowTotals: map[string]int{instanceUUID: 0},
		FlowsIn:            []int{0},
		FlowsOut:           []int{0},
		OutboundStats:      []*behaviorStats{nil},
		InboundStats:       []*behaviorStats{nil},
	}
	agg := &hostAgg{projects: make(map[string]struct{})}
	mc.collectDomainMetrics(
		libvirt.DomainStatsRecord{Dom: libvirt.Domain{Name: "domain", UUID: uuid}, Params: params},
		connAgg,
		nil,
		agg,
		1000,
		true,
		true,
		true,
	)
	reg := prometheus.NewRegistry()
	reg.MustRegister(staticMetricCollector{metrics: agg.metrics})
	if _, err := reg.Gather(); err != nil {
		t.Fatalf("full Prometheus gather failed: %v", err)
	}
}
