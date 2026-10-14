package main

import (
	"encoding/json"
	"os"

	"strings"
	"testing"
)

type scoringRemovalContract struct {
	Alerts     []string `json:"alerts"`
	Recordings []string `json:"recordings"`
	Metrics    []string `json:"metrics"`
	Flags      []string `json:"flags"`
}

func scoringRemovals(t *testing.T) scoringRemovalContract {
	t.Helper()
	data, err := os.ReadFile("testdata/contracts/unsupported-interfaces.json")
	if err != nil {
		t.Fatal(err)
	}
	var contract scoringRemovalContract
	if err := json.Unmarshal(data, &contract); err != nil {
		t.Fatal(err)
	}
	return contract
}

var scoringRemovedLogFields = []string{
	"severity_score", "confidence_score", "severity_band", "priority", "priority_basis", "behavior_signal",
	"previous_priority", "new_priority", "previous_severity_band", "new_severity_band", "threat_ewma_tau",
}

func TestScoringRemovalPublicSurfaceAndRuntimeEvents(t *testing.T) {
	c := scoringRemovals(t)
	if len(c.Metrics) != 8 || len(c.Flags) != 4 || len(c.Alerts) != 17 || len(c.Recordings) != 3 {
		t.Fatal("unexpected removal manifest")
	}
	labels := compatibilityDescriptorLabelOrder(t)
	for _, name := range c.Metrics {
		if _, ok := labels[name]; ok {
			t.Errorf("retired score metric %s remains", name)
		}
	}
	if strings.Contains(labels["oie_instance_mining_suspected"], "priority") {
		t.Fatal("mining priority label remains")
	}
	sources := compatibilityParseProductionSources(t)
	loggers := compatibilityDiscoverComponentLoggers(t, sources)
	providers := compatibilityDiscoverProviderBindings(t, sources)
	callsites, _, _ := compatibilityDiscoverLogCallsites(t, sources, loggers, providers)
	for _, callsite := range callsites {
		if callsite.Message == "resource_v2_event" {
			t.Error("resource score events remain")
		}
		for _, field := range callsite.Fields {
			for _, forbidden := range scoringRemovedLogFields {
				if field == forbidden {
					t.Errorf("%s still emits %s", callsite.Message, field)
				}
			}
		}
	}
	for _, name := range c.Flags {
		t.Run(name, func(t *testing.T) {
			if code := runMainForTest(t, "-"+name+"=1"); code != 2 {
				t.Fatalf("retired flag exit=%d", code)
			}
		})
	}
}

func TestDistributedFanoutNeedsBothBaselineChangesAndMeasuredFailures(t *testing.T) {
	cm := &ConntrackManager{behaviorSensitivity: 1}
	base := BehaviorFeature{Direction: "outbound", Flows: 120, UniqueRemotes: 80, UniqueDstPorts: 20, MaxSingleRemote: 2, MaxSingleDstPort: 6, UnrepliedRatio: 0.65}
	for _, tt := range []struct {
		name           string
		flows, remotes float64
		count, breadth int
		failures       float64
		hit            bool
	}{
		{"both deviations and measured failures", .8, .8, 120, 80, .65, true},
		{"flow change alone", 1, .79, 120, 80, .65, false},
		{"remote change alone", .79, 1, 120, 80, .65, false},
		{"replied traffic", 1, 1, 120, 80, .59, false},
		{"too few flows", 1, 1, 19, 80, .65, false},
		{"too few remotes", 1, 1, 120, 29, .65, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			feature := base
			feature.Flows = tt.count
			feature.UniqueRemotes = tt.breadth
			feature.UnrepliedRatio = tt.failures
			hit, signal, _ := cm.classifyOutboundScanning(feature, behaviorAnomalies{Flows: tt.flows, Remotes: tt.remotes}, newBehaviorScaler(1))
			if hit != tt.hit || (hit && signal != "outbound_distributed_fanout_unreplied") {
				t.Fatalf("hit=%v signal=%s, want hit=%v", hit, signal, tt.hit)
			}
		})
	}
}

func TestScoringRemovalRetiredInterfacesDoNotRemainInProductionSource(t *testing.T) {
	contract := scoringRemovals(t)
	forbidden := append([]string{}, contract.Metrics...)
	forbidden = append(forbidden, contract.Flags...)
	forbidden = append(forbidden, contract.Alerts...)
	forbidden = append(forbidden,
		"severity_score", "confidence_score", "severity_band", "priority_basis",
		"previous_priority", "new_priority", "previous_severity_band", "new_severity_band",
		"threat_ewma_tau",
	)

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		content, err := os.ReadFile(entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		text := string(content)
		for _, retired := range forbidden {
			if strings.Contains(text, retired) {
				t.Errorf("unsupported interface %q remains in production source %s", retired, entry.Name())
			}
		}
	}

	operatorForbidden := append([]string{}, contract.Flags...)
	for _, flagName := range contract.Flags {
		operatorForbidden = append(operatorForbidden, "openstack_instance_exporter_"+strings.ReplaceAll(flagName, ".", "_"))
	}
	for _, path := range []string{
		"ansible_role/openstack_instance_exporter/defaults/main.yml",
		"ansible_role/openstack_instance_exporter/templates/openstack_instance_exporter.service.j2",
	} {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		text := string(content)
		for _, retired := range operatorForbidden {
			if strings.Contains(text, retired) {
				t.Errorf("unsupported interface %q remains in current operator asset %s", retired, path)
			}
		}
	}
}
