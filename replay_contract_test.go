package main

import (
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

var replayCalibrationCorpusPaths = []string{
	"testdata/replay/benign.yaml",
	"testdata/replay/abusive.yaml",
	"testdata/replay/lifecycle.yaml",
}

var replayCalibrationDefaultWarningSecurityAlerts = []string{
	"OpenStackInstanceOutboundPortScanBurst",
	"OpenStackInstanceInboundPortScanBurst",
	"OpenStackInstanceOutboundSingleTargetFlood",
	"OpenStackInstanceInboundSingleSourceFlood",
	"OpenStackInstanceOutboundSprayOnSinglePort",
	"OpenStackInstanceInboundSprayOnSinglePort",
	"OpenStackInstanceExporterHostThreatListed",
	"OpenStackInstanceMiningSuspected",
}

var replayCalibrationInternalBehaviorSignals = map[string]struct{}{
	"conntrack_flow_limit_exceeded":         {},
	"inbound_service_spray_suspected":       {},
	"inbound_udp_targeted_flood_suspected":  {},
	"outbound_distributed_fanout_unreplied": {},
	"outbound_horizontal_scan_suspected":    {},
	"outbound_single_remote_flood":          {},
	"outbound_stratum_mining_suspected":     {},
	"outbound_vertical_scan_suspected":      {},
	"smtp_spam_behavior_suspected":          {},
}

type replayCalibrationReplayCorpus struct {
	SchemaVersion int                              `yaml:"schema_version"`
	Category      string                           `yaml:"category"`
	Fixtures      []replayCalibrationReplayFixture `yaml:"fixtures"`
}

type replayCalibrationReplayFixture struct {
	ID                               string                       `yaml:"id"`
	Description                      string                       `yaml:"description"`
	Input                            replayCalibrationReplayInput `yaml:"input_observations"`
	ExpectedMetrics                  []string                     `yaml:"expected_metrics"`
	ForbiddenMetrics                 []string                     `yaml:"forbidden_metrics"`
	ExpectedStateTransitions         []string                     `yaml:"expected_state_transitions"`
	ExpectedAlert                    string                       `yaml:"expected_alert"`
	ForbiddenAlerts                  []string                     `yaml:"forbidden_alerts"`
	MaximumExpectedDetectionDelaySec int64                        `yaml:"maximum_expected_detection_delay_seconds"`
	ExpectedRecoveryBehavior         string                       `yaml:"expected_recovery_behavior"`
}

// replayCalibrationReplayInput is intentionally observation-shaped. It contains the
// bounded values an anonymized capture can retain without tenant addresses,
// payloads, names, UUIDs, or packet contents.
type replayCalibrationReplayInput struct {
	Engine              string   `yaml:"engine"`
	Direction           string   `yaml:"direction,omitempty"`
	Cycles              int      `yaml:"cycles"`
	IntervalSeconds     int64    `yaml:"interval_seconds"`
	Flows               int      `yaml:"flows,omitempty"`
	UniqueRemotes       int      `yaml:"unique_remotes,omitempty"`
	NewRemotes          int      `yaml:"new_remotes,omitempty"`
	UniqueDstPorts      int      `yaml:"unique_dst_ports,omitempty"`
	NewDstPorts         int      `yaml:"new_dst_ports,omitempty"`
	MaxSingleRemote     int      `yaml:"max_single_remote,omitempty"`
	MaxSingleDstPort    int      `yaml:"max_single_dst_port,omitempty"`
	TopDstPort          uint16   `yaml:"top_dst_port,omitempty"`
	UnrepliedRatio      float64  `yaml:"unreplied_ratio,omitempty"`
	TCPFlows            int      `yaml:"tcp_flows,omitempty"`
	TCPUnrepliedRatio   float64  `yaml:"tcp_unreplied_ratio,omitempty"`
	TCPTopRemoteFlows   int      `yaml:"tcp_top_remote_flows,omitempty"`
	TCPTopDstPortFlows  int      `yaml:"tcp_top_dst_port_flows,omitempty"`
	UDPFlows            int      `yaml:"udp_flows,omitempty"`
	UDPUniqueRemotes    int      `yaml:"udp_unique_remotes,omitempty"`
	UDPUnrepliedRatio   float64  `yaml:"udp_unreplied_ratio,omitempty"`
	UDPTopRemoteFlows   int      `yaml:"udp_top_remote_flows,omitempty"`
	UDPTopDstPortFlows  int      `yaml:"udp_top_dst_port_flows,omitempty"`
	SMTPFlows           int      `yaml:"smtp_flows,omitempty"`
	SMTPUniqueRemotes   int      `yaml:"smtp_unique_remotes,omitempty"`
	SMTPUnrepliedRatio  float64  `yaml:"smtp_unreplied_ratio,omitempty"`
	AdminPortFlows      int      `yaml:"admin_port_flows,omitempty"`
	AdminUniqueRemotes  int      `yaml:"admin_unique_remotes,omitempty"`
	AdminNewRemotes     int      `yaml:"admin_new_remotes,omitempty"`
	AdminUnrepliedRatio float64  `yaml:"admin_unreplied_ratio,omitempty"`
	HostImpactPercent   float64  `yaml:"host_impact_percent,omitempty"`
	ThresholdFlows      int      `yaml:"threshold_flows,omitempty"`
	InstanceFlowTotal   int      `yaml:"instance_flow_total,omitempty"`
	HostPressureOwner   bool     `yaml:"host_pressure_owner,omitempty"`
	FlowDeviation       float64  `yaml:"flow_deviation,omitempty"`
	RemoteDeviation     float64  `yaml:"remote_deviation,omitempty"`
	MiningPort          uint16   `yaml:"mining_port,omitempty"`
	MiningFlows         int      `yaml:"mining_flows,omitempty"`
	MiningRepliedFlows  int      `yaml:"mining_replied_flows,omitempty"`
	MiningUniqueRemotes int      `yaml:"mining_unique_remotes,omitempty"`
	CPUPercent          float64  `yaml:"cpu_percent,omitempty"`
	DiskReadIOPS        float64  `yaml:"disk_read_iops,omitempty"`
	DiskWriteIOPS       float64  `yaml:"disk_write_iops,omitempty"`
	ThreatSources       []string `yaml:"threat_sources,omitempty"`
	ThreatActiveFlows   int      `yaml:"threat_active_flows,omitempty"`
	ThreatOverlapCopies int      `yaml:"threat_overlap_copies,omitempty"`
	Event               string   `yaml:"event,omitempty"`
	FailureCycles       int      `yaml:"failure_cycles,omitempty"`
	ZoneA               uint16   `yaml:"zone_a,omitempty"`
	ZoneB               uint16   `yaml:"zone_b,omitempty"`
}

func replayCalibrationLoadReplayCorpus(t *testing.T, path string) replayCalibrationReplayCorpus {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	var corpus replayCalibrationReplayCorpus
	if err := decoder.Decode(&corpus); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err != nil {
			t.Fatalf("decode trailing %s data: %v", path, err)
		}
		t.Fatalf("%s contains another YAML document", path)
	}
	return corpus
}

func replayCalibrationAllReplayFixtures(t *testing.T) []replayCalibrationReplayFixture {
	t.Helper()
	var fixtures []replayCalibrationReplayFixture
	for _, path := range replayCalibrationCorpusPaths {
		fixtures = append(fixtures, replayCalibrationLoadReplayCorpus(t, path).Fixtures...)
	}
	return fixtures
}

func replayCalibrationExpectedFixtureIDs() map[string][]string {
	return map[string][]string{
		"benign": {
			"web_server", "reverse_proxy", "dns_resolver", "smtp_server_or_relay",
			"database_server", "database_replication", "monitoring_server", "vpn_appliance",
			"package_update", "backup_process", "high_legitimate_cpu", "high_legitimate_iops",
			"high_legitimate_connection_count", "high_legitimate_remote_breadth",
			"alternate_port_web_service", "long_lived_ordinary_tcp_connection",
		},
		"abusive": {
			"horizontal_scan", "vertical_scan", "distributed_probe", "inbound_service_spray",
			"smtp_abuse", "udp_flood", "single_target_flood", "conntrack_exhaustion",
			"dedicated_port_mining", "shared_port_mining_with_high_cpu",
			"shared_port_traffic_without_mining_corroboration", "low_cpu_or_gpu_like_mining",
			"tor_contact", "known_bad_remote_contact", "same_remote_overlapping_threat_lists",
		},
		"lifecycle": {
			"ipv4_conntrack_failure", "ipv6_conntrack_failure", "truncated_dump",
			"malformed_netlink_message", "enobufs", "timeout", "libvirt_outage",
			"per_domain_libvirt_failure", "counter_reset", "live_migration", "cold_migration",
			"instance_reboot", "instance_shutdown", "instance_deletion", "ip_reuse",
			"duplicate_tenant_ips_separate_ovn_zones", "exporter_restart", "threat_feed_outage",
			"threat_feed_recovery", "temporary_missing_resource_counters",
		},
	}
}

func replayCalibrationContainsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func TestReplayCalibrationReplayCorpusSchemaAndInventory(t *testing.T) {
	metricInventory := compatibilityDescriptorLabelOrder(t)
	alertInventory, _ := alertValidationRuleInventory(t)
	expectedIDs := replayCalibrationExpectedFixtureIDs()
	seenGlobal := make(map[string]string)
	total := 0

	for _, path := range replayCalibrationCorpusPaths {
		corpus := replayCalibrationLoadReplayCorpus(t, path)
		if corpus.SchemaVersion != 1 {
			t.Fatalf("%s schema_version=%d, want 1", path, corpus.SchemaVersion)
		}
		wantCategory := strings.TrimSuffix(filepath.Base(path), ".yaml")
		if corpus.Category != wantCategory {
			t.Fatalf("%s category=%q, want %q", path, corpus.Category, wantCategory)
		}
		wantIDs := append([]string(nil), expectedIDs[corpus.Category]...)
		gotIDs := make([]string, 0, len(corpus.Fixtures))
		for _, fixture := range corpus.Fixtures {
			total++
			gotIDs = append(gotIDs, fixture.ID)
			if previous, duplicate := seenGlobal[fixture.ID]; duplicate {
				t.Fatalf("fixture %q appears in both %s and %s", fixture.ID, previous, path)
			}
			seenGlobal[fixture.ID] = path
			if fixture.Description == "" || fixture.Input.Engine == "" || fixture.Input.Cycles <= 0 || fixture.Input.IntervalSeconds <= 0 {
				t.Fatalf("fixture %q has incomplete input observations: %+v", fixture.ID, fixture.Input)
			}
			if fixture.ExpectedMetrics == nil || fixture.ForbiddenMetrics == nil || len(fixture.ExpectedStateTransitions) == 0 || len(fixture.ForbiddenAlerts) == 0 || fixture.ExpectedAlert == "" || fixture.ExpectedRecoveryBehavior == "" {
				t.Fatalf("fixture %q omits a required expectation field", fixture.ID)
			}
			if fixture.MaximumExpectedDetectionDelaySec < 0 {
				t.Fatalf("fixture %q has negative detection delay", fixture.ID)
			}
			for _, name := range append(append([]string(nil), fixture.ExpectedMetrics...), fixture.ForbiddenMetrics...) {
				if _, ok := metricInventory[name]; !ok {
					t.Fatalf("fixture %q references unknown metric %q", fixture.ID, name)
				}
			}
			if fixture.ExpectedAlert != "none" {
				if _, public := alertInventory[fixture.ExpectedAlert]; !public {
					if _, internal := replayCalibrationInternalBehaviorSignals[fixture.ExpectedAlert]; !internal {
						t.Fatalf("fixture %q references unknown expected alert %q", fixture.ID, fixture.ExpectedAlert)
					}
				}
			}
			for _, forbidden := range fixture.ForbiddenAlerts {
				if forbidden == "default_warning_security" || forbidden == "unrelated_security_alert" {
					continue
				}
				if _, public := alertInventory[forbidden]; !public {
					if _, internal := replayCalibrationInternalBehaviorSignals[forbidden]; !internal {
						t.Fatalf("fixture %q references unknown forbidden alert %q", fixture.ID, forbidden)
					}
				}
			}
		}
		sort.Strings(gotIDs)
		sort.Strings(wantIDs)
		if !reflect.DeepEqual(gotIDs, wantIDs) {
			t.Fatalf("%s fixture IDs\nwant: %v\ngot:  %v", path, wantIDs, gotIDs)
		}
	}
	if total != 51 {
		t.Fatalf("Replay calibration fixture total=%d, want 51", total)
	}
}

func TestReplayCalibrationCorpusContainsNoTenantIdentifiersOrPayloads(t *testing.T) {
	for _, path := range replayCalibrationCorpusPaths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		text := strings.ToLower(string(data))
		for _, forbidden := range []string{
			"instance_uuid:", "project_uuid:", "user_uuid:", "server_name:",
			"payload:", "packet_payload:", "tenant_name:", "mac_address:",
		} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s contains non-anonymized field %q", path, forbidden)
			}
		}
	}
}

func TestReplayCalibrationPublicSurfaceAndThresholdsStayFrozen(t *testing.T) {
	if got := len(compatibilityDescriptorLabelOrder(t)); got != inventoryOIEFamilyCount {
		t.Fatalf("current Prometheus families=%d, want %d", got, inventoryOIEFamilyCount)
	}
	rules, order := alertValidationRuleInventory(t)
	if len(rules) != 62 || len(order) != 62 {
		t.Fatalf("Replay calibration bundled alerts=%d/%d, want 62", len(rules), len(order))
	}
	wantCLI := compatibilityReadNonEmptyLines(t, "testdata/contracts/cli-flags.txt")
	if got := compatibilityRuntimeCLIContract(t); !reflect.DeepEqual(got, wantCLI) {
		t.Fatalf("Replay calibration changed the exporter CLI\nwant: %v\ngot:  %v", wantCLI, got)
	}
	if defaultRuleThresholds != (RuleThresholds{
		MetadataHammerHits: 100, MetadataProbeHits: 30, MetadataProbeUnreplied: 0.60,
		InfraLateralUnreplied: 0.80, InfraLateralShareOfTotal: 0.30,
		DarkUnreplied: 0.80, DarkFlowsWithUnreplied: 20, DarkFlowsTotal: 50,
		SMTPFlows: 50, SMTPRemotes: 20, SMTPUnreplied: 0.30, SMTPPortDominanceShare: 0.70,
		StratumFlows: 2, StratumMaxRemotes: 10,
		DNSMinUDP: 10, DNSMinBytesPerFlow: 3000, DNSUnreplied: 0.60,
		UDPFanoutUDP: 100, UDPFanoutUnreplied: 0.90, UDPFanoutRemotes: 50,
	}) {
		t.Fatalf("Replay calibration changed production behavior thresholds without a fixture-backed calibration decision: %+v", defaultRuleThresholds)
	}
}

func TestReplayCalibrationDocumentationAndRequiredCIContracts(t *testing.T) {
	readme := dashboardDocumentationReadFile(t, "README.md")
	for _, statement := range []string{
		"(testdata/replay/)",
		"make check PROMTOOL=/path/to/promtool",
		"validate behavior and capacity on your own hosts",
	} {
		if !strings.Contains(readme, statement) {
			t.Errorf("README omits operator guidance %q", statement)
		}
	}
	workflow := ciReleaseLoadWorkflow(t, ".github/workflows/ci.yml")
	if got := strings.Count(ciReleaseWorkflowCommands(workflow), `make replay PROMTOOL="$PROMTOOL"`); got != 1 {
		t.Fatalf("required CI replay invocation count=%d, want 1", got)
	}
}
