package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const replayCalibrationPriorGoldenSHA256Path = "testdata/replay-calibration-prior-golden-sha256.golden"

var replayCalibrationCorpusPaths = []string{
	"testdata/replay/benign.yaml",
	"testdata/replay/abusive.yaml",
	"testdata/replay/lifecycle.yaml",
}

var replayCalibrationDefaultWarningSecurityAlerts = []string{
	"OpenStackInstanceThreatScoreHigh",
	"OpenStackInstanceThreatScoreSevere",
	"OpenStackInstanceOutboundPortScanBurst",
	"OpenStackInstanceInboundPortScanBurst",
	"OpenStackInstanceOutboundSingleTargetFlood",
	"OpenStackInstanceInboundSingleSourceFlood",
	"OpenStackInstanceOutboundSprayOnSinglePort",
	"OpenStackInstanceInboundSprayOnSinglePort",
	"OpenStackInstanceExporterHostThreatListed",
	"OpenStackInstanceMiningSuspected",
}

var replayCalibrationInternalBehaviorAlerts = map[string]struct{}{
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
	ExpectedSeverityRange            replayCalibrationReplayRange `yaml:"expected_severity_range"`
	ExpectedStateTransitions         []string                     `yaml:"expected_state_transitions"`
	ExpectedAlert                    string                       `yaml:"expected_alert"`
	ForbiddenAlerts                  []string                     `yaml:"forbidden_alerts"`
	MaximumExpectedDetectionDelaySec int64                        `yaml:"maximum_expected_detection_delay_seconds"`
	ExpectedRecoveryBehavior         string                       `yaml:"expected_recovery_behavior"`
}

type replayCalibrationReplayRange struct {
	Min float64 `yaml:"min"`
	Max float64 `yaml:"max"`
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
	AnomalySignal       float64  `yaml:"anomaly_signal,omitempty"`
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
			if len(fixture.ExpectedMetrics) == 0 || len(fixture.ForbiddenMetrics) == 0 || len(fixture.ExpectedStateTransitions) == 0 || len(fixture.ForbiddenAlerts) == 0 || fixture.ExpectedAlert == "" || fixture.ExpectedRecoveryBehavior == "" {
				t.Fatalf("fixture %q omits a required expectation field", fixture.ID)
			}
			if fixture.ExpectedSeverityRange.Min < 0 || fixture.ExpectedSeverityRange.Max > 100 || fixture.ExpectedSeverityRange.Min > fixture.ExpectedSeverityRange.Max {
				t.Fatalf("fixture %q has invalid severity range %+v", fixture.ID, fixture.ExpectedSeverityRange)
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
					if _, internal := replayCalibrationInternalBehaviorAlerts[fixture.ExpectedAlert]; !internal {
						t.Fatalf("fixture %q references unknown expected alert %q", fixture.ID, fixture.ExpectedAlert)
					}
				}
			}
			for _, forbidden := range fixture.ForbiddenAlerts {
				if forbidden == "default_warning_security" || forbidden == "unrelated_security_alert" {
					continue
				}
				if _, public := alertInventory[forbidden]; !public {
					if _, internal := replayCalibrationInternalBehaviorAlerts[forbidden]; !internal {
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

func TestReplayCalibrationPriorGoldenAssetsAreByteFrozen(t *testing.T) {
	manifest, err := os.ReadFile(replayCalibrationPriorGoldenSHA256Path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(manifest)), "\n")
	if len(lines) != 40 {
		t.Fatalf("prior golden hash records=%d, want 40", len(lines))
	}
	wantPaths := make(map[string]struct{}, len(lines))
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 2 || len(fields[0]) != 64 || !strings.HasPrefix(fields[1], "testdata/") {
			t.Fatalf("invalid prior-golden hash record %q", line)
		}
		if _, duplicate := wantPaths[fields[1]]; duplicate {
			t.Fatalf("duplicate prior-golden hash path %q", fields[1])
		}
		wantPaths[fields[1]] = struct{}{}
		content, err := os.ReadFile(fields[1])
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(content)); got != fields[0] {
			t.Fatalf("frozen golden %s changed: sha256=%s want=%s", fields[1], got, fields[0])
		}
	}
	paths, err := filepath.Glob("testdata/*golden*")
	if err != nil {
		t.Fatal(err)
	}
	gotPaths := make(map[string]struct{})
	for _, path := range paths {
		if strings.Contains(filepath.Base(path), "replay-calibration") || strings.Contains(filepath.Base(path), "scaling") {
			continue
		}
		gotPaths[filepath.ToSlash(path)] = struct{}{}
	}
	if !reflect.DeepEqual(gotPaths, wantPaths) {
		t.Fatalf("Compatibility baseline through CI and release validation golden asset set changed\nwant: %v\ngot:  %v", wantPaths, gotPaths)
	}
}

func TestReplayCalibrationPublicSurfaceAndThresholdsStayFrozen(t *testing.T) {
	if got := len(compatibilityDescriptorLabelOrder(t)); got != inventoryOIEFamilyCount {
		t.Fatalf("current Prometheus families=%d, want %d", got, inventoryOIEFamilyCount)
	}
	rules, order := alertValidationRuleInventory(t)
	if len(rules) != 78 || len(order) != 78 {
		t.Fatalf("Replay calibration bundled alerts=%d/%d, want frozen 78", len(rules), len(order))
	}
	wantCLI := append(compatibilityReadNonEmptyLines(t, "testdata/cli-flags-baseline.golden"), compatibilityReadNonEmptyLines(t, threatIntelligenceCLIFlagAdditionsGoldenPath)...)
	wantCLI = append(wantCLI, compatibilityReadNonEmptyLines(t, runtimeConfigurationCLIFlagAdditionsGoldenPath)...)
	wantCLI = append(wantCLI, volumeRetypeCLIFlagAddition)
	sort.Strings(wantCLI)
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
	contractBytes, err := os.ReadFile("REPLAY_CALIBRATION.md")
	if err != nil {
		t.Fatal(err)
	}
	contractText := string(contractBytes)
	for _, statement := range []string{
		"51 anonymized replay fixtures",
		"16 benign, 15 abusive, and 20 failure/lifecycle",
		"The fixture-backed calibration retains the documented production thresholds.",
		"No benign fixture produces a warning-level security alert in that baseline.",
		"Overlapping threat feeds are scored from one deduplicated flow union.",
		"Scaling validation owns production-scale performance measurements",
	} {
		if !strings.Contains(contractText, statement) {
			t.Fatalf("Replay calibration contract is missing %q", statement)
		}
	}
	readmeBytes, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(readmeBytes), "[`REPLAY_CALIBRATION.md`](REPLAY_CALIBRATION.md)"); got != 1 {
		t.Fatalf("README Replay calibration contract link count=%d, want 1", got)
	}
	workflow := ciReleaseLoadWorkflow(t, ".github/workflows/ci.yml")
	if got := strings.Count(ciReleaseWorkflowCommands(workflow), `make replay PROMTOOL="$PROMTOOL"`); got != 1 {
		t.Fatalf("required CI replay invocation count=%d, want 1", got)
	}
}
