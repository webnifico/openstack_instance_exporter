package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
)

func TestBehaviorPortConfigStatusAndFallbackMatrix(t *testing.T) {
	builtinIn := builtinBehaviorInboundMonitoredPorts()
	builtinOut := builtinBehaviorOutboundMonitoredPorts()
	for _, path := range []string{"", "   "} {
		in, out, status := BuildBehaviorPortMaps(path)
		if status.Status != "not_configured" || status.Using != "builtin" || len(in) != len(builtinIn) || len(out) != len(builtinOut) {
			t.Fatalf("blank config status=%+v in=%d out=%d", status, len(in), len(out))
		}
	}
	missing := writeConfigTestFile(t, "placeholder", "x") + ".missing"
	in, out, status := BuildBehaviorPortMaps(missing)
	if status.Status != "missing" || status.Using != "builtin" || status.Err == "" || len(in) != len(builtinIn) || len(out) != len(builtinOut) {
		t.Fatalf("missing config status=%+v", status)
	}

	tests := []struct {
		name       string
		contents   string
		wantStatus string
	}{
		{"malformed", "behavior: [", "parse_error"},
		{"multiple documents", "behavior: {}\n---\nbehavior: {}\n", "parse_error"},
		{"no maps", "behavior:\n  ports: {}\n", "invalid"},
		{"zero inbound port", "behavior:\n  ports:\n    inbound_monitored:\n      0: bad\n", "invalid"},
		{"large inbound port", "behavior:\n  ports:\n    inbound_monitored:\n      65536: bad\n", "invalid"},
		{"empty inbound name", "behavior:\n  ports:\n    inbound_monitored:\n      22: '  '\n", "invalid"},
		{"zero outbound port", "behavior:\n  ports:\n    outbound_monitored:\n      -1: bad\n", "invalid"},
		{"empty outbound name", "behavior:\n  ports:\n    outbound_monitored:\n      443: ''\n", "invalid"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := writeConfigTestFile(t, "ports.yml", tc.contents)
			in, out, status := BuildBehaviorPortMaps(path)
			if status.Status != tc.wantStatus || status.Using != "builtin" || status.Err == "" {
				t.Fatalf("status=%+v, want %q builtin fallback", status, tc.wantStatus)
			}
			if len(in) != len(builtinIn) || len(out) != len(builtinOut) {
				t.Fatal("invalid config did not retain complete built-in maps")
			}
		})
	}
}

func TestBehaviorPortConfigSupportsMixedAndFullReplacement(t *testing.T) {
	inOnly := writeConfigTestFile(t, "in.yml", "behavior:\n  ports:\n    inbound_monitored:\n      2222: ' custom ssh '\n")
	in, out, status := BuildBehaviorPortMaps(inOnly)
	if status.Status != "loaded" || status.Using != "mixed" || len(in) != 1 || in[2222] != "custom ssh" || out[443] != "https" {
		t.Fatalf("inbound-only config in=%v out443=%q status=%+v", in, out[443], status)
	}

	outOnly := writeConfigTestFile(t, "out.yml", "behavior:\n  ports:\n    outbound_monitored:\n      4443: custom_https\n")
	in, out, status = BuildBehaviorPortMaps(outOnly)
	if status.Status != "loaded" || status.Using != "mixed" || in[22] != "ssh" || len(out) != 1 || out[4443] != "custom_https" {
		t.Fatalf("outbound-only config in22=%q out=%v status=%+v", in[22], out, status)
	}

	both := writeConfigTestFile(t, "both.yml", "behavior:\n  ports:\n    inbound_monitored: {22: ssh-only}\n    outbound_monitored: {443: https-only}\n")
	in, out, status = BuildBehaviorPortMaps(both)
	if status.Status != "loaded" || status.Using != "file" || len(in) != 1 || len(out) != 1 || in[22] != "ssh-only" || out[443] != "https-only" {
		t.Fatalf("full replacement in=%v out=%v status=%+v", in, out, status)
	}

	if got, err := validateBehaviorPortMap(map[int]string{1: " one "}); err != nil || got[1] != "one" {
		t.Fatalf("direct port validation=(%v,%v)", got, err)
	}
}

func TestExternalRuleConfigValidationMatrix(t *testing.T) {
	if rules, status := LoadBehaviorExternalRules(""); rules != nil || status.Status != "not_configured" {
		t.Fatalf("blank external rules=(%v,%+v)", rules, status)
	}
	if rules, status := LoadBehaviorExternalRules(writeConfigTestFile(t, "placeholder", "x") + ".missing"); rules != nil || status.Status != "error" || status.Err == "" {
		t.Fatalf("missing external rules=(%v,%+v)", rules, status)
	}

	var tooMany strings.Builder
	tooMany.WriteString("rules:\n")
	for i := 0; i <= maxExternalBehaviorRules; i++ {
		fmt.Fprintf(&tooMany, "  - {id: r%d, ports: [80], kind: test}\n", i)
	}
	tests := []struct {
		name string
		yaml string
	}{
		{"malformed", "rules: ["},
		{"multiple documents", "rules: [{id: a, ports: [80], kind: a}]\n---\nrules: []\n"},
		{"no rules", "port_sets: {web: [80]}\n"},
		{"too many", tooMany.String()},
		{"empty port set name", "port_sets:\n  '': [80]\nrules: [{id: a, port_set: '', kind: a}]\n"},
		{"invalid port set port", "port_sets: {bad: [0]}\nrules: [{id: a, port_set: bad, kind: a}]\n"},
		{"empty port set", "port_sets: {bad: []}\nrules: [{id: a, port_set: bad, kind: a}]\n"},
		{"missing id", "rules: [{ports: [80], kind: a}]\n"},
		{"missing kind", "rules: [{id: a, ports: [80]}]\n"},
		{"invalid direction", "rules: [{id: a, direction: sideways, ports: [80], kind: a}]\n"},
		{"unknown port set", "rules: [{id: a, port_set: missing, kind: a}]\n"},
		{"no ports", "rules: [{id: a, kind: a}]\n"},
		{"negative flows", "rules: [{id: a, ports: [80], flows_min: -1, kind: a}]\n"},
		{"negative remotes", "rules: [{id: a, ports: [80], unique_remotes_min: -1, kind: a}]\n"},
		{"invalid evidence mode", "rules: [{id: a, ports: [80], evidence_mode: narrow, kind: a}]\n"},
		{"invalid remote share low", "rules: [{id: a, ports: [80], top_remote_share_min: -0.1, kind: a}]\n"},
		{"invalid port share high", "rules: [{id: a, ports: [80], top_port_share_min: 1.1, kind: a}]\n"},
		{"non-finite unreplied ratio", "rules: [{id: a, ports: [80], ratios: {unreplied: .nan}, kind: a}]\n"},
		{"non-finite remote share", "rules: [{id: a, ports: [80], top_remote_share_min: .inf, kind: a}]\n"},
		{"non-finite port share", "rules: [{id: a, ports: [80], top_port_share_min: -.inf, kind: a}]\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := writeConfigTestFile(t, "rules.yml", tc.yaml)
			rules, status := LoadBehaviorExternalRules(path)
			if rules != nil || status.Status != "error" || status.Err == "" {
				t.Fatalf("invalid rules=(%v,%+v)", rules, status)
			}
		})
	}
}

func TestExternalRuleCompilationAndPredicateBoundaries(t *testing.T) {
	path := writeConfigTestFile(t, "rules.yml", `port_sets:
  web: [80, 443, 443]
rules:
  - id: strict_web
    direction: outbound
    port_set: web
    ports: [8080]
    flows_min: 10
    unique_remotes_min: 3
    ratios: {unreplied: 0.5}
    evidence_mode: dominant_port
    top_remote_share_min: 0.2
    top_port_share_min: 0.6
    kind: custom_web_probe
    reason: configured_reason
    severity: CRITICAL
  - id: defaulted
    ports: [53]
    kind: dns_rule
`)
	rules, status := LoadBehaviorExternalRules(path)
	if status.Status != "loaded" || status.Rules != 2 || status.PortSets != 1 || len(rules) != 2 {
		t.Fatalf("compiled rules=%v status=%+v", rules, status)
	}
	strict := rules[0]
	baseFeature := BehaviorFeature{Direction: "outbound", TopDstPort: 80, Flows: 10, UniqueRemotes: 3, UnrepliedRatio: 0.5}
	baseEvidence := BehaviorEvidence{EvidenceMode: "dominant_port", TopRemoteShare: 0.2, TopPortShare: 0.6}
	if !strict.When(baseFeature, newBehaviorScaler(1), baseEvidence, nil) {
		t.Fatal("strict rule did not match at all configured boundaries")
	}
	if strict.Kind(baseFeature, newBehaviorScaler(1), baseEvidence, nil) != "custom_web_probe" || strict.Reason(baseFeature, newBehaviorScaler(1), baseEvidence, nil) != "configured_reason" {
		t.Fatal("compiled rule lost configured kind or reason")
	}

	failures := []struct {
		name     string
		feature  BehaviorFeature
		evidence BehaviorEvidence
		ctx      *RuleCtx
	}{
		{"direction", func() BehaviorFeature { f := baseFeature; f.Direction = "inbound"; return f }(), baseEvidence, nil},
		{"port", func() BehaviorFeature { f := baseFeature; f.TopDstPort = 22; return f }(), baseEvidence, nil},
		{"flows", func() BehaviorFeature { f := baseFeature; f.Flows = 9; return f }(), baseEvidence, nil},
		{"remotes", func() BehaviorFeature { f := baseFeature; f.UniqueRemotes = 2; return f }(), baseEvidence, nil},
		{"unreplied", func() BehaviorFeature { f := baseFeature; f.UnrepliedRatio = 0.49; return f }(), baseEvidence, nil},
		{"mode", baseFeature, func() BehaviorEvidence { e := baseEvidence; e.EvidenceMode = "mixed"; return e }(), nil},
		{"remote share", baseFeature, func() BehaviorEvidence { e := baseEvidence; e.TopRemoteShare = 0.19; return e }(), nil},
		{"port share", baseFeature, func() BehaviorEvidence { e := baseEvidence; e.TopPortShare = 0.59; return e }(), nil},
		{"context port", baseFeature, baseEvidence, &RuleCtx{DstPortCounts: map[uint16]int{22: 5}}},
	}
	for _, tc := range failures {
		if strict.When(tc.feature, newBehaviorScaler(1), tc.evidence, tc.ctx) {
			t.Fatalf("strict rule matched failing %s case", tc.name)
		}
	}
	if !strict.When(baseFeature, newBehaviorScaler(1), baseEvidence, &RuleCtx{DstPortCounts: map[uint16]int{8080: 1}}) {
		t.Fatal("strict rule did not match an explicitly counted configured port")
	}
	defaulted := rules[1]
	if defaulted.Dir != "any" || defaulted.Source != "external" || defaulted.Reason(BehaviorFeature{}, newBehaviorScaler(1), BehaviorEvidence{}, nil) != "external_rule_match" {
		t.Fatalf("defaulted rule=%+v", defaulted)
	}
}

func runMainForTest(t *testing.T, args ...string) int {
	t.Helper()
	oldArgs := os.Args
	oldCommandLine := flag.CommandLine
	os.Args = append([]string{"openstack-instance-exporter-test"}, args...)
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	t.Cleanup(func() {
		os.Args = oldArgs
		flag.CommandLine = oldCommandLine
	})
	return runMain()
}

func TestRunMainRejectsInvalidStartupConfiguration(t *testing.T) {
	if code := runMainForTest(t, "-contacts.direction=sideways"); code != 2 {
		t.Fatalf("invalid contact direction exit=%d, want 2", code)
	}
}

func TestRunMainRejectsUnsupportedCollectorAndTelemetryConfiguration(t *testing.T) {
	if code := runMainForTest(t, "-libvirt.uri=qemu+ssh://host/system"); code != 1 {
		t.Fatalf("unsupported libvirt URI exit=%d, want 1", code)
	}
}

func TestRunMainReturnsNonzeroOnBindFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if code := runMainForTest(t,
		"-web.listen-address="+listener.Addr().String(),
		"-web.telemetry-path=/metrics",
		"-conntrack.ipv4.enable=false",
		"-conntrack.ipv6.enable=false",
	); code != 1 {
		t.Fatalf("bind failure exit=%d, want 1", code)
	}
}
