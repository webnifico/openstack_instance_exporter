package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"
)

const dataIntegrityFlagContractHelperEnv = "OIE_DATA_INTEGRITY_FLAG_CONTRACT_HELPER"
const dataIntegrityFlagContractOutputEnv = "OIE_DATA_INTEGRITY_FLAG_CONTRACT_OUTPUT"
const dataIntegrityFlagProbeConfigEnv = "OIE_DATA_INTEGRITY_FLAG_PROBE_CONFIG"
const threatIntelligenceCLIFlagAdditionsGoldenPath = "testdata/cli-flags-v2.0.0-threat-intelligence-additions.golden"
const runtimeConfigurationCLIFlagAdditionsGoldenPath = "testdata/cli-flags-v2.0.0-runtime-configuration-additions.golden"
const volumeRetypeCLIFlagAddition = `volume.retype.enable|"false"|Enable attached-volume retype monitoring and progress polling`

func TestDataIntegrityCLIFlagContract(t *testing.T) {
	tempDir := t.TempDir()
	contractPath := tempDir + "/cli-flags.contract"
	missingConfigPath := tempDir + "/missing-behavior-ports.yaml"
	cmd := exec.Command(os.Args[0], "-test.run=^TestDataIntegrityCLIFlagContractSubprocess$")
	cmd.Env = append(os.Environ(),
		dataIntegrityFlagContractHelperEnv+"=1",
		dataIntegrityFlagContractOutputEnv+"="+contractPath,
		dataIntegrityFlagProbeConfigEnv+"="+missingConfigPath,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("collect runtime flag help: %v\n%s", err, out)
	}

	gotBytes, err := os.ReadFile(contractPath)
	if err != nil {
		t.Fatalf("read runtime flag contract: %v\n%s", err, out)
	}
	got := strings.TrimSpace(string(gotBytes))
	wantBytes, err := os.ReadFile("testdata/cli-flags-baseline.golden")
	if err != nil {
		t.Fatal(err)
	}
	wantLines := strings.Split(strings.TrimSpace(string(wantBytes)), "\n")
	threatIntelligenceBytes, err := os.ReadFile(threatIntelligenceCLIFlagAdditionsGoldenPath)
	if err != nil {
		t.Fatal(err)
	}
	wantLines = append(wantLines, strings.Split(strings.TrimSpace(string(threatIntelligenceBytes)), "\n")...)
	runtimeConfigurationBytes, err := os.ReadFile(runtimeConfigurationCLIFlagAdditionsGoldenPath)
	if err != nil {
		t.Fatal(err)
	}
	wantLines = append(wantLines, strings.Split(strings.TrimSpace(string(runtimeConfigurationBytes)), "\n")...)
	wantLines = append(wantLines, volumeRetypeCLIFlagAddition)
	sort.Strings(wantLines)
	want := strings.Join(wantLines, "\n")
	if got != want {
		t.Fatalf("CLI flag names, defaults, or help changed outside the frozen development baseline contract and reviewed Threat intelligence/Runtime configuration additions\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestDataIntegrityCLIFlagContractSubprocess(t *testing.T) {
	if os.Getenv(dataIntegrityFlagContractHelperEnv) != "1" {
		return
	}
	flag.CommandLine = flag.NewFlagSet("openstack_instance_exporter", flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)
	missingConfigPath := os.Getenv(dataIntegrityFlagProbeConfigEnv)
	if missingConfigPath == "" {
		t.Fatal("flag contract helper probe config path is empty")
	}
	os.Args = []string{"openstack_instance_exporter", "-behavior.ports_config=" + missingConfigPath}
	if code := runMain(); code != 2 {
		t.Fatalf("flag-registration probe exit=%d, want configuration rejection exit 2", code)
	}

	contracts := make([]string, 0, 48)
	flag.CommandLine.VisitAll(func(f *flag.Flag) {
		contracts = append(contracts, fmt.Sprintf("%s|%q|%s", f.Name, f.DefValue, f.Usage))
	})
	sort.Strings(contracts)
	outputPath := os.Getenv(dataIntegrityFlagContractOutputEnv)
	if outputPath == "" {
		t.Fatal("flag contract helper output path is empty")
	}
	if err := os.WriteFile(outputPath, []byte(strings.Join(contracts, "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
}
