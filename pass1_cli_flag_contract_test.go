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

const passOneFlagContractHelperEnv = "OIE_PASS_ONE_FLAG_CONTRACT_HELPER"
const passOneFlagContractOutputEnv = "OIE_PASS_ONE_FLAG_CONTRACT_OUTPUT"
const passOneFlagProbeConfigEnv = "OIE_PASS_ONE_FLAG_PROBE_CONFIG"

func TestPassOneCLIFlagContract(t *testing.T) {
	tempDir := t.TempDir()
	contractPath := tempDir + "/cli-flags.contract"
	missingConfigPath := tempDir + "/missing-behavior-ports.yaml"
	cmd := exec.Command(os.Args[0], "-test.run=^TestPassOneCLIFlagContractSubprocess$")
	cmd.Env = append(os.Environ(),
		passOneFlagContractHelperEnv+"=1",
		passOneFlagContractOutputEnv+"="+contractPath,
		passOneFlagProbeConfigEnv+"="+missingConfigPath,
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
	wantBytes, err := os.ReadFile("testdata/cli-flags-v1.3.0.golden")
	if err != nil {
		t.Fatal(err)
	}
	want := strings.TrimSpace(string(wantBytes))
	if got != want {
		t.Fatalf("CLI flag names, defaults, or help changed\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestPassOneCLIFlagContractSubprocess(t *testing.T) {
	if os.Getenv(passOneFlagContractHelperEnv) != "1" {
		return
	}
	flag.CommandLine = flag.NewFlagSet("openstack_instance_exporter", flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)
	missingConfigPath := os.Getenv(passOneFlagProbeConfigEnv)
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
	outputPath := os.Getenv(passOneFlagContractOutputEnv)
	if outputPath == "" {
		t.Fatal("flag contract helper output path is empty")
	}
	if err := os.WriteFile(outputPath, []byte(strings.Join(contracts, "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
}
