package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"sort"
	"strings"
	"testing"
)

const dataIntegrityFlagContractHelperEnv = "OIE_DATA_INTEGRITY_FLAG_CONTRACT_HELPER"
const dataIntegrityFlagContractOutputEnv = "OIE_DATA_INTEGRITY_FLAG_CONTRACT_OUTPUT"
const dataIntegrityFlagProbeConfigEnv = "OIE_DATA_INTEGRITY_FLAG_PROBE_CONFIG"

func TestDataIntegrityCLIFlagContract(t *testing.T) {
	got := compatibilityRuntimeCLIContract(t)
	want := compatibilityReadNonEmptyLines(t, "testdata/contracts/cli-flags.txt")
	compatibilityAssertStringsEqual(t, "release CLI names, defaults and help", got, want)
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
