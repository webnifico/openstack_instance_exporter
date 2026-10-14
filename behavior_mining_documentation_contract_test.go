package main

import (
	"strings"
	"testing"
)

func TestBehaviorMiningDocumentationContract(t *testing.T) {
	readme := dashboardDocumentationReadFile(t, "README.md")
	for _, statement := range []string{
		"Behavior directions, threat feeds and retype monitoring are opt-in.",
		"not proof of compromise or mining",
		"Guest processes and payloads are outside OIE",
	} {
		if !strings.Contains(readme, statement) {
			t.Errorf("README omits operator guidance %q", statement)
		}
	}
}

func TestBehaviorMiningREADMEContract(t *testing.T) {
	readme := dashboardDocumentationReadFile(t, "ansible_role/openstack_instance_exporter/README.md")
	for _, statement := range []string{
		"(defaults/main.yml)",
		"profiles and custom-file examples",
		"5s through 1m",
		"Explicit variables override profiles.",
	} {
		if !strings.Contains(readme, statement) {
			t.Errorf("README omits operator guidance %q", statement)
		}
	}
}
