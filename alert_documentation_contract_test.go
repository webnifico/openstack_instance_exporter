package main

import (
	"strings"
	"testing"
)

func TestAlertValidationREADMEContract(t *testing.T) {
	readme := dashboardDocumentationReadFile(t, "README.md")
	for _, statement := range []string{
		"(README.md#alerting)",
		"(examples/prometheus_alerts_example/openstack_instance_exporter_alerts.yml)",
		"No OIE recording or notification rules are needed for dashboards.",
		"62 enabled alerts and 30 helper recording rules",
	} {
		if !strings.Contains(readme, statement) {
			t.Errorf("README omits operator guidance %q", statement)
		}
	}
}

func TestAlertValidationDocumentationContract(t *testing.T) {
	readme := dashboardDocumentationReadFile(t, "README.md")
	for _, statement := range []string{
		"prometheus_alert_rules",
		"not native Prometheus",
		"seven hours",
		"relevant workload impact and their alert hold",
		"Conditions, holds and severity are editable in the policy.",
		"Dashboards work without this file",
		"Alertmanager handles routing and delivery.",
		"helper calculations precede dependent alerts in the rendered evaluation group",
	} {
		if !strings.Contains(readme, statement) {
			t.Errorf("README omits operator guidance %q", statement)
		}
	}
}

func TestReleasePublicInterfaces(t *testing.T) {
	t.Run("Metrics", TestMetricNamesAndLabelsMatchRelease)
	t.Run("MetricSchema", TestReleasePrometheusMetricSchema)
	t.Run("CLI", TestDataIntegrityCLIFlagContract)
	t.Run("Ansible", TestDataIntegrityAnsibleRoleSemanticContract)
	t.Run("Alerts", TestAlertInventoryMatchesRelease)
	t.Run("AlertPolicy", TestReleaseAlertPolicySemanticContract)
	t.Run("StructuredLogs", TestCompatibilityStructuredLogProductionCallsitesMatchExpected)
}
