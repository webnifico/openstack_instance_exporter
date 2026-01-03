package main

import (
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
)

func initThreatMetrics(tm *ThreatManager) {
	// Initialize Generic Providers
	for _, p := range tm.Providers {
		p.InstanceContactsTotalDesc = newThreatDomainInstanceDirectionDesc(p.InstanceContactsMetricName, fmt.Sprintf("Total %s contacts for this instance (presence over intervals)", p.Name))
		p.InstanceActiveFlowsDesc = newThreatDomainInstanceDirectionDesc(p.InstanceActiveMetricName, fmt.Sprintf("Active %s flows for this instance", p.Name))
		p.HostRefreshLastSuccessDesc = newHostMetricDesc(p.HostRefreshLastMetricName, fmt.Sprintf("Last successful %s refresh (unix timestamp)", p.Name))
		p.HostRefreshDurationDesc = newHostMetricDesc(p.HostRefreshDurationMetricName, fmt.Sprintf("Duration of last %s refresh in seconds", p.Name))
		p.HostRefreshErrorsDesc = newHostMetricDesc(p.HostRefreshErrorsMetricName, fmt.Sprintf("Total %s refresh errors", p.Name))
		p.HostEntriesDesc = newHostMetricDesc(p.HostEntriesMetricName, fmt.Sprintf("Number of %s IPs currently loaded", p.Name))
	}

	// Initialize Spamhaus (Special Case: CIDRs)
	tm.instanceSpamhausContactsTotalDesc = newThreatDomainInstanceDirectionDesc("oie_instance_threat_spamhaus_contacts_total", "Total Spamhaus DROP contacts for this instance (presence over intervals)")
	tm.instanceSpamhausActiveFlowsDesc = newThreatDomainInstanceDirectionDesc("oie_instance_threat_spamhaus_active_flows", "Active Spamhaus DROP flows for this instance")
	tm.hostSpamhausRefreshLastSuccessTimestampDesc = newHostMetricDesc("oie_host_threat_spamhaus_refresh_last_success_timestamp_seconds", "Last successful Spamhaus list refresh (unix timestamp)")
	tm.hostSpamhausRefreshDurationSecondsDesc = newHostMetricDesc("oie_host_threat_spamhaus_refresh_duration_seconds", "Duration of last Spamhaus list refresh in seconds")
	tm.hostSpamhausRefreshErrorsTotalDesc = newHostMetricDesc("oie_host_threat_spamhaus_refresh_errors_total", "Total Spamhaus list refresh errors")
	tm.hostSpamhausEntriesDesc = newHostMetricDesc("oie_host_threat_spamhaus_entries", "Number of Spamhaus CIDRs currently loaded")

	tm.hostThreatListedDesc = prometheus.NewDesc("oie_host_threat_provider_ip_listed", "Provider-owned host IP present in a threat list (1 = member)", []string{"list", "ip", "family"}, nil)
}
func (tm *ThreatManager) describeThreatMetrics(ch chan<- *prometheus.Desc) {
	for _, p := range tm.Providers {
		ch <- p.InstanceContactsTotalDesc
		ch <- p.InstanceActiveFlowsDesc
	}
	ch <- tm.instanceSpamhausContactsTotalDesc
	ch <- tm.instanceSpamhausActiveFlowsDesc
}
