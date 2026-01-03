package main

func initConntrackMetrics(cm *ConntrackManager) {
	cm.instanceConntrackIPFlowsDesc = newInstanceConntrackMetricDesc("oie_instance_conntrack_ip_flows", "Conntrack flow entries matched to this fixed IP (inbound + outbound)")
	cm.instanceConntrackIPFlowsInboundDesc = newInstanceConntrackMetricDesc("oie_instance_conntrack_ip_flows_inbound", "Inbound conntrack flow entries matched to this fixed IP (VM as destination)")
	cm.instanceConntrackIPFlowsOutboundDesc = newInstanceConntrackMetricDesc("oie_instance_conntrack_ip_flows_outbound", "Outbound conntrack flow entries matched to this fixed IP (VM as source)")

	cm.instanceOutboundUniqueRemotesDesc = newInstanceConntrackMetricDesc("oie_instance_outbound_unique_remotes", "Outbound unique remote IPs for this fixed IP in the current interval")
	cm.instanceOutboundNewRemotesDesc = newInstanceConntrackMetricDesc("oie_instance_outbound_new_remotes", "Outbound new remote IPs discovered since previous interval")
	cm.instanceOutboundFlowsDesc = newInstanceConntrackMetricDesc("oie_instance_outbound_flows", "Outbound conntrack flows initiated by this fixed IP in the current interval")
	cm.instanceOutboundMaxFlowsSingleRemoteDesc = newInstanceConntrackMetricDesc("oie_instance_outbound_max_flows_single_remote", "Maximum outbound flows to a single remote IP in the current interval")
	cm.instanceOutboundUniqueDstPortsDesc = newInstanceConntrackMetricDesc("oie_instance_outbound_unique_dst_ports", "Outbound unique destination ports in the current interval")
	cm.instanceOutboundNewDstPortsDesc = newInstanceConntrackMetricDesc("oie_instance_outbound_new_dst_ports", "Outbound new destination ports discovered since previous interval")
	cm.instanceOutboundMaxFlowsSingleDstPortDesc = newInstanceConntrackMetricDesc("oie_instance_outbound_max_flows_single_dst_port", "Maximum outbound flows to a single destination port in the current interval")
	cm.instanceOutboundBytesPerFlowDesc = newInstanceConntrackMetricDesc("oie_instance_outbound_bytes_per_flow", "Outbound average bytes per conntrack flow for this fixed IP (requires nf_conntrack_acct=1)")
	cm.instanceOutboundPacketsPerFlowDesc = newInstanceConntrackMetricDesc("oie_instance_outbound_packets_per_flow", "Outbound average packets per conntrack flow for this fixed IP (requires nf_conntrack_acct=1)")

	cm.instanceInboundUniqueRemotesDesc = newInstanceConntrackMetricDesc("oie_instance_inbound_unique_remotes", "Inbound unique remote IPs for this fixed IP in the current interval")
	cm.instanceInboundNewRemotesDesc = newInstanceConntrackMetricDesc("oie_instance_inbound_new_remotes", "Inbound new remote IPs discovered since previous interval")
	cm.instanceInboundFlowsDesc = newInstanceConntrackMetricDesc("oie_instance_inbound_flows", "Inbound conntrack flows targeting this fixed IP in the current interval")
	cm.instanceInboundMaxFlowsSingleRemoteDesc = newInstanceConntrackMetricDesc("oie_instance_inbound_max_flows_single_remote", "Maximum inbound flows from a single remote IP in the current interval")
	cm.instanceInboundUniqueDstPortsDesc = newInstanceConntrackMetricDesc("oie_instance_inbound_unique_dst_ports", "Inbound unique destination ports on this fixed IP in the current interval")
	cm.instanceInboundNewDstPortsDesc = newInstanceConntrackMetricDesc("oie_instance_inbound_new_dst_ports", "Inbound new destination ports discovered since previous interval")
	cm.instanceInboundMaxFlowsSingleDstPortDesc = newInstanceConntrackMetricDesc("oie_instance_inbound_max_flows_single_dst_port", "Maximum inbound flows to a single destination port in the current interval")
	cm.instanceInboundBytesPerFlowDesc = newInstanceConntrackMetricDesc("oie_instance_inbound_bytes_per_flow", "Inbound average bytes per conntrack flow for this fixed IP (requires nf_conntrack_acct=1)")
	cm.instanceInboundPacketsPerFlowDesc = newInstanceConntrackMetricDesc("oie_instance_inbound_packets_per_flow", "Inbound average packets per conntrack flow for this fixed IP (requires nf_conntrack_acct=1)")
}
