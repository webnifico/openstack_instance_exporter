package main

type behaviorAlertEvent struct {
	Feature             BehaviorFeature
	Evidence            behaviorAlertEvidence
	Kind                string
	Reason              string
	Detail              string
	PersistenceHits     int
	PersistenceRequired int
	EmitReason          string
	SeverityScore       int
	ConfidenceScore     int
	SeverityBand        string
	PriorityBasis       string
	Priority            string
	HostImpact          float64
	BehaviorSignal      float64
	ConntrackAcct       bool
	SrcIP               string
	DstIP               string
	Mining              miningDetectionEvidence
}

type behaviorAlertTarget struct {
	Domain       string
	ServerName   string
	InstanceUUID string
	ProjectUUID  string
	ProjectName  string
	UserUUID     string
}

func buildBehaviorAlertKVs(event behaviorAlertEvent) []interface{} {
	feature := event.Feature
	ev := event.Evidence
	alertKVs := []interface{}{
		"kind", event.Kind,
		"reason", event.Reason,
		"detail", event.Detail,
		"direction", feature.Direction,
		"synergy_darkspace_scan", feature.SynergyDarkScan,
		"synergy_darkspace_physics", feature.SynergyDarkPhysics,
		"threshold_flows", feature.ThresholdFlows,
		"local_scan_hits", feature.LocalScanHits,
		"infra_hits", feature.InfraHits,
		"infra_max_flows", feature.InfraMaxFlows,
		"tenant_private_hits", feature.TenantPrivateHits,
		"tenant_private_max_flows", feature.TenantPrivateMaxFlows,
		"flows_current", feature.Flows,
		"unique_remotes", feature.UniqueRemotes,
		"unique_remotes_saturated", feature.UniqueRemotesSaturated,
		"new_remotes", feature.NewRemotes,
		"new_remotes_saturated", feature.NewRemotesSaturated,
		"unique_ports", feature.UniqueDstPorts,
		"new_ports", feature.NewDstPorts,
		"top_dst_port", int(ev.TopDstPort),
		"top_dst_port_name", ev.TopDstPortName,
		"top_remote_ip", ev.TopRemoteIP,
		"top_remote_share", ev.TopRemoteShare,
		"top_port_share", ev.TopPortShare,
		"evidence_mode", ev.EvidenceMode,
		"persistence_hits", event.PersistenceHits,
		"persistence_required", event.PersistenceRequired,
		"emit_reason", event.EmitReason,
		"severity_score", event.SeverityScore,
		"confidence_score", event.ConfidenceScore,
		"severity_band", event.SeverityBand,
		"priority_basis", event.PriorityBasis,
		"unreplied_ratio", roundToFiveDecimals(feature.UnrepliedRatio),
		"multicast_count", feature.MulticastCount,
		"icmp_count", feature.ICMPCount,
		"udp_count", feature.UDPCount,
		"host_impact_percent", roundToFiveDecimals(event.HostImpact * 100),
		"behavior_signal", roundToFiveDecimals(event.BehaviorSignal),
		"conntrack_acct", event.ConntrackAcct,
		"bytes_per_flow", roundToFiveDecimals(feature.BytesPerFlow),
		"packets_per_flow", roundToFiveDecimals(feature.PacketsPerFlow),
		"remote_map_capped", feature.RemoteMapCapped,
		"src_ip", event.SrcIP,
		"dst_ip", event.DstIP,
		"priority", event.Priority,
	}
	if event.Mining.Valid {
		alertKVs = append(alertKVs,
			"mining_port_confidence", event.Mining.Confidence.String(),
			"mining_flows", event.Mining.Flows,
			"mining_replied_flows", event.Mining.RepliedFlows,
			"mining_unique_remotes", event.Mining.UniqueRemotes,
			"mining_unique_ports", event.Mining.UniquePorts,
		)
	}
	if !feature.RemoteEvidenceApproximate {
		alertKVs = append(alertKVs, "max_flows_single_remote", feature.MaxSingleRemote)
	}
	return append(alertKVs, "max_flows_single_port", feature.MaxSingleDstPort)
}

func (cm *ConntrackManager) routeBehaviorAlert(target behaviorAlertTarget, alertKVs []interface{}) {
	if cm.LogThreat != nil {
		callbackKVs := append([]interface{}{"server_name", target.ServerName}, alertKVs...)
		cm.LogThreat("BEHAVIOR", "behavior_alert", target.Domain, target.InstanceUUID, target.ProjectUUID, target.ProjectName, target.UserUUID, callbackKVs...)
		return
	}
	kvs := append([]interface{}{"domain", target.Domain, "server_name", target.ServerName}, alertKVs...)
	kvs = append(kvs, "instance_uuid", target.InstanceUUID)
	logKV(LogLevelNotice, "behavior", "behavior", "behavior_alert", kvs...)
}
