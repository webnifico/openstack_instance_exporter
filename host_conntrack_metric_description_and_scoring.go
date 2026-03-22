package main

import (
	"github.com/prometheus/client_golang/prometheus"
)

func (cm *ConntrackManager) describeConntrackMetrics(ch chan<- *prometheus.Desc) {
	descs := []*prometheus.Desc{
		cm.instanceConntrackIPFlowsDesc, cm.instanceConntrackIPFlowsInboundDesc, cm.instanceConntrackIPFlowsOutboundDesc,
		cm.instanceOutboundUniqueRemotesDesc, cm.instanceOutboundNewRemotesDesc, cm.instanceOutboundFlowsDesc,
		cm.instanceOutboundMaxFlowsSingleRemoteDesc, cm.instanceOutboundUniqueDstPortsDesc, cm.instanceOutboundNewDstPortsDesc,
		cm.instanceOutboundMaxFlowsSingleDstPortDesc,
		cm.instanceOutboundBytesPerFlowDesc, cm.instanceOutboundPacketsPerFlowDesc,
		cm.instanceInboundUniqueRemotesDesc, cm.instanceInboundNewRemotesDesc, cm.instanceInboundFlowsDesc,
		cm.instanceInboundMaxFlowsSingleRemoteDesc, cm.instanceInboundUniqueDstPortsDesc, cm.instanceInboundNewDstPortsDesc,
		cm.instanceInboundMaxFlowsSingleDstPortDesc,
		cm.instanceInboundBytesPerFlowDesc, cm.instanceInboundPacketsPerFlowDesc,
	}
	for _, d := range descs {
		ch <- d
	}
}

func (cm *ConntrackManager) calculateConntrackMetrics(
	fixedIPs []IP,
	connAgg *ConntrackAgg,
	ipSet map[string]struct{},
	hostIPs map[string]struct{},
	hostConntrackMax uint64,
	domain, serverName, instanceUUID, projectUUID, projectName, userUUID string,
	dynamicMetrics *[]prometheus.Metric,
) (float64, float64, int) {

	var outboundSignal, inboundSignal float64
	instanceConntrackTotal := 0

	hostIPKeys := make(map[IPKey]struct{}, len(hostIPs))
	for ipStr := range hostIPs {
		k := IPStrToKey(ipStr)
		if k == (IPKey{}) {
			continue
		}
		hostIPKeys[k] = struct{}{}
	}

	instanceFlowTotal := 0
	if connAgg != nil && connAgg.InstanceFlowTotals != nil {
		instanceFlowTotal = connAgg.InstanceFlowTotals[instanceUUID]
	}

	ctx := BehaviorContext{
		HostIPs:           hostIPs,
		HostIPKeys:        hostIPKeys,
		HostConntrackMax:  hostConntrackMax,
		InstanceFlowTotal: instanceFlowTotal,
	}

	for _, ip := range fixedIPs {
		addr := ip.Address
		if addr == "" {
			continue
		}

		addrKey := IPStrToKey(addr)

		in := 0
		out := 0

		var outStats *behaviorStats
		var inStats *behaviorStats

		if connAgg != nil {
			if connAgg.VMIndex != nil {
				if idx, ok := connAgg.VMIndex[VMIPIdentity{InstanceUUID: instanceUUID, IP: addrKey}]; ok {
					i := int(idx)
					if i >= 0 && i < len(connAgg.FlowsIn) {
						in = connAgg.FlowsIn[i]
					}
					if i >= 0 && i < len(connAgg.FlowsOut) {
						out = connAgg.FlowsOut[i]
					}

					if cm.outboundBehaviorEnabled && i >= 0 && i < len(connAgg.OutboundStats) {
						outStats = connAgg.OutboundStats[i]
					}
					if cm.inboundBehaviorEnabled && i >= 0 && i < len(connAgg.InboundStats) {
						inStats = connAgg.InboundStats[i]
					}
				}
			}
		}

		total := in + out

		*dynamicMetrics = append(*dynamicMetrics,
			prometheus.MustNewConstMetric(cm.instanceConntrackIPFlowsDesc, prometheus.GaugeValue, float64(total), domain, serverName, instanceUUID, projectUUID, projectName, userUUID, addr, ip.Family),
			prometheus.MustNewConstMetric(cm.instanceConntrackIPFlowsInboundDesc, prometheus.GaugeValue, float64(in), domain, serverName, instanceUUID, projectUUID, projectName, userUUID, addr, ip.Family),
			prometheus.MustNewConstMetric(cm.instanceConntrackIPFlowsOutboundDesc, prometheus.GaugeValue, float64(out), domain, serverName, instanceUUID, projectUUID, projectName, userUUID, addr, ip.Family),
		)

		if cm.outboundBehaviorEnabled && outStats != nil {
			val := cm.analyzeBehavior(
				outStats,
				addrKey,
				addr,
				ip.Family,
				domain, serverName, instanceUUID, projectUUID, projectName, userUUID,
				dynamicMetrics,
				metricDescGroup{
					uniqueRemotes:      cm.instanceOutboundUniqueRemotesDesc,
					newRemotes:         cm.instanceOutboundNewRemotesDesc,
					flows:              cm.instanceOutboundFlowsDesc,
					maxSingleRemote:    cm.instanceOutboundMaxFlowsSingleRemoteDesc,
					uniqueDstPorts:     cm.instanceOutboundUniqueDstPortsDesc,
					newDstPorts:        cm.instanceOutboundNewDstPortsDesc,
					maxSingleDstPort:   cm.instanceOutboundMaxFlowsSingleDstPortDesc,
					bytesPerFlow:       cm.instanceOutboundBytesPerFlowDesc,
					packetsPerFlow:     cm.instanceOutboundPacketsPerFlowDesc,
					thresholdConfigKey: "outbound",
				},
				ctx,
			)
			if val > outboundSignal {
				outboundSignal = val
			}
		}

		if cm.inboundBehaviorEnabled && inStats != nil {
			val := cm.analyzeBehavior(
				inStats,
				addrKey,
				addr,
				ip.Family,
				domain, serverName, instanceUUID, projectUUID, projectName, userUUID,
				dynamicMetrics,
				metricDescGroup{
					uniqueRemotes:      cm.instanceInboundUniqueRemotesDesc,
					newRemotes:         cm.instanceInboundNewRemotesDesc,
					flows:              cm.instanceInboundFlowsDesc,
					maxSingleRemote:    cm.instanceInboundMaxFlowsSingleRemoteDesc,
					uniqueDstPorts:     cm.instanceInboundUniqueDstPortsDesc,
					newDstPorts:        cm.instanceInboundNewDstPortsDesc,
					maxSingleDstPort:   cm.instanceInboundMaxFlowsSingleDstPortDesc,
					bytesPerFlow:       cm.instanceInboundBytesPerFlowDesc,
					packetsPerFlow:     cm.instanceInboundPacketsPerFlowDesc,
					thresholdConfigKey: "inbound",
				},
				ctx,
			)
			if val > inboundSignal {
				inboundSignal = val
			}
		}
	}

	if connAgg != nil && connAgg.InstanceFlowTotals != nil {
		instanceConntrackTotal = connAgg.InstanceFlowTotals[instanceUUID]
	}

	_ = ipSet

	return outboundSignal, inboundSignal, instanceConntrackTotal
}
