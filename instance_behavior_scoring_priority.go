package main

import (
	"math"
)

func behaviorSeverityScore(feature BehaviorFeature) int {
	hostImpactPercent := feature.HostImpactPercent
	impactScore := clamp01(hostImpactPercent/10.0) * 100.0

	flowsScore := 0.0
	if feature.Flows > 0 {
		flowsScore = clamp01(math.Log10(1.0+float64(feature.Flows))/3.0) * 100.0
	}

	unrepliedScore := clamp01(feature.UnrepliedRatio) * 100.0

	policyScore := 0.0
	if feature.Flows > 0 {
		if feature.InfraHits > 0 {
			policyScore = math.Max(policyScore, clamp01(float64(feature.InfraMaxFlows)/float64(feature.Flows))*100.0)
		}
		if feature.LocalScanHits > 0 {
			policyScore = math.Max(policyScore, clamp01(float64(feature.LocalScanHits)/float64(feature.Flows))*100.0)
		}
		if feature.BGPFlows > 0 {
			policyScore = math.Max(policyScore, 100.0)
		}
		if feature.GeneveFlows > 0 {
			policyScore = math.Max(policyScore, 100.0)
		}
		if feature.MetadataHits > 0 {
			policyScore = math.Max(policyScore, clamp01(float64(feature.MetadataMaxFlows)/float64(feature.Flows))*100.0)
		}
		if feature.Direction == "inbound" && feature.AdminPortFlows > 0 {
			policyScore = math.Max(policyScore, clamp01(float64(feature.AdminPortFlows)/float64(feature.Flows))*100.0)
		}
	}

	sev := 0.35*impactScore + 0.30*flowsScore + 0.20*unrepliedScore + 0.15*policyScore
	if sev < 0 {
		sev = 0
	}
	if sev > 100 {
		sev = 100
	}
	return int(math.Round(sev))
}
func behaviorConfidenceScore(feature BehaviorFeature, kind string, topRemoteShare, topPortShare float64, evidenceMode string, persistenceHits int) int {
	dominanceScore := math.Max(topRemoteShare, topPortShare) * 100.0

	newnessScore := 0.0
	if feature.UniqueRemotes > 0 {
		newnessScore = math.Max(newnessScore, (float64(feature.NewRemotes)/float64(feature.UniqueRemotes))*100.0)
	}
	if feature.UniqueDstPorts > 0 {
		newnessScore = math.Max(newnessScore, (float64(feature.NewDstPorts)/float64(feature.UniqueDstPorts))*100.0)
	}

	hitsScore := clamp01(float64(persistenceHits)/3.0) * 100.0

	conf := 0.55*dominanceScore + 0.20*newnessScore + 0.25*hitsScore
	if evidenceMode == "distributed" && dominanceScore < 40.0 {
		conf *= 0.85
	}

	if (kind == "restricted_network_probe" || kind == "lateral_probe_suspected") && (feature.InfraHits > 0 || feature.LocalScanHits > 0) {
		if conf < 70.0 {
			conf = 70.0
		}
	}
	if kind == "bgp_peering_attempt" || kind == "geneve_underlay_attempt" {
		if conf < 80.0 {
			conf = 80.0
		}
	}
	if kind == "metadata_probe_suspected" || kind == "metadata_service_hammering" {
		if conf < 75.0 {
			conf = 75.0
		}
	}

	if feature.SynergyDarkScan {
		conf += 15.0
	}
	if feature.SynergyDarkPhysics {
		conf += 25.0
	}

	if conf < 0 {
		conf = 0
	}
	if conf > 100 {
		conf = 100
	}
	return int(math.Round(conf))
}
func behaviorSeverityBand(severityScore int) string {
	if severityScore >= 85 {
		return "critical"
	}
	if severityScore >= 65 {
		return "high"
	}
	if severityScore >= 35 {
		return "medium"
	}
	return "low"
}
func behaviorPriorityFromScores(severityScore, confidenceScore int) (string, string) {
	sev := severityScore
	conf := confidenceScore

	p := "P4"
	if sev >= 75 && conf >= 75 {
		p = "P1"
	} else if (sev >= 75 && conf >= 50) || (sev >= 50 && conf >= 75) {
		p = "P2"
	} else if (sev >= 50 && conf >= 50) || (sev >= 75 && conf >= 25) || (sev >= 25 && conf >= 75) {
		p = "P3"
	}

	basis := "mixed"
	if sev >= 75 && conf < 50 {
		basis = "severity"
	} else if conf >= 75 && sev < 50 {
		basis = "confidence"
	}

	return p, basis
}
func priorityRank(p string) int {
	switch p {
	case "P4":
		return 1
	case "P3":
		return 2
	case "P2":
		return 3
	case "P1":
		return 4
	default:
		return 1
	}
}
