package main

import (
	"fmt"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	miningBehaviorKind   = "outbound_stratum_mining_suspected"
	miningBehaviorRuleID = "proto_stratum_mining"
)

type miningAlertState struct {
	Hits          int
	FirstSeenUnix int64
	LastSeenUnix  int64
	Confirmed     bool
	Active        bool

	Evidence      miningDetectionEvidence
	Priority      string
	PriorityBasis string
	SeverityBand  string

	CandidateTopRemote  IPKey
	CandidateTopDstPort uint16

	LastEmitPriority     string
	LastEmitSeverityBand string
	LastEmitTopRemote    string
	LastEmitTopDstPort   uint16
	LastEpisodeStartUnix int64
	LastEmitUnix         int64
}

type miningAlertOutcome struct {
	Active               bool
	Confirmed            bool
	ShouldEmit           bool
	EmitReason           string
	SuppressReason       string
	PersistenceHits      int
	PersistenceRequired  int
	SeverityScore        int
	ConfidenceScore      int
	Priority             string
	PriorityBasis        string
	SeverityBand         string
	PreviousPriority     string
	PreviousSeverityBand string
	Evidence             miningDetectionEvidence
	AlertEvidence        behaviorAlertEvidence
}

func (cm *ConntrackManager) updateMiningAlertState(feature BehaviorFeature, ident behaviorIdentityKey, nowUnix int64) miningAlertOutcome {
	if feature.Direction != "outbound" || !feature.Mining.Valid {
		cm.behaviorAlertMu.Lock()
		if state := cm.miningAlerts[ident]; state != nil {
			// This path is reached only for a complete collection. Freeze-state
			// cycles use miningAlertSnapshot instead. A real clean cycle breaks
			// persistence; intermittent unrelated matches must not accumulate.
			state.Hits = 0
			state.FirstSeenUnix = 0
			state.LastSeenUnix = 0
			state.Confirmed = false
			state.Active = false
			state.Evidence = miningDetectionEvidence{}
			state.CandidateTopRemote = IPKey{}
			state.CandidateTopDstPort = 0
		}
		cm.behaviorAlertMu.Unlock()
		return miningAlertOutcome{}
	}

	alertEvidence := cm.buildBehaviorAlertEvidence(feature, IPKey{}, false, miningBehaviorKind)

	cm.behaviorAlertMu.Lock()
	defer cm.behaviorAlertMu.Unlock()
	if cm.miningAlerts == nil {
		cm.miningAlerts = make(map[behaviorIdentityKey]*miningAlertState)
	}
	state := cm.miningAlerts[ident]
	if state == nil {
		state = &miningAlertState{FirstSeenUnix: nowUnix}
		cm.miningAlerts[ident] = state
	}
	// Persistence must describe one stable endpoint. Alternating unrelated
	// shared/dedicated port hits must not combine into a mining classification.
	if !state.Confirmed && state.Hits > 0 &&
		(state.CandidateTopRemote != feature.Mining.TopRemote || state.CandidateTopDstPort != feature.Mining.TopPort) {
		state.Hits = 0
		state.FirstSeenUnix = nowUnix
		state.LastSeenUnix = 0
		state.Active = false
	}
	if state.FirstSeenUnix == 0 {
		state.FirstSeenUnix = nowUnix
	}
	state.CandidateTopRemote = feature.Mining.TopRemote
	state.CandidateTopDstPort = feature.Mining.TopPort

	emissionState := behaviorEmitState{
		LastPriority:         state.LastEmitPriority,
		LastSeverityBand:     state.LastEmitSeverityBand,
		LastTopRemote:        state.LastEmitTopRemote,
		LastTopDstPort:       state.LastEmitTopDstPort,
		LastEpisodeStartUnix: state.LastEpisodeStartUnix,
		LastEmitUnix:         state.LastEmitUnix,
	}
	if state.LastEmitUnix != 0 {
		emissionState.LastKind = miningBehaviorKind
	}
	transition := evaluateBehaviorAlertTransition(behaviorAlertTransitionInput{
		NowUnix:  nowUnix,
		Kind:     miningBehaviorKind,
		Feature:  feature,
		Evidence: alertEvidence,
		Persistence: behaviorPersistState{
			Hits:          state.Hits,
			FirstSeenUnix: state.FirstSeenUnix,
			LastSeenUnix:  state.LastSeenUnix,
		},
		Emission: emissionState,
	})

	if transition.PersistenceReset {
		state.Confirmed = false
		state.Active = false
	}
	state.Hits = transition.Persistence.Hits
	state.FirstSeenUnix = transition.Persistence.FirstSeenUnix
	state.LastSeenUnix = transition.Persistence.LastSeenUnix
	confirmed := transition.PersistenceSatisfied
	directAlertEligible := feature.Mining.Confidence == miningPortConfidenceHigh
	shouldEmit := transition.ShouldEmit && directAlertEligible
	suppressReason := transition.SuppressReason
	if confirmed && !directAlertEligible {
		suppressReason = "corroboration_required"
	}

	outcome := miningAlertOutcome{
		Active:               confirmed,
		Confirmed:            confirmed,
		ShouldEmit:           shouldEmit,
		EmitReason:           transition.EmitReason,
		SuppressReason:       suppressReason,
		PersistenceHits:      transition.Persistence.Hits,
		PersistenceRequired:  transition.PersistenceRequired,
		SeverityScore:        transition.SeverityScore,
		ConfidenceScore:      transition.ConfidenceScore,
		Priority:             transition.Priority,
		PriorityBasis:        transition.PriorityBasis,
		SeverityBand:         transition.SeverityBand,
		PreviousPriority:     transition.PreviousPriority,
		PreviousSeverityBand: transition.PreviousSeverityBand,
		Evidence:             feature.Mining,
		AlertEvidence:        alertEvidence,
	}

	state.Confirmed = state.Confirmed || confirmed
	state.Active = confirmed
	if confirmed {
		state.Evidence = feature.Mining
		state.Priority = transition.Priority
		state.PriorityBasis = transition.PriorityBasis
		state.SeverityBand = transition.SeverityBand
	}
	if shouldEmit {
		state.LastEmitPriority = transition.Emission.LastPriority
		state.LastEmitSeverityBand = transition.Emission.LastSeverityBand
		state.LastEmitTopRemote = transition.Emission.LastTopRemote
		state.LastEmitTopDstPort = transition.Emission.LastTopDstPort
		state.LastEpisodeStartUnix = transition.Emission.LastEpisodeStartUnix
		state.LastEmitUnix = transition.Emission.LastEmitUnix
	}
	return outcome
}

func (cm *ConntrackManager) miningAlertSnapshot(ident behaviorIdentityKey) miningAlertOutcome {
	cm.behaviorAlertMu.Lock()
	defer cm.behaviorAlertMu.Unlock()
	state := cm.miningAlerts[ident]
	if state == nil || !state.Active || !state.Confirmed || !state.Evidence.Valid {
		return miningAlertOutcome{}
	}
	return miningAlertOutcome{
		Active:        true,
		Confirmed:     true,
		Priority:      state.Priority,
		PriorityBasis: state.PriorityBasis,
		SeverityBand:  state.SeverityBand,
		Evidence:      state.Evidence,
	}
}

func (cm *ConntrackManager) appendMiningMetric(
	metrics *[]prometheus.Metric,
	outcome miningAlertOutcome,
	domain, serverName, instanceUUID, projectUUID, projectName, userUUID, addr, family string,
) {
	if metrics == nil || cm.instanceMiningSuspectedDesc == nil || !outcome.Active || !outcome.Confirmed || !outcome.Evidence.Valid {
		return
	}
	*metrics = append(*metrics, prometheus.MustNewConstMetric(
		cm.instanceMiningSuspectedDesc,
		prometheus.GaugeValue,
		1,
		domain,
		serverName,
		instanceUUID,
		projectUUID,
		projectName,
		userUUID,
		addr,
		family,
		strconv.Itoa(int(outcome.Evidence.TopPort)),
		builtinMiningPortName(outcome.Evidence.TopPort),
		outcome.Evidence.Confidence.String(),
		outcome.Priority,
	))
}

func applyConfirmedBehaviorPriorityFloor(severity float64, outcome miningAlertOutcome) float64 {
	if !outcome.Confirmed {
		return severity
	}
	switch outcome.Priority {
	case "P1":
		return 1
	case "P2":
		if severity < 0.7 {
			return 0.7
		}
	case "P3":
		if severity < 0.5 {
			return 0.5
		}
	}
	return severity
}

func (cm *ConntrackManager) emitMiningBehaviorAlert(
	feature BehaviorFeature,
	stats *behaviorStats,
	outcome miningAlertOutcome,
	addr, domain, serverName, instanceUUID, projectUUID, projectName, userUUID string,
	ctx BehaviorContext,
	hostImpact, behaviorSignal float64,
	acctEnabled bool,
	nowUnix int64,
) {
	if !outcome.ShouldEmit {
		return
	}
	if outcome.Evidence.Confidence != miningPortConfidenceHigh {
		// These are observable candidates, not standalone structured alerts.
		// Prometheus applies CPU or time corroboration before notifying.
		return
	}
	ev := outcome.AlertEvidence
	srcIP, dstIP := behaviorSelectAlertIPs(feature.Direction, addr, stats, miningBehaviorKind, ctx.HostIPs)
	if outcome.Evidence.TopRemote != (IPKey{}) {
		dstIP = IPKeyToString(outcome.Evidence.TopRemote)
	}
	reason := fmt.Sprintf(
		"mining_%s_flows_%d_replied_%d_port_%d_remotes_%d",
		outcome.Evidence.Confidence.String(),
		outcome.Evidence.Flows,
		outcome.Evidence.RepliedFlows,
		outcome.Evidence.TopPort,
		outcome.Evidence.UniqueRemotes,
	)
	detail := fmt.Sprintf(
		"Alert: %s detected (Flows: %d, Unreplied: %.0f%%, Impact: %.2f%%)",
		miningBehaviorKind,
		feature.Flows,
		feature.UnrepliedRatio*100,
		hostImpact*100,
	)

	if outcome.EmitReason == "new_kind" || outcome.EmitReason == "escalated" || outcome.EmitReason == "band_cross" {
		emitKey := behaviorEmitKey{InstanceUUID: instanceUUID, IP: IPStrToKey(addr), Direction: feature.Direction}
		if ruleLogStateMarkSummary(emitKey, nowUnix) {
			previousKind := miningBehaviorKind
			if outcome.PreviousPriority == "" {
				previousKind = ""
			}
			logKV(LogLevelNotice, "behavior", "behavior", "behavior_rule_summary",
				"project_uuid", projectUUID,
				"instance_uuid", instanceUUID,
				"direction", feature.Direction,
				"previous_kind", previousKind,
				"new_kind", miningBehaviorKind,
				"previous_priority", outcome.PreviousPriority,
				"new_priority", outcome.Priority,
				"previous_severity_band", outcome.PreviousSeverityBand,
				"new_severity_band", outcome.SeverityBand,
				"rule_id", miningBehaviorRuleID,
				"rule_source", "internal",
				"emit_reason", outcome.EmitReason,
				"severity_score", outcome.SeverityScore,
				"confidence_score", outcome.ConfidenceScore,
				"top_remote_share", ev.TopRemoteShare,
				"top_port_share", ev.TopPortShare,
				"evidence_mode", ev.EvidenceMode,
			)
		}
	}

	alertKVs := buildBehaviorAlertKVs(behaviorAlertEvent{
		Feature:             feature,
		Evidence:            ev,
		Kind:                miningBehaviorKind,
		Reason:              reason,
		Detail:              detail,
		PersistenceHits:     outcome.PersistenceHits,
		PersistenceRequired: outcome.PersistenceRequired,
		EmitReason:          outcome.EmitReason,
		SeverityScore:       outcome.SeverityScore,
		ConfidenceScore:     outcome.ConfidenceScore,
		SeverityBand:        outcome.SeverityBand,
		PriorityBasis:       outcome.PriorityBasis,
		Priority:            outcome.Priority,
		HostImpact:          hostImpact,
		BehaviorSignal:      behaviorSignal,
		ConntrackAcct:       acctEnabled,
		SrcIP:               srcIP,
		DstIP:               dstIP,
		Mining:              outcome.Evidence,
	})
	cm.routeBehaviorAlert(behaviorAlertTarget{
		Domain:       domain,
		ServerName:   serverName,
		InstanceUUID: instanceUUID,
		ProjectUUID:  projectUUID,
		ProjectName:  projectName,
		UserUUID:     userUUID,
	}, alertKVs)
}
