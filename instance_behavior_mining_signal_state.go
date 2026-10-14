package main

import (
	"fmt"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	miningBehaviorSignal = "outbound_stratum_mining_suspected"
	miningBehaviorRuleID = "proto_stratum_mining"
)

type miningSignalState struct {
	Hits                        int
	FirstSeenUnix               int64
	LastSeenUnix                int64
	LastRecoveryObservationUnix int64
	Confirmed                   bool
	Active                      bool

	Evidence miningDetectionEvidence

	CandidateTopRemote  IPKey
	CandidateTopDstPort uint16

	LastEmitTopRemote    string
	LastEmitTopDstPort   uint16
	LastEpisodeStartUnix int64
	LastEmitUnix         int64
}

type miningSignalOutcome struct {
	Active                           bool
	Confirmed                        bool
	ShouldEmit                       bool
	EmitReason                       string
	SuppressReason                   string
	PersistenceHits                  int
	PersistenceRequired              int
	PersistenceElapsedSeconds        int64
	PersistenceMinimumElapsedSeconds int64
	Evidence                         miningDetectionEvidence
	SignalEvidence                   behaviorSignalEvidence
}

// resetMiningObservedState ends the observed candidate or active episode while
// retaining emission history. If evidence later reconfirms, transition logic
// can report a recurrence instead of presenting it as the first-ever episode.
func resetMiningObservedState(state *miningSignalState) {
	if state == nil {
		return
	}
	state.Hits = 0
	state.FirstSeenUnix = 0
	state.LastSeenUnix = 0
	state.LastRecoveryObservationUnix = 0
	state.Confirmed = false
	state.Active = false
	state.Evidence = miningDetectionEvidence{}
	state.CandidateTopRemote = IPKey{}
	state.CandidateTopDstPort = 0
}

func miningOutcomeFromPublishedState(state *miningSignalState) miningSignalOutcome {
	if state == nil || !state.Active || !state.Confirmed || !state.Evidence.Valid {
		return miningSignalOutcome{}
	}
	return miningSignalOutcome{
		Active:    true,
		Confirmed: true,
		Evidence:  state.Evidence,
	}
}

func (cm *ConntrackManager) updateMiningSignalState(feature BehaviorFeature, ident behaviorIdentityKey, nowUnix int64) miningSignalOutcome {
	if feature.Direction != "outbound" || !feature.Mining.Valid {
		cm.behaviorSignalMu.Lock()
		if state := cm.miningSignals[ident]; state != nil {
			// This path is reached only for a complete collection. Freeze-state
			// cycles use miningSignalSnapshot instead. A real clean cycle breaks
			// persistence; intermittent unrelated matches must not accumulate.
			resetMiningObservedState(state)
		}
		cm.behaviorSignalMu.Unlock()
		return miningSignalOutcome{}
	}

	signalEvidence := cm.buildBehaviorSignalEvidence(feature, IPKey{}, false, miningBehaviorSignal)

	cm.behaviorSignalMu.Lock()
	defer cm.behaviorSignalMu.Unlock()
	if cm.miningSignals == nil {
		cm.miningSignals = make(map[behaviorIdentityKey]*miningSignalState)
	}
	state := cm.miningSignals[ident]
	if state == nil {
		state = &miningSignalState{FirstSeenUnix: nowUnix}
		cm.miningSignals[ident] = state
	}
	// This is a normal complete observation. It replaces any non-counting
	// recovery liveness reference before transition persistence is advanced.
	state.LastRecoveryObservationUnix = 0
	// Persistence must describe one stable endpoint. After an episode has been
	// confirmed, a pool switch keeps the last confirmed episode visible while
	// the replacement endpoint establishes its own consecutive observations.
	// A rotating destination therefore cannot borrow the prior endpoint's hits,
	// but it also cannot make an already confirmed episode look clean.
	episodeActive := state.Confirmed && state.Active && state.Evidence.Valid
	if state.Hits > 0 &&
		(state.CandidateTopRemote != feature.Mining.TopRemote || state.CandidateTopDstPort != feature.Mining.TopPort) {
		state.Hits = 0
		state.FirstSeenUnix = nowUnix
		state.LastSeenUnix = 0
	}
	if state.FirstSeenUnix == 0 {
		state.FirstSeenUnix = nowUnix
	}
	state.CandidateTopRemote = feature.Mining.TopRemote
	state.CandidateTopDstPort = feature.Mining.TopPort

	emissionState := behaviorEmitState{
		LastTopRemote:        state.LastEmitTopRemote,
		LastTopDstPort:       state.LastEmitTopDstPort,
		LastEpisodeStartUnix: state.LastEpisodeStartUnix,
		LastEmitUnix:         state.LastEmitUnix,
	}
	if state.LastEmitUnix != 0 {
		emissionState.LastSignal = miningBehaviorSignal
	}
	transition := evaluateBehaviorSignalTransition(behaviorSignalTransitionInput{
		NowUnix:  nowUnix,
		Signal:   miningBehaviorSignal,
		Feature:  feature,
		Evidence: signalEvidence,
		Persistence: behaviorPersistState{
			Hits:          state.Hits,
			FirstSeenUnix: state.FirstSeenUnix,
			LastSeenUnix:  state.LastSeenUnix,
		},
		Emission: emissionState,
	})

	if transition.PersistenceReset && !episodeActive {
		state.Confirmed = false
		state.Active = false
	}
	state.Hits = transition.Persistence.Hits
	state.FirstSeenUnix = transition.Persistence.FirstSeenUnix
	state.LastSeenUnix = transition.Persistence.LastSeenUnix
	confirmed := transition.PersistenceSatisfied
	if !confirmed && episodeActive {
		return miningSignalOutcome{
			Active:                           true,
			Confirmed:                        true,
			SuppressReason:                   transition.SuppressReason,
			PersistenceHits:                  transition.Persistence.Hits,
			PersistenceRequired:              transition.PersistenceRequired,
			PersistenceElapsedSeconds:        transition.PersistenceElapsedSeconds,
			PersistenceMinimumElapsedSeconds: transition.PersistenceMinimumElapsedSeconds,
			Evidence:                         state.Evidence,
		}
	}
	directSignalEligible := feature.Mining.Confidence == miningPortConfidenceHigh
	shouldEmit := transition.ShouldEmit && directSignalEligible
	suppressReason := transition.SuppressReason
	if confirmed && !directSignalEligible {
		suppressReason = "corroboration_required"
	}

	outcome := miningSignalOutcome{
		Active:                           confirmed,
		Confirmed:                        confirmed,
		ShouldEmit:                       shouldEmit,
		EmitReason:                       transition.EmitReason,
		SuppressReason:                   suppressReason,
		PersistenceHits:                  transition.Persistence.Hits,
		PersistenceRequired:              transition.PersistenceRequired,
		PersistenceElapsedSeconds:        transition.PersistenceElapsedSeconds,
		PersistenceMinimumElapsedSeconds: transition.PersistenceMinimumElapsedSeconds,
		Evidence:                         feature.Mining,
		SignalEvidence:                   signalEvidence,
	}

	state.Confirmed = state.Confirmed || confirmed
	state.Active = state.Active || confirmed
	if confirmed {
		state.Evidence = feature.Mining
	}
	if shouldEmit {
		state.LastEmitTopRemote = transition.Emission.LastTopRemote
		state.LastEmitTopDstPort = transition.Emission.LastTopDstPort
		state.LastEpisodeStartUnix = transition.Emission.LastEpisodeStartUnix
		state.LastEmitUnix = transition.Emission.LastEmitUnix
	}
	return outcome
}

// reconcileMiningRecovery applies the first complete observation after a
// failed conntrack period without advancing persistence or emitting events.
// The exact endpoint seen before the outage may preserve its state; clean or
// changed evidence invalidates state that can no longer be justified.
func (cm *ConntrackManager) reconcileMiningRecovery(feature BehaviorFeature, ident behaviorIdentityKey, nowUnix int64) miningSignalOutcome {
	cm.behaviorSignalMu.Lock()
	defer cm.behaviorSignalMu.Unlock()

	state := cm.miningSignals[ident]
	if state == nil {
		return miningSignalOutcome{}
	}
	if feature.Direction != "outbound" || !feature.Mining.Valid {
		resetMiningObservedState(state)
		return miningSignalOutcome{}
	}
	if nowUnix <= 0 {
		nowUnix = cm.conntrackNow().Unix()
	}
	if state.CandidateTopRemote == feature.Mining.TopRemote &&
		state.CandidateTopDstPort == feature.Mining.TopPort {
		state.LastRecoveryObservationUnix = nowUnix
		return miningOutcomeFromPublishedState(state)
	}

	if state.Active && state.Confirmed && state.Evidence.Valid {
		state.Hits = 0
		state.FirstSeenUnix = 0
		state.LastSeenUnix = 0
		state.LastRecoveryObservationUnix = nowUnix
		state.CandidateTopRemote = feature.Mining.TopRemote
		state.CandidateTopDstPort = feature.Mining.TopPort
		return miningOutcomeFromPublishedState(state)
	}

	resetMiningObservedState(state)
	return miningSignalOutcome{}
}

func (cm *ConntrackManager) miningSignalSnapshot(ident behaviorIdentityKey) miningSignalOutcome {
	cm.behaviorSignalMu.Lock()
	defer cm.behaviorSignalMu.Unlock()
	return miningOutcomeFromPublishedState(cm.miningSignals[ident])
}

func (cm *ConntrackManager) appendMiningMetric(
	metrics *[]prometheus.Metric,
	outcome miningSignalOutcome,
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
	))
}

func (cm *ConntrackManager) emitMiningBehaviorSignal(
	feature BehaviorFeature,
	stats *behaviorStats,
	outcome miningSignalOutcome,
	addr, domain, serverName, instanceUUID, projectUUID, projectName, userUUID string,
	ctx BehaviorContext,
	hostImpact float64,
	acctEnabled bool,
	nowUnix int64,
) {
	if !outcome.ShouldEmit {
		return
	}
	if outcome.Evidence.Confidence != miningPortConfidenceHigh {
		// These are observable candidates, not standalone structured signals.
		// Prometheus applies CPU or time corroboration before notifying.
		return
	}
	ev := outcome.SignalEvidence
	srcIP, dstIP := behaviorSelectSignalIPs(feature.Direction, addr, stats, miningBehaviorSignal, ctx.HostIPs)
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
		"Behavior signal: %s detected (Flows: %d, Unreplied: %.0f%%, Impact: %.2f%%)",
		miningBehaviorSignal,
		feature.Flows,
		feature.UnrepliedRatio*100,
		hostImpact*100,
	)

	signalKVs := buildBehaviorSignalKVs(behaviorSignalEvent{
		Feature:             feature,
		Evidence:            ev,
		Signal:              miningBehaviorSignal,
		Reason:              reason,
		Detail:              detail,
		PersistenceHits:     outcome.PersistenceHits,
		PersistenceRequired: outcome.PersistenceRequired,
		EmitReason:          outcome.EmitReason,
		HostImpact:          hostImpact,
		ConntrackAcct:       acctEnabled,
		SrcIP:               srcIP,
		DstIP:               dstIP,
		Mining:              outcome.Evidence,
	})
	cm.routeBehaviorSignal(behaviorSignalTarget{
		Domain:       domain,
		ServerName:   serverName,
		InstanceUUID: instanceUUID,
		ProjectUUID:  projectUUID,
		ProjectName:  projectName,
		UserUUID:     userUUID,
	}, signalKVs)
}
