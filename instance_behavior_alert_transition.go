package main

const (
	behaviorAlertPersistenceGapSeconds  int64 = 180
	behaviorPersistenceReferenceSeconds int64 = 15
)

type behaviorAlertTransitionInput struct {
	NowUnix     int64
	Kind        string
	Feature     BehaviorFeature
	Evidence    behaviorAlertEvidence
	Persistence behaviorPersistState
	Emission    behaviorEmitState
}

type behaviorAlertTransition struct {
	Persistence                      behaviorPersistState
	Emission                         behaviorEmitState
	PersistenceReset                 bool
	PersistenceSatisfied             bool
	ShouldEmit                       bool
	EmitReason                       string
	SuppressReason                   string
	PersistenceRequired              int
	PersistenceElapsedSeconds        int64
	PersistenceMinimumElapsedSeconds int64
	SeverityScore                    int
	ConfidenceScore                  int
	Priority                         string
	PriorityBasis                    string
	SeverityBand                     string
	PreviousKind                     string
	PreviousPriority                 string
	PreviousSeverityBand             string
}

func evaluateBehaviorAlertTransition(input behaviorAlertTransitionInput) behaviorAlertTransition {
	persistence := input.Persistence
	persistenceReset := false
	hasPriorObservation := persistence.Hits > 0
	clockMovedBackward := hasPriorObservation &&
		(input.NowUnix < persistence.LastSeenUnix || input.NowUnix < persistence.FirstSeenUnix)
	gapExceeded := hasPriorObservation &&
		(input.NowUnix-persistence.LastSeenUnix) > behaviorAlertPersistenceGapSeconds
	if clockMovedBackward || gapExceeded {
		persistence.Hits = 0
		persistence.FirstSeenUnix = input.NowUnix
		persistenceReset = true
	}
	if persistence.Hits <= 0 {
		persistence.FirstSeenUnix = input.NowUnix
	}
	// Every state-machine hit must represent a distinct complete collection.
	// All identities evaluated from one conntrack snapshot share NowUnix, so a
	// repeated evaluation of that snapshot is idempotent. Hits, rather than a
	// positive timestamp, distinguish an empty state because Unix epoch zero is
	// a valid first-observation boundary in deterministic tests.
	sameCompleteObservation := persistence.Hits > 0 && input.NowUnix == persistence.LastSeenUnix
	if !sameCompleteObservation {
		persistence.Hits++
		persistence.LastSeenUnix = input.NowUnix
	}

	severityScore := behaviorSeverityScore(input.Feature)
	confidenceScore := behaviorConfidenceScore(
		input.Feature,
		input.Kind,
		input.Evidence.TopRemoteShare,
		input.Evidence.TopPortShare,
		input.Evidence.EvidenceMode,
		persistence.Hits,
	)
	priority, priorityBasis := behaviorPriorityFromScores(severityScore, confidenceScore)
	severityBand := behaviorSeverityBand(severityScore)
	persistenceRequired := behaviorPersistenceRequired(input.Feature, input.Kind, priority)
	persistenceMinimumElapsedSeconds := behaviorPersistenceMinimumElapsedSeconds(persistenceRequired)
	persistenceElapsedSeconds := input.NowUnix - persistence.FirstSeenUnix
	if persistenceElapsedSeconds < 0 {
		persistenceElapsedSeconds = 0
	}
	persistenceSatisfied := persistence.Hits >= persistenceRequired &&
		persistenceElapsedSeconds >= persistenceMinimumElapsedSeconds

	result := behaviorAlertTransition{
		Persistence:                      persistence,
		Emission:                         input.Emission,
		PersistenceReset:                 persistenceReset,
		PersistenceSatisfied:             persistenceSatisfied,
		EmitReason:                       "new_kind",
		PersistenceRequired:              persistenceRequired,
		PersistenceElapsedSeconds:        persistenceElapsedSeconds,
		PersistenceMinimumElapsedSeconds: persistenceMinimumElapsedSeconds,
		SeverityScore:                    severityScore,
		ConfidenceScore:                  confidenceScore,
		Priority:                         priority,
		PriorityBasis:                    priorityBasis,
		SeverityBand:                     severityBand,
		PreviousKind:                     input.Emission.LastKind,
		PreviousPriority:                 input.Emission.LastPriority,
		PreviousSeverityBand:             input.Emission.LastSeverityBand,
	}

	if persistenceSatisfied {
		switch {
		case input.Emission.LastKind == "":
			result.ShouldEmit = true
			result.EmitReason = "new_kind"
		case input.Emission.LastKind != input.Kind:
			result.ShouldEmit = true
			result.EmitReason = "new_kind"
		case input.Emission.LastPriority != priority:
			result.ShouldEmit = true
			if priorityRank(priority) > priorityRank(input.Emission.LastPriority) {
				result.EmitReason = "escalated"
			} else {
				result.EmitReason = "band_cross"
			}
		case input.Emission.LastSeverityBand != "" && input.Emission.LastSeverityBand != severityBand:
			result.ShouldEmit = true
			result.EmitReason = "band_cross"
		case input.Emission.LastEpisodeStartUnix > 0 && persistence.FirstSeenUnix > input.Emission.LastEpisodeStartUnix:
			result.ShouldEmit = true
			result.EmitReason = "changed"
		case input.Evidence.TopRemoteShare >= 0.60 && input.Evidence.TopRemoteIP != "" &&
			input.Emission.LastTopRemote != "" && input.Emission.LastTopRemote != input.Evidence.TopRemoteIP:
			result.ShouldEmit = true
			result.EmitReason = "changed"
		case input.Evidence.TopPortShare >= 0.60 && input.Evidence.TopDstPort != 0 &&
			input.Emission.LastTopDstPort != 0 && input.Emission.LastTopDstPort != input.Evidence.TopDstPort:
			result.ShouldEmit = true
			result.EmitReason = "changed"
		}

		if result.ShouldEmit && behaviorAlertTransitionUsesCooldown(result.EmitReason) &&
			(input.NowUnix-input.Emission.LastEmitUnix) < behaviorAlertCooldownSeconds {
			result.ShouldEmit = false
		}
		if !result.ShouldEmit && priorityRank(priority) >= priorityRank("P2") &&
			(input.NowUnix-input.Emission.LastEmitUnix) >= behaviorAlertHeartbeatSeconds {
			result.ShouldEmit = true
			result.EmitReason = "heartbeat"
		}
	}

	switch {
	case !persistenceSatisfied:
		result.SuppressReason = "persistence_gate"
	case !result.ShouldEmit && behaviorAlertTransitionUsesCooldown(result.EmitReason) &&
		(input.NowUnix-input.Emission.LastEmitUnix) < behaviorAlertCooldownSeconds:
		result.SuppressReason = "cooldown"
	}

	if result.ShouldEmit {
		result.Emission.LastKind = input.Kind
		result.Emission.LastPriority = priority
		result.Emission.LastSeverityBand = severityBand
		result.Emission.LastTopRemote = input.Evidence.TopRemoteIP
		result.Emission.LastTopDstPort = input.Evidence.TopDstPort
		result.Emission.LastEpisodeStartUnix = persistence.FirstSeenUnix
		result.Emission.LastEmitUnix = input.NowUnix
	}

	return result
}

func behaviorPersistenceMinimumElapsedSeconds(requiredHits int) int64 {
	if requiredHits <= 1 {
		return 0
	}
	return int64(requiredHits-1) * behaviorPersistenceReferenceSeconds
}

func behaviorAlertTransitionUsesCooldown(emitReason string) bool {
	return emitReason == "changed" || emitReason == "band_cross"
}
