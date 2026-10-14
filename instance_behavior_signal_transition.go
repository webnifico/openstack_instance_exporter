package main

const (
	behaviorSignalPersistenceGapSeconds int64 = 180
	behaviorPersistenceReferenceSeconds int64 = 15
)

type behaviorSignalTransitionInput struct {
	NowUnix     int64
	Signal      string
	Feature     BehaviorFeature
	Evidence    behaviorSignalEvidence
	Persistence behaviorPersistState
	Emission    behaviorEmitState
}

type behaviorSignalTransition struct {
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
	PreviousSignal                   string
}

func evaluateBehaviorSignalTransition(input behaviorSignalTransitionInput) behaviorSignalTransition {
	persistence := input.Persistence
	persistenceReset := false
	hasPriorObservation := persistence.Hits > 0
	clockMovedBackward := hasPriorObservation &&
		(input.NowUnix < persistence.LastSeenUnix || input.NowUnix < persistence.FirstSeenUnix)
	gapExceeded := hasPriorObservation &&
		(input.NowUnix-persistence.LastSeenUnix) > behaviorSignalPersistenceGapSeconds
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

	persistenceRequired := behaviorPersistenceRequired(input.Feature, input.Signal)
	persistenceMinimumElapsedSeconds := behaviorPersistenceMinimumElapsedSeconds(persistenceRequired)
	persistenceElapsedSeconds := input.NowUnix - persistence.FirstSeenUnix
	if persistenceElapsedSeconds < 0 {
		persistenceElapsedSeconds = 0
	}
	persistenceSatisfied := persistence.Hits >= persistenceRequired &&
		persistenceElapsedSeconds >= persistenceMinimumElapsedSeconds

	result := behaviorSignalTransition{
		Persistence:                      persistence,
		Emission:                         input.Emission,
		PersistenceReset:                 persistenceReset,
		PersistenceSatisfied:             persistenceSatisfied,
		EmitReason:                       "new_signal",
		PersistenceRequired:              persistenceRequired,
		PersistenceElapsedSeconds:        persistenceElapsedSeconds,
		PersistenceMinimumElapsedSeconds: persistenceMinimumElapsedSeconds,
		PreviousSignal:                   input.Emission.LastSignal,
	}

	if persistenceSatisfied {
		switch {
		case input.Emission.LastSignal == "":
			result.ShouldEmit = true
			result.EmitReason = "new_signal"
		case input.Emission.LastSignal != input.Signal:
			result.ShouldEmit = true
			result.EmitReason = "new_signal"
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

		if result.ShouldEmit && behaviorSignalTransitionUsesCooldown(result.EmitReason) &&
			(input.NowUnix-input.Emission.LastEmitUnix) < behaviorSignalCooldownSeconds {
			result.ShouldEmit = false
		}
		if !result.ShouldEmit &&
			(input.NowUnix-input.Emission.LastEmitUnix) >= behaviorSignalHeartbeatSeconds {
			result.ShouldEmit = true
			result.EmitReason = "heartbeat"
		}
	}

	switch {
	case !persistenceSatisfied:
		result.SuppressReason = "persistence_gate"
	case !result.ShouldEmit && behaviorSignalTransitionUsesCooldown(result.EmitReason) &&
		(input.NowUnix-input.Emission.LastEmitUnix) < behaviorSignalCooldownSeconds:
		result.SuppressReason = "cooldown"
	}

	if result.ShouldEmit {
		result.Emission.LastSignal = input.Signal
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

func behaviorSignalTransitionUsesCooldown(emitReason string) bool {
	return emitReason == "changed"
}
