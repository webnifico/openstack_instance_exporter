package main

import (
	"math"
)

func ewmaAlpha(dtSeconds, tauSeconds float64) float64 {
	if dtSeconds <= 0 || tauSeconds <= 0 {
		return 1
	}
	return 1 - math.Exp(-dtSeconds/tauSeconds)
}

func updateAxisEWMA(a *axisEWMA, x float64, alphaFast, alphaSlow float64) {
	if !a.Initialized {
		a.Fast = x
		a.Slow = x
		a.Initialized = true
		return
	}
	a.Fast += alphaFast * (x - a.Fast)
	a.Slow += alphaSlow * (x - a.Slow)
}
func axisSpread(a *axisEWMA, minSpread float64) float64 {
	if !a.Initialized {
		return minSpread
	}
	s := math.Abs(a.Fast - a.Slow)
	if s < minSpread {
		return minSpread
	}
	return s
}
func featureAnomaly(x float64, a *axisEWMA, minSpread float64) float64 {
	if !a.Initialized {
		return 0
	}
	spread := axisSpread(a, minSpread)
	z := math.Abs(x-a.Slow) / spread
	return clamp01(z / 6.0)
}

// rebaselineBehaviorObservation accepts the first complete observation after a
// source outage as a new statistical baseline. It deliberately leaves signal,
// mining, and persistence state untouched: those state machines resume on the
// next complete interval, so changes accumulated while the source was absent
// cannot be compressed into one recovery anomaly.
func (cm *ConntrackManager) rebaselineBehaviorObservation(ident behaviorIdentityKey, feature BehaviorFeature, now int64) {
	idx := shardIndexBehavior(ident)
	cm.behaviorObservationMu[idx].Lock()
	state := &behaviorObservationState{
		LastSeenUnix: now,
		LastInterval: behaviorIntervalSnapshot{
			NewRemotes:          0,
			NewDstPorts:         0,
			NewRemotesSaturated: false,
			Initialized:         true,
		},
	}
	updateAxisEWMA(&state.Flows, float64(feature.Flows), 1, 1)
	updateAxisEWMA(&state.UniqueRemotes, float64(feature.UniqueRemotes), 1, 1)
	if cm.behaviorObservations[idx] == nil {
		cm.behaviorObservations[idx] = make(map[behaviorIdentityKey]*behaviorObservationState)
	}
	cm.behaviorObservations[idx][ident] = state
	cm.behaviorObservationMu[idx].Unlock()
}

func (cm *ConntrackManager) updateBehaviorEWMA(ident behaviorIdentityKey, feature BehaviorFeature, now int64) behaviorAnomalies {
	idx := shardIndexBehavior(ident)
	cm.behaviorObservationMu[idx].Lock()
	defer cm.behaviorObservationMu[idx].Unlock()
	if cm.behaviorObservations[idx] == nil {
		cm.behaviorObservations[idx] = make(map[behaviorIdentityKey]*behaviorObservationState)
	}

	ew, ok := cm.behaviorObservations[idx][ident]
	if !ok || ew == nil {
		ew = &behaviorObservationState{}
		cm.behaviorObservations[idx][ident] = ew
	}
	prevSeen := ew.LastSeenUnix
	initialized := ew.Flows.Initialized && ew.UniqueRemotes.Initialized
	if initialized && now == prevSeen {
		// A duplicate snapshot is not another learning sample. Production also
		// freezes its persistence and interval state before reaching this helper.
		return behaviorAnomalies{}
	}
	ew.LastSeenUnix = now

	dtSeconds := float64(0)
	if initialized || prevSeen > 0 {
		dtSeconds = float64(now - prevSeen)
		if dtSeconds < 1 {
			dtSeconds = 1
		}
	}
	tauFast := cm.behaviorEWMATauFast.Seconds()
	tauSlow := cm.behaviorEWMATauSlow.Seconds()
	if tauFast <= 0 {
		tauFast = behaviorEWMATauFastDefaultSeconds
	}
	if tauSlow <= 0 {
		tauSlow = behaviorEWMATauSlowDefaultSeconds
	}
	if (initialized || prevSeen > 0) && (now < prevSeen || dtSeconds > float64(behaviorIdentityTTLSeconds)) {
		*ew = behaviorObservationState{LastSeenUnix: now}
		updateAxisEWMA(&ew.Flows, float64(feature.Flows), 1, 1)
		updateAxisEWMA(&ew.UniqueRemotes, float64(feature.UniqueRemotes), 1, 1)
		return behaviorAnomalies{}
	}
	alphaFast := ewmaAlpha(dtSeconds, tauFast)
	alphaSlow := ewmaAlpha(dtSeconds, tauSlow)

	if feature.Flows == 0 {
		updateAxisEWMA(&ew.Flows, 0, alphaFast, alphaSlow)
		updateAxisEWMA(&ew.UniqueRemotes, 0, alphaFast, alphaSlow)

		return behaviorAnomalies{}
	}

	sens := cm.behaviorSensitivity
	if sens <= 0 {
		sens = 1.0
	}
	flowsMin := 10.0 / sens
	remotesMin := 5.0 / sens

	if flowsMin < 0.001 {
		flowsMin = 0.001
	}
	if remotesMin < 0.001 {
		remotesMin = 0.001
	}

	flowsAnom := featureAnomaly(float64(feature.Flows), &ew.Flows, flowsMin)
	remotesAnom := featureAnomaly(float64(feature.UniqueRemotes), &ew.UniqueRemotes, remotesMin)

	// Compare with the preceding complete observations before learning this
	// sample. Learning first can erase a real change before the persistence
	// gate gets its third distinct observation at the default 15s cadence.
	updateAxisEWMA(&ew.Flows, float64(feature.Flows), alphaFast, alphaSlow)
	updateAxisEWMA(&ew.UniqueRemotes, float64(feature.UniqueRemotes), alphaFast, alphaSlow)
	return behaviorAnomalies{Flows: flowsAnom, Remotes: remotesAnom}
}
