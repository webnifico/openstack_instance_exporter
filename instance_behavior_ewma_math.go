package main

import (
	"math"
	"time"
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
func (cm *ConntrackManager) updateBehaviorEWMA(ident behaviorIdentityKey, feature BehaviorFeature) (float64, behaviorAnomalies) {
	idx := shardIndexBehavior(ident)
	cm.behaviorEWMAMu[idx].Lock()
	now := time.Now().Unix()

	ew, ok := cm.behaviorEWMA[idx][ident]
	if !ok {
		ew = &behaviorEWMAState{}
		cm.behaviorEWMA[idx][ident] = ew
	}
	prevSeen := ew.LastSeenUnix
	ew.LastSeenUnix = now

	dtSeconds := float64(0)
	if prevSeen > 0 {
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
	alphaFast := ewmaAlpha(dtSeconds, tauFast)
	alphaSlow := ewmaAlpha(dtSeconds, tauSlow)

	if feature.Flows == 0 {
		updateAxisEWMA(&ew.Flows, 0, alphaFast, alphaSlow)
		updateAxisEWMA(&ew.UniqueRemotes, 0, alphaFast, alphaSlow)
		updateAxisEWMA(&ew.UniquePorts, 0, alphaFast, alphaSlow)
		updateAxisEWMA(&ew.Unreplied, 0, alphaFast, alphaSlow)
		if feature.ConntrackAcct {
			updateAxisEWMA(&ew.BytesPerFlow, 0, alphaFast, alphaSlow)
			updateAxisEWMA(&ew.PktsPerFlow, 0, alphaFast, alphaSlow)
		}
		cm.behaviorEWMAMu[idx].Unlock()
		return 0, behaviorAnomalies{}
	}

	updateAxisEWMA(&ew.Flows, float64(feature.Flows), alphaFast, alphaSlow)
	updateAxisEWMA(&ew.UniqueRemotes, float64(feature.UniqueRemotes), alphaFast, alphaSlow)
	updateAxisEWMA(&ew.UniquePorts, float64(feature.UniqueDstPorts), alphaFast, alphaSlow)
	updateAxisEWMA(&ew.Unreplied, feature.UnrepliedRatio, alphaFast, alphaSlow)

	if feature.ConntrackAcct {
		if feature.BytesPerFlow > 0 {
			updateAxisEWMA(&ew.BytesPerFlow, feature.BytesPerFlow, alphaFast, alphaSlow)
		}
		if feature.PacketsPerFlow > 0 {
			updateAxisEWMA(&ew.PktsPerFlow, feature.PacketsPerFlow, alphaFast, alphaSlow)
		}
	}

	sens := cm.behaviorSensitivity
	if sens <= 0 {
		sens = 1.0
	}
	flowsMin := 10.0 / sens
	remotesMin := 5.0 / sens
	portsMin := 5.0 / sens
	unrepMin := 0.05 / sens
	bytesMin := 256.0 / sens
	pktsMin := 2.0 / sens
	if flowsMin < 0.001 {
		flowsMin = 0.001
	}
	if remotesMin < 0.001 {
		remotesMin = 0.001
	}
	if portsMin < 0.001 {
		portsMin = 0.001
	}
	if unrepMin < 0.0001 {
		unrepMin = 0.0001
	}
	if bytesMin < 0.001 {
		bytesMin = 0.001
	}
	if pktsMin < 0.001 {
		pktsMin = 0.001
	}

	flowsAnom := featureAnomaly(float64(feature.Flows), &ew.Flows, flowsMin)
	remotesAnom := featureAnomaly(float64(feature.UniqueRemotes), &ew.UniqueRemotes, remotesMin)
	portsAnom := featureAnomaly(float64(feature.UniqueDstPorts), &ew.UniquePorts, portsMin)
	unrepAnom := featureAnomaly(feature.UnrepliedRatio, &ew.Unreplied, unrepMin)

	bytesAnom := 0.0
	pktsAnom := 0.0
	if feature.ConntrackAcct {
		if feature.BytesPerFlow > 0 {
			bytesAnom = featureAnomaly(feature.BytesPerFlow, &ew.BytesPerFlow, bytesMin)
		}
		if feature.PacketsPerFlow > 0 {
			pktsAnom = featureAnomaly(feature.PacketsPerFlow, &ew.PktsPerFlow, pktsMin)
		}
	}

	behaviorSignal := clamp01(
		0.25*flowsAnom +
			0.20*remotesAnom +
			0.20*portsAnom +
			0.20*unrepAnom +
			0.10*bytesAnom +
			0.05*pktsAnom,
	)

	if sens != 1.0 {
		behaviorSignal = clamp01(math.Pow(behaviorSignal, 1.0/sens))
	}

	cm.behaviorEWMAMu[idx].Unlock()
	return behaviorSignal, behaviorAnomalies{Flows: flowsAnom, Remotes: remotesAnom, Ports: portsAnom, Unreplied: unrepAnom, BytesPerFlow: bytesAnom, PacketsPerFlow: pktsAnom, Signal: behaviorSignal}
}
