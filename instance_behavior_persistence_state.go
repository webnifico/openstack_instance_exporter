package main

func behaviorSignalKeyMatchesIdentity(key behaviorSignalKey, ident behaviorIdentityKey) bool {
	return key.InstanceUUID == ident.InstanceUUID && key.IP == ident.IP && key.Direction == ident.Direction
}

// resetGenericBehaviorCandidateLocked removes only generic persistence state
// for one exact instance/IP/direction identity. Mining owns a separate map and
// lifecycle, so a generic clean observation cannot mutate mining evidence.
func (cm *ConntrackManager) resetGenericBehaviorCandidateLocked(ident behaviorIdentityKey) int {
	removed := 0
	for key := range cm.behaviorPersist {
		if behaviorSignalKeyMatchesIdentity(key, ident) {
			delete(cm.behaviorPersist, key)
			removed++
		}
	}
	return removed
}

func (cm *ConntrackManager) resetGenericBehaviorCandidate(ident behaviorIdentityKey) int {
	cm.behaviorSignalMu.Lock()
	removed := cm.resetGenericBehaviorCandidateLocked(ident)
	cm.behaviorSignalMu.Unlock()
	return removed
}

// genericBehaviorCandidateLocked selects exactly one candidate identity. A
// different signal, rule source, or rule ID breaks consecutiveness and starts a
// new one-hit sequence on this complete observation.
func (cm *ConntrackManager) genericBehaviorCandidateLocked(
	signalKey behaviorSignalKey,
	ruleID, ruleSource string,
	nowUnix int64,
) *behaviorPersistState {
	if cm.behaviorPersist == nil {
		cm.behaviorPersist = make(map[behaviorSignalKey]*behaviorPersistState)
	}
	ident := behaviorIdentityKey{
		InstanceUUID: signalKey.InstanceUUID,
		IP:           signalKey.IP,
		Direction:    signalKey.Direction,
	}
	for key := range cm.behaviorPersist {
		if behaviorSignalKeyMatchesIdentity(key, ident) && key != signalKey {
			delete(cm.behaviorPersist, key)
		}
	}

	state := cm.behaviorPersist[signalKey]
	if state == nil || state.CandidateRuleID != ruleID || state.CandidateRuleSource != ruleSource {
		state = &behaviorPersistState{
			FirstSeenUnix:       nowUnix,
			CandidateRuleID:     ruleID,
			CandidateRuleSource: ruleSource,
		}
		cm.behaviorPersist[signalKey] = state
	}
	return state
}

// reconcileGenericBehaviorRecovery consumes the first complete post-failure
// evidence without advancing or seeding persistence. An exact positive match
// may preserve a pending candidate; clean or changed evidence removes it.
func (cm *ConntrackManager) reconcileGenericBehaviorRecovery(
	ident behaviorIdentityKey,
	classification behaviorClassification,
) {
	cm.behaviorSignalMu.Lock()
	defer cm.behaviorSignalMu.Unlock()

	if !classification.Hit || classification.Signal == miningBehaviorSignal {
		cm.resetGenericBehaviorCandidateLocked(ident)
		return
	}
	keep := behaviorSignalKey{
		InstanceUUID: ident.InstanceUUID,
		IP:           ident.IP,
		Direction:    ident.Direction,
		Signal:       classification.Signal,
	}
	for key, state := range cm.behaviorPersist {
		if !behaviorSignalKeyMatchesIdentity(key, ident) {
			continue
		}
		if key != keep || state == nil || state.CandidateRuleID != classification.RuleID ||
			state.CandidateRuleSource != classification.RuleSource {
			delete(cm.behaviorPersist, key)
		}
	}
}
