package main

func behaviorAlertKeyMatchesIdentity(key behaviorAlertKey, ident behaviorIdentityKey) bool {
	return key.InstanceUUID == ident.InstanceUUID && key.IP == ident.IP && key.Direction == ident.Direction
}

// resetGenericBehaviorCandidateLocked removes only generic persistence state
// for one exact instance/IP/direction identity. Mining owns a separate map and
// lifecycle, so a generic clean observation cannot mutate mining evidence.
func (cm *ConntrackManager) resetGenericBehaviorCandidateLocked(ident behaviorIdentityKey) int {
	removed := 0
	for key := range cm.behaviorPersist {
		if behaviorAlertKeyMatchesIdentity(key, ident) {
			delete(cm.behaviorPersist, key)
			removed++
		}
	}
	return removed
}

func (cm *ConntrackManager) resetGenericBehaviorCandidate(ident behaviorIdentityKey) int {
	cm.behaviorAlertMu.Lock()
	removed := cm.resetGenericBehaviorCandidateLocked(ident)
	cm.behaviorAlertMu.Unlock()
	return removed
}

// genericBehaviorCandidateLocked selects exactly one candidate identity. A
// different kind, rule source, or rule ID breaks consecutiveness and starts a
// new one-hit sequence on this complete observation.
func (cm *ConntrackManager) genericBehaviorCandidateLocked(
	alertKey behaviorAlertKey,
	ruleID, ruleSource string,
	nowUnix int64,
) *behaviorPersistState {
	if cm.behaviorPersist == nil {
		cm.behaviorPersist = make(map[behaviorAlertKey]*behaviorPersistState)
	}
	ident := behaviorIdentityKey{
		InstanceUUID: alertKey.InstanceUUID,
		IP:           alertKey.IP,
		Direction:    alertKey.Direction,
	}
	for key := range cm.behaviorPersist {
		if behaviorAlertKeyMatchesIdentity(key, ident) && key != alertKey {
			delete(cm.behaviorPersist, key)
		}
	}

	state := cm.behaviorPersist[alertKey]
	if state == nil || state.CandidateRuleID != ruleID || state.CandidateRuleSource != ruleSource {
		state = &behaviorPersistState{
			FirstSeenUnix:       nowUnix,
			CandidateRuleID:     ruleID,
			CandidateRuleSource: ruleSource,
		}
		cm.behaviorPersist[alertKey] = state
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
	cm.behaviorAlertMu.Lock()
	defer cm.behaviorAlertMu.Unlock()

	if !classification.Hit || classification.Kind == miningBehaviorKind {
		cm.resetGenericBehaviorCandidateLocked(ident)
		return
	}
	keep := behaviorAlertKey{
		InstanceUUID: ident.InstanceUUID,
		IP:           ident.IP,
		Direction:    ident.Direction,
		Kind:         classification.Kind,
	}
	for key, state := range cm.behaviorPersist {
		if !behaviorAlertKeyMatchesIdentity(key, ident) {
			continue
		}
		if key != keep || state == nil || state.CandidateRuleID != classification.RuleID ||
			state.CandidateRuleSource != classification.RuleSource {
			delete(cm.behaviorPersist, key)
		}
	}
}
