package main

// A retained collection may expose only observations made for this identity.
func (cm *ConntrackManager) behaviorObservationAvailable(ident behaviorIdentityKey) bool {
	_, available := cm.behaviorIntervalSnapshot(ident)
	return available
}
