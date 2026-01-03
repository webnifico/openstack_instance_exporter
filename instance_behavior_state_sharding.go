package main

func shardIndexBehavior(k behaviorIdentityKey) int {
	var h uint32 = 2166136261
	for i := 0; i < len(k.InstanceUUID); i++ {
		h ^= uint32(k.InstanceUUID[i])
		h *= 16777619
	}
	for i := 0; i < len(k.IP); i++ {
		h ^= uint32(k.IP[i])
		h *= 16777619
	}
	for i := 0; i < len(k.Direction); i++ {
		h ^= uint32(k.Direction[i])
		h *= 16777619
	}
	return int(h % uint32(shardCount))
}
