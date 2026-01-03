package main

import "testing"

func TestShardIndexRange(t *testing.T) {
	idx := shardIndex("hello")
	if idx < 0 || idx >= shardCount {
		t.Fatalf("out of range: %d", idx)
	}
}

func TestShardIndexBehaviorRange(t *testing.T) {
	k := behaviorIdentityKey{InstanceUUID: "uuid", Direction: "outbound"}
	idx := shardIndexBehavior(k)
	if idx < 0 || idx >= shardCount {
		t.Fatalf("out of range: %d", idx)
	}
}
