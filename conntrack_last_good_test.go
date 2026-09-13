package main

import "testing"

func TestConntrackLastGoodSnapshotIsPreserved(t *testing.T) {
	cm := &ConntrackManager{}
	want := &ConntrackAgg{InstanceFlowTotals: map[string]int{"vm-1": 7}}
	cm.storeLastGoodConntrack(want, 11)

	got, count, ok := cm.snapshotLastGoodConntrack()
	if !ok || got != want || count != 11 {
		t.Fatalf("unexpected last-good snapshot: agg=%p count=%d ok=%v", got, count, ok)
	}

	if got2, count2, ok2 := cm.snapshotLastGoodConntrack(); !ok2 || got2 != want || count2 != 11 {
		t.Fatalf("last-good snapshot changed without a successful replacement: agg=%p count=%d ok=%v", got2, count2, ok2)
	}
}
