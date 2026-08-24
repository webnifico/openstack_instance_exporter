package main

import "testing"

func TestBehaviorAccountingAveragesUseOnlyCoveredFlows(t *testing.T) {
	s := newBehaviorStats(false)
	remote := IPStrToKey("203.0.113.10")
	s.updateDetailedWithCoverage(remote, 443, 6, IPS_SEEN_REPLY, 1, 1000, 10, true, true)
	s.updateDetailedWithCoverage(remote, 443, 6, IPS_SEEN_REPLY, 1, 0, 0, false, false)

	bytesPerFlow, packetsPerFlow, bytesOK, packetsOK := s.accountingAverages()
	if !bytesOK || !packetsOK {
		t.Fatal("covered counters were reported unavailable")
	}
	if bytesPerFlow != 1000 || packetsPerFlow != 10 {
		t.Fatalf("averages included uncovered flows: bytes=%v packets=%v", bytesPerFlow, packetsPerFlow)
	}
}

func TestBehaviorReplyStateDoesNotDependOnCounters(t *testing.T) {
	s := newBehaviorStats(false)
	remote := IPStrToKey("203.0.113.11")
	s.updateDetailedWithCoverage(remote, 443, 6, IPS_SEEN_REPLY|IPS_ASSURED, 1, 0, 0, false, false)
	if s.unreplied != 0 {
		t.Fatalf("replied flow marked unreplied without accounting: %d", s.unreplied)
	}
}
