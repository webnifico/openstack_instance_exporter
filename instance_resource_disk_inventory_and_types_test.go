package main

import "testing"

func TestParseDiskType(t *testing.T) {
	dt, vol := parseDiskType("rbd/volume-123")
	if dt != "rbd" || vol != "volume-123" {
		t.Fatalf("unexpected: %q %q", dt, vol)
	}
	dt, vol = parseDiskType("noslash")
	if dt != "unknown" || vol != "unknown" {
		t.Fatalf("unexpected: %q %q", dt, vol)
	}
}
