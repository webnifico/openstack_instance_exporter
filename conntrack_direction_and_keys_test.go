package main

import "testing"

func TestParseContactDirection(t *testing.T) {
	cases := []struct {
		in   string
		want ContactDirection
	}{
		{"any", ContactAny},
		{"ANY", ContactAny},
		{"  any  ", ContactAny},

		{"in", ContactIn},
		{"inbound", ContactIn},
		{"dst", ContactIn},
		{"  INBOUND  ", ContactIn},

		{"out", ContactOut},
		{"outbound", ContactOut},
		{"src", ContactOut},
		{"  OUTBOUND  ", ContactOut},

		{"", ContactOut},
		{"junk", ContactOut},
		{"inboundz", ContactOut},
	}

	for _, c := range cases {
		got := parseContactDirection(c.in)
		if got != c.want {
			t.Fatalf("parseContactDirection(%q)=%v want %v", c.in, got, c.want)
		}
	}
}

func TestContactDirectionString(t *testing.T) {
	if (ContactAny).String() != "any" {
		t.Fatalf("ContactAny.String()=%q", (ContactAny).String())
	}
	if (ContactIn).String() != "in" {
		t.Fatalf("ContactIn.String()=%q", (ContactIn).String())
	}
	if (ContactOut).String() != "out" {
		t.Fatalf("ContactOut.String()=%q", (ContactOut).String())
	}
}

func TestFlowDirection(t *testing.T) {
	ipSet := map[IPKey]struct{}{
		IPStrToKey("10.0.0.10"): {},
		IPStrToKey("10.0.0.11"): {},
	}

	cases := []struct {
		name string
		ct   ConntrackEntry
		want string
	}{
		{"out", ConntrackEntry{Src: "10.0.0.10", Dst: "1.1.1.1"}, "out"},
		{"in", ConntrackEntry{Src: "1.1.1.1", Dst: "10.0.0.10"}, "in"},
		{"intra", ConntrackEntry{Src: "10.0.0.10", Dst: "10.0.0.11"}, "any"},
		{"unknown", ConntrackEntry{Src: "1.1.1.1", Dst: "2.2.2.2"}, "any"},
	}

	for _, c := range cases {
		got := flowDirection(ipSet, c.ct)
		if got != c.want {
			t.Fatalf("%s: flowDirection()=%q want %q", c.name, got, c.want)
		}
	}
}
