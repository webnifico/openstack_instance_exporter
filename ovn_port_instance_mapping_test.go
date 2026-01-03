package main

import "testing"

func TestParseUint16Bounds(t *testing.T) {
	cases := []struct {
		in   string
		want uint16
	}{
		{"0", 0},
		{"1", 1},
		{"65535", 65535},
		{"0001", 1},
		{"065535", 65535},
		{"0000", 0},
	}

	for _, c := range cases {
		got, ok := parseUint16(c.in)
		if !ok {
			t.Fatalf("parseUint16(%q) ok=false want true", c.in)
		}
		if got != c.want {
			t.Fatalf("parseUint16(%q)=%d want %d", c.in, got, c.want)
		}
	}
}

func TestParseUint16RejectsJunk(t *testing.T) {
	cases := []string{
		"",
		" ",
		"abc",
		"12x",
		"x12",
		"-1",
		"65536",
		"99999",
	}

	for _, in := range cases {
		got, ok := parseUint16(in)
		if ok {
			t.Fatalf("parseUint16(%q) ok=true want false", in)
		}
		if got != 0 {
			t.Fatalf("parseUint16(%q)=%d want 0", in, got)
		}
	}
}
