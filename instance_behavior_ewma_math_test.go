package main

import (
	"math"
	"testing"
)

func TestEwmaAlpha(t *testing.T) {
	a := ewmaAlpha(1, 10)
	if a <= 0 || a >= 1 {
		t.Fatalf("alpha out of range: %v", a)
	}
	exp := 1 - math.Exp(-0.1)
	if math.Abs(a-exp) > 1e-6 {
		t.Fatalf("alpha mismatch: got %v want %v", a, exp)
	}
}

func TestUpdateAxisEWMAInitAndMove(t *testing.T) {
	var s axisEWMA
	updateAxisEWMA(&s, 10, 0.2, 0.05)
	if !s.Initialized {
		t.Fatalf("expected initialized")
	}
	if s.Fast != 10 || s.Slow != 10 {
		t.Fatalf("expected fast/slow set to 10, got %v/%v", s.Fast, s.Slow)
	}
	updateAxisEWMA(&s, 20, 0.5, 0.1)
	if s.Fast <= 10 {
		t.Fatalf("expected fast to increase, got %v", s.Fast)
	}
	if s.Slow <= 10 {
		t.Fatalf("expected slow to increase, got %v", s.Slow)
	}
}
