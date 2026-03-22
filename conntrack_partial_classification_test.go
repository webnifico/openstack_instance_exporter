package main

import (
	"errors"
	"testing"
)

func TestNewConntrackAggregateErrorReturnsNilWhenFamiliesSucceed(t *testing.T) {
	if err := newConntrackAggregateError(true, true, nil, nil); err != nil {
		t.Fatalf("err=%v want nil", err)
	}
}

func TestNewConntrackAggregateErrorMarksDualStackPartialFailure(t *testing.T) {
	err := newConntrackAggregateError(true, true, errors.New("v4 failed"), nil)
	if err == nil {
		t.Fatal("err=nil want partial error")
	}
	if !err.Partial {
		t.Fatalf("Partial=%v want true", err.Partial)
	}
}

func TestNewConntrackAggregateErrorMarksDualStackFullFailure(t *testing.T) {
	err := newConntrackAggregateError(true, true, errors.New("v4 failed"), errors.New("v6 failed"))
	if err == nil {
		t.Fatal("err=nil want full error")
	}
	if err.Partial {
		t.Fatalf("Partial=%v want false", err.Partial)
	}
}

func TestNewConntrackAggregateErrorMarksSingleStackFailureAsFull(t *testing.T) {
	err := newConntrackAggregateError(true, false, errors.New("v4 failed"), nil)
	if err == nil {
		t.Fatal("err=nil want full error")
	}
	if err.Partial {
		t.Fatalf("Partial=%v want false", err.Partial)
	}
}
