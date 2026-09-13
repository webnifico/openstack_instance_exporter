package main

import (
	"context"
	"log/slog"
	"testing"
)

type behaviorMiningBehaviorLockProbe struct {
	message             string
	behaviorAlertLocked bool
	ruleLogLocked       bool
}

type behaviorMiningBehaviorLockProbeHandler struct {
	cm     *ConntrackManager
	probes chan<- behaviorMiningBehaviorLockProbe
}

func (handler *behaviorMiningBehaviorLockProbeHandler) Enabled(context.Context, slog.Level) bool {
	return true
}

func (handler *behaviorMiningBehaviorLockProbeHandler) Handle(_ context.Context, record slog.Record) error {
	probe := behaviorMiningBehaviorLockProbe{message: record.Message}
	if handler.cm.behaviorAlertMu.TryLock() {
		handler.cm.behaviorAlertMu.Unlock()
	} else {
		probe.behaviorAlertLocked = true
	}
	if behaviorRuleLogMu.TryLock() {
		behaviorRuleLogMu.Unlock()
	} else {
		probe.ruleLogLocked = true
	}
	handler.probes <- probe
	return nil
}

func (handler *behaviorMiningBehaviorLockProbeHandler) WithAttrs([]slog.Attr) slog.Handler {
	return handler
}

func (handler *behaviorMiningBehaviorLockProbeHandler) WithGroup(string) slog.Handler {
	return handler
}

func TestBehaviorMiningGenericBehaviorLoggingRunsOutsideStateLocks(t *testing.T) {
	resetDataIntegrityBehaviorRuleLogState(t)
	cm := dataIntegrityBehaviorManager()
	probes := make(chan behaviorMiningBehaviorLockProbe, 4)
	logger := slog.New(&behaviorMiningBehaviorLockProbeHandler{cm: cm, probes: probes})
	oldRoot := getRootLogger()
	oldDefault := slog.Default()
	rootLoggerVal.Store(logger)
	slog.SetDefault(logger)
	t.Cleanup(func() {
		rootLoggerVal.Store(oldRoot)
		slog.SetDefault(oldDefault)
	})

	dataIntegrityAnalyzeBehaviorWithContext(
		cm,
		dataIntegrityGenericScanStats(),
		"vm-behavior-mining-lock-order",
		"server-behavior-mining-lock-order",
		BehaviorContext{ObservationUnix: 100},
	)

	select {
	case probe := <-probes:
		if probe.message != "behavior_rule_suppressed" {
			t.Fatalf("logged message=%q, want behavior_rule_suppressed", probe.message)
		}
		if probe.behaviorAlertLocked || probe.ruleLogLocked {
			t.Fatalf(
				"behavior log ran under state locks: behavior_alert=%v rule_log=%v",
				probe.behaviorAlertLocked,
				probe.ruleLogLocked,
			)
		}
	default:
		t.Fatal("generic persistence suppression did not emit the lock-order probe log")
	}
}
