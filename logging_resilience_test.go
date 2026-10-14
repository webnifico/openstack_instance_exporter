package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
)

type partialThenRecoverLogWriter struct {
	buf     bytes.Buffer
	partial bool
}

func (writer *partialThenRecoverLogWriter) Write(payload []byte) (int, error) {
	if !writer.partial && len(payload) > 1 {
		writer.partial = true
		cut := len(payload) / 2
		_, _ = writer.buf.Write(payload[:cut])
		return cut, io.ErrShortWrite
	}
	return writer.buf.Write(payload)
}

type toggleLogWriter struct {
	buf  bytes.Buffer
	fail bool
}

func (writer *toggleLogWriter) Write(payload []byte) (int, error) {
	if writer.fail {
		return 0, errors.New("simulated log write failure")
	}
	return writer.buf.Write(payload)
}

func TestLoggingResilientFileWriterDoesNotDependOnStdout(t *testing.T) {
	primary := &toggleLogWriter{}
	mirror := &toggleLogWriter{fail: true}
	fallback := &toggleLogWriter{}
	writer := &resilientFileLogWriter{
		primary:  primary,
		mirror:   mirror,
		fallback: fallback,
		path:     "/var/log/oie.log",
	}
	payload := []byte("{\"msg\":\"primary_survives_broken_stdout\"}\n")
	written, err := writer.Write(payload)
	if err != nil || written != len(payload) {
		t.Fatalf("write=(%d,%v), want (%d,nil)", written, err, len(payload))
	}
	if !bytes.Equal(primary.buf.Bytes(), payload) {
		t.Fatalf("primary file lost event: %q", primary.buf.String())
	}
	if fallback.buf.Len() != 0 {
		t.Fatalf("healthy primary unexpectedly used stderr fallback: %q", fallback.buf.String())
	}
}

func TestLoggingResilientFileWriterFallsBackAndReportsRecovery(t *testing.T) {
	primary := &toggleLogWriter{fail: true}
	mirror := &toggleLogWriter{}
	fallback := &toggleLogWriter{}
	writer := &resilientFileLogWriter{
		primary:  primary,
		mirror:   mirror,
		fallback: fallback,
		path:     "/var/log/oie.log",
	}
	failedPayload := []byte("{\"msg\":\"must_survive_file_failure\"}\n")
	if _, err := writer.Write(failedPayload); err == nil {
		t.Fatal("primary file failure was hidden from the handler")
	}
	fallbackText := fallback.buf.String()
	if !strings.Contains(fallbackText, "must_survive_file_failure") ||
		!strings.Contains(fallbackText, "logfile_write_failed") ||
		!strings.Contains(fallbackText, "simulated log write failure") {
		t.Fatalf("stderr fallback is incomplete: %s", fallbackText)
	}
	lines := strings.Split(strings.TrimSpace(fallbackText), "\n")
	if len(lines) != 2 {
		t.Fatalf("failure fallback lines=%d, want event plus one diagnostic: %q", len(lines), fallbackText)
	}
	var diagnostic map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &diagnostic); err != nil {
		t.Fatalf("failure diagnostic is not JSON: %v: %s", err, lines[1])
	}
	if diagnostic["msg"] != "logfile_write_failed" || diagnostic["level"] != "ERROR" ||
		diagnostic["category"] != "app" || diagnostic["component"] != "logging" {
		t.Fatalf("failure diagnostic schema=%v", diagnostic)
	}

	// Repeated failures preserve every event but report the destination failure
	// once until the primary recovers.
	fallback.buf.Reset()
	if _, err := writer.Write([]byte("{\"msg\":\"second_failed_event\"}\n")); err == nil {
		t.Fatal("second primary failure was hidden")
	}
	if strings.Count(fallback.buf.String(), "logfile_write_failed") != 0 ||
		!strings.Contains(fallback.buf.String(), "second_failed_event") {
		t.Fatalf("repeat failure diagnostics are noisy or evidence was lost: %s", fallback.buf.String())
	}

	primary.fail = false
	fallback.buf.Reset()
	recoveredPayload := []byte("{\"msg\":\"file_recovered\"}\n")
	if written, err := writer.Write(recoveredPayload); err != nil || written != len(recoveredPayload) {
		t.Fatalf("recovered write=(%d,%v)", written, err)
	}
	var recovery map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(fallback.buf.Bytes()), &recovery); err != nil {
		t.Fatalf("recovery diagnostic is not JSON: %v: %s", err, fallback.buf.String())
	}
	if recovery["msg"] != "logfile_write_recovered" || recovery["level"] != "INFO" ||
		recovery["category"] != "app" || recovery["component"] != "logging" {
		t.Fatalf("recovery diagnostic schema=%v", recovery)
	}

	// Keep the helper honest if its implementation changes to a short writer.
	var _ io.Writer = writer
}

func TestLoggingResilientFileWriterResynchronizesAfterPartialLine(t *testing.T) {
	primary := &partialThenRecoverLogWriter{}
	fallback := &toggleLogWriter{}
	writer := &resilientFileLogWriter{
		primary:  primary,
		fallback: fallback,
		path:     "/var/log/oie.log",
	}
	first := []byte("{\"msg\":\"partial\"}\n")
	if _, err := writer.Write(first); err == nil {
		t.Fatal("partial primary write did not fail")
	}
	second := []byte("{\"msg\":\"after_recovery\"}\n")
	if _, err := writer.Write(second); err != nil {
		t.Fatalf("recovery write failed: %v", err)
	}
	text := primary.buf.String()
	if !strings.Contains(text, "\n{\"msg\":\"after_recovery\"}\n") {
		t.Fatalf("file stream was not resynchronized after partial JSON: %q", text)
	}
}

type yieldingLogWriter struct {
	buf bytes.Buffer
}

func (writer *yieldingLogWriter) Write(payload []byte) (int, error) {
	for _, value := range payload {
		if err := writer.buf.WriteByte(value); err != nil {
			return 0, err
		}
		runtime.Gosched()
	}
	return len(payload), nil
}

func TestLoggingResilientFileWriterSerializesConcurrentJSONLines(t *testing.T) {
	primary := &yieldingLogWriter{}
	writer := &resilientFileLogWriter{primary: primary, path: "/var/log/oie.log"}

	const writers = 64
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index := 0; index < writers; index++ {
		index := index
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			payload := []byte(fmt.Sprintf("{\"msg\":\"concurrent\",\"index\":%d}\n", index))
			if written, err := writer.Write(payload); err != nil || written != len(payload) {
				t.Errorf("write %d=(%d,%v), want (%d,nil)", index, written, err, len(payload))
			}
		}()
	}
	close(start)
	wait.Wait()

	lines := strings.Split(strings.TrimSpace(primary.buf.String()), "\n")
	if len(lines) != writers {
		t.Fatalf("serialized line count=%d, want %d: %q", len(lines), writers, primary.buf.String())
	}
	seen := make(map[int]struct{}, writers)
	for _, line := range lines {
		var event struct {
			Message string `json:"msg"`
			Index   int    `json:"index"`
		}
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("concurrent output contains a torn JSON line: %v: %q", err, line)
		}
		if event.Message != "concurrent" {
			t.Fatalf("unexpected concurrent event: %+v", event)
		}
		seen[event.Index] = struct{}{}
	}
	if len(seen) != writers {
		t.Fatalf("unique concurrent events=%d, want %d", len(seen), writers)
	}
}

func TestLoggingFailureEpisodeSurvivesRuntimeLevelChange(t *testing.T) {
	preserveLoggingTestState(t)

	file, err := os.CreateTemp(t.TempDir(), "oie-log-handle-*")
	if err != nil {
		t.Fatal(err)
	}
	primary := &toggleLogWriter{fail: true}
	fallback := &toggleLogWriter{}
	writer := &resilientFileLogWriter{
		primary:  primary,
		fallback: fallback,
		path:     file.Name(),
	}

	logMu.Lock()
	logFileHandle = file
	logFileWriter = writer
	logger := slog.New(slog.NewJSONHandler(writer, &slog.HandlerOptions{Level: slog.LevelInfo}))
	rootLoggerVal.Store(logger)
	currentLogLevelVal.Store("info")
	slog.SetDefault(logger)
	logMu.Unlock()

	logMain.Info("first_failed_event")
	if got := strings.Count(fallback.buf.String(), "logfile_write_failed"); got != 1 {
		t.Fatalf("initial failure diagnostics=%d, want 1: %s", got, fallback.buf.String())
	}

	if applied, err := SetLogLevel("debug"); err != nil || applied != "debug" {
		t.Fatalf("SetLogLevel=(%q,%v), want debug,nil", applied, err)
	}
	if logFileWriter != writer {
		t.Fatal("runtime log-level change replaced resilient writer state")
	}
	logMain.Debug("second_failed_event")
	if got := strings.Count(fallback.buf.String(), "logfile_write_failed"); got != 1 {
		t.Fatalf("level swap restarted the same failure episode: diagnostics=%d: %s", got, fallback.buf.String())
	}
	if !strings.Contains(fallback.buf.String(), "second_failed_event") {
		t.Fatalf("post-level-change failed event was not preserved on fallback: %s", fallback.buf.String())
	}

	primary.fail = false
	logMain.Debug("recovered_after_level_change")
	if got := strings.Count(fallback.buf.String(), "logfile_write_recovered"); got != 1 {
		t.Fatalf("recovery diagnostics=%d, want 1: %s", got, fallback.buf.String())
	}
	if !strings.Contains(primary.buf.String(), "recovered_after_level_change") {
		t.Fatalf("recovered event did not return to primary destination: %s", primary.buf.String())
	}
}

func TestLoggingCheckedRejectsInvalidLevelWithoutMutation(t *testing.T) {
	preserveLoggingTestState(t)
	if _, err := InitLoggingChecked("info", "", false); err != nil {
		t.Fatal(err)
	}
	beforeRoot := getRootLogger()
	beforeLevel := CurrentLogLevel()
	if _, err := InitLoggingChecked("definitely-invalid", t.TempDir()+"/oie.log", true); err == nil {
		t.Fatal("invalid log level was accepted")
	}
	if got := CurrentLogLevel(); got != beforeLevel {
		t.Fatalf("invalid log-level request mutated level: got %q want %q", got, beforeLevel)
	}
	if got := getRootLogger(); got != beforeRoot {
		t.Fatal("invalid log-level request replaced the active logger")
	}
}
