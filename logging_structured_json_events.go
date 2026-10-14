package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var logFileHandle *os.File
var logFileWriter *resilientFileLogWriter
var currentLogLevelVal atomic.Value

type resilientFileLogWriter struct {
	mu              sync.Mutex
	primary         io.Writer
	mirror          io.Writer
	fallback        io.Writer
	path            string
	failureReported bool
	needsLineReset  bool
}

func (writer *resilientFileLogWriter) writePrimary(payload []byte) (int, error) {
	if writer.needsLineReset {
		written, err := writer.primary.Write([]byte{'\n'})
		if err != nil {
			return 0, fmt.Errorf("log line resynchronization failed: %w", err)
		}
		if written != 1 {
			return 0, fmt.Errorf("log line resynchronization failed: %w", io.ErrShortWrite)
		}
		writer.needsLineReset = false
	}

	written, err := writer.primary.Write(payload)
	if written > 0 && written < len(payload) {
		writer.needsLineReset = true
	}
	if err == nil && written != len(payload) {
		err = io.ErrShortWrite
	}
	return written, err
}

func (writer *resilientFileLogWriter) Write(payload []byte) (int, error) {
	if writer == nil || writer.primary == nil {
		return 0, fmt.Errorf("log file writer is unavailable")
	}
	writer.mu.Lock()
	defer writer.mu.Unlock()

	written, primaryErr := writer.writePrimary(payload)

	// The stdout copy is best-effort. In the bundled systemd unit it points to
	// /dev/null in file mode, while direct executions still get the convenient
	// console mirror. A broken stdout must never prevent the primary file write.
	if writer.mirror != nil {
		_, _ = writer.mirror.Write(payload)
	}

	if primaryErr == nil {
		if writer.failureReported {
			writer.failureReported = false
			writer.writeDiagnostic("INFO", "logfile_write_recovered", "")
		}
		return len(payload), nil
	}

	// slog intentionally discards Handler errors. Preserve the original event
	// on stderr so file-mode evidence does not disappear silently on ENOSPC,
	// EIO, a read-only remount, or a similar mid-runtime write failure.
	if writer.fallback != nil {
		_, _ = writer.fallback.Write(payload)
	}
	if !writer.failureReported {
		writer.failureReported = true
		writer.writeDiagnostic("ERROR", "logfile_write_failed", primaryErr.Error())
	}
	return written, primaryErr
}

func (writer *resilientFileLogWriter) writeDiagnostic(level, message, detail string) {
	if writer == nil || writer.fallback == nil {
		return
	}
	event := map[string]any{
		"time":      time.Now().UTC().Format(time.RFC3339Nano),
		"level":     level,
		"msg":       message,
		"category":  "app",
		"component": "logging",
		"path":      writer.path,
	}
	if detail != "" {
		event["err"] = detail
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		return
	}
	encoded = append(encoded, '\n')
	_, _ = writer.fallback.Write(encoded)
}

func newResilientFileLogWriter(file *os.File) *resilientFileLogWriter {
	if file == nil {
		return nil
	}
	return &resilientFileLogWriter{
		primary:  file,
		mirror:   os.Stdout,
		fallback: os.Stderr,
		path:     file.Name(),
	}
}

type LogLevel int

func getRootLogger() *slog.Logger {
	v := rootLoggerVal.Load()
	if v == nil {
		return slog.Default()
	}
	return v.(*slog.Logger)
}

// initStartupLogging keeps diagnostics visible before an operator-requested
// logfile has been validated and opened. The service retains stderr even when
// it discards the normal stdout copy of file logs.
func initStartupLogging() {
	logMu.Lock()
	defer logMu.Unlock()

	oldFileHandle := logFileHandle
	logFileHandle = nil
	logFileWriter = nil
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	rootLoggerVal.Store(logger)
	currentLogLevelVal.Store("info")
	slog.SetDefault(logger)
	if oldFileHandle != nil {
		_ = oldFileHandle.Close()
	}
}

// InitLoggingChecked installs the process logger and fails closed when the
// requested level or explicitly enabled logfile is invalid.
func InitLoggingChecked(logLevelStr, logFilePath string, enableFile bool) (string, error) {
	level, appliedLevel, valid := parseLogLevel(logLevelStr)
	if !valid {
		return "", fmt.Errorf("log.level must be one of debug, info, warn, notice, or error")
	}

	logMu.Lock()
	defer logMu.Unlock()

	var writer io.Writer = os.Stdout
	var newFileHandle *os.File
	var newFileWriter *resilientFileLogWriter

	if enableFile {
		if strings.TrimSpace(logFilePath) == "" {
			return "", fmt.Errorf("log.file.path must not be empty when log.file.enable is true")
		}

		// O_APPEND supports copytruncate rotation. O_NONBLOCK is inert for
		// regular files and prevents a FIFO/device from stalling startup before
		// its type is checked. O_NOFOLLOW rejects a symlink final component.
		file, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0o640)
		if err != nil {
			return "", fmt.Errorf("log.file.path is not writable: %w", err)
		}
		info, statErr := file.Stat()
		if statErr != nil || !info.Mode().IsRegular() {
			_ = file.Close()
			if statErr == nil {
				statErr = fmt.Errorf("configured destination is not a regular file")
			}
			return "", fmt.Errorf("log.file.path is not usable: %w", statErr)
		}
		newFileHandle = file
		newFileWriter = newResilientFileLogWriter(file)
		writer = newFileWriter
	}

	oldFileHandle := logFileHandle
	logFileHandle = newFileHandle
	logFileWriter = newFileWriter
	handler := slog.NewJSONHandler(writer, &slog.HandlerOptions{Level: level})
	logger := slog.New(handler)
	rootLoggerVal.Store(logger)
	currentLogLevelVal.Store(appliedLevel)
	slog.SetDefault(logger)
	if oldFileHandle != nil && oldFileHandle != logFileHandle {
		_ = oldFileHandle.Close()
	}
	return appliedLevel, nil
}

func SetLogLevel(logLevelStr string) (string, error) {
	logMu.Lock()
	defer logMu.Unlock()

	level, appliedLevel, valid := parseLogLevel(logLevelStr)
	if !valid {
		return "", fmt.Errorf("log.level must be one of debug, info, warn, notice, or error")
	}
	var writer io.Writer = os.Stdout
	if logFileHandle != nil {
		if _, err := logFileHandle.Stat(); err != nil {
			return "", fmt.Errorf("configured log destination is unavailable: %w", err)
		}
		if logFileWriter == nil {
			return "", fmt.Errorf("configured log destination writer is unavailable")
		}
		writer = logFileWriter
	}
	handler := slog.NewJSONHandler(writer, &slog.HandlerOptions{Level: level})
	logger := slog.New(handler)
	rootLoggerVal.Store(logger)
	currentLogLevelVal.Store(appliedLevel)
	slog.SetDefault(logger)
	return appliedLevel, nil
}

func parseLogLevel(logLevelStr string) (slog.Level, string, bool) {
	switch strings.ToLower(strings.TrimSpace(logLevelStr)) {
	case "debug":
		return slog.LevelDebug, "debug", true
	case "info":
		return slog.LevelInfo, "info", true
	case "warn", "notice":
		return slog.LevelWarn, "warn", true
	case "error":
		return slog.LevelError, "error", true
	default:
		return slog.LevelInfo, "", false
	}
}

func validateLogLevel(logLevelStr string) error {
	if _, _, valid := parseLogLevel(logLevelStr); !valid {
		return fmt.Errorf("log.level must be one of debug, info, warn, notice, or error")
	}
	return nil
}

func CurrentLogLevel() string {
	v := currentLogLevelVal.Load()
	if v == nil {
		return "unknown"
	}
	return v.(string)
}

// -----------------------------------------------------------------------------
// Component Logger Adapter
// -----------------------------------------------------------------------------
type ComponentLogger struct {
	category  string
	component string
}

func NewComponentLogger(category, component string) ComponentLogger {
	return ComponentLogger{category: category, component: component}
}
func (l ComponentLogger) Debug(msg string, kvpairs ...interface{}) {
	getRootLogger().Debug(msg, l.argsToAttrs(msg, kvpairs)...)
}
func (l ComponentLogger) Info(msg string, kvpairs ...interface{}) {
	getRootLogger().Info(msg, l.argsToAttrs(msg, kvpairs)...)
}
func (l ComponentLogger) Notice(msg string, kvpairs ...interface{}) {
	args := append([]interface{}{"severity_class", "notice"}, kvpairs...)
	getRootLogger().Warn(msg, l.argsToAttrs(msg, args)...)
}
func (l ComponentLogger) Error(msg string, kvpairs ...interface{}) {
	getRootLogger().Error(msg, l.argsToAttrs(msg, kvpairs)...)
}

// -----------------------------------------------------------------------------
// Structured logging helper used by behavior/threat paths that need dynamic
// category/component selection.
// -----------------------------------------------------------------------------

func logKV(level LogLevel, category, component, msg string, kvpairs ...interface{}) {
	args := make([]interface{}, 0, len(kvpairs)+4)
	args = append(args, "category", category, "component", component)
	args = append(args, kvpairs...)
	if level == LogLevelNotice {
		args = append(args, "severity_class", "notice")
	}

	ctx := context.Background()
	switch level {
	case LogLevelDebug:
		getRootLogger().DebugContext(ctx, msg, args...)
	case LogLevelInfo:
		getRootLogger().InfoContext(ctx, msg, args...)
	case LogLevelNotice:
		getRootLogger().WarnContext(ctx, msg, args...)
	case LogLevelError:
		getRootLogger().ErrorContext(ctx, msg, args...)
	default:
		getRootLogger().InfoContext(ctx, msg, args...)
	}
}
