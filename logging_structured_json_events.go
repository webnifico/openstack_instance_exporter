package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
)

var logFileHandle *os.File
var currentLogLevelVal atomic.Value

type LogLevel int

func getRootLogger() *slog.Logger {
	v := rootLoggerVal.Load()
	if v == nil {
		return slog.Default()
	}
	return v.(*slog.Logger)
}

// InitLogging sets up slog with JSON output.
func InitLogging(logLevelStr, logFilePath string, enableFile bool) string {
	logMu.Lock()
	defer logMu.Unlock()

	oldFileHandle := logFileHandle
	logFileHandle = nil

	level, appliedLevel := normalizeLogLevel(logLevelStr)

	opts := &slog.HandlerOptions{
		Level: level,
	}

	var writer io.Writer = os.Stdout

	if enableFile && logFilePath != "" {
		// O_APPEND support for copytruncate rotation
		f, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "openstack_instance_exporter failed_to_open_logfile path=%q err=%v\n", logFilePath, err)
		} else {
			logFileHandle = f
			writer = io.MultiWriter(os.Stdout, f)
		}
	}

	handler := slog.NewJSONHandler(writer, opts)
	rl := slog.New(handler)
	rootLoggerVal.Store(rl)
	currentLogLevelVal.Store(appliedLevel)
	slog.SetDefault(rl)
	if oldFileHandle != nil && oldFileHandle != logFileHandle {
		_ = oldFileHandle.Close()
	}
	return appliedLevel
}

func normalizeLogLevel(logLevelStr string) (slog.Level, string) {
	switch strings.ToLower(strings.TrimSpace(logLevelStr)) {
	case "debug":
		return slog.LevelDebug, "debug"
	case "info":
		return slog.LevelInfo, "info"
	case "warn", "notice":
		return slog.LevelWarn, "warn"
	case "error":
		return slog.LevelError, "error"
	default:
		return slog.LevelInfo, "info"
	}
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
// Compatibility Helpers
// -----------------------------------------------------------------------------

// logKV is used by metrics_engine.go
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
