package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
)

var logFileHandle *os.File

type LogLevel int

func getRootLogger() *slog.Logger {
	v := rootLoggerVal.Load()
	if v == nil {
		return slog.Default()
	}
	return v.(*slog.Logger)
}

// InitLogging sets up slog with JSON output.
func InitLogging(logLevelStr, logFilePath string, enableFile bool) {
	logMu.Lock()
	defer logMu.Unlock()

	if logFileHandle != nil {
		logFileHandle.Close()
		logFileHandle = nil
	}

	var level slog.Level
	switch strings.ToLower(strings.TrimSpace(logLevelStr)) {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn", "notice":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: level,
	}

	var writer io.Writer = os.Stdout

	if enableFile && logFilePath != "" {
		// O_APPEND support for copytruncate rotation
		f, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			slog.Error("failed_to_open_logfile", "err", err)
		} else {
			logFileHandle = f
			writer = io.MultiWriter(os.Stdout, f)
		}
	}

	handler := slog.NewJSONHandler(writer, opts)
	rl := slog.New(handler)
	rootLoggerVal.Store(rl)
	slog.SetDefault(rl)
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
	getRootLogger().Info(msg, l.argsToAttrs(msg, kvpairs)...)
}
func (l ComponentLogger) Error(msg string, kvpairs ...interface{}) {
	getRootLogger().Error(msg, l.argsToAttrs(msg, kvpairs)...)
}

// -----------------------------------------------------------------------------
// Compatibility Helpers
// -----------------------------------------------------------------------------

// logKV is used by metrics_engine.go
func logKV(level LogLevel, category, msg string, kvpairs ...interface{}) {
	args := make([]interface{}, 0, len(kvpairs)+2)
	args = append(args, "category", category)
	args = append(args, kvpairs...)

	ctx := context.Background()
	switch level {
	case LogLevelDebug:
		getRootLogger().DebugContext(ctx, msg, args...)
	case LogLevelInfo, LogLevelNotice:
		getRootLogger().InfoContext(ctx, msg, args...)
	case LogLevelError:
		getRootLogger().ErrorContext(ctx, msg, args...)
	default:
		getRootLogger().InfoContext(ctx, msg, args...)
	}
}
