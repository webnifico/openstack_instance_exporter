package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
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
	appliedLevel, _ := initializeLogging(logLevelStr, logFilePath, enableFile, false, os.OpenFile)
	return appliedLevel
}

func InitLoggingChecked(logLevelStr, logFilePath string, enableFile bool) (string, error) {
	return initializeLogging(logLevelStr, logFilePath, enableFile, true, os.OpenFile)
}

func initializeLogging(
	logLevelStr, logFilePath string,
	enableFile, failClosed bool,
	openFile func(string, int, os.FileMode) (*os.File, error),
) (string, error) {
	logMu.Lock()
	defer logMu.Unlock()

	level, appliedLevel := normalizeLogLevel(logLevelStr)
	var writer io.Writer = os.Stdout
	var newFileHandle *os.File

	if enableFile {
		if strings.TrimSpace(logFilePath) == "" {
			if failClosed {
				return "", fmt.Errorf("log.file.path must not be empty when log.file.enable is true")
			}
		} else if openFile == nil {
			if failClosed {
				return "", fmt.Errorf("log.file.path cannot be opened")
			}
		} else {
			// O_APPEND support for copytruncate rotation
			// O_NONBLOCK is inert for regular files and prevents a configured
			// FIFO or device from stalling startup before its type is checked.
			file, err := openFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND|syscall.O_NONBLOCK, 0o644)
			if err != nil || file == nil {
				if failClosed {
					if err == nil {
						err = fmt.Errorf("log file opener returned no file")
					}
					return "", fmt.Errorf("log.file.path is not writable: %w", err)
				}
				fmt.Fprintf(os.Stderr, "openstack_instance_exporter failed_to_open_logfile path=%q err=%v\n", logFilePath, err)
			} else {
				info, statErr := file.Stat()
				if statErr != nil || !info.Mode().IsRegular() {
					_ = file.Close()
					if statErr == nil {
						statErr = fmt.Errorf("configured destination is not a regular file")
					}
					if failClosed {
						return "", fmt.Errorf("log.file.path is not usable: %w", statErr)
					}
					fmt.Fprintf(os.Stderr, "openstack_instance_exporter invalid_logfile path=%q err=%v\n", logFilePath, statErr)
				} else {
					newFileHandle = file
					writer = io.MultiWriter(os.Stdout, file)
				}
			}
		}
	}

	oldFileHandle := logFileHandle
	logFileHandle = newFileHandle
	opts := &slog.HandlerOptions{Level: level}
	handler := slog.NewJSONHandler(writer, opts)
	rl := slog.New(handler)
	rootLoggerVal.Store(rl)
	currentLogLevelVal.Store(appliedLevel)
	slog.SetDefault(rl)
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
		writer = io.MultiWriter(os.Stdout, logFileHandle)
	}
	handler := slog.NewJSONHandler(writer, &slog.HandlerOptions{Level: level})
	logger := slog.New(handler)
	rootLoggerVal.Store(logger)
	currentLogLevelVal.Store(appliedLevel)
	slog.SetDefault(logger)
	return appliedLevel, nil
}

func normalizeLogLevel(logLevelStr string) (slog.Level, string) {
	level, appliedLevel, valid := parseLogLevel(logLevelStr)
	if !valid {
		return slog.LevelInfo, "info"
	}
	return level, appliedLevel
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
