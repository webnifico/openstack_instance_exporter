package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The subprocess captures the real os.Stdout/os.Stderr paths without racing
// with any other test that uses the package-wide logger.
func TestStartupLoggerRetainsEarlyErrors(t *testing.T) {
	for _, mode := range []string{"early", "open-failure", "file", "console", "runtime-level", "copytruncate"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "oie.log")
			cmd := exec.Command(os.Args[0], "-test.run=^TestStartupLoggerSubprocess$")
			cmd.Env = append(os.Environ(), "OIE_STARTUP_LOG_TEST="+mode, "OIE_STARTUP_LOG_PATH="+path)
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			if err := cmd.Run(); err != nil {
				t.Fatalf("helper failed: %v\nstdout: %s\nstderr: %s", err, &stdout, &stderr)
			}
			if mode == "early" || mode == "open-failure" {
				if stdout.Len() != 0 {
					t.Fatalf("early error leaked to discarded stdout: %s", &stdout)
				}
				var event map[string]any
				if err := json.Unmarshal(bytes.TrimSpace(stderr.Bytes()), &event); err != nil {
					t.Fatalf("stderr is not one JSON event: %v: %s", err, &stderr)
				}
				if event["level"] != "ERROR" || event["msg"] != "invalid_startup_configuration" {
					t.Fatalf("early event lost severity/schema: %#v", event)
				}
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatalf("early failure created an unintended logfile: %v", err)
				}
				return
			}
			if stderr.Len() != 0 {
				t.Fatalf("normal events duplicated into retained stderr: %s", &stderr)
			}
			if mode == "console" {
				if !strings.Contains(stdout.String(), `"msg":"console_event"`) {
					t.Fatalf("console event absent: %s", &stdout)
				}
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("console mode opened the inactive file")
				}
				return
			}
			file, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if got := info.Mode().Perm(); got != 0o640 {
				t.Fatalf("log file mode = %04o, want 0640", got)
			}
			if mode != "copytruncate" && !bytes.Equal(stdout.Bytes(), file) {
				t.Fatalf("standalone stdout/file output differs\nstdout: %s\nfile: %s", &stdout, file)
			}
			if mode == "runtime-level" {
				if strings.Contains(string(file), "hidden_debug") || !strings.Contains(string(file), "visible_debug") || !strings.Contains(string(file), `"severity_class":"notice"`) {
					t.Fatalf("runtime level/notice behavior changed: %s", file)
				}
			}
			if mode == "copytruncate" && (strings.Contains(string(file), "before_truncate") || !strings.Contains(string(file), "after_truncate")) {
				t.Fatalf("file did not continue after copytruncate: %s", file)
			}
		})
	}
}

func TestStartupLoggerSubprocess(t *testing.T) {
	mode := os.Getenv("OIE_STARTUP_LOG_TEST")
	if mode == "" {
		return
	}
	path := os.Getenv("OIE_STARTUP_LOG_PATH")
	initStartupLogging()
	logger := NewComponentLogger("app", "app")
	switch mode {
	case "early":
		logger.Error("invalid_startup_configuration", "err", "invalid requested log level")
	case "open-failure":
		_, err := InitLoggingChecked("info", filepath.Join(path, "missing", "oie.log"), true)
		if err == nil {
			t.Fatal("requested file destination did not fail closed")
		}
		logger.Error("invalid_startup_configuration", "err", err)
	case "console":
		if _, err := InitLoggingChecked("info", path, false); err != nil {
			t.Fatal(err)
		}
		logger.Info("console_event")
	default:
		if _, err := InitLoggingChecked("info", path, true); err != nil {
			t.Fatal(err)
		}
		switch mode {
		case "file":
			logger.Info("file_event")
			logger.Error("runtime_error")
		case "runtime-level":
			logger.Debug("hidden_debug")
			writerBefore := logFileWriter
			if writerBefore == nil {
				t.Fatal("file logging did not retain its resilient writer")
			}
			if _, err := SetLogLevel("debug"); err != nil {
				t.Fatal(err)
			}
			if logFileWriter != writerBefore {
				t.Fatal("runtime log-level change replaced resilient file-writer state")
			}
			logger.Debug("visible_debug")
			logger.Notice("notice_event")
			if _, err := SetLogLevel("invalid"); err == nil {
				t.Fatal("invalid runtime log level accepted")
			}
		case "copytruncate":
			logger.Info("before_truncate")
			if err := os.Truncate(path, 0); err != nil {
				t.Fatal(err)
			}
			logger.Info("after_truncate")
		default:
			t.Fatalf("unrecognized test mode %q", mode)
		}
	}
	// Avoid the test harness writing PASS to stdout, which is part of the
	// stream contract under test rather than a test result channel.
	os.Exit(0)
}
