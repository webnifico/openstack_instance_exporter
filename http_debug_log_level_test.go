package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type recordingLogLevelState struct {
	mu       sync.Mutex
	current  string
	setCalls []string
}

func newRecordingLogLevelHandler(initial string) (*debugLogLevelHandler, *recordingLogLevelState) {
	state := &recordingLogLevelState{current: initial}
	return &debugLogLevelHandler{
		current: func() string {
			state.mu.Lock()
			defer state.mu.Unlock()
			return state.current
		},
		set: func(level string) (string, error) {
			state.mu.Lock()
			defer state.mu.Unlock()
			state.current = level
			state.setCalls = append(state.setCalls, level)
			return level, nil
		},
	}, state
}

func (state *recordingLogLevelState) snapshot() (string, []string) {
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.current, append([]string(nil), state.setCalls...)
}

func serveDebugLogLevel(handler http.Handler, method, target string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(method, target, nil))
	return recorder
}

func TestDebugLogLevelGETIsReadOnly(t *testing.T) {
	for _, target := range []string{
		debugLogLevelPath,
		debugLogLevelPath + "?format=text",
	} {
		handler, state := newRecordingLogLevelHandler("warn")
		response := serveDebugLogLevel(handler, http.MethodGet, target)
		if response.Code != http.StatusOK {
			t.Fatalf("GET %q status=%d, want %d", target, response.Code, http.StatusOK)
		}
		if response.Body.String() != "current log level: warn\n" {
			t.Fatalf("GET %q body=%q", target, response.Body.String())
		}
		if current, calls := state.snapshot(); current != "warn" || len(calls) != 0 {
			t.Fatalf("GET %q mutated state: current=%q calls=%v", target, current, calls)
		}
	}

	for _, target := range []string{
		debugLogLevelPath + "?level=debug",
		debugLogLevelPath + "?level=",
		debugLogLevelPath + "?level=debug&level=error",
		debugLogLevelPath + "?level=%zz",
	} {
		handler, state := newRecordingLogLevelHandler("warn")
		response := serveDebugLogLevel(handler, http.MethodGet, target)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("GET %q status=%d, want %d", target, response.Code, http.StatusBadRequest)
		}
		if strings.TrimSpace(response.Body.String()) == "" {
			t.Fatalf("GET %q returned an empty rejection", target)
		}
		if current, calls := state.snapshot(); current != "warn" || len(calls) != 0 {
			t.Fatalf("rejected GET %q mutated state: current=%q calls=%v", target, current, calls)
		}
	}
}

func TestDebugLogLevelPOSTAcceptsOneValidLevel(t *testing.T) {
	for _, testCase := range []struct {
		query string
		want  string
	}{
		{query: "debug", want: "debug"},
		{query: "info", want: "info"},
		{query: "warn", want: "warn"},
		{query: "notice", want: "warn"},
		{query: "error", want: "error"},
		{query: "%20DeBuG%20", want: "debug"},
	} {
		t.Run(testCase.query, func(t *testing.T) {
			handler, state := newRecordingLogLevelHandler("info")
			response := serveDebugLogLevel(handler, http.MethodPost, debugLogLevelPath+"?level="+testCase.query)
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
			}
			if response.Body.String() != fmt.Sprintf("log level set to %s\n", testCase.want) {
				t.Fatalf("body=%q", response.Body.String())
			}
			if current, calls := state.snapshot(); current != testCase.want || len(calls) != 1 || calls[0] != testCase.want {
				t.Fatalf("current=%q calls=%v, want one %q mutation", current, calls, testCase.want)
			}
		})
	}
}

func TestDebugLogLevelPOSTRejectsAmbiguousOrInvalidLevelsWithoutMutation(t *testing.T) {
	for _, target := range []string{
		debugLogLevelPath,
		debugLogLevelPath + "?other=debug",
		debugLogLevelPath + "?level=",
		debugLogLevelPath + "?level=%20%20",
		debugLogLevelPath + "?level=trace",
		debugLogLevelPath + "?Level=debug",
		debugLogLevelPath + "?level=debug&other=value",
		debugLogLevelPath + "?level=debug&level=debug",
		debugLogLevelPath + "?level=debug&level=error",
		debugLogLevelPath + "?level=debug&level=",
		debugLogLevelPath + "?level=debug&level=%zz",
		debugLogLevelPath + "?level=debug&other=%zz",
	} {
		handler, state := newRecordingLogLevelHandler("error")
		response := serveDebugLogLevel(handler, http.MethodPost, target)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("POST %q status=%d, want %d", target, response.Code, http.StatusBadRequest)
		}
		if strings.TrimSpace(response.Body.String()) == "" {
			t.Fatalf("POST %q returned an empty error", target)
		}
		if current, calls := state.snapshot(); current != "error" || len(calls) != 0 {
			t.Fatalf("rejected POST %q mutated state: current=%q calls=%v", target, current, calls)
		}
	}
}

func TestDebugLogLevelPOSTReportsSetterFailureWithoutMutation(t *testing.T) {
	state := &recordingLogLevelState{current: "warn"}
	handler := &debugLogLevelHandler{
		current: func() string {
			state.mu.Lock()
			defer state.mu.Unlock()
			return state.current
		},
		set: func(level string) (string, error) {
			state.mu.Lock()
			defer state.mu.Unlock()
			state.setCalls = append(state.setCalls, level)
			return "", errors.New("level controller unavailable")
		},
	}

	response := serveDebugLogLevel(handler, http.MethodPost, debugLogLevelPath+"?level=debug")
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("setter failure status=%d, want %d", response.Code, http.StatusInternalServerError)
	}
	if !strings.Contains(response.Body.String(), "failed to set log level") {
		t.Fatalf("setter failure was not visible: %q", response.Body.String())
	}
	if current, calls := state.snapshot(); current != "warn" || len(calls) != 1 || calls[0] != "debug" {
		t.Fatalf("setter failure state: current=%q calls=%v", current, calls)
	}
}

func TestDebugLogLevelUnsupportedMethodsReturnAllowWithoutMutation(t *testing.T) {
	for _, method := range []string{
		http.MethodHead,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
		http.MethodOptions,
		http.MethodConnect,
		http.MethodTrace,
	} {
		handler, state := newRecordingLogLevelHandler("info")
		response := serveDebugLogLevel(handler, method, debugLogLevelPath+"?level=debug")
		if response.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s status=%d, want %d", method, response.Code, http.StatusMethodNotAllowed)
		}
		if response.Header().Get("Allow") != "GET, POST" {
			t.Fatalf("%s Allow=%q", method, response.Header().Get("Allow"))
		}
		if current, calls := state.snapshot(); current != "info" || len(calls) != 0 {
			t.Fatalf("%s mutated state: current=%q calls=%v", method, current, calls)
		}
	}
}

func TestDebugLogLevelEndpointCanBeEntirelyDisabled(t *testing.T) {
	handler, state := newRecordingLogLevelHandler("info")
	mux := http.NewServeMux()
	registerDebugLogLevelHandler(mux, false, handler)

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		response := serveDebugLogLevel(mux, method, debugLogLevelPath+"?level=debug")
		if response.Code != http.StatusNotFound {
			t.Fatalf("disabled endpoint %s status=%d, want %d", method, response.Code, http.StatusNotFound)
		}
	}
	if current, calls := state.snapshot(); current != "info" || len(calls) != 0 {
		t.Fatalf("disabled endpoint mutated state: current=%q calls=%v", current, calls)
	}

	mux = http.NewServeMux()
	registerDebugLogLevelHandler(mux, true, handler)
	if response := serveDebugLogLevel(mux, http.MethodGet, debugLogLevelPath); response.Code != http.StatusOK {
		t.Fatalf("enabled endpoint status=%d, want %d", response.Code, http.StatusOK)
	}
}

func TestDebugLogLevelHandlerConcurrentRequestsPreserveMethodSemantics(t *testing.T) {
	handler, state := newRecordingLogLevelHandler("info")
	validLevels := []string{"debug", "info", "warn", "notice", "error"}
	const mutationCount = 128
	const readOnlyCount = 128

	start := make(chan struct{})
	errors := make(chan string, mutationCount+readOnlyCount)
	var requests sync.WaitGroup
	for index := 0; index < mutationCount; index++ {
		level := validLevels[index%len(validLevels)]
		requests.Add(1)
		go func() {
			defer requests.Done()
			<-start
			response := serveDebugLogLevel(handler, http.MethodPost, debugLogLevelPath+"?level="+level)
			if response.Code != http.StatusOK {
				errors <- fmt.Sprintf("valid POST level=%s status=%d", level, response.Code)
			}
		}()
	}
	for index := 0; index < readOnlyCount; index++ {
		index := index
		requests.Add(1)
		go func() {
			defer requests.Done()
			<-start
			method := http.MethodGet
			target := debugLogLevelPath
			wantStatus := http.StatusOK
			switch index % 4 {
			case 1:
				target += "?level=debug"
				wantStatus = http.StatusBadRequest
			case 2:
				method = http.MethodPost
				target += "?level=trace"
				wantStatus = http.StatusBadRequest
			case 3:
				method = http.MethodPut
				target += "?level=error"
				wantStatus = http.StatusMethodNotAllowed
			}
			response := serveDebugLogLevel(handler, method, target)
			if response.Code != wantStatus {
				errors <- fmt.Sprintf("%s %s status=%d want=%d", method, target, response.Code, wantStatus)
			}
		}()
	}
	close(start)
	requests.Wait()
	close(errors)
	for requestError := range errors {
		t.Error(requestError)
	}

	current, calls := state.snapshot()
	if len(calls) != mutationCount {
		t.Fatalf("mutation count=%d, want %d", len(calls), mutationCount)
	}
	if _, valid := canonicalDebugLogLevel(current); !valid {
		t.Fatalf("final current level=%q is invalid", current)
	}
}

func TestDebugLogLevelProductionStateIsRaceSafe(t *testing.T) {
	previous, valid := canonicalDebugLogLevel(CurrentLogLevel())
	if !valid {
		previous = "info"
	}
	InitLogging("info", "", false)
	t.Cleanup(func() { InitLogging(previous, "", false) })

	handler := newDebugLogLevelHandler()
	levels := []string{"debug", "info", "warn", "error"}
	const requestCount = 64
	start := make(chan struct{})
	errors := make(chan string, requestCount)
	var requests sync.WaitGroup
	for index := 0; index < requestCount; index++ {
		index := index
		requests.Add(1)
		go func() {
			defer requests.Done()
			<-start
			method := http.MethodGet
			target := debugLogLevelPath
			if index%2 == 0 {
				method = http.MethodPost
				target += "?level=" + levels[index%len(levels)]
			}
			response := serveDebugLogLevel(handler, method, target)
			if response.Code != http.StatusOK {
				errors <- fmt.Sprintf("%s status=%d", method, response.Code)
			}
		}()
	}
	close(start)
	requests.Wait()
	close(errors)
	for requestError := range errors {
		t.Error(requestError)
	}
	if _, valid := canonicalDebugLogLevel(CurrentLogLevel()); !valid {
		t.Fatalf("final production log level=%q is invalid", CurrentLogLevel())
	}
}
