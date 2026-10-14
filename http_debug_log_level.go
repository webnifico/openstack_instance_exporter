package main

import (
	"fmt"
	"net/http"
	"net/url"
)

const debugLogLevelPath = "/debug/log-level"

type debugLogLevelHandler struct {
	current func() string
	set     func(string) (string, error)
}

func newDebugLogLevelHandler() http.Handler {
	return &debugLogLevelHandler{
		current: CurrentLogLevel,
		set:     SetLogLevel,
	}
}

func registerDebugLogLevelHandler(mux *http.ServeMux, enabled bool, handler http.Handler) {
	if enabled {
		mux.Handle(debugLogLevelPath, handler)
	}
}

func (handler *debugLogLevelHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	switch r.Method {
	case http.MethodGet:
		query, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			http.Error(w, "invalid query string", http.StatusBadRequest)
			return
		}
		if _, present := query["level"]; present {
			http.Error(w, "level is only accepted with POST", http.StatusBadRequest)
			return
		}
		fmt.Fprintf(w, "current log level: %s\n", handler.current())
	case http.MethodPost:
		query, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			http.Error(w, "invalid query string", http.StatusBadRequest)
			return
		}
		levels, present := query["level"]
		if len(query) != 1 || !present || len(levels) != 1 {
			http.Error(w, "exactly one level query parameter is required", http.StatusBadRequest)
			return
		}
		level, valid := canonicalDebugLogLevel(levels[0])
		if !valid {
			http.Error(w, "invalid log level; expected debug, info, warn, notice, or error", http.StatusBadRequest)
			return
		}
		applied, err := handler.set(level)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to set log level: %v", err), http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "log level set to %s\n", applied)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}
}

func canonicalDebugLogLevel(raw string) (string, bool) {
	_, canonical, valid := parseLogLevel(raw)
	return canonical, valid
}
