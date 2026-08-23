package main

import (
	"bytes"
	"fmt"
	yaml "gopkg.in/yaml.v3"
	"io"
	"math"
	"os"
	"strings"
)

const maxExternalBehaviorRules = 100

func LoadBehaviorExternalRules(path string) ([]BehaviorRule, BehaviorRulesConfigStatus) {
	st := BehaviorRulesConfigStatus{Status: "not_configured", Path: path}
	if path == "" {
		return nil, st
	}

	b, err := os.ReadFile(path)
	if err != nil {
		st.Status = "error"
		st.Err = err.Error()
		return nil, st
	}

	var rf externalBehaviorRulesFile
	decoder := yaml.NewDecoder(bytes.NewReader(b))
	decoder.KnownFields(true)
	if err := decoder.Decode(&rf); err != nil {
		st.Status = "error"
		st.Err = err.Error()
		return nil, st
	}
	var extra interface{}
	if err := decoder.Decode(&extra); err != io.EOF {
		st.Status = "error"
		if err == nil {
			st.Err = "multiple YAML documents are not supported"
		} else {
			st.Err = err.Error()
		}
		return nil, st
	}
	if len(rf.Rules) == 0 {
		st.Status = "error"
		st.Err = "no rules defined"
		return nil, st
	}
	if len(rf.Rules) > maxExternalBehaviorRules {
		st.Status = "error"
		st.Err = fmt.Sprintf("too many rules: %d exceeds %d", len(rf.Rules), maxExternalBehaviorRules)
		return nil, st
	}

	portSets := make(map[string]map[uint16]struct{}, len(rf.PortSets))
	for name, ports := range rf.PortSets {
		if strings.TrimSpace(name) == "" {
			st.Status = "error"
			st.Err = "port set has an empty name"
			return nil, st
		}
		set := make(map[uint16]struct{}, len(ports))
		for _, pi := range ports {
			if pi <= 0 || pi > 65535 {
				st.Status = "error"
				st.Err = fmt.Sprintf("port set %q contains invalid port %d", name, pi)
				return nil, st
			}
			set[uint16(pi)] = struct{}{}
		}
		if len(set) == 0 {
			st.Status = "error"
			st.Err = fmt.Sprintf("port set %q is empty", name)
			return nil, st
		}
		portSets[name] = set
	}
	var compiled []BehaviorRule
	seenIDs := make(map[string]struct{}, len(rf.Rules))
	for i, r := range rf.Rules {
		r.ID = strings.TrimSpace(r.ID)
		r.Kind = strings.TrimSpace(r.Kind)
		r.Severity = strings.ToLower(strings.TrimSpace(r.Severity))
		if r.ID == "" {
			st.Status = "error"
			st.Err = fmt.Sprintf("rule %d is missing id", i)
			return nil, st
		}
		if _, exists := seenIDs[r.ID]; exists {
			st.Status = "error"
			st.Err = fmt.Sprintf("duplicate rule id %q", r.ID)
			return nil, st
		}
		seenIDs[r.ID] = struct{}{}
		if r.Kind == "" {
			st.Status = "error"
			st.Err = fmt.Sprintf("rule %q is missing kind", r.ID)
			return nil, st
		}
		if r.Severity != "" && r.Severity != "low" && r.Severity != "medium" && r.Severity != "high" && r.Severity != "critical" {
			st.Status = "error"
			st.Err = fmt.Sprintf("rule %q has invalid legacy severity %q", r.ID, r.Severity)
			return nil, st
		}
		dir := r.Direction
		if dir == "" {
			dir = "any"
		}
		if dir != "any" && dir != "inbound" && dir != "outbound" {
			st.Status = "error"
			st.Err = fmt.Sprintf("rule %q has invalid direction %q", r.ID, dir)
			return nil, st
		}

		portSet := map[uint16]struct{}{}
		if r.PortSet != "" {
			ps, ok := portSets[r.PortSet]
			if !ok {
				st.Status = "error"
				st.Err = fmt.Sprintf("rule %q references unknown port_set %q", r.ID, r.PortSet)
				return nil, st
			}
			for p := range ps {
				portSet[p] = struct{}{}
			}
		}
		for _, pi := range r.Ports {
			if pi <= 0 || pi > 65535 {
				st.Status = "error"
				st.Err = fmt.Sprintf("rule %q contains invalid port %d", r.ID, pi)
				return nil, st
			}
			portSet[uint16(pi)] = struct{}{}
		}
		if len(portSet) == 0 {
			st.Status = "error"
			st.Err = fmt.Sprintf("rule %q has no ports", r.ID)
			return nil, st
		}

		flowsMin := r.FlowsMin
		if flowsMin < 0 {
			st.Status = "error"
			st.Err = fmt.Sprintf("rule %q has negative flows_min", r.ID)
			return nil, st
		}
		remotesMin := r.UniqueRemotesMin
		if remotesMin < 0 {
			st.Status = "error"
			st.Err = fmt.Sprintf("rule %q has negative unique_remotes_min", r.ID)
			return nil, st
		}
		unrepliedMin := r.Ratios.Unreplied
		if math.IsNaN(unrepliedMin) || math.IsInf(unrepliedMin, 0) || unrepliedMin < 0 || unrepliedMin > 1 {
			st.Status = "error"
			st.Err = fmt.Sprintf("rule %q has a non-finite or out-of-range unreplied ratio", r.ID)
			return nil, st
		}

		evMode := r.EvidenceMode
		if evMode != "" && evMode != "dominant_remote" && evMode != "dominant_port" && evMode != "distributed" && evMode != "mixed" {
			st.Status = "error"
			st.Err = fmt.Sprintf("rule %q has invalid evidence_mode %q", r.ID, evMode)
			return nil, st
		}

		topRemoteShareMin := r.TopRemoteShareMin
		topPortShareMin := r.TopPortShareMin
		if math.IsNaN(topRemoteShareMin) || math.IsInf(topRemoteShareMin, 0) ||
			math.IsNaN(topPortShareMin) || math.IsInf(topPortShareMin, 0) ||
			topRemoteShareMin < 0 || topRemoteShareMin > 1 || topPortShareMin < 0 || topPortShareMin > 1 {
			st.Status = "error"
			st.Err = fmt.Sprintf("rule %q has a non-finite or out-of-range evidence share", r.ID)
			return nil, st
		}

		kind := r.Kind
		reason := r.Reason
		if reason == "" {
			reason = "external_rule_match"
		}

		ruleID := r.ID
		compiled = append(compiled, BehaviorRule{
			ID:     ruleID,
			Dir:    dir,
			Source: "external",
			When: func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) bool {
				if !ruleDirMatch(dir, feature.Direction) {
					return false
				}
				matchedPort := false
				if ctx != nil && len(ctx.DstPortCounts) > 0 {
					for port := range portSet {
						if ctx.DstPortCounts[port] > 0 {
							matchedPort = true
							break
						}
					}
				} else if _, ok := portSet[feature.TopDstPort]; ok {
					matchedPort = true
				}
				if !matchedPort {
					return false
				}
				if flowsMin > 0 && feature.Flows < flowsMin {
					return false
				}
				if remotesMin > 0 && feature.UniqueRemotes < remotesMin {
					return false
				}
				if unrepliedMin > 0 && feature.UnrepliedRatio < unrepliedMin {
					return false
				}
				if evMode != "" && ev.EvidenceMode != evMode {
					return false
				}
				if topRemoteShareMin > 0 && ev.TopRemoteShare < topRemoteShareMin {
					return false
				}
				if topPortShareMin > 0 && ev.TopPortShare < topPortShareMin {
					return false
				}
				return true
			},
			Kind: func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) string {
				return kind
			},
			Reason: func(feature BehaviorFeature, sc behaviorScaler, ev BehaviorEvidence, ctx *RuleCtx) string {
				return reason
			},
		})
	}

	st.Status = "loaded"
	st.Rules = len(compiled)
	st.PortSets = len(portSets)
	return compiled, st
}
