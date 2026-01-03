package main

import (
	yaml "gopkg.in/yaml.v3"
	"os"
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
	if err := yaml.Unmarshal(b, &rf); err != nil {
		st.Status = "error"
		st.Err = err.Error()
		return nil, st
	}

	portSets := make(map[string]map[uint16]struct{}, len(rf.PortSets))
	for name, ports := range rf.PortSets {
		set := make(map[uint16]struct{}, len(ports))
		for _, pi := range ports {
			if pi <= 0 || pi > 65535 {
				continue
			}
			set[uint16(pi)] = struct{}{}
		}
		if len(set) > 0 {
			portSets[name] = set
		}
	}
	var compiled []BehaviorRule
	for i, r := range rf.Rules {
		if len(compiled) >= maxExternalBehaviorRules {
			logKV(LogLevelNotice, "behavior", "behavior_rules_yaml_truncated", "path", path, "max_rules", maxExternalBehaviorRules)
			break
		}
		if r.ID == "" {
			logKV(LogLevelNotice, "behavior", "behavior_rules_yaml_bad_rule", "path", path, "index", i, "error", "missing id")
			continue
		}
		if r.Kind == "" {
			logKV(LogLevelNotice, "behavior", "behavior_rules_yaml_bad_rule", "path", path, "rule_id", r.ID, "error", "missing kind")
			continue
		}
		dir := r.Direction
		if dir == "" {
			dir = "any"
		}
		if dir != "any" && dir != "inbound" && dir != "outbound" {
			logKV(LogLevelNotice, "behavior", "behavior_rules_yaml_bad_rule", "path", path, "rule_id", r.ID, "error", "invalid direction")
			continue
		}

		portSet := map[uint16]struct{}{}
		if r.PortSet != "" {
			ps, ok := portSets[r.PortSet]
			if !ok {
				logKV(LogLevelNotice, "behavior", "behavior_rules_yaml_bad_rule", "path", path, "rule_id", r.ID, "error", "unknown port_set")
				continue
			}
			for p := range ps {
				portSet[p] = struct{}{}
			}
		}
		for _, pi := range r.Ports {
			if pi <= 0 || pi > 65535 {
				continue
			}
			portSet[uint16(pi)] = struct{}{}
		}
		if len(portSet) == 0 {
			logKV(LogLevelNotice, "behavior", "behavior_rules_yaml_bad_rule", "path", path, "rule_id", r.ID, "error", "no ports specified")
			continue
		}

		flowsMin := r.FlowsMin
		if flowsMin < 0 {
			flowsMin = 0
		}
		remotesMin := r.UniqueRemotesMin
		if remotesMin < 0 {
			remotesMin = 0
		}
		unrepliedMin := r.Ratios.Unreplied
		if unrepliedMin < 0 {
			unrepliedMin = 0
		}

		evMode := r.EvidenceMode
		if evMode != "" && evMode != "dominant_remote" && evMode != "dominant_port" && evMode != "distributed" && evMode != "mixed" {
			logKV(LogLevelNotice, "behavior", "behavior_rules_yaml_bad_rule", "path", path, "rule_id", r.ID, "error", "invalid evidence_mode")
			continue
		}

		topRemoteShareMin := r.TopRemoteShareMin
		topPortShareMin := r.TopPortShareMin

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
				if _, ok := portSet[feature.TopDstPort]; !ok {
					return false
				}
				if flowsMin > 0 && feature.MaxSingleDstPort < flowsMin {
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
