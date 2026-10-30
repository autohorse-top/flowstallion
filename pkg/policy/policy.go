// Package policy implements the FlowStallion policy gateway: it classifies
// pipeline steps by risk and decides, for a given autonomy level, whether a
// step (and therefore its run) requires human approval before execution.
//
// Autonomy levels (v1):
//
//	L0 — fully manual: every step requires approval.
//	L1 — high + critical steps require approval.
//	L2 — only critical steps require approval (default).
//
// Risk classification (v1 rule set):
//
//	critical — step id suggests deployment/release AND env marks production;
//	high     — step touches production env, or id suggests a destructive op;
//	low      — everything else.
//
// The decision matrix is small enough to mirror in Python
// (agent/flowstallion_agent/policy.py); both implementations are checked
// against the shared vectors in testdata/policy-vectors.json.
package policy

import (
	"strings"
)

// Risk is a step risk class.
type Risk int

// Risk classes, ordered by severity.
const (
	RiskLow Risk = iota
	RiskHigh
	RiskCritical
)

// String returns the risk name.
func (r Risk) String() string {
	switch r {
	case RiskHigh:
		return "high"
	case RiskCritical:
		return "critical"
	default:
		return "low"
	}
}

// Autonomy is the run autonomy level.
type Autonomy int

// Autonomy levels.
const (
	L0 Autonomy = 0 // every step requires approval
	L1 Autonomy = 1 // high + critical steps require approval
	L2 Autonomy = 2 // only critical steps require approval
)

// Valid reports whether the level is supported.
func (a Autonomy) Valid() bool { return a >= L0 && a <= L2 }

// StepInfo is the minimal step description needed for risk evaluation.
type StepInfo struct {
	ID  string
	Env map[string]string // merged pipeline + step env
}

// prodEnvKeys are env keys that mark the target environment (any case).
var prodEnvKeys = map[string]bool{
	"environment":   true,
	"env":           true,
	"target":        true,
	"flowstallion_env": true,
}

// prodEnvValues are env values that mean "production" (any case).
var prodEnvValues = map[string]bool{
	"production": true,
	"prod":       true,
}

// highKeywords in a step id (any case, substring) mark destructive ops.
var highKeywords = []string{
	"migrate", "destroy", "drop", "delete", "remove", "purge", "publish", "prune",
}

// IsProductionEnv reports whether env marks the production environment.
func IsProductionEnv(env map[string]string) bool {
	for k, v := range env {
		if prodEnvKeys[strings.ToLower(k)] && prodEnvValues[strings.ToLower(v)] {
			return true
		}
	}
	return false
}

// StepRisk classifies a step by its id and its merged (pipeline+step) env.
func StepRisk(id string, env map[string]string) Risk {
	lowID := strings.ToLower(id)
	prod := IsProductionEnv(env)
	if prod && (strings.Contains(lowID, "deploy") || strings.Contains(lowID, "release")) {
		return RiskCritical
	}
	if prod {
		return RiskHigh
	}
	for _, kw := range highKeywords {
		if strings.Contains(lowID, kw) {
			return RiskHigh
		}
	}
	return RiskLow
}

// NeedsApproval reports whether a step of the given risk must be approved
// before running at the given autonomy level.
func NeedsApproval(risk Risk, level Autonomy) bool {
	switch level {
	case L0:
		return true
	case L1:
		return risk >= RiskHigh
	case L2:
		return risk == RiskCritical
	default:
		// Unknown level: fail safe to the most restrictive sane level.
		return risk == RiskCritical
	}
}

// AnyStepRequiresApproval reports whether any step in the pipeline must be
// approved at the given level (i.e. the whole run should be held).
func AnyStepRequiresApproval(steps []StepInfo, level Autonomy) bool {
	for _, st := range steps {
		if NeedsApproval(StepRisk(st.ID, st.Env), level) {
			return true
		}
	}
	return false
}

// ParseLevel parses "0"/"1"/"2" into an Autonomy level. Empty or invalid
// input yields the v1 default, L2.
func ParseLevel(raw string) Autonomy {
	switch strings.TrimSpace(raw) {
	case "0":
		return L0
	case "1":
		return L1
	case "2":
		return L2
	default:
		return L2
	}
}
