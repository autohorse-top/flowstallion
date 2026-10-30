package policy

import (
	"encoding/json"
	"os"
	"testing"
)

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

func TestStepRisk(t *testing.T) {
	cases := []struct {
		name string
		id   string
		env  map[string]string
		want Risk
	}{
		{"prod deploy is critical", "deploy-prod", map[string]string{"environment": "production"}, RiskCritical},
		{"prod release is critical", "release-prod", map[string]string{"target": "prod"}, RiskCritical},
		{"case-insensitive id+env", "DEPLOY-PROD", map[string]string{"Environment": "PRODUCTION"}, RiskCritical},
		{"staging deploy is low", "deploy-prod", map[string]string{"environment": "staging"}, RiskLow},
		{"deploy without prod env is low", "deploy-app", map[string]string{}, RiskLow},
		{"prod env without deploy id is high", "sync-prod", map[string]string{"environment": "production"}, RiskHigh},
		{"migrate keyword is high", "migrate-db", map[string]string{}, RiskHigh},
		{"drop keyword is high", "drop-tables", map[string]string{}, RiskHigh},
		{"plain build is low", "build", map[string]string{}, RiskLow},
		{"plain test in prod env is high not critical", "test-unit", map[string]string{"environment": "production"}, RiskHigh},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := StepRisk(tc.id, tc.env); got != tc.want {
				t.Errorf("StepRisk(%q, %v) = %v, want %v", tc.id, tc.env, got, tc.want)
			}
		})
	}
}

func TestNeedsApprovalMatrix(t *testing.T) {
	cases := []struct {
		risk    Risk
		level   Autonomy
		approve bool
	}{
		{RiskLow, L0, true},
		{RiskLow, L1, false},
		{RiskLow, L2, false},
		{RiskHigh, L0, true},
		{RiskHigh, L1, true},
		{RiskHigh, L2, false},
		{RiskCritical, L0, true},
		{RiskCritical, L1, true},
		{RiskCritical, L2, true},
		{RiskCritical, Autonomy(9), true}, // unknown level: fail safe to critical-only
	}
	for _, tc := range cases {
		if got := NeedsApproval(tc.risk, tc.level); got != tc.approve {
			t.Errorf("NeedsApproval(%v, %d) = %v, want %v", tc.risk, tc.level, got, tc.approve)
		}
	}
}

func TestAnyStepRequiresApproval(t *testing.T) {
	steps := []StepInfo{
		{ID: "build", Env: map[string]string{}},
		{ID: "test", Env: map[string]string{}},
	}
	if AnyStepRequiresApproval(steps, L2) {
		t.Error("L2: plain steps should not require approval")
	}
	steps = append(steps, StepInfo{ID: "deploy-prod", Env: map[string]string{"environment": "production"}})
	if !AnyStepRequiresApproval(steps, L2) {
		t.Error("L2: prod deploy should require approval")
	}
}

func TestParseLevel(t *testing.T) {
	cases := map[string]Autonomy{
		"0": L0, "1": L1, "2": L2,
		" 1 ": L1, "": L2, "garbage": L2, "3": L2,
	}
	for in, want := range cases {
		if got := ParseLevel(in); got != want {
			t.Errorf("ParseLevel(%q) = %v, want %v", in, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// Shared vectors (also consumed by the Python mirror test)
// ---------------------------------------------------------------------------

type vector struct {
	StepID   string            `json:"step_id"`
	Env      map[string]string `json:"env"`
	Level    int               `json:"level"`
	Approval bool              `json:"approval"`
}

func loadVectors(t *testing.T) []vector {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/policy-vectors.json")
	if err != nil {
		t.Fatalf("read policy vectors: %v", err)
	}
	var out []vector
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("parse policy vectors: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("policy vectors file is empty")
	}
	return out
}

func TestVectors(t *testing.T) {
	for i, v := range loadVectors(t) {
		risk := StepRisk(v.StepID, v.Env)
		got := NeedsApproval(risk, Autonomy(v.Level))
		if got != v.Approval {
			t.Errorf("vector %d: StepRisk(%q,%v)=%v at L%d -> %v, want approval=%v",
				i, v.StepID, v.Env, risk, v.Level, got, v.Approval)
		}
	}
}
