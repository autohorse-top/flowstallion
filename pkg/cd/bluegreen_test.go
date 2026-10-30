package cd

import (
	"strings"
	"testing"
	"time"

	"github.com/flowstallion/flowstallion/pkg/store"
)

// bgRel is a blue-green release: same shape as defaultRel but with
// Strategy=blue_green, so the alternate objects are named "<name>-alt" and
// run at the full replica count.
var bgRel = store.CanaryRelease{
	Name: "demoapp", Namespace: "flowstallion-cd-demo",
	StableImage: "flowstallion/demoapp:v1", CanaryImage: "flowstallion/demoapp:v2",
	Replicas: 2, Port: 8080,
	Threshold: 0.3, MinSamples: 5, WarmupS: 4, ObserveS: 8,
	Strategy: "blue_green",
}

// TestBlueGreenHappyPromote drives a healthy blue-green release to promoted
// and asserts the alternate is scaled (not the canary) and the stable
// deployment is deleted.
func TestBlueGreenHappyPromote(t *testing.T) {
	sc := scenario{
		name:      "blue-green healthy full window promotes",
		rel:       bgRel,
		wantState: store.CanaryPromoted,
		wantSub:   "promoted",
		steps: []tickEnv{
			{},               // 1: apply
			{deployReady: 0}, // 2: not ready yet
			{deployReady: 1}, // 3: ready (start)
			{},               // 4: observing
			{deployReady: 1, metricsJSON: healthyMetrics(5, 0)},
			{deployReady: 1, metricsJSON: healthyMetrics(10, 1)},
			{deployReady: 1, metricsJSON: healthyMetrics(10, 1)},
			{deployReady: 1, metricsJSON: healthyMetrics(12, 2)},
			{deployReady: 1, metricsJSON: healthyMetrics(12, 2)}, // 9: age 12 -> promoting
			{}, // 10: scale+delete -> promoted
		},
		wantCalls: []string{
			"-n flowstallion-cd-demo scale deploy/demoapp-alt --replicas=2",
			"-n flowstallion-cd-demo delete deploy demoapp",
		},
	}
	runScenario(t, sc)
}

// TestBlueGreenErrorRateRollback verifies a high error rate rolls back a
// blue-green release by deleting the alternate deployment+service while
// leaving the stable deployment untouched.
func TestBlueGreenErrorRateRollback(t *testing.T) {
	sc := scenario{
		name:      "blue-green error rate above threshold rolls back",
		rel:       bgRel,
		wantState: store.CanaryRolledBack,
		wantSub:   "error rate 0.875",
		steps: []tickEnv{
			{},
			{deployReady: 0},
			{deployReady: 1},
			{},
			{deployReady: 1, metricsJSON: healthyMetrics(5, 4)},
			{deployReady: 1, metricsJSON: healthyMetrics(9, 7)},
			{deployReady: 1, metricsJSON: healthyMetrics(13, 11)},
		},
		wantCalls:   []string{"delete deploy demoapp-alt", "delete svc demoapp-alt"},
		wantNoCalls: []string{"delete deploy demoapp "},
	}
	runScenario(t, sc)
}

// TestBlueGreenApplyingTimeoutRollback verifies a blue-green release whose
// alternate never becomes ready is rolled back at the applying timeout and
// the alternate deployment (not the stable one) is deleted.
func TestBlueGreenApplyingTimeoutRollback(t *testing.T) {
	sc := scenario{
		name:         "blue-green applying timeout rolls back",
		rel:          bgRel,
		wantState:    store.CanaryRolledBack,
		wantSub:      "not ready within",
		applyTimeout: 10 * time.Second,
		steps: []tickEnv{
			{},
			{deployReady: 0},
			{deployReady: 0},
			{deployReady: 0},
			{deployReady: 0},
			{deployReady: 0},
			{deployReady: 0},
		},
		wantCalls:   []string{"delete deploy demoapp-alt"},
		wantNoCalls: []string{"get --raw", "scale"},
	}
	runScenario(t, sc)
}

// TestBlueGreenApplyManifest pins the apply payload for a blue-green release:
// the alternate deployment is named "<name>-alt", carries release=blue_green
// and runs at the full replica count (unlike the canary strategy's 1 replica).
func TestBlueGreenApplyManifest(t *testing.T) {
	st := openTestStore(t)
	id, err := st.CreateCanary(bgRel)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	fk := &fakeKubectl{step: &tickEnv{}}
	ctl := &Controller{Store: st, Kubectl: fk, Now: time.Now}
	if err := ctl.Advance(id); err != nil {
		t.Fatalf("advance: %v", err)
	}
	stdins := fk.applyStdins()
	if len(stdins) != 1 {
		t.Fatalf("expected 1 apply, got %d", len(stdins))
	}
	man := stdins[0]
	if !strings.Contains(man, "name: demoapp-alt") {
		t.Errorf("alt deployment name not present:\n%s", man)
	}
	if !strings.Contains(man, "release: blue_green") {
		t.Errorf("alt release label not present:\n%s", man)
	}
	// Alternate deployment (5th doc) must run at full replicas (2), not 1.
	docs := strings.Split(man, "\n---\n")
	if len(docs) != 5 {
		t.Fatalf("expected 5 docs, got %d", len(docs))
	}
	altDep := unmarshalDoc(t, "alt deployment", docs[3])
	if got := deployReplicas(t, altDep); got != 2 {
		t.Errorf("alt replicas = %d, want 2 (full size for blue-green)", got)
	}
}

// TestBlueGreenPromotingRollbackRestore verifies that a forced rollback from
// the promoting state first restores the stable Service selector, then deletes
// the blue-green alternate deployment and service.
func TestBlueGreenPromotingRollbackRestore(t *testing.T) {
	st := openTestStore(t)
	id, _ := st.CreateCanary(bgRel)
	if err := st.SetCanaryState(id, store.CanaryPromoting, "", ""); err != nil {
		t.Fatalf("set promoting: %v", err)
	}
	fk := &fakeKubectl{step: &tickEnv{}}
	ctl := &Controller{Store: st, Kubectl: fk, Now: time.Now}
	if err := ctl.Rollback(id, "manual bg rollback"); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	r, _ := st.GetCanary(id)
	if r.State != store.CanaryRolledBack {
		t.Fatalf("state = %q, want rolled_back (reason=%q)", r.State, r.Reason)
	}
	if len(fk.calls) != 3 {
		t.Fatalf("expected 3 kubectl calls (restore, del deploy, del svc), got %d: %v", len(fk.calls), fk.calls)
	}
	joined := func(i int) string { return strings.Join(fk.calls[i], " ") }
	if !strings.Contains(joined(0), "apply -f -") {
		t.Errorf("first call must be the stable-Service restore apply, got: %v", fk.calls[0])
	}
	if !strings.Contains(joined(1), "delete deploy demoapp-alt") {
		t.Errorf("second call must delete the alt deployment, got: %v", fk.calls[1])
	}
	if !strings.Contains(joined(2), "delete svc demoapp-alt") {
		t.Errorf("third call must delete the alt service, got: %v", fk.calls[2])
	}
	stdins := fk.applyStdins()
	if len(stdins) != 1 {
		t.Fatalf("expected exactly 1 apply call, got %d", len(stdins))
	}
	if !strings.Contains(stdins[0], "kind: Service") || !strings.Contains(stdins[0], "release: stable") {
		t.Errorf("restore apply must point the stable Service back at the stable selector:\n%s", stdins[0])
	}
}
