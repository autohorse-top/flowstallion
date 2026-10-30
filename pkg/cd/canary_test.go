package cd

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/flowstallion/flowstallion/pkg/store"
)

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "canary-test.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// fakeKubectl records every invocation and answers from the current step env.
type fakeKubectl struct {
	mu     sync.Mutex
	calls  [][]string
	stdins []string
	step   *tickEnv
}

func (f *fakeKubectl) Run(args []string, stdin string) (string, error) {
	f.mu.Lock()
	f.calls = append(f.calls, append([]string(nil), args...))
	f.stdins = append(f.stdins, stdin)
	env := *f.step
	f.mu.Unlock()
	cmd := strings.Join(args, " ")
	switch {
	case strings.Contains(cmd, "apply -f -"):
		if env.applyErr {
			return "", errors.New("apply boom")
		}
		return "namespace/flowstallion-cd-demo created\ndeployment.apps/demoapp created\n", nil
	case strings.Contains(cmd, "get deploy"):
		if env.deployErr {
			return "", errors.New("get deploy boom")
		}
		return fmt.Sprintf(`{"spec":{"replicas":1},"status":{"replicas":1,"readyReplicas":%d}}`, env.deployReady), nil
	case strings.Contains(cmd, "get --raw"):
		if env.metricsErr {
			return "", errors.New("scrape boom")
		}
		return env.metricsJSON, nil
	case strings.Contains(cmd, "scale"):
		if env.scaleErr {
			return "", errors.New("scale boom")
		}
		return "deployment.apps/demoapp-canary scaled", nil
	case strings.Contains(cmd, "delete"):
		return "deleted", nil
	}
	return "", nil
}

// callContains returns the recorded calls whose arg-join contains sub.
func (f *fakeKubectl) callContains(sub string) [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out [][]string
	for _, c := range f.calls {
		if strings.Contains(strings.Join(c, " "), sub) {
			out = append(out, c)
		}
	}
	return out
}

// applyStdins returns the stdin payloads of all apply invocations.
func (f *fakeKubectl) applyStdins() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for i, c := range f.calls {
		if strings.Contains(strings.Join(c, " "), "apply -f -") {
			out = append(out, f.stdins[i])
		}
	}
	return out
}

// tickEnv is the scripted cluster state for one Advance() call.
type tickEnv struct {
	applyErr    bool
	deployReady int
	deployErr   bool
	metricsJSON string
	metricsErr  bool
	scaleErr    bool
}

func healthyMetrics(req, err int) string {
	return fmt.Sprintf(`{"version":"v2","requests":%d,"errors":%d,"fail_rate":%.3f,"uptime_s":30}`, req, err, float64(err)/float64(req))
}

// scenario drives a release through scripted ticks and asserts the outcome.
type scenario struct {
	name         string
	rel          store.CanaryRelease
	steps        []tickEnv
	wantState    string
	wantSub      string // substring in final reason ("" = don't check)
	wantCalls    []string
	wantNoCalls  []string
	applyTimeout time.Duration
}

func runScenario(t *testing.T, sc scenario) {
	t.Helper()
	st := openTestStore(t)
	id, err := st.CreateCanary(sc.rel)
	if err != nil {
		t.Fatalf("create canary: %v", err)
	}
	fk := &fakeKubectl{}
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	ctl := &Controller{
		Store:   st,
		Kubectl: fk,
		Now:     func() time.Time { return now },
	}
	if sc.applyTimeout > 0 {
		ctl.ApplyTimeout = sc.applyTimeout
	}
	_ = id
	for i, env := range sc.steps {
		fk.step = &env
		now = now.Add(2 * time.Second) // one sim tick per Advance call
		if err := ctl.Advance(id); err != nil {
			t.Fatalf("step %d: Advance: %v", i, err)
		}
	}
	r, err := st.GetCanary(id)
	if err != nil {
		t.Fatalf("get canary: %v", err)
	}
	if r.State != sc.wantState {
		t.Fatalf("final state = %q, want %q (reason=%q)", r.State, sc.wantState, r.Reason)
	}
	if sc.wantSub != "" && !strings.Contains(r.Reason, sc.wantSub) {
		t.Fatalf("reason %q does not contain %q", r.Reason, sc.wantSub)
	}
	for _, sub := range sc.wantCalls {
		if len(fk.callContains(sub)) == 0 {
			t.Errorf("expected a kubectl call containing %q; calls: %v", sub, fk.calls)
		}
	}
	for _, sub := range sc.wantNoCalls {
		if got := fk.callContains(sub); len(got) > 0 {
			t.Errorf("did not expect kubectl call containing %q; got %v", sub, got)
		}
	}
}

var defaultRel = store.CanaryRelease{
	Name: "demoapp", Namespace: "flowstallion-cd-demo",
	StableImage: "flowstallion/demoapp:v1", CanaryImage: "flowstallion/demoapp:v2",
	Replicas: 2, Port: 8080,
	Threshold: 0.3, MinSamples: 5, WarmupS: 4, ObserveS: 8,
}

func TestCanaryStateMachine(t *testing.T) {
	tests := []scenario{
		{
			name:      "error rate above threshold rolls back",
			rel:       defaultRel,
			wantState: store.CanaryRolledBack,
			wantSub:   "error rate 0.875",
			steps: []tickEnv{
				{},               // 1: apply
				{deployReady: 0}, // 2: not ready yet
				{deployReady: 1}, // 3: ready (start)
				{},               // 4: observing
				{deployReady: 1, metricsJSON: healthyMetrics(5, 4)},   // 5: baseline (5,4)
				{deployReady: 1, metricsJSON: healthyMetrics(9, 7)},   // 6: delta (4,3) 0.75 but window < min_samples
				{deployReady: 1, metricsJSON: healthyMetrics(13, 11)}, // 7: delta (8,7) 0.875 -> rollback
			},
			wantCalls:   []string{"delete deploy demoapp-canary", "delete svc demoapp-canary"},
			wantNoCalls: []string{"delete deploy demoapp ", "scale"},
		},
		{
			name:      "healthy full window promotes",
			rel:       defaultRel,
			wantState: store.CanaryPromoted,
			wantSub:   "promoted",
			steps: []tickEnv{
				{},               // 1: t=2, apply
				{deployReady: 0}, // 2: t=4
				{deployReady: 1}, // 3: t=6, canary_ready (start=6)
				{},               // 4: t=8, observing
				{deployReady: 1, metricsJSON: healthyMetrics(5, 0)},  // 5: t=10, baseline (5,0)
				{deployReady: 1, metricsJSON: healthyMetrics(10, 1)}, // 6: t=12, delta (5,1)
				{deployReady: 1, metricsJSON: healthyMetrics(10, 1)}, // 7: t=14, delta (5,1)
				{deployReady: 1, metricsJSON: healthyMetrics(12, 2)}, // 8: t=16, delta (7,2)
				{deployReady: 1, metricsJSON: healthyMetrics(12, 2)}, // 9: t=18, age 12 -> promoting
				{}, // 10: t=20, scale+delete -> promoted
			},
			wantCalls: []string{"-n flowstallion-cd-demo scale deploy/demoapp-canary --replicas=2",
				"-n flowstallion-cd-demo delete deploy demoapp"},
		},
		{
			name:        "apply failure fails the release",
			rel:         defaultRel,
			wantState:   store.CanaryFailed,
			wantSub:     "apply failed",
			steps:       []tickEnv{{applyErr: true}, {applyErr: true}, {applyErr: true}},
			wantNoCalls: []string{"get deploy", "delete"},
		},
		{
			name: "three consecutive scrape failures roll back",
			rel: store.CanaryRelease{
				Name: "demoapp", Namespace: "flowstallion-cd-demo",
				StableImage: "flowstallion/demoapp:v1", CanaryImage: "flowstallion/demoapp:v2",
				Replicas: 2, Port: 8080,
				Threshold: 0.3, MinSamples: 5, WarmupS: 0, ObserveS: 8,
			},
			wantState: store.CanaryRolledBack,
			wantSub:   "metrics scrape failed 3 consecutive times",
			steps: []tickEnv{
				{},
				{deployReady: 1},
				{},
				{deployReady: 1, metricsErr: true},
				{deployReady: 1, metricsErr: true},
				{deployReady: 1, metricsErr: true},
			},
			wantCalls: []string{"delete deploy demoapp-canary"},
		},
		{
			name: "cluster status response counts as probe failure",
			rel: store.CanaryRelease{
				Name: "demoapp", Namespace: "flowstallion-cd-demo",
				StableImage: "flowstallion/demoapp:v1", CanaryImage: "flowstallion/demoapp:v2",
				Replicas: 2, Port: 8080,
				Threshold: 0.3, MinSamples: 5, WarmupS: 0, ObserveS: 8,
			},
			wantState: store.CanaryRolledBack,
			wantSub:   "metrics scrape failed",
			steps: []tickEnv{
				{},
				{deployReady: 1},
				{},
				{deployReady: 1, metricsJSON: `{"kind":"Status","apiVersion":"v1"}`},
				{deployReady: 1, metricsJSON: `{"kind":"Status","apiVersion":"v1"}`},
				{deployReady: 1, metricsJSON: `{"kind":"Status","apiVersion":"v1"}`},
			},
			wantCalls: []string{"delete deploy demoapp-canary"},
		},
		{
			// F-2: a readiness dip after warmup no longer kills the release
			// on the first tick; it takes maxProbeFailures consecutive
			// not-ready ticks.
			name: "canary not ready for 3 consecutive ticks after warmup rolls back",
			rel: store.CanaryRelease{
				Name: "demoapp", Namespace: "flowstallion-cd-demo",
				StableImage: "flowstallion/demoapp:v1", CanaryImage: "flowstallion/demoapp:v2",
				Replicas: 2, Port: 8080,
				Threshold: 0.3, MinSamples: 5, WarmupS: 2, ObserveS: 8,
			},
			wantState: store.CanaryRolledBack,
			wantSub:   "canary not ready",
			steps: []tickEnv{
				{},
				{deployReady: 1},
				{},
				{deployReady: 0}, // strike 1
				{deployReady: 0}, // strike 2
				{deployReady: 0}, // strike 3 -> rollback
			},
			wantCalls: []string{"delete deploy demoapp-canary"},
		},
		{
			// F-2 discriminating case: two not-ready strikes, then recovery
			// (successful scrape resets the counter), then one more dip —
			// must survive as observing. The old code (instant rollback on
			// the first not-ready tick) would have ended rolled_back.
			name: "readiness dip with recovery does not roll back",
			rel: store.CanaryRelease{
				Name: "demoapp", Namespace: "flowstallion-cd-demo",
				StableImage: "flowstallion/demoapp:v1", CanaryImage: "flowstallion/demoapp:v2",
				Replicas: 2, Port: 8080,
				Threshold: 0.3, MinSamples: 5, WarmupS: 2, ObserveS: 8,
			},
			wantState: store.CanaryObserving,
			steps: []tickEnv{
				{},
				{deployReady: 1},
				{},
				{deployReady: 0}, // strike 1
				{deployReady: 0}, // strike 2
				{deployReady: 1, metricsJSON: healthyMetrics(5, 0)}, // recovered: counter reset
				{deployReady: 0}, // new streak: strike 1
			},
			wantNoCalls: []string{"delete deploy demoapp-canary"},
		},
		{
			// B-1: a canary that never becomes ready (crash-looping image)
			// must roll back at the applying timeout instead of pinning the
			// (name, namespace) slot forever.
			name:         "applying timeout rolls back",
			rel:          defaultRel,
			wantState:    store.CanaryRolledBack,
			wantSub:      "not ready within",
			applyTimeout: 10 * time.Second,
			steps: []tickEnv{
				{},               // t=2: apply -> applying (applying_since=2s)
				{deployReady: 0}, // t=4
				{deployReady: 0}, // t=6
				{deployReady: 0}, // t=8
				{deployReady: 0}, // t=10
				{deployReady: 0}, // t=12: elapsed 10s, not yet > 10s
				{deployReady: 0}, // t=14: elapsed 12s > 10s -> rollback
			},
			wantCalls:   []string{"delete deploy demoapp-canary"},
			wantNoCalls: []string{"get --raw", "scale"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runScenario(t, tt)
		})
	}
}

func TestPromoteServiceSelectorSwitch(t *testing.T) {
	st := openTestStore(t)
	id, _ := st.CreateCanary(defaultRel)
	fk := &fakeKubectl{}
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	ctl := &Controller{
		Store:   st,
		Kubectl: fk,
		Now:     func() time.Time { return now },
	}
	// Tick = 2s. Ready at t=4 (start=4); window 4+8=12s -> promote starts
	// at t=16 (state promoting), completes (scale + delete) at t=18.
	for _, env := range []tickEnv{
		{},
		{deployReady: 1},
		{},
		{deployReady: 1, metricsJSON: healthyMetrics(5, 0)},
		{deployReady: 1, metricsJSON: healthyMetrics(5, 0)},
		{deployReady: 1, metricsJSON: healthyMetrics(6, 0)},
		{deployReady: 1, metricsJSON: healthyMetrics(8, 1)},
		{deployReady: 1, metricsJSON: healthyMetrics(8, 1)},
		{},
	} {
		fk.step = &env
		now = now.Add(2 * time.Second)
		if err := ctl.Advance(id); err != nil {
			t.Fatalf("Advance: %v", err)
		}
	}
	r, _ := st.GetCanary(id)
	if r.State != store.CanaryPromoted {
		t.Fatalf("final state = %q, want promoted (reason=%q)", r.State, r.Reason)
	}
	// Two applies: initial manifests (with Namespace) and the promote
	// service (selector switch, no Namespace, canary release only).
	stdins := fk.applyStdins()
	if len(stdins) != 2 {
		t.Fatalf("expected 2 apply calls, got %d", len(stdins))
	}
	if !strings.Contains(stdins[0], "kind: Namespace") {
		t.Errorf("first apply should create the namespace:\n%s", stdins[0])
	}
	if strings.Contains(stdins[1], "kind: Namespace") {
		t.Errorf("promote apply must not recreate objects:\n%s", stdins[1])
	}
	if !strings.Contains(stdins[1], "kind: Service") || !strings.Contains(stdins[1], "release: canary") {
		t.Errorf("promote apply must switch the stable service to canary:\n%s", stdins[1])
	}
}

func TestTerminalStateIsStable(t *testing.T) {
	st := openTestStore(t)
	id, _ := st.CreateCanary(defaultRel)
	if err := st.SetCanaryState(id, store.CanaryPromoted, "ok", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatalf("set state: %v", err)
	}
	fk := &fakeKubectl{}
	ctl := &Controller{Store: st, Kubectl: fk, Now: time.Now}
	if err := ctl.Advance(id); err != nil {
		t.Fatalf("Advance: %v", err)
	}
	fk.mu.Lock()
	n := len(fk.calls)
	fk.mu.Unlock()
	if n != 0 {
		t.Fatalf("terminal release must not issue kubectl calls, got %d", n)
	}
	r, _ := st.GetCanary(id)
	if r.State != store.CanaryPromoted {
		t.Fatalf("state changed: %q", r.State)
	}
}

func TestTickAllAdvancesAllActive(t *testing.T) {
	st := openTestStore(t)
	a, _ := st.CreateCanary(defaultRel)
	other := defaultRel
	other.Name = "demoapp-two" // same (name, namespace) while both are active violates the partial unique index
	b, _ := st.CreateCanary(other)
	if err := st.SetCanaryState(b, store.CanaryPromoted, "ok", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatalf("set b promoted: %v", err)
	}
	fk := &fakeKubectl{}
	fk.step = &tickEnv{}
	ctl := &Controller{Store: st, Kubectl: fk, Now: time.Now}
	ctl.TickAll()
	ra, _ := st.GetCanary(a)
	rb, _ := st.GetCanary(b)
	if ra.State != store.CanaryApplying {
		t.Fatalf("active release not advanced: %q", ra.State)
	}
	if rb.State != store.CanaryPromoted {
		t.Fatalf("terminal release must stay put: %q", rb.State)
	}
}

// TestPromoteReplaysAfterPartialFailure is the m-5 regression: a release
// that reached "promoting" (service switched) but crashed before
// scale/delete completes must be replayed to promoted on the next tick,
// not stranded or failed.
func TestPromoteReplaysAfterPartialFailure(t *testing.T) {
	st := openTestStore(t)
	id, _ := st.CreateCanary(defaultRel)
	if err := st.SetCanaryState(id, store.CanaryPromoting, "", ""); err != nil {
		t.Fatalf("set promoting: %v", err)
	}
	fk := &fakeKubectl{}
	fk.step = &tickEnv{}
	ctl := &Controller{Store: st, Kubectl: fk, Now: time.Now}
	if err := ctl.Advance(id); err != nil {
		t.Fatalf("advance promoting: %v", err)
	}
	r, _ := st.GetCanary(id)
	if r.State != store.CanaryPromoted {
		t.Fatalf("state = %q, want promoted (reason=%q)", r.State, r.Reason)
	}
	if got := len(fk.callContains("-n flowstallion-cd-demo scale deploy/demoapp-canary")); got != 1 {
		t.Errorf("expected exactly one scale call, got %d; calls: %v", got, fk.calls)
	}
	if got := len(fk.callContains("-n flowstallion-cd-demo delete deploy demoapp")); got != 1 {
		t.Errorf("expected exactly one stable-delete call, got %d; calls: %v", got, fk.calls)
	}
}

// TestPromoteFailureRestoresStableService is the F-1 regression: after the
// selector has been switched (state=promoting), a terminally failing
// scale-up must restore the stable Service selector before the release is
// marked failed, so traffic can reach the stable Deployment again.
func TestPromoteFailureRestoresStableService(t *testing.T) {
	st := openTestStore(t)
	id, _ := st.CreateCanary(defaultRel)
	fk := &fakeKubectl{}
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	ctl := &Controller{
		Store:   st,
		Kubectl: fk,
		Now:     func() time.Time { return now },
	}
	for _, env := range []tickEnv{
		{},               // t=2: apply
		{deployReady: 1}, // t=4: canary_ready (start=4)
		{},               // t=6: observing
		{deployReady: 1, metricsJSON: healthyMetrics(5, 0)}, // t=8: baseline (5,0)
		{deployReady: 1, metricsJSON: healthyMetrics(5, 0)}, // t=10: window 0
		{deployReady: 1, metricsJSON: healthyMetrics(6, 0)}, // t=12: window (1,0)
		{deployReady: 1, metricsJSON: healthyMetrics(8, 1)}, // t=14: window (3,1)
		{deployReady: 1, metricsJSON: healthyMetrics(8, 1)}, // t=16: age 12 -> promoting
		{scaleErr: true}, // t=18: strike 1
		{scaleErr: true}, // t=20: strike 2
		{scaleErr: true}, // t=22: strike 3 -> restore + fail
	} {
		fk.step = &env
		now = now.Add(2 * time.Second)
		if err := ctl.Advance(id); err != nil {
			t.Fatalf("Advance: %v", err)
		}
	}
	r, _ := st.GetCanary(id)
	if r.State != store.CanaryFailed {
		t.Fatalf("final state = %q, want failed (reason=%q)", r.State, r.Reason)
	}
	if !strings.Contains(r.Reason, "scale canary failed 3 consecutive times") {
		t.Fatalf("reason = %q", r.Reason)
	}
	stdins := fk.applyStdins()
	// apply #1: initial manifests; apply #2: promote service (release: canary);
	// apply #3: F-1 restore (release: stable, no Namespace).
	if len(stdins) != 3 {
		t.Fatalf("expected 3 apply calls, got %d", len(stdins))
	}
	if !strings.Contains(stdins[1], "release: canary") {
		t.Errorf("second apply should switch the selector to canary:\n%s", stdins[1])
	}
	if !strings.Contains(stdins[2], "kind: Service") || !strings.Contains(stdins[2], "release: stable") {
		t.Errorf("third apply must restore the stable selector:\n%s", stdins[2])
	}
	if strings.Contains(stdins[2], "kind: Namespace") {
		t.Errorf("restore apply must not recreate objects:\n%s", stdins[2])
	}
}

// TestCounterResetReanchorsBaseline covers the m-3 reset path: when the
// canary pod restarts and its cumulative counters drop below the baseline,
// the baseline is re-anchored (instead of producing a negative window) and
// the threshold then applies to the new window.
func TestCounterResetReanchorsBaseline(t *testing.T) {
	st := openTestStore(t)
	id, _ := st.CreateCanary(defaultRel)
	fk := &fakeKubectl{}
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	ctl := &Controller{
		Store:   st,
		Kubectl: fk,
		Now:     func() time.Time { return now },
	}
	for _, env := range []tickEnv{
		{},
		{deployReady: 1},
		{},
		{deployReady: 1, metricsJSON: healthyMetrics(10, 0)},  // baseline (10,0)
		{deployReady: 1, metricsJSON: healthyMetrics(3, 2)},   // counters reset -> re-anchor (3,2)
		{deployReady: 1, metricsJSON: healthyMetrics(10, 10)}, // window (7,8): rate 1.143 -> rollback
	} {
		fk.step = &env
		now = now.Add(2 * time.Second)
		if err := ctl.Advance(id); err != nil {
			t.Fatalf("Advance: %v", err)
		}
	}
	r, _ := st.GetCanary(id)
	if r.State != store.CanaryRolledBack {
		t.Fatalf("final state = %q, want rolled_back (reason=%q)", r.State, r.Reason)
	}
	if !strings.Contains(r.Reason, "error rate 1.143") {
		t.Fatalf("reason = %q", r.Reason)
	}
}

// ---------------------------------------------------------------------------
// P7⑤ additions: StableDeployment, ContextKubectl, Controller.Rollback
// ---------------------------------------------------------------------------

// cannedKubectl answers "get deploy <name> -o json" with a fixed body and
// records invocations (StableDeployment / ContextKubectl tests).
type cannedKubectl struct {
	mu    sync.Mutex
	body  string
	err   error
	calls [][]string
}

func (c *cannedKubectl) Run(args []string, _ string) (string, error) {
	c.mu.Lock()
	c.calls = append(c.calls, append([]string(nil), args...))
	c.mu.Unlock()
	if c.err != nil {
		return "", c.err
	}
	return c.body, nil
}

func TestStableDeployment(t *testing.T) {
	stableJSON := `{"spec":{"replicas":3,"template":{"spec":{"containers":[{"image":"registry/demoapp:1.0"},{"image":"sidecar:1"}]}}}}`
	c := &cannedKubectl{body: stableJSON}
	img, repl, err := StableDeployment(c, "default", "demoapp")
	if err != nil {
		t.Fatalf("StableDeployment: %v", err)
	}
	if img != "registry/demoapp:1.0" {
		t.Errorf("image = %q, want registry/demoapp:1.0 (first container)", img)
	}
	if repl != 3 {
		t.Errorf("replicas = %d, want 3", repl)
	}
	joined := strings.Join(c.calls[0], " ")
	if !strings.Contains(joined, "get deploy demoapp") || !strings.Contains(joined, "-o json") {
		t.Errorf("unexpected kubectl args: %v", joined)
	}

	if _, _, err := StableDeployment(&cannedKubectl{err: errors.New("NotFound")}, "default", "demoapp"); err == nil {
		t.Error("want error when kubectl fails")
	}
	if _, _, err := StableDeployment(&cannedKubectl{body: `{}`}, "default", "demoapp"); err == nil {
		t.Error("want error for a deployment with no containers")
	}
	if _, _, err := StableDeployment(&cannedKubectl{body: `not json`}, "default", "demoapp"); err == nil {
		t.Error("want error for unparseable deployment JSON")
	}
}

func TestContextKubectl(t *testing.T) {
	rec := &cannedKubectl{}
	wrapped := ContextKubectl{Inner: rec, Context: "prod"}
	if _, err := wrapped.Run([]string{"-n", "default", "get", "deploy", "demoapp", "-o", "json"}, ""); err != nil {
		t.Fatalf("wrapped run: %v", err)
	}
	joined := strings.Join(rec.calls[0], " ")
	if !strings.HasPrefix(joined, "--context prod ") {
		t.Errorf("args = %q, want --context prod prefix", joined)
	}

	empty := ContextKubectl{Inner: rec, Context: ""}
	if _, err := empty.Run([]string{"get", "pods"}, ""); err != nil {
		t.Fatalf("passthrough run: %v", err)
	}
	if strings.Join(rec.calls[1], " ") != "get pods" {
		t.Errorf("empty context must pass through unchanged, got %q", strings.Join(rec.calls[1], " "))
	}
}

func TestControllerRollback(t *testing.T) {
	st := openTestStore(t)
	fk := &fakeKubectl{step: &tickEnv{}}
	ctl := &Controller{Store: st, Kubectl: fk, Now: time.Now}

	// Non-terminal release: forced rollback lands in rolled_back and the
	// canary resources are deleted.
	id, err := st.CreateCanary(defaultRel)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := ctl.Rollback(id, "forced by scheduler"); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	r, _ := st.GetCanary(id)
	if r.State != store.CanaryRolledBack {
		t.Fatalf("state = %q, want rolled_back", r.State)
	}
	if !strings.Contains(r.Reason, "forced by scheduler") {
		t.Errorf("reason = %q", r.Reason)
	}
	if len(fk.callContains("delete deploy demoapp-canary")) == 0 || len(fk.callContains("delete svc demoapp-canary")) == 0 {
		t.Errorf("rollback must delete canary deployment and service; calls: %v", fk.calls)
	}

	// Terminal release: Rollback is a no-op.
	id2, _ := st.CreateCanary(defaultRel)
	if err := ctl.Advance(id2); err != nil { // pending -> applying
		t.Fatalf("advance: %v", err)
	}
	if err := st.SetCanaryState(id2, store.CanaryPromoted, "done", ""); err != nil {
		t.Fatalf("set promoted: %v", err)
	}
	if err := ctl.Rollback(id2, "should be ignored"); err != nil {
		t.Fatalf("Rollback on terminal: %v", err)
	}
	r2, _ := st.GetCanary(id2)
	if r2.State != store.CanaryPromoted {
		t.Errorf("terminal release state changed to %q", r2.State)
	}

	// Unknown id: error.
	if err := ctl.Rollback(99999, "x"); err == nil {
		t.Error("want error for unknown release id")
	}
}

// TestRollbackDuringPromotingRestoresStableService is the regression for the
// manual-rollback gap: once beginPromote has switched the stable Service
// selector to the canary pods (state=promoting), a forced Rollback must
// restore the stable selector BEFORE deleting the canary objects — otherwise
// the stable Service would dangle over deleted canary pods (502s) even
// though the stable Deployment still exists.
func TestRollbackDuringPromotingRestoresStableService(t *testing.T) {
	st := openTestStore(t)
	id, _ := st.CreateCanary(defaultRel)
	if err := st.SetCanaryState(id, store.CanaryPromoting, "", ""); err != nil {
		t.Fatalf("set promoting: %v", err)
	}
	fk := &fakeKubectl{step: &tickEnv{}}
	ctl := &Controller{Store: st, Kubectl: fk, Now: time.Now}
	if err := ctl.Rollback(id, "manual rollback during promote"); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	r, _ := st.GetCanary(id)
	if r.State != store.CanaryRolledBack {
		t.Fatalf("state = %q, want rolled_back (reason=%q)", r.State, r.Reason)
	}
	if !strings.Contains(r.Reason, "manual rollback during promote") {
		t.Errorf("reason = %q", r.Reason)
	}
	// Exactly three kubectl calls, in order: (1) restore stable Service
	// selector, (2) delete canary Deployment, (3) delete canary Service.
	if len(fk.calls) != 3 {
		t.Fatalf("expected 3 kubectl calls (restore, del deploy, del svc), got %d: %v", len(fk.calls), fk.calls)
	}
	joined := func(i int) string { return strings.Join(fk.calls[i], " ") }
	if !strings.Contains(joined(0), "apply -f -") {
		t.Errorf("first call must be the stable-Service restore apply, got: %v", fk.calls[0])
	}
	if !strings.Contains(joined(1), "delete deploy demoapp-canary") {
		t.Errorf("second call must delete the canary deployment, got: %v", fk.calls[1])
	}
	if !strings.Contains(joined(2), "delete svc demoapp-canary") {
		t.Errorf("third call must delete the canary service, got: %v", fk.calls[2])
	}
	stdins := fk.applyStdins()
	if len(stdins) != 1 {
		t.Fatalf("expected exactly 1 apply call, got %d", len(stdins))
	}
	if !strings.Contains(stdins[0], "kind: Service") || !strings.Contains(stdins[0], "release: stable") {
		t.Errorf("restore apply must point the stable Service back at the stable selector:\n%s", stdins[0])
	}
	if strings.Contains(stdins[0], "kind: Namespace") {
		t.Errorf("restore apply must not recreate the namespace:\n%s", stdins[0])
	}
}

// Rollback from non-promoting states must NOT re-apply the stable Service
// (the selector was never switched there; re-applying is harmless but must
// not happen — it would mask a missing stable Service in broken clusters).
func TestRollbackOutsidePromotingSkipsRestore(t *testing.T) {
	st := openTestStore(t)
	id, _ := st.CreateCanary(defaultRel)
	fk := &fakeKubectl{step: &tickEnv{}}
	ctl := &Controller{Store: st, Kubectl: fk, Now: time.Now}
	if err := ctl.Rollback(id, "manual"); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	for _, c := range fk.calls {
		if strings.Contains(strings.Join(c, " "), "apply -f -") {
			t.Fatalf("rollback from pending must not apply any manifest; calls: %v", fk.calls)
		}
	}
}

// fnKubectl adapts a closure to the Kubectl interface.
type fnKubectl struct {
	run func(args []string, stdin string) (string, error)
}

func (f fnKubectl) Run(args []string, stdin string) (string, error) {
	return f.run(args, stdin)
}

// TestConcurrentDriversSerialize (K1) reproduces the production race at the
// controller layer: two separate Controller instances — like the API's
// rollback controller and the scheduler's TickAll controller — drive the
// SAME release concurrently. Driver A advances toward a terminal state;
// driver B hammers Rollback. The per-release lock must serialize every
// kubectl call for that release (no two invocations in flight at once), and
// the store must end in exactly one terminal state.
func TestConcurrentDriversSerialize(t *testing.T) {
	st := openTestStore(t)
	id, err := st.CreateCanary(defaultRel)
	if err != nil {
		t.Fatalf("create canary: %v", err)
	}

	// Gated kubectl: any overlap of two in-flight invocations is recorded as
	// a serialization violation.
	var (
		gateMu   sync.Mutex
		inFlight int
		overlap  int
	)
	run := func(args []string, stdin string) (string, error) {
		gateMu.Lock()
		if inFlight > 0 {
			overlap++
		}
		inFlight++
		gateMu.Unlock()
		time.Sleep(2 * time.Millisecond) // widen the overlap window
		gateMu.Lock()
		inFlight--
		gateMu.Unlock()
		switch {
		case strings.Contains(strings.Join(args, " "), "get deploy"):
			return `{"spec":{"replicas":1},"status":{"replicas":1,"readyReplicas":1}}`, nil
		case strings.Contains(strings.Join(args, " "), "get --raw"):
			return healthyMetrics(100, 0), nil
		}
		return "ok", nil
	}

	// Shared fake clock: +2s per call, so the warmup+observe window (12s)
	// elapses within a handful of steps.
	var nowMu sync.Mutex
	nowT := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	nowFn := func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		nowT = nowT.Add(2 * time.Second)
		return nowT
	}

	ctlA := &Controller{Store: st, Kubectl: fnKubectl{run: run}, Now: nowFn}
	ctlB := &Controller{Store: st, Kubectl: fnKubectl{run: run}, Now: nowFn}

	var (
		wg     sync.WaitGroup
		errMu  sync.Mutex
		badErr int
	)
	report := func(err error) {
		if err == nil || errors.Is(err, store.ErrCanaryStateConflict) {
			return
		}
		errMu.Lock()
		badErr++
		errMu.Unlock()
		t.Errorf("unexpected driver error: %v", err)
	}

	// Driver A: advance until terminal.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			report(ctlA.Advance(id))
			r, _ := st.GetCanary(id)
			if store.CanaryTerminal(r.State) {
				return
			}
		}
	}()
	// Driver B: hammer Rollback until terminal.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			report(ctlB.Rollback(id, "manual"))
			r, _ := st.GetCanary(id)
			if store.CanaryTerminal(r.State) {
				return
			}
		}
	}()
	wg.Wait()

	if overlap > 0 {
		t.Errorf("kubectl invocations overlapped %d time(s): per-release lock failed to serialize drivers", overlap)
	}
	if badErr > 0 {
		t.Errorf("%d unexpected driver error(s)", badErr)
	}
	r, err := st.GetCanary(id)
	if err != nil {
		t.Fatalf("get canary: %v", err)
	}
	if !store.CanaryTerminal(r.State) {
		t.Errorf("final state = %q (reason %q), want a terminal state", r.State, r.Reason)
	}
}
