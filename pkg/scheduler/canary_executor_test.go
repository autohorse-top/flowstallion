package scheduler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/flowstallion/flowstallion/pkg/pipeline"
	"github.com/flowstallion/flowstallion/pkg/store"
)

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

// fakeK8s is a scripted cd.Kubectl for the canary executor tests.
//
// Cluster shape it simulates: a stable Deployment "demoapp" in namespace
// "default" (image/replicas configurable, or a NotFound error), a canary
// Deployment "demoapp-canary" whose ready replica count is scripted, and a
// /metrics scrape that either fails or returns increasing request counters.
type fakeK8s struct {
	mu          sync.Mutex
	calls       [][]string
	stableImage string
	stableRepl  int
	stableErr   error
	canaryReady int
	metricsErr  error
	metricsStep int64 // requests added per successful scrape
	metricsReq  int64
	metricsBase int64
}

func newFakeK8s() *fakeK8s {
	return &fakeK8s{stableImage: "registry/demoapp:1.0", stableRepl: 3, canaryReady: 2, metricsStep: 50}
}

func (f *fakeK8s) Run(args []string, stdin string) (string, error) {
	f.mu.Lock()
	f.calls = append(f.calls, append([]string(nil), args...))
	f.mu.Unlock()
	cmd := strings.Join(args, " ")
	switch {
	case strings.Contains(cmd, "get deploy demoapp-canary"):
		return fmt.Sprintf(`{"spec":{"replicas":2},"status":{"replicas":2,"readyReplicas":%d}}`, f.canaryReady), nil
	case strings.Contains(cmd, "get deploy demoapp"):
		if f.stableErr != nil {
			return "", f.stableErr
		}
		return fmt.Sprintf(
			`{"spec":{"replicas":%d,"template":{"spec":{"containers":[{"image":%q}]}}},"status":{"replicas":%d,"readyReplicas":%d}}`,
			f.stableRepl, f.stableImage, f.stableRepl, f.stableRepl), nil
	case strings.Contains(cmd, "get --raw"):
		if f.metricsErr != nil {
			return "", f.metricsErr
		}
		f.mu.Lock()
		f.metricsReq += f.metricsStep
		req := f.metricsReq
		f.mu.Unlock()
		return fmt.Sprintf(`{"version":"v2","requests":%d,"errors":0,"fail_rate":0,"uptime_s":60}`, req), nil
	case strings.Contains(cmd, "apply -f -"):
		return "applied", nil
	case strings.Contains(cmd, "scale"):
		return "scaled", nil
	case strings.Contains(cmd, "delete"):
		return "deleted", nil
	}
	return "", nil
}

// called reports whether some recorded invocation's arg-join contains sub.
func (f *fakeK8s) called(sub string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if strings.Contains(strings.Join(c, " "), sub) {
			return true
		}
	}
	return false
}

// calledExact reports whether some recorded invocation's arg-join exactly
// equals whole (used to distinguish "delete deploy demoapp" from
// "delete deploy demoapp-canary").
func (f *fakeK8s) calledExact(whole string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if strings.Join(c, " ") == whole {
			return true
		}
	}
	return false
}

func (f *fakeK8s) callsWith(sub string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if strings.Contains(strings.Join(c, " "), sub) {
			n++
		}
	}
	return n
}

// allPrefixed reports whether every recorded call is prefixed with the
// given leading args (e.g. "--context e2e").
func (f *fakeK8s) allPrefixed(prefix ...string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if len(c) < len(prefix) {
			return false
		}
		for i, p := range prefix {
			if c[i] != p {
				return false
			}
		}
	}
	return true
}

// fakeClock advances by a fixed increment on every Now() call.
type fakeClock struct {
	mu  sync.Mutex
	t   time.Time
	inc time.Duration
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(c.inc)
	return c.t
}

func newFakeClock(inc time.Duration) *fakeClock {
	return &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), inc: inc}
}

// canaryStep is the standard k8s_canary step for the executor unit tests.
func canaryStep() pipeline.StepDef {
	return pipeline.StepDef{
		ID:           "deploy",
		Type:         "k8s_canary",
		Image:        "registry/demoapp:2.0",
		Namespace:    "default",
		Deployment:   "demoapp",
		CanaryWeight: 10,
	}
}

func canaryReleaseOf(t *testing.T, st *store.Store) store.CanaryRelease {
	t.Helper()
	releases, err := st.ListCanaries()
	if err != nil {
		t.Fatalf("list canaries: %v", err)
	}
	if len(releases) != 1 {
		t.Fatalf("want exactly 1 canary release, got %d", len(releases))
	}
	return releases[0]
}

// ---------------------------------------------------------------------------
// Executor unit tests
// ---------------------------------------------------------------------------

func TestCanaryExecutorHappy(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/canary-exec.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	fk := newFakeK8s()
	clk := newFakeClock(10 * time.Second)
	ex := &CanaryExecutor{Store: st, Kubectl: fk, Now: clk.Now, Poll: time.Millisecond}

	err = ex.Execute(context.Background(), canaryStep(), 0, nil)
	if err != nil {
		t.Fatalf("Execute happy: %v", err)
	}
	rel := canaryReleaseOf(t, st)
	if rel.State != store.CanaryPromoted {
		t.Fatalf("release state = %q, want promoted", rel.State)
	}
	if rel.RunID != 0 {
		t.Errorf("release RunID = %d, want 0", rel.RunID)
	}
	if rel.StableImage != "registry/demoapp:1.0" {
		t.Errorf("StableImage = %q, want registry/demoapp:1.0 (seeded from live deployment)", rel.StableImage)
	}
	if rel.Replicas != 3 {
		t.Errorf("Replicas = %d, want 3 (seeded from live deployment)", rel.Replicas)
	}
	if !fk.called("scale deploy/demoapp-canary") {
		t.Errorf("scale canary to full replicas not called")
	}
	if !fk.calledExact("-n default delete deploy demoapp") {
		t.Errorf("stable deployment delete not called after promote; calls: %v", fk.calls)
	}
}

func TestCanaryExecutorProbeFailureRollback(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/canary-exec2.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	fk := newFakeK8s()
	fk.metricsErr = errors.New("scrape boom")
	clk := newFakeClock(10 * time.Second)
	ex := &CanaryExecutor{Store: st, Kubectl: fk, Now: clk.Now, Poll: time.Millisecond}

	step := canaryStep()
	step.CanaryProbeFailures = 2

	err = ex.Execute(context.Background(), step, 0, nil)
	if err == nil {
		t.Fatalf("Execute probe-failure: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "rolled_back") {
		t.Fatalf("error = %q, want rolled_back", err.Error())
	}
	rel := canaryReleaseOf(t, st)
	if rel.State != store.CanaryRolledBack {
		t.Fatalf("release state = %q, want rolled_back", rel.State)
	}
	if !fk.calledExact("-n default delete deploy demoapp-canary") {
		t.Errorf("canary deployment delete not called on rollback")
	}
	if !fk.calledExact("-n default delete svc demoapp-canary") {
		t.Errorf("canary service delete not called on rollback")
	}
	if fk.calledExact("-n default delete deploy demoapp") {
		t.Errorf("stable deployment must NOT be deleted on rollback")
	}
}

func TestCanaryExecutorApplyingTimeout(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/canary-exec3.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	fk := newFakeK8s()
	fk.canaryReady = 0 // never becomes ready
	clk := newFakeClock(10 * time.Second)
	ex := &CanaryExecutor{Store: st, Kubectl: fk, Now: clk.Now, Poll: time.Millisecond}

	step := canaryStep()
	step.CanaryTimeout = 1 // 1s applying window

	err = ex.Execute(context.Background(), step, 0, nil)
	if err == nil {
		t.Fatalf("Execute applying-timeout: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "applying timeout") {
		t.Fatalf("error = %q, want applying timeout", err.Error())
	}
	rel := canaryReleaseOf(t, st)
	if rel.State != store.CanaryRolledBack {
		t.Fatalf("release state = %q, want rolled_back", rel.State)
	}
}

func TestCanaryExecutorContextCancelRollsBack(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/canary-exec4.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	fk := newFakeK8s()
	fk.canaryReady = 0 // stuck in applying; default 300s apply window never elapses
	clk := newFakeClock(10 * time.Second)
	ex := &CanaryExecutor{Store: st, Kubectl: fk, Now: clk.Now, Poll: 10 * time.Millisecond}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()

	err = ex.Execute(ctx, canaryStep(), 0, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Execute cancel: err = %v, want context.DeadlineExceeded", err)
	}
	rel := canaryReleaseOf(t, st)
	if rel.State != store.CanaryRolledBack {
		t.Fatalf("release state = %q, want rolled_back", rel.State)
	}
	if !strings.Contains(rel.Reason, "canceled") {
		t.Errorf("reason = %q, want canceled marker", rel.Reason)
	}
	if !fk.called("delete deploy demoapp-canary") {
		t.Errorf("canary deployment delete not called on cancel-rollback")
	}
}

func TestCanaryExecutorStableNotFound(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/canary-exec5.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	fk := newFakeK8s()
	fk.stableErr = errors.New(`NotFound: no resources found`)
	ex := &CanaryExecutor{Store: st, Kubectl: fk, Now: newFakeClock(10 * time.Second).Now, Poll: time.Millisecond}

	err = ex.Execute(context.Background(), canaryStep(), 0, nil)
	if err == nil {
		t.Fatalf("Execute stable-not-found: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "NotFound") {
		t.Fatalf("error = %q, want NotFound", err.Error())
	}
	actives, err := st.ActiveCanaries()
	if err != nil {
		t.Fatalf("active canaries: %v", err)
	}
	if len(actives) != 0 {
		t.Errorf("no release may be created when the stable deployment is missing, got %d active", len(actives))
	}
}

func TestCanaryExecutorConflict(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/canary-exec6.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	// A background (API-created) release already occupies the (name, namespace)
	// slot; the step must fail with the stable conflict sentinel.
	if _, err := st.CreateCanary(store.CanaryRelease{
		Name: "demoapp", Namespace: "default",
		StableImage: "registry/demoapp:1.0", CanaryImage: "registry/demoapp:0.9",
	}); err != nil {
		t.Fatalf("seed active canary: %v", err)
	}

	fk := newFakeK8s()
	ex := &CanaryExecutor{Store: st, Kubectl: fk, Now: newFakeClock(10 * time.Second).Now, Poll: time.Millisecond}

	err = ex.Execute(context.Background(), canaryStep(), 0, nil)
	if !errors.Is(err, store.ErrCanaryConflict) {
		t.Fatalf("Execute conflict: err = %v, want ErrCanaryConflict", err)
	}
}

func TestCanaryExecutorContextPrefix(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/canary-exec7.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	fk := newFakeK8s()
	clk := newFakeClock(10 * time.Second)
	ex := &CanaryExecutor{Store: st, Kubectl: fk, Now: clk.Now, Poll: time.Millisecond}

	step := canaryStep()
	step.K8sContext = "e2e"

	if err := ex.Execute(context.Background(), step, 0, nil); err != nil {
		t.Fatalf("Execute context: %v", err)
	}
	if !fk.allPrefixed("--context", "e2e") {
		t.Errorf("every kubectl invocation must be prefixed with --context e2e; calls: %+v", fk.calls)
	}
}

// ---------------------------------------------------------------------------
// Scheduler integration: build → k8s_canary in one pipeline run
// ---------------------------------------------------------------------------

const canaryPipelineYAML = `
version: 1
pipeline:
  name: p7canary
  steps:
    - id: build
      type: docker_build
      image: registry/demoapp:2.0
    - id: deploy
      type: k8s_canary
      needs: [build]
      image: registry/demoapp:2.0
      k8s_context: e2e
      namespace: default
      deployment: demoapp
      canary:
        weight: 20
`

func TestSchedulerK8sCanaryRun(t *testing.T) {
	ts := newTestScheduler(t)
	ts.upsert("p7canary", canaryPipelineYAML)

	fk := newFakeK8s()
	clk := newFakeClock(10 * time.Second)
	ts.s.CanaryExec = &CanaryExecutor{Store: ts.st, Kubectl: fk, Now: clk.Now, Poll: time.Millisecond}

	runID, err := ts.s.Trigger("p7canary", "manual", "")
	if err != nil {
		t.Fatalf("trigger: %v", err)
	}
	r := ts.waitForTerminal(runID)
	if r.Status != store.RunSuccess {
		t.Fatalf("run status = %q, want success", r.Status)
	}
	if got := ts.stepStatus(runID, "deploy"); got != store.StepSuccess {
		t.Fatalf("deploy step status = %q, want success", got)
	}
	if ts.fx.ran("deploy") {
		t.Fatalf("k8s_canary step must not be dispatched to the agent executor")
	}

	// The deploy step's outputs carry the release id + final state (P7④
	// channel). All values are JSON strings (the API decodes outputs into
	// map[string]string), so parse the release id as a string.
	var out struct {
		ReleaseID string `json:"canary_release_id"`
		State     string `json:"canary_state"`
		Stable    string `json:"stable_image"`
	}
	for _, rs := range mustRunSteps(t, ts.st, runID) {
		if rs.StepID != "deploy" {
			continue
		}
		if err := json.Unmarshal([]byte(rs.Outputs), &out); err != nil {
			t.Fatalf("deploy outputs not JSON: %v (%q)", err, rs.Outputs)
		}
	}
	releaseID, err := strconv.ParseInt(out.ReleaseID, 10, 64)
	if err != nil || releaseID == 0 {
		t.Fatalf("deploy outputs missing numeric canary_release_id: %+v (parse err %v)", out, err)
	}
	if out.State != store.CanaryPromoted {
		t.Errorf("deploy outputs canary_state = %q, want promoted", out.State)
	}
	if out.Stable != "registry/demoapp:1.0" {
		t.Errorf("deploy outputs stable_image = %q, want registry/demoapp:1.0", out.Stable)
	}

	rel, err := ts.st.GetCanary(releaseID)
	if err != nil {
		t.Fatalf("get canary %d: %v", releaseID, err)
	}
	if rel.RunID != runID {
		t.Errorf("release RunID = %d, want %d", rel.RunID, runID)
	}
	if rel.State != store.CanaryPromoted {
		t.Errorf("release state = %q, want promoted", rel.State)
	}
	if rel.CanaryImage != "registry/demoapp:2.0" {
		t.Errorf("release CanaryImage = %q, want registry/demoapp:2.0", rel.CanaryImage)
	}
	if !fk.allPrefixed("--context", "e2e") {
		t.Errorf("all kubectl calls must use the step's k8s_context (e2e)")
	}

	// A run-bound release must not be picked up by the background TickAll
	// driver (ActiveCanaries filters run_id = 0).
	actives, err := ts.st.ActiveCanaries()
	if err != nil {
		t.Fatalf("active canaries: %v", err)
	}
	for _, a := range actives {
		if a.RunID != 0 {
			t.Errorf("run-bound release %d in ActiveCanaries (would be double-driven)", a.ID)
		}
	}
}

// TestSchedulerK8sCanaryFailure marks the run failed when the canary is
// rolled back, and leaves the release in rolled_back state.
func TestSchedulerK8sCanaryFailure(t *testing.T) {
	ts := newTestScheduler(t)
	ts.upsert("p7canary", canaryPipelineYAML)

	fk := newFakeK8s()
	fk.metricsErr = errors.New("scrape boom")
	clk := newFakeClock(10 * time.Second)
	ts.s.CanaryExec = &CanaryExecutor{Store: ts.st, Kubectl: fk, Now: clk.Now, Poll: time.Millisecond}

	// Lower the probe budget so the rollback happens within a few ticks.
	fk.metricsErr = errors.New("scrape boom")
	runID, err := ts.s.Trigger("p7canary", "manual", "")
	if err != nil {
		t.Fatalf("trigger: %v", err)
	}
	r := ts.waitForTerminal(runID)
	if r.Status != store.RunFailed {
		t.Fatalf("run status = %q, want failed", r.Status)
	}
	if got := ts.stepStatus(runID, "deploy"); got != store.StepFailed {
		t.Fatalf("deploy step status = %q, want failed", got)
	}
	rel := canaryReleaseOf(t, ts.st)
	if rel.State != store.CanaryRolledBack {
		t.Fatalf("release state = %q, want rolled_back", rel.State)
	}
	if rel.RunID != runID {
		t.Errorf("release RunID = %d, want %d", rel.RunID, runID)
	}
}

func mustRunSteps(t *testing.T, st *store.Store, runID int64) []store.RunStep {
	t.Helper()
	steps, err := st.ListRunSteps(runID)
	if err != nil {
		t.Fatalf("list run steps: %v", err)
	}
	return steps
}

// ---------------------------------------------------------------------------
// Blue-green strategy (k8s_blue_green step type)
// ---------------------------------------------------------------------------

// blueGreenStep is a k8s_blue_green variant of canaryStep.
func blueGreenStep() pipeline.StepDef {
	s := canaryStep()
	s.Type = "k8s_blue_green"
	return s
}

// TestCanaryExecutorBlueGreen: a k8s_blue_green step must create a
// run-bound release with strategy "blue_green", drive the alt object
// ("<name>-alt", never "-canary"), and reach promoted.
func TestCanaryExecutorBlueGreen(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/canary-exec-bg.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	fk := newFakeK8s()
	clk := newFakeClock(10 * time.Second)
	ex := &CanaryExecutor{Store: st, Kubectl: fk, Now: clk.Now, Poll: time.Millisecond}

	if err := ex.Execute(context.Background(), blueGreenStep(), 0, nil); err != nil {
		t.Fatalf("Execute blue-green happy: %v", err)
	}
	rel := canaryReleaseOf(t, st)
	if rel.Strategy != "blue_green" {
		t.Fatalf("release Strategy = %q, want blue_green", rel.Strategy)
	}
	if rel.State != store.CanaryPromoted {
		t.Fatalf("release state = %q, want promoted", rel.State)
	}
	if !fk.called("get deploy demoapp-alt") {
		t.Errorf("alt deployment readiness check not called; calls: %v", fk.calls)
	}
	if fk.called("demoapp-canary") {
		t.Errorf("blue-green release must not touch any -canary object; calls: %v", fk.calls)
	}
	if !fk.calledExact("-n default delete deploy demoapp") {
		t.Errorf("stable deployment delete not called after promote; calls: %v", fk.calls)
	}
}

const blueGreenPipelineYAML = `
version: 1
pipeline:
  name: p7bluegreen
  steps:
    - id: build
      type: docker_build
      image: registry/demoapp:2.0
    - id: deploy
      type: k8s_blue_green
      needs: [build]
      image: registry/demoapp:2.0
      k8s_context: e2e
      namespace: default
      deployment: demoapp
`

// TestSchedulerK8sBlueGreenRun: a k8s_blue_green step is executed in-process
// by the CD executor (never the agent), and the run-bound release carries
// strategy blue_green end to end.
func TestSchedulerK8sBlueGreenRun(t *testing.T) {
	ts := newTestScheduler(t)
	ts.upsert("p7bluegreen", blueGreenPipelineYAML)

	fk := newFakeK8s()
	clk := newFakeClock(10 * time.Second)
	ts.s.CanaryExec = &CanaryExecutor{Store: ts.st, Kubectl: fk, Now: clk.Now, Poll: time.Millisecond}

	runID, err := ts.s.Trigger("p7bluegreen", "manual", "")
	if err != nil {
		t.Fatalf("trigger: %v", err)
	}
	r := ts.waitForTerminal(runID)
	if r.Status != store.RunSuccess {
		t.Fatalf("run status = %q, want success", r.Status)
	}
	if got := ts.stepStatus(runID, "deploy"); got != store.StepSuccess {
		t.Fatalf("deploy step status = %q, want success", got)
	}
	if ts.fx.ran("deploy") {
		t.Fatalf("k8s_blue_green step must not be dispatched to the agent executor")
	}
	rel := canaryReleaseOf(t, ts.st)
	if rel.Strategy != "blue_green" {
		t.Errorf("release Strategy = %q, want blue_green", rel.Strategy)
	}
	if rel.RunID != runID {
		t.Errorf("release RunID = %d, want %d", rel.RunID, runID)
	}
	if rel.State != store.CanaryPromoted {
		t.Errorf("release state = %q, want promoted", rel.State)
	}
	if !fk.allPrefixed("--context", "e2e") {
		t.Errorf("all kubectl calls must use the step's k8s_context (e2e)")
	}
}
