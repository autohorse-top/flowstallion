package scheduler

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/flowstallion/flowstallion/pkg/pipeline"
	"github.com/flowstallion/flowstallion/pkg/policy"
	"github.com/flowstallion/flowstallion/pkg/store"
)

// ---------------------------------------------------------------------------
// Fakes & helpers
// ---------------------------------------------------------------------------

type stepCall struct {
	StepID string
	Image  string
	Env    map[string]string
}

// fakeExecutor records each step it executes and can be programmed to fail
// specific steps. It honours ctx cancellation (simulating a killed process)
// and streams one log line per command to the log writer in the context.
type fakeExecutor struct {
	mu      sync.Mutex
	calls   []stepCall
	delay   time.Duration
	failIDs map[string]bool
}

func newFakeExecutor() *fakeExecutor {
	return &fakeExecutor{failIDs: make(map[string]bool)}
}

func (f *fakeExecutor) Execute(ctx context.Context, step pipeline.StepDef, runID int64, env map[string]string) error {
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	envCopy := make(map[string]string, len(env))
	for k, v := range env {
		envCopy[k] = v
	}
	f.mu.Lock()
	f.calls = append(f.calls, stepCall{StepID: step.ID, Image: step.Image, Env: envCopy})
	f.mu.Unlock()

	lw := LogWriterFrom(ctx)
	for _, c := range step.Commands {
		if _, err := fmt.Fprintf(lw, "step %s: %s\n", step.ID, c); err != nil {
			return err
		}
	}
	if f.failIDs[step.ID] {
		return fmt.Errorf("forced failure: %s", step.ID)
	}
	return nil
}

// envFor returns the env map observed by a step (nil if the step never ran).
func (f *fakeExecutor) envFor(stepID string) map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if c.StepID == stepID {
			return c.Env
		}
	}
	return nil
}

// ran reports whether a step was executed at all.
func (f *fakeExecutor) ran(stepID string) bool {
	return f.envFor(stepID) != nil
}

// imageFor returns the Image the executor observed for a step ("", if the
// step never ran). P7④: used to assert docker_build tag expansion.
func (f *fakeExecutor) imageFor(stepID string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if c.StepID == stepID {
			return c.Image
		}
	}
	return ""
}

type testScheduler struct {
	t  *testing.T
	st *store.Store
	s  *Scheduler
	fx *fakeExecutor
}

func newTestScheduler(t *testing.T) *testScheduler {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	fx := newFakeExecutor()
	return &testScheduler{t: t, st: st, s: New(st, fx), fx: fx}
}

// upsert stores a pipeline YAML, failing the test if it does not parse.
func (ts *testScheduler) upsert(name, yaml string) {
	ts.t.Helper()
	if _, err := pipeline.ParseYAML([]byte(yaml)); err != nil {
		ts.t.Fatalf("test yaml for %q invalid: %v", name, err)
	}
	if _, err := ts.st.UpsertPipeline(name, yaml); err != nil {
		ts.t.Fatalf("upsert %q: %v", name, err)
	}
}

// waitForTerminal polls until the run reaches a terminal status.
func (ts *testScheduler) waitForTerminal(runID int64) store.Run {
	ts.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		r, err := ts.st.GetRun(runID)
		if err != nil {
			ts.t.Fatalf("get run %d: %v", runID, err)
		}
		if r.Status == store.RunSuccess || r.Status == store.RunFailed || r.Status == store.RunCanceled {
			return r
		}
		if time.Now().After(deadline) {
			ts.t.Fatalf("run %d still %q after 10s", runID, r.Status)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// stepStatus returns the stored status of a step within a run.
func (ts *testScheduler) stepStatus(runID int64, stepID string) string {
	ts.t.Helper()
	steps, err := ts.st.ListRunSteps(runID)
	if err != nil {
		ts.t.Fatalf("list steps for run %d: %v", runID, err)
	}
	for _, rs := range steps {
		if rs.StepID == stepID {
			return rs.Status
		}
	}
	ts.t.Fatalf("run %d has no step %q", runID, stepID)
	return ""
}

// collectEvents drains the bus until (and including) a run.finished event for
// runID, or times out.
func collectEvents(t *testing.T, ch <-chan Event, runID int64) []Event {
	t.Helper()
	var out []Event
	timeout := time.After(10 * time.Second)
	for {
		select {
		case e := <-ch:
			if e.RunID != runID {
				t.Fatalf("event for unexpected run %d (want %d): %+v", e.RunID, runID, e)
			}
			out = append(out, e)
			if e.Type == EvtRunFinished {
				return out
			}
		case <-timeout:
			t.Fatalf("no run.finished for run %d after %d events", runID, len(out))
		}
	}
}

// ---------------------------------------------------------------------------
// YAML fixtures
// ---------------------------------------------------------------------------

const linearYAML = `
version: 1
pipeline:
  name: linear
  steps:
    - id: a
      image: alpine
      commands:
        - echo a
    - id: b
      image: alpine
      needs: [a]
      commands:
        - echo b
    - id: c
      image: alpine
      needs: [b]
      commands:
        - echo c
`

const branchYAML = `
version: 1
pipeline:
  name: branch
  steps:
    - id: ok
      image: alpine
      commands: [echo ok]
    - id: bad
      image: alpine
      needs: [ok]
      commands: [echo bad]
    - id: after-bad
      image: alpine
      needs: [bad]
      commands: [echo never]
    - id: side
      image: alpine
      commands: [echo side]
`

const slowYAML = `
version: 1
pipeline:
  name: slow
  concurrency: 1
  steps:
    - id: a
      image: alpine
      commands: [echo a]
`

const cancelYAML = `
version: 1
pipeline:
  name: cancelme
  steps:
    - id: a
      image: alpine
      commands: [echo a]
    - id: b
      image: alpine
      needs: [a]
      commands: [echo b]
`

const envYAML = `
version: 1
pipeline:
  name: envtest
  env:
    FOO: pipeline
    BAZ: qux
  steps:
    - id: s
      image: alpine
      env:
        FOO: step
      commands: [echo s]
`

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestLinearSuccess: a → b → c all succeed; event ordering, log capture,
// cleanup of the active set.
func TestLinearSuccess(t *testing.T) {
	ts := newTestScheduler(t)
	ts.upsert("linear", linearYAML)

	ch, cancelSub := ts.s.Events.Subscribe()
	defer cancelSub()

	runID, err := ts.s.Trigger("linear", "manual", "")
	if err != nil {
		t.Fatalf("trigger: %v", err)
	}

	events := collectEvents(t, ch, runID)

	r := ts.waitForTerminal(runID)
	if r.Status != store.RunSuccess {
		t.Fatalf("run status = %q, want %q", r.Status, store.RunSuccess)
	}
	for _, id := range []string{"a", "b", "c"} {
		if got := ts.stepStatus(runID, id); got != store.StepSuccess {
			t.Errorf("step %s status = %q, want %q", id, got, store.StepSuccess)
		}
	}
	if got := ts.s.ActiveCount(); got != 0 {
		t.Errorf("ActiveCount after finish = %d, want 0", got)
	}

	// Event ordering: a.started < a.finished < b.started < b.finished < c.started.
	idx := map[string]int{}
	for i, e := range events {
		if e.Type == EvtStepStarted || e.Type == EvtStepFinished {
			idx[e.StepID+"."+e.Type] = i
		}
	}
	order := []string{"a." + EvtStepStarted, "a." + EvtStepFinished,
		"b." + EvtStepStarted, "b." + EvtStepFinished, "c." + EvtStepStarted}
	for i, k := range order {
		j, ok := idx[k]
		if !ok {
			t.Fatalf("event %q not observed in %d events", k, len(events))
		}
		if i > 0 && j < idx[order[i-1]] {
			t.Errorf("event %q at %d out of order (after %q at %d)", k, j, order[i-1], idx[order[i-1]])
		}
	}

	// Log capture: exactly one line per step, stored in SQLite.
	for _, id := range []string{"a", "b", "c"} {
		logs, err := ts.st.ListLogs(runID, id, 0, 0)
		if err != nil {
			t.Fatalf("list logs step %s: %v", id, err)
		}
		if len(logs) != 1 || logs[0].Line != "step "+id+": echo "+id {
			t.Errorf("logs for step %s = %+v, want one line %q", id, logs, "step "+id+": echo "+id)
		}
	}

	// Log events published on the bus.
	logEvents := 0
	for _, e := range events {
		if e.Type == EvtLog {
			logEvents++
		}
	}
	if logEvents != 3 {
		t.Errorf("EvtLog events = %d, want 3", logEvents)
	}
}

// TestFailureSkipsDependents: a failing step fails the run; its dependent is
// skipped; an independent step still runs.
func TestFailureSkipsDependents(t *testing.T) {
	ts := newTestScheduler(t)
	ts.upsert("branch", branchYAML)
	ts.fx.failIDs["bad"] = true

	runID, err := ts.s.Trigger("branch", "manual", "refs/heads/main")
	if err != nil {
		t.Fatalf("trigger: %v", err)
	}
	r := ts.waitForTerminal(runID)

	if r.Status != store.RunFailed {
		t.Fatalf("run status = %q, want %q", r.Status, store.RunFailed)
	}
	want := map[string]string{
		"ok":        store.StepSuccess,
		"bad":       store.StepFailed,
		"after-bad": store.StepSkipped,
		"side":      store.StepSuccess,
	}
	for id, status := range want {
		if got := ts.stepStatus(runID, id); got != status {
			t.Errorf("step %s status = %q, want %q", id, got, status)
		}
	}
	if ts.fx.ran("after-bad") {
		t.Error("skipped step after-bad was executed")
	}
	if !ts.fx.ran("side") {
		t.Error("independent step side did not run")
	}
}

// TestConcurrencyLimit: pipeline concurrency=1 blocks a second trigger with
// ErrLimit while the first run is in flight, and releases it afterwards.
func TestConcurrencyLimit(t *testing.T) {
	ts := newTestScheduler(t)
	ts.upsert("slow", slowYAML)
	ts.fx.delay = 200 * time.Millisecond

	run1, err := ts.s.Trigger("slow", "manual", "")
	if err != nil {
		t.Fatalf("trigger run1: %v", err)
	}
	if _, err := ts.s.Trigger("slow", "manual", ""); err == nil {
		t.Fatal("second trigger while at the concurrency limit: want ErrLimit, got nil")
	}

	r := ts.waitForTerminal(run1)
	if r.Status != store.RunSuccess {
		t.Fatalf("run1 status = %q, want %q", r.Status, store.RunSuccess)
	}
	// Limit released once the run finishes.
	if _, err := ts.s.Trigger("slow", "manual", ""); err != nil {
		t.Fatalf("trigger after finish: %v", err)
	}
}

// TestUnknownPipeline: triggering a name that is not stored fails.
func TestUnknownPipeline(t *testing.T) {
	ts := newTestScheduler(t)
	if _, err := ts.s.Trigger("ghost", "manual", ""); err == nil {
		t.Fatal("trigger of unknown pipeline: want error, got nil")
	}
}

// TestCancel: canceling an in-flight run ends it in the canceled state and
// releases the active slot.
func TestCancel(t *testing.T) {
	ts := newTestScheduler(t)
	ts.upsert("cancelme", cancelYAML)
	ts.fx.delay = 300 * time.Millisecond

	runID, err := ts.s.Trigger("cancelme", "manual", "")
	if err != nil {
		t.Fatalf("trigger: %v", err)
	}
	time.Sleep(30 * time.Millisecond) // let step a start
	if err := ts.s.Cancel(runID); err != nil {
		t.Fatalf("cancel: %v", err)
	}

	r := ts.waitForTerminal(runID)
	if r.Status != store.RunCanceled {
		t.Fatalf("run status = %q, want %q", r.Status, store.RunCanceled)
	}
	if got := ts.s.ActiveCount(); got != 0 {
		t.Errorf("ActiveCount after cancel = %d, want 0", got)
	}
}

// TestEnvMerge: pipeline env is the base; step env overrides it.
func TestEnvMerge(t *testing.T) {
	ts := newTestScheduler(t)
	ts.upsert("envtest", envYAML)

	runID, err := ts.s.Trigger("envtest", "manual", "")
	if err != nil {
		t.Fatalf("trigger: %v", err)
	}
	ts.waitForTerminal(runID)

	env := ts.fx.envFor("s")
	if env == nil {
		t.Fatal("step s never ran")
	}
	if env["FOO"] != "step" {
		t.Errorf("FOO = %q, want step-level override %q", env["FOO"], "step")
	}
	if env["BAZ"] != "qux" {
		t.Errorf("BAZ = %q, want pipeline-level %q", env["BAZ"], "qux")
	}
}

// TestTriggerInvalidStoredYAML: a stored pipeline whose YAML no longer
// parses fails at trigger time (defense in depth — the store is writable).
func TestTriggerInvalidStoredYAML(t *testing.T) {
	ts := newTestScheduler(t)
	if _, err := ts.st.UpsertPipeline("broken", "version: 2\npipeline: {}\n"); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if _, err := ts.s.Trigger("broken", "manual", ""); err == nil {
		t.Fatal("trigger of unparseable stored YAML: want error, got nil")
	}
}

// ---------------------------------------------------------------------------
// EventBus unit tests
// ---------------------------------------------------------------------------

// TestEventBusBackpressure: publishing beyond the per-subscriber buffer
// drops the oldest events (counted) and never blocks the publisher.
func TestEventBusBackpressure(t *testing.T) {
	b := NewEventBus()
	ch, cancel := b.Subscribe()
	defer cancel()

	start := time.Now()
	for i := 0; i < 500; i++ {
		b.Publish(Event{RunID: 1, Type: EvtLog, Message: "x"})
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("Publish blocked for %v; must be non-blocking", d)
	}
	if got := b.DroppedCount(); got < 1 {
		t.Fatalf("DroppedCount = %d, want > 0 after 500 publishes into a 256 buffer", got)
	}

	received := 0
	for {
		select {
		case <-ch:
			received++
		default:
			goto done
		}
	}
done:
	if received > 256 {
		t.Fatalf("subscriber holds %d events, more than its 256 buffer", received)
	}
}

// TestEventBusMultiSubscriber: every subscriber gets every event.
func TestEventBusMultiSubscriber(t *testing.T) {
	b := NewEventBus()
	chA, cancelA := b.Subscribe()
	defer cancelA()
	chB, cancelB := b.Subscribe()
	defer cancelB()

	b.Publish(Event{RunID: 1, Type: EvtRunStarted})
	for name, ch := range map[string]<-chan Event{"A": chA, "B": chB} {
		select {
		case e := <-ch:
			if e.RunID != 1 || e.Type != EvtRunStarted {
				t.Errorf("subscriber %s got unexpected event %+v", name, e)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("subscriber %s received no event", name)
		}
	}
}

// TestLogWriterLineSplitting: the log writer emits one complete line per
// '\n' and flushes a trailing partial line.
func TestLogWriterLineSplitting(t *testing.T) {
	var mu sync.Mutex
	var lines []string
	sink := func(line string) {
		mu.Lock()
		lines = append(lines, line)
		mu.Unlock()
	}
	lw := &logWriter{complete: sink}

	w, err := lw.Write([]byte("line1\nline2"))
	if err != nil || w != 11 {
		t.Fatalf("Write = (%d, %v), want (11, nil)", w, err)
	}
	lw.Flush()

	mu.Lock()
	defer mu.Unlock()
	want := []string{"line1", "line2"}
	if len(lines) != len(want) {
		t.Fatalf("lines = %v, want %v", lines, want)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line[%d] = %q, want %q", i, lines[i], want[i])
		}
	}
}

// TestLogWriterFromDefault: without a context-carried writer, the fallback
// is io.Discard (never nil, never errors).
func TestLogWriterFromDefault(t *testing.T) {
	w := LogWriterFrom(context.Background())
	if w == nil {
		t.Fatal("LogWriterFrom(default ctx) = nil, want io.Discard")
	}
	if n, err := w.Write([]byte("x")); err != nil || n != 1 {
		t.Errorf("Write on default writer = (%d, %v), want (1, nil)", n, err)
	}
}

// ---------------------------------------------------------------------------
// Policy gateway (hold / approve / reject / autonomy levels)
// ---------------------------------------------------------------------------

const policyProdYAML = `
version: 1
pipeline:
  name: polprod
  concurrency: 1
  env:
    environment: production
  steps:
    - id: build
      image: alpine
      commands:
        - echo build
    - id: deploy-prod
      image: alpine
      needs: [build]
      commands:
        - echo deploy
`

const policyStagingYAML = `
version: 1
pipeline:
  name: polstag
  env:
    environment: staging
  steps:
    - id: build
      image: alpine
      commands:
        - echo build
    - id: deploy-prod
      image: alpine
      needs: [build]
      commands:
        - echo deploy
`

// waitStatus polls GetRun until the run reaches the wanted status.
func (ts *testScheduler) waitStatus(runID int64, want string) store.Run {
	ts.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		r, err := ts.st.GetRun(runID)
		if err != nil {
			ts.t.Fatalf("get run %d: %v", runID, err)
		}
		if r.Status == want {
			return r
		}
		if time.Now().After(deadline) {
			ts.t.Fatalf("run %d status %q, want %q", runID, r.Status, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestPolicyHoldProdDeploy: at L2 (default) a production deploy step holds the
// run in pending_approval; Approve releases it to success; nothing ran before
// approval.
func TestPolicyHoldProdDeploy(t *testing.T) {
	ts := newTestScheduler(t)
	ts.upsert("polprod", policyProdYAML)

	id, err := ts.s.Trigger("polprod", "manual", "")
	if err != nil {
		t.Fatalf("trigger: %v", err)
	}
	r := ts.waitStatus(id, store.RunPendingApproval)
	if r.Status != store.RunPendingApproval {
		t.Fatalf("status = %q, want pending_approval", r.Status)
	}
	if got := ts.s.ActiveCount(); got != 0 {
		t.Fatalf("active count = %d, want 0 (held run must not count as active)", got)
	}
	if ts.fx.ran("build") || ts.fx.ran("deploy-prod") {
		t.Fatal("steps executed before approval")
	}
	if ts.stepStatus(id, "deploy-prod") != store.StepPending {
		t.Fatalf("step status = %q, want pending", ts.stepStatus(id, "deploy-prod"))
	}

	if err := ts.s.Approve(id); err != nil {
		t.Fatalf("approve: %v", err)
	}
	fin := ts.waitForTerminal(id)
	if fin.Status != store.RunSuccess {
		t.Fatalf("status after approve = %q, want success", fin.Status)
	}
	if !ts.fx.ran("build") || !ts.fx.ran("deploy-prod") {
		t.Fatal("steps did not run after approval")
	}
	if env := ts.fx.envFor("deploy-prod"); env["environment"] != "production" {
		t.Fatalf("deploy-prod env = %v, want environment=production", env)
	}
}

// TestPolicyReject: rejecting a held run marks it rejected with skipped steps
// and never executes.
func TestPolicyReject(t *testing.T) {
	ts := newTestScheduler(t)
	ts.upsert("polprod", policyProdYAML)
	id, err := ts.s.Trigger("polprod", "manual", "")
	if err != nil {
		t.Fatalf("trigger: %v", err)
	}
	ts.waitStatus(id, store.RunPendingApproval)
	if err := ts.s.Reject(id); err != nil {
		t.Fatalf("reject: %v", err)
	}
	r := ts.waitStatus(id, store.RunRejected)
	if r.Status != store.RunRejected {
		t.Fatalf("status = %q, want rejected", r.Status)
	}
	if r.FinishedAt == "" {
		t.Error("rejected run must have finished_at set")
	}
	if ts.stepStatus(id, "build") != store.StepSkipped ||
		ts.stepStatus(id, "deploy-prod") != store.StepSkipped {
		t.Fatalf("steps not skipped: build=%q deploy-prod=%q",
			ts.stepStatus(id, "build"), ts.stepStatus(id, "deploy-prod"))
	}
	if ts.fx.ran("build") || ts.fx.ran("deploy-prod") {
		t.Fatal("steps executed after reject")
	}
}

// TestRejectWithReason (P7⑧): rejecting with a reason persists the reason on
// the run row; the legacy Reject keeps the reason empty.
func TestRejectWithReason(t *testing.T) {
	ts := newTestScheduler(t)
	ts.upsert("polprod", policyProdYAML)
	id, err := ts.s.Trigger("polprod", "manual", "")
	if err != nil {
		t.Fatalf("trigger: %v", err)
	}
	ts.waitStatus(id, store.RunPendingApproval)

	if err := ts.s.RejectWithReason(id, "deploy target changed"); err != nil {
		t.Fatalf("reject with reason: %v", err)
	}
	r := ts.waitStatus(id, store.RunRejected)
	if r.RejectReason != "deploy target changed" {
		t.Fatalf("reject reason = %q, want %q", r.RejectReason, "deploy target changed")
	}
	if ts.stepStatus(id, "deploy-prod") != store.StepSkipped {
		t.Fatalf("step status = %q, want skipped", ts.stepStatus(id, "deploy-prod"))
	}
	if ts.fx.ran("build") || ts.fx.ran("deploy-prod") {
		t.Fatal("steps executed after reject")
	}

	// Rejecting a terminal run still fails with ErrNotPending.
	if err := ts.s.RejectWithReason(id, "again"); !errors.Is(err, ErrNotPending) {
		t.Fatalf("second reject err = %v, want ErrNotPending", err)
	}

	// Legacy Reject keeps an empty reason.
	id2, err := ts.s.Trigger("polprod", "manual", "")
	if err != nil {
		t.Fatalf("trigger 2: %v", err)
	}
	ts.waitStatus(id2, store.RunPendingApproval)
	if err := ts.s.Reject(id2); err != nil {
		t.Fatalf("reject: %v", err)
	}
	r2 := ts.waitStatus(id2, store.RunRejected)
	if r2.RejectReason != "" {
		t.Fatalf("legacy reject reason = %q, want empty", r2.RejectReason)
	}
}

// TestPolicyCancelPending: canceling a held run cancels it directly.
func TestPolicyCancelPending(t *testing.T) {
	ts := newTestScheduler(t)
	ts.upsert("polprod", policyProdYAML)
	id, err := ts.s.Trigger("polprod", "manual", "")
	if err != nil {
		t.Fatalf("trigger: %v", err)
	}
	ts.waitStatus(id, store.RunPendingApproval)
	if err := ts.s.Cancel(id); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	r := ts.waitStatus(id, store.RunCanceled)
	if r.Status != store.RunCanceled {
		t.Fatalf("status = %q, want canceled", r.Status)
	}
}

// TestPolicyL0HoldsAll: at L0 even a prod pipeline is held for every step,
// and held runs do not count against the concurrency limit.
func TestPolicyL0HoldsAll(t *testing.T) {
	ts := newTestScheduler(t)
	ts.s.Cfg.Autonomy = int(policy.L0)
	ts.upsert("polprod", policyProdYAML) // concurrency: 1 in the YAML

	id1, err := ts.s.Trigger("polprod", "manual", "")
	if err != nil {
		t.Fatalf("trigger 1: %v", err)
	}
	ts.waitStatus(id1, store.RunPendingApproval)
	id2, err := ts.s.Trigger("polprod", "manual", "")
	if err != nil {
		t.Fatalf("trigger 2 (held runs must not count toward the limit): %v", err)
	}
	ts.waitStatus(id2, store.RunPendingApproval)
	if err := ts.s.Approve(id1); err != nil {
		t.Fatalf("approve 1: %v", err)
	}
	fin := ts.waitForTerminal(id1)
	if fin.Status != store.RunSuccess {
		t.Fatalf("run 1 = %q, want success", fin.Status)
	}
	if err := ts.s.Reject(id2); err != nil {
		t.Fatalf("reject 2: %v", err)
	}
	if st := ts.waitStatus(id2, store.RunRejected).Status; st != store.RunRejected {
		t.Fatalf("run 2 = %q, want rejected", st)
	}
}

// TestPolicyStagingAuto: a deploy step targeting staging is not held at L2.
func TestPolicyStagingAuto(t *testing.T) {
	ts := newTestScheduler(t)
	ts.upsert("polstag", policyStagingYAML)
	id, err := ts.s.Trigger("polstag", "manual", "")
	if err != nil {
		t.Fatalf("trigger: %v", err)
	}
	fin := ts.waitForTerminal(id)
	if fin.Status != store.RunSuccess {
		t.Fatalf("status = %q, want success (staging deploy should auto-run)", fin.Status)
	}
	if !ts.fx.ran("deploy-prod") {
		t.Fatal("deploy step did not run")
	}
}

// TestApproveWrongState: approve/reject on a non-pending run fails with
// ErrNotPending; GetRun on an unknown id fails with sql.ErrNoRows.
func TestApproveWrongState(t *testing.T) {
	ts := newTestScheduler(t)
	ts.upsert("polstag", policyStagingYAML)
	id, err := ts.s.Trigger("polstag", "manual", "")
	if err != nil {
		t.Fatalf("trigger: %v", err)
	}
	fin := ts.waitForTerminal(id)
	if fin.Status != store.RunSuccess {
		t.Fatalf("status = %q, want success", fin.Status)
	}
	if err := ts.s.Approve(id); err == nil {
		t.Error("approve on finished run: want error, got nil")
	} else if !errors.Is(err, ErrNotPending) {
		t.Errorf("approve error = %v, want ErrNotPending", err)
	}
	if err := ts.s.Reject(id); err == nil {
		t.Error("reject on finished run: want error, got nil")
	} else if !errors.Is(err, ErrNotPending) {
		t.Errorf("reject error = %v, want ErrNotPending", err)
	}
	if _, err := ts.st.GetRun(999999); err != sql.ErrNoRows {
		t.Fatalf("GetRun(unknown) err = %v, want sql.ErrNoRows", err)
	}
}
