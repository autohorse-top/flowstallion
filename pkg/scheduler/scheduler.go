// Package scheduler drives pipeline execution: it triggers runs, executes
// steps (via a pluggable StepExecutor) honouring the needs-DAG and
// concurrency limits, and publishes lifecycle events on an in-process
// EventBus that the web layer can subscribe to (SSE).
//
// The scheduler never talks to Docker directly; a StepExecutor implementation
// (the Docker runner) does. This keeps the core logic unit-testable without
// a container runtime.
package scheduler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/flowstallion/flowstallion/pkg/pipeline"
	"github.com/flowstallion/flowstallion/pkg/policy"
	"github.com/flowstallion/flowstallion/pkg/secret"
	"github.com/flowstallion/flowstallion/pkg/store"
)

// ErrLimit is returned by Trigger when the pipeline's concurrency limit is
// already reached.
var ErrLimit = errors.New("scheduler: concurrency limit reached")

// ErrSecrets is returned by Trigger when a pipeline's secret declarations
// cannot be satisfied (undeclared ${NAME} reference, missing secret, or no
// encryption key configured). The API layer maps it to HTTP 400.
var ErrSecrets = errors.New("scheduler: secret check failed")

// ErrNotPending is returned by Approve/Reject/RejectWithReason when the run
// is not in the pending_approval state.
var ErrNotPending = errors.New("scheduler: run is not pending approval")

// Event types.
const (
	EvtRunStarted   = "run.started"
	EvtRunPending   = "run.pending"
	EvtStepStarted  = "step.started"
	EvtStepFinished = "step.finished"
	EvtRunFinished  = "run.finished"
	EvtLog          = "log"
)

// Event is one lifecycle or log event for a run.
type Event struct {
	RunID   int64  `json:"run_id"`
	StepID  string `json:"step_id,omitempty"`
	Type    string `json:"type"`
	Message string `json:"message,omitempty"`
	TS      string `json:"ts"`
}

// ---------------------------------------------------------------------------
// EventBus
// ---------------------------------------------------------------------------

// EventBus is an in-process pub/sub with one bounded buffer per subscriber.
// Publishing never blocks: if a subscriber's buffer is full the oldest event
// is dropped (and counted by DroppedCount).
type EventBus struct {
	mu      sync.Mutex
	subs    map[int64]chan Event
	nextID  int64
	dropped int64
}

// NewEventBus creates an empty bus.
func NewEventBus() *EventBus {
	return &EventBus{subs: make(map[int64]chan Event)}
}

// Subscribe opens a new bounded (256) event channel. The returned cancel
// function removes the subscriber and closes its channel.
func (b *EventBus) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 256)
	b.mu.Lock()
	b.nextID++
	id := b.nextID
	b.subs[id] = ch
	b.mu.Unlock()
	cancel := func() {
		b.mu.Lock()
		delete(b.subs, id)
		close(ch)
		b.mu.Unlock()
	}
	return ch, cancel
}

// Publish delivers e to every subscriber without blocking.
func (b *EventBus) Publish(e Event) {
	if e.TS == "" {
		e.TS = time.Now().UTC().Format(time.RFC3339Nano)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, ch := range b.subs {
		select {
		case ch <- e:
			continue
		default:
		}
		select {
		case <-ch: // drop the oldest event
		default:
			b.dropped++
			continue
		}
		b.dropped++
		select {
		case ch <- e:
		default:
			b.dropped++
		}
	}
}

// DroppedCount returns how many events were dropped due to full buffers.
func (b *EventBus) DroppedCount() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.dropped
}

// ---------------------------------------------------------------------------
// Log writer (context-carried)
// ---------------------------------------------------------------------------

type ctxKey int

const logWriterKey ctxKey = iota

// logWriter splits its stream on '\n' and hands each complete line to a sink.
type logWriter struct {
	complete func(string)
	pending  []byte
}

func (w *logWriter) Write(p []byte) (int, error) {
	w.pending = append(w.pending, p...)
	for {
		idx := bytes.IndexByte(w.pending, '\n')
		if idx < 0 {
			break
		}
		line := string(w.pending[:idx])
		w.pending = w.pending[idx+1:]
		w.complete(line)
	}
	return len(p), nil
}

// Flush emits any trailing partial line.
func (w *logWriter) Flush() {
	if len(w.pending) > 0 {
		line := string(w.pending)
		w.pending = w.pending[:0]
		w.complete(line)
	}
}

// WithLogWriter returns a context carrying w as the step's log sink.
func WithLogWriter(ctx context.Context, w io.Writer) context.Context {
	return context.WithValue(ctx, logWriterKey, w)
}

// LogWriterFrom returns the log sink carried by ctx (io.Discard if absent).
// Executors should stream step stdout/stderr to it.
func LogWriterFrom(ctx context.Context) io.Writer {
	if w, ok := ctx.Value(logWriterKey).(io.Writer); ok {
		return w
	}
	return io.Discard
}

// ---------------------------------------------------------------------------
// StepExecutor
// ---------------------------------------------------------------------------

// StepExecutor runs one pipeline step. Implementations must honour ctx
// cancellation and stream output to LogWriterFrom(ctx).
type StepExecutor interface {
	Execute(ctx context.Context, step pipeline.StepDef, runID int64, env map[string]string) error
}

// ---------------------------------------------------------------------------
// Scheduler
// ---------------------------------------------------------------------------

// Config tunes the scheduler.
type Config struct {
	// MaxConcurrentRuns caps how many runs of one pipeline may be in
	// flight at once (combined with pipeline.concurrency, the smaller wins).
	MaxConcurrentRuns int
	// Autonomy is the policy autonomy level (policy.L0..L2). L2 (default):
	// only critical steps (e.g. production deploys) hold a run for approval.
	Autonomy int
	// WebBaseURL is the base of the web console (no trailing slash) used
	// for the notification payload "url" field (P7⑦). Empty → url omitted.
	WebBaseURL string
}

type activeRun struct {
	pipelineID int64
	cancel     context.CancelFunc
}

// Scheduler executes pipelines against a store, using an executor for steps.
type Scheduler struct {
	Store    *store.Store
	Events   *EventBus
	Executor StepExecutor
	// CanaryExec executes k8s_canary steps in-process (P7⑤). When nil,
	// k8s_canary steps fail fast with a configuration error.
	CanaryExec StepExecutor
	// Notifier delivers webhook notifications on run terminal states and
	// canary rollbacks (P7⑦). Nil = notifications disabled. See notify.go.
	Notifier Notifier
	Cfg      Config
	// SecretVault decrypts secrets for ${NAME} env injection (P6②).
	// Nil when FLOWSTALLION_SECRET_KEY is unset: triggers that declare
	// secrets then fail fast with ErrSecrets.
	SecretVault *secret.Vault

	// NowFn returns the current time used by CronTick (P7③). Nil means
	// time.Now().UTC(); tests inject a fixed clock.
	NowFn func() time.Time

	// Retention configures log / canary-event purging (P7⑧); the zero
	// value disables retention entirely. See RetentionTick.
	Retention RetentionPolicy

	mu     sync.Mutex
	active map[int64]*activeRun
}

// New creates a Scheduler with a default config (4 concurrent runs, autonomy L2).
func New(st *store.Store, ex StepExecutor) *Scheduler {
	return &Scheduler{
		Store:    st,
		Events:   NewEventBus(),
		Executor: ex,
		Cfg:      Config{MaxConcurrentRuns: 4, Autonomy: int(policy.L2)},
		active:   make(map[int64]*activeRun),
	}
}

// Trigger validates the pipeline, enqueues a run and starts executing it in
// the background. It returns the new run id. It fails with ErrLimit when the
// pipeline's concurrency limit is reached, or with a parse/store error.
func (s *Scheduler) Trigger(pipelineName, triggerType, sourceRef string) (int64, error) {
	return s.TriggerWithMeta(pipelineName, triggerType, sourceRef, store.RunMeta{})
}

// TriggerWithMeta is Trigger with optional trigger metadata (P7: GitHub
// pull_request runs carry PR number / head / base / repo URL; push, manual,
// schedule and canary runs pass a zero RunMeta, which stores NULL columns).
func (s *Scheduler) TriggerWithMeta(pipelineName, triggerType, sourceRef string, meta store.RunMeta) (int64, error) {
	p, err := s.Store.GetPipelineByName(pipelineName)
	if err != nil {
		return 0, fmt.Errorf("scheduler: pipeline %q: %w", pipelineName, err)
	}
	pl, err := pipeline.ParseYAML([]byte(p.YAMLText))
	if err != nil {
		return 0, fmt.Errorf("scheduler: pipeline %q invalid: %w", pipelineName, err)
	}
	if err := s.validatePipelineSecrets(pl.Pipeline); err != nil {
		return 0, fmt.Errorf("%w: pipeline %q: %v", ErrSecrets, pipelineName, err)
	}
	if triggerType == "" {
		triggerType = "manual"
	}

	limit := s.Cfg.MaxConcurrentRuns
	if limit <= 0 {
		limit = 4
	}
	if c := pl.Pipeline.Concurrency; c > 0 && c < limit {
		limit = c
	}

	s.mu.Lock()
	running := 0
	for _, ar := range s.active {
		if ar.pipelineID == p.ID {
			running++
		}
	}
	if running >= limit {
		s.mu.Unlock()
		return 0, fmt.Errorf("%w: pipeline %q has %d running (limit %d)", ErrLimit, pipelineName, running, limit)
	}

	runID, err := s.Store.CreateRunMeta(p.ID, triggerType, sourceRef, meta)
	if err != nil {
		s.mu.Unlock()
		return 0, err
	}
	for i, st := range pl.Pipeline.Steps {
		cmdJSON, err := json.Marshal(st.Commands)
		if err != nil {
			s.mu.Unlock()
			return 0, fmt.Errorf("scheduler: encode commands for step %q: %w", st.ID, err)
		}
		if _, err := s.Store.AddRunStep(runID, st.ID, i, st.Image, string(cmdJSON)); err != nil {
			s.mu.Unlock()
			return 0, err
		}
	}

	// Policy gate: hold the run for approval if any step requires it.
	level := policy.Autonomy(s.Cfg.Autonomy)
	if !level.Valid() {
		level = policy.L2
	}
	stepsInfo := make([]policy.StepInfo, 0, len(pl.Pipeline.Steps))
	for _, st := range pl.Pipeline.Steps {
		env := mergedEnv(pl.Pipeline, st)
		stepsInfo = append(stepsInfo, policy.StepInfo{ID: st.ID, Env: env})
	}
	if policy.AnyStepRequiresApproval(stepsInfo, level) {
		if err := s.Store.SetRunStatus(runID, store.RunPendingApproval); err != nil {
			s.mu.Unlock()
			return 0, err
		}
		s.mu.Unlock()
		s.Events.Publish(Event{RunID: runID, Type: EvtRunPending, Message: "awaiting approval"})
		return runID, nil
	}

	if err := s.Store.SetRunStatus(runID, store.RunRunning); err != nil {
		s.mu.Unlock()
		return 0, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.active[runID] = &activeRun{pipelineID: p.ID, cancel: cancel}
	s.mu.Unlock()

	s.Events.Publish(Event{RunID: runID, Type: EvtRunStarted, Message: pipelineName})
	go s.runPipeline(ctx, runID, pl)
	return runID, nil
}

// Cancel requests cancellation of a running run. Pending (held) runs are
// canceled directly; finished runs are ignored.
func (s *Scheduler) Cancel(runID int64) error {
	s.mu.Lock()
	ar, ok := s.active[runID]
	s.mu.Unlock()
	if ok {
		ar.cancel()
		return nil
	}
	if run, err := s.Store.GetRun(runID); err == nil && run.Status == store.RunPendingApproval {
		if steps, err := s.Store.ListRunSteps(runID); err == nil {
			for _, rs := range steps {
				if rs.Status == store.StepPending {
					_ = s.Store.SetRunStepStatus(rs.ID, store.StepCanceled)
				}
			}
		}
		if err := s.Store.SetRunStatus(runID, store.RunCanceled); err != nil {
			return err
		}
		s.Events.Publish(Event{RunID: runID, Type: EvtRunFinished, Message: "canceled"})
		s.notifyTerminal(runID, store.RunCanceled)
		return nil
	}
	return nil
}

// Approve releases a held (pending_approval) run: marks it running and starts
// execution. Returns sql.ErrNoRows if the run does not exist, ErrNotPending if
// the run is not in the pending_approval state.
func (s *Scheduler) Approve(runID int64) error {
	run, err := s.Store.GetRun(runID)
	if err != nil {
		return err
	}
	if run.Status != store.RunPendingApproval {
		return fmt.Errorf("%w: run %d is %q", ErrNotPending, runID, run.Status)
	}
	p, err := s.Store.GetPipeline(run.PipelineID)
	if err != nil {
		return fmt.Errorf("scheduler: approve run %d: %w", runID, err)
	}
	pl, err := pipeline.ParseYAML([]byte(p.YAMLText))
	if err != nil {
		return fmt.Errorf("scheduler: approve run %d: pipeline %q invalid: %w", runID, p.Name, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	s.active[runID] = &activeRun{pipelineID: run.PipelineID, cancel: cancel}
	s.mu.Unlock()
	if err := s.Store.SetRunStatus(runID, store.RunRunning); err != nil {
		cancel()
		s.releaseActive(runID)
		return err
	}
	s.Events.Publish(Event{RunID: runID, Type: EvtRunStarted, Message: "approved"})
	go s.runPipeline(ctx, runID, pl)
	return nil
}

// Reject dismisses a held (pending_approval) run without executing it and
// without a recorded reason.
func (s *Scheduler) Reject(runID int64) error {
	return s.RejectWithReason(runID, "")
}

// RejectWithReason dismisses a held (pending_approval) run without executing
// it, recording the operator-given reason on the run row (runs.reject_reason,
// P7⑧). All pending steps are marked skipped and the run becomes terminal
// "rejected". reason may be empty (the column then stays "").
func (s *Scheduler) RejectWithReason(runID int64, reason string) error {
	run, err := s.Store.GetRun(runID)
	if err != nil {
		return err
	}
	if run.Status != store.RunPendingApproval {
		return fmt.Errorf("%w: run %d is %q", ErrNotPending, runID, run.Status)
	}
	if steps, err := s.Store.ListRunSteps(runID); err == nil {
		for _, rs := range steps {
			if rs.Status == store.StepPending {
				_ = s.Store.SetRunStepStatus(rs.ID, store.StepSkipped)
			}
		}
	}
	if err := s.Store.SetRunStatus(runID, store.RunRejected); err != nil {
		return err
	}
	if reason != "" {
		if err := s.Store.SetRunRejectReason(runID, reason); err != nil {
			log.Printf("scheduler: run %d: record reject reason: %v", runID, err)
		}
	}
	s.Events.Publish(Event{RunID: runID, Type: EvtRunFinished, Message: "rejected"})
	return nil
}

// mergedEnv merges pipeline-level env with step-level env (step wins),
// matching the env seen by runStep.
func mergedEnv(spec pipeline.PipelineSpec, st pipeline.StepDef) map[string]string {
	out := make(map[string]string, len(spec.Env)+len(st.Env))
	for k, v := range spec.Env {
		out[k] = v
	}
	for k, v := range st.Env {
		out[k] = v
	}
	return out
}

// secretRefPattern matches an env value that is exactly a ${NAME} reference
// (NAME = alnum, dot, underscore, hyphen; ≥1 char). Partial references such
// as "x${Y}" are NOT secrets (no leak / no injection).
var secretRefPattern = regexp.MustCompile(`^\$\{([a-zA-Z0-9_.-]+)\}$`)

// validatePipelineSecrets is the P6② fail-fast gate run inside Trigger before
// a run row is created. It errors (wrapped in ErrSecrets) when:
//   - a step env value is exactly ${NAME} but NAME is not in pipeline.secrets,
//   - a declared secret does not exist in the secret store,
//   - secrets are declared but no encryption key is configured (nil vault).
//
// It never mutates state and never logs secret values.
func (s *Scheduler) validatePipelineSecrets(spec pipeline.PipelineSpec) error {
	declared := make(map[string]bool, len(spec.Secrets))
	for _, n := range spec.Secrets {
		declared[n] = true
	}
	// Local consistency: every exact ${NAME} reference in the merged env must
	// be declared in pipeline.secrets — checked even when the declaration list
	// is empty, so a stray ${X} is a broken pipeline, not a silent no-op.
	for _, st := range spec.Steps {
		for _, v := range mergedEnv(spec, st) {
			if m := secretRefPattern.FindStringSubmatch(v); m != nil && !declared[m[1]] {
				return fmt.Errorf("env value ${%s} references a secret not declared in pipeline.secrets", m[1])
			}
		}
	}
	if len(declared) == 0 {
		return nil
	}
	// External checks, only when secrets are actually declared.
	if s.SecretVault == nil {
		return errors.New("pipeline declares secrets but FLOWSTALLION_SECRET_KEY is not set")
	}
	names := make([]string, 0, len(declared))
	for n := range declared {
		names = append(names, n)
	}
	sort.Strings(names) // deterministic error reporting when several are missing
	for _, n := range names {
		ok, err := s.Store.SecretExists(n)
		if err != nil {
			return fmt.Errorf("secret store lookup %q: %w", n, err)
		}
		if !ok {
			return fmt.Errorf("declared secret %q not found in secret store", n)
		}
	}
	return nil
}

// injectSecrets replaces, in memory only, env values that are exactly
// ${NAME} (for NAME in spec.Secrets) with the decrypted secret value.
// Secrets never enter stored run steps, logs, or events.
func (s *Scheduler) injectSecrets(spec pipeline.PipelineSpec, env map[string]string) error {
	if s.SecretVault == nil || len(spec.Secrets) == 0 {
		return nil
	}
	declared := make(map[string]bool, len(spec.Secrets))
	for _, n := range spec.Secrets {
		declared[n] = true
	}
	for k, v := range env {
		m := secretRefPattern.FindStringSubmatch(v)
		if m == nil || !declared[m[1]] {
			continue
		}
		blob, err := s.Store.GetSecret(m[1])
		if err != nil {
			return fmt.Errorf("secret %q: %w", m[1], err)
		}
		plain, err := s.SecretVault.Open(blob)
		if err != nil {
			return fmt.Errorf("secret %q: %w", m[1], err)
		}
		env[k] = string(plain)
	}
	return nil
}

// ActiveCount returns how many runs are currently in flight.
func (s *Scheduler) ActiveCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.active)
}

func (s *Scheduler) releaseActive(runID int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.active, runID)
}

// runPipeline executes all steps of a run honouring the needs-DAG. Steps
// whose needs are satisfied run concurrently; a failed step causes its
// dependents to be skipped.
func (s *Scheduler) runPipeline(ctx context.Context, runID int64, pl pipeline.Pipeline) {
	defer s.releaseActive(runID)
	spec := pl.Pipeline
	steps := spec.Steps

	pending := make(map[string]bool, len(steps))
	for _, st := range steps {
		pending[st.ID] = true
	}
	succeeded := make(map[string]bool, len(steps))
	failed := 0

	for {
		select {
		case <-ctx.Done():
			s.cancelRun(runID)
			return
		default:
		}

		var ready []pipeline.StepDef
		for _, st := range steps {
			if !pending[st.ID] {
				continue
			}
			ok := true
			for _, n := range st.Needs {
				if !succeeded[n] {
					ok = false
					break
				}
			}
			if ok {
				ready = append(ready, st)
			}
		}
		if len(ready) == 0 {
			break
		}

		type outcome struct {
			id string
			ok bool
		}
		outcomes := make(chan outcome, len(ready))
		var wg sync.WaitGroup
		for _, st := range ready {
			pending[st.ID] = false
			wg.Add(1)
			go func(st pipeline.StepDef) {
				defer wg.Done()
				ok := s.runStep(ctx, runID, spec, st)
				outcomes <- outcome{id: st.ID, ok: ok}
			}(st)
		}
		wg.Wait()
		close(outcomes)
		for o := range outcomes {
			if o.ok {
				succeeded[o.id] = true
			} else {
				failed++
			}
		}
	}

	for _, st := range steps {
		if pending[st.ID] {
			s.skipStep(runID, st.ID)
		}
	}
	if failed == 0 {
		s.Store.SetRunStatus(runID, store.RunSuccess)
		s.Events.Publish(Event{RunID: runID, Type: EvtRunFinished, Message: "success"})
		s.notifyTerminal(runID, store.RunSuccess)
	} else {
		s.Store.SetRunStatus(runID, store.RunFailed)
		s.Events.Publish(Event{RunID: runID, Type: EvtRunFinished, Message: "failed"})
		s.notifyTerminal(runID, store.RunFailed)
	}
}

// runStep executes one step and returns whether it succeeded.
func (s *Scheduler) runStep(ctx context.Context, runID int64, spec pipeline.PipelineSpec, st pipeline.StepDef) bool {
	row, err := s.runStepRow(runID, st.ID)
	if err != nil {
		return false
	}

	env := mergedEnv(spec, st)

	// P7⑤: CD steps (k8s_canary / k8s_blue_green) are executed in-process
	// by the canary executor, never dispatched to an agent.
	exec := s.Executor
	if st.Type == "k8s_canary" || st.Type == "k8s_blue_green" {
		if s.CanaryExec == nil {
			_ = s.Store.SetRunStepStatus(row.ID, store.StepFailed)
			s.Events.Publish(Event{RunID: runID, StepID: st.ID, Type: EvtStepFinished,
				Message: "failed: CD executor not configured"})
			return false
		}
		exec = s.CanaryExec
	}

	// P7④: docker_build tag templates ({{sha}}/{{branch}}/{{ts}}) expand
	// here, where the run's trigger metadata is known. Non-build steps
	// never carry templates (rejected at parse), so this is a no-op for
	// them.
	if st.Type == "docker_build" {
		if run, err := s.Store.GetRun(runID); err == nil {
			st.Image = expandImageTemplate(st.Image, run, time.Now().UTC())
		}
	}

	if err := s.injectSecrets(spec, env); err != nil {
		_ = s.Store.SetRunStepStatus(row.ID, store.StepFailed)
		s.Events.Publish(Event{RunID: runID, StepID: st.ID, Type: EvtStepFinished,
			Message: "failed: secret injection: " + err.Error()})
		return false
	}

	_ = s.Store.SetRunStepStatus(row.ID, store.StepRunning)
	s.Events.Publish(Event{RunID: runID, StepID: st.ID, Type: EvtStepStarted})

	lw := &logWriter{complete: func(line string) {
		if _, err := s.Store.AddLog(runID, st.ID, line); err == nil {
			s.Events.Publish(Event{RunID: runID, StepID: st.ID, Type: EvtLog, Message: line})
		}
	}}
	stepCtx, cancel := context.WithTimeout(WithLogWriter(ctx, lw), time.Duration(st.Timeout)*time.Second)
	execErr := exec.Execute(stepCtx, st, runID, env)
	cancel()
	lw.Flush()

	if execErr == nil {
		_ = s.Store.SetRunStepStatus(row.ID, store.StepSuccess)
		s.Events.Publish(Event{RunID: runID, StepID: st.ID, Type: EvtStepFinished, Message: "success"})
		return true
	}
	_ = s.Store.SetRunStepStatus(row.ID, store.StepFailed)
	s.Events.Publish(Event{RunID: runID, StepID: st.ID, Type: EvtStepFinished, Message: "failed: " + execErr.Error()})
	return false
}

// skipStep marks a never-run step as skipped.
func (s *Scheduler) skipStep(runID int64, stepID string) {
	row, err := s.runStepRow(runID, stepID)
	if err != nil {
		return
	}
	_ = s.Store.SetRunStepStatus(row.ID, store.StepSkipped)
}

// cancelRun marks a run and its non-terminal steps as canceled.
func (s *Scheduler) cancelRun(runID int64) {
	if run, err := s.Store.GetRun(runID); err == nil &&
		(run.Status == store.RunSuccess || run.Status == store.RunFailed) {
		return // already terminal
	}
	if steps, err := s.Store.ListRunSteps(runID); err == nil {
		for _, rs := range steps {
			if rs.Status == store.StepPending || rs.Status == store.StepRunning {
				_ = s.Store.SetRunStepStatus(rs.ID, store.StepCanceled)
			}
		}
	}
	_ = s.Store.SetRunStatus(runID, store.RunCanceled)
	s.Events.Publish(Event{RunID: runID, Type: EvtRunFinished, Message: "canceled"})
	s.notifyTerminal(runID, store.RunCanceled)
}

// runStepRow looks up the run_steps row for a step id within a run.
func (s *Scheduler) runStepRow(runID int64, stepID string) (store.RunStep, error) {
	steps, err := s.Store.ListRunSteps(runID)
	if err != nil {
		return store.RunStep{}, err
	}
	for _, rs := range steps {
		if rs.StepID == stepID {
			return rs, nil
		}
	}
	return store.RunStep{}, fmt.Errorf("scheduler: run %d has no step %q", runID, stepID)
}
