package scheduler

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/flowstallion/flowstallion/pkg/store"
)

// ---------------------------------------------------------------------------
// YAML fixtures for the cron (schedule-trigger) tests
// ---------------------------------------------------------------------------

const cronPipeYAML = `
version: 1
pipeline:
  name: cronpipe
  trigger:
    - event: schedule
      cron: "0 * * * *"
  steps:
    - id: a
      image: alpine
      commands: [echo a]
`

const pushPipeYAML = `
version: 1
pipeline:
  name: pushpipe
  trigger:
    - event: push
  steps:
    - id: a
      image: alpine
      commands: [echo a]
`

// badCronYAML passes pipeline.ParseYAML (cron is only length-checked there)
// but is unparseable by the schedule parser — the tick must skip it.
const badCronYAML = `
version: 1
pipeline:
  name: badcron
  trigger:
    - event: schedule
      cron: "99 * * * *"
  steps:
    - id: a
      image: alpine
      commands: [echo a]
`

const slowCronYAML = `
version: 1
pipeline:
  name: slowcron
  concurrency: 1
  trigger:
    - event: schedule
      cron: "0 * * * *"
  steps:
    - id: a
      image: alpine
      commands: [echo a]
`

// runsOf returns the stored runs of the named pipeline (newest first).
func (ts *testScheduler) runsOf(name string) []store.Run {
	ts.t.Helper()
	p, err := ts.st.GetPipelineByName(name)
	if err != nil {
		ts.t.Fatalf("get pipeline %q: %v", name, err)
	}
	runs, err := ts.st.ListRuns(p.ID, 100)
	if err != nil {
		ts.t.Fatalf("list runs for %q: %v", name, err)
	}
	return runs
}

// ---------------------------------------------------------------------------
// CronTick tests (injected clock — no real waiting)
// ---------------------------------------------------------------------------

// TestCronTickFiresDueAndNoDuplicate: with no watermark the first tick fires
// exactly one run; a second tick in the same slot must not duplicate it.
func TestCronTickFiresDueAndNoDuplicate(t *testing.T) {
	ts := newTestScheduler(t)
	ts.upsert("cronpipe", cronPipeYAML)
	now := time.Date(2026, 10, 26, 12, 0, 5, 0, time.UTC)
	ts.s.NowFn = func() time.Time { return now }

	if err := ts.s.CronTick(); err != nil {
		t.Fatalf("tick 1: %v", err)
	}
	runs := ts.runsOf("cronpipe")
	if len(runs) != 1 {
		t.Fatalf("after tick 1: %d runs, want 1", len(runs))
	}
	if runs[0].Trigger != "schedule" {
		t.Fatalf("trigger = %q, want schedule", runs[0].Trigger)
	}
	wm, ok, err := ts.st.GetLastScheduleFire("cronpipe|0 * * * *")
	if err != nil || !ok {
		t.Fatalf("watermark after tick 1: ok=%v err=%v, want set", ok, err)
	}
	if !wm.Equal(now) {
		t.Fatalf("watermark = %s, want the tick time %s", wm, now)
	}

	if err := ts.s.CronTick(); err != nil {
		t.Fatalf("tick 2: %v", err)
	}
	if got := len(ts.runsOf("cronpipe")); got != 1 {
		t.Fatalf("after tick 2: %d runs, want 1 (no duplicate)", got)
	}
}

// TestCronTickNotDue: a watermark inside the current slot means the next fire
// is a full slot away — no run.
func TestCronTickNotDue(t *testing.T) {
	ts := newTestScheduler(t)
	ts.upsert("cronpipe", cronPipeYAML)
	if err := ts.st.SetLastScheduleFire("cronpipe|0 * * * *",
		time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("seed watermark: %v", err)
	}
	now := time.Date(2026, 10, 26, 12, 30, 0, 0, time.UTC)
	ts.s.NowFn = func() time.Time { return now }

	if err := ts.s.CronTick(); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if got := len(ts.runsOf("cronpipe")); got != 0 {
		t.Fatalf("not-due tick: %d runs, want 0", got)
	}
}

// TestCronTickCatchUpOnce: an outage spanning three missed slots (10:00,
// 11:00, 12:00) produces exactly ONE catch-up run; the watermark advances to
// the tick time so the next tick cannot replay the missed slots.
func TestCronTickCatchUpOnce(t *testing.T) {
	ts := newTestScheduler(t)
	ts.upsert("cronpipe", cronPipeYAML)
	if err := ts.st.SetLastScheduleFire("cronpipe|0 * * * *",
		time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("seed watermark: %v", err)
	}
	now := time.Date(2026, 10, 26, 12, 30, 0, 0, time.UTC)
	ts.s.NowFn = func() time.Time { return now }

	if err := ts.s.CronTick(); err != nil {
		t.Fatalf("tick 1: %v", err)
	}
	if got := len(ts.runsOf("cronpipe")); got != 1 {
		t.Fatalf("catch-up: %d runs, want exactly 1", got)
	}
	if err := ts.s.CronTick(); err != nil {
		t.Fatalf("tick 2: %v", err)
	}
	if got := len(ts.runsOf("cronpipe")); got != 1 {
		t.Fatalf("after tick 2: %d runs, want 1 (missed slots must not replay)", got)
	}
}

// TestCronTickIgnoresNonScheduleTriggers: pipelines whose triggers are not
// `event: schedule` are never fired by the cron loop.
func TestCronTickIgnoresNonScheduleTriggers(t *testing.T) {
	ts := newTestScheduler(t)
	ts.upsert("pushpipe", pushPipeYAML)
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	ts.s.NowFn = func() time.Time { return now }

	if err := ts.s.CronTick(); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if got := len(ts.runsOf("pushpipe")); got != 0 {
		t.Fatalf("push-only pipeline: %d runs, want 0", got)
	}
}

// TestCronTickSkipsBrokenPipelines: invalid YAML and an unparseable cron must
// be skipped (logged, not fatal) while a healthy pipeline in the same store
// still fires.
func TestCronTickSkipsBrokenPipelines(t *testing.T) {
	ts := newTestScheduler(t)
	if _, err := ts.st.UpsertPipeline("broken", "version: 1\npipeline: {"); err != nil {
		t.Fatalf("upsert broken: %v", err)
	}
	ts.upsert("badcron", badCronYAML)
	ts.upsert("cronpipe", cronPipeYAML)
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	ts.s.NowFn = func() time.Time { return now }

	if err := ts.s.CronTick(); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if got := len(ts.runsOf("cronpipe")); got != 1 {
		t.Fatalf("healthy pipeline: %d runs, want 1", got)
	}
	if got := len(ts.runsOf("badcron")); got != 0 {
		t.Fatalf("unparseable cron: %d runs, want 0", got)
	}
}

// TestCronTickConsumesSlotWhenTriggerLimited: when the pipeline is at its
// concurrency limit, the failed trigger still consumes the slot (watermark
// advanced) so the tick loop cannot retry-storm on every tick.
func TestCronTickConsumesSlotWhenTriggerLimited(t *testing.T) {
	ts := newTestScheduler(t)
	ts.upsert("slowcron", slowCronYAML)
	ts.fx.delay = 2 * time.Second

	occupy, err := ts.s.Trigger("slowcron", "manual", "")
	if err != nil {
		t.Fatalf("occupy trigger: %v", err)
	}
	_ = occupy
	if err := ts.st.SetLastScheduleFire("slowcron|0 * * * *",
		time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("seed watermark: %v", err)
	}
	now := time.Date(2026, 10, 26, 12, 30, 0, 0, time.UTC)
	ts.s.NowFn = func() time.Time { return now }

	if err := ts.s.CronTick(); err != nil {
		t.Fatalf("tick: %v", err)
	}
	runs := ts.runsOf("slowcron")
	if len(runs) != 1 || runs[0].Trigger != "manual" {
		t.Fatalf("after tick: %+v, want exactly the manual run", runs)
	}
	wm, ok, err := ts.st.GetLastScheduleFire("slowcron|0 * * * *")
	if err != nil || !ok || !wm.Equal(now) {
		t.Fatalf("watermark = (%s, %v, %v), want tick time %s (slot consumed despite ErrLimit)",
			wm, ok, err, now)
	}
	if err := ts.s.CronTick(); err != nil {
		t.Fatalf("tick 2: %v", err)
	}
	if got := len(ts.runsOf("slowcron")); got != 1 {
		t.Fatalf("after tick 2: %d runs, want 1 (no retry storm)", got)
	}
}

// TestCronTickNoRefireAfterRestart simulates a restart: the same on-disk DB is
// reopened by a fresh Scheduler at the same clock time; the already-consumed
// slot must not fire again (watermark persisted in schedule_state).
func TestCronTickNoRefireAfterRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "restart.db")
	fx := newFakeExecutor()

	st1, err := store.Open(path)
	if err != nil {
		t.Fatalf("open 1: %v", err)
	}
	id, err := st1.UpsertPipeline("cronpipe", cronPipeYAML)
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	s1 := New(st1, fx)
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	s1.NowFn = func() time.Time { return now }
	if err := s1.CronTick(); err != nil {
		t.Fatalf("tick 1: %v", err)
	}
	runs, err := st1.ListRuns(id, 100)
	if err != nil {
		t.Fatalf("list runs 1: %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("after tick 1: %d runs, want 1", len(runs))
	}
	// Wait for the background run to reach a non-active status before
	// closing the DB, otherwise the reopen below can hit SQLITE_BUSY.
	for i := 0; i < 200; i++ {
		r, err := st1.GetRun(runs[0].ID)
		if err != nil {
			t.Fatalf("get run: %v", err)
		}
		if r.Status != store.RunQueued && r.Status != store.RunRunning {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(30 * time.Millisecond)
	st1.Close()

	// "Restart": reopen the same DB with a fresh scheduler, same clock.
	st2, err := store.Open(path)
	if err != nil {
		t.Fatalf("open 2: %v", err)
	}
	defer st2.Close()
	s2 := New(st2, fx)
	s2.NowFn = func() time.Time { return now }
	if err := s2.CronTick(); err != nil {
		t.Fatalf("tick after restart: %v", err)
	}
	runs, err = st2.ListRuns(id, 100)
	if err != nil {
		t.Fatalf("list runs 2: %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("after restart: %d runs, want 1 (no re-fire of consumed slot)", len(runs))
	}
}

// TestCronTickEmptyStore: a scheduler with no pipelines ticks cleanly.
func TestCronTickEmptyStore(t *testing.T) {
	ts := newTestScheduler(t)
	ts.s.NowFn = func() time.Time { return time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC) }
	if err := ts.s.CronTick(); err != nil {
		t.Fatalf("tick on empty store: %v", err)
	}
}
