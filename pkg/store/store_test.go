package store

import (
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
)

func openTemp(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOpenIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	s1, err := Open(path)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	s1.Close()
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("second Open (idempotent): %v", err)
	}
	s2.Close()
}

func TestUpsertPipeline(t *testing.T) {
	s := openTemp(t)
	id1, err := s.UpsertPipeline("build", "yaml-v1")
	if err != nil {
		t.Fatalf("upsert v1: %v", err)
	}
	id2, err := s.UpsertPipeline("build", "yaml-v2")
	if err != nil {
		t.Fatalf("upsert v2: %v", err)
	}
	if id1 != id2 {
		t.Fatalf("upsert should reuse id, got %d then %d", id1, id2)
	}
	pl, err := s.GetPipelineByName("build")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if pl.YAMLText != "yaml-v2" {
		t.Fatalf("yaml not updated: %q", pl.YAMLText)
	}
	all, err := s.ListPipelines()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("expected 1 pipeline, got %d", len(all))
	}
}

func TestRunLifecycle(t *testing.T) {
	s := openTemp(t)
	pid, _ := s.UpsertPipeline("build", "y")
	rid, err := s.CreateRun(pid, "manual", "main@abc123")
	if err != nil {
		t.Fatalf("create run: %v", err)
	}
	r, _ := s.GetRun(rid)
	if r.Status != RunQueued {
		t.Fatalf("new run status = %q, want queued", r.Status)
	}
	if r.StartedAt != "" {
		t.Fatalf("queued run should have empty started_at, got %q", r.StartedAt)
	}
	if err := s.SetRunStatus(rid, RunRunning); err != nil {
		t.Fatalf("set running: %v", err)
	}
	r, _ = s.GetRun(rid)
	if r.StartedAt == "" {
		t.Fatal("running run should have started_at set")
	}
	if err := s.SetRunStatus(rid, RunSuccess); err != nil {
		t.Fatalf("set success: %v", err)
	}
	r, _ = s.GetRun(rid)
	if r.Status != RunSuccess || r.FinishedAt == "" {
		t.Fatalf("final run = %+v, want success with finished_at", r)
	}
}

func TestAddRunStep(t *testing.T) {
	s := openTemp(t)
	pid, _ := s.UpsertPipeline("build", "y")
	rid, _ := s.CreateRun(pid, "manual", "")
	sid, err := s.AddRunStep(rid, "build", 0, "golang:1.22", `["go build ./..."]`)
	if err != nil {
		t.Fatalf("add step: %v", err)
	}
	if err := s.SetRunStepStatus(sid, StepRunning); err != nil {
		t.Fatalf("step running: %v", err)
	}
	if err := s.SetRunStepStatus(sid, StepSuccess); err != nil {
		t.Fatalf("step success: %v", err)
	}
	steps, err := s.ListRunSteps(rid)
	if err != nil {
		t.Fatalf("list steps: %v", err)
	}
	if len(steps) != 1 || steps[0].Command != `["go build ./..."]` {
		t.Fatalf("step command roundtrip = %+v", steps)
	}
}

func TestSaveAndGetRunAnalysis(t *testing.T) {
	s := openTemp(t)
	pid, _ := s.UpsertPipeline("build", "y")
	rid, _ := s.CreateRun(pid, "manual", "")
	if _, err := s.AddRunStep(rid, "build", 0, "img", `["make"]`); err != nil {
		t.Fatalf("add step: %v", err)
	}

	// No analysis yet → sql.ErrNoRows
	if _, err := s.GetRunAnalysis(rid); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("get before save err = %v, want sql.ErrNoRows", err)
	}

	a := RunAnalysis{
		RunID: rid, StepID: "build", Kind: "rule",
		RootCause: "build failed", Detail: "make: *** Error",
		SuggestedFix: "fix deps", Command: `["make"]`,
	}
	if err := s.SaveRunAnalysis(a); err != nil {
		t.Fatalf("save analysis: %v", err)
	}
	got, err := s.GetRunAnalysis(rid)
	if err != nil {
		t.Fatalf("get analysis: %v", err)
	}
	if got.StepID != "build" || got.Kind != "rule" || got.RootCause != "build failed" {
		t.Fatalf("analysis = %+v", got)
	}
	if got.CreatedAt == "" {
		t.Fatal("created_at should be set on save")
	}

	// Upsert: second save replaces, keeps run
	a2 := a
	a2.Kind = "llm"
	a2.RootCause = "upgraded cause"
	if err := s.SaveRunAnalysis(a2); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got2, _ := s.GetRunAnalysis(rid)
	if got2.Kind != "llm" || got2.RootCause != "upgraded cause" {
		t.Fatalf("after upsert = %+v", got2)
	}
	if got2.CreatedAt != got.CreatedAt {
		t.Fatalf("upsert should keep original created_at: %q vs %q", got2.CreatedAt, got.CreatedAt)
	}

	// P7⑥: multiple kinds coexist; AI kinds do not change the primary (rule/llm).
	list, err := s.ListRunAnalyses(rid)
	if err != nil {
		t.Fatalf("list analyses: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("analyses = %d rows, want 2 (rule+llm)", len(list))
	}
	if err := s.SaveRunAnalysis(RunAnalysis{
		RunID: rid, Kind: "pr_review", RootCause: "PR review: 1 finding",
	}); err != nil {
		t.Fatalf("save pr_review (empty step_id): %v", err)
	}
	got3, err := s.GetRunAnalysis(rid)
	if err != nil {
		t.Fatalf("get after pr_review: %v", err)
	}
	if got3.Kind != "llm" {
		t.Fatalf("primary after pr_review = %q, want llm", got3.Kind)
	}
	if list3, _ := s.ListRunAnalyses(rid); len(list3) != 3 {
		t.Fatalf("analyses = %d rows, want 3", len(list3))
	}
}

// TestRunAnalysisLegacyMigration builds a pre-P7⑥ database (one-row-per-run
// run_analysis, no surrogate id, no PR columns on runs) and verifies Open()
// migrates it in place while preserving the stored row.
func TestRunAnalysisLegacyMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	oldSchema := []string{
		`CREATE TABLE pipelines (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			yaml_text TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL)`,
		`CREATE TABLE runs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			pipeline_id INTEGER NOT NULL REFERENCES pipelines(id),
			status TEXT NOT NULL DEFAULT 'queued',
			trigger TEXT NOT NULL DEFAULT 'manual',
			source_ref TEXT NOT NULL DEFAULT '',
			started_at TEXT,
			finished_at TEXT,
			created_at TEXT NOT NULL)`,
		`CREATE TABLE run_analysis (
			run_id INTEGER NOT NULL PRIMARY KEY REFERENCES runs(id),
			step_id TEXT NOT NULL,
			kind TEXT NOT NULL,
			root_cause TEXT NOT NULL,
			detail TEXT NOT NULL,
			suggested_fix TEXT NOT NULL,
			command TEXT NOT NULL,
			log_excerpt TEXT NOT NULL,
			created_at TEXT NOT NULL)`,
		`INSERT INTO pipelines VALUES (1, 'p', 'y', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`,
		`INSERT INTO runs VALUES (1, 1, 'failed', 'manual', '', NULL, NULL, '2026-01-01T00:00:00Z')`,
		`INSERT INTO run_analysis VALUES (1, 's', 'rule', 'rc', 'd', 'sf', 'c', 'le', '2026-01-01T00:00:00Z')`,
	}
	for _, stmt := range oldSchema {
		if _, err := db.Exec(stmt); err != nil {
			db.Close()
			t.Fatalf("legacy stmt: %v", err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close legacy: %v", err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatalf("open migrated db: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	a, err := s.GetRunAnalysis(1)
	if err != nil {
		t.Fatalf("get legacy row: %v", err)
	}
	if a.StepID != "s" || a.Kind != "rule" || a.RootCause != "rc" {
		t.Fatalf("legacy row after migration = %+v", a)
	}
	// New schema must accept a second kind for the same run.
	if err := s.SaveRunAnalysis(RunAnalysis{
		RunID: 1, Kind: "test_selection", RootCause: "ts",
	}); err != nil {
		t.Fatalf("save second kind: %v", err)
	}
	list, err := s.ListRunAnalyses(1)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("analyses after migration = %d rows, want 2", len(list))
	}
}

func TestLogsAppendAndList(t *testing.T) {
	s := openTemp(t)
	pid, _ := s.UpsertPipeline("build", "y")
	rid, _ := s.CreateRun(pid, "manual", "")
	lines := []string{"line1", "line2", "line3"}
	var seqs []int64
	for _, l := range lines {
		seq, err := s.AddLog(rid, "build", l)
		if err != nil {
			t.Fatalf("add log: %v", err)
		}
		seqs = append(seqs, seq)
	}
	for i, sq := range seqs {
		if sq != int64(i+1) {
			t.Fatalf("seq %d = %d, want %d", i, sq, i+1)
		}
	}
	all, err := s.ListLogs(rid, "build", 0, 0)
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 logs, got %d", len(all))
	}
	tail, err := s.ListLogs(rid, "build", 2, 0)
	if err != nil {
		t.Fatalf("list tail: %v", err)
	}
	if len(tail) != 1 || tail[0].Seq != 3 || tail[0].Line != "line3" {
		t.Fatalf("tail = %+v, want [seq3 line3]", tail)
	}
}

func TestAgentRegisterIdempotent(t *testing.T) {
	s := openTemp(t)
	id1, isNew1, err := s.RegisterAgent("agent-a")
	if err != nil {
		t.Fatalf("register 1: %v", err)
	}
	if !isNew1 {
		t.Fatal("first register should be new")
	}
	id2, isNew2, err := s.RegisterAgent("agent-a")
	if err != nil {
		t.Fatalf("register 2: %v", err)
	}
	if isNew2 {
		t.Fatal("second register should not be new")
	}
	if id1 != id2 {
		t.Fatalf("agent id changed: %d then %d", id1, id2)
	}
}

func TestListRuns(t *testing.T) {
	s := openTemp(t)
	pid, _ := s.UpsertPipeline("build", "y")
	for i := 0; i < 5; i++ {
		if _, err := s.CreateRun(pid, "manual", ""); err != nil {
			t.Fatalf("create run %d: %v", i, err)
		}
	}
	runs, err := s.ListRuns(pid, 3)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(runs) != 3 {
		t.Fatalf("expected 3 runs, got %d", len(runs))
	}
	all, _ := s.ListRuns(0, 0)
	if len(all) != 5 {
		t.Fatalf("expected 5 runs, got %d", len(all))
	}
}

// TestRunRejectReason (P7⑧): empty default on fresh rows, set/get roundtrip,
// visibility through ListRuns, and a miss on an unknown run id.
func TestRunRejectReason(t *testing.T) {
	s := openTemp(t)
	pid, _ := s.UpsertPipeline("build", "y")
	rid, err := s.CreateRun(pid, "manual", "")
	if err != nil {
		t.Fatalf("create run: %v", err)
	}

	r, err := s.GetRun(rid)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if r.RejectReason != "" {
		t.Fatalf("fresh run reject reason = %q, want empty", r.RejectReason)
	}

	if err := s.SetRunRejectReason(rid, "bad deploy target"); err != nil {
		t.Fatalf("set reject reason: %v", err)
	}
	r, err = s.GetRun(rid)
	if err != nil {
		t.Fatalf("get after set: %v", err)
	}
	if r.RejectReason != "bad deploy target" {
		t.Fatalf("reject reason = %q, want %q", r.RejectReason, "bad deploy target")
	}

	runs, err := s.ListRuns(pid, 10)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(runs) != 1 || runs[0].RejectReason != "bad deploy target" {
		t.Fatalf("ListRuns = %+v, want one run carrying the reject reason", runs)
	}

	if err := s.SetRunRejectReason(999999, "x"); err == nil {
		t.Fatal("SetRunRejectReason on missing run should fail")
	}
}

// TestRunRejectReasonLegacyBackfill builds a pre-P7⑧ database (runs table
// without reject_reason, pre-P7 PR metadata) and verifies Open() migrates it
// in place: existing rows get the empty default, new sets persist.
func TestRunRejectReasonLegacyBackfill(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	oldSchema := []string{
		`CREATE TABLE pipelines (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			yaml_text TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL)`,
		`CREATE TABLE runs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			pipeline_id INTEGER NOT NULL REFERENCES pipelines(id),
			status TEXT NOT NULL DEFAULT 'queued',
			trigger TEXT NOT NULL DEFAULT 'manual',
			source_ref TEXT NOT NULL DEFAULT '',
			started_at TEXT,
			finished_at TEXT,
			created_at TEXT NOT NULL)`,
		`INSERT INTO pipelines VALUES (1, 'p', 'y', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`,
		`INSERT INTO runs VALUES (1, 1, 'rejected', 'manual', '', NULL, NULL, '2026-01-01T00:00:00Z')`,
	}
	for _, stmt := range oldSchema {
		if _, err := db.Exec(stmt); err != nil {
			db.Close()
			t.Fatalf("legacy stmt: %v", err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close legacy: %v", err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatalf("open migrated db: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	r, err := s.GetRun(1)
	if err != nil {
		t.Fatalf("get legacy run: %v", err)
	}
	if r.RejectReason != "" {
		t.Fatalf("backfilled reject reason = %q, want empty", r.RejectReason)
	}
	if err := s.SetRunRejectReason(1, "legacy rejected"); err != nil {
		t.Fatalf("set on legacy row: %v", err)
	}
	r, err = s.GetRun(1)
	if err != nil {
		t.Fatalf("get after set: %v", err)
	}
	if r.RejectReason != "legacy rejected" {
		t.Fatalf("reject reason = %q, want %q", r.RejectReason, "legacy rejected")
	}
}

func TestConcurrentAppend(t *testing.T) {
	s := openTemp(t)
	pid, _ := s.UpsertPipeline("build", "y")
	rid, _ := s.CreateRun(pid, "manual", "")
	const workers = 8
	const per = 25
	var wg sync.WaitGroup
	errCh := make(chan error, workers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < per; i++ {
				if _, err := s.AddLog(rid, "build", fmt.Sprintf("w%d-%d", w, i)); err != nil {
					errCh <- err
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent add log: %v", err)
	}
	logs, err := s.ListLogs(rid, "build", 0, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(logs) != workers*per {
		t.Fatalf("expected %d logs, got %d", workers*per, len(logs))
	}
	seen := make(map[int64]bool, len(logs))
	for _, l := range logs {
		if seen[l.Seq] {
			t.Fatalf("duplicate seq %d", l.Seq)
		}
		seen[l.Seq] = true
	}
}
