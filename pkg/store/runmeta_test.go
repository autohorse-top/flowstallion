// P7②: migration tests for the runs PR-metadata columns
// (pr / base_ref / head_ref / repo_url) and CreateRunMeta round-trips.
package store

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

// legacyRunsSchema is a pre-P7 database: the runs table without the four PR
// columns. Two separate statements because modernc.org/sqlite executes one
// statement per Exec.
var legacyRunsSchema = []string{
	`CREATE TABLE pipelines (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE,
		yaml_text TEXT NOT NULL,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	)`,
	`CREATE TABLE runs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		pipeline_id INTEGER NOT NULL REFERENCES pipelines(id),
		status TEXT NOT NULL DEFAULT 'queued',
		trigger TEXT NOT NULL DEFAULT 'manual',
		source_ref TEXT NOT NULL DEFAULT '',
		started_at TEXT,
		finished_at TEXT,
		created_at TEXT NOT NULL
	)`,
}

// wantPRCols are the P7 columns that must exist after Open() migrates.
var wantPRCols = []string{"pr", "base_ref", "head_ref", "repo_url"}

// assertPRColumns verifies via PRAGMA table_info that all four P7 columns
// are present on the runs table of the DB at path.
func assertPRColumns(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open db for column check: %v", err)
	}
	defer db.Close()
	cols, err := tableColumns(db, "runs")
	if err != nil {
		t.Fatalf("table_info(runs): %v", err)
	}
	for _, c := range wantPRCols {
		if !cols[c] {
			t.Fatalf("runs table missing column %q (have %v)", c, cols)
		}
	}
}

// TestRunLegacyMigration: a pre-P7 database (runs table without the PR
// columns, with one legacy row) must be upgraded in place by Open():
// the columns appear, the legacy row reads back with zero metadata, and
// re-opening (idempotent migrate) must not error.
func TestRunLegacyMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open raw sqlite: %v", err)
	}
	for _, stmt := range legacyRunsSchema {
		if _, err := raw.Exec(stmt); err != nil {
			raw.Close()
			t.Fatalf("create legacy schema: %v", err)
		}
	}
	if _, err := raw.Exec(`INSERT INTO pipelines (name, yaml_text, created_at, updated_at)
		VALUES ('old', 'version: 1', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`); err != nil {
		raw.Close()
		t.Fatalf("insert legacy pipeline: %v", err)
	}
	if _, err := raw.Exec(`INSERT INTO runs (pipeline_id, trigger, source_ref, created_at)
		VALUES (1, 'push', 'main', '2026-01-02T00:00:00Z')`); err != nil {
		raw.Close()
		t.Fatalf("insert legacy run: %v", err)
	}
	raw.Close()

	s, err := Open(path) // migrate(): ALTER TABLE runs ADD COLUMN x4
	if err != nil {
		t.Fatalf("open upgraded db: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	assertPRColumns(t, path)

	// Legacy row survives and reads back with zero/NULL metadata.
	legacy, err := s.GetRun(1)
	if err != nil {
		t.Fatalf("get legacy run: %v", err)
	}
	if legacy.Trigger != "push" || legacy.SourceRef != "main" {
		t.Fatalf("legacy row not preserved: %+v", legacy)
	}
	if legacy.PR != 0 || legacy.BaseRef != "" || legacy.HeadRef != "" || legacy.RepoURL != "" {
		t.Fatalf("legacy row must have zero PR metadata, got %+v", legacy)
	}

	// Idempotency: re-open re-runs migrate() on the upgraded DB; the
	// PRAGMA-guarded ALTERs must be skipped, not fail.
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("re-open upgraded db (idempotent migrate): %v", err)
	}
	defer s2.Close()
	assertPRColumns(t, path)
}

// TestRunFreshDBMeta: on a freshly created DB (columns present from CREATE
// TABLE) both CreateRun (no metadata) and CreateRunMeta (full metadata)
// must round-trip through GetRun and ListRuns.
func TestRunFreshDBMeta(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "fresh.db"))
	if err != nil {
		t.Fatalf("open fresh db: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	pid, err := s.UpsertPipeline("hookdemo", "version: 1\npipeline:\n  name: hookdemo\n  steps:\n    - id: a\n      image: alpine\n      commands: [echo a]\n")
	if err != nil {
		t.Fatalf("upsert pipeline: %v", err)
	}

	// push-style run: zero RunMeta -> all four columns NULL.
	plain, err := s.CreateRun(pid, "push", "main")
	if err != nil {
		t.Fatalf("create plain run: %v", err)
	}
	rp, err := s.GetRun(plain)
	if err != nil {
		t.Fatalf("get plain run: %v", err)
	}
	if rp.PR != 0 || rp.BaseRef != "" || rp.HeadRef != "" || rp.RepoURL != "" {
		t.Fatalf("push run must have zero PR metadata, got %+v", rp)
	}

	// PR run: full metadata.
	meta := RunMeta{PR: 42, HeadRef: "feature/login", BaseRef: "main",
		RepoURL: "https://github.com/owner/hookdemo"}
	prID, err := s.CreateRunMeta(pid, "pull_request", "feature/login", meta)
	if err != nil {
		t.Fatalf("create meta run: %v", err)
	}
	r, err := s.GetRun(prID)
	if err != nil {
		t.Fatalf("get meta run: %v", err)
	}
	if r.Trigger != "pull_request" {
		t.Errorf("trigger = %q, want pull_request", r.Trigger)
	}
	if r.PR != 42 {
		t.Errorf("PR = %d, want 42", r.PR)
	}
	if r.HeadRef != "feature/login" {
		t.Errorf("HeadRef = %q, want feature/login", r.HeadRef)
	}
	if r.BaseRef != "main" {
		t.Errorf("BaseRef = %q, want main", r.BaseRef)
	}
	if r.RepoURL != meta.RepoURL {
		t.Errorf("RepoURL = %q, want %q", r.RepoURL, meta.RepoURL)
	}

	// ListRuns must surface the metadata too.
	runs, err := s.ListRuns(pid, 10)
	if err != nil {
		t.Fatalf("list runs: %v", err)
	}
	var prRun, plainRun *Run
	for i := range runs {
		switch runs[i].ID {
		case prID:
			prRun = &runs[i]
		case plain:
			plainRun = &runs[i]
		}
	}
	if prRun == nil || plainRun == nil {
		t.Fatalf("ListRuns missing rows: %+v", runs)
	}
	if prRun.PR != 42 || prRun.RepoURL != meta.RepoURL {
		t.Errorf("ListRuns PR row metadata wrong: %+v", *prRun)
	}
	if plainRun.PR != 0 || plainRun.HeadRef != "" {
		t.Errorf("ListRuns plain row must have zero metadata: %+v", *plainRun)
	}
}
