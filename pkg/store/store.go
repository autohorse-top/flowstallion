// Package store is the FlowStallion SQLite persistence layer.
//
// It uses a pure-Go SQLite driver (modernc.org/sqlite, no CGO) so the
// scheduler stays a single static binary. All SQL is parameterised; no
// user-controlled string is ever concatenated into a query.
package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Run lifecycle statuses.
const (
	RunQueued   = "queued"
	RunRunning  = "running"
	RunSuccess  = "success"
	RunFailed   = "failed"
	RunCanceled = "canceled"
	// RunPendingApproval: held by the policy gateway awaiting a human
	// decision (approve / reject). Not yet started; no steps ran.
	RunPendingApproval = "pending_approval"
	// RunRejected: held run dismissed without execution.
	RunRejected = "rejected"
)

// Step lifecycle statuses.
const (
	StepPending  = "pending"
	StepRunning  = "running"
	StepSuccess  = "success"
	StepFailed   = "failed"
	StepSkipped  = "skipped"
	StepCanceled = "canceled"
)

// Pipeline is a stored pipeline definition (name + raw YAML text).
type Pipeline struct {
	ID        int64
	Name      string
	YAMLText  string
	CreatedAt string
	UpdatedAt string
}

// Run is one execution of a pipeline.
type Run struct {
	ID         int64
	PipelineID int64
	Status     string
	Trigger    string
	SourceRef  string
	StartedAt  string
	FinishedAt string
	CreatedAt  string
	// P7: optional trigger metadata (GitHub pull_request). PR == 0 and the
	// ref/URL fields == "" mean the run was not PR-triggered (columns are
	// NULL for push / manual / schedule / canary runs).
	PR      int
	BaseRef string
	HeadRef string
	RepoURL string
	// P7④: commit SHA for the triggering push (payload "after") or PR
	// (head.SHA); "" for manual / schedule runs. Feeds {{sha}} image templates.
	SHA string
	// P7⑧: operator reason recorded when a held run is rejected at the
	// policy gate ("" for non-rejected runs or a reject without reason).
	RejectReason string
}

// RunMeta carries optional trigger metadata stored alongside the run row.
// The zero value means "no metadata" (all four columns stay NULL).
type RunMeta struct {
	PR      int    // pull request number; 0 = not a PR run
	HeadRef string // PR head branch (or source branch)
	BaseRef string // PR base branch
	RepoURL string // repository html_url
	SHA     string // P7④: triggering commit SHA (payload "after" / PR head.SHA)
}

// RunStep is one step within a run. Command holds the JSON-encoded command
// list captured at scheduling time ("" on pre-P2 rows). Outputs holds the
// JSON-encoded step outputs written by the agent at finish time ("" when the
// step produced none; P7④: docker_build writes {"image_ref": "<ref>"}).
type RunStep struct {
	ID         int64
	RunID      int64
	StepID     string
	StepIndex  int
	Status     string
	Image      string
	Command    string
	Outputs    string
	StartedAt  string
	FinishedAt string
}

// runAnalysisSchema is the run_analysis DDL (P7⑥): one row per (run_id,
// kind), so a single run can hold the RCA report (rule/llm) alongside the
// AI analyses (pr_review / test_selection).
const runAnalysisSchema = `CREATE TABLE IF NOT EXISTS run_analysis (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	run_id INTEGER NOT NULL REFERENCES runs(id),
	step_id TEXT NOT NULL,
	kind TEXT NOT NULL,
	root_cause TEXT NOT NULL,
	detail TEXT NOT NULL,
	suggested_fix TEXT NOT NULL,
	command TEXT NOT NULL,
	log_excerpt TEXT NOT NULL,
	created_at TEXT NOT NULL,
	UNIQUE (run_id, kind)
)`

// RunAnalysis is a structured analysis report for a run (one row per
// (run, kind), produced by the AI agent).
type RunAnalysis struct {
	RunID        int64
	StepID       string
	Kind         string // "rule" | "llm" | "pr_review" | "test_selection"
	RootCause    string
	Detail       string
	SuggestedFix string
	Command      string
	LogExcerpt   string
	CreatedAt    string
}

// LogRow is a single line of a step's log stream. Seq is the monotonic
// per-(run, step) sequence number (the row id), which SSE clients use as
// their "last seen" cursor.
type LogRow struct {
	Seq  int64
	Line string
	TS   string
}

// Store wraps an open SQLite database.
type Store struct {
	db *sql.DB
}

// Open opens (or creates) the SQLite database at path, applies pragmas and
// ensures the schema exists. It is safe to call on an already-migrated DB.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("store: open %q: %w", path, err)
	}
	// A single connection keeps the writer serialised so concurrent callers
	// never hit SQLITE_BUSY; WAL still lets a reader make progress.
	db.SetMaxOpenConns(1)

	for _, p := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA foreign_keys=ON",
	} {
		if _, err := db.Exec(p); err != nil {
			db.Close()
			return nil, fmt.Errorf("store: pragma: %w", err)
		}
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: migrate: %w", err)
	}
	return &Store{db: db}, nil
}

// migrate creates tables and indexes if they do not already exist.
func migrate(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS pipelines (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			yaml_text TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS runs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			pipeline_id INTEGER NOT NULL REFERENCES pipelines(id),
			status TEXT NOT NULL DEFAULT 'queued',
			trigger TEXT NOT NULL DEFAULT 'manual',
			source_ref TEXT NOT NULL DEFAULT '',
			sha TEXT NOT NULL DEFAULT '',
			pr INTEGER,
			base_ref TEXT,
			head_ref TEXT,
			repo_url TEXT,
			reject_reason TEXT NOT NULL DEFAULT '',
			started_at TEXT,
			finished_at TEXT,
			created_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_runs_pipeline ON runs (pipeline_id, id)`,
		`CREATE TABLE IF NOT EXISTS run_steps (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			run_id INTEGER NOT NULL REFERENCES runs(id),
			step_id TEXT NOT NULL,
			step_index INTEGER NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending',
			image TEXT NOT NULL,
			command TEXT NOT NULL DEFAULT '',
			outputs TEXT NOT NULL DEFAULT '',
			started_at TEXT,
			finished_at TEXT,
			UNIQUE (run_id, step_index)
		)`,
		`CREATE TABLE IF NOT EXISTS logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			run_id INTEGER NOT NULL REFERENCES runs(id),
			step_id TEXT NOT NULL,
			line TEXT NOT NULL,
			ts TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_logs_lookup ON logs (run_id, step_id, id)`,
		`CREATE TABLE IF NOT EXISTS agents (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			last_heartbeat TEXT NOT NULL,
			created_at TEXT NOT NULL
		)`,
		runAnalysisSchema,
		`CREATE TABLE IF NOT EXISTS canary_releases (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			namespace TEXT NOT NULL,
			strategy TEXT NOT NULL DEFAULT 'canary',
			stable_image TEXT NOT NULL,
			canary_image TEXT NOT NULL,
			source_ref TEXT NOT NULL DEFAULT '',
			run_id INTEGER NOT NULL DEFAULT 0,
			replicas INTEGER NOT NULL DEFAULT 2,
			port INTEGER NOT NULL DEFAULT 8080,
			threshold REAL NOT NULL DEFAULT 0.3,
			min_samples INTEGER NOT NULL DEFAULT 20,
			warmup_s REAL NOT NULL DEFAULT 10,
			observe_s REAL NOT NULL DEFAULT 20,
			state TEXT NOT NULL DEFAULT 'pending',
			reason TEXT NOT NULL DEFAULT '',
			canary_start TEXT,
			applying_since TEXT NOT NULL DEFAULT '',
			scrape_failures INTEGER NOT NULL DEFAULT 0,
			last_err_rate REAL NOT NULL DEFAULT 0,
			last_requests INTEGER NOT NULL DEFAULT 0,
			last_errors INTEGER NOT NULL DEFAULT 0,
			baseline_requests INTEGER NOT NULL DEFAULT 0,
			baseline_errors INTEGER NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			finished_at TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS canary_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			release_id INTEGER NOT NULL REFERENCES canary_releases(id),
			ts TEXT NOT NULL,
			state TEXT NOT NULL,
			detail TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_canary_events_release ON canary_events (release_id, id)`,
		`CREATE TABLE IF NOT EXISTS run_scans (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			run_id INTEGER NOT NULL REFERENCES runs(id),
			tool TEXT NOT NULL,
			target TEXT NOT NULL,
			mode TEXT NOT NULL,
			exit_code INTEGER NOT NULL DEFAULT 0,
			findings_count INTEGER NOT NULL DEFAULT 0,
			severity_json TEXT NOT NULL DEFAULT '{}',
			report_json TEXT NOT NULL,
			truncated INTEGER NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_run_scans_run ON run_scans (run_id, id)`,
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			role TEXT NOT NULL CHECK (role IN ('admin','operator','viewer')),
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS sessions (
			token TEXT PRIMARY KEY,
			user_id INTEGER NOT NULL REFERENCES users(id),
			created_at TEXT NOT NULL,
			expires_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions (expires_at)`,
		`CREATE TABLE IF NOT EXISTS secrets (
			name TEXT PRIMARY KEY,
			data BLOB NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		// P7③: cron schedule watermark (last fire per pipeline+cron key).
		`CREATE TABLE IF NOT EXISTS schedule_state (
			key TEXT PRIMARY KEY,
			last_fire TEXT NOT NULL
		)`,
		// Task ③: append-only audit event stream (no UPDATE/DELETE paths).
		`CREATE TABLE IF NOT EXISTS audit_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ts TEXT NOT NULL,
			actor TEXT NOT NULL,
			action TEXT NOT NULL,
			target TEXT NOT NULL,
			outcome TEXT NOT NULL,
			detail TEXT NOT NULL DEFAULT '',
			src TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_events (actor, id)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events (action, id)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			return fmt.Errorf("exec %s: %w", head(s), err)
		}
	}
	// Backfill pre-P2 databases: CREATE TABLE IF NOT EXISTS does not add
	// the command column to an existing run_steps table.
	if _, err := db.Exec(`ALTER TABLE run_steps ADD COLUMN command TEXT NOT NULL DEFAULT ''`); err != nil {
		if !strings.Contains(err.Error(), "duplicate column") {
			return fmt.Errorf("migrate run_steps.command: %w", err)
		}
	}
	// P7④: backfill pre-P7④ databases with run_steps.outputs (JSON step
	// outputs, e.g. docker_build's image_ref).
	if _, err := db.Exec(`ALTER TABLE run_steps ADD COLUMN outputs TEXT NOT NULL DEFAULT ''`); err != nil {
		if !strings.Contains(err.Error(), "duplicate column") {
			return fmt.Errorf("migrate run_steps.outputs: %w", err)
		}
	}
	// Backfill pre-baseline canary databases (m-3 windowed error rate) and
	// pre-P4 databases (P4: optional source_ref, the git ref the canary
	// image was built from). Idempotent: on a fresh DB the column already
	// exists from CREATE TABLE, so the ALTER hits "duplicate column" and is
	// ignored.
	for _, col := range []struct {
		name, def string
	}{
		{"baseline_requests", "INTEGER NOT NULL DEFAULT 0"},
		{"baseline_errors", "INTEGER NOT NULL DEFAULT 0"},
		{"applying_since", "TEXT NOT NULL DEFAULT ''"},
		{"source_ref", "TEXT NOT NULL DEFAULT ''"},
		// P7⑤: run-bound canaries are driven synchronously by the step
		// executor; the background TickAll only advances API-created ones.
		{"run_id", "INTEGER NOT NULL DEFAULT 0"},
		// Blue-green: release strategy ("canary" | "blue_green"). Legacy
		// rows backfill to "canary" — the original isolated-canary behavior.
		{"strategy", "TEXT NOT NULL DEFAULT 'canary'"},
	} {
		if _, err := db.Exec(`ALTER TABLE canary_releases ADD COLUMN ` + col.name + ` ` + col.def); err != nil {
			if !strings.Contains(err.Error(), "duplicate column") {
				return fmt.Errorf("migrate canary_releases.%s: %w", col.name, err)
			}
		}
	}
	// P7: runs PR trigger metadata (pr / base_ref / head_ref / repo_url).
	// Unlike the backfills above (which rely on the "duplicate column" error),
	// these four columns are added only when a PRAGMA table_info check shows
	// they are missing, so a pre-P7 database is upgraded in place and a fresh
	// database (columns present from CREATE TABLE) skips the ALTER entirely.
	// All four are nullable: push / manual / schedule / canary runs leave them
	// NULL; only pull_request-triggered runs fill them.
	if cols, err := tableColumns(db, "runs"); err != nil {
		return fmt.Errorf("migrate runs columns: %w", err)
	} else {
		for _, col := range []struct {
			name, def string
		}{
			{"pr", "INTEGER"},
			{"base_ref", "TEXT"},
			{"head_ref", "TEXT"},
			{"repo_url", "TEXT"},
			{"sha", "TEXT NOT NULL DEFAULT ''"},
		} {
			if !cols[col.name] {
				if _, err := db.Exec(`ALTER TABLE runs ADD COLUMN ` + col.name + ` ` + col.def); err != nil {
					return fmt.Errorf("migrate runs.%s: %w", col.name, err)
				}
			}
		}
	}
	// P7⑧: backfill pre-P7⑧ databases with runs.reject_reason (reason
	// recorded when a held run is rejected at the policy gate). Idempotent:
	// on a fresh DB the column already exists from CREATE TABLE, so the
	// ALTER hits "duplicate column" and is ignored.
	if _, err := db.Exec(`ALTER TABLE runs ADD COLUMN reject_reason TEXT NOT NULL DEFAULT ''`); err != nil {
		if !strings.Contains(err.Error(), "duplicate column") {
			return fmt.Errorf("migrate runs.reject_reason: %w", err)
		}
	}
	// P7⑥: run_analysis is now one row per (run_id, kind) (see
	// runAnalysisSchema) so a run can hold the RCA report (rule/llm) plus AI
	// analyses (pr_review / test_selection). Pre-P7⑥ databases have the
	// one-row-per-run table (PK run_id, no surrogate id); the batch's
	// CREATE TABLE IF NOT EXISTS above was a no-op there, so rebuild in
	// place: rename → create new → copy → drop.
	if cols, err := tableColumns(db, "run_analysis"); err != nil {
		return fmt.Errorf("migrate run_analysis columns: %w", err)
	} else if !cols["id"] {
		if err := rebuildRunAnalysis(db); err != nil {
			return err
		}
	}
	// M-2: atomic duplicate guard — at most one active (non-terminal) release
	// per (name, namespace). Closes the check-then-insert race that let
	// concurrent API requests create duplicate active canaries.
	if _, err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_canary_active
		ON canary_releases(name, namespace) WHERE ` + canaryActiveWhere); err != nil {
		return fmt.Errorf("migrate idx_canary_active: %w", err)
	}
	return nil
}

// rebuildRunAnalysis migrates the pre-P7⑥ one-row-per-run run_analysis table
// (PK run_id, no surrogate id) to the current schema, preserving stored rows.
// The rename/create/copy/drop steps run in ONE transaction (N5): a crash or
// failure mid-migration rolls back to the old table, and Open() retries the
// same migration on the next start — the database is never left with both
// or neither table.
func rebuildRunAnalysis(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("migrate run_analysis: begin: %w", err)
	}
	fail := func(err error) error {
		if rbErr := tx.Rollback(); rbErr != nil && err == nil {
			err = fmt.Errorf("migrate run_analysis: rollback: %w", rbErr)
		}
		return err
	}
	if _, err := tx.Exec(`ALTER TABLE run_analysis RENAME TO run_analysis_old`); err != nil {
		return fail(fmt.Errorf("migrate run_analysis: rename: %w", err))
	}
	if _, err := tx.Exec(runAnalysisSchema); err != nil {
		return fail(fmt.Errorf("migrate run_analysis: create: %w", err))
	}
	if _, err := tx.Exec(`INSERT INTO run_analysis
		(run_id, step_id, kind, root_cause, detail, suggested_fix, command, log_excerpt, created_at)
		SELECT run_id, step_id, kind, root_cause, detail, suggested_fix,
		       command, log_excerpt, created_at
		FROM run_analysis_old`); err != nil {
		return fail(fmt.Errorf("migrate run_analysis: copy: %w", err))
	}
	if _, err := tx.Exec(`DROP TABLE run_analysis_old`); err != nil {
		return fail(fmt.Errorf("migrate run_analysis: drop: %w", err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("migrate run_analysis: commit: %w", err)
	}
	return nil
}

// tableColumns returns the set of column names of a table (PRAGMA table_info).
// The table name is always a literal internal to this file, never user input.
func tableColumns(db *sql.DB, table string) (map[string]bool, error) {
	rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols := make(map[string]bool)
	for rows.Next() {
		var (
			cid     int
			name    string
			ctype   string
			notnull int
			dflt    sql.NullString
			pk      int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return nil, err
		}
		cols[name] = true
	}
	return cols, rows.Err()
}

// head returns the first word of a SQL statement for terse error messages.
func head(s string) string {
	f := strings.Fields(s)
	if len(f) == 0 {
		return "?"
	}
	return f[0]
}

// now returns the current time as RFC3339 UTC.
func now() string { return time.Now().UTC().Format(time.RFC3339) }

// Close closes the underlying database.
func (s *Store) Close() error { return s.db.Close() }

// UpsertPipeline inserts a pipeline or, if the name exists, updates its YAML.
// It returns the pipeline row id.
func (s *Store) UpsertPipeline(name, yamlText string) (int64, error) {
	if name == "" {
		return 0, fmt.Errorf("store: pipeline name is empty")
	}
	ts := now()
	if _, err := s.db.Exec(
		`INSERT INTO pipelines (name, yaml_text, created_at, updated_at)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(name) DO UPDATE SET
		   yaml_text = excluded.yaml_text, updated_at = excluded.updated_at`,
		name, yamlText, ts, ts,
	); err != nil {
		return 0, fmt.Errorf("store: upsert pipeline %q: %w", name, err)
	}
	// last_insert_rowid is only set on the INSERT path, so resolve by name.
	var id int64
	if err := s.db.QueryRow(`SELECT id FROM pipelines WHERE name = ?`, name).Scan(&id); err != nil {
		return 0, fmt.Errorf("store: read back pipeline %q: %w", name, err)
	}
	return id, nil
}

// GetPipelineByName returns the pipeline with the given name.
func (s *Store) GetPipelineByName(name string) (Pipeline, error) {
	var p Pipeline
	err := s.db.QueryRow(
		`SELECT id, name, yaml_text, created_at, updated_at FROM pipelines WHERE name = ?`, name,
	).Scan(&p.ID, &p.Name, &p.YAMLText, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return p, err
	}
	return p, nil
}

// GetPipeline returns the pipeline with the given id.
func (s *Store) GetPipeline(id int64) (Pipeline, error) {
	var p Pipeline
	err := s.db.QueryRow(
		`SELECT id, name, yaml_text, created_at, updated_at FROM pipelines WHERE id = ?`, id,
	).Scan(&p.ID, &p.Name, &p.YAMLText, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return p, err
	}
	return p, nil
}

// ListPipelines returns all pipelines ordered by name.
func (s *Store) ListPipelines() ([]Pipeline, error) {
	rows, err := s.db.Query(`SELECT id, name, yaml_text, created_at, updated_at FROM pipelines ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Pipeline
	for rows.Next() {
		var p Pipeline
		if err := rows.Scan(&p.ID, &p.Name, &p.YAMLText, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// CreateRun queues a new run of the given pipeline (no PR metadata).
func (s *Store) CreateRun(pipelineID int64, trigger, sourceRef string) (int64, error) {
	return s.CreateRunMeta(pipelineID, trigger, sourceRef, RunMeta{})
}

// CreateRunMeta queues a new run with optional trigger metadata (P7).
// A zero RunMeta leaves pr / base_ref / head_ref / repo_url NULL
// (push / manual / schedule / canary runs).
func (s *Store) CreateRunMeta(pipelineID int64, trigger, sourceRef string, m RunMeta) (int64, error) {
	var (
		pr      any
		baseRef any
		headRef any
		repoURL any
	)
	if m.PR != 0 {
		pr, baseRef, headRef, repoURL = m.PR, m.BaseRef, m.HeadRef, m.RepoURL
	}
	res, err := s.db.Exec(
		`INSERT INTO runs (pipeline_id, status, trigger, source_ref, sha,
		                  pr, base_ref, head_ref, repo_url, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		pipelineID, RunQueued, trigger, sourceRef, m.SHA, pr, baseRef, headRef, repoURL, now(),
	)
	if err != nil {
		return 0, fmt.Errorf("store: create run: %w", err)
	}
	return res.LastInsertId()
}

// SetRunStatus transitions a run, stamping started_at when it begins and
// finished_at when it reaches a terminal state.
func (s *Store) SetRunStatus(runID int64, status string) error {
	ts := now()
	var (
		query string
		args  []interface{}
	)
	switch status {
	case RunRunning:
		query, args = `UPDATE runs SET status = ?, started_at = ? WHERE id = ?`, []interface{}{status, ts, runID}
	case RunSuccess, RunFailed, RunCanceled, RunRejected:
		query, args = `UPDATE runs SET status = ?, finished_at = ? WHERE id = ?`, []interface{}{status, ts, runID}
	default:
		query, args = `UPDATE runs SET status = ? WHERE id = ?`, []interface{}{status, runID}
	}
	if _, err := s.db.Exec(query, args...); err != nil {
		return fmt.Errorf("store: set run %d status %q: %w", runID, status, err)
	}
	return nil
}

// SetRunRejectReason records the operator-given reason for a rejected run
// (P7⑧). Empty reason clears the field. Errors if the run does not exist.
func (s *Store) SetRunRejectReason(runID int64, reason string) error {
	res, err := s.db.Exec(`UPDATE runs SET reject_reason = ? WHERE id = ?`, reason, runID)
	if err != nil {
		return fmt.Errorf("store: set run %d reject reason: %w", runID, err)
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		return fmt.Errorf("store: no run %d", runID)
	}
	return nil
}

// GetRun returns the run with the given id.
func (s *Store) GetRun(runID int64) (Run, error) {
	var r Run
	err := s.db.QueryRow(
		`SELECT id, pipeline_id, status, trigger, source_ref, sha,
		        IFNULL(pr, 0), IFNULL(base_ref, ''), IFNULL(head_ref, ''), IFNULL(repo_url, ''),
		        reject_reason,
		        IFNULL(started_at, ''), IFNULL(finished_at, ''), created_at
		 FROM runs WHERE id = ?`, runID,
	).Scan(&r.ID, &r.PipelineID, &r.Status, &r.Trigger, &r.SourceRef, &r.SHA,
		&r.PR, &r.BaseRef, &r.HeadRef, &r.RepoURL, &r.RejectReason,
		&r.StartedAt, &r.FinishedAt, &r.CreatedAt)
	if err != nil {
		return r, err
	}
	return r, nil
}

// ListRuns returns up to limit most-recent runs, optionally filtered by
// pipeline. limit <= 0 defaults to 50.
func (s *Store) ListRuns(pipelineID int64, limit int) ([]Run, error) {
	if limit <= 0 {
		limit = 50
	}
	q := `SELECT id, pipeline_id, status, trigger, source_ref, sha,
	          IFNULL(pr, 0), IFNULL(base_ref, ''), IFNULL(head_ref, ''), IFNULL(repo_url, ''),
	          reject_reason,
	          IFNULL(started_at, ''), IFNULL(finished_at, ''), created_at
	          FROM runs`
	var args []interface{}
	if pipelineID > 0 {
		q += ` WHERE pipeline_id = ?`
		args = append(args, pipelineID)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Run
	for rows.Next() {
		var r Run
		if err := rows.Scan(&r.ID, &r.PipelineID, &r.Status, &r.Trigger, &r.SourceRef, &r.SHA,
			&r.PR, &r.BaseRef, &r.HeadRef, &r.RepoURL, &r.RejectReason,
			&r.StartedAt, &r.FinishedAt, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AddRunStep records a step in a run (initially pending). command is the
// JSON-encoded command list (may be "" for legacy callers).
func (s *Store) AddRunStep(runID int64, stepID string, index int, image, command string) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO run_steps (run_id, step_id, step_index, status, image, command)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		runID, stepID, index, StepPending, image, command,
	)
	if err != nil {
		return 0, fmt.Errorf("store: add run step: %w", err)
	}
	return res.LastInsertId()
}

// ListRunSteps returns all steps of a run, in step_index order.
func (s *Store) ListRunSteps(runID int64) ([]RunStep, error) {
	rows, err := s.db.Query(
		`SELECT id, run_id, step_id, step_index, status, image, command, IFNULL(outputs, ''),
		        IFNULL(started_at, ''), IFNULL(finished_at, '')
		 FROM run_steps WHERE run_id = ? ORDER BY step_index ASC`, runID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RunStep
	for rows.Next() {
		var rs RunStep
		if err := rows.Scan(&rs.ID, &rs.RunID, &rs.StepID, &rs.StepIndex, &rs.Status,
			&rs.Image, &rs.Command, &rs.Outputs, &rs.StartedAt, &rs.FinishedAt); err != nil {
			return nil, err
		}
		out = append(out, rs)
	}
	return out, rows.Err()
}

// SetRunStepOutputs stores the JSON-encoded outputs produced by a step
// (P7④: docker_build writes {"image_ref": "<ref>"}). It fails when the
// (run, step) row does not exist.
func (s *Store) SetRunStepOutputs(runID int64, stepID string, outputs string) error {
	res, err := s.db.Exec(
		`UPDATE run_steps SET outputs = ? WHERE run_id = ? AND step_id = ?`,
		outputs, runID, stepID,
	)
	if err != nil {
		return fmt.Errorf("store: set run step outputs: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		return fmt.Errorf("store: no run_steps row for run %d step %q", runID, stepID)
	}
	return nil
}

// SaveRunAnalysis upserts one analysis of the given kind for a run. A run may
// carry several analyses side by side (rule/llm RCA plus pr_review /
// test_selection); each (run_id, kind) pair is unique.
func (s *Store) SaveRunAnalysis(a RunAnalysis) error {
	if a.CreatedAt == "" {
		a.CreatedAt = now()
	}
	_, err := s.db.Exec(
		`INSERT INTO run_analysis (run_id, step_id, kind, root_cause, detail,
		 suggested_fix, command, log_excerpt, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(run_id, kind) DO UPDATE SET
		   step_id = excluded.step_id,
		   root_cause = excluded.root_cause,
		   detail = excluded.detail,
		   suggested_fix = excluded.suggested_fix,
		   command = excluded.command,
		   log_excerpt = excluded.log_excerpt`,
		// created_at is intentionally NOT in the DO UPDATE list: upsert keeps
		// the timestamp of the first report of that kind.
		a.RunID, a.StepID, a.Kind, a.RootCause, a.Detail,
		a.SuggestedFix, a.Command, a.LogExcerpt, a.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("store: save run analysis: %w", err)
	}
	return nil
}

// GetRunAnalysis returns the run's primary root-cause report: the most recent
// rule/llm analysis (the AI sidecar's RCA). Returns sql.ErrNoRows when no
// rule/llm analysis has been stored (e.g. only pr_review / test_selection).
func (s *Store) GetRunAnalysis(runID int64) (RunAnalysis, error) {
	var a RunAnalysis
	err := s.db.QueryRow(
		`SELECT run_id, step_id, kind, root_cause, detail,
		        suggested_fix, command, log_excerpt, created_at
		 FROM run_analysis
		 WHERE run_id = ? AND kind IN ('rule', 'llm')
		 ORDER BY created_at DESC, id DESC LIMIT 1`, runID,
	).Scan(&a.RunID, &a.StepID, &a.Kind, &a.RootCause, &a.Detail,
		&a.SuggestedFix, &a.Command, &a.LogExcerpt, &a.CreatedAt)
	if err != nil {
		return a, err
	}
	return a, nil
}

// ListRunAnalyses returns every stored analysis for a run (all kinds),
// oldest first.
func (s *Store) ListRunAnalyses(runID int64) ([]RunAnalysis, error) {
	rows, err := s.db.Query(
		`SELECT run_id, step_id, kind, root_cause, detail,
		        suggested_fix, command, log_excerpt, created_at
		 FROM run_analysis WHERE run_id = ?
		 ORDER BY created_at ASC, id ASC`, runID,
	)
	if err != nil {
		return nil, fmt.Errorf("store: list run analyses: %w", err)
	}
	defer rows.Close()
	out := make([]RunAnalysis, 0)
	for rows.Next() {
		var a RunAnalysis
		if err := rows.Scan(&a.RunID, &a.StepID, &a.Kind, &a.RootCause, &a.Detail,
			&a.SuggestedFix, &a.Command, &a.LogExcerpt, &a.CreatedAt); err != nil {
			return nil, fmt.Errorf("store: scan run analysis: %w", err)
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list run analyses: %w", err)
	}
	return out, nil
}

// SetRunStepStatus transitions a step, stamping started_at / finished_at.
func (s *Store) SetRunStepStatus(id int64, status string) error {
	ts := now()
	var (
		query string
		args  []interface{}
	)
	switch status {
	case StepRunning:
		query, args = `UPDATE run_steps SET status = ?, started_at = ? WHERE id = ?`, []interface{}{status, ts, id}
	case StepSuccess, StepFailed, StepSkipped, StepCanceled:
		query, args = `UPDATE run_steps SET status = ?, finished_at = ? WHERE id = ?`, []interface{}{status, ts, id}
	default:
		query, args = `UPDATE run_steps SET status = ? WHERE id = ?`, []interface{}{status, id}
	}
	if _, err := s.db.Exec(query, args...); err != nil {
		return fmt.Errorf("store: set run step %d status %q: %w", id, status, err)
	}
	return nil
}

// AddLog appends one log line for (runID, stepID). The row id is the
// sequence number: a single autoincrement INSERT is atomic under SQLite's
// write lock, so concurrent appenders never collide (no read-then-write).
// It returns the assigned seq.
func (s *Store) AddLog(runID int64, stepID, line string) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO logs (run_id, step_id, line, ts) VALUES (?, ?, ?, ?)`,
		runID, stepID, line, now(),
	)
	if err != nil {
		return 0, fmt.Errorf("store: add log: %w", err)
	}
	seq, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("store: add log id: %w", err)
	}
	return seq, nil
}

// ListLogs returns log lines for (runID, stepID) with seq (row id) greater
// than afterSeq, in ascending order, capped at limit (<=0 defaults to 500).
func (s *Store) ListLogs(runID int64, stepID string, afterSeq, limit int64) ([]LogRow, error) {
	if limit <= 0 {
		limit = 500
	}
	rows, err := s.db.Query(
		`SELECT id, line, ts FROM logs
		 WHERE run_id = ? AND step_id = ? AND id > ?
		 ORDER BY id ASC LIMIT ?`,
		runID, stepID, afterSeq, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LogRow
	for rows.Next() {
		var l LogRow
		if err := rows.Scan(&l.Seq, &l.Line, &l.TS); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// RegisterAgent registers an agent by name, returning its id and whether it
// was newly created. Re-registering an existing name refreshes its heartbeat.
func (s *Store) RegisterAgent(name string) (int64, bool, error) {
	if name == "" {
		return 0, false, fmt.Errorf("store: agent name is empty")
	}
	var id int64
	err := s.db.QueryRow(`SELECT id FROM agents WHERE name = ?`, name).Scan(&id)
	if err == sql.ErrNoRows {
		res, err := s.db.Exec(
			`INSERT INTO agents (name, last_heartbeat, created_at) VALUES (?, ?, ?)`,
			name, now(), now(),
		)
		if err != nil {
			return 0, false, fmt.Errorf("store: register agent %q: %w", name, err)
		}
		id, err = res.LastInsertId()
		if err != nil {
			return 0, false, err
		}
		return id, true, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("store: look up agent %q: %w", name, err)
	}
	if _, err := s.db.Exec(`UPDATE agents SET last_heartbeat = ? WHERE id = ?`, now(), id); err != nil {
		return 0, false, fmt.Errorf("store: heartbeat agent %d: %w", id, err)
	}
	return id, false, nil
}

// HeartbeatAgent refreshes the last-seen time for an agent.
func (s *Store) HeartbeatAgent(id int64) error {
	if _, err := s.db.Exec(`UPDATE agents SET last_heartbeat = ? WHERE id = ?`, now(), id); err != nil {
		return fmt.Errorf("store: heartbeat agent %d: %w", id, err)
	}
	return nil
}
