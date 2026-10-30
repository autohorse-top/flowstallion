package store

import (
	"database/sql"
	"path/filepath"
	"reflect"
	"testing"
)

// TestRunScanRoundtrip verifies SaveRunScan/ListRunScans round-trip,
// including severity map and truncated flag, and id ordering.
func TestRunScanRoundtrip(t *testing.T) {
	s := openTemp(t)
	pid, err := s.UpsertPipeline("build", "yaml")
	if err != nil {
		t.Fatalf("upsert pipeline: %v", err)
	}
	runID, err := s.CreateRun(pid, "manual", "")
	if err != nil {
		t.Fatalf("create run: %v", err)
	}

	id1, err := s.SaveRunScan(RunScan{
		RunID:         runID,
		Tool:          "trivy",
		Target:        "/tmp/repo",
		Mode:          "fs",
		ExitCode:      0,
		FindingsCount: 3,
		Severity:      map[string]int{"CRITICAL": 1, "HIGH": 2},
		ReportJSON:    `{"SchemaVersion":2,"ReportID":"r1"}`,
		Truncated:     true,
		CreatedAt:     "2026-10-23T10:00:00Z",
	})
	if err != nil {
		t.Fatalf("save scan 1: %v", err)
	}
	id2, err := s.SaveRunScan(RunScan{
		RunID:         runID,
		Tool:          "trivy",
		Target:        "nginx:1.25",
		Mode:          "image",
		FindingsCount: 0,
		Severity:      map[string]int{},
		ReportJSON:    `{"Results":[]}`,
	})
	if err != nil {
		t.Fatalf("save scan 2: %v", err)
	}

	scans, err := s.ListRunScans(runID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(scans) != 2 {
		t.Fatalf("got %d scans, want 2", len(scans))
	}
	if scans[0].ID != id1 || scans[1].ID != id2 {
		t.Fatalf("order = [%d %d], want [%d %d]", scans[0].ID, scans[1].ID, id1, id2)
	}
	a := scans[0]
	if a.RunID != runID || a.Tool != "trivy" || a.Target != "/tmp/repo" || a.Mode != "fs" ||
		a.ExitCode != 0 || a.FindingsCount != 3 || !a.Truncated ||
		a.CreatedAt != "2026-10-23T10:00:00Z" ||
		a.ReportJSON != `{"SchemaVersion":2,"ReportID":"r1"}` {
		t.Errorf("scan 1 mismatch: %+v", a)
	}
	if !reflect.DeepEqual(a.Severity, map[string]int{"CRITICAL": 1, "HIGH": 2}) {
		t.Errorf("severity = %v, want map[CRITICAL:1 HIGH:2]", a.Severity)
	}
	b := scans[1]
	if b.ExitCode != 0 || b.FindingsCount != 0 || b.Truncated || len(b.Severity) != 0 ||
		b.CreatedAt == "" || b.ReportJSON != `{"Results":[]}` {
		t.Errorf("scan 2 mismatch: %+v", b)
	}
	if b.Severity == nil {
		t.Error("scan 2 severity should be an empty map, not nil")
	}
}

// TestRunScanUnknownRun verifies the foreign key rejects scans for runs
// that do not exist (foreign_keys pragma is ON in Open).
func TestRunScanUnknownRun(t *testing.T) {
	s := openTemp(t)
	_, err := s.SaveRunScan(RunScan{RunID: 99999, Tool: "trivy", Target: "/tmp/x", Mode: "fs"})
	if err == nil {
		t.Fatal("want FK violation for unknown run id, got nil")
	}
}

// TestRunScansLegacyMigration simulates a pre-P5 database (no run_scans
// table) and verifies Open() adds it idempotently.
func TestRunScansLegacyMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open raw sqlite: %v", err)
	}
	_, err = raw.Exec(`CREATE TABLE IF NOT EXISTS runs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		pipeline_id INTEGER NOT NULL,
		status TEXT NOT NULL DEFAULT 'queued',
		created_at TEXT NOT NULL
	)`)
	if err != nil {
		raw.Close()
		t.Fatalf("create legacy runs table: %v", err)
	}
	_, err = raw.Exec(`INSERT INTO runs (pipeline_id, status, created_at) VALUES (1, 'queued', '2026-01-01T00:00:00Z')`)
	if err != nil {
		raw.Close()
		t.Fatalf("insert legacy run: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close raw db: %v", err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatalf("open upgraded db: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	var table string
	err = s.db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='run_scans'`).Scan(&table)
	if err == sql.ErrNoRows {
		t.Fatal("run_scans table missing after migration")
	} else if err != nil {
		t.Fatalf("query sqlite_master: %v", err)
	}

	// The legacy run (id 1) must accept scans even though it predates the table.
	id, err := s.SaveRunScan(RunScan{RunID: 1, Tool: "trivy", Target: "/tmp/repo", Mode: "fs", ReportJSON: "{}"})
	if err != nil {
		t.Fatalf("save scan on legacy run: %v", err)
	}
	scans, err := s.ListRunScans(1)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(scans) != 1 || scans[0].ID != id {
		t.Fatalf("got %+v, want one scan with id %d", scans, id)
	}

	// Re-open to confirm migrate is idempotent on the upgraded DB.
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := Open(path); err != nil {
		t.Fatalf("re-open upgraded db: %v", err)
	}
}
