package store

import (
	"encoding/json"
	"fmt"
)

// RunScan is one stored security-scan result attached to a run (P5). A run
// may accumulate several scans; rows are appended, never updated.
type RunScan struct {
	ID            int64
	RunID         int64
	Tool          string
	Target        string
	Mode          string // "fs" | "image"
	ExitCode      int
	FindingsCount int
	Severity      map[string]int
	ReportJSON    string
	Truncated     bool
	CreatedAt     string
}

// SaveRunScan appends a scan result to a run and returns the new row id.
// The run must exist: run_id is a foreign key and Open() enables
// PRAGMA foreign_keys, so an unknown run is rejected by SQLite.
func (s *Store) SaveRunScan(r RunScan) (int64, error) {
	if r.CreatedAt == "" {
		r.CreatedAt = now()
	}
	sev, err := json.Marshal(r.Severity)
	if err != nil {
		return 0, fmt.Errorf("store: marshal run scan severity: %w", err)
	}
	if r.Severity == nil {
		sev = []byte("{}")
	}
	truncated := 0
	if r.Truncated {
		truncated = 1
	}
	res, err := s.db.Exec(
		`INSERT INTO run_scans (run_id, tool, target, mode, exit_code,
		        findings_count, severity_json, report_json, truncated, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.RunID, r.Tool, r.Target, r.Mode, r.ExitCode, r.FindingsCount,
		string(sev), r.ReportJSON, truncated, r.CreatedAt,
	)
	if err != nil {
		return 0, fmt.Errorf("store: save run scan: %w", err)
	}
	return res.LastInsertId()
}

// ListRunScans returns all scan results of a run in ascending id order.
func (s *Store) ListRunScans(runID int64) ([]RunScan, error) {
	rows, err := s.db.Query(
		`SELECT id, run_id, tool, target, mode, exit_code, findings_count,
		        severity_json, report_json, truncated, created_at
		 FROM run_scans WHERE run_id = ? ORDER BY id ASC`, runID,
	)
	if err != nil {
		return nil, fmt.Errorf("store: list run scans: %w", err)
	}
	defer rows.Close()
	var out []RunScan
	for rows.Next() {
		var rs RunScan
		var sevJSON string
		var truncated int
		if err := rows.Scan(&rs.ID, &rs.RunID, &rs.Tool, &rs.Target, &rs.Mode,
			&rs.ExitCode, &rs.FindingsCount, &sevJSON, &rs.ReportJSON,
			&truncated, &rs.CreatedAt); err != nil {
			return nil, fmt.Errorf("store: scan run_scans row: %w", err)
		}
		rs.Severity = map[string]int{}
		if sevJSON != "" && sevJSON != "null" {
			if err := json.Unmarshal([]byte(sevJSON), &rs.Severity); err != nil {
				return nil, fmt.Errorf("store: unmarshal run scan severity: %w", err)
			}
		}
		if truncated != 0 {
			rs.Truncated = true
		}
		out = append(out, rs)
	}
	return out, rows.Err()
}
