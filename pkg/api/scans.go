package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/flowstallion/flowstallion/pkg/security"
	"github.com/flowstallion/flowstallion/pkg/store"
)

// maxReportJSON caps the stored trivy report (mirrors security.MaxRawJSON).
const maxReportJSON = 1 << 20

// maxScanBody caps the whole request body: report_json (<= 1 MiB after
// decode) plus JSON-escaping overhead of the surrounding document.
const maxScanBody = 2 << 20

type scanJSON struct {
	ID            int64          `json:"id"`
	RunID         int64          `json:"run_id"`
	Tool          string         `json:"tool"`
	Target        string         `json:"target"`
	Mode          string         `json:"mode"`
	ExitCode      int            `json:"exit_code"`
	FindingsCount int            `json:"findings_count"`
	Severity      map[string]int `json:"severity"`
	ReportJSON    string         `json:"report_json"`
	Truncated     bool           `json:"truncated"`
	CreatedAt     string         `json:"created_at"`
}

// toScanJSON converts a stored scan to its wire form. Severity is rendered
// as {} (not null) when empty.
func toScanJSON(rs store.RunScan) scanJSON {
	sev := rs.Severity
	if sev == nil {
		sev = map[string]int{}
	}
	return scanJSON{
		ID: rs.ID, RunID: rs.RunID, Tool: rs.Tool, Target: rs.Target,
		Mode: rs.Mode, ExitCode: rs.ExitCode, FindingsCount: rs.FindingsCount,
		Severity: sev, ReportJSON: rs.ReportJSON, Truncated: rs.Truncated,
		CreatedAt: rs.CreatedAt,
	}
}

// scanDTOs converts a stored scan list, guaranteeing a non-nil ([]) result.
func scanDTOs(scans []store.RunScan) []scanJSON {
	out := make([]scanJSON, 0, len(scans))
	for _, sc := range scans {
		out = append(out, toScanJSON(sc))
	}
	return out
}

// requireRun resolves the {id} path parameter and verifies the run exists;
// on failure it writes the error response and returns the status it wrote
// (ok=false).
func (s *Server) requireRun(w http.ResponseWriter, r *http.Request) (int64, int, bool) {
	runID, ok := parseRunID(r, w)
	if !ok {
		return 0, http.StatusBadRequest, false
	}
	if _, err := s.Store.GetRun(runID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "run not found")
			return 0, http.StatusNotFound, false
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return 0, http.StatusInternalServerError, false
	}
	return runID, http.StatusOK, true
}

// allowedScanTools is the P6③ tool whitelist for POST /api/runs/{id}/scans;
// it mirrors the scanners shipped in pkg/security.
var allowedScanTools = map[string]bool{
	security.ToolName:     true, // "trivy"
	security.GitleaksTool: true, // "gitleaks"
	security.SemgrepTool:  true, // "semgrep"
}

// handleSaveScan stores a security-scan result for a run (appended; a run
// may accumulate several scans). Validation: run exists, tool in
// {trivy, gitleaks, semgrep}, target non-empty, mode in {fs, image},
// findings_count >= 0, severity values >= 0, report_json <= 1 MiB.
func (s *Server) handleSaveScan(w http.ResponseWriter, r *http.Request) {
	runID, status, ok := s.requireRun(w, r)
	if !ok {
		s.record(r, AuditScanSave, scanTarget(runID), status, "run check failed")
		return
	}
	var body struct {
		Tool          string         `json:"tool"`
		Target        string         `json:"target"`
		Mode          string         `json:"mode"`
		ExitCode      int            `json:"exit_code"`
		FindingsCount int            `json:"findings_count"`
		Severity      map[string]int `json:"severity"`
		Truncated     bool           `json:"truncated"`
		ReportJSON    string         `json:"report_json"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxScanBody)).Decode(&body); err != nil {
		s.record(r, AuditScanSave, fmt.Sprintf("run:%d", runID), http.StatusBadRequest, "invalid body")
		writeErr(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	if !allowedScanTools[body.Tool] {
		s.record(r, AuditScanSave, fmt.Sprintf("run:%d", runID), http.StatusBadRequest, "bad tool")
		writeErr(w, http.StatusBadRequest, `tool must be one of "trivy", "gitleaks", "semgrep"`)
		return
	}
	if body.Target == "" {
		s.record(r, AuditScanSave, fmt.Sprintf("run:%d", runID), http.StatusBadRequest, "target required")
		writeErr(w, http.StatusBadRequest, "target is required")
		return
	}
	if body.Mode != "fs" && body.Mode != "image" {
		s.record(r, AuditScanSave, fmt.Sprintf("run:%d", runID), http.StatusBadRequest, "bad mode")
		writeErr(w, http.StatusBadRequest, `mode must be "fs" or "image"`)
		return
	}
	if body.FindingsCount < 0 {
		s.record(r, AuditScanSave, fmt.Sprintf("run:%d", runID), http.StatusBadRequest, "findings_count negative")
		writeErr(w, http.StatusBadRequest, "findings_count must be >= 0")
		return
	}
	for k, v := range body.Severity {
		if v < 0 {
			s.record(r, AuditScanSave, fmt.Sprintf("run:%d", runID), http.StatusBadRequest,
				"severity negative (key: "+k+")")
			writeErr(w, http.StatusBadRequest, "severity values must be >= 0 (key: "+k+")")
			return
		}
	}
	if len(body.ReportJSON) > maxReportJSON {
		s.record(r, AuditScanSave, fmt.Sprintf("run:%d", runID), http.StatusBadRequest, "report too large")
		writeErr(w, http.StatusBadRequest, "report_json exceeds 1 MiB")
		return
	}
	id, err := s.Store.SaveRunScan(store.RunScan{
		RunID: runID, Tool: body.Tool, Target: body.Target, Mode: body.Mode,
		ExitCode: body.ExitCode, FindingsCount: body.FindingsCount,
		Severity: body.Severity, ReportJSON: body.ReportJSON, Truncated: body.Truncated,
	})
	if err != nil {
		s.record(r, AuditScanSave, fmt.Sprintf("run:%d", runID), http.StatusInternalServerError, "save: "+err.Error())
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Return the persisted row (including the server-assigned created_at).
	scans, err := s.Store.ListRunScans(runID)
	if err != nil {
		s.record(r, AuditScanSave, fmt.Sprintf("run:%d", runID), http.StatusInternalServerError, "read-back: "+err.Error())
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, sc := range scans {
		if sc.ID == id {
			s.record(r, AuditScanSave, fmt.Sprintf("run:%d", runID), http.StatusOK,
				fmt.Sprintf("tool=%s findings=%d", body.Tool, body.FindingsCount))
			writeJSON(w, http.StatusOK, toScanJSON(sc))
			return
		}
	}
	s.record(r, AuditScanSave, fmt.Sprintf("run:%d", runID), http.StatusInternalServerError, "stored but not readable")
	writeErr(w, http.StatusInternalServerError, "scan was stored but could not be read back")
}

// scanTarget formats the audit target for a (possibly unresolved) run id.
func scanTarget(runID int64) string {
	if runID > 0 {
		return fmt.Sprintf("run:%d", runID)
	}
	return "run:unknown"
}

// handleListScans returns all scan results for a run (empty list, not null,
// when the run has no scans).
func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	runID, _, ok := s.requireRun(w, r)
	if !ok {
		return
	}
	scans, err := s.Store.ListRunScans(runID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, scanDTOs(scans))
}
