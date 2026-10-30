package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

// postScanBody POSTs a raw JSON scan body and returns status + decoded map.
func postScanBody(t *testing.T, c *http.Client, base string, runID int64, body map[string]any) (int, map[string]any) {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal scan body: %v", err)
	}
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/api/runs/%d/scans", base, runID), bytes.NewReader(b))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("post scan: %v", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if len(data) > 0 {
		_ = json.Unmarshal(data, &out)
	}
	return resp.StatusCode, out
}

// getRaw performs a GET and returns status + trimmed raw body.
func getRaw(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("get %s: %v", url, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(data))
}

// TestScansPostThenGet verifies the happy path: POST stores a scan and GET
// lists it back with all fields intact.
func TestScansPostThenGet(t *testing.T) {
	ts, _ := newTestServer(t)
	c := ts.Client()
	createPipeline(t, c, ts.URL, "linear", linearYAML)
	runID := triggerRun(t, c, ts.URL, "linear")

	body := map[string]any{
		"tool":           "trivy",
		"target":         "/tmp/repo",
		"mode":           "fs",
		"exit_code":      1,
		"findings_count": 3,
		"severity":       map[string]any{"CRITICAL": 1, "HIGH": 2},
		"truncated":      true,
		"report_json":    `{"SchemaVersion":2,"ReportID":"r1"}`,
	}
	code, out := postScanBody(t, c, ts.URL, runID, body)
	if code != http.StatusOK {
		t.Fatalf("post scan: got %d, want 200 (body=%v)", code, out)
	}
	id, ok := out["id"].(float64)
	if !ok || id < 1 {
		t.Fatalf("post response has no valid id: %v", out)
	}
	if out["run_id"] != float64(runID) || out["tool"] != "trivy" ||
		out["mode"] != "fs" || out["exit_code"] != float64(1) ||
		out["findings_count"] != float64(3) || out["truncated"] != true ||
		out["report_json"] != `{"SchemaVersion":2,"ReportID":"r1"}` {
		t.Fatalf("post response fields wrong: %v", out)
	}
	sev, _ := out["severity"].(map[string]any)
	if sev == nil || sev["CRITICAL"] != float64(1) || sev["HIGH"] != float64(2) {
		t.Fatalf("severity not round-tripped: %v", out["severity"])
	}
	if out["created_at"] == nil || out["created_at"] == "" {
		t.Fatalf("created_at missing: %v", out)
	}

	code, raw := getRaw(t, fmt.Sprintf("%s/api/runs/%d/scans", ts.URL, runID))
	if code != http.StatusOK {
		t.Fatalf("get scans: got %d, want 200", code)
	}
	var listed []map[string]any
	if err := json.Unmarshal([]byte(raw), &listed); err != nil {
		t.Fatalf("unmarshal list %q: %v", raw, err)
	}
	if len(listed) != 1 {
		t.Fatalf("listed %d scans, want 1: %s", len(listed), raw)
	}
	if listed[0]["id"] != out["id"] || listed[0]["target"] != "/tmp/repo" {
		t.Fatalf("listed scan mismatch: %v", listed[0])
	}
}

// TestScansPostUnknownRun verifies 404 for a nonexistent run.
func TestScansPostUnknownRun(t *testing.T) {
	ts, _ := newTestServer(t)
	c := ts.Client()
	code, out := postScanBody(t, c, ts.URL, 999999, map[string]any{
		"tool": "trivy", "target": "/tmp/x", "mode": "fs",
	})
	if code != http.StatusNotFound {
		t.Fatalf("post to unknown run: got %d, want 404 (body=%v)", code, out)
	}
}

// TestScansPostValidationErrors table-checks the 400 paths.
func TestScansPostValidationErrors(t *testing.T) {
	ts, _ := newTestServer(t)
	c := ts.Client()
	createPipeline(t, c, ts.URL, "linear", linearYAML)
	runID := triggerRun(t, c, ts.URL, "linear")

	valid := func() map[string]any {
		return map[string]any{
			"tool": "trivy", "target": "/tmp/repo", "mode": "fs",
			"findings_count": 0, "severity": map[string]any{}, "report_json": "{}",
		}
	}
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"invalid mode", func(b map[string]any) { b["mode"] = "fsx" }},
		{"empty tool", func(b map[string]any) { b["tool"] = "" }},
		{"tool not in whitelist (long string)", func(b map[string]any) { b["tool"] = strings.Repeat("t", 65) }},
		{"empty target", func(b map[string]any) { b["target"] = "" }},
		{"negative findings", func(b map[string]any) { b["findings_count"] = -1 }},
		{"negative severity value", func(b map[string]any) { b["severity"] = map[string]any{"HIGH": -1} }},
		{"oversized report_json", func(b map[string]any) { b["report_json"] = strings.Repeat("a", 1<<20+1) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := valid()
			tt.mutate(body)
			code, out := postScanBody(t, c, ts.URL, runID, body)
			if code != http.StatusBadRequest {
				t.Fatalf("%s: got %d, want 400 (body=%v)", tt.name, code, out)
			}
		})
	}

	// Nothing should have been stored by the rejected posts.
	code, raw := getRaw(t, fmt.Sprintf("%s/api/runs/%d/scans", ts.URL, runID))
	if code != http.StatusOK || raw != "[]" {
		t.Fatalf("after invalid posts: code=%d raw=%q, want 200 []", code, raw)
	}
}

// TestScansGetEmptyList verifies an empty list serialises as [] not null.
func TestScansGetEmptyList(t *testing.T) {
	ts, _ := newTestServer(t)
	c := ts.Client()
	createPipeline(t, c, ts.URL, "linear", linearYAML)
	runID := triggerRun(t, c, ts.URL, "linear")
	code, raw := getRaw(t, fmt.Sprintf("%s/api/runs/%d/scans", ts.URL, runID))
	if code != http.StatusOK {
		t.Fatalf("get scans: got %d, want 200", code)
	}
	if raw != "[]" {
		t.Fatalf("empty list = %q, want \"[]\"", raw)
	}
}

// TestScansGetUnknownRun verifies 404 for a nonexistent run.
func TestScansGetUnknownRun(t *testing.T) {
	ts, _ := newTestServer(t)
	code, _ := getRaw(t, ts.URL+"/api/runs/999999/scans")
	if code != http.StatusNotFound {
		t.Fatalf("get scans unknown run: got %d, want 404", code)
	}
}

// TestRunDetailIncludesScans verifies GET /api/runs/{id} carries the scans
// list ([] when empty, populated after a POST).
func TestRunDetailIncludesScans(t *testing.T) {
	ts, _ := newTestServer(t)
	c := ts.Client()
	createPipeline(t, c, ts.URL, "linear", linearYAML)
	runID := triggerRun(t, c, ts.URL, "linear")

	// Empty before any scan.
	code, raw := getRaw(t, fmt.Sprintf("%s/api/runs/%d", ts.URL, runID))
	if code != http.StatusOK {
		t.Fatalf("get run: got %d", code)
	}
	var detail map[string]any
	if err := json.Unmarshal([]byte(raw), &detail); err != nil {
		t.Fatalf("unmarshal detail: %v", err)
	}
	scans, ok := detail["scans"].([]any)
	if !ok {
		t.Fatalf("run detail missing scans array: %v", detail["scans"])
	}
	if len(scans) != 0 {
		t.Fatalf("expected empty scans, got %v", scans)
	}

	// Populated after a POST.
	body := map[string]any{
		"tool": "trivy", "target": "nginx:1.25", "mode": "image",
		"findings_count": 1, "severity": map[string]any{"HIGH": 1}, "report_json": "{}",
	}
	code, out := postScanBody(t, c, ts.URL, runID, body)
	if code != http.StatusOK {
		t.Fatalf("post scan: got %d (body=%v)", code, out)
	}
	code, raw = getRaw(t, fmt.Sprintf("%s/api/runs/%d", ts.URL, runID))
	if code != http.StatusOK {
		t.Fatalf("get run after scan: got %d", code)
	}
	detail = map[string]any{}
	if err := json.Unmarshal([]byte(raw), &detail); err != nil {
		t.Fatalf("unmarshal detail: %v", err)
	}
	scans, ok = detail["scans"].([]any)
	if !ok || len(scans) != 1 {
		t.Fatalf("expected 1 scan in run detail, got %v", detail["scans"])
	}
	scan, _ := scans[0].(map[string]any)
	if scan["tool"] != "trivy" || scan["mode"] != "image" || scan["target"] != "nginx:1.25" {
		t.Fatalf("scan in run detail wrong: %v", scan)
	}
}

// TestScansPostToolWhitelist verifies the P6③ tool whitelist: trivy,
// gitleaks and semgrep are accepted; every other tool (including case
// variants) is rejected with 400.
func TestScansPostToolWhitelist(t *testing.T) {
	ts, _ := newTestServer(t)
	c := ts.Client()
	createPipeline(t, c, ts.URL, "linear", linearYAML)
	runID := triggerRun(t, c, ts.URL, "linear")

	for _, tool := range []string{"trivy", "gitleaks", "semgrep"} {
		code, out := postScanBody(t, c, ts.URL, runID, map[string]any{
			"tool": tool, "target": "/tmp/repo", "mode": "fs",
			"findings_count": 0, "severity": map[string]any{}, "report_json": "{}",
		})
		if code != http.StatusOK {
			t.Fatalf("tool %q: got %d, want 200 (body=%v)", tool, code, out)
		}
	}
	for _, tool := range []string{"nuclei", "TRIVY", "trivy2"} {
		code, out := postScanBody(t, c, ts.URL, runID, map[string]any{
			"tool": tool, "target": "/tmp/repo", "mode": "fs",
		})
		if code != http.StatusBadRequest {
			t.Fatalf("tool %q: got %d, want 400 (body=%v)", tool, code, out)
		}
	}
}
