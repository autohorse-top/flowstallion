package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const costLedgerFixture = `{"ts":"2026-10-22T09:00:00Z","source":"llm","run_id":"42","pr":"pr-101","team":"team-infra","model":"gpt-4o-mini","prompt_tokens":12000,"completion_tokens":800,"total_tokens":12800,"cost":0.00228}
{"ts":"2026-10-22T09:45:00Z","source":"llm","run_id":"51","pr":"pr-207","team":"team-data","model":"gpt-4o-mini","prompt_tokens":20000,"completion_tokens":900,"total_tokens":20900,"cost":0.00354}
{"ts":"2026-10-22T00:00:00Z","source":"cloud","pr":"pr-101","team":"team-infra","namespace":"prod-infra","pod":"api-7d9f4c6","cost":0.42}
{"ts":"2026-10-22T00:00:00Z","source":"cloud","pr":"pr-207","team":"team-data","namespace":"data-lake","pod":"etl-9c3f7","cost":1.25}
`

// setLedger writes a JSONL ledger and points FLOWSTALLION_COST_LEDGER at it.
func setLedger(t *testing.T, content string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cost-ledger.jsonl")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write ledger: %v", err)
	}
	t.Setenv("FLOWSTALLION_COST_LEDGER", p)
}

// TestCostByPr verifies GET /api/cost?by=pr aggregates the ledger by PR with
// cost-descending order and a correct total.
func TestCostByPr(t *testing.T) {
	ts, _ := newTestServer(t)
	setLedger(t, costLedgerFixture)
	code, out := doJSON(t, ts.Client(), http.MethodGet, ts.URL+"/api/cost?by=pr", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /api/cost?by=pr: got %d, want 200 (body=%v)", code, out)
	}
	if out["by"] != "pr" {
		t.Fatalf("by = %v, want \"pr\"", out["by"])
	}
	rows, ok := out["rows"].([]any)
	if !ok || len(rows) != 2 {
		t.Fatalf("rows = %v, want 2 entries", out["rows"])
	}
	first, _ := rows[0].(map[string]any)
	if first["pr"] != "pr-207" {
		t.Fatalf("first row = %v, want pr-207 (cost 1.25354 > 0.42228)", first)
	}
	second, _ := rows[1].(map[string]any)
	if second["pr"] != "pr-101" {
		t.Fatalf("second row = %v, want pr-101", second)
	}
	if first["records"] != float64(2) || first["total_tokens"] != float64(20900) {
		t.Fatalf("pr-207 counts wrong: %v", first)
	}
	total, _ := out["total"].(map[string]any)
	if total["records"] != float64(4) || total["total_tokens"] != float64(33700) {
		t.Fatalf("total = %v, want records 4 / total_tokens 33700", total)
	}
	if c, ok := total["cost_usd"].(float64); !ok || c < 1.675 || c > 1.676 {
		t.Fatalf("total cost_usd = %v, want ~1.67582", total["cost_usd"])
	}
}

// TestCostByTeam verifies by=team grouping.
func TestCostByTeam(t *testing.T) {
	ts, _ := newTestServer(t)
	setLedger(t, costLedgerFixture)
	code, out := doJSON(t, ts.Client(), http.MethodGet, ts.URL+"/api/cost?by=team", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /api/cost?by=team: got %d, want 200 (body=%v)", code, out)
	}
	rows := out["rows"].([]any)
	if len(rows) != 2 {
		t.Fatalf("rows = %v, want 2 entries", out["rows"])
	}
	first, _ := rows[0].(map[string]any)
	// team-data: 0.00354 + 1.25 = 1.25354 > team-infra 0.00228 + 0.42 = 0.42228
	if first["team"] != "team-data" {
		t.Fatalf("first row = %v, want team-data", first)
	}
}

// costDayFixture spans three UTC days across both sources, so by=day can be
// checked for grouping, ordering (oldest first) and source filtering.
const costDayFixture = `{"ts":"2026-10-27T08:00:00Z","source":"llm","pr":"pr-1","team":"t-a","total_tokens":100,"cost":0.10}
{"ts":"2026-10-28T09:00:00Z","source":"llm","pr":"pr-2","team":"t-a","total_tokens":200,"cost":0.20}
{"ts":"2026-10-28T10:00:00Z","source":"cloud","pr":"pr-3","team":"t-b","total_tokens":0,"cost":0.55}
{"ts":"2026-10-29T09:30:00Z","source":"llm","pr":"pr-4","team":"t-b","total_tokens":300,"cost":0.05}
`

// TestCostByDay verifies by=day: rows carry a "day" key, are sorted
// chronologically (oldest first), and sums are correct.
func TestCostByDay(t *testing.T) {
	ts, _ := newTestServer(t)
	setLedger(t, costDayFixture)
	code, out := doJSON(t, ts.Client(), http.MethodGet, ts.URL+"/api/cost?by=day", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /api/cost?by=day: got %d, want 200 (body=%v)", code, out)
	}
	if out["by"] != "day" {
		t.Fatalf("by = %v, want \"day\"", out["by"])
	}
	rows, ok := out["rows"].([]any)
	if !ok || len(rows) != 3 {
		t.Fatalf("rows = %v, want 3 days", out["rows"])
	}
	wantDays := []string{"2026-10-27", "2026-10-28", "2026-10-29"}
	for i, want := range wantDays {
		m, _ := rows[i].(map[string]any)
		if m["day"] != want {
			t.Fatalf("row %d day = %v, want %q (rows=%v)", i, m["day"], want, rows)
		}
	}
	d28, _ := rows[1].(map[string]any)
	if d28["records"] != float64(2) || d28["total_tokens"] != float64(200) {
		t.Fatalf("2026-10-28 = %v, want 2 records / 200 tokens", d28)
	}
	if c, _ := d28["cost_usd"].(float64); c < 0.749 || c > 0.751 {
		t.Fatalf("2026-10-28 cost_usd = %v, want 0.75", d28["cost_usd"])
	}
	total, _ := out["total"].(map[string]any)
	if total["records"] != float64(4) || total["total_tokens"] != float64(600) {
		t.Fatalf("total = %v, want 4 records / 600 tokens", total)
	}
}

// TestCostByDaySourceFilter verifies by=day respects the source filter.
func TestCostByDaySourceFilter(t *testing.T) {
	ts, _ := newTestServer(t)
	setLedger(t, costDayFixture)
	code, out := doJSON(t, ts.Client(), http.MethodGet, ts.URL+"/api/cost?by=day&source=llm", nil)
	if code != http.StatusOK {
		t.Fatalf("by=day&source=llm: got %d, want 200 (body=%v)", code, out)
	}
	rows := out["rows"].([]any)
	if len(rows) != 3 {
		t.Fatalf("rows = %v, want 3 days", rows)
	}
	d28, _ := rows[1].(map[string]any)
	if d28["records"] != float64(1) {
		t.Fatalf("2026-10-28 llm records = %v, want 1 (cloud excluded)", d28)
	}
	if c, _ := d28["cost_usd"].(float64); c < 0.199 || c > 0.201 {
		t.Fatalf("2026-10-28 llm cost = %v, want 0.20", d28["cost_usd"])
	}
	if out["source"] != "llm" {
		t.Fatalf("source = %v, want llm", out["source"])
	}
}

// TestCostByDayMissingLedger verifies by=day on a missing ledger yields [].
func TestCostByDayMissingLedger(t *testing.T) {
	ts, _ := newTestServer(t)
	t.Setenv("FLOWSTALLION_COST_LEDGER", filepath.Join(t.TempDir(), "does-not-exist.jsonl"))
	code, out := doJSON(t, ts.Client(), http.MethodGet, ts.URL+"/api/cost?by=day", nil)
	if code != http.StatusOK {
		t.Fatalf("by=day (missing ledger): got %d, want 200 (body=%v)", code, out)
	}
	rows, _ := out["rows"].([]any)
	if rows == nil || len(rows) != 0 {
		t.Fatalf("rows = %v, want empty []", out["rows"])
	}
}

// TestCostSourceFilter verifies source=llm filters cloud records out.
func TestCostSourceFilter(t *testing.T) {
	ts, _ := newTestServer(t)
	setLedger(t, costLedgerFixture)
	code, out := doJSON(t, ts.Client(), http.MethodGet, ts.URL+"/api/cost?by=pr&source=llm", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /api/cost?source=llm: got %d, want 200 (body=%v)", code, out)
	}
	if out["source"] != "llm" {
		t.Fatalf("source = %v, want \"llm\"", out["source"])
	}
	rows := out["rows"].([]any)
	if len(rows) != 2 {
		t.Fatalf("rows = %v, want 2 llm entries", out["rows"])
	}
	total := out["total"].(map[string]any)
	if total["records"] != float64(2) || total["total_tokens"] != float64(33700) {
		t.Fatalf("llm total = %v, want records 2 / total_tokens 33700", total)
	}
	code, out = doJSON(t, ts.Client(), http.MethodGet, ts.URL+"/api/cost?by=pr&source=cloud", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /api/cost?source=cloud: got %d, want 200", code)
	}
	total = out["total"].(map[string]any)
	if total["records"] != float64(2) || total["total_tokens"] != float64(0) {
		t.Fatalf("cloud total = %v, want records 2 / total_tokens 0", total)
	}
}

// TestCostInvalidParams verifies 400s for bad by/source values.
func TestCostInvalidParams(t *testing.T) {
	ts, _ := newTestServer(t)
	setLedger(t, costLedgerFixture)
	for _, q := range []string{"?by=cost", "?by=pr&source=both", "?by=PR"} {
		code, out := doJSON(t, ts.Client(), http.MethodGet, ts.URL+"/api/cost"+q, nil)
		if code != http.StatusBadRequest {
			t.Fatalf("GET /api/cost%s: got %d, want 400 (body=%v)", q, code, out)
		}
	}
}

// TestCostMissingLedger verifies a missing ledger file is not an error.
func TestCostMissingLedger(t *testing.T) {
	ts, _ := newTestServer(t)
	t.Setenv("FLOWSTALLION_COST_LEDGER", filepath.Join(t.TempDir(), "does-not-exist.jsonl"))
	code, out := doJSON(t, ts.Client(), http.MethodGet, ts.URL+"/api/cost?by=pr", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /api/cost (missing ledger): got %d, want 200 (body=%v)", code, out)
	}
	rows, _ := out["rows"].([]any)
	if rows == nil || len(rows) != 0 {
		t.Fatalf("rows = %v, want empty []", out["rows"])
	}
}

// TestCostMalformedLedger verifies a bad line is a 400 with the line number.
func TestCostMalformedLedger(t *testing.T) {
	ts, _ := newTestServer(t)
	setLedger(t, `{"source":"llm","pr":"pr-1","cost":0.1}
{"pr": 42}
`)
	code, out := doJSON(t, ts.Client(), http.MethodGet, ts.URL+"/api/cost?by=pr", nil)
	if code != http.StatusBadRequest {
		t.Fatalf("GET /api/cost (malformed): got %d, want 400 (body=%v)", code, out)
	}
	msg, _ := out["error"].(string)
	if !strings.Contains(msg, "line 2") {
		t.Fatalf("error = %v, want it to mention line 2", out["error"])
	}
}
