package finops

import (
	"errors"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sampleLedger mirrors the 11-record fixture produced by
// `python -m flowstallion_agent.cost --sample` (5 llm + 6 cloud records).
const sampleLedger = `{"ts":"2026-10-22T09:00:00Z","source":"llm","run_id":"42","pr":"pr-101","team":"team-infra","model":"gpt-4o-mini","prompt_tokens":12000,"completion_tokens":800,"total_tokens":12800,"cost":0.00228}
{"ts":"2026-10-22T10:30:00Z","source":"llm","run_id":"43","pr":"pr-101","team":"team-infra","model":"gpt-4o-mini","prompt_tokens":30000,"completion_tokens":1500,"total_tokens":31500,"cost":0.0054}
{"ts":"2026-10-22T14:15:00Z","source":"llm","run_id":"47","pr":"pr-101","team":"team-infra","model":"gpt-4o-mini","prompt_tokens":5000,"completion_tokens":400,"total_tokens":5400,"cost":0.00099}
{"ts":"2026-10-22T09:45:00Z","source":"llm","run_id":"51","pr":"pr-207","team":"team-data","model":"gpt-4o-mini","prompt_tokens":20000,"completion_tokens":900,"total_tokens":20900,"cost":0.00354}
{"ts":"2026-10-22T16:20:00Z","source":"llm","run_id":"55","pr":"pr-207","team":"team-data","model":"gpt-4o-mini","prompt_tokens":8000,"completion_tokens":600,"total_tokens":8600,"cost":0.00156}
{"ts":"2026-10-22T00:00:00Z","source":"cloud","pr":"pr-101","team":"team-infra","namespace":"prod-infra","pod":"api-7d9f4c6","cost":0.42}
{"ts":"2026-10-22T06:00:00Z","source":"cloud","pr":"pr-101","team":"team-infra","namespace":"prod-infra","pod":"worker-2b8e1","cost":0.61}
{"ts":"2026-10-22T00:00:00Z","source":"cloud","pr":"pr-101","team":"team-data","namespace":"data-lake","pod":"etl-9c3f7","cost":1.25}
{"ts":"2026-10-22T00:00:00Z","source":"cloud","pr":"pr-207","team":"team-infra","namespace":"prod-search","pod":"index-5f1a2","cost":0.87}
{"ts":"2026-10-22T06:00:00Z","source":"cloud","pr":"pr-207","team":"team-data","namespace":"data-lake","pod":"etl-4d7b8","cost":2.03}
{"ts":"2026-10-22T12:00:00Z","source":"cloud","pr":"pr-207","team":"team-data","namespace":"data-lake","pod":"spark-8e2c4","cost":0.55}
`

func writeLedger(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cost-ledger.jsonl")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write ledger: %v", err)
	}
	return p
}

func TestReadFileValid(t *testing.T) {
	p := writeLedger(t, sampleLedger)
	recs, err := ReadFile(p)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(recs) != 11 {
		t.Fatalf("got %d records, want 11", len(recs))
	}
	r0 := recs[0]
	if r0.Source != "llm" || r0.PR != "pr-101" || r0.Team != "team-infra" ||
		r0.Model != "gpt-4o-mini" || r0.RunID != "42" ||
		r0.PromptTokens != 12000 || r0.CompletionTokens != 800 || r0.TotalTokens != 12800 {
		t.Fatalf("record 0 wrong: %+v", r0)
	}
	if math.Abs(r0.Cost-0.00228) > 1e-12 {
		t.Fatalf("record 0 cost = %v, want 0.00228", r0.Cost)
	}
	// Cloud record: optional token fields default to 0, namespace/pod set.
	c0 := recs[5]
	if c0.Source != "cloud" || c0.Namespace != "prod-infra" || c0.Pod != "api-7d9f4c6" ||
		c0.RunID != "" || c0.Model != "" || c0.TotalTokens != 0 {
		t.Fatalf("cloud record 5 wrong: %+v", c0)
	}
}

func TestReadFileDefaultsAndBlankLines(t *testing.T) {
	// A minimal object gets every default (pr/team -> "unknown"); blank
	// lines are skipped and still count toward line numbering.
	content := "\n\n{}\n\n{\"source\":\"cloud\",\"cost\":0.1}\n"
	recs, err := ReadFile(writeLedger(t, content))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2", len(recs))
	}
	r0 := recs[0]
	if r0.PR != "unknown" || r0.Team != "unknown" || r0.Source != "" ||
		r0.RunID != "" || r0.Model != "" || r0.Cost != 0.0 {
		t.Fatalf("defaults wrong: %+v", r0)
	}
	if recs[1].Source != "cloud" || recs[1].PR != "unknown" {
		t.Fatalf("second record wrong: %+v", recs[1])
	}
}

// TestReadFileNullOptionalStrings verifies that null optional string fields
// (run_id, model, namespace, pod) map to "" (Python's opt_str_field returns
// None for both null and absent keys).
func TestReadFileNullOptionalStrings(t *testing.T) {
	content := `{"run_id": null, "model": null, "namespace": null, "pod": null}
`
	recs, err := ReadFile(writeLedger(t, content))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	r := recs[0]
	if r.RunID != "" || r.Model != "" || r.Namespace != "" || r.Pod != "" {
		t.Fatalf("null optional strings should be empty: %+v", r)
	}
}

// TestReadFileLineTooLong verifies that a line exceeding the 1 MiB scanner
// buffer surfaces as a *LineError (line 1), not a bare scanner error.
func TestReadFileLineTooLong(t *testing.T) {
	content := strings.Repeat("a", 1<<20+1) + "\n"
	_, err := ReadFile(writeLedger(t, content))
	var le *LineError
	if !errors.As(err, &le) || le.Line != 1 {
		t.Fatalf("want *LineError line 1, got %v", err)
	}
}

func TestReadFileEmpty(t *testing.T) {
	recs, err := ReadFile(writeLedger(t, ""))
	if err != nil {
		t.Fatalf("ReadFile empty: %v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("got %d records, want 0", len(recs))
	}
}

func TestReadFileMissing(t *testing.T) {
	_, err := ReadFile(filepath.Join(t.TempDir(), "nope.jsonl"))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing file: want ErrNotExist, got %v", err)
	}
}

func TestReadFileBadLines(t *testing.T) {
	tests := []struct {
		name    string
		content string
		line    int
	}{
		{"bad json on line 2", `{"source":"llm"}
{broken
`, 2},
		{"array line", `[1, 2]
`, 1},
		{"null line", "null\n", 1},
		{"number line", "42\n", 1},
		{"string line", `"hello"\n`, 1},
		{"pr wrong type", `{"pr": 5}
`, 1},
		{"pr null", `{"pr": null}
`, 1},
		{"ts null", `{"ts": null}
`, 1},
		{"source null", `{"source": null}
`, 1},
		{"team null", `{"team": null}
`, 1},
		{"prompt_tokens bool", `{"prompt_tokens": true}
`, 1},
		{"prompt_tokens float", `{"prompt_tokens": 1.5}
`, 1},
		{"prompt_tokens null", `{"prompt_tokens": null}
`, 1},
		{"cost null", `{"cost": null}
`, 1},
		{"cost bool", `{"cost": true}
`, 1},
		{"bad line after blanks", `
{"source":"llm"}
{"ts": 7}
`, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ReadFile(writeLedger(t, tt.content))
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			var le *LineError
			if !errors.As(err, &le) {
				t.Fatalf("want *LineError, got %T: %v", err, err)
			}
			if le.Line != tt.line {
				t.Fatalf("line = %d, want %d (msg=%q)", le.Line, tt.line, le.Msg)
			}
		})
	}
}

func rowOf(rows []Row, key string) (Row, bool) {
	for _, r := range rows {
		if r["pr"] == key || r["team"] == key {
			return r, true
		}
	}
	return nil, false
}

func TestAggregateByPr(t *testing.T) {
	recs, err := ReadFile(writeLedger(t, sampleLedger))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	rows, err := Aggregate(recs, "pr")
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2: %v", len(rows), rows)
	}
	// Cost-descending: pr-207 (3.4551) before pr-101 (2.28867).
	if rows[0]["pr"] != "pr-207" || rows[1]["pr"] != "pr-101" {
		t.Fatalf("row order wrong: %v", rows)
	}
	r207, _ := rowOf(rows, "pr-207")
	if r207["records"] != 5 || r207["total_tokens"] != int64(29500) {
		t.Fatalf("pr-207 counts wrong: %v", r207)
	}
	if c := r207["cost_usd"].(float64); math.Abs(c-3.4551) > 1e-9 {
		t.Fatalf("pr-207 cost = %v, want 3.4551", c)
	}
	r101, _ := rowOf(rows, "pr-101")
	if r101["records"] != 6 || r101["total_tokens"] != int64(49700) {
		t.Fatalf("pr-101 counts wrong: %v", r101)
	}
	if c := r101["cost_usd"].(float64); math.Abs(c-2.28867) > 1e-9 {
		t.Fatalf("pr-101 cost = %v, want 2.28867", c)
	}
}

func TestAggregateByTeam(t *testing.T) {
	recs, _ := ReadFile(writeLedger(t, sampleLedger))
	rows, err := Aggregate(recs, "team")
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	if rows[0]["team"] != "team-data" || rows[1]["team"] != "team-infra" {
		t.Fatalf("row order wrong: %v", rows)
	}
	td, _ := rowOf(rows, "team-data")
	if td["records"] != 5 || td["total_tokens"] != int64(29500) {
		t.Fatalf("team-data counts wrong: %v", td)
	}
	if c := td["cost_usd"].(float64); math.Abs(c-3.8351) > 1e-9 {
		t.Fatalf("team-data cost = %v, want 3.8351", c)
	}
	ti, _ := rowOf(rows, "team-infra")
	if c := ti["cost_usd"].(float64); math.Abs(c-1.90867) > 1e-9 {
		t.Fatalf("team-infra cost = %v, want 1.90867", c)
	}
}

func TestAggregateInvalidBy(t *testing.T) {
	if _, err := Aggregate(nil, "cost"); err == nil {
		t.Fatal("want error for by=cost")
	}
}

func TestAggregateTieStability(t *testing.T) {
	recs := []Record{
		{PR: "b", Cost: 1.0},
		{PR: "a", Cost: 1.0},
		{PR: "c", Cost: 2.0},
	}
	rows, err := Aggregate(recs, "pr")
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	// c (2.0) first; the 1.0 tie keeps first-seen order (b then a).
	want := []string{"c", "b", "a"}
	for i, w := range want {
		if got, _ := rows[i]["pr"].(string); got != w {
			gotOrder := make([]string, len(rows))
			for j := range rows {
				gotOrder[j], _ = rows[j]["pr"].(string)
			}
			t.Fatalf("order = %v, want %v", gotOrder, want)
		}
	}
}

func TestTotal(t *testing.T) {
	recs, _ := ReadFile(writeLedger(t, sampleLedger))
	tot := Total(recs)
	if tot["records"] != 11 || tot["total_tokens"] != int64(79200) {
		t.Fatalf("total counts wrong: %v", tot)
	}
	if c := tot["cost_usd"].(float64); math.Abs(c-5.74377) > 1e-9 {
		t.Fatalf("total cost = %v, want 5.74377", c)
	}
	if p := tot["prompt_tokens"].(int64); p != 75000 {
		t.Fatalf("prompt tokens = %d, want 75000", p)
	}
	if c := tot["completion_tokens"].(int64); c != 4200 {
		t.Fatalf("completion tokens = %d, want 4200", c)
	}
}

// TestDayOf is table-driven: valid RFC3339-style timestamps yield the first
// ten chars; short or malformed input yields "unknown".
func TestDayOf(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"2026-10-22T09:00:00Z", "2026-10-22"},
		{"2026-01-02T03:04:05+08:00", "2026-01-02"},
		{"2026-10-22", "2026-10-22"},
		{"", "unknown"},
		{"2026-10", "unknown"},
		{"2026/10/22T09:00:00Z", "unknown"},
		{"not-a-timestamp", "unknown"},
	}
	for _, tc := range cases {
		if got := DayOf(tc.in); got != tc.want {
			t.Errorf("DayOf(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestAggregateByDay buckets records by UTC calendar day, sums counters,
// and returns rows in chronological (oldest-first) order.
func TestAggregateByDay(t *testing.T) {
	recs := []Record{
		{TS: "2026-10-29T09:30:00Z", TotalTokens: 300, Cost: 0.05},
		{TS: "2026-10-28T09:00:00Z", TotalTokens: 100, Cost: 0.20},
		{TS: "2026-10-28T10:00:00Z", TotalTokens: 100, Cost: 0.55},
		{TS: "", TotalTokens: 50, Cost: 0.01}, // malformed ts -> "unknown"
	}
	rows := AggregateByDay(recs)
	if len(rows) != 3 {
		t.Fatalf("rows = %v, want 3 buckets (2 days + unknown)", rows)
	}
	wantOrder := []string{"2026-10-28", "2026-10-29", "unknown"}
	for i, want := range wantOrder {
		if rows[i]["day"] != want {
			t.Fatalf("row %d day = %v, want %q (rows=%v)", i, rows[i]["day"], want, rows)
		}
	}
	// "unknown" sorts after real dates lexicographically.
	if rows[0]["records"] != 2 || rows[0]["total_tokens"] != int64(200) {
		t.Fatalf("2026-10-28 sums wrong: %v", rows[0])
	}
	if c, _ := rows[0]["cost_usd"].(float64); math.Abs(c-0.75) > 1e-12 {
		t.Fatalf("2026-10-28 cost = %v, want 0.75", c)
	}
	if rows[2]["records"] != 1 || rows[2]["total_tokens"] != int64(50) {
		t.Fatalf("unknown bucket = %v, want 1 record / 50 tokens", rows[2])
	}
	// Empty input: non-nil empty slice (JSON []).
	if got := AggregateByDay(nil); got == nil {
		t.Fatal("AggregateByDay(nil) = nil, want non-nil empty slice")
	}
}

func TestLedgerPath(t *testing.T) {
	t.Run("unset", func(t *testing.T) {
		t.Setenv(EnvLedger, "")
		home, err := os.UserHomeDir()
		if err != nil {
			t.Fatalf("UserHomeDir: %v", err)
		}
		if got := LedgerPath(); got != filepath.Join(home, ".flowstallion", "cost-ledger.jsonl") {
			t.Fatalf("LedgerPath() = %q, want %q", got, filepath.Join(home, ".flowstallion", "cost-ledger.jsonl"))
		}
	})
	t.Run("set", func(t *testing.T) {
		t.Setenv(EnvLedger, "  /data/cost/ledger.jsonl  ")
		if got := LedgerPath(); got != "/data/cost/ledger.jsonl" {
			t.Fatalf("LedgerPath() = %q", got)
		}
	})
	t.Run("tilde", func(t *testing.T) {
		t.Setenv(EnvLedger, "~/cost.jsonl")
		home, _ := os.UserHomeDir()
		if got := LedgerPath(); got != filepath.Join(home, "cost.jsonl") {
			t.Fatalf("LedgerPath() = %q", got)
		}
	})
}
