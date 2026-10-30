// Package finops reads and aggregates the FlowStallion JSONL cost ledger
// (FLOWSTALLION_COST_LEDGER, default ~/.flowstallion/cost-ledger.jsonl). It mirrors
// the Python reference implementation (agent/flowstallion_agent/cost.py): strict
// line-by-line parsing with 1-based physical line numbers, missing-field
// defaults, and cost-descending aggregation with stable tie order.
package finops

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DefaultLedger is the ledger path used when FLOWSTALLION_COST_LEDGER is unset.
const DefaultLedger = "~/.flowstallion/cost-ledger.jsonl"

// EnvLedger is the environment variable that overrides the ledger path.
const EnvLedger = "FLOWSTALLION_COST_LEDGER"

// LineError reports a ledger line that could not be parsed. Line is the
// 1-based physical line number (blank lines are counted too).
type LineError struct {
	Line int
	Msg  string
}

func (e *LineError) Error() string {
	return fmt.Sprintf("line %d: %s", e.Line, e.Msg)
}

// IsLineError reports whether err is a *LineError.
func IsLineError(err error) bool {
	var le *LineError
	return errors.As(err, &le)
}

// Record is one cost-ledger line. Field names and defaults mirror the
// Python CostRecord in agent/flowstallion_agent/cost.py.
type Record struct {
	TS               string // "" when absent; an explicit null is an error
	Source           string // "" when absent; an explicit null is an error
	RunID            string // "" when null/absent
	PR               string // "unknown" when absent; an explicit null is an error
	Team             string // "unknown" when absent; an explicit null is an error
	Model            string // "" when null/absent
	PromptTokens     int
	CompletionTokens int
	TotalTokens      int
	Cost             float64
	Namespace        string // "" when null/absent
	Pod              string // "" when null/absent
}

// rawLine is the decoded form of one ledger line: a JSON object with the
// field names of cost.py's CostRecord. Lines are decoded into a map of raw
// messages rather than a struct because encoding/json sets a pointer field
// to nil on a JSON null without calling its UnmarshalJSON — a struct field
// cannot tell "key absent" (Python default applies) from "explicit null"
// (a Python parse error). The map keeps both signals.
type rawLine map[string]json.RawMessage

// strField reads a required string (ts, source, pr, team): absent -> def,
// present non-string (including null) -> error, matching Python's str_field
// (d.get(name, default) then an isinstance check that rejects None).
func strField(line rawLine, name, def string) (string, error) {
	raw, ok := line[name]
	if !ok {
		return def, nil
	}
	if string(raw) == "null" {
		return "", fmt.Errorf("%s: expected str, got null", name)
	}
	var v string
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", fmt.Errorf("%s: %v", name, err)
	}
	return v, nil
}

// optStrField reads an optional string (run_id, model, namespace, pod):
// absent or null -> "", present non-string -> error (Python's opt_str_field
// returns None for both null and absent keys).
func optStrField(line rawLine, name string) (string, error) {
	raw, ok := line[name]
	if !ok || string(raw) == "null" {
		return "", nil
	}
	var v string
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", fmt.Errorf("%s: %v", name, err)
	}
	return v, nil
}

// intField reads an int token counter: absent -> 0, explicit null, bool, or
// non-integer number -> error (Python's int_field rejects all of those).
func intField(line rawLine, name string) (int, error) {
	raw, ok := line[name]
	if !ok {
		return 0, nil
	}
	if string(raw) == "null" {
		return 0, fmt.Errorf("%s: expected int, got null", name)
	}
	var v int
	if err := json.Unmarshal(raw, &v); err != nil {
		return 0, fmt.Errorf("%s: %v", name, err)
	}
	return v, nil
}

// floatField reads cost: absent -> 0, explicit null or bool -> error
// (Python's float_field rejects bool explicitly).
func floatField(line rawLine, name string) (float64, error) {
	raw, ok := line[name]
	if !ok {
		return 0, nil
	}
	if string(raw) == "null" {
		return 0, fmt.Errorf("%s: expected number, got null", name)
	}
	var v float64
	if err := json.Unmarshal(raw, &v); err != nil {
		return 0, fmt.Errorf("%s: %v", name, err)
	}
	return v, nil
}

// record builds a Record from a decoded line, mirroring
// CostRecord.from_dict field by field.
func (r rawLine) record() (Record, error) {
	ts, err := strField(r, "ts", "")
	if err != nil {
		return Record{}, err
	}
	source, err := strField(r, "source", "")
	if err != nil {
		return Record{}, err
	}
	pr, err := strField(r, "pr", "unknown")
	if err != nil {
		return Record{}, err
	}
	team, err := strField(r, "team", "unknown")
	if err != nil {
		return Record{}, err
	}
	runID, err := optStrField(r, "run_id")
	if err != nil {
		return Record{}, err
	}
	model, err := optStrField(r, "model")
	if err != nil {
		return Record{}, err
	}
	prompt, err := intField(r, "prompt_tokens")
	if err != nil {
		return Record{}, err
	}
	completion, err := intField(r, "completion_tokens")
	if err != nil {
		return Record{}, err
	}
	total, err := intField(r, "total_tokens")
	if err != nil {
		return Record{}, err
	}
	cost, err := floatField(r, "cost")
	if err != nil {
		return Record{}, err
	}
	namespace, err := optStrField(r, "namespace")
	if err != nil {
		return Record{}, err
	}
	pod, err := optStrField(r, "pod")
	if err != nil {
		return Record{}, err
	}
	return Record{
		TS:               ts,
		Source:           source,
		RunID:            runID,
		PR:               pr,
		Team:             team,
		Model:            model,
		PromptTokens:     prompt,
		CompletionTokens: completion,
		TotalTokens:      total,
		Cost:             cost,
		Namespace:        namespace,
		Pod:              pod,
	}, nil
}

// ReadFile parses a JSONL cost ledger. Blank lines are skipped; every other
// line must be a JSON object with the field types of cost.py's CostRecord
// (missing fields fall back to the same defaults). The first bad line stops
// the read and is reported as *LineError with its 1-based physical line
// number. A missing file returns the underlying os error (fs.ErrNotExist).
func ReadFile(path string) ([]Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := make([]Record, 0, 64)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if line == "null" {
			return nil, &LineError{Line: lineNo, Msg: "expected object, got null"}
		}
		var r rawLine
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return nil, &LineError{Line: lineNo, Msg: "malformed JSON: " + err.Error()}
		}
		rec, err := r.record()
		if err != nil {
			return nil, &LineError{Line: lineNo, Msg: err.Error()}
		}
		out = append(out, rec)
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			// The failed line is the one after the last successfully scanned.
			return nil, &LineError{Line: lineNo + 1, Msg: "line exceeds 1 MiB"}
		}
		return nil, err
	}
	return out, nil
}

// LedgerPath resolves the ledger file path: env FLOWSTALLION_COST_LEDGER
// (trimmed), falling back to DefaultLedger. Any leading "~" (including the
// "~user" form) is stripped and the remainder is joined to the current
// user's home directory. Unlike Python's os.path.expanduser, which resolves
// "~user" to user's home, this keeps everything under the caller's HOME
// (~user/x -> $HOME/user/x). If the home directory cannot be determined the
// literal "~" path is kept, which then fails as a missing file.
func LedgerPath() string {
	p := strings.TrimSpace(os.Getenv(EnvLedger))
	if p == "" {
		p = DefaultLedger
	}
	if strings.HasPrefix(p, "~") {
		if home, err := os.UserHomeDir(); err == nil {
			p = filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	return p
}

// Row is one aggregate bucket: the group key (named "pr" or "team") plus
// summed counters, matching the JSON shape of Python's cost.aggregate.
type Row map[string]any

// Aggregate groups records by "pr" or "team". Each row carries the group key
// under the by-field name plus records / prompt_tokens / completion_tokens /
// total_tokens / cost_usd. Rows are sorted by cost_usd descending; ties keep
// first-seen order (Python's sort is stable; sort.SliceStable matches that).
func Aggregate(records []Record, by string) ([]Row, error) {
	if by != "pr" && by != "team" {
		return nil, fmt.Errorf("aggregate: by must be \"pr\" or \"team\", got %q", by)
	}
	type agg struct {
		key              string
		records          int
		promptTokens     int64
		completionTokens int64
		totalTokens      int64
		costUSD          float64
	}
	idx := make(map[string]*agg, 8)
	var order []string
	for _, r := range records {
		key := r.PR
		if by == "team" {
			key = r.Team
		}
		g, ok := idx[key]
		if !ok {
			g = &agg{key: key}
			idx[key] = g
			order = append(order, key)
		}
		g.records++
		g.promptTokens += int64(r.PromptTokens)
		g.completionTokens += int64(r.CompletionTokens)
		g.totalTokens += int64(r.TotalTokens)
		g.costUSD += r.Cost
	}
	ags := make([]*agg, 0, len(order))
	for _, k := range order {
		ags = append(ags, idx[k])
	}
	sort.SliceStable(ags, func(i, j int) bool { return ags[i].costUSD > ags[j].costUSD })
	out := make([]Row, 0, len(ags))
	for _, g := range ags {
		out = append(out, Row{
			by:                  g.key,
			"records":           g.records,
			"prompt_tokens":     g.promptTokens,
			"completion_tokens": g.completionTokens,
			"total_tokens":      g.totalTokens,
			"cost_usd":          g.costUSD,
		})
	}
	return out, nil
}

// AggregateByDay groups records by UTC calendar day ("YYYY-MM-DD", the first
// ten chars of an RFC3339 ts). Records whose ts is empty or malformed are
// bucketed under "unknown". Rows carry the "day" key plus records /
// total_tokens / cost_usd and are sorted by day ascending (oldest first) so a
// time series renders left-to-right; "unknown" sorts after real dates and is
// conventionally dropped by chart consumers.
func AggregateByDay(records []Record) []Row {
	type agg struct {
		records     int
		totalTokens int64
		costUSD     float64
	}
	idx := make(map[string]*agg, 8)
	for _, r := range records {
		day := DayOf(r.TS)
		g, ok := idx[day]
		if !ok {
			g = &agg{}
			idx[day] = g
		}
		g.records++
		g.totalTokens += int64(r.TotalTokens)
		g.costUSD += r.Cost
	}
	days := make([]string, 0, len(idx))
	for d := range idx {
		days = append(days, d)
	}
	sort.Strings(days)
	out := make([]Row, 0, len(days))
	for _, d := range days {
		g := idx[d]
		out = append(out, Row{
			"day":          d,
			"records":      g.records,
			"total_tokens": g.totalTokens,
			"cost_usd":     g.costUSD,
		})
	}
	return out
}

// DayOf extracts the UTC "YYYY-MM-DD" day from an RFC3339 timestamp.
// Empty or malformed timestamps (fewer than 10 chars, or missing the dashes)
// yield "unknown" rather than a partial date.
func DayOf(ts string) string {
	if len(ts) < 10 || ts[4] != '-' || ts[7] != '-' {
		return "unknown"
	}
	return ts[:10]
}

// Total sums every record into one bucket (the /api/cost "total" row).
func Total(records []Record) map[string]any {
	var prompt, completion, total int64
	var cost float64
	for _, r := range records {
		prompt += int64(r.PromptTokens)
		completion += int64(r.CompletionTokens)
		total += int64(r.TotalTokens)
		cost += r.Cost
	}
	return map[string]any{
		"records":           len(records),
		"prompt_tokens":     prompt,
		"completion_tokens": completion,
		"total_tokens":      total,
		"cost_usd":          cost,
	}
}
