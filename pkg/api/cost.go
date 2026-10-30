package api

import (
	"errors"
	"io/fs"
	"net/http"

	"github.com/flowstallion/flowstallion/pkg/finops"
)

// handleCost serves GET /api/cost?by=pr|team|day&source=llm|cloud (viewer+).
// It reads the shared JSONL cost ledger (env FLOWSTALLION_COST_LEDGER, default
// ~/.flowstallion/cost-ledger.jsonl — the same file the Python agent appends to),
// filters by source when requested, and aggregates server-side.
//
// by=day buckets records by UTC calendar day (chronological, oldest first) and
// powers the cost page's 7-day trend chart.
//
// Semantics mirror the Python ledger's strict mode: a missing ledger file is
// NOT an error (fresh install, nothing written yet) and yields zero rows; a
// malformed ledger line is a 400 whose message carries the 1-based physical
// line number.
func (s *Server) handleCost(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	by := q.Get("by")
	if by == "" {
		by = "pr"
	}
	if by != "pr" && by != "team" && by != "day" {
		writeErr(w, http.StatusBadRequest, `by must be "pr", "team" or "day"`)
		return
	}
	source := q.Get("source")
	if source != "" && source != "llm" && source != "cloud" {
		writeErr(w, http.StatusBadRequest, `source must be "llm" or "cloud"`)
		return
	}

	recs, err := finops.ReadFile(finops.LedgerPath())
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			recs = nil // ledger not written yet: zero rows, not an error
		} else {
			var le *finops.LineError
			if errors.As(err, &le) {
				writeErr(w, http.StatusBadRequest, "ledger: "+le.Error())
				return
			}
			writeErr(w, http.StatusInternalServerError, "ledger: "+err.Error())
			return
		}
	}
	if source != "" {
		filtered := make([]finops.Record, 0, len(recs))
		for _, rec := range recs {
			if rec.Source == source {
				filtered = append(filtered, rec)
			}
		}
		recs = filtered
	}
	var rows []finops.Row
	if by == "day" {
		rows = finops.AggregateByDay(recs)
	} else {
		rows, err = finops.Aggregate(recs, by)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	out := map[string]any{
		"by":    by,
		"rows":  rows,
		"total": finops.Total(recs),
	}
	if source != "" {
		out["source"] = source
	}
	writeJSON(w, http.StatusOK, out)
}
