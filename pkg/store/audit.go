// Audit-event persistence (task ③): the append-only audit_events stream.
// Rows are written by the API layer at every mutation/auth/SCM decision
// point and read back via GET /api/audit and the `flowstallion audit` CLI. The table
// is append-only by design: no UPDATE/DELETE paths are provided here.
package store

import (
	"fmt"
	"strings"
	"time"
)

// AuditEvent is one row of the audit_events table.
type AuditEvent struct {
	ID      int64
	TS      string // RFC3339 UTC; assigned by AddAuditEvent when empty
	Actor   string // "bob" | "anonymous" | "scm:github" ...
	Action  string // closed set, see pkg/api action constants
	Target  string // "run:5" | "pipeline:demo" | "user:bob" | "POST /api/users" ...
	Outcome string // ok | invalid | denied | not_found | conflict | error
	Detail  string // key=value / short JSON; must never contain passwords or secret values
	Src     string // client IP (host part of RemoteAddr; "" when unparseable)
}

// AuditFilter narrows ListAuditEvents results. All string filters are
// exact-match and optional ("" = no filter); After is an id cursor
// (only events with id < After); Since is a time lower bound (ts >= Since);
// Limit defaults to 50 and caps at 200.
type AuditFilter struct {
	Actor  string
	Action string
	Target string
	After  int64 // <=0 means "no cursor"
	Since  time.Time
	Limit  int // <=0 -> 50; >200 -> 200
}

// AddAuditEvent appends one audit event, stamping now() when a.TS is empty.
// All fields are parameterised; no user input reaches SQL.
func (s *Store) AddAuditEvent(a AuditEvent) error {
	ts := a.TS
	if ts == "" {
		ts = now()
	}
	if _, err := s.db.Exec(
		`INSERT INTO audit_events (ts, actor, action, target, outcome, detail, src)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ts, a.Actor, a.Action, a.Target, a.Outcome, a.Detail, a.Src,
	); err != nil {
		return fmt.Errorf("store: add audit event: %w", err)
	}
	return nil
}

// ListAuditEvents returns up to Limit most-recent events matching the
// filter, ordered by id DESC (newest first).
func (s *Store) ListAuditEvents(f AuditFilter) ([]AuditEvent, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	var b strings.Builder
	b.WriteString(`SELECT id, ts, actor, action, target, outcome, detail, src
		FROM audit_events`)
	var args []any
	conds := make([]string, 0, 4)
	if f.Actor != "" {
		conds = append(conds, "actor = ?")
		args = append(args, f.Actor)
	}
	if f.Action != "" {
		conds = append(conds, "action = ?")
		args = append(args, f.Action)
	}
	if f.Target != "" {
		conds = append(conds, "target = ?")
		args = append(args, f.Target)
	}
	if f.After > 0 {
		conds = append(conds, "id < ?")
		args = append(args, f.After)
	}
	if !f.Since.IsZero() {
		// ts is stored as RFC3339 UTC ("...Z"); normalising to the same
		// format makes lexicographic comparison chronological.
		conds = append(conds, "ts >= ?")
		args = append(args, f.Since.UTC().Format(time.RFC3339))
	}
	if len(conds) > 0 {
		b.WriteString(" WHERE ")
		b.WriteString(strings.Join(conds, " AND "))
	}
	b.WriteString(" ORDER BY id DESC LIMIT ?")
	args = append(args, limit)

	rows, err := s.db.Query(b.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("store: list audit events: %w", err)
	}
	defer rows.Close()
	out := make([]AuditEvent, 0, limit)
	for rows.Next() {
		var e AuditEvent
		if err := rows.Scan(&e.ID, &e.TS, &e.Actor, &e.Action, &e.Target, &e.Outcome, &e.Detail, &e.Src); err != nil {
			return nil, fmt.Errorf("store: scan audit event: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list audit events: %w", err)
	}
	return out, nil
}
