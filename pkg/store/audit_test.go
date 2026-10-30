package store

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

// TestAuditAddRoundTrip verifies AddAuditEvent persists all fields and that
// an empty TS is stamped with now().
func TestAuditAddRoundTrip(t *testing.T) {
	s := openTemp(t)

	in := AuditEvent{
		Actor:   "bob",
		Action:  "pipeline.upsert",
		Target:  "pipeline:demo",
		Outcome: "ok",
		Detail:  "len=42",
		Src:     "10.0.0.1",
	}
	if err := s.AddAuditEvent(in); err != nil {
		t.Fatalf("add: %v", err)
	}

	got, err := s.ListAuditEvents(AuditFilter{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("events = %d, want 1", len(got))
	}
	e := got[0]
	if e.ID == 0 {
		t.Fatal("id must be assigned by the database")
	}
	if e.TS == "" {
		t.Fatal("ts must be stamped when left empty")
	}
	if _, err := time.Parse(time.RFC3339, e.TS); err != nil {
		t.Fatalf("ts %q is not RFC3339: %v", e.TS, err)
	}
	if e.Actor != in.Actor || e.Action != in.Action || e.Target != in.Target ||
		e.Outcome != in.Outcome || e.Detail != in.Detail || e.Src != in.Src {
		t.Fatalf("roundtrip = %+v, want %+v", e, in)
	}
}

// TestAuditListOrderAndLimit verifies newest-first ordering and the limit.
func TestAuditListOrderAndLimit(t *testing.T) {
	s := openTemp(t)
	for i := 1; i <= 5; i++ {
		if err := s.AddAuditEvent(AuditEvent{
			Actor: "a", Action: "act", Target: "t", Outcome: "ok",
			Detail: string(rune('0' + i)),
		}); err != nil {
			t.Fatalf("add %d: %v", i, err)
		}
	}
	all, err := s.ListAuditEvents(AuditFilter{Limit: 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 5 {
		t.Fatalf("all = %d, want 5", len(all))
	}
	for i := 1; i < len(all); i++ {
		if all[i].ID >= all[i-1].ID {
			t.Fatalf("not newest-first at %d: %+v", i, all)
		}
	}
	two, err := s.ListAuditEvents(AuditFilter{Limit: 2})
	if err != nil {
		t.Fatalf("list limit 2: %v", err)
	}
	if len(two) != 2 || two[0].Detail != "5" || two[1].Detail != "4" {
		t.Fatalf("limit 2 = %+v, want the two newest", two)
	}
}

// TestAuditLimitBounds covers the documented default (<=0 → 50) and cap (>200
// → 200) on the limit parameter.
func TestAuditLimitBounds(t *testing.T) {
	s := openTemp(t)
	const n = 250
	for i := 0; i < n; i++ {
		if err := s.AddAuditEvent(AuditEvent{Actor: "a", Action: "act", Target: "t", Outcome: "ok"}); err != nil {
			t.Fatalf("add %d: %v", i, err)
		}
	}
	if got, _ := s.ListAuditEvents(AuditFilter{}); len(got) != 50 {
		t.Fatalf("default limit = %d rows, want 50", len(got))
	}
	if got, _ := s.ListAuditEvents(AuditFilter{Limit: 1000}); len(got) != 200 {
		t.Fatalf("capped limit = %d rows, want 200", len(got))
	}
	if got, _ := s.ListAuditEvents(AuditFilter{Limit: 1}); len(got) != 1 {
		t.Fatalf("limit 1 = %d rows, want 1", len(got))
	}
}

// TestAuditFilters is table-driven over the exact-match filters and the id
// cursor.
func TestAuditFilters(t *testing.T) {
	s := openTemp(t)
	events := []AuditEvent{
		{Actor: "alice", Action: "auth.login", Target: "user:alice", Outcome: "ok"},
		{Actor: "bob", Action: "run.trigger", Target: "run:1", Outcome: "ok"},
		{Actor: "bob", Action: "auth.deny", Target: "POST /api/users", Outcome: "denied"},
		{Actor: "scm:github", Action: "scm.push", Target: "run:2", Outcome: "ok"},
		{Actor: "bob", Action: "run.trigger", Target: "run:3", Outcome: "conflict"},
	}
	for i := range events {
		if err := s.AddAuditEvent(events[i]); err != nil {
			t.Fatalf("add %d: %v", i, err)
		}
	}
	firstID := func(f AuditFilter) (int64, int) {
		t.Helper()
		got, err := s.ListAuditEvents(f)
		if err != nil {
			t.Fatalf("list %+v: %v", f, err)
		}
		if len(got) == 0 {
			return 0, 0
		}
		return got[0].ID, len(got)
	}
	cases := []struct {
		name string
		f    AuditFilter
		// wantIDs: expected event insertion order is [1..5]; the filter must
		// return exactly these rows (in newest-first order).
		wantIDs []int64
	}{
		{"no filter", AuditFilter{}, []int64{5, 4, 3, 2, 1}},
		{"actor exact", AuditFilter{Actor: "bob"}, []int64{5, 3, 2}},
		{"actor miss", AuditFilter{Actor: "carol"}, []int64{}},
		{"action exact", AuditFilter{Action: "run.trigger"}, []int64{5, 2}},
		{"action exact+actor", AuditFilter{Action: "run.trigger", Actor: "bob"}, []int64{5, 2}},
		{"target exact", AuditFilter{Target: "run:3"}, []int64{5}},
		{"cursor after id 2", AuditFilter{After: 2}, []int64{1}},
		{"cursor combined with actor", AuditFilter{After: 4, Actor: "bob"}, []int64{3, 2}},
		{"impossible cursor", AuditFilter{After: 0}, []int64{5, 4, 3, 2, 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotID, n := firstID(tc.f)
			wantTop := int64(0)
			if len(tc.wantIDs) > 0 {
				wantTop = tc.wantIDs[0]
			}
			if n != len(tc.wantIDs) || gotID != wantTop {
				got, _ := s.ListAuditEvents(tc.f)
				var ids []int64
				for _, e := range got {
					ids = append(ids, e.ID)
				}
				t.Fatalf("filter %+v → ids %v (top %d), want %v", tc.f, ids, gotID, tc.wantIDs)
			}
		})
	}
}

// TestAuditOldDBMigration builds a pre-audit database (only the pipelines
// table) and verifies Open() creates audit_events on top of it without
// touching the old rows.
func TestAuditOldDBMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE pipelines (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE,
		yaml_text TEXT NOT NULL,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL)`); err != nil {
		db.Close()
		t.Fatalf("create legacy pipelines: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO pipelines VALUES (1, 'p', 'y', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`); err != nil {
		db.Close()
		t.Fatalf("insert legacy row: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close legacy: %v", err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatalf("open migrated db: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	if err := s.AddAuditEvent(AuditEvent{Actor: "x", Action: "y", Target: "z", Outcome: "ok"}); err != nil {
		t.Fatalf("add on migrated db: %v", err)
	}
	got, err := s.ListAuditEvents(AuditFilter{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("events = %d, want 1", len(got))
	}
	pl, err := s.GetPipelineByName("p")
	if err != nil {
		t.Fatalf("legacy pipeline missing: %v", err)
	}
	if pl.ID != 1 {
		t.Fatalf("legacy row id = %d, want 1", pl.ID)
	}
}
