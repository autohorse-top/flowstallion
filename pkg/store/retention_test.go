package store

import "testing"

// TestRetentionEmptyDB (P7⑧): purge queries on an empty database delete
// nothing and do not error.
func TestRetentionEmptyDB(t *testing.T) {
	s := openTemp(t)
	for _, call := range []func() (int64, error){
		func() (int64, error) { return s.PurgeLogsByAge("2026-01-01T00:00:00Z") },
		func() (int64, error) { return s.PurgeLogsKeepLast(1) },
		func() (int64, error) { return s.PurgeCanaryEventsByAge("2026-01-01T00:00:00Z") },
		func() (int64, error) { return s.PurgeCanaryEventsKeepLast(1) },
		func() (int64, error) { return s.PurgeAuditEventsByAge("2026-01-01T00:00:00Z") },
		func() (int64, error) { return s.PurgeAuditEventsKeepLast(1) },
	} {
		if n, err := call(); err != nil || n != 0 {
			t.Fatalf("purge on empty db = (%d, %v), want (0, nil)", n, err)
		}
	}
}

// TestPurgeLogsByAge (P7⑧): a run's log age is COALESCE(started_at,
// created_at) — an old created_at with a recent started_at must survive, an
// old created_at with no started_at must be purged, and a recent run
// survives.
func TestPurgeLogsByAge(t *testing.T) {
	s := openTemp(t)
	pid, _ := s.UpsertPipeline("p", "y")
	rOld, _ := s.CreateRun(pid, "manual", "")
	rStarted, _ := s.CreateRun(pid, "manual", "")
	rRecent, _ := s.CreateRun(pid, "manual", "")

	// rOld: never started, created long ago → age key is created_at (old).
	if _, err := s.db.Exec(`UPDATE runs SET created_at = '2020-01-01T00:00:00Z' WHERE id = ?`, rOld); err != nil {
		t.Fatalf("backdate rOld: %v", err)
	}
	// rStarted: created long ago but started recently → age key is the
	// recent started_at, so it survives the cutoff.
	if _, err := s.db.Exec(
		`UPDATE runs SET created_at = '2020-01-01T00:00:00Z', started_at = '2026-06-01T00:00:00Z' WHERE id = ?`, rStarted,
	); err != nil {
		t.Fatalf("backdate rStarted: %v", err)
	}
	// rRecent: created now.

	for _, r := range []int64{rOld, rStarted, rRecent} {
		for i := 0; i < 2; i++ {
			if _, err := s.AddLog(r, "s", "line"); err != nil {
				t.Fatalf("add log: %v", err)
			}
		}
	}

	n, err := s.PurgeLogsByAge("2026-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("purge by age: %v", err)
	}
	if n != 2 {
		t.Fatalf("purged %d log rows, want 2 (rOld only)", n)
	}
	for r, want := range map[int64]int{rOld: 0, rStarted: 2, rRecent: 2} {
		logs, err := s.ListLogs(r, "s", 0, 0)
		if err != nil {
			t.Fatalf("list logs run %d: %v", r, err)
		}
		if len(logs) != want {
			t.Fatalf("run %d: %d logs left, want %d", r, len(logs), want)
		}
	}
}

// TestPurgeLogsKeepLast (P7⑧): keep-last purges the logs of all but the
// keep most-recent runs (by run id, the insertion order).
func TestPurgeLogsKeepLast(t *testing.T) {
	s := openTemp(t)
	pid, _ := s.UpsertPipeline("p", "y")
	ids := make([]int64, 5)
	for i := range ids {
		var err error
		if ids[i], err = s.CreateRun(pid, "manual", ""); err != nil {
			t.Fatalf("create run %d: %v", i, err)
		}
		if _, err := s.AddLog(ids[i], "s", "line"); err != nil {
			t.Fatalf("add log: %v", err)
		}
	}

	n, err := s.PurgeLogsKeepLast(2)
	if err != nil {
		t.Fatalf("purge keep-last: %v", err)
	}
	if n != 3 {
		t.Fatalf("purged %d log rows, want 3 (runs 1-3)", n)
	}
	for i, id := range ids {
		logs, err := s.ListLogs(id, "s", 0, 0)
		if err != nil {
			t.Fatalf("list logs run %d: %v", i+1, err)
		}
		want := 0
		if i >= 3 {
			want = 1
		}
		if len(logs) != want {
			t.Fatalf("run %d: %d logs left, want %d", i+1, len(logs), want)
		}
	}

	// Keeping more than the run count deletes nothing.
	if n, err := s.PurgeLogsKeepLast(100); err != nil || n != 0 {
		t.Fatalf("keep 100 = (%d, %v), want (0, nil)", n, err)
	}
}

func testCanaryRelease(t *testing.T, s *Store, name string) int64 {
	t.Helper()
	id, err := s.CreateCanary(CanaryRelease{
		Name:        name,
		Namespace:   "ns",
		StableImage: "app:1",
		CanaryImage: "app:2",
	})
	if err != nil {
		t.Fatalf("create canary %s: %v", name, err)
	}
	return id
}

// TestPurgeCanaryEventsByAge (P7⑧): events strictly older than the cutoff
// are deleted; recent events survive.
func TestPurgeCanaryEventsByAge(t *testing.T) {
	s := openTemp(t)
	a := testCanaryRelease(t, s, "app-a")
	b := testCanaryRelease(t, s, "app-b")
	c := testCanaryRelease(t, s, "app-c")

	for i := 0; i < 2; i++ {
		if err := s.InsertCanaryEvent(a, "observing", "tick"); err != nil {
			t.Fatalf("event a%d: %v", i, err)
		}
	}
	if err := s.InsertCanaryEvent(b, "observing", "tick"); err != nil {
		t.Fatalf("event b: %v", err)
	}
	if err := s.InsertCanaryEvent(c, "observing", "tick"); err != nil {
		t.Fatalf("event c: %v", err)
	}
	// Age out a and b's events.
	if _, err := s.db.Exec(
		`UPDATE canary_events SET ts = '2020-01-01T00:00:00Z' WHERE release_id IN (?, ?)`, a, b,
	); err != nil {
		t.Fatalf("backdate events: %v", err)
	}

	n, err := s.PurgeCanaryEventsByAge("2026-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("purge by age: %v", err)
	}
	if n != 3 {
		t.Fatalf("purged %d events, want 3 (a×2 + b×1)", n)
	}
	if ev, _ := s.EventsOf(a); len(ev) != 0 {
		t.Fatalf("release a still has %d events", len(ev))
	}
	if ev, _ := s.EventsOf(c); len(ev) != 1 {
		t.Fatalf("release c lost its event (%d left)", len(ev))
	}
}

// TestPurgeCanaryEventsKeepLast (P7⑧): keep-last purges events of all but
// the keep most-recent releases (by release id, the insertion order).
func TestPurgeCanaryEventsKeepLast(t *testing.T) {
	s := openTemp(t)
	a := testCanaryRelease(t, s, "app-a")
	b := testCanaryRelease(t, s, "app-b")
	c := testCanaryRelease(t, s, "app-c")

	for i := 0; i < 2; i++ {
		if err := s.InsertCanaryEvent(a, "observing", "tick"); err != nil {
			t.Fatalf("event a%d: %v", i, err)
		}
	}
	if err := s.InsertCanaryEvent(b, "observing", "tick"); err != nil {
		t.Fatalf("event b: %v", err)
	}
	if err := s.InsertCanaryEvent(c, "observing", "tick"); err != nil {
		t.Fatalf("event c: %v", err)
	}

	n, err := s.PurgeCanaryEventsKeepLast(1)
	if err != nil {
		t.Fatalf("purge keep-last: %v", err)
	}
	if n != 3 {
		t.Fatalf("purged %d events, want 3 (a×2 + b×1)", n)
	}
	if ev, _ := s.EventsOf(c); len(ev) != 1 {
		t.Fatalf("release c lost its event (%d left)", len(ev))
	}

	// Keeping more than the release count deletes nothing.
	if n, err := s.PurgeCanaryEventsKeepLast(100); err != nil || n != 0 {
		t.Fatalf("keep 100 = (%d, %v), want (0, nil)", n, err)
	}
}

// TestPurgeAuditEventsByAge (Task 9): audit events strictly older than the
// cutoff are deleted; recent events survive.
func TestPurgeAuditEventsByAge(t *testing.T) {
	s := openTemp(t)
	for _, ts := range []string{"2020-01-01T00:00:00Z", "2020-06-01T00:00:00Z", "2026-06-01T00:00:00Z"} {
		if err := s.AddAuditEvent(AuditEvent{
			Actor: "a", Action: "act", Target: "t", Outcome: "ok", TS: ts,
		}); err != nil {
			t.Fatalf("add audit event: %v", err)
		}
	}

	n, err := s.PurgeAuditEventsByAge("2026-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("purge by age: %v", err)
	}
	if n != 2 {
		t.Fatalf("purged %d audit events, want 2", n)
	}
	got, err := s.ListAuditEvents(AuditFilter{})
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(got) != 1 || got[0].TS != "2026-06-01T00:00:00Z" {
		t.Fatalf("want 1 recent event left, got %v", got)
	}
}

// TestPurgeAuditEventsKeepLast (Task 9): keep-last purges all but the keep
// most-recent audit events (by event id, the insertion order).
func TestPurgeAuditEventsKeepLast(t *testing.T) {
	s := openTemp(t)
	for i := 0; i < 5; i++ {
		if err := s.AddAuditEvent(AuditEvent{Actor: "a", Action: "act", Target: "t", Outcome: "ok"}); err != nil {
			t.Fatalf("add audit event %d: %v", i, err)
		}
	}

	n, err := s.PurgeAuditEventsKeepLast(2)
	if err != nil {
		t.Fatalf("purge keep-last: %v", err)
	}
	if n != 3 {
		t.Fatalf("purged %d audit events, want 3", n)
	}
	got, err := s.ListAuditEvents(AuditFilter{})
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("%d audit events left, want 2", len(got))
	}

	// Keeping more than the event count deletes nothing.
	if n, err := s.PurgeAuditEventsKeepLast(100); err != nil || n != 0 {
		t.Fatalf("keep 100 = (%d, %v), want (0, nil)", n, err)
	}
}
