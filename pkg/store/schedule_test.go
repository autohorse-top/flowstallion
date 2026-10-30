package store

import (
	"testing"
	"time"
)

func TestScheduleStateRoundTrip(t *testing.T) {
	s := openTemp(t)
	key := "nightly|0 3 * * *"
	ts := time.Date(2026, 10, 26, 3, 0, 0, 0, time.UTC)

	if got, ok, err := s.GetLastScheduleFire(key); err != nil || ok {
		t.Fatalf("absent key: got (%v, %v, %v), want (zero, false, nil)", got, ok, err)
	}

	if err := s.SetLastScheduleFire(key, ts); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, ok, err := s.GetLastScheduleFire(key)
	if err != nil || !ok {
		t.Fatalf("get: got (%v, %v, %v), want ok", got, ok, err)
	}
	if !got.Equal(ts) {
		t.Fatalf("round trip: got %s, want %s", got.Format(time.RFC3339), ts.Format(time.RFC3339))
	}

	// Upsert overwrites with the newer watermark.
	ts2 := ts.Add(24 * time.Hour)
	if err := s.SetLastScheduleFire(key, ts2); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	got, _, _ = s.GetLastScheduleFire(key)
	if !got.Equal(ts2) {
		t.Fatalf("overwrite: got %s, want %s", got.Format(time.RFC3339), ts2.Format(time.RFC3339))
	}
}

func TestScheduleStateIndependentKeys(t *testing.T) {
	s := openTemp(t)
	a := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	b := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := s.SetLastScheduleFire("a|*", a); err != nil {
		t.Fatalf("set a: %v", err)
	}
	if err := s.SetLastScheduleFire("b|*", b); err != nil {
		t.Fatalf("set b: %v", err)
	}
	if ga, ok, err := s.GetLastScheduleFire("a|*"); err != nil || !ok || !ga.Equal(a) {
		t.Fatalf("a: got (%s, %v, %v), want %s", ga.Format(time.RFC3339), ok, err, a.Format(time.RFC3339))
	}
	if gb, ok, err := s.GetLastScheduleFire("b|*"); err != nil || !ok || !gb.Equal(b) {
		t.Fatalf("b: got (%s, %v, %v), want %s", gb.Format(time.RFC3339), ok, err, b.Format(time.RFC3339))
	}
}

func TestScheduleStatePersistsAcrossOpen(t *testing.T) {
	path := t.TempDir() + "/sched.db"
	s1, err := Open(path)
	if err != nil {
		t.Fatalf("open 1: %v", err)
	}
	ts := time.Date(2026, 5, 5, 5, 5, 5, 0, time.UTC)
	if err := s1.SetLastScheduleFire("p|0 0 * * *", ts); err != nil {
		t.Fatalf("set: %v", err)
	}
	s1.Close()

	s2, err := Open(path)
	if err != nil {
		t.Fatalf("open 2 (idempotent migration): %v", err)
	}
	defer s2.Close()
	got, ok, err := s2.GetLastScheduleFire("p|0 0 * * *")
	if err != nil || !ok || !got.Equal(ts) {
		t.Fatalf("after reopen: got (%s, %v, %v), want %s",
			got.Format(time.RFC3339), ok, err, ts.Format(time.RFC3339))
	}
}
