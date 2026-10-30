package store

import (
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestCanaryLifecycle(t *testing.T) {
	s := openTemp(t)
	id, err := s.CreateCanary(CanaryRelease{
		Name: "demoapp", Namespace: "ns",
		StableImage: "img:v1", CanaryImage: "img:v2",
		Replicas: 2, Port: 8080,
		Threshold: 0.3, MinSamples: 5, WarmupS: 4, ObserveS: 8,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	r, err := s.GetCanary(id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if r.State != CanaryPending {
		t.Fatalf("new state = %q, want pending", r.State)
	}
	if r.Reason != "" || r.CanaryStart != "" || r.FinishedAt != "" {
		t.Fatalf("new canary should have empty reason/start/finished, got %+v", r)
	}

	if err := s.SetCanaryStart(id, "2026-01-01T00:00:00Z"); err != nil {
		t.Fatalf("set start: %v", err)
	}
	if err := s.SetCanaryState(id, CanaryObserving, "", ""); err != nil {
		t.Fatalf("set state: %v", err)
	}
	if err := s.SetLastMetrics(id, 0.25, 40, 10); err != nil {
		t.Fatalf("set metrics: %v", err)
	}
	n, err := s.BumpScrapeFailures(id)
	if err != nil {
		t.Fatalf("bump: %v", err)
	}
	if n != 1 {
		t.Fatalf("bump = %d, want 1", n)
	}
	if err := s.ResetScrapeFailures(id); err != nil {
		t.Fatalf("reset: %v", err)
	}

	r, _ = s.GetCanary(id)
	if r.State != CanaryObserving || r.CanaryStart != "2026-01-01T00:00:00Z" ||
		r.LastErrRate != 0.25 || r.LastRequests != 40 || r.LastErrors != 10 ||
		r.ScrapeFailures != 0 {
		t.Fatalf("state not persisted correctly: %+v", r)
	}

	if err := s.SetCanaryState(id, CanaryRolledBack, "err rate too high", "2026-01-01T00:10:00Z"); err != nil {
		t.Fatalf("terminal state: %v", err)
	}
	r, _ = s.GetCanary(id)
	if r.State != CanaryRolledBack || r.Reason != "err rate too high" || r.FinishedAt != "2026-01-01T00:10:00Z" {
		t.Fatalf("terminal fields wrong: %+v", r)
	}

	acts, err := s.ActiveCanaries()
	if err != nil {
		t.Fatalf("active: %v", err)
	}
	if len(acts) != 0 {
		t.Fatalf("terminal release should not be active, got %d", len(acts))
	}
}

func TestCanaryActiveFilter(t *testing.T) {
	s := openTemp(t)
	a, _ := s.CreateCanary(CanaryRelease{Name: "a", Namespace: "ns", StableImage: "s", CanaryImage: "c",
		Threshold: 0.3, MinSamples: 1, WarmupS: 1, ObserveS: 1})
	b, _ := s.CreateCanary(CanaryRelease{Name: "b", Namespace: "ns", StableImage: "s", CanaryImage: "c",
		Threshold: 0.3, MinSamples: 1, WarmupS: 1, ObserveS: 1})
	if err := s.SetCanaryState(b, CanaryPromoted, "ok", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatalf("promote b: %v", err)
	}
	acts, err := s.ActiveCanaries()
	if err != nil {
		t.Fatalf("active: %v", err)
	}
	if len(acts) != 1 || acts[0].ID != a {
		t.Fatalf("active should contain only a, got %+v", acts)
	}

	has, err := s.HasActiveCanary("a", "ns")
	if err != nil || !has {
		t.Fatalf("HasActiveCanary(a) = %v, %v; want true", has, err)
	}
	has, _ = s.HasActiveCanary("b", "ns")
	if has {
		t.Fatalf("HasActiveCanary(b) should be false (terminal)")
	}
	has, _ = s.HasActiveCanary("zzz", "ns")
	if has {
		t.Fatalf("HasActiveCanary(zzz) should be false")
	}
}

func TestCanaryEvents(t *testing.T) {
	s := openTemp(t)
	id, _ := s.CreateCanary(CanaryRelease{Name: "e", Namespace: "ns",
		StableImage: "s", CanaryImage: "c",
		Threshold: 0.3, MinSamples: 1, WarmupS: 1, ObserveS: 1})
	for _, st := range []string{CanaryApplying, CanaryReady, CanaryObserving} {
		if err := s.InsertCanaryEvent(id, st, `{"phase":"x"}`); err != nil {
			t.Fatalf("insert event %s: %v", st, err)
		}
	}
	evs, err := s.EventsOf(id)
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	if len(evs) != 3 {
		t.Fatalf("expected 3 events, got %d", len(evs))
	}
	if evs[0].State != CanaryApplying || evs[2].State != CanaryObserving {
		t.Fatalf("events out of order: %+v", evs)
	}
	for i, e := range evs {
		if e.ReleaseID != id {
			t.Fatalf("event %d release_id = %d, want %d", i, e.ReleaseID, id)
		}
	}
}

func TestCanaryListOrder(t *testing.T) {
	s := openTemp(t)
	first, _ := s.CreateCanary(CanaryRelease{Name: "first", Namespace: "ns",
		StableImage: "s", CanaryImage: "c",
		Threshold: 0.3, MinSamples: 1, WarmupS: 1, ObserveS: 1})
	second, _ := s.CreateCanary(CanaryRelease{Name: "second", Namespace: "ns",
		StableImage: "s", CanaryImage: "c",
		Threshold: 0.3, MinSamples: 1, WarmupS: 1, ObserveS: 1})
	all, err := s.ListCanaries()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 2 || all[0].ID != second || all[1].ID != first {
		t.Fatalf("list order wrong: %+v", all)
	}
}

// TestCanaryConcurrentCreate is the M-2 regression: concurrent creates of
// the same (name, namespace) must yield exactly one active release — the
// partial unique index rejects the rest atomically (no check-then-insert
// window).
func TestCanaryConcurrentCreate(t *testing.T) {
	s := openTemp(t)
	spec := CanaryRelease{Name: "racer", Namespace: "ns",
		StableImage: "s", CanaryImage: "c",
		Threshold: 0.3, MinSamples: 1, WarmupS: 1, ObserveS: 1}
	const n = 50
	var wg sync.WaitGroup
	var mu sync.Mutex
	var ok, conflict int
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.CreateCanary(spec)
			mu.Lock()
			switch {
			case err == nil:
				ok++
			case errors.Is(err, ErrCanaryConflict):
				conflict++
			default:
				t.Errorf("unexpected error: %v", err)
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	if ok != 1 {
		t.Fatalf("%d creates succeeded, want exactly 1 (conflicts=%d)", ok, conflict)
	}
	acts, err := s.ActiveCanaries()
	if err != nil {
		t.Fatalf("active: %v", err)
	}
	if len(acts) != 1 {
		t.Fatalf("active releases = %d, want 1", len(acts))
	}
}

func TestPromotedCanaryPairs(t *testing.T) {
	s := openTemp(t)
	rel := func(name string) CanaryRelease {
		return CanaryRelease{Name: name, Namespace: "ns",
			StableImage: "s", CanaryImage: "c",
			Threshold: 0.3, MinSamples: 1, WarmupS: 1, ObserveS: 1}
	}
	bg := func(name string) CanaryRelease {
		r := rel(name)
		r.Strategy = "blue_green"
		return r
	}
	p, _ := s.CreateCanary(rel("promo"))
	a, _ := s.CreateCanary(rel("active"))
	r, _ := s.CreateCanary(rel("rolled"))
	bgrel, _ := s.CreateCanary(bg("bgpromo"))
	_ = s.SetCanaryState(p, CanaryPromoted, "ok", "2026-01-01T00:00:00Z")
	_ = s.SetCanaryState(r, CanaryRolledBack, "bad", "2026-01-01T00:00:00Z")
	_ = s.SetCanaryState(bgrel, CanaryPromoted, "ok", "2026-01-01T00:00:00Z")
	_ = a

	pairs, err := s.PromotedCanaryPairs("ns")
	if err != nil {
		t.Fatalf("PromotedCanaryPairs: %v", err)
	}
	got := map[string]string{}
	for _, p := range pairs {
		got[p.Name] = p.Strategy
	}
	if len(pairs) != 2 || got["promo"] != "canary" || got["bgpromo"] != "blue_green" {
		t.Fatalf("got %v, want promo=canary bgpromo=blue_green", pairs)
	}

	pairs, _ = s.PromotedCanaryPairs("other")
	if len(pairs) != 0 {
		t.Fatalf("other namespace should have none, got %v", pairs)
	}

	acts, err := s.ActiveCanaryPairs("ns")
	if err != nil {
		t.Fatalf("ActiveCanaryPairs: %v", err)
	}
	if len(acts) != 1 || acts[0].Name != "active" || acts[0].Strategy != "canary" {
		t.Fatalf("active pairs = %v, want [active/canary]", acts)
	}
}

func TestCanaryApplyingSince(t *testing.T) {
	s := openTemp(t)
	id, _ := s.CreateCanary(CanaryRelease{Name: "t", Namespace: "ns",
		StableImage: "s", CanaryImage: "c",
		Threshold: 0.3, MinSamples: 1, WarmupS: 1, ObserveS: 1})
	r, _ := s.GetCanary(id)
	if r.ApplyingSince != "" {
		t.Fatalf("new canary ApplyingSince = %q, want empty", r.ApplyingSince)
	}
	if err := s.SetApplyingSince(id, "2026-01-01T00:00:00Z"); err != nil {
		t.Fatalf("set applying_since: %v", err)
	}
	r, _ = s.GetCanary(id)
	if r.ApplyingSince != "2026-01-01T00:00:00Z" {
		t.Fatalf("ApplyingSince = %q", r.ApplyingSince)
	}
}

func TestCanaryEventsLimit(t *testing.T) {
	s := openTemp(t)
	id, _ := s.CreateCanary(CanaryRelease{Name: "e", Namespace: "ns",
		StableImage: "s", CanaryImage: "c",
		Threshold: 0.3, MinSamples: 1, WarmupS: 1, ObserveS: 1})
	for i := 0; i < 7; i++ {
		if err := s.InsertCanaryEvent(id, CanaryObserving, fmt.Sprintf(`{"i":%d}`, i)); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	evs, err := s.EventsOfLimit(id, 3)
	if err != nil {
		t.Fatalf("EventsOfLimit: %v", err)
	}
	if len(evs) != 3 {
		t.Fatalf("got %d events, want 3", len(evs))
	}
	if !strings.Contains(evs[0].Detail, `"i":4`) || !strings.Contains(evs[2].Detail, `"i":6`) {
		t.Fatalf("expected last 3 in chronological order: %+v", evs)
	}
}

// TestSetCanaryStateIf (K1) is the compare-and-swap guard: a transition
// applies only when the row is still in `expected` state; a mismatch (or a
// missing row) leaves the row untouched and returns the conflict sentinel.
func TestSetCanaryStateIf(t *testing.T) {
	s := openTemp(t)
	id, err := s.CreateCanary(CanaryRelease{Name: "cas", Namespace: "ns",
		StableImage: "s", CanaryImage: "c",
		Threshold: 0.3, MinSamples: 1, WarmupS: 1, ObserveS: 1})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Fresh release is pending; matching expected transitions it.
	if err := s.SetCanaryStateIf(id, CanaryApplying, "", "", CanaryPending); err != nil {
		t.Fatalf("matching CAS: %v", err)
	}
	got, _ := s.GetCanary(id)
	if got.State != CanaryApplying || got.Reason != "" {
		t.Fatalf("after matching CAS = %+v", got)
	}
	// Stale expected: row is applying, expected observing -> conflict, row unchanged.
	if err := s.SetCanaryStateIf(id, CanaryObserving, "", "", CanaryReady); !errors.Is(err, ErrCanaryStateConflict) {
		t.Fatalf("stale CAS err = %v, want ErrCanaryStateConflict", err)
	}
	got, _ = s.GetCanary(id)
	if got.State != CanaryApplying {
		t.Fatalf("row must be untouched after conflict, got %q", got.State)
	}
	// Terminal transition with finished_at stamps both fields.
	if err := s.SetCanaryStateIf(id, CanaryRolledBack, "done", "2026-01-02T00:00:00Z", CanaryApplying); err != nil {
		t.Fatalf("terminal CAS: %v", err)
	}
	got, _ = s.GetCanary(id)
	if got.State != CanaryRolledBack || got.FinishedAt != "2026-01-02T00:00:00Z" {
		t.Fatalf("terminal CAS fields = %+v", got)
	}
	// CAS on a missing row conflicts (never fabricates a row).
	if err := s.SetCanaryStateIf(99999, CanaryPromoted, "", "", CanaryObserving); !errors.Is(err, ErrCanaryStateConflict) {
		t.Fatalf("missing-row CAS err = %v, want ErrCanaryStateConflict", err)
	}
}

// TestSetCanaryStateIfConcurrent hammers one observing row from 64 goroutines
// with the same expected state: exactly one winner, 63 conflicts.
func TestSetCanaryStateIfConcurrent(t *testing.T) {
	s := openTemp(t)
	id, err := s.CreateCanary(CanaryRelease{Name: "race", Namespace: "ns",
		StableImage: "s", CanaryImage: "c",
		Threshold: 0.3, MinSamples: 1, WarmupS: 1, ObserveS: 1})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.SetCanaryState(id, CanaryObserving, "", ""); err != nil {
		t.Fatalf("seed observing: %v", err)
	}
	const n = 64
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		ok, conf int
	)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.SetCanaryStateIf(id, CanaryPromoting, "", "", CanaryObserving)
			mu.Lock()
			switch {
			case err == nil:
				ok++
			case errors.Is(err, ErrCanaryStateConflict):
				conf++
			default:
				t.Errorf("unexpected error: %v", err)
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	if ok != 1 || conf != n-1 {
		t.Fatalf("winners = %d, conflicts = %d; want 1 / %d", ok, conf, n-1)
	}
	got, _ := s.GetCanary(id)
	if got.State != CanaryPromoting {
		t.Fatalf("final state = %q, want promoting", got.State)
	}
}

// TestCanarySourceRefRoundtrip is the P4 feature: the optional source_ref
// (git commit sha or branch name) must survive Create/Get/List round-trips,
// and must stay empty when omitted.
func TestCanarySourceRefRoundtrip(t *testing.T) {
	s := openTemp(t)
	id, err := s.CreateCanary(CanaryRelease{
		Name: "refapp", Namespace: "ns",
		StableImage: "img:v1", CanaryImage: "img:v2",
		SourceRef: "abc123def",
		Replicas:  2, Port: 8080,
		Threshold: 0.3, MinSamples: 5, WarmupS: 4, ObserveS: 8,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	r, err := s.GetCanary(id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if r.SourceRef != "abc123def" {
		t.Fatalf("SourceRef = %q, want abc123def", r.SourceRef)
	}

	id2, err := s.CreateCanary(CanaryRelease{
		Name: "noref", Namespace: "ns",
		StableImage: "img:v1", CanaryImage: "img:v2",
	})
	if err != nil {
		t.Fatalf("create without ref: %v", err)
	}
	r2, _ := s.GetCanary(id2)
	if r2.SourceRef != "" {
		t.Fatalf("omitted SourceRef = %q, want empty", r2.SourceRef)
	}

	all, err := s.ListCanaries()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 2 ||
		all[0].ID != id2 || all[0].SourceRef != "" ||
		all[1].ID != id || all[1].SourceRef != "abc123def" {
		t.Fatalf("list wrong: %+v", all)
	}
}

// legacyCanarySchema is the canary_releases table as it existed before P4
// (no source_ref column), used to exercise the ALTER TABLE migration path.
const legacyCanarySchema = `CREATE TABLE canary_releases (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL,
	namespace TEXT NOT NULL,
	stable_image TEXT NOT NULL,
	canary_image TEXT NOT NULL,
	replicas INTEGER NOT NULL DEFAULT 2,
	port INTEGER NOT NULL DEFAULT 8080,
	threshold REAL NOT NULL DEFAULT 0.3,
	min_samples INTEGER NOT NULL DEFAULT 20,
	warmup_s REAL NOT NULL DEFAULT 10,
	observe_s REAL NOT NULL DEFAULT 20,
	state TEXT NOT NULL DEFAULT 'pending',
	reason TEXT NOT NULL DEFAULT '',
	canary_start TEXT,
	applying_since TEXT NOT NULL DEFAULT '',
	scrape_failures INTEGER NOT NULL DEFAULT 0,
	last_err_rate REAL NOT NULL DEFAULT 0,
	last_requests INTEGER NOT NULL DEFAULT 0,
	last_errors INTEGER NOT NULL DEFAULT 0,
	baseline_requests INTEGER NOT NULL DEFAULT 0,
	baseline_errors INTEGER NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	finished_at TEXT
)`

// TestCanaryLegacySourceRefMigration is the P4 migration regression: a
// pre-P4 database whose canary_releases table lacks source_ref must be
// upgraded in place (ALTER TABLE backfill, default ”), stay readable, and
// support new writes; re-opening the upgraded DB must not error (the ALTER
// is a no-op "duplicate column" in that case).
func TestCanaryLegacySourceRefMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open raw sqlite: %v", err)
	}
	if _, err := raw.Exec(legacyCanarySchema); err != nil {
		raw.Close()
		t.Fatalf("create legacy table: %v", err)
	}
	if _, err := raw.Exec(
		`INSERT INTO canary_releases (name, namespace, stable_image, canary_image, created_at, updated_at)
		 VALUES ('oldapp', 'ns', 'img:v1', 'img:v2', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`); err != nil {
		raw.Close()
		t.Fatalf("insert legacy row: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close legacy db: %v", err)
	}

	s, err := Open(path) // migrate(): ALTER TABLE ... ADD COLUMN source_ref
	if err != nil {
		t.Fatalf("open upgraded db: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	// Legacy row is readable and source_ref defaults to ''.
	legacy, err := s.GetCanary(1)
	if err != nil {
		t.Fatalf("get legacy row: %v", err)
	}
	if legacy.Name != "oldapp" || legacy.State != "pending" {
		t.Fatalf("legacy row not preserved: %+v", legacy)
	}
	if legacy.SourceRef != "" {
		t.Fatalf("legacy row SourceRef = %q, want empty default", legacy.SourceRef)
	}

	// New writes on the upgraded DB store source_ref.
	id, err := s.CreateCanary(CanaryRelease{
		Name: "newapp", Namespace: "ns",
		StableImage: "s", CanaryImage: "c", SourceRef: "main",
		Threshold: 0.3, MinSamples: 1, WarmupS: 1, ObserveS: 1,
	})
	if err != nil {
		t.Fatalf("create on upgraded db: %v", err)
	}
	r2, _ := s.GetCanary(id)
	if r2.SourceRef != "main" {
		t.Fatalf("new row SourceRef = %q, want main", r2.SourceRef)
	}

	// Idempotency: re-opening re-runs migrate() on the upgraded DB; the
	// ALTER must hit "duplicate column" and be ignored, not fail.
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("re-open upgraded db (idempotent migrate): %v", err)
	}
	defer s2.Close()
}

// preP7CanarySchema is the canary_releases table as it existed before P7⑤
// (has source_ref, lacks run_id), used to exercise the run_id ALTER path.
const preP7CanarySchema = `CREATE TABLE canary_releases (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL,
	namespace TEXT NOT NULL,
	stable_image TEXT NOT NULL,
	canary_image TEXT NOT NULL,
	source_ref TEXT NOT NULL DEFAULT '',
	replicas INTEGER NOT NULL DEFAULT 2,
	port INTEGER NOT NULL DEFAULT 8080,
	threshold REAL NOT NULL DEFAULT 0.3,
	min_samples INTEGER NOT NULL DEFAULT 20,
	warmup_s REAL NOT NULL DEFAULT 10,
	observe_s REAL NOT NULL DEFAULT 20,
	state TEXT NOT NULL DEFAULT 'pending',
	reason TEXT NOT NULL DEFAULT '',
	canary_start TEXT,
	applying_since TEXT NOT NULL DEFAULT '',
	scrape_failures INTEGER NOT NULL DEFAULT 0,
	last_err_rate REAL NOT NULL DEFAULT 0,
	last_requests INTEGER NOT NULL DEFAULT 0,
	last_errors INTEGER NOT NULL DEFAULT 0,
	baseline_requests INTEGER NOT NULL DEFAULT 0,
	baseline_errors INTEGER NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	finished_at TEXT
)`

// TestCanaryRunIDMigration is the P7⑤ migration regression: a pre-P7⑤
// database lacking run_id must be upgraded in place (ALTER TABLE backfill,
// default 0), keep legacy rows readable, store new run-bound writes, and
// keep ActiveCanaries returning only run_id=0 releases.
func TestCanaryRunIDMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pre7.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open raw sqlite: %v", err)
	}
	if _, err := raw.Exec(preP7CanarySchema); err != nil {
		raw.Close()
		t.Fatalf("create legacy table: %v", err)
	}
	if _, err := raw.Exec(
		`INSERT INTO canary_releases (name, namespace, stable_image, canary_image, created_at, updated_at)
		 VALUES ('oldapp', 'ns', 'img:v1', 'img:v2', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`); err != nil {
		raw.Close()
		t.Fatalf("insert legacy row: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close legacy db: %v", err)
	}

	s, err := Open(path) // migrate(): ALTER TABLE ... ADD COLUMN run_id
	if err != nil {
		t.Fatalf("open upgraded db: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	legacy, err := s.GetCanary(1)
	if err != nil {
		t.Fatalf("get legacy row: %v", err)
	}
	if legacy.Name != "oldapp" || legacy.State != "pending" || legacy.RunID != 0 {
		t.Fatalf("legacy row wrong: %+v", legacy)
	}

	// New write stores a non-zero run_id.
	id, err := s.CreateCanary(CanaryRelease{
		Name: "runapp", Namespace: "ns2",
		StableImage: "s", CanaryImage: "c",
		RunID: 42, Threshold: 0.3, MinSamples: 1, WarmupS: 1, ObserveS: 1,
	})
	if err != nil {
		t.Fatalf("create run-bound canary: %v", err)
	}
	r, _ := s.GetCanary(id)
	if r.RunID != 42 {
		t.Fatalf("RunID = %d, want 42", r.RunID)
	}

	// ActiveCanaries must exclude the run-bound release and keep the
	// legacy (run_id=0) one — the background TickAll only drives API
	// canaries; the executor drives its own release inline.
	acts, err := s.ActiveCanaries()
	if err != nil {
		t.Fatalf("active: %v", err)
	}
	if len(acts) != 1 || acts[0].ID != 1 {
		t.Fatalf("ActiveCanaries = %+v, want only legacy id=1", acts)
	}
}

// TestCanaryStrategyRoundtrip: strategy defaults to "canary" when omitted
// and round-trips "blue_green" through Create/Get/List.
func TestCanaryStrategyRoundtrip(t *testing.T) {
	s := openTemp(t)
	base := func(name, strat string) CanaryRelease {
		return CanaryRelease{Name: name, Namespace: "ns",
			StableImage: "s", CanaryImage: "c",
			Strategy:  strat,
			Threshold: 0.3, MinSamples: 1, WarmupS: 1, ObserveS: 1}
	}
	a, err := s.CreateCanary(base("plain", ""))
	if err != nil {
		t.Fatalf("create default: %v", err)
	}
	b, err := s.CreateCanary(base("bg", "blue_green"))
	if err != nil {
		t.Fatalf("create blue_green: %v", err)
	}
	ra, _ := s.GetCanary(a)
	rb, _ := s.GetCanary(b)
	if ra.Strategy != "canary" {
		t.Fatalf("omitted strategy = %q, want canary", ra.Strategy)
	}
	if rb.Strategy != "blue_green" {
		t.Fatalf("explicit strategy = %q, want blue_green", rb.Strategy)
	}
	all, err := s.ListCanaries()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 2 || all[0].Strategy != "blue_green" || all[1].Strategy != "canary" {
		t.Fatalf("list strategies wrong: %+v", all)
	}
}

// preBlueGreenCanarySchema is the canary_releases table as it existed before
// the strategy column was added (has run_id, lacks strategy).
const preBlueGreenCanarySchema = `CREATE TABLE canary_releases (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL,
	namespace TEXT NOT NULL,
	stable_image TEXT NOT NULL,
	canary_image TEXT NOT NULL,
	source_ref TEXT NOT NULL DEFAULT '',
	run_id INTEGER NOT NULL DEFAULT 0,
	replicas INTEGER NOT NULL DEFAULT 2,
	port INTEGER NOT NULL DEFAULT 8080,
	threshold REAL NOT NULL DEFAULT 0.3,
	min_samples INTEGER NOT NULL DEFAULT 20,
	warmup_s REAL NOT NULL DEFAULT 10,
	observe_s REAL NOT NULL DEFAULT 20,
	state TEXT NOT NULL DEFAULT 'pending',
	reason TEXT NOT NULL DEFAULT '',
	canary_start TEXT,
	applying_since TEXT NOT NULL DEFAULT '',
	scrape_failures INTEGER NOT NULL DEFAULT 0,
	last_err_rate REAL NOT NULL DEFAULT 0,
	last_requests INTEGER NOT NULL DEFAULT 0,
	last_errors INTEGER NOT NULL DEFAULT 0,
	baseline_requests INTEGER NOT NULL DEFAULT 0,
	baseline_errors INTEGER NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	finished_at TEXT
)`

// TestCanaryStrategyMigration is the strategy-column migration regression:
// a database lacking canary_releases.strategy must be upgraded in place
// (ALTER TABLE backfill, default 'canary'), keep legacy rows readable as
// strategy=canary, and support new writes; re-opening must be idempotent.
func TestCanaryStrategyMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "prebg.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open raw sqlite: %v", err)
	}
	if _, err := raw.Exec(preBlueGreenCanarySchema); err != nil {
		raw.Close()
		t.Fatalf("create legacy table: %v", err)
	}
	if _, err := raw.Exec(
		`INSERT INTO canary_releases (name, namespace, stable_image, canary_image, created_at, updated_at)
		 VALUES ('oldapp', 'ns', 'img:v1', 'img:v2', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`); err != nil {
		raw.Close()
		t.Fatalf("insert legacy row: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close legacy db: %v", err)
	}

	s, err := Open(path) // migrate(): ALTER TABLE ... ADD COLUMN strategy
	if err != nil {
		t.Fatalf("open upgraded db: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	legacy, err := s.GetCanary(1)
	if err != nil {
		t.Fatalf("get legacy row: %v", err)
	}
	if legacy.Name != "oldapp" || legacy.Strategy != "canary" {
		t.Fatalf("legacy row not backfilled: %+v", legacy)
	}

	// New writes on the upgraded DB store an explicit strategy.
	id, err := s.CreateCanary(CanaryRelease{
		Name: "bgapp", Namespace: "ns2",
		StableImage: "s", CanaryImage: "c", Strategy: "blue_green",
		Threshold: 0.3, MinSamples: 1, WarmupS: 1, ObserveS: 1,
	})
	if err != nil {
		t.Fatalf("create on upgraded db: %v", err)
	}
	r, _ := s.GetCanary(id)
	if r.Strategy != "blue_green" {
		t.Fatalf("new row strategy = %q, want blue_green", r.Strategy)
	}

	// Idempotency: re-opening re-runs migrate(); the ALTER must hit
	// "duplicate column" and be ignored, not fail.
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if s2, err := Open(path); err != nil {
		t.Fatalf("re-open upgraded db (idempotent migrate): %v", err)
	} else {
		s2.Close()
	}
}
