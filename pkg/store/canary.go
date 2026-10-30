// Canary persistence for the K8s canary release state machine (P3).
package store

import (
	"errors"
	"fmt"
	"strings"
)

// Canary release lifecycle states.
const (
	CanaryPending   = "pending"
	CanaryApplying  = "applying"
	CanaryReady     = "canary_ready"
	CanaryObserving = "observing"
	// CanaryPromoting: the stable Service selector has been switched to the
	// canary pods but the scale-up / stable-deployment deletion is not yet
	// complete. Non-terminal and re-entrant: a crash mid-promote is replayed
	// from here instead of being stranded in a half-promoted cluster (m-5).
	CanaryPromoting  = "promoting"
	CanaryPromoted   = "promoted"
	CanaryRolledBack = "rolled_back"
	CanaryFailed     = "failed"
)

// ErrCanaryConflict is returned by CreateCanary when the (name, namespace)
// active-release unique constraint fires (concurrent duplicate create, M-2).
var ErrCanaryConflict = errors.New("canary: an active release with this name and namespace already exists")

// ErrCanaryStateConflict is returned by SetCanaryStateIf when the row's
// current state does not match the expected value (a concurrent driver
// already moved the release), or the row does not exist. Callers must
// re-read the release and re-decide rather than retrying the same write
// (K1: rollback/promote race).
var ErrCanaryStateConflict = errors.New("canary: state conflict (concurrent transition or missing release)")

// canaryActiveWhere is the single source of truth for "non-terminal"
// states; every active-release query and the partial unique index must
// agree on it (n-7: no duplicated literal lists to drift apart).
const canaryActiveWhere = `state NOT IN ('promoted', 'rolled_back', 'failed')`

// CanaryTerminal reports whether a canary state is final.
func CanaryTerminal(state string) bool {
	switch state {
	case CanaryPromoted, CanaryRolledBack, CanaryFailed:
		return true
	}
	return false
}

// CanaryRelease is one K8s release under observation. The release is driven
// by a strategy: "canary" (isolated 1-replica canary, the original behavior)
// or "blue_green" (full-replica alternate environment, selector switch).
type CanaryRelease struct {
	ID        int64
	Name      string
	Namespace string
	// Strategy selects the release strategy ("canary" | "blue_green").
	// Stored as-is; empty at creation normalizes to "canary" (legacy default).
	Strategy    string
	StableImage string
	CanaryImage string
	// SourceRef is the optional git ref (full/short commit sha or branch name)
	// the canary image was built from. It anchors the Release→Commit edge in
	// the knowledge graph. Empty when not provided.
	SourceRef string
	// RunID links this release to the pipeline run that created it (P7⑤).
	// 0 = created via the API, driven by the background TickAll loop;
	// >0 = created by the scheduler's k8s_canary executor (driven inline).
	RunID       int64
	Replicas    int
	Port        int
	Threshold   float64
	MinSamples  int
	WarmupS     float64
	ObserveS    float64
	State       string
	Reason      string
	CanaryStart string
	// ApplyingSince stamps when the release entered the applying phase;
	// the applying timeout (B-1) is measured from here.
	ApplyingSince  string
	ScrapeFailures int
	LastErrRate    float64
	LastRequests   int64
	LastErrors     int64
	// BaselineRequests / BaselineErrors are the app's cumulative counters at
	// the first successful scrape after the canary became ready. The error
	// rate is computed on the delta since this baseline so traffic
	// accumulated before canary_ready cannot dilute the observation window
	// (m-3). Zero means "not set yet".
	BaselineRequests int64
	BaselineErrors   int64
	CreatedAt        string
	UpdatedAt        string
	FinishedAt       string
}

// CanaryEvent is one state-machine event for a canary release.
type CanaryEvent struct {
	ID        int64
	ReleaseID int64
	TS        string
	State     string
	Detail    string
}

const canaryCols = `id, name, namespace, strategy, stable_image, canary_image, IFNULL(source_ref, ''), run_id,
	replicas, port, threshold, min_samples, warmup_s, observe_s,
	state, IFNULL(reason, ''), IFNULL(canary_start, ''), IFNULL(applying_since, ''), scrape_failures,
	last_err_rate, last_requests, last_errors,
	baseline_requests, baseline_errors,
	created_at, updated_at, IFNULL(finished_at, '')`

func scanCanary(scanner interface{ Scan(...interface{}) error }) (CanaryRelease, error) {
	var r CanaryRelease
	err := scanner.Scan(
		&r.ID, &r.Name, &r.Namespace, &r.Strategy, &r.StableImage, &r.CanaryImage, &r.SourceRef, &r.RunID,
		&r.Replicas, &r.Port, &r.Threshold, &r.MinSamples, &r.WarmupS, &r.ObserveS,
		&r.State, &r.Reason, &r.CanaryStart, &r.ApplyingSince, &r.ScrapeFailures,
		&r.LastErrRate, &r.LastRequests, &r.LastErrors,
		&r.BaselineRequests, &r.BaselineErrors,
		&r.CreatedAt, &r.UpdatedAt, &r.FinishedAt,
	)
	return r, err
}

// CreateCanary inserts a new release (state pending) and returns its id.
// An empty Strategy normalizes to "canary" (legacy default).
func (s *Store) CreateCanary(r CanaryRelease) (int64, error) {
	if r.State == "" {
		r.State = CanaryPending
	}
	if r.Strategy == "" {
		r.Strategy = "canary"
	}
	ts := now()
	res, err := s.db.Exec(
		`INSERT INTO canary_releases (name, namespace, strategy, stable_image, canary_image, source_ref, run_id,
		   replicas, port, threshold, min_samples, warmup_s, observe_s,
		   state, reason, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', ?, ?)`,
		r.Name, r.Namespace, r.Strategy, r.StableImage, r.CanaryImage, r.SourceRef, r.RunID,
		r.Replicas, r.Port, r.Threshold, r.MinSamples, r.WarmupS, r.ObserveS,
		r.State, ts, ts,
	)
	if err != nil {
		// M-2: the partial unique index makes duplicate active creates fail
		// atomically; surface a stable sentinel so callers can map it to 409.
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return 0, ErrCanaryConflict
		}
		return 0, fmt.Errorf("store: create canary %q: %w", r.Name, err)
	}
	return res.LastInsertId()
}

// GetCanary returns the release with the given id.
func (s *Store) GetCanary(id int64) (CanaryRelease, error) {
	row := s.db.QueryRow(
		`SELECT `+canaryCols+` FROM canary_releases WHERE id = ?`, id,
	)
	r, err := scanCanary(row)
	if err != nil {
		return r, err
	}
	return r, nil
}

// ListCanaries returns all releases, most recent first.
func (s *Store) ListCanaries() ([]CanaryRelease, error) {
	rows, err := s.db.Query(
		`SELECT ` + canaryCols + ` FROM canary_releases ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CanaryRelease
	for rows.Next() {
		r, err := scanCanary(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ActiveCanaries returns releases still in flight (non-terminal states).
// Run-bound releases (run_id > 0, P7⑤) are excluded: they are driven
// synchronously by the scheduler's k8s_canary executor, not by the
// background TickAll loop, so the two drivers never touch the same row.
func (s *Store) ActiveCanaries() ([]CanaryRelease, error) {
	rows, err := s.db.Query(
		`SELECT ` + canaryCols + ` FROM canary_releases
		 WHERE ` + canaryActiveWhere + ` AND run_id = 0 ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CanaryRelease
	for rows.Next() {
		r, err := scanCanary(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// HasActiveCanary reports whether a non-terminal release with the name exists
// in the given namespace.
func (s *Store) HasActiveCanary(name, namespace string) (bool, error) {
	var n int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM canary_releases
		 WHERE name = ? AND namespace = ? AND `+canaryActiveWhere, name, namespace,
	).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("store: has active canary %q: %w", name, err)
	}
	return n > 0, nil
}

// CanaryPair is a (name, strategy) pair for K8s object-name collision
// checks: each release occupies the stable-named object "P" plus the
// strategy-specific alternate object (P-canary or P-alt).
type CanaryPair struct {
	Name     string
	Strategy string
}

// ActiveCanaryPairs lists (name, strategy) of all non-terminal releases in
// the namespace, used for the K8s object-name collision check (m-1,
// generalized to strategies).
func (s *Store) ActiveCanaryPairs(namespace string) ([]CanaryPair, error) {
	rows, err := s.db.Query(
		`SELECT name, strategy FROM canary_releases WHERE namespace = ? AND `+canaryActiveWhere,
		namespace,
	)
	if err != nil {
		return nil, fmt.Errorf("store: active canary pairs in %q: %w", namespace, err)
	}
	defer rows.Close()
	var out []CanaryPair
	for rows.Next() {
		var p CanaryPair
		if err := rows.Scan(&p.Name, &p.Strategy); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// SetCanaryState transitions a release. finishedAt (non-empty) stamps
// finished_at for terminal states.
//
// Unconditional: last writer wins. Use this only for writes outside the
// state machine (tests, repair tooling); state-machine transitions from
// pkg/cd must use SetCanaryStateIf (K1).
func (s *Store) SetCanaryState(id int64, state, reason, finishedAt string) error {
	ts := now()
	var (
		query string
		args  []interface{}
	)
	if finishedAt != "" {
		query = `UPDATE canary_releases SET state=?, reason=?, updated_at=?, finished_at=? WHERE id=?`
		args = []interface{}{state, reason, ts, finishedAt, id}
	} else {
		query = `UPDATE canary_releases SET state=?, reason=?, updated_at=? WHERE id=?`
		args = []interface{}{state, reason, ts, id}
	}
	if _, err := s.db.Exec(query, args...); err != nil {
		return fmt.Errorf("store: set canary %d state %q: %w", id, state, err)
	}
	return nil
}

// SetCanaryStateIf is the compare-and-swap variant used by state-machine
// transitions (K1): the UPDATE only applies when the row is still in
// `expected` state. If a concurrent driver already moved the row (or the row
// is gone), RowsAffected is 0 and ErrCanaryStateConflict is returned without
// touching the row. Callers must re-read the release and re-decide, not
// retry the same write. finishedAt is handled identically to
// SetCanaryState.
func (s *Store) SetCanaryStateIf(id int64, state, reason, finishedAt, expected string) error {
	ts := now()
	var (
		query string
		args  []interface{}
	)
	if finishedAt != "" {
		query = `UPDATE canary_releases SET state=?, reason=?, updated_at=?, finished_at=? WHERE id=? AND state=?`
		args = []interface{}{state, reason, ts, finishedAt, id, expected}
	} else {
		query = `UPDATE canary_releases SET state=?, reason=?, updated_at=? WHERE id=? AND state=?`
		args = []interface{}{state, reason, ts, id, expected}
	}
	res, err := s.db.Exec(query, args...)
	if err != nil {
		return fmt.Errorf("store: set canary %d state %q (expected %q): %w", id, state, expected, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("store: canary %d state conflict: expected %q: %w", id, expected, ErrCanaryStateConflict)
	}
	return nil
}

// SetCanaryStart stamps the moment the canary became ready and resets the
// metrics baseline (the observation window starts here).
func (s *Store) SetCanaryStart(id int64, ts string) error {
	if _, err := s.db.Exec(
		`UPDATE canary_releases
		 SET canary_start = ?, baseline_requests = 0, baseline_errors = 0, updated_at = ?
		 WHERE id = ?`,
		ts, ts, id,
	); err != nil {
		return fmt.Errorf("store: set canary %d start: %w", id, err)
	}
	return nil
}

// SetApplyingSince stamps the moment the release entered the applying phase
// (B-1: the applying timeout is measured from here).
func (s *Store) SetApplyingSince(id int64, ts string) error {
	if _, err := s.db.Exec(
		`UPDATE canary_releases SET applying_since = ?, updated_at = ? WHERE id = ?`,
		ts, now(), id,
	); err != nil {
		return fmt.Errorf("store: set canary %d applying_since: %w", id, err)
	}
	return nil
}

// PromotedCanaryPairs lists (name, strategy) of promoted releases in the
// namespace.
// A promoted release leaves its alternate deployment ("P-canary" / "P-alt")
// and the stable-named Service "P" behind as live production objects, so a
// new release whose object names would reuse them must be rejected (F-3,
// generalized to strategies).
func (s *Store) PromotedCanaryPairs(namespace string) ([]CanaryPair, error) {
	rows, err := s.db.Query(
		`SELECT name, strategy FROM canary_releases WHERE namespace = ? AND state = ?`,
		namespace, CanaryPromoted,
	)
	if err != nil {
		return nil, fmt.Errorf("store: promoted canary pairs in %q: %w", namespace, err)
	}
	defer rows.Close()
	var out []CanaryPair
	for rows.Next() {
		var p CanaryPair
		if err := rows.Scan(&p.Name, &p.Strategy); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// SetCanaryBaseline records the cumulative counters at the first successful
// scrape (or after a detected counter reset).
func (s *Store) SetCanaryBaseline(id int64, requests, errs int64) error {
	if _, err := s.db.Exec(
		`UPDATE canary_releases SET baseline_requests = ?, baseline_errors = ?, updated_at = ?
		 WHERE id = ?`,
		requests, errs, now(), id,
	); err != nil {
		return fmt.Errorf("store: set canary %d baseline: %w", id, err)
	}
	return nil
}

// BumpScrapeFailures increments the consecutive-failure counter and
// returns the new count.
func (s *Store) BumpScrapeFailures(id int64) (int, error) {
	if _, err := s.db.Exec(
		`UPDATE canary_releases SET scrape_failures = scrape_failures + 1, updated_at = ?
		 WHERE id = ?`,
		now(), id,
	); err != nil {
		return 0, fmt.Errorf("store: bump canary %d failures: %w", id, err)
	}
	var n int
	if err := s.db.QueryRow(
		`SELECT scrape_failures FROM canary_releases WHERE id = ?`, id,
	).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: read canary %d failures: %w", id, err)
	}
	return n, nil
}

// ResetScrapeFailures clears the consecutive-failure counter.
func (s *Store) ResetScrapeFailures(id int64) error {
	if _, err := s.db.Exec(
		`UPDATE canary_releases SET scrape_failures = 0 WHERE id = ?`, id,
	); err != nil {
		return fmt.Errorf("store: reset canary %d failures: %w", id, err)
	}
	return nil
}

// SetLastMetrics stores the most recent scrape results.
func (s *Store) SetLastMetrics(id int64, errRate float64, requests, errs int64) error {
	if _, err := s.db.Exec(
		`UPDATE canary_releases SET last_err_rate=?, last_requests=?, last_errors=? WHERE id=?`,
		errRate, requests, errs, id,
	); err != nil {
		return fmt.Errorf("store: set canary %d metrics: %w", id, err)
	}
	return nil
}

// InsertCanaryEvent appends one state-machine event.
func (s *Store) InsertCanaryEvent(releaseID int64, state, detail string) error {
	if _, err := s.db.Exec(
		`INSERT INTO canary_events (release_id, ts, state, detail) VALUES (?, ?, ?, ?)`,
		releaseID, now(), state, detail,
	); err != nil {
		return fmt.Errorf("store: insert canary event: %w", err)
	}
	return nil
}

// EventsOf returns the events of a release in chronological order.
func (s *Store) EventsOf(releaseID int64) ([]CanaryEvent, error) {
	return s.eventsOf(releaseID, 0)
}

// EventsOfLimit returns up to limit most recent events, chronological order.
func (s *Store) EventsOfLimit(releaseID int64, limit int) ([]CanaryEvent, error) {
	return s.eventsOf(releaseID, limit)
}

func (s *Store) eventsOf(releaseID int64, limit int) ([]CanaryEvent, error) {
	query := `SELECT id, release_id, ts, state, detail
	FROM (SELECT id, release_id, ts, state, detail FROM canary_events
	         WHERE release_id = ?`
	args := []interface{}{releaseID}
	if limit > 0 {
		query += ` ORDER BY id DESC LIMIT ?)`
		args = append(args, limit)
	} else {
		query += `)`
	}
	query += ` ORDER BY id ASC`
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CanaryEvent
	for rows.Next() {
		var e CanaryEvent
		if err := rows.Scan(&e.ID, &e.ReleaseID, &e.TS, &e.State, &e.Detail); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
