// Log, canary-event and audit-event retention (P7⑧; audit events added in
// task ⑨). The scheduler's RetentionTick (driven by FLOWSTALLION_LOG_RETENTION)
// calls these purge queries; each returns the number of rows deleted.
package store

import (
	"fmt"
)

// PurgeLogsByAge deletes log lines of runs whose age —
// COALESCE(started_at, created_at), i.e. when the run started or, if never
// started, when it was created — is strictly older than cutoffTS (RFC3339).
func (s *Store) PurgeLogsByAge(cutoffTS string) (int64, error) {
	res, err := s.db.Exec(
		`DELETE FROM logs WHERE run_id IN (
		       SELECT id FROM runs WHERE COALESCE(started_at, created_at) < ?)`,
		cutoffTS,
	)
	if err != nil {
		return 0, fmt.Errorf("store: purge logs by age: %w", err)
	}
	return res.RowsAffected()
}

// PurgeLogsKeepLast deletes log lines of all but the keep most-recent runs
// (by run id, the insertion order). keep = 0 deletes all log lines.
func (s *Store) PurgeLogsKeepLast(keep int64) (int64, error) {
	res, err := s.db.Exec(
		`DELETE FROM logs WHERE run_id NOT IN (
		       SELECT id FROM runs ORDER BY id DESC LIMIT ?)`,
		keep,
	)
	if err != nil {
		return 0, fmt.Errorf("store: purge logs keep-last: %w", err)
	}
	return res.RowsAffected()
}

// PurgeCanaryEventsByAge deletes canary events with ts strictly older than
// cutoffTS (RFC3339).
func (s *Store) PurgeCanaryEventsByAge(cutoffTS string) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM canary_events WHERE ts < ?`, cutoffTS)
	if err != nil {
		return 0, fmt.Errorf("store: purge canary events by age: %w", err)
	}
	return res.RowsAffected()
}

// PurgeCanaryEventsKeepLast deletes canary events of all but the keep
// most-recent releases (by release id, the insertion order). keep = 0
// deletes all events.
func (s *Store) PurgeCanaryEventsKeepLast(keep int64) (int64, error) {
	res, err := s.db.Exec(
		`DELETE FROM canary_events WHERE release_id NOT IN (
		       SELECT id FROM canary_releases ORDER BY id DESC LIMIT ?)`,
		keep,
	)
	if err != nil {
		return 0, fmt.Errorf("store: purge canary events keep-last: %w", err)
	}
	return res.RowsAffected()
}

// PurgeAuditEventsByAge deletes audit events with ts strictly older than
// cutoffTS (RFC3339). ts is stored as RFC3339 UTC, so lexicographic
// comparison is chronological (same convention as the since filter in
// ListAuditEvents).
func (s *Store) PurgeAuditEventsByAge(cutoffTS string) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM audit_events WHERE ts < ?`, cutoffTS)
	if err != nil {
		return 0, fmt.Errorf("store: purge audit events by age: %w", err)
	}
	return res.RowsAffected()
}

// PurgeAuditEventsKeepLast deletes all but the keep most-recent audit events
// (by event id, the insertion order). keep = 0 deletes all events. Unlike
// the log/canary keep-last variants, "keep" counts events directly: audit
// rows are a flat append-only stream, not grouped by a parent entity.
func (s *Store) PurgeAuditEventsKeepLast(keep int64) (int64, error) {
	res, err := s.db.Exec(
		`DELETE FROM audit_events WHERE id NOT IN (
		       SELECT id FROM audit_events ORDER BY id DESC LIMIT ?)`,
		keep,
	)
	if err != nil {
		return 0, fmt.Errorf("store: purge audit events keep-last: %w", err)
	}
	return res.RowsAffected()
}
