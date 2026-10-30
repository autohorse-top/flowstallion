package store

import (
	"database/sql"
	"fmt"
	"time"
)

// GetLastScheduleFire returns the last recorded cron fire time for the given
// schedule key. It returns (zero, false, nil) when the key has never fired,
// so callers can treat "no watermark" as "fire from the epoch".
func (s *Store) GetLastScheduleFire(key string) (time.Time, bool, error) {
	var ts string
	err := s.db.QueryRow(
		`SELECT last_fire FROM schedule_state WHERE key = ?`, key,
	).Scan(&ts)
	if err == sql.ErrNoRows {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, fmt.Errorf("store: get schedule state %q: %w", key, err)
	}
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("store: parse schedule state %q: %w", key, err)
	}
	return t, true, nil
}

// SetLastScheduleFire upserts the last recorded cron fire time for a
// schedule key. Times are stored as RFC3339 UTC.
func (s *Store) SetLastScheduleFire(key string, t time.Time) error {
	if _, err := s.db.Exec(
		`INSERT INTO schedule_state (key, last_fire) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET last_fire = excluded.last_fire`,
		key, t.UTC().Format(time.RFC3339),
	); err != nil {
		return fmt.Errorf("store: set schedule state %q: %w", key, err)
	}
	return nil
}
