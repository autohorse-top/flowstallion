// Retention policy for log / canary-event / audit-event growth control
// (P7⑧; audit events added in task ⑨). The policy comes from the
// FLOWSTALLION_LOG_RETENTION env var ("30d" by-age or "runs=500" keep-last)
// and is applied by RetentionTick, which cmd/scheduler runs once at startup
// and then every 5 minutes.
package scheduler

import (
	"errors"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// RetentionPolicy is the parsed form of a FLOWSTALLION_LOG_RETENTION value.
// Exactly one of Age (by-age purge) or Keep (keep-newest-N runs) is set;
// the zero value means retention is disabled.
type RetentionPolicy struct {
	Spec string
	Age  time.Duration
	Keep int64
}

// Enabled reports whether the policy is configured.
func (p RetentionPolicy) Enabled() bool {
	return p.Age > 0 || p.Keep > 0
}

// retentionMaxDays caps the by-age horizon (100 years) so a huge day count
// cannot overflow a time.Duration.
const retentionMaxDays = 36500

var (
	retentionAgeRe  = regexp.MustCompile(`^(\d+)d$`)
	retentionKeepRe = regexp.MustCompile(`^runs=(\d+)$`)
)

// ParseRetention parses a FLOWSTALLION_LOG_RETENTION value: "30d" (purge rows
// older than 30 days) or "runs=500" (keep the 500 newest runs, purge the
// rest). It returns an error for anything else.
func ParseRetention(spec string) (RetentionPolicy, error) {
	spec = strings.TrimSpace(spec)
	if m := retentionAgeRe.FindStringSubmatch(spec); m != nil {
		days, err := strconv.ParseInt(m[1], 10, 64)
		if err != nil || days < 1 || days > retentionMaxDays {
			return RetentionPolicy{}, fmt.Errorf("invalid retention spec %q (want e.g. \"30d\" or \"runs=500\")", spec)
		}
		return RetentionPolicy{Spec: spec, Age: time.Duration(days) * 24 * time.Hour}, nil
	}
	if m := retentionKeepRe.FindStringSubmatch(spec); m != nil {
		keep, err := strconv.ParseInt(m[1], 10, 64)
		if err != nil || keep < 1 {
			return RetentionPolicy{}, fmt.Errorf("invalid retention spec %q (want e.g. \"30d\" or \"runs=500\")", spec)
		}
		return RetentionPolicy{Spec: spec, Keep: keep}, nil
	}
	return RetentionPolicy{}, fmt.Errorf("invalid retention spec %q (want e.g. \"30d\" or \"runs=500\")", spec)
}

// RetentionTick applies the configured retention policy once and returns the
// total number of rows purged (logs + canary events + audit events). A
// disabled policy returns (0, nil). Store errors are wrapped and returned so
// the caller can log them; a failure on one table does not stop the others
// from being purged.
func (s *Scheduler) RetentionTick() (int64, error) {
	if !s.Retention.Enabled() {
		return 0, nil
	}
	now := time.Now().UTC()
	if s.NowFn != nil {
		now = s.NowFn().UTC()
	}
	var (
		purged int64
		errs   []error
	)
	if s.Retention.Age > 0 {
		cutoff := now.Add(-s.Retention.Age).Format(time.RFC3339)
		n, err := s.Store.PurgeLogsByAge(cutoff)
		if err != nil {
			errs = append(errs, fmt.Errorf("purge logs by age: %w", err))
		} else {
			purged += n
		}
		n, err = s.Store.PurgeCanaryEventsByAge(cutoff)
		if err != nil {
			errs = append(errs, fmt.Errorf("purge canary events by age: %w", err))
		} else {
			purged += n
		}
		n, err = s.Store.PurgeAuditEventsByAge(cutoff)
		if err != nil {
			errs = append(errs, fmt.Errorf("purge audit events by age: %w", err))
		} else {
			purged += n
		}
	} else {
		n, err := s.Store.PurgeLogsKeepLast(s.Retention.Keep)
		if err != nil {
			errs = append(errs, fmt.Errorf("purge logs keep-last: %w", err))
		} else {
			purged += n
		}
		n, err = s.Store.PurgeCanaryEventsKeepLast(s.Retention.Keep)
		if err != nil {
			errs = append(errs, fmt.Errorf("purge canary events keep-last: %w", err))
		} else {
			purged += n
		}
		n, err = s.Store.PurgeAuditEventsKeepLast(s.Retention.Keep)
		if err != nil {
			errs = append(errs, fmt.Errorf("purge audit events keep-last: %w", err))
		} else {
			purged += n
		}
	}
	if len(errs) > 0 {
		return purged, fmt.Errorf("scheduler: retention tick: %w", errors.Join(errs...))
	}
	if purged > 0 {
		log.Printf("retention: purged %d log/event/audit rows (policy %q)", purged, s.Retention.Spec)
	}
	return purged, nil
}
