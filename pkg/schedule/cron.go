// Package schedule implements a minimal five-field cron expression parser
// (minute hour day-of-month month day-of-week) plus the next-fire-time
// computation the scheduler's cron loop needs.
//
// Supported field syntax:
//
//   - any value
//     5         a single value
//     1-5       a range (inclusive)
//     1,15,30   a list
//     */15      step from the field minimum
//     1-30/5    step within a range
//     5/20      step from a single value to the field maximum
//
// Day-of-week accepts 0-7; both 0 and 7 mean Sunday. There is no seconds
// field, no @macros and no month/day names. When both day-of-month and
// day-of-week are restricted (neither field starts with '*'), a date
// matches when EITHER matches, following Vixie cron semantics.
//
// All times are handled in the location of the time.Time passed to NextRun;
// the FlowStallion scheduler passes UTC times.
package schedule

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Cron is a parsed five-field cron expression. It is immutable after Parse.
type Cron struct {
	minute     []bool // length 60
	hour       []bool // length 24
	dayOfMonth []bool // length 31
	month      []bool // length 12
	dayOfWeek  []bool // length 7, index 0 = Sunday

	domRestricted bool // day-of-month field did not start with '*'
	dowRestricted bool // day-of-week field did not start with '*'
}

// fieldSpecs describes the value bounds of the five cron fields, in order.
var fieldSpecs = [5]struct {
	name   string
	lo, hi int
}{
	{"minute", 0, 59},
	{"hour", 0, 23},
	{"day-of-month", 1, 31},
	{"month", 1, 12},
	{"day-of-week", 0, 7},
}

// Parse parses a five-field cron expression:
// "minute hour day-of-month month day-of-week".
// Errors name the offending field.
func Parse(expr string) (Cron, error) {
	fields := strings.Fields(strings.TrimSpace(expr))
	if len(fields) != 5 {
		return Cron{}, fmt.Errorf("cron %q: expected 5 fields (minute hour day-of-month month day-of-week), got %d", expr, len(fields))
	}
	var c Cron
	var rawDow []bool
	for i, field := range fields {
		spec := fieldSpecs[i]
		allowed, err := parseField(field, spec.name, spec.lo, spec.hi)
		if err != nil {
			return Cron{}, err
		}
		switch i {
		case 0:
			c.minute = allowed
		case 1:
			c.hour = allowed
		case 2:
			c.dayOfMonth = allowed
		case 3:
			c.month = allowed
		default:
			rawDow = allowed // length 8: values 0..7
		}
	}
	// Fold day-of-week value 7 (Sunday alias) into index 0.
	c.dayOfWeek = make([]bool, 7)
	for i, v := range rawDow[:7] {
		c.dayOfWeek[i] = v
	}
	c.dayOfWeek[0] = c.dayOfWeek[0] || rawDow[7]
	c.domRestricted = !strings.HasPrefix(fields[2], "*")
	c.dowRestricted = !strings.HasPrefix(fields[4], "*")
	return c, nil
}

// NextRun returns the first instant strictly after `after` at which the
// expression fires, with seconds and nanoseconds zeroed and the location of
// `after` preserved. The second return value is false when the expression
// matches no calendar date within the five-year search horizon (e.g.
// "0 0 31 2 *": February 31 never exists).
func (c Cron) NextRun(after time.Time) (time.Time, bool) {
	// Start on the next whole minute strictly after `after`.
	t := after.Truncate(time.Minute).Add(time.Minute)
	limit := t.AddDate(5, 0, 0)
	for !t.After(limit) {
		if !c.month[int(t.Month())-1] {
			t = time.Date(t.Year(), t.Month()+1, 1, 0, 0, 0, 0, t.Location())
			continue
		}
		if !c.dayMatches(t) {
			t = time.Date(t.Year(), t.Month(), t.Day()+1, 0, 0, 0, 0, t.Location())
			continue
		}
		if !c.hour[t.Hour()] {
			t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour()+1, 0, 0, 0, t.Location())
			continue
		}
		if !c.minute[t.Minute()] {
			t = t.Add(time.Minute)
			continue
		}
		return t, true
	}
	return time.Time{}, false
}

// dayMatches reports whether t's calendar date matches the day fields. When
// both day-of-month and day-of-week are restricted, a date matches when
// EITHER matches (Vixie cron); otherwise every restricted field must match.
func (c Cron) dayMatches(t time.Time) bool {
	domOK := c.dayOfMonth[t.Day()-1]
	dowOK := c.dayOfWeek[int(t.Weekday())]
	if c.domRestricted && c.dowRestricted {
		return domOK || dowOK
	}
	return domOK && dowOK
}

// parseField parses one cron field and returns a boolean set indexed
// value-lo, of length hi-lo+1.
func parseField(field, name string, lo, hi int) ([]bool, error) {
	allowed := make([]bool, hi-lo+1)
	for _, part := range strings.Split(field, ",") {
		step := 1
		if slash := strings.IndexByte(part, '/'); slash >= 0 {
			var err error
			step, err = strconv.Atoi(part[slash+1:])
			if err != nil || step < 1 {
				return nil, fmt.Errorf("cron %s field %q: invalid step %q", name, field, part[slash+1:])
			}
			part = part[:slash]
		}
		var start, end int
		switch {
		case part == "*":
			start, end = lo, hi
		case strings.Contains(part, "-"):
			bounds := strings.SplitN(part, "-", 2)
			var err error
			start, err = strconv.Atoi(bounds[0])
			if err != nil {
				return nil, fmt.Errorf("cron %s field %q: invalid range %q", name, field, part)
			}
			end, err = strconv.Atoi(bounds[1])
			if err != nil {
				return nil, fmt.Errorf("cron %s field %q: invalid range %q", name, field, part)
			}
			if start > end {
				return nil, fmt.Errorf("cron %s field %q: range %q ends before it starts", name, field, part)
			}
		default:
			var err error
			start, err = strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("cron %s field %q: invalid value %q", name, field, part)
			}
			if step > 1 {
				end = hi // "N/step" steps from N to the field maximum
			} else {
				end = start
			}
		}
		if start < lo || end > hi {
			return nil, fmt.Errorf("cron %s field %q: value out of range (%d-%d)", name, field, lo, hi)
		}
		for v := start; v <= end; v += step {
			allowed[v-lo] = true
		}
	}
	return allowed, nil
}
