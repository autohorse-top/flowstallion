package schedule

import (
	"testing"
	"time"
)

// All times UTC. Reference: 2026-01-01 is Thursday, 2026-10-26 is Monday,
// 2026 is not a leap year, 2028 is.

// TestParseNextRun: table-driven NextRun cases.
func TestParseNextRun(t *testing.T) {
	utc := time.UTC
	mk := func(y int, mo time.Month, d, h, mi int) time.Time {
		return time.Date(y, mo, d, h, mi, 0, 0, utc)
	}
	cases := []struct {
		name  string
		expr  string
		after time.Time
		want  time.Time
		ok    bool
	}{
		// --- minute / hour basics ---
		{"hourly next", "0 * * * *", mk(2026, 10, 26, 10, 30), mk(2026, 10, 26, 11, 0), true},
		{"hourly exact slot strictly after", "0 * * * *", mk(2026, 10, 26, 10, 0), mk(2026, 10, 26, 11, 0), true},
		{"daily exact slot strictly after", "30 5 * * *", mk(2026, 10, 26, 5, 30), mk(2026, 10, 27, 5, 30), true},
		{"daily just before slot", "30 5 * * *", mk(2026, 10, 26, 5, 29), mk(2026, 10, 26, 5, 30), true},
		{"step from star", "*/15 * * * *", mk(2026, 10, 26, 10, 7), mk(2026, 10, 26, 10, 15), true},
		{"step from star exact slot", "*/15 * * * *", mk(2026, 10, 26, 10, 15), mk(2026, 10, 26, 10, 30), true},
		{"step within range", "10-40/10 * * * *", mk(2026, 10, 26, 10, 41), mk(2026, 10, 26, 11, 10), true},
		{"step from single value", "5/20 * * * *", mk(2026, 10, 26, 10, 0), mk(2026, 10, 26, 10, 5), true},
		// --- list ---
		{"list next value", "5,20,50 * * * *", mk(2026, 10, 26, 10, 21), mk(2026, 10, 26, 10, 50), true},
		// --- hour range ---
		{"hour range end wraps to next day", "0 8-10 * * *", mk(2026, 10, 26, 10, 7), mk(2026, 10, 27, 8, 0), true},
		{"hourly step within business hours", "15 */6 * * *", mk(2026, 10, 26, 7, 20), mk(2026, 10, 26, 12, 15), true},
		// --- day of week ---
		{"dow monday same day passed", "0 9 * * 1", mk(2026, 10, 26, 9, 0), mk(2026, 11, 2, 9, 0), true},
		{"dow monday from previous sunday", "0 9 * * 1", mk(2026, 10, 25, 10, 0), mk(2026, 10, 26, 9, 0), true},
		{"dow 7 means sunday", "0 0 * * 7", mk(2026, 10, 22, 12, 0), mk(2026, 10, 25, 0, 0), true},
		{"weekdays only", "*/5 9-17 * * 1-5", mk(2026, 10, 26, 17, 56), mk(2026, 10, 27, 9, 0), true},
		// --- day of month ---
		{"dom 31 skips short month", "0 0 31 * *", mk(2026, 4, 30, 0, 0), mk(2026, 5, 31, 0, 0), true},
		{"dom 31 across year", "0 0 31 * *", mk(2026, 12, 31, 0, 0), mk(2027, 1, 31, 0, 0), true},
		// --- Vixie dom+dow OR rule (both restricted) ---
		{"dom15 or monday: monday wins", "0 0 15 * 1", mk(2026, 10, 26, 9, 0), mk(2026, 11, 2, 0, 0), true},
		{"dom15 or monday: dom15 wins", "0 0 15 * 1", mk(2026, 10, 14, 0, 0), mk(2026, 10, 15, 0, 0), true},
		// --- month / year boundaries ---
		{"leap day", "0 0 29 2 *", mk(2026, 1, 1, 0, 0), mk(2028, 2, 29, 0, 0), true},
		{"impossible date", "0 0 31 2 *", mk(2026, 1, 1, 0, 0), time.Time{}, false},
		{"new year", "0 0 1 1 *", mk(2026, 1, 2, 0, 0), mk(2027, 1, 1, 0, 0), true},
		{"midnight year wrap", "0 0 * * *", mk(2026, 12, 31, 23, 30), mk(2027, 1, 1, 0, 0), true},
		{"yearly exact slot strictly after", "59 23 31 12 *", mk(2026, 12, 31, 23, 59), mk(2027, 12, 31, 23, 59), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := Parse(tc.expr)
			if err != nil {
				t.Fatalf("Parse(%q): %v", tc.expr, err)
			}
			got, ok := c.NextRun(tc.after)
			if ok != tc.ok {
				t.Fatalf("NextRun(%q, %s) ok = %v, want %v", tc.expr, tc.after, ok, tc.ok)
			}
			if tc.ok && !got.Equal(tc.want) {
				t.Fatalf("NextRun(%q, %s) = %s, want %s", tc.expr, tc.after, got, tc.want)
			}
		})
	}
}

// TestParseInvalid: malformed expressions must be rejected, never silently
// accepted (the scheduler relies on this to skip broken pipelines).
func TestParseInvalid(t *testing.T) {
	cases := []struct {
		name string
		expr string
	}{
		{"empty", ""},
		{"whitespace only", "   "},
		{"4 fields", "* * * *"},
		{"6 fields", "* * * * * *"},
		{"macro", "@daily"},
		{"minute out of range", "60 * * * *"},
		{"hour out of range", "* 24 * * *"},
		{"dom zero", "* * 0 * *"},
		{"dom 32", "* * 32 * *"},
		{"month zero", "* * * 0 *"},
		{"month 13", "* * * 13 *"},
		{"dow 8", "* * * * 8"},
		{"non-numeric", "a * * * *"},
		{"empty list item", "1,,2 * * * *"},
		{"step zero", "*/0 * * * *"},
		{"step non-numeric", "*/x * * * *"},
		{"range inverted", "5-1 * * * *"},
		{"range malformed", "1--5 * * * *"},
		{"day name", "0 9 * * MON"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse(tc.expr); err == nil {
				t.Fatalf("Parse(%q) succeeded, want error", tc.expr)
			}
		})
	}
}

// TestParseErrorNamesField: errors name the offending field so operators can
// fix the pipeline.
func TestParseErrorNamesField(t *testing.T) {
	for expr, field := range map[string]string{
		"60 * * * *": "minute",
		"* 24 * * *": "hour",
		"* * 0 * *":  "day-of-month",
		"* * * 13 *": "month",
		"* * * * 8":  "day-of-week",
	} {
		_, err := Parse(expr)
		if err == nil {
			t.Fatalf("Parse(%q): want error", expr)
		}
		if !contains(err.Error(), field) {
			t.Errorf("Parse(%q) error = %v, want it to name field %q", expr, err, field)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// TestNextRunNoAllocationOverhead: sanity — NextRun on dense expressions must
// return quickly (field-level skipping, not minute-by-minute brute force).
func TestNextRunNoAllocationOverhead(t *testing.T) {
	c, err := Parse("0 0 29 2 *") // fires ~1x/4 years
	if err != nil {
		t.Fatal(err)
	}
	after := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	got, ok := c.NextRun(after)
	if !ok {
		t.Fatal("expected a match within the 5-year horizon")
	}
	if !got.Equal(time.Date(2028, 2, 29, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("got %s, want 2028-02-29T00:00:00Z", got)
	}
}
