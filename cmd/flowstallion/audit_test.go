// audit_test.go: table-driven tests for the flowstallion audit query builder and
// table formatter (the pure parts of the command; HTTP is covered by the
// scheduler's GET /api/audit tests in pkg/api).
package main

import (
	"strings"
	"testing"
)

func TestBuildAuditQuery(t *testing.T) {
	const since = "2026-10-29T00:00:00Z"
	cases := []struct {
		name   string
		limit  int
		actor  string
		action string
		after  int64
		since  string
		want   string
	}{
		{name: "limit only", limit: 20, want: "/api/audit?limit=20"},
		{name: "actor filter", limit: 5, actor: "admin", want: "/api/audit?limit=5&actor=admin"},
		{name: "actor with colon is escaped", limit: 10, actor: "scm:github",
			want: "/api/audit?limit=10&actor=scm%3Agithub"},
		{name: "action filter", limit: 20, action: "run.trigger",
			want: "/api/audit?limit=20&action=run.trigger"},
		{name: "after cursor", limit: 30, after: 42, want: "/api/audit?limit=30&after=42"},
		{name: "since filter is escaped", limit: 20, since: since,
			want: "/api/audit?limit=20&since=2026-10-29T00%3A00%3A00Z"},
		{
			name:  "since stacks with after",
			limit: 30, after: 42, since: since,
			want: "/api/audit?limit=30&after=42&since=2026-10-29T00%3A00%3A00Z",
		},
		{
			name:   "all filters",
			limit:  100,
			actor:  "bob",
			action: "auth.deny",
			after:  7,
			since:  since,
			want:   "/api/audit?limit=100&actor=bob&action=auth.deny&after=7&since=2026-10-29T00%3A00%3A00Z",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := buildAuditQuery(tc.limit, tc.actor, tc.action, tc.after, tc.since); got != tc.want {
				t.Errorf("buildAuditQuery(%d, %q, %q, %d, %q) = %q, want %q",
					tc.limit, tc.actor, tc.action, tc.after, tc.since, got, tc.want)
			}
		})
	}
}

func TestFormatAuditTable(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		if got := formatAuditTable(nil); got != "No audit events found.\n" {
			t.Fatalf("formatAuditTable(nil) = %q", got)
		}
	})

	t.Run("rows", func(t *testing.T) {
		events := []auditJSON{
			{ID: 2, TS: "2026-10-28T12:00:01Z", Actor: "admin", Action: "user.create",
				Target: "user:bob", Outcome: "ok"},
			{ID: 1, TS: "2026-10-28T12:00:00Z", Actor: "scm:github", Action: "scm.push",
				Target: "run:9", Outcome: "ok"},
		}
		pad := func(s string, n int) string {
			if len(s) < n {
				s += strings.Repeat(" ", n-len(s))
			}
			return s
		}
		want := pad("TS", 20) + " " + pad("ACTOR", 12) + " " + pad("ACTION", 20) + " " +
			pad("TARGET", 24) + " OUTCOME\n" +
			pad("2026-10-28T12:00:01Z", 20) + " " + pad("admin", 12) + " " +
			pad("user.create", 20) + " " + pad("user:bob", 24) + " ok\n" +
			pad("2026-10-28T12:00:00Z", 20) + " " + pad("scm:github", 12) + " " +
			pad("scm.push", 20) + " " + pad("run:9", 24) + " ok\n"
		if got := formatAuditTable(events); got != want {
			t.Fatalf("formatAuditTable mismatch:\n--- got ---\n%q\n--- want ---\n%q", got, want)
		}
	})
}
