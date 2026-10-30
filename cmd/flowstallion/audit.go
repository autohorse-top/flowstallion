// audit.go: flowstallion audit command (task ③) — query the audit log via
// GET /api/audit and print events as a table (ts actor action target outcome).
package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// auditJSON mirrors one event row of GET /api/audit (pkg/api/audit.go).
type auditJSON struct {
	ID      int64  `json:"id"`
	TS      string `json:"ts"`
	Actor   string `json:"actor"`
	Action  string `json:"action"`
	Target  string `json:"target"`
	Outcome string `json:"outcome"`
	Detail  string `json:"detail"`
	Src     string `json:"src"`
}

// runAudit implements `flowstallion audit [--limit N] [--actor a] [--action x]
// [--after id] [--since <RFC3339>]`: fetches audit events (viewer+) and
// prints them as a table.
func runAudit(args []string) {
	flags := flag.NewFlagSet("audit", flag.ExitOnError)
	limit := flags.Int("limit", 20, "max events to list (1-200)")
	actor := flags.String("actor", "", "filter by exact actor (e.g. admin, scm:github)")
	action := flags.String("action", "", "filter by exact action (e.g. run.trigger)")
	after := flags.Int64("after", 0, "only list events with id < after (pagination)")
	since := flags.String("since", "", "only list events with ts >= since (RFC3339, e.g. 2026-10-29T00:00:00Z)")
	flags.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: flowstallion audit [--limit N] [--actor <actor>] [--action <action>] [--after <id>] [--since <RFC3339>]")
	}
	args = extractFlags(args, []string{"--limit", "--actor", "--action", "--after", "--since"})
	flags.Parse(args)
	if flags.NArg() != 0 {
		flags.Usage()
		os.Exit(1)
	}
	if *limit < 1 || *limit > 200 {
		fmt.Fprintf(os.Stderr, "flowstallion: --limit must be in [1, 200] (got %d)\n", *limit)
		os.Exit(1)
	}
	c, err := apiClient()
	if err != nil {
		fatalConfig(err)
	}
	var out struct {
		Events []auditJSON `json:"events"`
	}
	if err := c.doJSON("GET", buildAuditQuery(*limit, *actor, *action, *after, *since), nil, &out); err != nil {
		fatalAPI(err)
	}
	fmt.Print(formatAuditTable(out.Events))
}

// buildAuditQuery assembles the GET /api/audit query string (limit is
// always sent; actor/action/after/since only when set).
func buildAuditQuery(limit int, actor, action string, after int64, since string) string {
	q := fmt.Sprintf("/api/audit?limit=%d", limit)
	if actor != "" {
		q += "&actor=" + url.QueryEscape(actor)
	}
	if action != "" {
		q += "&action=" + url.QueryEscape(action)
	}
	if after > 0 {
		q += fmt.Sprintf("&after=%d", after)
	}
	if since != "" {
		q += "&since=" + url.QueryEscape(since)
	}
	return q
}

// formatAuditTable renders audit events as a fixed-width table
// (ts actor action target outcome); "No audit events found." when empty.
func formatAuditTable(events []auditJSON) string {
	if len(events) == 0 {
		return "No audit events found.\n"
	}
	var b strings.Builder
	writeRow := func(ts, actor, action, target, outcome string) {
		fmt.Fprintf(&b, "%-20s %-12s %-20s %-24s %s\n", ts, actor, action, target, outcome)
	}
	writeRow("TS", "ACTOR", "ACTION", "TARGET", "OUTCOME")
	for _, e := range events {
		writeRow(e.TS, e.Actor, e.Action, e.Target, e.Outcome)
	}
	return b.String()
}
