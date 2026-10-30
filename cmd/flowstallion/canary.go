// canary.go: flowstallion canary command (P7⑧) — read back the canary release bound to
// a run, or roll it back.
package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// runCanary implements `flowstallion canary <run-id> [rollback] [--reason text]`:
// without the rollback argument it prints the canary release bound to the
// run (state, metrics, recent events); with it, rolls the release back to
// the stable image.
func runCanary(args []string) {
	flags := flag.NewFlagSet("canary", flag.ExitOnError)
	reason := flags.String("reason", "", "reason recorded for the rollback")
	flags.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: flowstallion canary <run-id> [rollback] [--reason <text>]")
	}
	args = extractFlags(args, []string{"--reason"})
	flags.Parse(args)
	if flags.NArg() < 1 || flags.NArg() > 2 {
		flags.Usage()
		os.Exit(1)
	}
	runID, perr := strconv.ParseInt(flags.Arg(0), 10, 64)
	if perr != nil {
		fmt.Fprintf(os.Stderr, "flowstallion: run id must be an integer (got %q)\n", flags.Arg(0))
		os.Exit(1)
	}
	rollback := flags.NArg() == 2 && flags.Arg(1) == "rollback"
	if flags.NArg() == 2 && flags.Arg(1) != "rollback" {
		fmt.Fprintf(os.Stderr, "flowstallion: unknown subcommand %q (want rollback)\n", flags.Arg(1))
		os.Exit(1)
	}
	c, err := apiClient()
	if err != nil {
		fatalConfig(err)
	}
	var list []canaryJSON
	if err := c.doJSON("GET", "/api/canaries", nil, &list); err != nil {
		fatalAPI(err)
	}
	cr, ok := findCanaryForRun(list, runID)
	if !ok {
		fmt.Fprintf(os.Stderr, "flowstallion: no canary release bound to run %d\n", runID)
		os.Exit(1)
	}
	if !rollback {
		var detail struct {
			Canary canaryJSON        `json:"canary"`
			Events []canaryEventJSON `json:"events"`
		}
		if err := c.doJSON("GET", "/api/canaries/"+strconv.FormatInt(cr.ID, 10), nil, &detail); err != nil {
			fatalAPI(err)
		}
		fmt.Print(formatCanaryReadback(detail.Canary, detail.Events))
		return
	}
	r := *reason
	if r == "" {
		r = "manual rollback (flowstallion CLI)"
	}
	if err := c.doJSON("POST", "/api/canaries/"+strconv.FormatInt(cr.ID, 10)+"/rollback",
		map[string]string{"reason": r}, nil); err != nil {
		fatalAPI(err)
	}
	fmt.Printf("%s #%d rolled back\n", releaseKind(cr.Strategy), cr.ID)
}

// findCanaryForRun returns the canary release bound to a run (the one with
// the highest id when several are bound to the same run).
func findCanaryForRun(cs []canaryJSON, runID int64) (canaryJSON, bool) {
	var found *canaryJSON
	for i := range cs {
		if cs[i].RunID == runID {
			if found == nil || cs[i].ID > found.ID {
				found = &cs[i]
			}
		}
	}
	if found == nil {
		return canaryJSON{}, false
	}
	return *found, true
}

// releaseKind is the human-facing label for a release's strategy
// ("blue_green" is the only non-legacy strategy; anything else is canary).
func releaseKind(strategy string) string {
	if strategy == "blue_green" {
		return "Blue-Green"
	}
	return "Canary"
}

// formatCanaryReadback renders the `flowstallion canary <run-id>` output.
func formatCanaryReadback(c canaryJSON, events []canaryEventJSON) string {
	strategy := c.Strategy
	if strategy == "" {
		strategy = "canary"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s #%d  %s  (namespace %s, run %d)\n",
		releaseKind(strategy), c.ID, c.Name, c.Namespace, c.RunID)
	fmt.Fprintf(&b, "  strategy:   %s\n", strategy)
	fmt.Fprintf(&b, "  state:      %s\n", c.State)
	if c.Reason != "" {
		fmt.Fprintf(&b, "  reason:     %s\n", c.Reason)
	}
	fmt.Fprintf(&b, "  err_rate:   %s (requests %d, errors %d)\n",
		strconv.FormatFloat(c.LastErrRate, 'f', 4, 64), c.LastRequests, c.LastErrors)
	if c.CanaryStart != "" {
		fmt.Fprintf(&b, "  canary_start: %s\n", c.CanaryStart)
	}
	if c.FinishedAt != "" {
		fmt.Fprintf(&b, "  finished_at:  %s\n", c.FinishedAt)
	}
	b.WriteString("  recent events (last 20):\n")
	if len(events) == 0 {
		b.WriteString("  (none)\n")
		return b.String()
	}
	start := 0
	if len(events) > 20 {
		start = len(events) - 20
	}
	for _, e := range events[start:] {
		fmt.Fprintf(&b, "    %s  %s  %s\n", e.TS, e.State, e.Detail)
	}
	return b.String()
}
