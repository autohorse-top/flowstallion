// approval.go: flowstallion approve / flowstallion reject commands (P7⑧).
package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
)

// runApprove implements `flowstallion approve <run-id>`: releases a policy-held
// (pending_approval) run.
func runApprove(args []string) {
	flags := flag.NewFlagSet("approve", flag.ExitOnError)
	flags.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: flowstallion approve <run-id>")
	}
	flags.Parse(args)
	if flags.NArg() != 1 {
		flags.Usage()
		os.Exit(1)
	}
	runID, err := strconv.ParseInt(flags.Arg(0), 10, 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "flowstallion: run id must be an integer (got %q)\n", flags.Arg(0))
		os.Exit(1)
	}
	c, err := apiClient()
	if err != nil {
		fatalConfig(err)
	}
	if err := c.doJSON("POST", "/api/runs/"+strconv.FormatInt(runID, 10)+"/approve", nil, nil); err != nil {
		fatalAPI(err)
	}
	fmt.Printf("Run #%d approved\n", runID)
}

// runReject implements `flowstallion reject <run-id> [--reason text]`: dismisses a
// policy-held (pending_approval) run, persisting the optional reason on the
// run (P7⑧).
func runReject(args []string) {
	flags := flag.NewFlagSet("reject", flag.ExitOnError)
	reason := flags.String("reason", "", "reason recorded on the run")
	flags.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: flowstallion reject <run-id> [--reason <text>]")
	}
	args = extractFlags(args, []string{"--reason"})
	flags.Parse(args)
	if flags.NArg() != 1 {
		flags.Usage()
		os.Exit(1)
	}
	runID, err := strconv.ParseInt(flags.Arg(0), 10, 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "flowstallion: run id must be an integer (got %q)\n", flags.Arg(0))
		os.Exit(1)
	}
	c, err := apiClient()
	if err != nil {
		fatalConfig(err)
	}
	var body any
	if *reason != "" {
		body = map[string]string{"reason": *reason}
	}
	if err := c.doJSON("POST", "/api/runs/"+strconv.FormatInt(runID, 10)+"/reject", body, nil); err != nil {
		fatalAPI(err)
	}
	fmt.Printf("Run #%d rejected\n", runID)
}
