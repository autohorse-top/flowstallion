// cost.go: flowstallion cost command (P7⑧) — prints an aggregated cost table from the
// shared JSONL cost ledger (same file the Python agent appends to).
package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/flowstallion/flowstallion/pkg/finops"
)

// runCost implements `flowstallion cost [--by pr|team] [--source llm|cloud]`.
// It reads the ledger locally (no server round-trip) and prints a table.
func runCost(args []string) {
	flags := flag.NewFlagSet("cost", flag.ExitOnError)
	by := flags.String("by", "pr", "group key: pr or team")
	source := flags.String("source", "", "filter by source: llm or cloud (default: all)")
	flags.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: flowstallion cost [--by pr|team] [--source llm|cloud]")
	}
	args = extractFlags(args, []string{"--by", "--source"})
	flags.Parse(args)
	if flags.NArg() != 0 {
		flags.Usage()
		os.Exit(1)
	}
	byN, srcN, err := resolveCostArgs(*by, *source)
	if err != nil {
		fmt.Fprintf(os.Stderr, "flowstallion: %v\n", err)
		os.Exit(1)
	}
	recs, err := finops.ReadFile(finops.LedgerPath())
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "flowstallion: cost ledger: %v\n", err)
			os.Exit(1)
		}
		recs = nil // ledger not written yet: zero rows, not an error
	}
	if srcN != "" {
		filtered := make([]finops.Record, 0, len(recs))
		for _, rec := range recs {
			if rec.Source == srcN {
				filtered = append(filtered, rec)
			}
		}
		recs = filtered
	}
	rows, err := finops.Aggregate(recs, byN)
	if err != nil {
		fmt.Fprintf(os.Stderr, "flowstallion: %v\n", err)
		os.Exit(1)
	}
	fmt.Print(formatCostTable(rows, byN, srcN, finops.Total(recs)))
}

// resolveCostArgs validates and normalizes the --by / --source flags.
func resolveCostArgs(by, source string) (string, string, error) {
	if by == "" {
		by = "pr"
	}
	if by != "pr" && by != "team" {
		return "", "", fmt.Errorf(`by must be "pr" or "team"`)
	}
	if source != "" && source != "llm" && source != "cloud" {
		return "", "", fmt.Errorf(`source must be "llm" or "cloud"`)
	}
	return by, source, nil
}

// formatCostTable renders the cost table. A zero-row ledger prints the
// header plus "(no cost records)" (no TOTAL row). The TOTAL row sums the
// (post-filter) records via finops.Total.
func formatCostTable(rows []finops.Row, by, source string, total map[string]any) string {
	var b strings.Builder
	label := "all"
	if source != "" {
		label = source
	}
	fmt.Fprintf(&b, "cost by %s (source: %s)\n", by, label)
	fmt.Fprintf(&b, "%-14s %7s %7s %9s %8s %9s\n", "KEY", "RECORDS", "PROMPT", "COMPLETION", "TOTAL", "COST_USD")
	if len(rows) == 0 {
		b.WriteString("(no cost records)\n")
		return b.String()
	}
	for _, row := range rows {
		key, _ := row[by].(string)
		records, _ := row["records"].(int)
		prompt, _ := row["prompt_tokens"].(int64)
		completion, _ := row["completion_tokens"].(int64)
		tokens, _ := row["total_tokens"].(int64)
		cost, _ := row["cost_usd"].(float64)
		fmt.Fprintf(&b, "%-14s %7d %7d %9d %8d %9.4f\n", key, records, prompt, completion, tokens, cost)
	}
	records, _ := total["records"].(int)
	prompt, _ := total["prompt_tokens"].(int64)
	completion, _ := total["completion_tokens"].(int64)
	tokens, _ := total["total_tokens"].(int64)
	cost, _ := total["cost_usd"].(float64)
	fmt.Fprintf(&b, "%-14s %7d %7d %9d %8d %9.4f\n", "TOTAL", records, prompt, completion, tokens, cost)
	return b.String()
}
