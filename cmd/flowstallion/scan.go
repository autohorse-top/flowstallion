package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/flowstallion/flowstallion/pkg/security"
)

// ---------------------------------------------------------------------------
// scan
// ---------------------------------------------------------------------------

// runScan implements `flowstallion scan --run <id> [--tool trivy|gitleaks|semgrep]
// (--repo <path> | --image <ref>)`: runs a security scan locally, then stores
// the normalised result on the run via the scheduler API. gitleaks and
// semgrep only support --repo (fs mode); --image is trivy-only.
// Exit codes: 0 stored, 1 scan/HTTP failure, 2 usage error or missing binary.
func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	runID := fs.Int64("run", 0, "run id to attach the scan to (required)")
	tool := fs.String("tool", "trivy", "scanner tool: trivy | gitleaks | semgrep")
	repo := fs.String("repo", "", "local path to scan (fs mode; required for gitleaks/semgrep)")
	image := fs.String("image", "", "container image reference to scan (trivy image mode only)")
	server := fs.String("server", "", "scheduler base URL (overrides FLOWSTALLION_SERVER and login config)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: flowstallion scan --run <id> [--tool trivy|gitleaks|semgrep] (--repo <path> | --image <ref>) [--server URL]")
	}
	args = extractFlags(args, []string{"--run", "--tool", "--repo", "--image", "--server"})
	fs.Parse(args)
	if fs.NArg() != 0 {
		fs.Usage()
		os.Exit(2)
	}
	if *runID <= 0 {
		fmt.Fprintln(os.Stderr, "flowstallion: --run <id> is required")
		fs.Usage()
		os.Exit(2)
	}
	mode, target, err := resolveScanTarget(*tool, *repo, *image)
	if err != nil {
		fmt.Fprintf(os.Stderr, "flowstallion: %v\n", err)
		fs.Usage()
		os.Exit(2)
	}

	res, err := runScanTool(*tool, mode, target)
	if err != nil {
		switch {
		case errors.Is(err, security.ErrTrivyNotFound),
			errors.Is(err, security.ErrGitleaksNotFound),
			errors.Is(err, security.ErrSemgrepNotFound):
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "flowstallion: scan failed: %v\n", err)
		os.Exit(1)
	}

	base := *server
	token := os.Getenv("FLOWSTALLION_TOKEN")
	if base == "" {
		base = os.Getenv("FLOWSTALLION_SERVER")
	}
	if cfg, cerr := loadConfig(); cerr == nil {
		if base == "" {
			base = cfg.Server
		}
		if token == "" {
			token = cfg.Token
		}
	} else if base == "" {
		fatalConfig(cerr)
	}
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		fmt.Fprintf(os.Stderr, "flowstallion: server URL must start with http:// or https:// (got %q)\n", base)
		os.Exit(1)
	}
	c := newClient(base, token)
	body := map[string]any{
		"tool":           res.Tool,
		"target":         res.Target,
		"mode":           res.Mode,
		"exit_code":      res.ExitCode,
		"findings_count": res.FindingsCount,
		"severity":       res.Severity,
		"truncated":      res.Truncated,
		"report_json":    res.RawJSON,
	}
	if err := c.doJSON("POST", "/api/runs/"+strconv.FormatInt(*runID, 10)+"/scans", body, nil); err != nil {
		fatalAPI(err)
	}
	printScanSaved(*runID, res)
}

// resolveScanTarget validates the (tool, --repo, --image) combination and
// returns the scan mode/target to pass to the runner. gitleaks and semgrep
// are fs-only; trivy supports fs and image.
func resolveScanTarget(tool, repo, image string) (mode, target string, err error) {
	switch tool {
	case "trivy":
		switch {
		case repo != "" && image != "":
			return "", "", errors.New("use either --repo or --image, not both")
		case repo != "":
			return "fs", repo, nil
		case image != "":
			return "image", image, nil
		default:
			return "", "", errors.New("--repo <path> or --image <ref> is required")
		}
	case "gitleaks", "semgrep":
		if image != "" {
			return "", "", fmt.Errorf("%s only supports --repo <path> (fs mode), not --image", tool)
		}
		if repo == "" {
			return "", "", fmt.Errorf("--repo <path> is required for %s", tool)
		}
		return "fs", repo, nil
	default:
		return "", "", fmt.Errorf("unknown --tool %q (want trivy, gitleaks or semgrep)", tool)
	}
}

// runScanTool dispatches to the selected scanner and returns the common
// normalised result (the API only persists the common Result fields).
func runScanTool(tool, mode, target string) (security.Result, error) {
	ctx := context.Background()
	switch tool {
	case "trivy":
		res, err := security.NewTrivyRunner(security.TrivyConfig{}).Scan(ctx, mode, target)
		if err != nil {
			return security.Result{}, err
		}
		return res.Result, nil
	case "gitleaks":
		res, err := security.NewGitleaksRunner(security.GitleaksConfig{}).Scan(ctx, mode, target)
		if err != nil {
			return security.Result{}, err
		}
		return *res, nil
	case "semgrep":
		res, err := security.NewSemgrepRunner(security.SemgrepConfig{}).Scan(ctx, mode, target)
		if err != nil {
			return security.Result{}, err
		}
		return *res, nil
	default:
		// Defensive: resolveScanTarget already rejects unknown tools before
		// this is reached; kept as a last-resort guard for direct callers.
		return security.Result{}, fmt.Errorf("unknown scan tool %q (want trivy, gitleaks or semgrep)", tool)
	}
}

// printScanSaved prints the summary line. trivy keeps the P5 five-bucket
// format; other tools print their non-zero severity buckets in sorted order.
func printScanSaved(runID int64, res security.Result) {
	if res.Tool == "trivy" {
		fmt.Printf("scan saved: run=%d tool=%s target=%s findings=%d (critical=%d high=%d medium=%d low=%d unknown=%d)\n",
			runID, res.Tool, res.Target, res.FindingsCount,
			res.Severity["CRITICAL"], res.Severity["HIGH"], res.Severity["MEDIUM"],
			res.Severity["LOW"], res.Severity["UNKNOWN"],
		)
		return
	}
	keys := make([]string, 0, len(res.Severity))
	for k, v := range res.Severity {
		if v > 0 {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", strings.ToLower(k), res.Severity[k]))
	}
	summary := ""
	if len(parts) > 0 {
		summary = " (" + strings.Join(parts, " ") + ")"
	}
	fmt.Printf("scan saved: run=%d tool=%s target=%s findings=%d%s\n",
		runID, res.Tool, res.Target, res.FindingsCount, summary)
}
