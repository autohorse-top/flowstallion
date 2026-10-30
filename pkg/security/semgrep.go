// P6③: semgrep runner — SAST scanning for local code (fs mode).
//
// Follows the TrivyRunner pattern: external binary located via
// FLOWSTALLION_SEMGREP_BIN or PATH, JSON report on stdout, normalised into the
// common Result. Finding severities map to FlowStallion buckets:
// ERROR -> HIGH, WARNING -> MEDIUM, INFO -> LOW; unrecognised severities are
// counted in FindingsCount but in no bucket.
package security

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// ErrSemgrepNotFound is returned when the semgrep binary cannot be located.
var ErrSemgrepNotFound = errors.New("semgrep binary not found (set FLOWSTALLION_SEMGREP_BIN or install semgrep, e.g. pip install semgrep)")

// SemgrepConfig configures a SemgrepRunner.
type SemgrepConfig struct {
	// BinPath, when non-empty, takes priority over FLOWSTALLION_SEMGREP_BIN
	// and PATH lookup. It is intended for explicit programmatic configuration.
	BinPath string
	// Timeout bounds a single semgrep run; values <= 0 use DefaultTimeout.
	Timeout time.Duration
}

// SemgrepRunner runs the semgrep CLI in fs mode and normalises its JSON
// report into the common Result.
type SemgrepRunner struct {
	cfg SemgrepConfig
}

// NewSemgrepRunner builds a SemgrepRunner from cfg. A zero value is valid and
// yields the defaults (env/PATH lookup, DefaultTimeout).
func NewSemgrepRunner(cfg SemgrepConfig) *SemgrepRunner {
	return &SemgrepRunner{cfg: cfg}
}

// findSemgrepBin resolves the semgrep binary:
//  1. explicit cfg.BinPath, when set;
//  2. the FLOWSTALLION_SEMGREP_BIN environment variable, when non-empty;
//  3. exec.LookPath("semgrep").
//
// A configured path that is missing or not executable is treated as "not
// found" so callers get one stable error to handle.
func (r *SemgrepRunner) findSemgrepBin() (string, error) {
	if r.cfg.BinPath != "" {
		if isExecutable(r.cfg.BinPath) {
			return r.cfg.BinPath, nil
		}
		return "", fmt.Errorf("%w: configured path %q is missing or not executable", ErrSemgrepNotFound, r.cfg.BinPath)
	}
	if env := os.Getenv("FLOWSTALLION_SEMGREP_BIN"); env != "" {
		if isExecutable(env) {
			return env, nil
		}
		return "", fmt.Errorf("%w: FLOWSTALLION_SEMGREP_BIN=%q is missing or not executable", ErrSemgrepNotFound, env)
	}
	p, err := exec.LookPath("semgrep")
	if err != nil {
		return "", ErrSemgrepNotFound
	}
	return p, nil
}

// semgrepSeverity maps semgrep finding severities to FlowStallion buckets.
var semgrepSeverity = map[string]string{
	"ERROR":   "HIGH",
	"WARNING": "MEDIUM",
	"INFO":    "LOW",
}

// Scan runs `semgrep scan --json --quiet <target>` and returns the
// normalised result. The JSON report is written to stdout; exit 0 is
// success. A non-zero exit with a valid, error-free report is still
// returned (the real ExitCode is recorded); a missing or invalid report is
// an error, as is a report carrying top-level errors (fatal scan failures
// such as an invalid target or broken rules). Only mode "fs" is supported
// (image scanning is trivy-only).
func (r *SemgrepRunner) Scan(ctx context.Context, mode, target string) (*Result, error) {
	if mode != "fs" {
		return nil, fmt.Errorf("security: semgrep only supports scan mode \"fs\" (got %q)", mode)
	}
	if target == "" {
		return nil, errors.New("security: scan target must not be empty")
	}

	bin, err := r.findSemgrepBin()
	if err != nil {
		return nil, err
	}

	timeout := r.cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	sctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(sctx, bin, "scan", "--json", "--quiet", target)
	groupKill(cmd)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	var exitCode int
	switch {
	case runErr == nil:
		exitCode = 0
	case errors.Is(sctx.Err(), context.DeadlineExceeded):
		return nil, fmt.Errorf("security: semgrep fs scan timed out after %s", timeout)
	case sctx.Err() != nil:
		return nil, fmt.Errorf("security: semgrep fs scan canceled: %w", sctx.Err())
	default:
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			exitCode = ee.ExitCode()
		} else {
			return nil, fmt.Errorf("security: failed to start semgrep: %w", runErr)
		}
	}

	rep, perr := parseSemgrepReport(stdout.Bytes())
	if perr != nil {
		return nil, fmt.Errorf("security: semgrep fs scan failed (exit %d): %s", exitCode, tail(stderr.String(), 512))
	}
	if len(rep.Errors) > 0 {
		// A non-empty top-level errors array means the scan itself failed
		// (e.g. invalid target, rule parse error). Storing the empty results
		// would record a false "clean" scan, so fail instead.
		msg := rep.Errors[0].Message
		if msg == "" {
			msg = tail(stderr.String(), 512)
		}
		return nil, fmt.Errorf("security: semgrep fs scan reported errors (exit %d): %s", exitCode, msg)
	}

	raw := stdout.String()
	truncated := false
	if len(raw) > MaxRawJSON {
		raw = raw[:MaxRawJSON]
		truncated = true
	}
	return &Result{
		Tool:          SemgrepTool,
		Target:        target,
		Mode:          mode,
		ExitCode:      exitCode,
		FindingsCount: rep.findingsCount(),
		Severity:      rep.severityCounts(),
		RawJSON:       raw,
		Truncated:     truncated,
	}, nil
}

// semgrepReport mirrors the subset of semgrep's JSON output consumed here.
type semgrepReport struct {
	Results []struct {
		Extra struct {
			Severity string `json:"severity"`
		} `json:"extra"`
	} `json:"results"`
	// Errors carries fatal scan-level errors (invalid target, broken rules).
	// Presence of any entry means the run failed and is an error here.
	Errors []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
}

// parseSemgrepReport decodes a semgrep JSON report. Any structural JSON error
// is returned; absent optional fields stay zero-valued.
func parseSemgrepReport(data []byte) (*semgrepReport, error) {
	var rep semgrepReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, fmt.Errorf("parse semgrep report: %w", err)
	}
	return &rep, nil
}

// findingsCount returns the number of semgrep findings.
func (r *semgrepReport) findingsCount() int {
	return len(r.Results)
}

// severityCounts tallies findings into FlowStallion buckets via the
// ERROR->HIGH / WARNING->MEDIUM / INFO->LOW mapping; only non-zero buckets
// are kept. Unrecognised severities are counted in FindingsCount but in no
// bucket.
func (r *semgrepReport) severityCounts() map[string]int {
	out := map[string]int{}
	for _, res := range r.Results {
		if b, ok := semgrepSeverity[res.Extra.Severity]; ok {
			out[b]++
		}
	}
	return out
}
