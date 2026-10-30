// Package security provides security scanning for FlowStallion runs.
//
// P5 ships a trivy-backed scanner; P6 adds gitleaks (secrets) and semgrep
// (SAST). Every runner shells out to an external CLI (located via a
// FLOWSTALLION_*_BIN env var or PATH), parses the JSON report, and normalises
// it into the common Result fields that are stored and served by the API.
// TrivyResult adds trivy-specific report metadata on top of Result.
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

// ToolName is the fixed tool identifier for trivy results.
const ToolName = "trivy"

// DefaultTimeout bounds a single trivy invocation when the caller does not
// supply its own timeout.
const DefaultTimeout = 10 * time.Minute

// MaxRawJSON is the cap (in bytes) for the stored raw trivy report.
const MaxRawJSON = 1 << 20

// ErrTrivyNotFound is returned when the trivy binary cannot be located.
var ErrTrivyNotFound = errors.New("trivy binary not found (set FLOWSTALLION_TRIVY_BIN or install trivy, e.g. brew install trivy)")

// severityLevels are the trivy severity buckets we count. Only keys with a
// non-zero count are kept in TrivyResult.Severity.
var severityLevels = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}

// Result is the tool-agnostic, normalised outcome of a security scan. It
// carries exactly the fields the scheduler persists (see store.RunScan and
// the API scanJSON wire type); tool-specific result types embed it and add
// report metadata that is not stored as its own column.
type Result struct {
	Tool          string         `json:"tool"`
	Target        string         `json:"target"`
	Mode          string         `json:"mode"` // "fs" | "image"
	ExitCode      int            `json:"exit_code"`
	FindingsCount int            `json:"findings_count"`
	Severity      map[string]int `json:"severity"`
	RawJSON       string         `json:"raw_json"`
	Truncated     bool           `json:"truncated"`
}

// TrivyResult is the normalised outcome of one trivy scan: the common
// persisted fields (embedded Result) plus trivy report metadata.
type TrivyResult struct {
	Result
	ReportID     string `json:"report_id"`
	CreatedAt    string `json:"created_at"`
	TrivyVersion string `json:"trivy_version"`
}

// TrivyScanner is the trivy-specific runner contract (returns *TrivyResult,
// which embeds the common Result). GitleaksRunner/SemgrepRunner are
// tool-specific concrete runners that return the common *Result directly and
// do not implement this interface. Implementations must honour ctx
// cancellation and must not panic on bad input.
type TrivyScanner interface {
	Scan(ctx context.Context, mode, target string) (*TrivyResult, error)
}

// TrivyConfig configures a TrivyRunner.
type TrivyConfig struct {
	// BinPath, when non-empty, takes priority over FLOWSTALLION_TRIVY_BIN and
	// PATH lookup. It is intended for explicit programmatic configuration.
	BinPath string
	// Timeout bounds a single trivy run; values <= 0 use DefaultTimeout.
	Timeout time.Duration
}

// TrivyRunner runs the trivy CLI and normalises its JSON report.
type TrivyRunner struct {
	cfg TrivyConfig
}

var _ TrivyScanner = (*TrivyRunner)(nil)

// NewTrivyRunner builds a TrivyRunner from cfg. A zero value is valid and
// yields the defaults (env/PATH lookup, DefaultTimeout).
func NewTrivyRunner(cfg TrivyConfig) *TrivyRunner {
	return &TrivyRunner{cfg: cfg}
}

// findTrivyBin resolves the trivy binary:
//  1. explicit cfg.BinPath, when set;
//  2. the FLOWSTALLION_TRIVY_BIN environment variable, when non-empty;
//  3. exec.LookPath("trivy").
//
// A configured path that is missing or not executable is treated as "not
// found" so callers get one stable error to handle.
func (r *TrivyRunner) findTrivyBin() (string, error) {
	if r.cfg.BinPath != "" {
		if isExecutable(r.cfg.BinPath) {
			return r.cfg.BinPath, nil
		}
		return "", fmt.Errorf("%w: configured path %q is missing or not executable", ErrTrivyNotFound, r.cfg.BinPath)
	}
	if env := os.Getenv("FLOWSTALLION_TRIVY_BIN"); env != "" {
		if isExecutable(env) {
			return env, nil
		}
		return "", fmt.Errorf("%w: FLOWSTALLION_TRIVY_BIN=%q is missing or not executable", ErrTrivyNotFound, env)
	}
	p, err := exec.LookPath("trivy")
	if err != nil {
		return "", ErrTrivyNotFound
	}
	return p, nil
}

// isExecutable reports whether p exists, is a regular file, and has any
// execute bit set.
func isExecutable(p string) bool {
	fi, err := os.Stat(p)
	if err != nil || fi.IsDir() {
		return false
	}
	return fi.Mode().Perm()&0o111 != 0
}

// Scan runs `trivy <mode> --format json --quiet <target>` and returns the
// normalised result.
//
// trivy sometimes exits non-zero while still printing a valid report on
// stdout (for example when it finds critical vulnerabilities). In that case
// Scan returns the result with the real ExitCode recorded. An error is
// returned when the binary is missing, the run is canceled/times out, the
// process cannot be started, or the stdout payload is not a JSON report;
// parse/execution errors carry the last 512 characters of stderr.
func (r *TrivyRunner) Scan(ctx context.Context, mode, target string) (*TrivyResult, error) {
	switch mode {
	case "fs", "image":
	default:
		return nil, fmt.Errorf("security: unsupported scan mode %q (want \"fs\" or \"image\")", mode)
	}
	if target == "" {
		return nil, errors.New("security: scan target must not be empty")
	}

	bin, err := r.findTrivyBin()
	if err != nil {
		return nil, err
	}

	timeout := r.cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	sctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(sctx, bin, mode, "--format", "json", "--quiet", target)
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
		return nil, fmt.Errorf("security: trivy %s scan timed out after %s", mode, timeout)
	case sctx.Err() != nil:
		return nil, fmt.Errorf("security: trivy %s scan canceled: %w", mode, sctx.Err())
	default:
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			exitCode = ee.ExitCode()
		} else {
			return nil, fmt.Errorf("security: failed to start trivy %s: %w", mode, runErr)
		}
	}

	rep, perr := parseTrivyReport(stdout.Bytes())
	if perr != nil {
		return nil, fmt.Errorf("security: trivy %s scan failed (exit %d): %s", mode, exitCode, tail(stderr.String(), 512))
	}

	raw := stdout.String()
	truncated := false
	if len(raw) > MaxRawJSON {
		raw = raw[:MaxRawJSON]
		truncated = true
	}

	return &TrivyResult{
		Result: Result{
			Tool:          ToolName,
			Target:        target,
			Mode:          mode,
			ExitCode:      exitCode,
			FindingsCount: rep.findingsCount(),
			Severity:      rep.severityCounts(),
			RawJSON:       raw,
			Truncated:     truncated,
		},
		ReportID:     rep.ReportID,
		CreatedAt:    rep.CreatedAt,
		TrivyVersion: rep.Trivy.Version,
	}, nil
}

// tail returns the last n characters of s (or s when it is shorter).
func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

// trivyReport mirrors the subset of trivy's JSON report (SchemaVersion 2)
// that FlowStallion consumes. Fields are tolerated when missing; a
// non-string/missing Severity entry is skipped rather than an error.
type trivyReport struct {
	SchemaVersion int    `json:"SchemaVersion"`
	ReportID      string `json:"ReportID"`
	CreatedAt     string `json:"CreatedAt"`
	Trivy         struct {
		Version string `json:"Version"`
	} `json:"Trivy"`
	Results []struct {
		ArtifactName    string `json:"ArtifactName"`
		Vulnerabilities []struct {
			Severity json.RawMessage `json:"Severity"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

// parseTrivyReport decodes a trivy JSON report. Any structural JSON error is
// returned; absent optional fields stay zero-valued.
func parseTrivyReport(data []byte) (*trivyReport, error) {
	var rep trivyReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, fmt.Errorf("parse trivy report: %w", err)
	}
	return &rep, nil
}

// findingsCount counts every vulnerability entry across all results,
// regardless of whether its severity is recognised.
func (r *trivyReport) findingsCount() int {
	n := 0
	for _, res := range r.Results {
		n += len(res.Vulnerabilities)
	}
	return n
}

// severityCounts tallies findings per known severity level and returns only
// the non-zero buckets. Unrecognised or malformed severities are skipped.
func (r *trivyReport) severityCounts() map[string]int {
	out := make(map[string]int, len(severityLevels))
	for _, res := range r.Results {
		for _, v := range res.Vulnerabilities {
			var sev string
			if err := json.Unmarshal(v.Severity, &sev); err != nil {
				continue
			}
			if isValidSeverity(sev) {
				out[sev]++
			}
		}
	}
	return out
}

// isValidSeverity reports whether s is one of trivy's severity levels.
func isValidSeverity(s string) bool {
	for _, k := range severityLevels {
		if s == k {
			return true
		}
	}
	return false
}
