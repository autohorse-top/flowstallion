// P6③: gitleaks runner — secrets scanning for local repositories (fs mode).
//
// Follows the TrivyRunner pattern: external binary located via
// FLOWSTALLION_GITLEAKS_BIN or PATH, JSON report, normalised into the common
// Result. gitleaks has no severity concept, so Result.Severity is always an
// empty map ({}).
package security

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// GitleaksTool and SemgrepTool are the tool identifiers stored on scan rows
// for the P6③ multi-tool scanners.
const (
	GitleaksTool = "gitleaks"
	SemgrepTool  = "semgrep"
)

// ErrGitleaksNotFound is returned when the gitleaks binary cannot be located.
var ErrGitleaksNotFound = errors.New("gitleaks binary not found (set FLOWSTALLION_GITLEAKS_BIN or install gitleaks, e.g. brew install gitleaks)")

// GitleaksConfig configures a GitleaksRunner.
type GitleaksConfig struct {
	// BinPath, when non-empty, takes priority over FLOWSTALLION_GITLEAKS_BIN
	// and PATH lookup. It is intended for explicit programmatic configuration.
	BinPath string
	// Timeout bounds a single gitleaks run; values <= 0 use DefaultTimeout.
	Timeout time.Duration
}

// GitleaksRunner runs the gitleaks CLI in fs mode and normalises its JSON
// findings report into the common Result.
type GitleaksRunner struct {
	cfg GitleaksConfig
}

// NewGitleaksRunner builds a GitleaksRunner from cfg. A zero value is valid
// and yields the defaults (env/PATH lookup, DefaultTimeout).
func NewGitleaksRunner(cfg GitleaksConfig) *GitleaksRunner {
	return &GitleaksRunner{cfg: cfg}
}

// findGitleaksBin resolves the gitleaks binary:
//  1. explicit cfg.BinPath, when set;
//  2. the FLOWSTALLION_GITLEAKS_BIN environment variable, when non-empty;
//  3. exec.LookPath("gitleaks").
//
// A configured path that is missing or not executable is treated as "not
// found" so callers get one stable error to handle.
func (r *GitleaksRunner) findGitleaksBin() (string, error) {
	if r.cfg.BinPath != "" {
		if isExecutable(r.cfg.BinPath) {
			return r.cfg.BinPath, nil
		}
		return "", fmt.Errorf("%w: configured path %q is missing or not executable", ErrGitleaksNotFound, r.cfg.BinPath)
	}
	if env := os.Getenv("FLOWSTALLION_GITLEAKS_BIN"); env != "" {
		if isExecutable(env) {
			return env, nil
		}
		return "", fmt.Errorf("%w: FLOWSTALLION_GITLEAKS_BIN=%q is missing or not executable", ErrGitleaksNotFound, env)
	}
	p, err := exec.LookPath("gitleaks")
	if err != nil {
		return "", ErrGitleaksNotFound
	}
	return p, nil
}

// Scan runs
//
//	gitleaks detect --no-banner --report-path <tmp> --report-format json --source <target>
//
// and returns the normalised result. gitleaks exits 0 when clean and 1 when
// findings are reported; both are success. Any other exit code, a missing
// report file, or a malformed report is an error. Only mode "fs" is
// supported (image scanning is trivy-only).
func (r *GitleaksRunner) Scan(ctx context.Context, mode, target string) (*Result, error) {
	if mode != "fs" {
		return nil, fmt.Errorf("security: gitleaks only supports scan mode \"fs\" (got %q)", mode)
	}
	if target == "" {
		return nil, errors.New("security: scan target must not be empty")
	}

	bin, err := r.findGitleaksBin()
	if err != nil {
		return nil, err
	}

	timeout := r.cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	sctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// The report path is handed to gitleaks; it creates the file itself.
	// We deliberately do NOT pre-create it, so an absent file after the run
	// means gitleaks produced no report (a real error).
	reportPath := filepath.Join(os.TempDir(), fmt.Sprintf("flowstallion-gitleaks-%d.json", time.Now().UnixNano()))
	defer os.Remove(reportPath)

	cmd := exec.CommandContext(sctx, bin, "detect", "--no-banner",
		"--report-path", reportPath, "--report-format", "json", "--source", target)
	groupKill(cmd)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	var exitCode int
	switch {
	case runErr == nil:
		exitCode = 0
	case errors.Is(sctx.Err(), context.DeadlineExceeded):
		return nil, fmt.Errorf("security: gitleaks fs scan timed out after %s", timeout)
	case sctx.Err() != nil:
		return nil, fmt.Errorf("security: gitleaks fs scan canceled: %w", sctx.Err())
	default:
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			exitCode = ee.ExitCode()
		} else {
			return nil, fmt.Errorf("security: failed to start gitleaks: %w", runErr)
		}
	}
	if exitCode != 0 && exitCode != 1 {
		return nil, fmt.Errorf("security: gitleaks fs scan failed (exit %d): %s", exitCode, tail(stderr.String(), 512))
	}

	data, err := os.ReadFile(reportPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("security: gitleaks produced no report file (exit %d): %s", exitCode, tail(stderr.String(), 512))
		}
		return nil, fmt.Errorf("security: read gitleaks report: %w", err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		// An empty report file is normalised to an empty findings array.
		data = []byte("[]")
	}
	findings, perr := parseGitleaksFindings(data)
	if perr != nil {
		return nil, fmt.Errorf("security: gitleaks fs scan failed (exit %d): %v", exitCode, perr)
	}

	raw := string(data)
	truncated := false
	if len(raw) > MaxRawJSON {
		raw = raw[:MaxRawJSON]
		truncated = true
	}
	return &Result{
		Tool:          GitleaksTool,
		Target:        target,
		Mode:          mode,
		ExitCode:      exitCode,
		FindingsCount: findings,
		Severity:      map[string]int{}, // gitleaks has no severity buckets
		RawJSON:       raw,
		Truncated:     truncated,
	}, nil
}

// parseGitleaksFindings decodes a gitleaks JSON report (a top-level array of
// finding objects) and returns the number of findings.
func parseGitleaksFindings(data []byte) (int, error) {
	var findings []json.RawMessage
	if err := json.Unmarshal(data, &findings); err != nil {
		return 0, fmt.Errorf("parse gitleaks report: %w", err)
	}
	return len(findings), nil
}
