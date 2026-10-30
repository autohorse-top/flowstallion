package security

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// writeFakeBin writes an executable shell script (the fake scanner binary) to
// t.TempDir() and returns its path. The filename is irrelevant; the runner is
// pointed at it via BinPath.
func writeFakeBin(t *testing.T, script string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fakebin")
	full := "#!/bin/sh\n" + script + "\n"
	if err := os.WriteFile(p, []byte(full), 0o755); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}
	return p
}

// const glFindings is a minimal gitleaks JSON report (top-level array).
const glFindings = `[
  { "RuleID": "aws-access-token", "File": "main.go", "Secret": "AKIAFAKE" },
  { "RuleID": "github-token", "File": "setup.sh", "Secret": "ghp_xxxx" }
]`

// glClean is an empty gitleaks report.
const glClean = `[]`

// TestGitleaksRunnerScan is the table-driven contract for GitleaksRunner.Scan.
// The fake gitleaks is a shell script; no real gitleaks is required.
func TestGitleaksRunnerScan(t *testing.T) {
	tests := []struct {
		name          string
		script        string
		payload       string
		binOverride   string
		mode          string
		target        string
		recordArgs    bool
		wantErr       bool
		wantErrIs     error
		wantErrSubstr string
		wantExit      int
		wantFindings  int
		wantSeverity  map[string]int
		wantTruncated bool
		wantRaw       string
		wantRawLen    int
	}{
		{
			// gitleaks exits 1 when findings exist; that is success.
			name:         "fs findings report, exit 1 is success",
			script:       `gp=""; prev=""; for a in "$@"; do [ "$prev" = "--report-path" ] && gp="$a"; prev="$a"; done; cat "$PH_FAKE_PAYLOAD" > "$gp"; exit 1`,
			payload:      glFindings,
			mode:         "fs",
			target:       "/tmp/repo",
			wantExit:     1,
			wantFindings: 2,
			wantSeverity: map[string]int{},
			wantRaw:      glFindings,
		},
		{
			name:         "fs clean report, exit 0",
			script:       `gp=""; prev=""; for a in "$@"; do [ "$prev" = "--report-path" ] && gp="$a"; prev="$a"; done; cat "$PH_FAKE_PAYLOAD" > "$gp"`,
			payload:      glClean,
			mode:         "fs",
			target:       "/tmp/repo",
			wantExit:     0,
			wantFindings: 0,
			wantSeverity: map[string]int{},
			wantRaw:      glClean,
		},
		{
			name:          "exit 2 is an error",
			script:        `exit 2`,
			mode:          "fs",
			target:        "/tmp/repo",
			wantErr:       true,
			wantErrSubstr: "gitleaks fs scan failed (exit 2)",
		},
		{
			name:          "missing report file is an error",
			script:        `exit 1`,
			mode:          "fs",
			target:        "/tmp/repo",
			wantErr:       true,
			wantErrSubstr: "produced no report file",
		},
		{
			name:         "empty report file normalises to zero findings",
			script:       `gp=""; prev=""; for a in "$@"; do [ "$prev" = "--report-path" ] && gp="$a"; prev="$a"; done; : > "$gp"`,
			mode:         "fs",
			target:       "/tmp/repo",
			wantExit:     0,
			wantFindings: 0,
			wantSeverity: map[string]int{},
			wantRaw:      "[]",
		},
		{
			name:          "malformed json report is an error",
			script:        `gp=""; prev=""; for a in "$@"; do [ "$prev" = "--report-path" ] && gp="$a"; prev="$a"; done; echo 'this is not json' > "$gp"; exit 1`,
			mode:          "fs",
			target:        "/tmp/repo",
			wantErr:       true,
			wantErrSubstr: "parse gitleaks report",
		},
		{
			name:          "gitleaks missing via env",
			binOverride:   "/nonexistent/path/to/gitleaks",
			mode:          "fs",
			target:        "/tmp/repo",
			wantErr:       true,
			wantErrIs:     ErrGitleaksNotFound,
			wantErrSubstr: "gitleaks binary not found",
		},
		{
			name:          "image mode rejected",
			mode:          "image",
			target:        "nginx:1.25",
			wantErr:       true,
			wantErrSubstr: `gitleaks only supports scan mode "fs"`,
		},
		{
			name:          "empty target",
			mode:          "fs",
			target:        "",
			wantErr:       true,
			wantErrSubstr: "target must not be empty",
		},
		{
			name:         "args recorded",
			script:       `echo "$@" > "$PH_FAKE_ARGS"; gp=""; prev=""; for a in "$@"; do [ "$prev" = "--report-path" ] && gp="$a"; prev="$a"; done; echo '[]' > "$gp"`,
			mode:         "fs",
			target:       "/tmp/repo",
			recordArgs:   true,
			wantFindings: 0,
		},
		{
			name:          "raw json truncated at 1MiB",
			script:        `gp=""; prev=""; for a in "$@"; do [ "$prev" = "--report-path" ] && gp="$a"; prev="$a"; done; cat "$PH_FAKE_PAYLOAD" > "$gp"`,
			payload:       `["` + strings.Repeat("a", MaxRawJSON+100) + `"]`,
			mode:          "fs",
			target:        "/tmp/repo",
			wantExit:      0,
			wantFindings:  1,
			wantTruncated: true,
			wantRawLen:    MaxRawJSON,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.payload != "" {
				t.Setenv("PH_FAKE_PAYLOAD", writePayload(t, tt.payload))
			}
			if tt.recordArgs {
				t.Setenv("PH_FAKE_ARGS", filepath.Join(t.TempDir(), "args.txt"))
			}

			var bin string
			if tt.binOverride != "" {
				bin = tt.binOverride
			} else {
				bin = writeFakeBin(t, tt.script)
			}

			r := NewGitleaksRunner(GitleaksConfig{BinPath: bin})
			res, err := r.Scan(context.Background(), tt.mode, tt.target)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("want error, got result %+v", res)
				}
				if tt.wantErrIs != nil && !errors.Is(err, tt.wantErrIs) {
					t.Errorf("error = %v, want errors.Is %v", err, tt.wantErrIs)
				}
				if tt.wantErrSubstr != "" && !strings.Contains(err.Error(), tt.wantErrSubstr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErrSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.Tool != "gitleaks" {
				t.Errorf("Tool = %q, want %q", res.Tool, "gitleaks")
			}
			if res.Mode != tt.mode {
				t.Errorf("Mode = %q, want %q", res.Mode, tt.mode)
			}
			if res.Target != tt.target {
				t.Errorf("Target = %q, want %q", res.Target, tt.target)
			}
			if res.ExitCode != tt.wantExit {
				t.Errorf("ExitCode = %d, want %d", res.ExitCode, tt.wantExit)
			}
			if res.FindingsCount != tt.wantFindings {
				t.Errorf("FindingsCount = %d, want %d", res.FindingsCount, tt.wantFindings)
			}
			if tt.wantSeverity != nil && !reflect.DeepEqual(res.Severity, tt.wantSeverity) {
				t.Errorf("Severity = %v, want %v", res.Severity, tt.wantSeverity)
			}
			if tt.wantRaw != "" && res.RawJSON != tt.wantRaw {
				t.Errorf("RawJSON = %q, want %q", res.RawJSON, tt.wantRaw)
			}
			if tt.wantRawLen > 0 && len(res.RawJSON) != tt.wantRawLen {
				t.Errorf("len(RawJSON) = %d, want %d", len(res.RawJSON), tt.wantRawLen)
			}
			if tt.wantTruncated != res.Truncated {
				t.Errorf("Truncated = %v, want %v", res.Truncated, tt.wantTruncated)
			}

			if tt.recordArgs {
				data, rerr := os.ReadFile(os.Getenv("PH_FAKE_ARGS"))
				if rerr != nil {
					t.Fatalf("read args file: %v", rerr)
				}
				got := strings.Fields(string(data))
				wantPrefix := []string{"detect", "--no-banner", "--report-path"}
				if len(got) != 8 {
					t.Fatalf("got %d args, want 8: %v", len(got), got)
				}
				for i, w := range wantPrefix {
					if got[i] != w {
						t.Errorf("arg[%d] = %q, want %q", i, got[i], w)
					}
				}
				if got[3] == "" {
					t.Errorf("arg[3] = %q, want <tmp report path>", got[3])
				}
				if got[4] != "--report-format" || got[5] != "json" {
					t.Errorf("arg[4..5] = %q %q, want --report-format json", got[4], got[5])
				}
				if got[6] != "--source" {
					t.Errorf("arg[6] = %q, want --source (target flag)", got[6])
				}
			}
		})
	}
}

// TestGitleaksRunnerTimeout verifies the scan is aborted when the runner
// timeout expires. The fake sleeps 1s: far longer than the 100ms timeout but
// short enough that a slow kill/reap under load stays inside the 3s guard.
func TestGitleaksRunnerTimeout(t *testing.T) {
	bin := writeFakeBin(t, "sleep 1")
	r := NewGitleaksRunner(GitleaksConfig{BinPath: bin, Timeout: 100 * time.Millisecond})
	start := time.Now()
	_, err := r.Scan(context.Background(), "fs", "/tmp/x")
	if err == nil {
		t.Fatal("want timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("error = %q, want timeout", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("Scan took %v, expected to abort early", time.Since(start))
	}
}
