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

const sgFindings = `{
  "results": [
    { "path": "a.py", "extra": { "severity": "ERROR", "rule_id": "r1" } },
    { "path": "b.py", "extra": { "severity": "WARNING", "rule_id": "r2" } },
    { "path": "c.py", "extra": { "severity": "INFO", "rule_id": "r3" } },
    { "path": "d.py", "extra": { "severity": "BOGUS", "rule_id": "r4" } }
  ]
}`

const sgClean = `{ "results": [] }`

// TestSemgrepRunnerScan is the table-driven contract for SemgrepRunner.Scan.
// The fake semgrep is a shell script; no real semgrep is required.
func TestSemgrepRunnerScan(t *testing.T) {
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
			name:         "fs normal report maps severities",
			script:       `cat "$PH_FAKE_PAYLOAD"`,
			payload:      sgFindings,
			mode:         "fs",
			target:       "/tmp/repo",
			wantExit:     0,
			wantFindings: 4,
			// BOGUS is counted in FindingsCount but in no bucket.
			wantSeverity: map[string]int{"HIGH": 1, "MEDIUM": 1, "LOW": 1},
			wantRaw:      sgFindings,
		},
		{
			name:         "zero results",
			script:       `cat "$PH_FAKE_PAYLOAD"`,
			payload:      sgClean,
			mode:         "fs",
			target:       "/tmp/repo",
			wantExit:     0,
			wantFindings: 0,
			wantSeverity: map[string]int{},
			wantRaw:      sgClean,
		},
		{
			name:         "nonzero exit with valid json still returns result",
			script:       `cat "$PH_FAKE_PAYLOAD"; exit 1`,
			payload:      sgFindings,
			mode:         "fs",
			target:       "/tmp/repo",
			wantExit:     1,
			wantFindings: 4,
			wantSeverity: map[string]int{"HIGH": 1, "MEDIUM": 1, "LOW": 1},
		},
		{
			// A report carrying top-level errors is a failed scan (e.g.
			// invalid target), never a "clean, 0 findings" result.
			name:          "fatal scan error in report is an error",
			script:        `cat "$PH_FAKE_PAYLOAD"; exit 2`,
			payload:       `{"results":[],"errors":[{"code":2,"message":"Invalid scanning root: /nonexistent"}]}`,
			mode:          "fs",
			target:        "/nonexistent",
			wantErr:       true,
			wantErrSubstr: "semgrep fs scan reported errors (exit 2)",
		},
		{
			name:          "malformed json is an error",
			script:        `echo 'this is not json'`,
			mode:          "fs",
			target:        "/tmp/repo",
			wantErr:       true,
			wantErrSubstr: "semgrep fs scan failed (exit 0)",
		},
		{
			name:          "exit 2 with invalid report is an error",
			script:        `echo 'semgrep: fatal'; exit 2`,
			mode:          "fs",
			target:        "/tmp/repo",
			wantErr:       true,
			wantErrSubstr: "semgrep fs scan failed (exit 2)",
		},
		{
			name:          "semgrep missing via env",
			binOverride:   "/nonexistent/path/to/semgrep",
			mode:          "fs",
			target:        "/tmp/repo",
			wantErr:       true,
			wantErrIs:     ErrSemgrepNotFound,
			wantErrSubstr: "semgrep binary not found",
		},
		{
			name:          "image mode rejected",
			mode:          "image",
			target:        "nginx:1.25",
			wantErr:       true,
			wantErrSubstr: `semgrep only supports scan mode "fs"`,
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
			script:       `echo "$@" > "$PH_FAKE_ARGS"; echo '{ "results": [] }'`,
			mode:         "fs",
			target:       "/tmp/repo",
			recordArgs:   true,
			wantFindings: 0,
		},
		{
			name:          "raw json truncated at 1MiB",
			script:        `cat "$PH_FAKE_PAYLOAD"`,
			payload:       `{"results":[],"padding":"` + strings.Repeat("a", MaxRawJSON+100) + `"}`,
			mode:          "fs",
			target:        "/tmp/repo",
			wantExit:      0,
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

			r := NewSemgrepRunner(SemgrepConfig{BinPath: bin})
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
			if res.Tool != "semgrep" {
				t.Errorf("Tool = %q, want %q", res.Tool, "semgrep")
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
				want := []string{"scan", "--json", "--quiet", tt.target}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("semgrep args = %v, want %v", got, want)
				}
			}
		})
	}
}

// TestSemgrepRunnerTimeout verifies the scan is aborted when the runner
// timeout expires. The fake sleeps 1s: far longer than the 100ms timeout but
// short enough that a slow kill/reap under load stays inside the 3s guard.
func TestSemgrepRunnerTimeout(t *testing.T) {
	bin := writeFakeBin(t, "sleep 1")
	r := NewSemgrepRunner(SemgrepConfig{BinPath: bin, Timeout: 100 * time.Millisecond})
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
