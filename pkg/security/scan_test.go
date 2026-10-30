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

// writeFakeTrivy writes an executable shell script to t.TempDir() and
// returns its path. The script is the "trivy binary" under test.
func writeFakeTrivy(t *testing.T, script string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "trivy")
	full := "#!/bin/sh\n" + script + "\n"
	if err := os.WriteFile(p, []byte(full), 0o755); err != nil {
		t.Fatalf("write fake trivy: %v", err)
	}
	return p
}

// writePayload writes s to a temp file and returns its path, for fakes that
// cat a payload file as their report.
func writePayload(t *testing.T, s string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "payload.json")
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	return p
}

const sampleReport = `{
  "SchemaVersion": 2,
  "ReportID": "p5-test-report",
  "CreatedAt": "2026-10-23T10:00:00Z",
  "Trivy": { "Version": "0.76.1" },
  "Results": [
    {
      "Target": "/repo",
      "Vulnerabilities": [
        { "Severity": "CRITICAL" },
        { "Severity": "HIGH" },
        { "Severity": "HIGH" },
        { "Severity": "MEDIUM" },
        { "Severity": "LOW" },
        { "Severity": "UNKNOWN" }
      ]
    },
    { "Target": "sub", "Vulnerabilities": [] }
  ]
}`

const zeroReport = `{
  "SchemaVersion": 2,
  "ReportID": "zero-1",
  "CreatedAt": "2026-10-23T11:00:00Z",
  "Trivy": { "Version": "0.76.1" },
  "Results": [ { "Target": "/repo", "Vulnerabilities": [] } ]
}`

// TestTrivyRunnerScan is the table-driven contract for TrivyRunner.Scan.
// The fake trivy is a shell script; no real trivy is required.
func TestTrivyRunnerScan(t *testing.T) {
	tests := []struct {
		name          string
		script        string // shell body of the fake trivy; "" for the missing-binary case
		payload       string // report the fake emits (written to $PH_FAKE_PAYLOAD and cat'ed)
		binOverride   string // non-empty -> use this (non-existent) path instead of a fake
		mode          string
		target        string
		recordArgs    bool
		wantErr       bool
		wantErrIs     error
		wantErrSubstr string
		wantExit      int
		wantFindings  int
		wantSeverity  map[string]int
		wantReportID  string
		wantVersion   string
		wantCreated   string
		wantTruncated bool
		wantRaw       string
		wantRawLen    int
	}{
		{
			name:         "fs normal report",
			script:       `cat "$PH_FAKE_PAYLOAD"`,
			payload:      sampleReport,
			mode:         "fs",
			target:       "/tmp/repo",
			wantExit:     0,
			wantFindings: 6,
			wantSeverity: map[string]int{"CRITICAL": 1, "HIGH": 2, "MEDIUM": 1, "LOW": 1, "UNKNOWN": 1},
			wantReportID: "p5-test-report",
			wantVersion:  "0.76.1",
			wantCreated:  "2026-10-23T10:00:00Z",
			wantRaw:      sampleReport,
		},
		{
			name:         "image mode passes image to trivy",
			script:       `echo "$@" > "$PH_FAKE_ARGS"; cat "$PH_FAKE_PAYLOAD"`,
			payload:      zeroReport,
			mode:         "image",
			target:       "nginx:1.25",
			recordArgs:   true,
			wantExit:     0,
			wantFindings: 0,
			wantSeverity: map[string]int{},
			wantReportID: "zero-1",
		},
		{
			name:         "zero vulnerabilities",
			script:       `cat "$PH_FAKE_PAYLOAD"`,
			payload:      zeroReport,
			mode:         "fs",
			target:       "/tmp/repo",
			wantExit:     0,
			wantFindings: 0,
			wantSeverity: map[string]int{},
			wantReportID: "zero-1",
		},
		{
			name:          "malformed json is an error",
			script:        `echo 'this is not json'`,
			mode:          "fs",
			target:        "/tmp/repo",
			wantErr:       true,
			wantErrSubstr: "trivy fs scan failed (exit 0)",
		},
		{
			name:         "nonzero exit with valid json",
			script:       `cat "$PH_FAKE_PAYLOAD"; exit 1`,
			payload:      zeroReport,
			mode:         "fs",
			target:       "/tmp/repo",
			wantExit:     1,
			wantFindings: 0,
			wantSeverity: map[string]int{},
			wantReportID: "zero-1",
		},
		{
			name:          "trivy missing via env",
			binOverride:   "/nonexistent/path/to/trivy",
			mode:          "fs",
			target:        "/tmp/repo",
			wantErr:       true,
			wantErrIs:     ErrTrivyNotFound,
			wantErrSubstr: "trivy binary not found",
		},
		{
			name:          "invalid mode",
			mode:          "fsx",
			target:        "/tmp/repo",
			wantErr:       true,
			wantErrSubstr: "unsupported scan mode",
		},
		{
			name:          "empty target",
			mode:          "fs",
			target:        "",
			wantErr:       true,
			wantErrSubstr: "target must not be empty",
		},
		{
			name:          "raw json truncated at 1MiB",
			script:        `cat "$PH_FAKE_PAYLOAD"`,
			payload:       `{"SchemaVersion":2,"Results":[],"padding":"` + strings.Repeat("a", MaxRawJSON+100) + `"}`,
			mode:          "fs",
			target:        "/tmp/repo",
			wantExit:      0,
			wantFindings:  0,
			wantSeverity:  map[string]int{},
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
				bin = writeFakeTrivy(t, tt.script)
				t.Setenv("FLOWSTALLION_TRIVY_BIN", bin)
			}

			r := NewTrivyRunner(TrivyConfig{BinPath: bin})
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
			if res.Tool != "trivy" {
				t.Errorf("Tool = %q, want %q", res.Tool, "trivy")
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
			if tt.wantReportID != "" && res.ReportID != tt.wantReportID {
				t.Errorf("ReportID = %q, want %q", res.ReportID, tt.wantReportID)
			}
			if tt.wantVersion != "" && res.TrivyVersion != tt.wantVersion {
				t.Errorf("TrivyVersion = %q, want %q", res.TrivyVersion, tt.wantVersion)
			}
			if tt.wantCreated != "" && res.CreatedAt != tt.wantCreated {
				t.Errorf("CreatedAt = %q, want %q", res.CreatedAt, tt.wantCreated)
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
				want := []string{tt.mode, "--format", "json", "--quiet", tt.target}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("trivy args = %v, want %v", got, want)
				}
			}
		})
	}
}

// TestTrivyRunnerTimeout verifies the scan is aborted when the runner timeout
// expires. The fake sleeps 1s: far longer than the 100ms timeout (so the
// deadline always fires while the process is alive) but short enough that
// even a slow group-kill/reap under load stays well inside the 3s guard.
func TestTrivyRunnerTimeout(t *testing.T) {
	bin := writeFakeTrivy(t, "sleep 1")
	t.Setenv("FLOWSTALLION_TRIVY_BIN", bin)
	r := NewTrivyRunner(TrivyConfig{Timeout: 100 * time.Millisecond})
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
