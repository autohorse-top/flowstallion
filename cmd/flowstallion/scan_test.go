package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/flowstallion/flowstallion/pkg/security"
)

// TestResolveScanTarget table-checks the (tool, --repo, --image) matrix.
func TestResolveScanTarget(t *testing.T) {
	tests := []struct {
		name    string
		tool    string
		repo    string
		image   string
		mode    string
		target  string
		wantErr bool
	}{
		{"trivy repo", "trivy", "/tmp/repo", "", "fs", "/tmp/repo", false},
		{"trivy image", "trivy", "", "nginx:1.25", "image", "nginx:1.25", false},
		{"trivy both rejected", "trivy", "/tmp/repo", "nginx:1.25", "", "", true},
		{"trivy neither rejected", "trivy", "", "", "", "", true},
		{"gitleaks repo", "gitleaks", "/tmp/repo", "", "fs", "/tmp/repo", false},
		{"gitleaks image rejected", "gitleaks", "", "nginx:1.25", "", "", true},
		{"gitleaks no target rejected", "gitleaks", "", "", "", "", true},
		{"semgrep repo", "semgrep", "/tmp/repo", "", "fs", "/tmp/repo", false},
		{"semgrep image rejected", "semgrep", "", "nginx:1.25", "", "", true},
		{"semgrep no target rejected", "semgrep", "", "", "", "", true},
		{"unknown tool rejected", "nuclei", "/tmp/repo", "", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mode, target, err := resolveScanTarget(tt.tool, tt.repo, tt.image)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("want error, got mode=%q target=%q", mode, target)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if mode != tt.mode || target != tt.target {
				t.Fatalf("got (%q, %q), want (%q, %q)", mode, target, tt.mode, tt.target)
			}
		})
	}
}

// TestRunScanToolMissingBinary verifies each tool surfaces its stable
// ErrXNotFound so the CLI can exit 2.
func TestRunScanToolMissingBinary(t *testing.T) {
	t.Setenv("FLOWSTALLION_TRIVY_BIN", "/nonexistent/trivy")
	t.Setenv("FLOWSTALLION_GITLEAKS_BIN", "/nonexistent/gitleaks")
	t.Setenv("FLOWSTALLION_SEMGREP_BIN", "/nonexistent/semgrep")

	if _, err := runScanTool("trivy", "fs", "/tmp/x"); !errors.Is(err, security.ErrTrivyNotFound) {
		t.Errorf("trivy: err = %v, want ErrTrivyNotFound", err)
	}
	if _, err := runScanTool("gitleaks", "fs", "/tmp/x"); !errors.Is(err, security.ErrGitleaksNotFound) {
		t.Errorf("gitleaks: err = %v, want ErrGitleaksNotFound", err)
	}
	if _, err := runScanTool("semgrep", "fs", "/tmp/x"); !errors.Is(err, security.ErrSemgrepNotFound) {
		t.Errorf("semgrep: err = %v, want ErrSemgrepNotFound", err)
	}
	if _, err := runScanTool("nuclei", "fs", "/tmp/x"); err == nil {
		t.Error("unknown tool: want error, got nil")
	}
}

// writeFakeBin writes an executable shell script to dir under name and
// returns its path.
func writeFakeBin(dir, name, script string) string {
	p := filepath.Join(dir, name)
	full := "#!/bin/sh\n" + script + "\n"
	if err := os.WriteFile(p, []byte(full), 0o755); err != nil {
		panic(err)
	}
	return p
}

// TestRunScanToolFakes drives each runner through the CLI dispatch with fake
// binaries, pinning the normalised common fields.
func TestRunScanToolFakes(t *testing.T) {
	t.Run("trivy", func(t *testing.T) {
		dir := t.TempDir()
		payload := filepath.Join(dir, "report.json")
		if err := os.WriteFile(payload, []byte(`{"SchemaVersion":2,"ReportID":"cli-1","CreatedAt":"2026-10-26T00:00:00Z","Trivy":{"Version":"0.76.1"},"Results":[{"Vulnerabilities":[{"Severity":"HIGH"}]}]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		bin := writeFakeBin(dir, "trivy", `cat `+`"`+payload+`"`)
		t.Setenv("FLOWSTALLION_TRIVY_BIN", bin)
		res, err := runScanTool("trivy", "image", "nginx:1.25")
		if err != nil {
			t.Fatalf("trivy scan: %v", err)
		}
		if res.Tool != "trivy" || res.Mode != "image" || res.FindingsCount != 1 || res.ExitCode != 0 {
			t.Fatalf("unexpected trivy result: %+v", res)
		}
		if res.Severity["HIGH"] != 1 {
			t.Fatalf("severity = %v, want HIGH=1", res.Severity)
		}
	})

	t.Run("gitleaks", func(t *testing.T) {
		dir := t.TempDir()
		bin := writeFakeBin(dir, "gitleaks",
			`gp=""; prev=""; for a in "$@"; do [ "$prev" = "--report-path" ] && gp="$a"; prev="$a"; done; printf '[{"RuleID":"aws"}]' > "$gp"; exit 1`)
		t.Setenv("FLOWSTALLION_GITLEAKS_BIN", bin)
		res, err := runScanTool("gitleaks", "fs", "/tmp/repo")
		if err != nil {
			t.Fatalf("gitleaks scan: %v", err)
		}
		if res.Tool != "gitleaks" || res.Mode != "fs" || res.FindingsCount != 1 || res.ExitCode != 1 {
			t.Fatalf("unexpected gitleaks result: %+v", res)
		}
		if len(res.Severity) != 0 {
			t.Fatalf("gitleaks severity should be empty, got %v", res.Severity)
		}
	})

	t.Run("semgrep", func(t *testing.T) {
		dir := t.TempDir()
		bin := writeFakeBin(dir, "semgrep",
			`echo '{"results":[{"extra":{"severity":"ERROR"}},{"extra":{"severity":"INFO"}}]}'`)
		t.Setenv("FLOWSTALLION_SEMGREP_BIN", bin)
		res, err := runScanTool("semgrep", "fs", "/tmp/repo")
		if err != nil {
			t.Fatalf("semgrep scan: %v", err)
		}
		if res.Tool != "semgrep" || res.Mode != "fs" || res.FindingsCount != 2 || res.ExitCode != 0 {
			t.Fatalf("unexpected semgrep result: %+v", res)
		}
		if res.Severity["HIGH"] != 1 || res.Severity["LOW"] != 1 {
			t.Fatalf("semgrep severity = %v, want HIGH=1 LOW=1", res.Severity)
		}
	})
}
