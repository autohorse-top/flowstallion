package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRegistryHost: table-driven check of registry extraction from image refs.
func TestRegistryHost(t *testing.T) {
	cases := []struct {
		ref  string
		want string
	}{
		{"alpine:3.20", ""},
		{"alpine", ""},
		{"ubuntu:22.04", ""},   // repo:tag, no slash -> default registry
		{"my.registry.io", ""}, // no slash -> default registry (docker rule)
		{"ghcr.io/org/app:v1", "ghcr.io"},
		{"registry.example.com/team/app", "registry.example.com"},
		{"localhost:5000/app:1", "localhost:5000"},
		{"localhost/app", "localhost"},
		{"my.registry.io:8080/app", "my.registry.io:8080"},
	}
	for _, tc := range cases {
		if got := registryHost(tc.ref); got != tc.want {
			t.Errorf("registryHost(%q) = %q, want %q", tc.ref, got, tc.want)
		}
	}
}

// fakeDockerScript writes a shell script acting as a stand-in for the docker
// CLI: it records argv to $FAKE_DOCKER_LOG, mirrors login stdin to
// $FAKE_DOCKER_STDIN, and fails per subcommand when the matching
// FAKE_DOCKER_FAIL_<CMD> env var is set.
const fakeDockerScript = `#!/bin/sh
echo "$*" >> "$FAKE_DOCKER_LOG"
if [ "$1" = "login" ]; then cat >> "$FAKE_DOCKER_STDIN"; fi
case "$1" in
  build) [ -n "$FAKE_DOCKER_FAIL_BUILD" ] && exit 1 ;;
  push)  [ -n "$FAKE_DOCKER_FAIL_PUSH" ] && exit 1 ;;
  login) [ -n "$FAKE_DOCKER_FAIL_LOGIN" ] && exit 1 ;;
esac
exit 0
`

// newFakeDockerBin creates the fake docker binary and registers env vars.
func newFakeDockerBin(t *testing.T) (bin, logFile, stdinFile string) {
	t.Helper()
	dir := t.TempDir()
	bin = filepath.Join(dir, "docker")
	logFile = filepath.Join(dir, "argv.log")
	stdinFile = filepath.Join(dir, "stdin.log")
	if err := os.WriteFile(bin, []byte(fakeDockerScript), 0o755); err != nil {
		t.Fatalf("write fake docker: %v", err)
	}
	t.Setenv("FAKE_DOCKER_LOG", logFile)
	t.Setenv("FAKE_DOCKER_STDIN", stdinFile)
	return bin, logFile, stdinFile
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("read %s: %v", path, err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return nil
	}
	return lines
}

// TestHostCLIArgv pins the exact argv of the docker CLI invocations, and
// verifies the registry password never appears on the command line.
func TestHostCLIArgv(t *testing.T) {
	bin, logFile, stdinFile := newFakeDockerBin(t)
	h := &HostCLI{Bin: bin}
	ctx := context.Background()

	if _, err := h.Build(ctx, "reg.io/app:1", "Dockerfile.app", "svc"); err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := h.Push(ctx, "reg.io/app:1"); err != nil {
		t.Fatalf("push: %v", err)
	}
	if err := h.Login(ctx, "reg.io", "user", "s3cret"); err != nil {
		t.Fatalf("login with registry: %v", err)
	}
	if err := h.Login(ctx, "", "user", "s3cret"); err != nil {
		t.Fatalf("login without registry: %v", err)
	}

	got := readLines(t, logFile)
	want := []string{
		"build -t reg.io/app:1 -f Dockerfile.app svc",
		"push reg.io/app:1",
		"login reg.io --username user --password-stdin",
		"login --username user --password-stdin",
	}
	if len(got) != len(want) {
		t.Fatalf("argv log = %v, want %v", got, want)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("argv[%d] = %q, want %q", i, got[i], w)
		}
	}
	// Password must be delivered on stdin only, never in argv.
	stdin, _ := os.ReadFile(stdinFile)
	if !strings.Contains(string(stdin), "s3cret") {
		t.Errorf("stdin log = %q, want to contain the password", string(stdin))
	}
	if b, _ := os.ReadFile(logFile); strings.Contains(string(b), "s3cret") {
		t.Errorf("argv log must not contain the password: %q", string(b))
	}
}

// TestHostCLIFailures: non-zero exit from the fake docker surfaces as an error.
func TestHostCLIFailures(t *testing.T) {
	bin, _, _ := newFakeDockerBin(t)
	h := &HostCLI{Bin: bin}
	ctx := context.Background()

	t.Setenv("FAKE_DOCKER_FAIL_BUILD", "1")
	if _, err := h.Build(ctx, "r/x:1", "Dockerfile", "."); err == nil {
		t.Error("build with FAKE_DOCKER_FAIL_BUILD: want error, got nil")
	}
	t.Setenv("FAKE_DOCKER_FAIL_BUILD", "")

	t.Setenv("FAKE_DOCKER_FAIL_PUSH", "1")
	if err := h.Push(ctx, "r/x:1"); err == nil {
		t.Error("push with FAKE_DOCKER_FAIL_PUSH: want error, got nil")
	}
	t.Setenv("FAKE_DOCKER_FAIL_PUSH", "")

	t.Setenv("FAKE_DOCKER_FAIL_LOGIN", "1")
	if err := h.Login(ctx, "", "u", "p"); err == nil {
		t.Error("login with FAKE_DOCKER_FAIL_LOGIN: want error, got nil")
	}
}
