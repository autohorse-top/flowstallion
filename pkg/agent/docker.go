// Package agent implements the FlowStallion runner agent. It polls the
// scheduler for jobs, executes step commands inside Docker containers,
// and streams logs back to the scheduler.
package agent

import (
	"context"
	"fmt"
	"os/exec"
	"sort"
	"strings"
)

// Docker abstracts container operations so tests can use a fake.
type Docker interface {
	// Run creates and starts a container kept alive for exec calls.
	Run(ctx context.Context, name, image string, env map[string]string) error
	// Exec runs a shell command inside the container and returns combined
	// stdout+stderr. Returns the exit error (nil if exit code 0).
	Exec(ctx context.Context, name, command string) (string, error)
	// Remove force-removes a container. Errors are non-fatal (idempotent).
	Remove(ctx context.Context, name string) error
}

// CLI is the production Docker implementation using the docker CLI.
type CLI struct{}

var _ Docker = (*CLI)(nil)

// Run creates a detached container with the given image, env vars, and a
// no-op entrypoint (sleep infinity) so it stays alive for exec calls.
func (c *CLI) Run(ctx context.Context, name, image string, env map[string]string) error {
	// Clean up any stale container with the same name.
	c.Remove(ctx, name)

	args := []string{"run", "-d", "--name", name, "--entrypoint", "sh"}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		args = append(args, "-e", k+"="+env[k])
	}
	args = append(args, image, "-c", "sleep infinity")

	cmd := exec.CommandContext(ctx, "docker", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker run %s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Exec runs a command inside the container via docker exec.
// Returns combined stdout+stderr and the command's exit error.
func (c *CLI) Exec(ctx context.Context, name, command string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", "exec", name, "sh", "-c", command)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// Remove force-removes a container. A "no such container" error is not
// propagated (idempotent cleanup).
func (c *CLI) Remove(ctx context.Context, name string) error {
	cmd := exec.CommandContext(ctx, "docker", "rm", "-f", name)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if strings.Contains(msg, "no such container") || strings.Contains(msg, "No such container") {
			return nil
		}
		return fmt.Errorf("docker rm %s: %w: %s", name, err, msg)
	}
	return nil
}

// HostDocker abstracts host-side docker operations (image build / push /
// login) for docker_build steps. These run on the agent's host, not inside
// a job container, so they are kept separate from the Docker interface.
type HostDocker interface {
	// Build builds the image tagged tag from dockerfile in contextDir and
	// returns the build output (stdout+stderr).
	Build(ctx context.Context, tag, dockerfile, contextDir string) (string, error)
	// Push pushes the image ref to its registry.
	Push(ctx context.Context, ref string) error
	// Login authenticates to registry ("" = Docker Hub) with the given
	// credentials. The password is delivered on stdin only, never in argv
	// (security baseline: no secrets in process args).
	Login(ctx context.Context, registry, user, password string) error
}

// HostCLI is the production HostDocker implementation using the docker CLI.
type HostCLI struct {
	// Bin overrides the docker executable (tests point it at a fake
	// binary); defaults to "docker" on PATH.
	Bin string
}

var _ HostDocker = (*HostCLI)(nil)

func (h *HostCLI) bin() string {
	if h == nil || h.Bin == "" {
		return "docker"
	}
	return h.Bin
}

// Build runs `docker build -t <tag> -f <dockerfile> <context>` and returns
// the combined output.
func (h *HostCLI) Build(ctx context.Context, tag, dockerfile, contextDir string) (string, error) {
	args := []string{"build", "-t", tag, "-f", dockerfile, contextDir}
	out, err := exec.CommandContext(ctx, h.bin(), args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("docker build %s: %w: %s", tag, err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// Push runs `docker push <ref>`.
func (h *HostCLI) Push(ctx context.Context, ref string) error {
	out, err := exec.CommandContext(ctx, h.bin(), "push", ref).CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker push %s: %w: %s", ref, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Login runs `docker login [--registry] --username <user> --password-stdin`,
// feeding the password on stdin so it never appears in the process argv.
func (h *HostCLI) Login(ctx context.Context, registry, user, password string) error {
	args := []string{"login"}
	if registry != "" {
		args = append(args, registry)
	}
	args = append(args, "--username", user, "--password-stdin")
	cmd := exec.CommandContext(ctx, h.bin(), args...)
	cmd.Stdin = strings.NewReader(password)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker login: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// registryHost extracts the registry host of a docker image ref:
// "registry.example.com/x/y" -> "registry.example.com",
// "ghcr.io/org/app" -> "ghcr.io", "localhost:5000/app" -> "localhost:5000",
// "alpine:3.20" / "ubuntu:22.04" -> "". An empty result means the default
// registry (Docker Hub). Follows docker's parsing rules: without a "/"
// there is no registry; otherwise the first path segment is a registry
// only if it contains "." or ":" or is "localhost".
func registryHost(ref string) string {
	i := strings.Index(ref, "/")
	if i < 0 {
		return ""
	}
	seg := ref[:i]
	if seg == "localhost" || strings.Contains(seg, ".") || strings.Contains(seg, ":") {
		return seg
	}
	return ""
}
