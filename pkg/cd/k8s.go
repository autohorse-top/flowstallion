// Package cd implements FlowStallion's K8s continuous delivery: a canary
// release state machine that applies declarative manifests via kubectl,
// observes built-in app metrics through the API-server service proxy, and
// auto-rolls back (or promotes) based on an error-rate threshold.
package cd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Kubectl executes kubectl CLI commands. Run returns stdout; on failure the
// error carries stderr (truncated to 512 bytes). stdin is piped to the
// command when non-empty (used by kubectl apply -f -).
type Kubectl interface {
	Run(args []string, stdin string) (string, error)
}

// RealKubectl shells out to the kubectl binary (KUBECONFIG from env).
type RealKubectl struct {
	// Timeout bounds a single invocation so a wedged API server cannot
	// stall the whole tick loop (m-2). Zero means the 30s default.
	Timeout time.Duration
	// Binary is the kubectl executable to run (default "kubectl").
	// Overridable so the scheduler process can be pointed at a wrapper
	// or a test fake (FLOWSTALLION_KUBECTL_BIN, P7⑤ E2E).
	Binary string
}

// defaultKubectlTimeout applies when RealKubectl.Timeout is zero.
const defaultKubectlTimeout = 30 * time.Second

// Run executes kubectl with the given args, optionally piping stdin.
func (k RealKubectl) Run(args []string, stdin string) (string, error) {
	timeout := k.Timeout
	if timeout <= 0 {
		timeout = defaultKubectlTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	bin := k.Binary
	if bin == "" {
		bin = "kubectl"
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	if err != nil {
		return out.String(), fmt.Errorf("kubectl %s: %v: %s",
			strings.Join(args, " "), err, truncate(errb.String(), 512))
	}
	return out.String(), nil
}

// ContextKubectl wraps another Kubectl and prepends "--context <name>" to
// every invocation (P7⑤: k8s_canary steps may target a non-default kube
// context). Empty Context is a no-op passthrough.
type ContextKubectl struct {
	Inner   Kubectl
	Context string
}

// Run delegates to Inner with the --context prefix when Context is set.
func (k ContextKubectl) Run(args []string, stdin string) (string, error) {
	if k.Context != "" {
		a := make([]string, 0, len(args)+2)
		a = append(a, "--context", k.Context)
		a = append(a, args...)
		args = a
	}
	return k.Inner.Run(args, stdin)
}

// stableDeployJSON is the subset of a Deployment JSON document the executor
// needs to seed a canary release (P7⑤).
type stableDeployJSON struct {
	Spec struct {
		Replicas int `json:"replicas"`
		Template struct {
			Spec struct {
				Containers []struct {
					Image string `json:"image"`
				} `json:"containers"`
			} `json:"spec"`
		} `json:"template"`
	} `json:"spec"`
}

// StableDeployment reads the live stable deployment's current container image
// and replica count via "kubectl get deploy <name> -o json".
func StableDeployment(k Kubectl, namespace, name string) (image string, replicas int, err error) {
	out, err := k.Run([]string{"-n", namespace, "get", "deploy", name, "-o", "json"}, "")
	if err != nil {
		return "", 0, fmt.Errorf("get deploy %q in %q: %w", name, namespace, err)
	}
	var d stableDeployJSON
	if err := json.Unmarshal([]byte(out), &d); err != nil {
		return "", 0, fmt.Errorf("unparseable deploy json for %q: %v", name, err)
	}
	if len(d.Spec.Template.Spec.Containers) == 0 {
		return "", 0, fmt.Errorf("deployment %q has no containers", name)
	}
	return d.Spec.Template.Spec.Containers[0].Image, d.Spec.Replicas, nil
}

// truncate shortens s to at most n bytes and trims whitespace. The cut is
// backed up to a UTF-8 rune boundary so multi-byte characters are never
// split (n-2).
func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	for n > 0 && n < len(s) && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n] + "…"
}
