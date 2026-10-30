package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/flowstallion/flowstallion/pkg/api"
)

// Agent is a FlowStallion runner. It registers with the scheduler, polls for
// jobs, executes each job in a Docker container, streams logs back, and
// reports completion.
type Agent struct {
	Name    string
	Server  string // base URL, e.g. http://localhost:8080
	Docker  Docker
	Host    HostDocker // P7④: host-side docker ops for docker_build steps
	Client  *http.Client
	Poll    time.Duration
	RegPoll time.Duration // register retry interval (default 2s); agent stays
	// up while the scheduler is down / restarting instead of exiting
	MaxLine    int    // max chars per log line before truncation (server cap 8192)
	AgentToken string // machine token, optional; sent as X-Agent-Token on every
	// scheduler request. Required when the scheduler has auth enabled with
	// FLOWSTALLION_AGENT_TOKEN set (otherwise all /api/agent/* calls 401).
}

// Run blocks, driving the register/poll/execute loop until ctx is done.
// It returns nil on clean shutdown.
func (a *Agent) Run(ctx context.Context) error {
	if a.Client == nil {
		a.Client = &http.Client{Timeout: 30 * time.Second}
	}
	if a.Poll <= 0 {
		a.Poll = 500 * time.Millisecond
	}
	if a.MaxLine <= 0 {
		a.MaxLine = 8192
	}
	if a.Host == nil {
		a.Host = &HostCLI{}
	}
	if a.RegPoll <= 0 {
		a.RegPoll = 2 * time.Second
	}

	for {
		err := a.register(ctx)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return nil
		}
		log.Printf("register: %v (retrying in %s)", err, a.RegPoll)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(a.RegPoll):
		}
	}
	log.Printf("agent %q connected to %s", a.Name, a.Server)

	ticker := time.NewTicker(a.Poll)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("agent %q shutting down", a.Name)
			return nil
		case <-ticker.C:
			job, err := a.claim(ctx)
			if err != nil {
				log.Printf("claim: %v", err)
				continue
			}
			if job == nil {
				continue
			}
			log.Printf("claim job: run=%d step=%s image=%s", job.RunID, job.StepID, job.Image)
			a.handleJob(ctx, job)
		}
	}
}

// newRequest builds a scheduler request and attaches the agent's machine
// token (X-Agent-Token) when one is configured.
func (a *Agent) newRequest(ctx context.Context, method, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	if a.AgentToken != "" {
		req.Header.Set("X-Agent-Token", a.AgentToken)
	}
	return req, nil
}

// register announces this agent to the scheduler.
func (a *Agent) register(ctx context.Context) error {
	body, _ := json.Marshal(map[string]string{"name": a.Name})
	url := a.Server + "/api/agent/register"
	req, err := a.newRequest(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("unexpected status %d: %s", resp.StatusCode, readBody(resp))
		if resp.StatusCode == http.StatusUnauthorized {
			err = fmt.Errorf("%w (scheduler requires auth: set FLOWSTALLION_AGENT_TOKEN and restart agent)", err)
		}
		return err
	}
	return nil
}

// claim fetches the next pending job for this agent, or nil if none.
func (a *Agent) claim(ctx context.Context) (*api.Job, error) {
	url := fmt.Sprintf("%s/api/agent/jobs?agent=%s", a.Server, a.Name)
	req, err := a.newRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := a.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, readBody(resp))
	}
	var out struct {
		Job api.Job `json:"job"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out.Job, nil
}

// handleJob executes a single job (step) end to end.
func (a *Agent) handleJob(ctx context.Context, job *api.Job) {
	// Per-step timeout.
	stepCtx := ctx
	if job.TimeoutS > 0 {
		var cancel context.CancelFunc
		stepCtx, cancel = context.WithTimeout(ctx, time.Duration(job.TimeoutS)*time.Second)
		defer cancel()
	}

	if job.StepType == "docker_build" {
		a.handleDockerBuild(ctx, stepCtx, job)
		return
	}

	name := containerName(job.RunID, job.StepID)

	if err := a.Docker.Run(stepCtx, name, job.Image, job.Env); err != nil {
		log.Printf("create container run=%d step=%s: %v", job.RunID, job.StepID, err)
		a.finish(ctx, job.RunID, job.StepID, "failed", "create container: "+err.Error(), nil)
		return
	}
	// Always clean up the container, even if the run is cancelled.
	defer func() {
		if err := a.Docker.Remove(context.Background(), name); err != nil {
			log.Printf("cleanup container %s: %v", name, err)
		}
	}()

	for i, cmd := range job.Commands {
		output, err := a.Docker.Exec(stepCtx, name, cmd)
		if output != "" {
			a.postLogs(ctx, job.RunID, job.StepID, output)
		}
		if err != nil {
			log.Printf("exec run=%d step=%s cmd=%q: %v", job.RunID, job.StepID, cmd, err)
			msg := fmt.Sprintf("step %d/%d command %q failed: %v", i+1, len(job.Commands), cmd, err)
			if stepCtx.Err() == context.DeadlineExceeded {
				msg = fmt.Sprintf("step timed out after %ds", job.TimeoutS)
			}
			a.finish(ctx, job.RunID, job.StepID, "failed", msg, nil)
			return
		}
	}

	a.finish(ctx, job.RunID, job.StepID, "success", "", nil)
	log.Printf("job done: run=%d step=%s success", job.RunID, job.StepID)
}

// handleDockerBuild executes a docker_build step on the agent host:
// `docker build` (output streamed to the run log), then — when the step
// declares push — optional registry login (credentials from the job env)
// and `docker push`. On success the built image ref is reported as the step
// output "image_ref". The Dockerfile / build context are paths relative to
// the agent's working directory (the job's project directory).
func (a *Agent) handleDockerBuild(ctx context.Context, stepCtx context.Context, job *api.Job) {
	tag := job.Image
	dockerfile := job.Dockerfile
	if dockerfile == "" {
		dockerfile = "Dockerfile"
	}
	contextDir := job.Context
	if contextDir == "" {
		contextDir = "."
	}

	out, err := a.Host.Build(stepCtx, tag, dockerfile, contextDir)
	if out != "" {
		a.postLogs(ctx, job.RunID, job.StepID, out)
	}
	if err != nil {
		log.Printf("docker build run=%d step=%s: %v", job.RunID, job.StepID, err)
		msg := "docker build: " + err.Error()
		if stepCtx.Err() == context.DeadlineExceeded {
			msg = fmt.Sprintf("step timed out after %ds", job.TimeoutS)
		}
		a.finish(ctx, job.RunID, job.StepID, "failed", msg, nil)
		return
	}

	if job.Push {
		registry := registryHost(tag)
		user, pass := job.Env["REGISTRY_USER"], job.Env["REGISTRY_PASSWORD"]
		if user != "" && pass != "" {
			if err := a.Host.Login(ctx, registry, user, pass); err != nil {
				log.Printf("registry login run=%d step=%s: %v", job.RunID, job.StepID, err)
				a.finish(ctx, job.RunID, job.StepID, "failed", "registry login: "+err.Error(), nil)
				return
			}
		}
		if err := a.Host.Push(ctx, tag); err != nil {
			log.Printf("docker push run=%d step=%s: %v", job.RunID, job.StepID, err)
			a.finish(ctx, job.RunID, job.StepID, "failed", "docker push: "+err.Error(), nil)
			return
		}
	}

	a.finish(ctx, job.RunID, job.StepID, "success", "", map[string]string{"image_ref": tag})
	log.Printf("job done: run=%d step=%s docker_build image=%s push=%v", job.RunID, job.StepID, tag, job.Push)
}

// postLogs splits output into lines and POSTs them to the scheduler in
// batches of at most 200 lines.
func (a *Agent) postLogs(ctx context.Context, runID int64, stepID, output string) {
	lines := splitLines(output)
	const batch = 200
	for i := 0; i < len(lines); i += batch {
		end := i + batch
		if end > len(lines) {
			end = len(lines)
		}
		if err := a.postLogLines(ctx, runID, stepID, lines[i:end]); err != nil {
			log.Printf("post logs run=%d step=%s: %v", runID, stepID, err)
		}
	}
}

func (a *Agent) postLogLines(ctx context.Context, runID int64, stepID string, lines []string) error {
	body, _ := json.Marshal(map[string][]string{"lines": lines})
	url := fmt.Sprintf("%s/api/agent/jobs/%d/%s/logs", a.Server, runID, stepID)
	req, err := a.newRequest(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, readBody(resp))
	}
	return nil
}

// finish reports the final status of a job to the scheduler.
// P7④: optional step outputs (e.g. docker_build "image_ref") are included
// in the POST body when non-empty; the server persists them on the step row.
func (a *Agent) finish(ctx context.Context, runID int64, stepID, status, message string, outputs map[string]string) {
	m := map[string]any{"status": status, "message": message}
	if len(outputs) > 0 {
		m["outputs"] = outputs
	}
	body, _ := json.Marshal(m)
	url := fmt.Sprintf("%s/api/agent/jobs/%d/%s", a.Server, runID, stepID)
	req, err := a.newRequest(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		log.Printf("finish run=%d step=%s: %v", runID, stepID, err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.Client.Do(req)
	if err != nil {
		log.Printf("finish run=%d step=%s: %v", runID, stepID, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("finish run=%d step=%s: status %d: %s", runID, stepID, resp.StatusCode, readBody(resp))
	}
}

// containerName builds a stable, docker-safe container name for a job.
func containerName(runID int64, stepID string) string {
	safe := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, stepID)
	return fmt.Sprintf("flowstallion-%d-%s", runID, safe)
}

// splitLines splits output into log lines, truncating any line longer than
// maxLine and discarding trailing empty fragments.
func splitLines(output string) []string {
	raw := strings.Split(output, "\n")
	// Trim a trailing empty element produced by a final newline.
	if len(raw) > 0 && raw[len(raw)-1] == "" {
		raw = raw[:len(raw)-1]
	}
	return raw
}

// readBody drains a response body into a string (for error reporting).
func readBody(resp *http.Response) string {
	b, _ := io.ReadAll(resp.Body)
	return strings.TrimSpace(string(b))
}
