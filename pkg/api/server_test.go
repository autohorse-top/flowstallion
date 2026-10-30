package api

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/flowstallion/flowstallion/pkg/scheduler"
	"github.com/flowstallion/flowstallion/pkg/store"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const linearYAML = `
version: 1
pipeline:
  name: linear
  steps:
    - id: a
      image: alpine
      commands:
        - echo a
    - id: b
      image: alpine
      needs: [a]
      commands:
        - echo b
    - id: c
      image: alpine
      needs: [b]
      commands:
        - echo c
`

const slowYAML = `
version: 1
pipeline:
  name: slow
  concurrency: 1
  steps:
    - id: a
      image: alpine
      commands: [echo a]
`

func newTestServer(t *testing.T) (*httptest.Server, *Server) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "api-test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	disp := NewDispatcher()
	sched := scheduler.New(st, &AgentExecutor{D: disp})
	srv := New(st, sched, disp)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, srv
}

// doJSON performs an HTTP request and decodes the JSON body (if any).
func doJSON(t *testing.T, c *http.Client, method, url string, body any) (int, map[string]any) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if ct := resp.Header.Get("Content-Type"); strings.HasPrefix(ct, "application/json") {
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil && resp.StatusCode != http.StatusOK {
			// error bodies are JSON too, but tolerate non-JSON
			t.Logf("decode %s %s: %v", method, url, err)
		}
	}
	return resp.StatusCode, out
}

// createPipeline POSTs a pipeline and returns its id.
func createPipeline(t *testing.T, c *http.Client, base, name, yaml string) int64 {
	t.Helper()
	code, out := doJSON(t, c, "POST", base+"/api/pipelines", map[string]string{"name": name, "yaml": yaml})
	if code != http.StatusCreated {
		t.Fatalf("create pipeline %q: got %d, want 201 (body=%v)", name, code, out)
	}
	id, ok := out["id"].(float64)
	if !ok {
		t.Fatalf("create pipeline response has no id: %v", out)
	}
	return int64(id)
}

// triggerRun POSTs a trigger and returns the run id.
func triggerRun(t *testing.T, c *http.Client, base, name string) int64 {
	t.Helper()
	code, out := doJSON(t, c, "POST", fmt.Sprintf("%s/api/pipelines/%s/trigger", base, name),
		map[string]string{"trigger": "manual"})
	if code != http.StatusAccepted {
		t.Fatalf("trigger %q: got %d, want 202 (body=%v)", name, code, out)
	}
	id, ok := out["run_id"].(float64)
	if !ok {
		t.Fatalf("trigger response has no run_id: %v", out)
	}
	return int64(id)
}

// runStatus GETs a run and returns its status (fatals on 4xx/5xx).
func runStatus(t *testing.T, c *http.Client, base string, runID int64) string {
	t.Helper()
	code, out := doJSON(t, c, "GET", fmt.Sprintf("%s/api/runs/%d", base, runID), nil)
	if code != http.StatusOK {
		t.Fatalf("get run %d: got %d", runID, code)
	}
	inner, _ := out["run"].(map[string]any)
	status, _ := inner["status"].(string)
	return status
}

// waitForRunStatus polls until the run reaches any of the given terminal
// statuses or the deadline passes.
func waitForRunStatus(t *testing.T, c *http.Client, base string, runID int64, terminal ...string) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		s := runStatus(t, c, base, runID)
		for _, want := range terminal {
			if s == want {
				return s
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("run %d never reached %v (last status %q)", runID, terminal, s)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

type claimedJob struct {
	RunID    int64             `json:"run_id"`
	StepID   string            `json:"step_id"`
	Image    string            `json:"image"`
	Commands []string          `json:"commands"`
	Env      map[string]string `json:"env"`
	TimeoutS int               `json:"timeout_s"`
}

// claimJobNoFatal GETs the next job for an agent; a nil job means the queue
// is empty (204). Non-fatal: safe to call from a goroutine.
func claimJobNoFatal(c *http.Client, base, agent string) (*claimedJob, error) {
	req, err := http.NewRequest(http.MethodGet, base+"/api/agent/jobs?agent="+agent, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("claim: unexpected status %d", resp.StatusCode)
	}
	var out struct {
		Job claimedJob `json:"job"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("claim: decode: %w", err)
	}
	return &out.Job, nil
}

// postLogsNoFatal streams two canned log lines for a claimed job.
func postLogsNoFatal(c *http.Client, base string, j *claimedJob) error {
	body, _ := json.Marshal(map[string]any{"lines": []string{"line-1", "line-2"}})
	req, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("%s/api/agent/jobs/%d/%s/logs", base, j.RunID, j.StepID),
		bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("post logs: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// finishJobNoFatal reports a job's outcome via the agent protocol.
func finishJobNoFatal(c *http.Client, base string, j *claimedJob, status, message string) error {
	body, _ := json.Marshal(map[string]string{"status": status, "message": message})
	req, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("%s/api/agent/jobs/%d/%s", base, j.RunID, j.StepID),
		bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("finish: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// statusNoFatal GETs a run's status. Non-fatal: safe to call from a goroutine.
func statusNoFatal(c *http.Client, base string, runID int64) (string, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/runs/%d", base, runID), nil)
	if err != nil {
		return "", err
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("get run: unexpected status %d", resp.StatusCode)
	}
	var out struct {
		Run struct {
			Status string `json:"status"`
		} `json:"run"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("get run: decode: %w", err)
	}
	return out.Run.Status, nil
}

// fakeAgent claims and finishes jobs over HTTP until the run is terminal.
// It runs in a goroutine and therefore never calls t.Fatal/t.Error; it
// reports exactly one result (nil or an error) on the done channel.
func fakeAgent(t *testing.T, c *http.Client, base, agent string, runID int64, delay time.Duration, done chan<- error) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	report := func(err error) {
		select {
		case done <- err:
		default:
		}
	}
	for time.Now().Before(deadline) {
		j, err := claimJobNoFatal(c, base, agent)
		if err != nil {
			report(fmt.Errorf("claim: %w", err))
			return
		}
		if j != nil {
			if delay > 0 {
				time.Sleep(delay)
			}
			if err := postLogsNoFatal(c, base, j); err != nil {
				report(err)
				return
			}
			if err := finishJobNoFatal(c, base, j, "success", ""); err != nil {
				report(err)
				return
			}
			continue
		}
		s, err := statusNoFatal(c, base, runID)
		if err != nil {
			report(err)
			return
		}
		if s == store.RunSuccess || s == store.RunFailed || s == store.RunCanceled {
			report(nil)
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	report(fmt.Errorf("fake agent %s timed out", agent))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestHealthz(t *testing.T) {
	ts, _ := newTestServer(t)
	code, out := doJSON(t, ts.Client(), "GET", ts.URL+"/healthz", nil)
	if code != http.StatusOK || out["status"] != "ok" {
		t.Fatalf("healthz: got %d %v, want 200 {status: ok}", code, out)
	}
}

func TestPipelineUpsertAndList(t *testing.T) {
	ts, _ := newTestServer(t)
	c := ts.Client()

	// Create.
	id := createPipeline(t, c, ts.URL, "demo", linearYAML)
	if id <= 0 {
		t.Fatalf("pipeline id = %d, want > 0", id)
	}

	// Upsert the same name: must succeed and keep the same id.
	code, out := doJSON(t, c, "POST", ts.URL+"/api/pipelines",
		map[string]string{"name": "demo", "yaml": linearYAML})
	if code != http.StatusCreated {
		t.Fatalf("upsert existing: got %d, want 201", code)
	}
	if got := int64(out["id"].(float64)); got != id {
		t.Fatalf("upsert returned id %d, want %d (same row)", got, id)
	}

	// Invalid YAML is rejected before persistence, with field paths.
	code, out = doJSON(t, c, "POST", ts.URL+"/api/pipelines",
		map[string]string{"name": "bad", "yaml": "version: 2\npipeline: {}\n"})
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid pipeline: got %d, want 422 (body=%v)", code, out)
	}
	problems, _ := out["problems"].([]any)
	if len(problems) < 2 {
		t.Fatalf("expected aggregated problems, got %v", problems)
	}

	// Missing name.
	if code, _ := doJSON(t, c, "POST", ts.URL+"/api/pipelines",
		map[string]string{"yaml": linearYAML}); code != http.StatusBadRequest {
		t.Fatalf("missing name: got %d, want 400", code)
	}

	// List: the response is a bare JSON array; assert it contains "demo".
	resp, err := c.Get(ts.URL + "/api/pipelines")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"demo"`) {
		t.Fatalf("pipeline list does not contain demo: %s", body)
	}

	// The list now carries the raw YAML (console admin editor pre-fill).
	var pls []struct {
		Name string `json:"name"`
		YAML string `json:"yaml"`
	}
	if err := json.Unmarshal(body, &pls); err != nil {
		t.Fatalf("pipeline list is not a JSON array of objects: %v (%s)", err, body)
	}
	found := false
	for _, p := range pls {
		if p.Name == "demo" {
			found = true
			if p.YAML != linearYAML {
				t.Fatalf("demo yaml = %q, want the upserted YAML", p.YAML)
			}
		}
	}
	if !found {
		t.Fatalf("pipeline list does not contain demo: %s", body)
	}
}

func TestTriggerRunLifecycleWithAgent(t *testing.T) {
	ts, _ := newTestServer(t)
	c := ts.Client()
	createPipeline(t, c, ts.URL, "linear", linearYAML)

	// Register the agent.
	code, out := doJSON(t, c, "POST", ts.URL+"/api/agent/register", map[string]string{"name": "worker-1"})
	if code != http.StatusOK || out["created"] != true {
		t.Fatalf("register: got %d %v, want 200 created=true", code, out)
	}
	// Re-register: same id, created=false.
	code, out = doJSON(t, c, "POST", ts.URL+"/api/agent/register", map[string]string{"name": "worker-1"})
	if code != http.StatusOK || out["created"] != false {
		t.Fatalf("re-register: got %d %v, want created=false", code, out)
	}

	runID := triggerRun(t, c, ts.URL, "linear")
	done := make(chan error, 1)
	go fakeAgent(t, c, ts.URL, "worker-1", runID, 0, done)

	status := waitForRunStatus(t, c, ts.URL, runID, store.RunSuccess)
	if status != store.RunSuccess {
		t.Fatalf("run status = %q, want success", status)
	}

	// All three steps succeeded.
	code, out = doJSON(t, c, "GET", fmt.Sprintf("%s/api/runs/%d", ts.URL, runID), nil)
	if code != http.StatusOK {
		t.Fatalf("get run: %d", code)
	}
	steps, _ := out["steps"].([]any)
	if len(steps) != 3 {
		t.Fatalf("steps = %d, want 3", len(steps))
	}
	for i, raw := range steps {
		st := raw.(map[string]any)
		if st["status"] != store.StepSuccess {
			t.Errorf("step %d status = %v, want success", i, st["status"])
		}
	}

	// Logs were stored and are queryable per step.
	code, out = doJSON(t, c, "GET", fmt.Sprintf("%s/api/runs/%d/logs?step=a", ts.URL, runID), nil)
	if code != http.StatusOK {
		t.Fatalf("logs: %d", code)
	}
	logs, _ := out["logs"].([]any)
	if len(logs) != 2 {
		t.Fatalf("logs for step a = %d lines, want 2 (%v)", len(logs), logs)
	}

	// Unknown step -> 404.
	if code, _ := doJSON(t, c, "GET", fmt.Sprintf("%s/api/runs/%d/logs?step=ghost", ts.URL, runID), nil); code != http.StatusNotFound {
		t.Fatalf("logs for unknown step: got %d, want 404", code)
	}

	// Unknown run -> 404.
	if code, _ := doJSON(t, c, "GET", ts.URL+"/api/runs/999999", nil); code != http.StatusNotFound {
		t.Fatalf("unknown run: got %d, want 404", code)
	}

	if err := <-done; err != nil {
		t.Fatalf("fake agent reported error: %v", err)
	}
}

func TestRunAnalysisEndpoint(t *testing.T) {
	ts, _ := newTestServer(t)
	c := ts.Client()
	createPipeline(t, c, ts.URL, "linear", linearYAML)
	doJSON(t, c, "POST", ts.URL+"/api/agent/register", map[string]string{"name": "worker-1"})

	runID := triggerRun(t, c, ts.URL, "linear")
	var j *claimedJob
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		got, err := claimJobNoFatal(c, ts.URL, "worker-1")
		if err != nil {
			t.Fatalf("claim: %v", err)
		}
		if got != nil && got.StepID == "a" {
			j = got
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if j == nil {
		t.Fatal("never claimed step a")
	}
	if err := postLogsNoFatal(c, ts.URL, j); err != nil {
		t.Fatalf("post logs: %v", err)
	}
	if err := finishJobNoFatal(c, ts.URL, j, "failed", "command exited with code 1"); err != nil {
		t.Fatalf("finish failed: %v", err)
	}
	if status := waitForRunStatus(t, c, ts.URL, runID, store.RunFailed); status != store.RunFailed {
		t.Fatalf("run status = %q, want failed", status)
	}

	// Steps carry their command list; no analysis yet.
	code, out := doJSON(t, c, "GET", fmt.Sprintf("%s/api/runs/%d", ts.URL, runID), nil)
	if code != http.StatusOK {
		t.Fatalf("get run: %d", code)
	}
	steps, _ := out["steps"].([]any)
	var aStep map[string]any
	for _, raw := range steps {
		m := raw.(map[string]any)
		if m["step_id"] == "a" {
			aStep = m
		}
	}
	if aStep == nil {
		t.Fatal("step a not in run response")
	}
	cmds, _ := aStep["command"].([]any)
	if len(cmds) != 1 || cmds[0] != "echo a" {
		t.Fatalf("step a command = %v, want [echo a]", aStep["command"])
	}
	if out["analysis"] != nil {
		t.Fatalf("analysis = %v before save, want null", out["analysis"])
	}

	// Save a rule-based analysis.
	body := map[string]any{
		"step_id": "a", "kind": "rule",
		"root_cause": "exit code 1",
		"detail":     "d", "suggested_fix": "f",
		"command": "echo a", "log_excerpt": "line-2",
	}
	code, out = doJSON(t, c, "POST", fmt.Sprintf("%s/api/runs/%d/analysis", ts.URL, runID), body)
	if code != http.StatusOK || out["ok"] != true {
		t.Fatalf("save analysis: got %d %v, want 200 ok=true", code, out)
	}
	code, out = doJSON(t, c, "GET", fmt.Sprintf("%s/api/runs/%d", ts.URL, runID), nil)
	ana := out["analysis"].(map[string]any)
	if ana["root_cause"] != "exit code 1" || ana["kind"] != "rule" || ana["step_id"] != "a" {
		t.Fatalf("analysis = %v", ana)
	}

	// Upsert replaces the report.
	body["kind"] = "llm"
	body["root_cause"] = "upgraded"
	code, _ = doJSON(t, c, "POST", fmt.Sprintf("%s/api/runs/%d/analysis", ts.URL, runID), body)
	if code != http.StatusOK {
		t.Fatalf("upsert analysis: got %d, want 200", code)
	}
	code, out = doJSON(t, c, "GET", fmt.Sprintf("%s/api/runs/%d", ts.URL, runID), nil)
	ana = out["analysis"].(map[string]any)
	if ana["kind"] != "llm" || ana["root_cause"] != "upgraded" {
		t.Fatalf("after upsert = %v", ana)
	}

	// Unknown step -> 404, unknown run -> 404, missing root_cause -> 400, bad kind -> 400.
	if code, _ := doJSON(t, c, "POST", fmt.Sprintf("%s/api/runs/%d/analysis", ts.URL, runID),
		map[string]any{"step_id": "ghost", "root_cause": "x"}); code != http.StatusNotFound {
		t.Fatalf("unknown step: got %d, want 404", code)
	}
	if code, _ := doJSON(t, c, "POST", ts.URL+"/api/runs/999999/analysis",
		map[string]any{"step_id": "a", "root_cause": "x"}); code != http.StatusNotFound {
		t.Fatalf("unknown run: got %d, want 404", code)
	}
	if code, _ := doJSON(t, c, "POST", fmt.Sprintf("%s/api/runs/%d/analysis", ts.URL, runID),
		map[string]any{"step_id": "a", "kind": "rule", "root_cause": ""}); code != http.StatusBadRequest {
		t.Fatalf("missing root_cause: got %d, want 400", code)
	}
	if code, _ := doJSON(t, c, "POST", fmt.Sprintf("%s/api/runs/%d/analysis", ts.URL, runID),
		map[string]any{"step_id": "a", "kind": "voodoo", "root_cause": "x"}); code != http.StatusBadRequest {
		t.Fatalf("bad kind: got %d, want 400", code)
	}

	// P7⑥: AI kinds are run-level (step_id omitted) and coexist with RCA.
	bodyAI := map[string]any{"kind": "pr_review", "root_cause": "PR review: 1 finding"}
	code, out = doJSON(t, c, "POST", fmt.Sprintf("%s/api/runs/%d/analysis", ts.URL, runID), bodyAI)
	if code != http.StatusOK || out["ok"] != true {
		t.Fatalf("save pr_review: got %d %v, want 200 ok=true", code, out)
	}
	bodyAI["kind"] = "test_selection"
	code, _ = doJSON(t, c, "POST", fmt.Sprintf("%s/api/runs/%d/analysis", ts.URL, runID), bodyAI)
	if code != http.StatusOK {
		t.Fatalf("save test_selection: got %d, want 200", code)
	}
	// RCA kinds still require an existing step_id.
	if code, _ := doJSON(t, c, "POST", fmt.Sprintf("%s/api/runs/%d/analysis", ts.URL, runID),
		map[string]any{"kind": "rule", "root_cause": "x"}); code != http.StatusBadRequest {
		t.Fatalf("rule without step_id: got %d, want 400", code)
	}
	code, out = doJSON(t, c, "GET", fmt.Sprintf("%s/api/runs/%d", ts.URL, runID), nil)
	if ana, _ := out["analysis"].(map[string]any); ana["kind"] != "llm" {
		t.Fatalf("primary analysis after AI kinds = %v, want llm", out["analysis"])
	}
	list, _ := out["analyses"].([]any)
	kinds := map[string]bool{}
	for _, e := range list {
		kinds[e.(map[string]any)["kind"].(string)] = true
	}
	if !kinds["rule"] || !kinds["llm"] || !kinds["pr_review"] || !kinds["test_selection"] {
		t.Fatalf("analyses kinds = %v, want rule+llm+pr_review+test_selection", kinds)
	}
}

func TestAPICancelWithoutAgent(t *testing.T) {
	ts, _ := newTestServer(t)
	c := ts.Client()
	createPipeline(t, c, ts.URL, "linear", linearYAML)

	runID := triggerRun(t, c, ts.URL, "linear")
	// No agent ever claims the job; the run stays running until canceled.
	code, _ := doJSON(t, c, "POST", fmt.Sprintf("%s/api/runs/%d/cancel", ts.URL, runID), nil)
	if code != http.StatusOK {
		t.Fatalf("cancel: got %d, want 200", code)
	}
	if status := waitForRunStatus(t, c, ts.URL, runID, store.RunCanceled); status != store.RunCanceled {
		t.Fatalf("run status = %q, want canceled", status)
	}

	// Canceling a finished/unknown run: finished -> 200 (no-op), unknown -> 404.
	if code, _ := doJSON(t, c, "POST", fmt.Sprintf("%s/api/runs/%d/cancel", ts.URL, runID), nil); code != http.StatusOK {
		t.Fatalf("cancel of finished run: got %d, want 200", code)
	}
	if code, _ := doJSON(t, c, "POST", ts.URL+"/api/runs/999999/cancel", nil); code != http.StatusNotFound {
		t.Fatalf("cancel unknown run: got %d, want 404", code)
	}
}

func TestAPIConcurrencyLimit(t *testing.T) {
	ts, _ := newTestServer(t)
	c := ts.Client()
	createPipeline(t, c, ts.URL, "slow", slowYAML)

	run1 := triggerRun(t, c, ts.URL, "slow")
	done1 := make(chan error, 1)
	go fakeAgent(t, c, ts.URL, "w1", run1, 400*time.Millisecond, done1) // slow agent

	// While run1 is in flight, a second trigger must hit the concurrency limit.
	if code, out := doJSON(t, c, "POST", ts.URL+"/api/pipelines/slow/trigger",
		map[string]string{"trigger": "manual"}); code != http.StatusConflict {
		t.Fatalf("second trigger: got %d %v, want 409 (limit)", code, out)
	}

	// After the first run finishes, a new trigger is accepted.
	waitForRunStatus(t, c, ts.URL, run1, store.RunSuccess)
	if err := <-done1; err != nil {
		t.Fatalf("fake agent run1: %v", err)
	}
	run2 := triggerRun(t, c, ts.URL, "slow")
	done2 := make(chan error, 1)
	go fakeAgent(t, c, ts.URL, "w1", run2, 0, done2)
	waitForRunStatus(t, c, ts.URL, run2, store.RunSuccess)
	if err := <-done2; err != nil {
		t.Fatalf("fake agent run2: %v", err)
	}
}

func TestAgentUnknownJobAndBadInput(t *testing.T) {
	ts, _ := newTestServer(t)
	c := ts.Client()

	// Finishing a job nobody claimed -> 404.
	if code, _ := doJSON(t, c, "POST", ts.URL+"/api/agent/jobs/999/ghost",
		map[string]string{"status": "success"}); code != http.StatusNotFound {
		t.Fatalf("finish unknown job: got %d, want 404", code)
	}
	// Invalid status value -> 400.
	if code, _ := doJSON(t, c, "POST", ts.URL+"/api/agent/jobs/999/ghost",
		map[string]string{"status": "maybe"}); code != http.StatusBadRequest {
		t.Fatalf("invalid status: got %d, want 400", code)
	}
	// Claim without agent param -> 400.
	if code, _ := doJSON(t, c, "GET", ts.URL+"/api/agent/jobs", nil); code != http.StatusBadRequest {
		t.Fatalf("claim without agent: got %d, want 400", code)
	}
	// Register with empty name -> 400.
	if code, _ := doJSON(t, c, "POST", ts.URL+"/api/agent/register",
		map[string]string{"name": ""}); code != http.StatusBadRequest {
		t.Fatalf("register empty name: got %d, want 400", code)
	}
	// Trigger of unknown pipeline -> 404.
	if code, _ := doJSON(t, c, "POST", ts.URL+"/api/pipelines/ghost/trigger", nil); code != http.StatusNotFound {
		t.Fatalf("trigger unknown pipeline: got %d, want 404", code)
	}
}

func TestAPISSEStream(t *testing.T) {
	ts, _ := newTestServer(t)
	c := ts.Client()
	createPipeline(t, c, ts.URL, "linear", linearYAML)

	// Delayed agent: guarantees the run is still in flight when the SSE
	// connection opens below, so all events are delivered live.
	runID := triggerRun(t, c, ts.URL, "linear")
	done := make(chan error, 1)
	go fakeAgent(t, c, ts.URL, "worker-1", runID, 300*time.Millisecond, done)

	resp, err := c.Get(fmt.Sprintf("%s/api/runs/%d/events", ts.URL, runID))
	if err != nil {
		t.Fatalf("open SSE: %v", err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("SSE content-type = %q", ct)
	}

	br := bufio.NewReader(resp.Body)
	deadline := time.Now().Add(10 * time.Second)
	var sawSnapshot, sawStepStarted, sawRunFinished bool
readLoop:
	for {
		if time.Now().After(deadline) {
			t.Fatalf("SSE timed out; saw snapshot=%v step=%v finished=%v",
				sawSnapshot, sawStepStarted, sawRunFinished)
		}
		line, err := br.ReadString('\n')
		if err != nil {
			if strings.Contains(line, `"type":"run.finished"`) {
				sawRunFinished = true
			}
			break // stream closed by server after run.finished
		}
		switch {
		case strings.Contains(line, `"type":"snapshot"`):
			sawSnapshot = true
		case strings.Contains(line, `"type":"step.started"`):
			sawStepStarted = true
		case strings.Contains(line, `"type":"run.finished"`):
			sawRunFinished = true
			break readLoop
		}
	}
	if !sawSnapshot {
		t.Error("SSE did not deliver an initial snapshot")
	}
	if !sawStepStarted {
		t.Error("SSE did not deliver a step.started event")
	}
	if !sawRunFinished {
		t.Error("SSE did not deliver run.finished")
	}
	if err := <-done; err != nil {
		t.Fatalf("fake agent reported error: %v", err)
	}
}
