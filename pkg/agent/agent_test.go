package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/flowstallion/flowstallion/pkg/api"
)

// ---------------------------------------------------------------------------
// Fake docker
// ---------------------------------------------------------------------------

type fakeDocker struct {
	mu       sync.Mutex
	runErr   error
	execOuts []string
	execErrs []error
	calls    []string // "run:name" / "exec:name:cmd" / "remove:name"
	execIdx  int
}

func (f *fakeDocker) record(c string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, c)
}

func (f *fakeDocker) Run(_ context.Context, name, _ string, _ map[string]string) error {
	f.record("run:" + name)
	return f.runErr
}

func (f *fakeDocker) Exec(_ context.Context, name, command string) (string, error) {
	f.record("exec:" + name + ":" + command)
	f.mu.Lock()
	i := f.execIdx
	f.execIdx++
	f.mu.Unlock()
	out := ""
	var err error
	if i < len(f.execOuts) {
		out = f.execOuts[i]
	}
	if i < len(f.execErrs) {
		err = f.execErrs[i]
	}
	return out, err
}

func (f *fakeDocker) Remove(_ context.Context, name string) error {
	f.record("remove:" + name)
	return nil
}

func (f *fakeDocker) callList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.calls))
	copy(out, f.calls)
	return out
}

// slowDocker blocks Exec until the context is cancelled (simulates a hung
// command so the per-step timeout path can be exercised quickly).
type slowDocker struct {
	fakeDocker
}

func (s *slowDocker) Exec(ctx context.Context, name, command string) (string, error) {
	s.record("exec:" + name + ":" + command)
	<-ctx.Done()
	return "", ctx.Err()
}

// fakeHost implements HostDocker for testing docker_build steps.
type fakeHost struct {
	mu       sync.Mutex
	buildOut string
	buildErr error
	pushErr  error
	loginErr error
	calls    []string // "build:tag:dockerfile:ctx" / "push:ref" / "login:reg:user"
}

func (f *fakeHost) record(c string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, c)
}

func (f *fakeHost) Build(_ context.Context, tag, dockerfile, ctxDir string) (string, error) {
	f.record("build:" + tag + ":" + dockerfile + ":" + ctxDir)
	return f.buildOut, f.buildErr
}

func (f *fakeHost) Push(_ context.Context, ref string) error {
	f.record("push:" + ref)
	return f.pushErr
}

func (f *fakeHost) Login(_ context.Context, registry, user, _ string) error {
	f.record("login:" + registry + ":" + user)
	return f.loginErr
}

func (f *fakeHost) callList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.calls))
	copy(out, f.calls)
	return out
}

// ---------------------------------------------------------------------------
// Fake scheduler (agent endpoints only)
// ---------------------------------------------------------------------------

type fakeScheduler struct {
	mu         sync.Mutex
	registered string
	job        *api.Job
	logs       [][]string
	finished   []string // "status|message"
	outputs    []string // raw JSON of outputs per finish (P7④)
	reqTokens  []string // "path|token" per request; empty token = header not sent
}

func newFakeScheduler(job *api.Job) *fakeScheduler {
	return &fakeScheduler{job: job}
}

// recordToken appends "path|token" for the request. The token part is empty
// when the X-Agent-Token header is not present (r.Header.Values returns an
// empty slice for absent keys).
func (s *fakeScheduler) recordToken(r *http.Request) {
	vals := r.Header.Values("X-Agent-Token")
	tok := ""
	if len(vals) > 0 {
		tok = strings.Join(vals, ",")
	}
	s.mu.Lock()
	s.reqTokens = append(s.reqTokens, r.URL.Path+"|"+tok)
	s.mu.Unlock()
}

func (s *fakeScheduler) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/agent/register", func(w http.ResponseWriter, r *http.Request) {
		s.recordToken(r)
		var body struct {
			Name string `json:"name"`
		}
		_ = jsonDecode(r, &body)
		s.mu.Lock()
		s.registered = body.Name
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"agent_id":1,"created":true}`)
	})
	mux.HandleFunc("/api/agent/jobs", func(w http.ResponseWriter, r *http.Request) {
		s.recordToken(r)
		s.mu.Lock()
		job := s.job
		s.job = nil // consumed on first claim
		s.mu.Unlock()
		if job == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"job":%s}`, jobJSON(job))
	})
	mux.HandleFunc("/api/agent/jobs/", func(w http.ResponseWriter, r *http.Request) {
		s.recordToken(r)
		// /api/agent/jobs/{runID}/{stepID} or /api/agent/jobs/{runID}/{stepID}/logs
		rest := strings.TrimPrefix(r.URL.Path, "/api/agent/jobs/")
		parts := strings.Split(rest, "/")
		if len(parts) != 2 && len(parts) != 3 {
			http.Error(w, "bad path", http.StatusBadRequest)
			return
		}
		if len(parts) == 3 && parts[2] == "logs" {
			var body struct {
				Lines []string `json:"lines"`
			}
			_ = jsonDecode(r, &body)
			s.mu.Lock()
			s.logs = append(s.logs, body.Lines)
			s.mu.Unlock()
			fmt.Fprintf(w, `{"stored":%d}`, len(body.Lines))
			return
		}
		var body struct {
			Status  string            `json:"status"`
			Message string            `json:"message"`
			Outputs map[string]string `json:"outputs"`
		}
		_ = jsonDecode(r, &body)
		s.mu.Lock()
		s.finished = append(s.finished, body.Status+"|"+body.Message)
		if body.Outputs != nil {
			raw, _ := json.Marshal(body.Outputs)
			s.outputs = append(s.outputs, string(raw))
		}
		s.mu.Unlock()
		fmt.Fprint(w, `{"ok":true}`)
	})
	return mux
}

// waitFor polls cond until true or the timeout elapses.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", timeout)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// startAgent runs agent.Run in a goroutine and returns a cancel func.
func startAgent(t *testing.T, srv *httptest.Server, d Docker, name string) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		a := &Agent{Name: name, Server: srv.URL, Docker: d, Poll: 10 * time.Millisecond}
		if err := a.Run(ctx); err != nil && ctx.Err() == nil {
			// Agent exited on its own with an error before cancellation.
			t.Errorf("agent.Run returned early: %v", err)
		}
	}()
	return cancel
}

// startAgentWithHost is startAgent but also sets the Host field for
// docker_build tests.
func startAgentWithHost(t *testing.T, srv *httptest.Server, d Docker, h HostDocker, name string) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		a := &Agent{Name: name, Server: srv.URL, Docker: d, Host: h, Poll: 10 * time.Millisecond}
		if err := a.Run(ctx); err != nil && ctx.Err() == nil {
			t.Errorf("agent.Run returned early: %v", err)
		}
	}()
	return cancel
}

func TestAgentHappyPath(t *testing.T) {
	job := &api.Job{
		RunID:    7,
		StepID:   "build",
		Image:    "alpine:3.20",
		Commands: []string{"echo hello", "echo world"},
		Env:      map[string]string{"FOO": "bar"},
		TimeoutS: 60,
	}
	fs := newFakeScheduler(job)
	srv := httptest.NewServer(fs.handler())
	defer srv.Close()

	d := &fakeDocker{execOuts: []string{"hello\n", "world\n"}}
	cancel := startAgent(t, srv, d, "agent-1")
	defer cancel()

	waitFor(t, 5*time.Second, func() bool {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		return len(fs.finished) == 1
	})

	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.registered != "agent-1" {
		t.Errorf("registered = %q, want agent-1", fs.registered)
	}
	if len(fs.finished) != 1 || !strings.HasPrefix(fs.finished[0], "success|") {
		t.Fatalf("finished = %v, want one success entry", fs.finished)
	}
	got := strings.Join(append([]string{}, flattenLogs(fs.logs)...), "\n")
	if !strings.Contains(got, "hello") || !strings.Contains(got, "world") {
		t.Errorf("logs = %q, want to contain hello and world", got)
	}

	calls := d.callList()
	if !contains(calls, "run:flowstallion-7-build") {
		t.Errorf("calls = %v, want run:flowstallion-7-build", calls)
	}
	if !contains(calls, "exec:flowstallion-7-build:echo hello") || !contains(calls, "exec:flowstallion-7-build:echo world") {
		t.Errorf("calls = %v, want both execs", calls)
	}
	if !contains(calls, "remove:flowstallion-7-build") {
		t.Errorf("calls = %v, want remove:flowstallion-7-build (cleanup)", calls)
	}
}

func TestAgentFailedCommand(t *testing.T) {
	job := &api.Job{
		RunID:    8,
		StepID:   "test",
		Image:    "alpine:3.20",
		Commands: []string{"echo ok", "false"},
	}
	fs := newFakeScheduler(job)
	srv := httptest.NewServer(fs.handler())
	defer srv.Close()

	d := &fakeDocker{
		execOuts: []string{"ok\n", "boom\n"},
		execErrs: []error{nil, errors.New("exit status 1")},
	}
	cancel := startAgent(t, srv, d, "agent-2")
	defer cancel()

	waitFor(t, 5*time.Second, func() bool {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		return len(fs.finished) == 1
	})

	fs.mu.Lock()
	defer fs.mu.Unlock()
	if len(fs.finished) != 1 {
		t.Fatalf("finished = %v, want 1", fs.finished)
	}
	entry := fs.finished[0]
	if !strings.HasPrefix(entry, "failed|") {
		t.Errorf("finished[0] = %q, want failed prefix", entry)
	}
	if !strings.Contains(entry, `"false"`) {
		t.Errorf("message = %q, want to mention failing command", entry)
	}
}

func TestAgentContainerCreateFailure(t *testing.T) {
	job := &api.Job{RunID: 9, StepID: "deploy", Image: "nope:latest", Commands: []string{"true"}}
	fs := newFakeScheduler(job)
	srv := httptest.NewServer(fs.handler())
	defer srv.Close()

	d := &fakeDocker{runErr: errors.New("image not found")}
	cancel := startAgent(t, srv, d, "agent-3")
	defer cancel()

	waitFor(t, 5*time.Second, func() bool {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		return len(fs.finished) == 1
	})

	fs.mu.Lock()
	defer fs.mu.Unlock()
	if len(fs.finished) != 1 || !strings.HasPrefix(fs.finished[0], "failed|") {
		t.Fatalf("finished = %v, want one failed entry", fs.finished)
	}
	if !strings.Contains(fs.finished[0], "create container") {
		t.Errorf("message = %q, want create-container error", fs.finished[0])
	}
	// No exec should have happened.
	for _, c := range d.callList() {
		if strings.HasPrefix(c, "exec:") {
			t.Errorf("unexpected exec call %q after container creation failure", c)
		}
	}
}

func TestAgentStepTimeout(t *testing.T) {
	job := &api.Job{
		RunID:    10,
		StepID:   "long",
		Image:    "alpine:3.20",
		Commands: []string{"sleep 30"},
		TimeoutS: 1,
	}
	fs := newFakeScheduler(job)
	srv := httptest.NewServer(fs.handler())
	defer srv.Close()

	d := &slowDocker{}
	cancel := startAgent(t, srv, d, "agent-4")
	defer cancel()

	waitFor(t, 10*time.Second, func() bool {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		return len(fs.finished) == 1
	})

	fs.mu.Lock()
	defer fs.mu.Unlock()
	if len(fs.finished) != 1 || !strings.HasPrefix(fs.finished[0], "failed|") {
		t.Fatalf("finished = %v, want one failed entry", fs.finished)
	}
	if !strings.Contains(fs.finished[0], "timed out") {
		t.Errorf("message = %q, want timeout message", fs.finished[0])
	}
}

func TestAgentClaimEmpty(t *testing.T) {
	// No job queued: agent should keep polling without error.
	fs := newFakeScheduler(nil)
	srv := httptest.NewServer(fs.handler())
	defer srv.Close()

	d := &fakeDocker{}
	cancel := startAgent(t, srv, d, "agent-5")
	defer cancel()

	time.Sleep(150 * time.Millisecond) // let several polls happen
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.registered != "agent-5" {
		t.Errorf("registered = %q, want agent-5", fs.registered)
	}
	if len(fs.finished) != 0 {
		t.Errorf("finished = %v, want none", fs.finished)
	}
}

// TestAgentDockerBuildPush: docker_build step runs on the host (no container),
// builds, logs, logs in (creds from env), pushes, and reports image_ref.
func TestAgentDockerBuildPush(t *testing.T) {
	job := &api.Job{
		RunID:      21,
		StepID:     "build",
		StepType:   "docker_build",
		Image:      "reg.io/app:abc123",
		Dockerfile: "Dockerfile.app",
		Context:    "svc",
		Push:       true,
		Env:        map[string]string{"REGISTRY_USER": "u", "REGISTRY_PASSWORD": "p"},
		TimeoutS:   60,
	}
	fs := newFakeScheduler(job)
	srv := httptest.NewServer(fs.handler())
	defer srv.Close()

	d := &fakeDocker{}
	h := &fakeHost{buildOut: "built ok\n"}
	cancel := startAgentWithHost(t, srv, d, h, "agent-db")
	defer cancel()

	waitFor(t, 5*time.Second, func() bool {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		return len(fs.finished) == 1
	})

	fs.mu.Lock()
	defer fs.mu.Unlock()
	if len(fs.finished) != 1 || !strings.HasPrefix(fs.finished[0], "success|") {
		t.Fatalf("finished = %v, want one success entry", fs.finished)
	}
	if len(fs.outputs) != 1 || fs.outputs[0] != `{"image_ref":"reg.io/app:abc123"}` {
		t.Fatalf("outputs = %v, want image_ref", fs.outputs)
	}
	hc := h.callList()
	if !contains(hc, "build:reg.io/app:abc123:Dockerfile.app:svc") {
		t.Errorf("host calls = %v, want build call", hc)
	}
	if !contains(hc, "login:reg.io:u") {
		t.Errorf("host calls = %v, want login to reg.io", hc)
	}
	if !contains(hc, "push:reg.io/app:abc123") {
		t.Errorf("host calls = %v, want push", hc)
	}
	// No container operations for a docker_build step.
	if got := d.callList(); len(got) != 0 {
		t.Errorf("container calls = %v, want none for docker_build", got)
	}
}

// TestAgentDockerBuildNoPush: push=false skips login/push but still reports
// the image_ref output.
func TestAgentDockerBuildNoPush(t *testing.T) {
	job := &api.Job{
		RunID: 22, StepID: "build", StepType: "docker_build",
		Image: "reg.io/app:22", Dockerfile: "Dockerfile", Context: ".",
	}
	fs := newFakeScheduler(job)
	srv := httptest.NewServer(fs.handler())
	defer srv.Close()

	h := &fakeHost{}
	cancel := startAgentWithHost(t, srv, &fakeDocker{}, h, "agent-db2")
	defer cancel()

	waitFor(t, 5*time.Second, func() bool {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		return len(fs.finished) == 1
	})
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if !strings.HasPrefix(fs.finished[0], "success|") {
		t.Fatalf("finished = %v, want success", fs.finished)
	}
	if fs.outputs[0] != `{"image_ref":"reg.io/app:22"}` {
		t.Errorf("outputs = %v, want image_ref", fs.outputs)
	}
	for _, c := range h.callList() {
		if strings.HasPrefix(c, "login:") || strings.HasPrefix(c, "push:") {
			t.Errorf("unexpected host call %q when push=false", c)
		}
	}
}

// TestAgentDockerBuildFailure: build error -> failed, no outputs, no push.
func TestAgentDockerBuildFailure(t *testing.T) {
	job := &api.Job{
		RunID: 23, StepID: "build", StepType: "docker_build",
		Image: "reg.io/app:23", Push: true,
		Env: map[string]string{"REGISTRY_USER": "u", "REGISTRY_PASSWORD": "p"},
	}
	fs := newFakeScheduler(job)
	srv := httptest.NewServer(fs.handler())
	defer srv.Close()

	h := &fakeHost{buildErr: errors.New("exit status 1: bad dockerfile")}
	cancel := startAgentWithHost(t, srv, &fakeDocker{}, h, "agent-db3")
	defer cancel()

	waitFor(t, 5*time.Second, func() bool {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		return len(fs.finished) == 1
	})
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if len(fs.finished) != 1 || !strings.HasPrefix(fs.finished[0], "failed|docker build:") {
		t.Fatalf("finished = %v, want failed docker build", fs.finished)
	}
	if len(fs.outputs) != 0 {
		t.Errorf("outputs = %v, want none on failure", fs.outputs)
	}
	for _, c := range h.callList() {
		if strings.HasPrefix(c, "push:") {
			t.Errorf("unexpected push after build failure: %v", h.callList())
		}
	}
}

// TestAgentDockerPushFailure: push error -> failed with push message.
func TestAgentDockerPushFailure(t *testing.T) {
	job := &api.Job{
		RunID: 24, StepID: "build", StepType: "docker_build",
		Image: "reg.io/app:24", Push: true,
		Env: map[string]string{"REGISTRY_USER": "u", "REGISTRY_PASSWORD": "p"},
	}
	fs := newFakeScheduler(job)
	srv := httptest.NewServer(fs.handler())
	defer srv.Close()

	h := &fakeHost{pushErr: errors.New("denied: rate limit")}
	cancel := startAgentWithHost(t, srv, &fakeDocker{}, h, "agent-db4")
	defer cancel()

	waitFor(t, 5*time.Second, func() bool {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		return len(fs.finished) == 1
	})
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if len(fs.finished) != 1 || !strings.HasPrefix(fs.finished[0], "failed|docker push:") {
		t.Fatalf("finished = %v, want failed docker push", fs.finished)
	}
}

// TestAgentRetriesRegister: the scheduler may not be listening when the agent
// starts (local-first: agent before server). Registration must retry instead
// of exiting; once the server comes up, the agent connects and runs jobs.
func TestAgentRetriesRegister(t *testing.T) {
	job := &api.Job{RunID: 31, StepID: "s1", Image: "alpine",
		Commands: []string{"echo retry-register"}, TimeoutS: 10}
	fs := newFakeScheduler(job)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		a := &Agent{Name: "retry-agent", Server: "http://" + addr,
			Docker: &fakeDocker{}, Poll: 10 * time.Millisecond,
			RegPoll: 50 * time.Millisecond}
		_ = a.Run(ctx)
	}()

	time.Sleep(300 * time.Millisecond) // let the agent fail register a few times
	srv := &http.Server{Addr: addr, Handler: fs.handler()}
	ln2, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("bind %s: %v", addr, err)
	}
	go srv.Serve(ln2)
	t.Cleanup(func() { srv.Close() })

	waitFor(t, 8*time.Second, func() bool {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		return len(fs.finished) == 1
	})
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if len(fs.finished) != 1 || !strings.HasPrefix(fs.finished[0], "success|") {
		t.Fatalf("agent did not recover and run job: finished=%v registered=%q",
			fs.finished, fs.registered)
	}
	if fs.registered != "retry-agent" {
		t.Errorf("registered = %q, want retry-agent", fs.registered)
	}
}

// TestAgentSendsAgentToken: with AgentToken configured, every scheduler
// request (register, claim, logs, finish) carries X-Agent-Token.
func TestAgentSendsAgentToken(t *testing.T) {
	job := &api.Job{
		RunID:    32,
		StepID:   "s1",
		Image:    "alpine:3.20",
		Commands: []string{"echo tok"},
	}
	fs := newFakeScheduler(job)
	srv := httptest.NewServer(fs.handler())
	defer srv.Close()

	d := &fakeDocker{execOuts: []string{"tok\n"}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		a := &Agent{Name: "tok-agent", Server: srv.URL, Docker: d,
			AgentToken: "tok-abc", Poll: 10 * time.Millisecond}
		if err := a.Run(ctx); err != nil && ctx.Err() == nil {
			t.Errorf("agent.Run returned early: %v", err)
		}
	}()

	waitFor(t, 5*time.Second, func() bool {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		return len(fs.finished) == 1
	})

	fs.mu.Lock()
	defer fs.mu.Unlock()
	if len(fs.reqTokens) == 0 {
		t.Fatal("no requests recorded")
	}
	seen := map[string]bool{}
	for _, rec := range fs.reqTokens {
		path, tok, ok := strings.Cut(rec, "|")
		if !ok {
			t.Fatalf("malformed record %q", rec)
		}
		seen[path] = true
		if tok != "tok-abc" {
			t.Errorf("request %s: X-Agent-Token = %q, want tok-abc", path, tok)
		}
	}
	for _, p := range []string{
		"/api/agent/register",
		"/api/agent/jobs",
		"/api/agent/jobs/32/s1/logs",
		"/api/agent/jobs/32/s1",
	} {
		if !seen[p] {
			t.Errorf("no recorded request for %s (records: %v)", p, fs.reqTokens)
		}
	}
}

// TestAgentNoTokenHeaderWhenUnset: without AgentToken the agent must not send
// X-Agent-Token at all (header absent, not present-but-empty).
func TestAgentNoTokenHeaderWhenUnset(t *testing.T) {
	job := &api.Job{
		RunID:    33,
		StepID:   "s1",
		Image:    "alpine:3.20",
		Commands: []string{"echo notok"},
	}
	fs := newFakeScheduler(job)
	srv := httptest.NewServer(fs.handler())
	defer srv.Close()

	d := &fakeDocker{execOuts: []string{"notok\n"}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		a := &Agent{Name: "notok-agent", Server: srv.URL, Docker: d,
			Poll: 10 * time.Millisecond}
		if err := a.Run(ctx); err != nil && ctx.Err() == nil {
			t.Errorf("agent.Run returned early: %v", err)
		}
	}()

	waitFor(t, 5*time.Second, func() bool {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		return len(fs.finished) == 1
	})

	fs.mu.Lock()
	defer fs.mu.Unlock()
	if len(fs.reqTokens) == 0 {
		t.Fatal("no requests recorded")
	}
	for _, rec := range fs.reqTokens {
		path, tok, ok := strings.Cut(rec, "|")
		if !ok {
			t.Fatalf("malformed record %q", rec)
		}
		if tok != "" {
			t.Errorf("request %s: X-Agent-Token present = %q, want header absent", path, tok)
		}
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func flattenLogs(batches [][]string) []string {
	var out []string
	for _, b := range batches {
		out = append(out, b...)
	}
	return out
}

// jobJSON serializes a job for the fake scheduler's claim response.
func jobJSON(j *api.Job) string {
	b, err := json.Marshal(j)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func jsonDecode(r *http.Request, v any) error {
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
