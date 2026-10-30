// Task ⑨ P1: request-body caps. Every JSON endpoint that used to read
// r.Body unbounded now caps the body and answers 413 "body too large" on
// overflow; small valid bodies are unaffected.
package api

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// postRaw POSTs a raw body and returns (status, response text).
func postRaw(t *testing.T, c *http.Client, url, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp.StatusCode, string(b)
}

// TestRequestBodyCaps413 is the table-driven over-cap test: each of the six
// previously-unbounded JSON endpoints must answer 413 "body too large", and
// the audited ones (pipelines / canaries / trigger) must log an
// outcome=invalid audit event on the 413 path.
func TestRequestBodyCaps413(t *testing.T) {
	a := strings.Repeat("a", 1)
	cases := []struct {
		name   string
		path   string
		body   string
		setup  func(t *testing.T, srv *Server)
		action string // audit action expected on the 413 path ("" = none)
	}{
		{
			name:   "pipelines",
			path:   "/api/pipelines",
			body:   `{"name":"cap","yaml":"` + strings.Repeat(a, maxPipelineBody+1) + `"}`,
			action: AuditPipelineUpsert,
		},
		{
			name:   "canaries",
			path:   "/api/canaries",
			body:   `{"stable_image":"` + strings.Repeat(a, maxCanaryBody+1) + `"}`,
			action: AuditCanaryCreate,
		},
		{
			name: "trigger",
			path: "/api/pipelines/captest/trigger",
			body: `{"trigger":"manual","source_ref":"` + strings.Repeat(a, maxTriggerBody+1) + `"}`,
			setup: func(t *testing.T, srv *Server) {
				if _, err := srv.Store.UpsertPipeline("captest", linearYAML); err != nil {
					t.Fatalf("seed pipeline: %v", err)
				}
			},
			action: AuditRunTrigger,
		},
		{
			name: "agent register",
			path: "/api/agent/register",
			body: `{"name":"` + strings.Repeat(a, maxAgentRegisterBody+1) + `"}`,
		},
		{
			name: "agent logs",
			path: "/api/agent/jobs/1/s1/logs",
			body: `{"lines":["` + strings.Repeat(a, maxAgentLogsBody+1) + `"]}`,
		},
		{
			name: "agent finish",
			path: "/api/agent/jobs/1/s1",
			body: `{"status":"success","outputs":{"k":"` + strings.Repeat(a, maxAgentFinishBody+1) + `"}}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts, srv := newTestServer(t)
			if tc.setup != nil {
				tc.setup(t, srv)
			}
			code, text := postRaw(t, ts.Client(), ts.URL+tc.path, tc.body)
			if code != http.StatusRequestEntityTooLarge {
				t.Fatalf("got %d, want 413 (body=%s)", code, text)
			}
			if !strings.Contains(text, "body too large") {
				t.Errorf("body %q, want it to contain %q", text, "body too large")
			}
			if tc.action != "" {
				ev := latestAudit(t, srv.Store, tc.action)
				if ev.Outcome != OutcomeInvalid {
					t.Errorf("audit outcome %q, want %q", ev.Outcome, OutcomeInvalid)
				}
				if ev.Detail != "body too large" {
					t.Errorf("audit detail %q, want %q", ev.Detail, "body too large")
				}
			}
		})
	}
}

// TestRequestBodyCapsHappyPath pins the in-cap behaviour: normal-sized bodies
// on the same endpoints still work (no accidental cap regression).
func TestRequestBodyCapsHappyPath(t *testing.T) {
	ts, _ := newTestServer(t)
	c := ts.Client()
	// pipelines: a normal-sized body still creates (201).
	code, out := doJSON(t, c, "POST", ts.URL+"/api/pipelines",
		map[string]string{"name": "cap-ok", "yaml": linearYAML})
	if code != http.StatusCreated {
		t.Fatalf("pipelines: got %d, want 201 (body=%v)", code, out)
	}
	// trigger: a normal-sized body still triggers (202).
	code, out = doJSON(t, c, "POST", ts.URL+"/api/pipelines/cap-ok/trigger",
		map[string]string{"trigger": "manual"})
	if code != http.StatusAccepted {
		t.Fatalf("trigger: got %d, want 202 (body=%v)", code, out)
	}
	// canaries: a normal-sized body still creates (201).
	code, out = doJSON(t, c, "POST", ts.URL+"/api/canaries", map[string]any{
		"name": "capok", "stable_image": "nginx:1.27", "canary_image": "nginx:1.28",
	})
	if code != http.StatusCreated {
		t.Fatalf("canaries: got %d, want 201 (body=%v)", code, out)
	}
	// agent register: a normal-sized body still registers (200).
	code, out = doJSON(t, c, "POST", ts.URL+"/api/agent/register",
		map[string]string{"name": "cap-ok-agent"})
	if code != http.StatusOK {
		t.Fatalf("agent register: got %d, want 200 (body=%v)", code, out)
	}
}
