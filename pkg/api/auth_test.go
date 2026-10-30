package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/flowstallion/flowstallion/pkg/auth"
	"github.com/flowstallion/flowstallion/pkg/cd"
	"github.com/flowstallion/flowstallion/pkg/scheduler"
	"github.com/flowstallion/flowstallion/pkg/secret"
	"github.com/flowstallion/flowstallion/pkg/store"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// fakeKubectl answers every kubectl call with success so the RBAC matrix can
// exercise the operator canary-rollback path without a cluster.
type fakeKubectl struct{}

func (fakeKubectl) Run(args []string, stdin string) (string, error) { return "", nil }

// newAuthServer builds a fully wired API server with auth enabled and
// seeded users (admin / operator / viewer). Agent token: "agent-secret".
// It also wires a test vault and a canary controller with a fake kubectl so
// the matrix's admin/operator success rows reach handler logic instead of
// 503-ing on missing infrastructure.
func newAuthServer(t *testing.T) *httptest.Server {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	disp := NewDispatcher()
	sched := scheduler.New(st, &AgentExecutor{D: disp})
	srv := New(st, sched, disp)
	srv.Auth = auth.New(st, true, time.Hour, "agent-secret")
	// m3: wire a vault and a k8s controller so the matrix's admin/operator
	// success rows (secrets upsert, canary rollback) reach the handler logic
	// instead of 503-ing on missing infrastructure.
	vault, err := secret.New(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	srv.Vault = vault
	srv.CanaryCtl = cd.NewController(st, fakeKubectl{})
	seedUsers(t, st)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

// newPlainServer builds a server with auth disabled (pre-P6 behaviour).
func newPlainServer(t *testing.T) *httptest.Server {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "plain.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	disp := NewDispatcher()
	sched := scheduler.New(st, &AgentExecutor{D: disp})
	srv := New(st, sched, disp)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func seedUsers(t *testing.T, st *store.Store) {
	t.Helper()
	for _, u := range []struct{ name, pw, role string }{
		{"admin", "admin-pass-1", "admin"},
		{"operator", "operator-pass-1", "operator"},
		{"viewer", "viewer-pass-1", "viewer"},
	} {
		hash, err := auth.HashPassword(u.pw)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.CreateUser(u.name, hash, u.role); err != nil {
			t.Fatal(err)
		}
	}
}

// doReq performs an HTTP request and returns (status, body).
func doReq(t *testing.T, method, url string, token, agentToken string, body any) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if agentToken != "" {
		req.Header.Set("X-Agent-Token", agentToken)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("doReq %s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

// loginToken obtains a session token for user/pass via the HTTP login endpoint.
func loginToken(t *testing.T, ts *httptest.Server, user, pass string) string {
	t.Helper()
	code, data := doReq(t, "POST", ts.URL+"/api/auth/login", "", "",
		map[string]string{"username": user, "password": pass})
	if code != http.StatusOK {
		t.Fatalf("login %s: got %d, want 200 (body=%s)", user, code, string(data))
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(data, &out); err != nil || out.Token == "" {
		t.Fatalf("login response has no token: %s", string(data))
	}
	return out.Token
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestAuthLoginFlow covers the full login -> me -> logout cycle.
func TestAuthLoginFlow(t *testing.T) {
	ts := newAuthServer(t)

	// bad password
	code, _ := doReq(t, "POST", ts.URL+"/api/auth/login", "", "",
		map[string]string{"username": "admin", "password": "wrong"})
	if code != http.StatusUnauthorized {
		t.Errorf("bad password: got %d, want 401", code)
	}
	// unknown user
	code, _ = doReq(t, "POST", ts.URL+"/api/auth/login", "", "",
		map[string]string{"username": "ghost", "password": "whatever123"})
	if code != http.StatusUnauthorized {
		t.Errorf("unknown user: got %d, want 401", code)
	}
	// good login
	tok := loginToken(t, ts, "admin", "admin-pass-1")

	// /me
	code, data := doReq(t, "GET", ts.URL+"/api/auth/me", tok, "", nil)
	if code != http.StatusOK {
		t.Fatalf("/me: got %d, want 200", code)
	}
	var me map[string]any
	json.Unmarshal(data, &me)
	if me["username"] != "admin" || me["role"] != "admin" {
		t.Errorf("/me: got %v, want admin/admin", me)
	}

	// logout
	code, _ = doReq(t, "POST", ts.URL+"/api/auth/logout", tok, "", nil)
	if code != http.StatusOK {
		t.Errorf("logout: got %d, want 200", code)
	}
	// /me again -> 401 (session invalidated)
	code, _ = doReq(t, "GET", ts.URL+"/api/auth/me", tok, "", nil)
	if code != http.StatusUnauthorized {
		t.Errorf("/me after logout: got %d, want 401", code)
	}
}

// holdYAML produces a run that is held in pending_approval at the default
// L2 autonomy (production deploy step), so approve/reject have valid targets.
const holdYAML = `
version: 1
pipeline:
  name: rbac-hold
  env:
    environment: production
  steps:
    - id: deploy-prod
      image: alpine
      commands:
        - echo deploy
`

// TestRBACMatrix is a table-driven test of the role gate.
// want: 401 (no/invalid token), 403 (role insufficient), or the exact success
// code for allowed calls.
func TestRBACMatrix(t *testing.T) {
	ts := newAuthServer(t)

	adminTok := loginToken(t, ts, "admin", "admin-pass-1")
	opTok := loginToken(t, ts, "operator", "operator-pass-1")
	viewTok := loginToken(t, ts, "viewer", "viewer-pass-1")

	// Seed a pipeline + a run so trigger/cancel have valid targets.
	code, _ := doReq(t, "POST", ts.URL+"/api/pipelines", adminTok, "",
		map[string]string{"name": "rbac", "yaml": linearYAML})
	if code != http.StatusCreated {
		t.Fatalf("admin create pipeline: got %d, want 201", code)
	}
	code, data := doReq(t, "POST", ts.URL+"/api/pipelines/rbac/trigger", adminTok, "",
		map[string]string{"trigger": "manual"})
	if code != http.StatusAccepted {
		t.Fatalf("admin trigger: got %d, want 202 (body=%s)", code, string(data))
	}
	var tr struct {
		RunID int64 `json:"run_id"`
	}
	json.Unmarshal(data, &tr)
	cancelPath := "/api/runs/" + itoa(tr.RunID) + "/cancel"

	// m3: held-run targets for approve/reject. The production deploy step in
	// holdYAML holds runs in pending_approval under the default L2 autonomy.
	code, _ = doReq(t, "POST", ts.URL+"/api/pipelines", adminTok, "",
		map[string]string{"name": "rbac-hold", "yaml": holdYAML})
	if code != http.StatusCreated {
		t.Fatalf("create rbac-hold: got %d, want 201", code)
	}
	var holdRunIDs [2]int64
	for i := range holdRunIDs {
		code, data = doReq(t, "POST", ts.URL+"/api/pipelines/rbac-hold/trigger", adminTok, "",
			map[string]string{"trigger": "manual"})
		if code != http.StatusAccepted {
			t.Fatalf("trigger rbac-hold #%d: got %d, want 202 (body=%s)", i+1, code, string(data))
		}
		var tr2 struct {
			RunID int64 `json:"run_id"`
		}
		if err := json.Unmarshal(data, &tr2); err != nil {
			t.Fatalf("trigger response %s: %v", data, err)
		}
		holdRunIDs[i] = tr2.RunID
	}
	approvePath := "/api/runs/" + itoa(holdRunIDs[0]) + "/approve"
	rejectPath := "/api/runs/" + itoa(holdRunIDs[1]) + "/reject"

	// m3: canary + secret targets for admin/operator success rows.
	code, data = doReq(t, "POST", ts.URL+"/api/canaries", opTok, "", validCanaryBody("rbac-can"))
	if code != http.StatusCreated {
		t.Fatalf("create rbac-can: got %d, want 201 (body=%s)", code, string(data))
	}
	var canary struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(data, &canary); err != nil {
		t.Fatalf("canary response %s: %v", data, err)
	}
	rollbackPath := "/api/canaries/" + itoa(canary.ID) + "/rollback"

	code, _ = doReq(t, "POST", ts.URL+"/api/secrets", adminTok, "",
		map[string]string{"name": "rbac-secret", "value": "matrix-test"})
	if code != http.StatusOK {
		t.Fatalf("create rbac-secret: got %d, want 200", code)
	}

	cases := []struct {
		name   string
		method string
		path   string
		token  string
		body   any
		want   int
	}{
		// open endpoints
		{"healthz, no token", "GET", "/healthz", "", nil, http.StatusOK},
		// no token -> 401
		{"list pipelines, no token", "GET", "/api/pipelines", "", nil, http.StatusUnauthorized},
		{"create pipeline, no token", "POST", "/api/pipelines", "", map[string]string{"name": "x", "yaml": linearYAML}, http.StatusUnauthorized},
		// viewer: reads ok, writes denied
		{"viewer list pipelines", "GET", "/api/pipelines", viewTok, nil, http.StatusOK},
		{"viewer list runs", "GET", "/api/runs", viewTok, nil, http.StatusOK},
		{"viewer create pipeline", "POST", "/api/pipelines", viewTok, map[string]string{"name": "x", "yaml": linearYAML}, http.StatusForbidden},
		{"viewer trigger", "POST", "/api/pipelines/rbac/trigger", viewTok, map[string]string{"trigger": "manual"}, http.StatusForbidden},
		{"viewer cancel", "POST", cancelPath, viewTok, nil, http.StatusForbidden},
		{"viewer list users", "GET", "/api/users", viewTok, nil, http.StatusForbidden},
		{"viewer create canary", "POST", "/api/canaries", viewTok, validCanaryBody("can-v"), http.StatusForbidden},
		// operator: operator writes ok, admin writes denied
		{"operator create pipeline", "POST", "/api/pipelines", opTok, map[string]string{"name": "x", "yaml": linearYAML}, http.StatusForbidden},
		{"operator list users", "GET", "/api/users", opTok, nil, http.StatusForbidden},
		{"operator trigger", "POST", "/api/pipelines/rbac/trigger", opTok, map[string]string{"trigger": "manual"}, http.StatusAccepted},
		{"operator cancel", "POST", cancelPath, opTok, nil, http.StatusOK},
		{"operator create canary", "POST", "/api/canaries", opTok, validCanaryBody("can-o"), http.StatusCreated},
		// admin: everything
		{"admin create pipeline", "POST", "/api/pipelines", adminTok, map[string]string{"name": "rbac2", "yaml": linearYAML}, http.StatusCreated},
		{"admin list users", "GET", "/api/users", adminTok, nil, http.StatusOK},
		{"admin create user", "POST", "/api/users", adminTok,
			map[string]string{"username": "rbactmp", "password": "password123", "role": "viewer"}, http.StatusCreated},
		// m3 additions: user delete, secrets, approve/reject, canary rollback
		{"viewer delete user", "DELETE", "/api/users/rbactmp", viewTok, nil, http.StatusForbidden},
		{"admin delete user", "DELETE", "/api/users/rbactmp", adminTok, nil, http.StatusNoContent},
		{"viewer create secret", "POST", "/api/secrets", viewTok,
			map[string]string{"name": "rbac-secret2", "value": "x"}, http.StatusForbidden},
		{"admin create secret", "POST", "/api/secrets", adminTok,
			map[string]string{"name": "rbac-secret2", "value": "x"}, http.StatusOK},
		{"viewer delete secret", "DELETE", "/api/secrets/rbac-secret", viewTok, nil, http.StatusForbidden},
		{"admin delete secret", "DELETE", "/api/secrets/rbac-secret", adminTok, nil, http.StatusNoContent},
		{"operator approve", "POST", approvePath, opTok, nil, http.StatusOK},
		{"viewer approve", "POST", approvePath, viewTok, nil, http.StatusForbidden},
		{"operator reject", "POST", rejectPath, opTok, nil, http.StatusOK},
		{"viewer reject", "POST", rejectPath, viewTok, nil, http.StatusForbidden},
		{"operator rollback canary", "POST", rollbackPath, opTok, nil, http.StatusOK},
		{"viewer rollback canary", "POST", rollbackPath, viewTok, nil, http.StatusForbidden},
	}
	for _, tc := range cases {
		code, data := doReq(t, tc.method, ts.URL+tc.path, tc.token, "", tc.body)
		if code != tc.want {
			t.Errorf("%s: %s %s -> got %d, want %d (body=%s)",
				tc.name, tc.method, tc.path, code, tc.want, string(data))
		}
	}
}

func validCanaryBody(name string) map[string]any {
	return map[string]any{
		"name": name, "namespace": "flowstallion",
		"stable_image": "nginx:1.25", "canary_image": "nginx:1.26",
		"replicas": 2, "port": 8080, "threshold": 0.3,
		"min_samples": 20, "warmup_s": 10, "observe_s": 20,
	}
}

func itoa(v int64) string {
	return strconv.FormatInt(v, 10)
}

// TestAgentTokenEndpoints verifies the requireAgent gate.
func TestAgentTokenEndpoints(t *testing.T) {
	ts := newAuthServer(t)

	// no token -> 401
	code, _ := doReq(t, "POST", ts.URL+"/api/agent/register", "", "",
		map[string]string{"name": "agent1"})
	if code != http.StatusUnauthorized {
		t.Errorf("agent register, no token: got %d, want 401", code)
	}
	// wrong agent token -> 401
	code, _ = doReq(t, "POST", ts.URL+"/api/agent/register", "", "wrong",
		map[string]string{"name": "agent1"})
	if code != http.StatusUnauthorized {
		t.Errorf("agent register, wrong token: got %d, want 401", code)
	}
	// correct agent token -> 200
	code, _ = doReq(t, "POST", ts.URL+"/api/agent/register", "", "agent-secret",
		map[string]string{"name": "agent1"})
	if code != http.StatusOK {
		t.Errorf("agent register, correct token: got %d, want 200", code)
	}
	// operator Bearer token (no agent header) -> 200
	opTok := loginToken(t, ts, "operator", "operator-pass-1")
	code, _ = doReq(t, "POST", ts.URL+"/api/agent/register", opTok, "",
		map[string]string{"name": "agent2"})
	if code != http.StatusOK {
		t.Errorf("agent register, operator token: got %d, want 200", code)
	}
	// viewer Bearer token (no agent header) -> 401
	viewTok := loginToken(t, ts, "viewer", "viewer-pass-1")
	code, _ = doReq(t, "POST", ts.URL+"/api/agent/register", viewTok, "",
		map[string]string{"name": "agent3"})
	if code != http.StatusUnauthorized {
		t.Errorf("agent register, viewer token: got %d, want 401", code)
	}
}

// TestAuthOffRegression ensures pre-P6 behaviour: every endpoint open,
// login returns 403.
func TestAuthOffRegression(t *testing.T) {
	ts := newPlainServer(t)

	code, _ := doReq(t, "GET", ts.URL+"/api/pipelines", "", "", nil)
	if code != http.StatusOK {
		t.Errorf("GET /api/pipelines (auth off): got %d, want 200", code)
	}
	code, _ = doReq(t, "POST", ts.URL+"/api/pipelines", "", "",
		map[string]string{"name": "open-test", "yaml": linearYAML})
	if code != http.StatusCreated {
		t.Errorf("POST /api/pipelines (auth off): got %d, want 201", code)
	}
	code, _ = doReq(t, "POST", ts.URL+"/api/auth/login", "", "",
		map[string]string{"username": "x", "password": "y"})
	if code != http.StatusForbidden {
		t.Errorf("login (auth off): got %d, want 403", code)
	}
	code, _ = doReq(t, "POST", ts.URL+"/api/agent/register", "", "",
		map[string]string{"name": "a1"})
	if code != http.StatusOK {
		t.Errorf("agent register (auth off): got %d, want 200", code)
	}
	code, _ = doReq(t, "GET", ts.URL+"/api/users", "", "", nil)
	if code != http.StatusOK {
		t.Errorf("GET /api/users (auth off): got %d, want 200", code)
	}
}

// TestDeleteUserGuards covers self-delete, last-admin and unknown-user guards.
func TestDeleteUserGuards(t *testing.T) {
	ts := newAuthServer(t)
	adminTok := loginToken(t, ts, "admin", "admin-pass-1")

	// create a temp user
	code, _ := doReq(t, "POST", ts.URL+"/api/users", adminTok, "",
		map[string]string{"username": "tempuser", "password": "password123", "role": "viewer"})
	if code != http.StatusCreated {
		t.Fatalf("create tempuser: got %d, want 201", code)
	}

	// self-delete -> 409
	code, _ = doReq(t, "DELETE", ts.URL+"/api/users/admin", adminTok, "", nil)
	if code != http.StatusConflict {
		t.Errorf("self-delete: got %d, want 409", code)
	}
	// delete known user -> 204
	code, _ = doReq(t, "DELETE", ts.URL+"/api/users/tempuser", adminTok, "", nil)
	if code != http.StatusNoContent {
		t.Errorf("delete tempuser: got %d, want 204", code)
	}
	// delete unknown user -> 404
	code, _ = doReq(t, "DELETE", ts.URL+"/api/users/ghost", adminTok, "", nil)
	if code != http.StatusNotFound {
		t.Errorf("delete unknown user: got %d, want 404", code)
	}
}
