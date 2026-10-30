package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/flowstallion/flowstallion/pkg/auth"
	"github.com/flowstallion/flowstallion/pkg/cd"
	"github.com/flowstallion/flowstallion/pkg/scheduler"
	"github.com/flowstallion/flowstallion/pkg/secret"
	"github.com/flowstallion/flowstallion/pkg/store"
)

// newAuditSecretServer is like newSecretServer but also returns the store so
// tests can inspect audit rows.
func newAuditSecretServer(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "audit-secret.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	disp := NewDispatcher()
	sched := scheduler.New(st, &AgentExecutor{D: disp})
	srv := New(st, sched, disp)
	key, err := secret.KeyFromString(strings.Repeat("0011223344556677", 4))
	if err != nil {
		t.Fatalf("test key: %v", err)
	}
	vault, err := secret.New(key)
	if err != nil {
		t.Fatalf("new vault: %v", err)
	}
	srv.Auth = auth.New(st, true, time.Hour, "agent-secret")
	srv.Vault = vault
	seedUsers(t, st)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, st
}

// checkAudit asserts that the newest audit event with the given action has the
// expected actor/target/outcome and that its detail contains all fragments.
func checkAudit(t *testing.T, st *store.Store, action, actor, target, outcome string, detailFragments ...string) {
	t.Helper()
	ev := latestAudit(t, st, action)
	if ev.Actor != actor || ev.Target != target || ev.Outcome != outcome {
		t.Fatalf("%s event = %+v, want actor=%q target=%q outcome=%q", action, ev, actor, target, outcome)
	}
	for _, frag := range detailFragments {
		if !strings.Contains(ev.Detail, frag) {
			t.Errorf("%s detail %q missing %q", action, ev.Detail, frag)
		}
	}
}

// TestAuditPipelineUpsertEvents covers pipeline.upsert (ok, invalid yaml,
// missing name) and proves auth-off requests are recorded as "anonymous".
func TestAuditPipelineUpsertEvents(t *testing.T) {
	ts, st := newAuditTestServer(t, false)

	code, _ := doReq(t, "POST", ts.URL+"/api/pipelines", "", "",
		map[string]string{"name": "linear", "yaml": linearYAML})
	if code != http.StatusCreated {
		t.Fatalf("create pipeline: got %d, want 201", code)
	}
	checkAudit(t, st, AuditPipelineUpsert, "anonymous", "pipeline:linear", OutcomeOK, "id=")

	// Invalid YAML → 422 + invalid.
	code, _ = doReq(t, "POST", ts.URL+"/api/pipelines", "", "",
		map[string]string{"name": "bad", "yaml": "version: 2\npipeline: {}\n"})
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("bad yaml: got %d, want 422", code)
	}
	checkAudit(t, st, AuditPipelineUpsert, "anonymous", "pipeline:bad", OutcomeInvalid, "invalid yaml")

	// Missing name → 400 + invalid, target unknown.
	code, _ = doReq(t, "POST", ts.URL+"/api/pipelines", "", "",
		map[string]string{"yaml": linearYAML})
	if code != http.StatusBadRequest {
		t.Fatalf("missing name: got %d, want 400", code)
	}
	checkAudit(t, st, AuditPipelineUpsert, "anonymous", "pipeline:unknown", OutcomeInvalid, "name required")
}

// TestAuditRunEvents covers run.trigger (ok + pipeline-not-found) and
// run.cancel with the authenticated actor resolved from the session.
func TestAuditRunEvents(t *testing.T) {
	ts, st := newAuditTestServer(t, true)
	adminTok := loginToken(t, ts, "admin", "admin-pass-1")
	opTok := loginToken(t, ts, "operator", "operator-pass-1")

	code, _ := doReq(t, "POST", ts.URL+"/api/pipelines", adminTok, "",
		map[string]string{"name": "linear", "yaml": linearYAML})
	if code != http.StatusCreated {
		t.Fatalf("create pipeline: got %d, want 201", code)
	}
	checkAudit(t, st, AuditPipelineUpsert, "admin", "pipeline:linear", OutcomeOK)

	code, data := doReq(t, "POST", ts.URL+"/api/pipelines/linear/trigger", opTok, "",
		map[string]string{"trigger": "manual", "source_ref": "refs/heads/main"})
	if code != http.StatusAccepted {
		t.Fatalf("trigger: got %d, want 202 (body=%s)", code, data)
	}
	var out struct {
		RunID int64 `json:"run_id"`
	}
	if err := json.Unmarshal(data, &out); err != nil || out.RunID == 0 {
		t.Fatalf("trigger response: %s", data)
	}
	target := fmt.Sprintf("run:%d", out.RunID)
	checkAudit(t, st, AuditRunTrigger, "operator", target, OutcomeOK, "trigger=manual", "source_ref=refs/heads/main")

	// Cancel while the run is still pending an agent → 200 ok.
	code, _ = doReq(t, "POST", fmt.Sprintf("%s/api/runs/%d/cancel", ts.URL, out.RunID), opTok, "", nil)
	if code != http.StatusOK {
		t.Fatalf("cancel: got %d, want 200", code)
	}
	checkAudit(t, st, AuditRunCancel, "operator", target, OutcomeOK)

	// Trigger of an unknown pipeline → 404 + not_found, target run:unknown.
	code, _ = doReq(t, "POST", ts.URL+"/api/pipelines/ghost/trigger", opTok, "",
		map[string]string{"trigger": "manual"})
	if code != http.StatusNotFound {
		t.Fatalf("ghost trigger: got %d, want 404", code)
	}
	checkAudit(t, st, AuditRunTrigger, "operator", "run:unknown", OutcomeNotFound, "pipeline not found")
}

// heldRunIDOn is like heldRunID but on a pipeline with a custom name, so
// concurrent holds do not trip the per-pipeline concurrency limit.
func heldRunIDOn(t *testing.T, c *http.Client, base, name string) int64 {
	t.Helper()
	yaml := strings.ReplaceAll(prodHoldYAML, "name: polapi", "name: "+name)
	createPipeline(t, c, base, name, yaml)
	id := triggerRun(t, c, base, name)
	if s := waitForRunStatus(t, c, base, id, "pending_approval"); s != "pending_approval" {
		t.Fatalf("run %d status = %q, want pending_approval", id, s)
	}
	return id
}

// TestAuditApproveRejectEvents covers run.approve / run.reject success and
// failure paths (auth off, so the actor is "anonymous").
func TestAuditApproveRejectEvents(t *testing.T) {
	ts, srv := newTestServer(t)
	c := ts.Client()
	base := ts.URL
	st := srv.Store

	id := heldRunIDOn(t, c, base, "polapi-a")
	code, _ := doJSON(t, c, "POST", fmt.Sprintf("%s/api/runs/%d/approve", base, id), nil)
	if code != http.StatusOK {
		t.Fatalf("approve: got %d, want 200", code)
	}
	checkAudit(t, st, AuditRunApprove, "anonymous", fmt.Sprintf("run:%d", id), OutcomeOK)

	id2 := heldRunIDOn(t, c, base, "polapi-b")
	code, _ = doJSON(t, c, "POST", fmt.Sprintf("%s/api/runs/%d/reject", base, id2),
		map[string]any{"reason": "flaky"})
	if code != http.StatusOK {
		t.Fatalf("reject: got %d, want 200", code)
	}
	checkAudit(t, st, AuditRunReject, "anonymous", fmt.Sprintf("run:%d", id2), OutcomeOK, "reason=flaky")

	// Reject of an unknown run → 404 + not_found.
	code, _ = doJSON(t, c, "POST", base+"/api/runs/999999/reject", nil)
	if code != http.StatusNotFound {
		t.Fatalf("reject unknown run: got %d, want 404", code)
	}
	checkAudit(t, st, AuditRunReject, "anonymous", "run:999999", OutcomeNotFound)
}

// TestAuditScanSaveEvents covers scan.save (ok, bad tool, unknown run).
func TestAuditScanSaveEvents(t *testing.T) {
	ts, srv := newTestServer(t)
	c := ts.Client()
	base := ts.URL
	st := srv.Store
	createPipeline(t, c, base, "linear", linearYAML)
	runID := triggerRun(t, c, base, "linear")
	target := fmt.Sprintf("run:%d", runID)

	code, _ := doJSON(t, c, "POST", fmt.Sprintf("%s/api/runs/%d/scans", base, runID),
		map[string]any{"tool": "trivy", "target": "repo", "mode": "fs", "findings_count": 2})
	if code != http.StatusOK {
		t.Fatalf("save scan: got %d, want 200", code)
	}
	checkAudit(t, st, AuditScanSave, "anonymous", target, OutcomeOK, "tool=trivy", "findings=2")

	// Bad tool → 400 + invalid.
	code, _ = doJSON(t, c, "POST", fmt.Sprintf("%s/api/runs/%d/scans", base, runID),
		map[string]any{"tool": "curl", "target": "repo", "mode": "fs"})
	if code != http.StatusBadRequest {
		t.Fatalf("bad tool: got %d, want 400", code)
	}
	checkAudit(t, st, AuditScanSave, "anonymous", target, OutcomeInvalid, "bad tool")

	// Unknown run → 404 + not_found, target run:unknown.
	code, _ = doJSON(t, c, "POST", base+"/api/runs/999999/scans",
		map[string]any{"tool": "trivy", "target": "repo", "mode": "fs"})
	if code != http.StatusNotFound {
		t.Fatalf("unknown run: got %d, want 404", code)
	}
	checkAudit(t, st, AuditScanSave, "anonymous", "run:unknown", OutcomeNotFound)
}

// TestAuditCanaryEvents covers canary.create (ok, duplicate, invalid name) and
// canary.rollback (bad id, missing controller, success).
func TestAuditCanaryEvents(t *testing.T) {
	ts, srv := newTestServer(t)
	c := ts.Client()
	base := ts.URL
	st := srv.Store

	code, out := postCanary(t, ts, baseCanaryBody)
	if code != http.StatusCreated {
		t.Fatalf("create: got %d, want 201 (body=%v)", code, out)
	}
	id := int64(out["id"].(float64))
	target := fmt.Sprintf("canary:%d", id)
	checkAudit(t, st, AuditCanaryCreate, "anonymous", target, OutcomeOK,
		"name=demoapp", "ns=flowstallion-cd-demo", "strategy=canary")

	// Duplicate name while active → 409 + conflict.
	code, _ = postCanary(t, ts, baseCanaryBody)
	if code != http.StatusConflict {
		t.Fatalf("duplicate create: got %d, want 409", code)
	}
	checkAudit(t, st, AuditCanaryCreate, "anonymous", "canary:demoapp", OutcomeConflict)

	// Invalid name → 400 + invalid.
	patch := map[string]any{}
	for k, v := range baseCanaryBody {
		patch[k] = v
	}
	patch["name"] = "DemoApp"
	code, _ = postCanary(t, ts, patch)
	if code != http.StatusBadRequest {
		t.Fatalf("bad name: got %d, want 400", code)
	}
	checkAudit(t, st, AuditCanaryCreate, "anonymous", "canary:DemoApp", OutcomeInvalid)

	// Rollback: bad id → 400 + invalid.
	if code, _ := doJSON(t, c, "POST", base+"/api/canaries/abc/rollback", nil); code != http.StatusBadRequest {
		t.Fatalf("bad id: got %d, want 400", code)
	}
	checkAudit(t, st, AuditCanaryRollback, "anonymous", "canary:unknown", OutcomeInvalid)

	// Rollback without a controller → 503 + error.
	if code, _ := doJSON(t, c, "POST", fmt.Sprintf("%s/api/canaries/%d/rollback", base, id), nil); code != http.StatusServiceUnavailable {
		t.Fatalf("nil controller: got %d, want 503", code)
	}
	checkAudit(t, st, AuditCanaryRollback, "anonymous", target, OutcomeError)

	// Wire a controller; rollback with reason → 200 + ok.
	srv.CanaryCtl = cd.NewController(st, &fakeK{})
	code, _ = doJSON(t, c, "POST", fmt.Sprintf("%s/api/canaries/%d/rollback", base, id),
		map[string]any{"reason": "err spike"})
	if code != http.StatusOK {
		t.Fatalf("rollback: got %d, want 200", code)
	}
	checkAudit(t, st, AuditCanaryRollback, "anonymous", target, OutcomeOK, "reason=err spike")
}

// TestAuditUserEvents covers user.create / user.delete (ok, invalid,
// conflict, not_found) and asserts the password never reaches the audit.
func TestAuditUserEvents(t *testing.T) {
	ts, st := newAuditTestServer(t, true)
	adminTok := loginToken(t, ts, "admin", "admin-pass-1")
	const pw = "bob-secret-pw-1"

	code, _ := doReq(t, "POST", ts.URL+"/api/users", adminTok, "",
		map[string]string{"username": "bob", "password": pw, "role": "operator"})
	if code != http.StatusCreated {
		t.Fatalf("create user: got %d, want 201", code)
	}
	checkAudit(t, st, AuditUserCreate, "admin", "user:bob", OutcomeOK, "role=operator")

	// Short password → 400 + invalid.
	code, _ = doReq(t, "POST", ts.URL+"/api/users", adminTok, "",
		map[string]string{"username": "eve", "password": "short", "role": "viewer"})
	if code != http.StatusBadRequest {
		t.Fatalf("short password: got %d, want 400", code)
	}
	checkAudit(t, st, AuditUserCreate, "admin", "user:eve", OutcomeInvalid)

	// Duplicate → 409 + conflict.
	code, _ = doReq(t, "POST", ts.URL+"/api/users", adminTok, "",
		map[string]string{"username": "bob", "password": pw, "role": "operator"})
	if code != http.StatusConflict {
		t.Fatalf("duplicate user: got %d, want 409", code)
	}
	checkAudit(t, st, AuditUserCreate, "admin", "user:bob", OutcomeConflict)

	// Delete ok.
	code, _ = doReq(t, "DELETE", ts.URL+"/api/users/bob", adminTok, "", nil)
	if code != http.StatusNoContent {
		t.Fatalf("delete user: got %d, want 204", code)
	}
	checkAudit(t, st, AuditUserDelete, "admin", "user:bob", OutcomeOK)

	// Delete unknown → 404 + not_found.
	code, _ = doReq(t, "DELETE", ts.URL+"/api/users/ghost", adminTok, "", nil)
	if code != http.StatusNotFound {
		t.Fatalf("delete unknown: got %d, want 404", code)
	}
	checkAudit(t, st, AuditUserDelete, "admin", "user:ghost", OutcomeNotFound)

	// The password must never appear in any audit detail.
	for _, e := range countAudit(t, st, store.AuditFilter{Limit: 200}) {
		if strings.Contains(e.Detail, pw) {
			t.Fatalf("audit detail %q leaks the password", e.Detail)
		}
	}
}

// TestAuditSecretEvents covers secret.upsert / secret.delete and asserts the
// secret value never appears in any audit detail.
func TestAuditSecretEvents(t *testing.T) {
	ts, st := newAuditSecretServer(t)
	adminTok := loginToken(t, ts, "admin", "admin-pass-1")
	const secretVal = "super-secret-value-xyz"

	code, _ := doReq(t, "POST", ts.URL+"/api/secrets", adminTok, "",
		map[string]string{"name": "DB_PASSWORD", "value": secretVal})
	if code != http.StatusOK {
		t.Fatalf("upsert secret: got %d, want 200", code)
	}
	checkAudit(t, st, AuditSecretUpsert, "admin", "secret:DB_PASSWORD", OutcomeOK, "name=DB_PASSWORD")

	// Invalid name → 400 + invalid, target secret:unknown.
	code, _ = doReq(t, "POST", ts.URL+"/api/secrets", adminTok, "",
		map[string]string{"name": "bad name!", "value": "x"})
	if code != http.StatusBadRequest {
		t.Fatalf("bad name: got %d, want 400", code)
	}
	checkAudit(t, st, AuditSecretUpsert, "admin", "secret:unknown", OutcomeInvalid, "invalid name")

	// Delete ok.
	code, _ = doReq(t, "DELETE", ts.URL+"/api/secrets/DB_PASSWORD", adminTok, "", nil)
	if code != http.StatusNoContent {
		t.Fatalf("delete secret: got %d, want 204", code)
	}
	checkAudit(t, st, AuditSecretDelete, "admin", "secret:DB_PASSWORD", OutcomeOK)

	// Delete unknown → 404 + not_found.
	code, _ = doReq(t, "DELETE", ts.URL+"/api/secrets/ghost", adminTok, "", nil)
	if code != http.StatusNotFound {
		t.Fatalf("delete unknown: got %d, want 404", code)
	}
	checkAudit(t, st, AuditSecretDelete, "admin", "secret:ghost", OutcomeNotFound)

	// The secret value must never appear in any audit detail.
	for _, e := range countAudit(t, st, store.AuditFilter{Limit: 200}) {
		if strings.Contains(e.Detail, secretVal) {
			t.Fatalf("audit detail %q leaks the secret value", e.Detail)
		}
	}
}
