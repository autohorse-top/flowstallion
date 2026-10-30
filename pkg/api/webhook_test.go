// Webhook endpoint tests: HMAC signature verification, event filtering,
// repo→pipeline mapping and branch-rule matching.
package api

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/flowstallion/flowstallion/pkg/store"
)

const webhookTestSecret = "webhook-test-secret"

// webhookPushAllYAML declares a push trigger with no branch filter (all branches).
const webhookPushAllYAML = `
version: 1
pipeline:
  name: hookdemo
  trigger:
    - event: push
  steps:
    - id: a
      image: alpine
      commands:
        - echo a
`

// webhookPushMainYAML only triggers on the main branch.
const webhookPushMainYAML = `
version: 1
pipeline:
  name: hookdemo
  trigger:
    - event: push
      branches: [main]
  steps:
    - id: a
      image: alpine
      commands:
        - echo a
`

// webhookNoTriggerYAML declares no trigger rules at all.
const webhookNoTriggerYAML = `
version: 1
pipeline:
  name: hookdemo
  steps:
    - id: a
      image: alpine
      commands:
        - echo a
`

// webhookSlowYAML declares a push trigger (all branches) with
// concurrency: 1, for exercising the 409 concurrency-limit path.
const webhookSlowYAML = `
version: 1
pipeline:
  name: hookdemo
  concurrency: 1
  trigger:
    - event: push
  steps:
    - id: a
      image: alpine
      commands:
        - echo a
`

// signWebhook returns the X-Hub-Signature-256 value for body under secret.
func signWebhook(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// pushPayload builds a minimal GitHub push payload for repo and ref.
func pushPayload(t *testing.T, repo, ref string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"ref":        ref,
		"repository": map[string]any{"full_name": repo},
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return b
}

// doWebhook POSTs body to the GitHub webhook endpoint with the given
// signature ("" omits the header) and event ("" omits the header).
func doWebhook(t *testing.T, c *http.Client, base string, body []byte, sig, event string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, base+"/api/webhooks/github", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if sig != "" {
		req.Header.Set("X-Hub-Signature-256", sig)
	}
	if event != "" {
		req.Header.Set("X-GitHub-Event", event)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("POST webhook: %v", err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if ct := resp.Header.Get("Content-Type"); strings.HasPrefix(ct, "application/json") {
		_ = json.NewDecoder(resp.Body).Decode(&out)
	}
	return resp.StatusCode, out
}

// requireNotTriggered asserts a 200 response with triggered=false and a
// reason containing wantReason.
func requireNotTriggered(t *testing.T, code int, out map[string]any, wantReason string) {
	t.Helper()
	if code != http.StatusOK {
		t.Fatalf("want 200, got %d (body=%v)", code, out)
	}
	if got, _ := out["triggered"].(bool); got {
		t.Fatalf("want triggered=false, got true (body=%v)", out)
	}
	reason, _ := out["reason"].(string)
	if !strings.Contains(reason, wantReason) {
		t.Errorf("reason %q does not contain %q", reason, wantReason)
	}
}

func TestWebhookNoSecret(t *testing.T) {
	ts, _ := newTestServer(t)
	t.Cleanup(ts.Close)
	t.Setenv(WebhookSecretEnv, "") // explicit empty = not configured
	body := pushPayload(t, "owner/hookdemo", "refs/heads/main")
	code, _ := doWebhook(t, ts.Client(), ts.URL, body, signWebhook(body, "anything"), "ping")
	if code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d", code)
	}
}

func TestWebhookBadSignature(t *testing.T) {
	ts, _ := newTestServer(t)
	t.Cleanup(ts.Close)
	t.Setenv(WebhookSecretEnv, webhookTestSecret)
	body := pushPayload(t, "owner/hookdemo", "refs/heads/main")
	code, _ := doWebhook(t, ts.Client(), ts.URL, body, signWebhook(body, "wrong-secret"), "ping")
	if code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", code)
	}
}

func TestWebhookMissingSignature(t *testing.T) {
	ts, _ := newTestServer(t)
	t.Cleanup(ts.Close)
	t.Setenv(WebhookSecretEnv, webhookTestSecret)
	body := pushPayload(t, "owner/hookdemo", "refs/heads/main")
	code, _ := doWebhook(t, ts.Client(), ts.URL, body, "", "ping")
	if code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", code)
	}
}

func TestWebhookPing(t *testing.T) {
	ts, _ := newTestServer(t)
	t.Cleanup(ts.Close)
	t.Setenv(WebhookSecretEnv, webhookTestSecret)
	body := []byte(`{"zen":"Keep it easy.","hook":1}`)
	code, out := doWebhook(t, ts.Client(), ts.URL, body, signWebhook(body, webhookTestSecret), "ping")
	if code != http.StatusOK {
		t.Fatalf("want 200, got %d", code)
	}
	if got, _ := out["status"].(string); got != "ok" {
		t.Fatalf("want status ok, got %v", out)
	}
}

func TestWebhookPushTriggersRun(t *testing.T) {
	ts, srv := newTestServer(t)
	t.Cleanup(ts.Close)
	t.Setenv(WebhookSecretEnv, webhookTestSecret)

	// Create the pipeline; its name must equal the repository name.
	pl, err := srv.Store.UpsertPipeline("hookdemo", webhookPushAllYAML)
	if err != nil {
		t.Fatalf("upsert pipeline: %v", err)
	}
	_ = pl

	body := pushPayload(t, "owner/hookdemo", "refs/heads/main")
	code, out := doWebhook(t, ts.Client(), ts.URL, body, signWebhook(body, webhookTestSecret), "push")
	if code != http.StatusAccepted {
		t.Fatalf("want 202, got %d (body=%v)", code, out)
	}
	runID, ok := out["run_id"].(float64)
	if !ok || int64(runID) < 1 {
		t.Fatalf("want run_id >= 1, got %v", out)
	}

	// The run must be recorded with trigger=push and source_ref=main.
	s, err := srv.Store.GetRun(int64(runID))
	if err != nil {
		t.Fatalf("get run: %v", err)
	}
	if s.Trigger != "push" {
		t.Errorf("run trigger = %q, want push", s.Trigger)
	}
	if s.SourceRef != "main" {
		t.Errorf("run source_ref = %q, want main", s.SourceRef)
	}
	if s.Status != store.RunQueued {
		t.Logf("run status = %q (agent not registered; queued is expected)", s.Status)
	}
}

// TestWebhookPushAfterStoredAsSHA: the push payload's "after" sha is
// recorded on the run (feeds the {{sha}} image template, P7④).
func TestWebhookPushAfterStoredAsSHA(t *testing.T) {
	ts, srv := newTestServer(t)
	t.Cleanup(ts.Close)
	t.Setenv(WebhookSecretEnv, webhookTestSecret)
	if _, err := srv.Store.UpsertPipeline("hookdemo", webhookPushAllYAML); err != nil {
		t.Fatalf("upsert pipeline: %v", err)
	}
	body, err := json.Marshal(map[string]any{
		"ref":        "refs/heads/main",
		"after":      "deadbeefcafe",
		"repository": map[string]any{"full_name": "owner/hookdemo"},
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	code, out := doWebhook(t, ts.Client(), ts.URL, body, signWebhook(body, webhookTestSecret), "push")
	if code != http.StatusAccepted {
		t.Fatalf("want 202, got %d (body=%v)", code, out)
	}
	runID, ok := out["run_id"].(float64)
	if !ok {
		t.Fatalf("want run_id in response, got %v", out)
	}
	r, err := srv.Store.GetRun(int64(runID))
	if err != nil {
		t.Fatalf("get run: %v", err)
	}
	if r.SHA != "deadbeefcafe" {
		t.Errorf("run.SHA = %q, want deadbeefcafe", r.SHA)
	}
}

// TestRunJSONExposesSHA (QA MINOR-2 regression): GET /api/runs/{id} must
// surface the triggering commit SHA in the "sha" field of the run JSON —
// a webhook push run carries the payload "after" value, a manually
// triggered run exposes "" (no omitempty, consistent with the other
// trigger-metadata fields).
func TestRunJSONExposesSHA(t *testing.T) {
	t.Run("push_webhook", func(t *testing.T) {
		ts, srv := newTestServer(t)
		t.Cleanup(ts.Close)
		t.Setenv(WebhookSecretEnv, webhookTestSecret)
		if _, err := srv.Store.UpsertPipeline("hookdemo", webhookPushAllYAML); err != nil {
			t.Fatalf("upsert pipeline: %v", err)
		}
		body, err := json.Marshal(map[string]any{
			"ref":        "refs/heads/main",
			"after":      "cafebabe42",
			"repository": map[string]any{"full_name": "owner/hookdemo"},
		})
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
		code, out := doWebhook(t, ts.Client(), ts.URL, body, signWebhook(body, webhookTestSecret), "push")
		if code != http.StatusAccepted {
			t.Fatalf("want 202, got %d (body=%v)", code, out)
		}
		runID, ok := out["run_id"].(float64)
		if !ok || int64(runID) < 1 {
			t.Fatalf("want run_id >= 1, got %v", out)
		}
		code, out = doJSON(t, ts.Client(), "GET", fmt.Sprintf("%s/api/runs/%d", ts.URL, int64(runID)), nil)
		if code != http.StatusOK {
			t.Fatalf("get run: want 200, got %d", code)
		}
		run, _ := out["run"].(map[string]any)
		if run == nil {
			t.Fatalf("run detail has no 'run' object: %v", out)
		}
		if _, present := run["sha"]; !present {
			t.Fatalf("run json missing 'sha' field: %v", run)
		}
		if sha, _ := run["sha"].(string); sha != "cafebabe42" {
			t.Errorf("run sha = %q, want cafebabe42", sha)
		}
	})

	t.Run("manual", func(t *testing.T) {
		ts, _ := newTestServer(t)
		t.Cleanup(ts.Close)
		c := ts.Client()
		_ = createPipeline(t, c, ts.URL, "linear", linearYAML)
		runID := triggerRun(t, c, ts.URL, "linear")
		code, out := doJSON(t, c, "GET", fmt.Sprintf("%s/api/runs/%d", ts.URL, runID), nil)
		if code != http.StatusOK {
			t.Fatalf("get run: want 200, got %d", code)
		}
		run, _ := out["run"].(map[string]any)
		if run == nil {
			t.Fatalf("run detail has no 'run' object: %v", out)
		}
		if _, present := run["sha"]; !present {
			t.Fatalf("run json missing 'sha' field: %v", run)
		}
		if sha, _ := run["sha"].(string); sha != "" {
			t.Errorf("manual run sha = %q, want empty", sha)
		}
	})
}

func TestWebhookPushBranchMismatch(t *testing.T) {
	ts, srv := newTestServer(t)
	t.Cleanup(ts.Close)
	t.Setenv(WebhookSecretEnv, webhookTestSecret)
	if _, err := srv.Store.UpsertPipeline("hookdemo", webhookPushMainYAML); err != nil {
		t.Fatalf("upsert pipeline: %v", err)
	}
	body := pushPayload(t, "owner/hookdemo", "refs/heads/develop")
	code, out := doWebhook(t, ts.Client(), ts.URL, body, signWebhook(body, webhookTestSecret), "push")
	requireNotTriggered(t, code, out, "no matching push trigger rule")
}

func TestWebhookPushNoPushRule(t *testing.T) {
	ts, srv := newTestServer(t)
	t.Cleanup(ts.Close)
	t.Setenv(WebhookSecretEnv, webhookTestSecret)
	if _, err := srv.Store.UpsertPipeline("hookdemo", webhookNoTriggerYAML); err != nil {
		t.Fatalf("upsert pipeline: %v", err)
	}
	body := pushPayload(t, "owner/hookdemo", "refs/heads/main")
	code, out := doWebhook(t, ts.Client(), ts.URL, body, signWebhook(body, webhookTestSecret), "push")
	requireNotTriggered(t, code, out, "no matching push trigger rule")
}

func TestWebhookUnknownRepo(t *testing.T) {
	ts, _ := newTestServer(t)
	t.Cleanup(ts.Close)
	t.Setenv(WebhookSecretEnv, webhookTestSecret)
	body := pushPayload(t, "owner/no-such-repo", "refs/heads/main")
	code, out := doWebhook(t, ts.Client(), ts.URL, body, signWebhook(body, webhookTestSecret), "push")
	requireNotTriggered(t, code, out, "no pipeline for repository")
}

func TestWebhookNonBranchRef(t *testing.T) {
	ts, srv := newTestServer(t)
	t.Cleanup(ts.Close)
	t.Setenv(WebhookSecretEnv, webhookTestSecret)
	if _, err := srv.Store.UpsertPipeline("hookdemo", webhookPushAllYAML); err != nil {
		t.Fatalf("upsert pipeline: %v", err)
	}
	body := pushPayload(t, "owner/hookdemo", "refs/tags/v1.0.0")
	code, out := doWebhook(t, ts.Client(), ts.URL, body, signWebhook(body, webhookTestSecret), "push")
	requireNotTriggered(t, code, out, "non-branch ref")
}

func TestWebhookUnsupportedEvent(t *testing.T) {
	ts, _ := newTestServer(t)
	t.Cleanup(ts.Close)
	t.Setenv(WebhookSecretEnv, webhookTestSecret)
	body := pushPayload(t, "owner/hookdemo", "refs/heads/main")
	code, out := doWebhook(t, ts.Client(), ts.URL, body, signWebhook(body, webhookTestSecret), "release")
	requireNotTriggered(t, code, out, `event "release" not supported`)
}

func TestWebhookMalformedPayload(t *testing.T) {
	ts, _ := newTestServer(t)
	t.Cleanup(ts.Close)
	t.Setenv(WebhookSecretEnv, webhookTestSecret)
	body := []byte(`{not json`)
	code, _ := doWebhook(t, ts.Client(), ts.URL, body, signWebhook(body, webhookTestSecret), "push")
	if code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", code)
	}
}

// TestWebhookPushBranchDeletion (N2): a branch deletion arrives as a push
// whose "after" is 40 zeros; there is no commit to build, so the hook must
// answer 200 triggered=false and create no run.
func TestWebhookPushBranchDeletion(t *testing.T) {
	ts, srv := newTestServer(t)
	t.Cleanup(ts.Close)
	t.Setenv(WebhookSecretEnv, webhookTestSecret)
	plID, err := srv.Store.UpsertPipeline("hookdemo", webhookPushAllYAML)
	if err != nil {
		t.Fatalf("upsert pipeline: %v", err)
	}
	body, err := json.Marshal(map[string]any{
		"ref":        "refs/heads/feature-x",
		"after":      strings.Repeat("0", 40),
		"repository": map[string]any{"full_name": "owner/hookdemo"},
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	code, out := doWebhook(t, ts.Client(), ts.URL, body, signWebhook(body, webhookTestSecret), "push")
	requireNotTriggered(t, code, out, "branch deletion")
	runs, err := srv.Store.ListRuns(plID, 100)
	if err != nil {
		t.Fatalf("list runs: %v", err)
	}
	if len(runs) != 0 {
		t.Fatalf("branch deletion must not create runs, got %d", len(runs))
	}
}

// TestWebhookSCMAuditEvents (task ③): every successful webhook dispatch
// records an scm.push / scm.pull_request audit event with actor
// "scm:<provider>", target "run:<id>", and repo/branch or repo/PR detail.
func TestWebhookSCMAuditEvents(t *testing.T) {
	ts, srv := newTestServer(t)
	t.Cleanup(ts.Close)
	t.Setenv(WebhookSecretEnv, webhookTestSecret)
	st := srv.Store
	c := ts.Client()

	prYAML := `
version: 1
pipeline:
  name: hookpr
  trigger:
    - event: pull_request
  steps:
    - id: a
      image: alpine
      commands:
        - echo a
`
	pipelines := map[string]string{
		"hookdemo":   webhookPushAllYAML,
		"hookgitea":  strings.ReplaceAll(webhookPushAllYAML, "name: hookdemo", "name: hookgitea"),
		"hookgitlab": strings.ReplaceAll(webhookPushAllYAML, "name: hookdemo", "name: hookgitlab"),
		"hookpr":     prYAML,
	}
	for name, yaml := range pipelines {
		if _, err := st.UpsertPipeline(name, yaml); err != nil {
			t.Fatalf("upsert %s: %v", name, err)
		}
	}

	// github push → 202 + scm.push (actor=scm:github).
	body := pushPayload(t, "owner/hookdemo", "refs/heads/main")
	code, out := doWebhook(t, c, ts.URL, body, signWebhook(body, webhookTestSecret), "push")
	if code != http.StatusAccepted {
		t.Fatalf("github push: want 202, got %d (body=%v)", code, out)
	}
	runID := int64(out["run_id"].(float64))
	checkSCMAudit(t, st, AuditSCMPush, "scm:github", runID, "repo=hookdemo", "ref=main")

	// github pull_request → 202 + scm.pull_request (pr number in detail).
	prBody, _ := json.Marshal(map[string]any{
		"action": "opened",
		"pull_request": map[string]any{
			"number": 7,
			"head":   map[string]any{"ref": "feature", "sha": "abc123"},
			"base":   map[string]any{"ref": "main"},
		},
		"repository": map[string]any{
			"full_name": "owner/hookpr",
			"html_url":  "https://github.com/owner/hookpr",
		},
	})
	code, out = doWebhook(t, c, ts.URL, prBody, signWebhook(prBody, webhookTestSecret), "pull_request")
	if code != http.StatusAccepted {
		t.Fatalf("github pr: want 202, got %d (body=%v)", code, out)
	}
	runID = int64(out["run_id"].(float64))
	checkSCMAudit(t, st, AuditSCMPullRequest, "scm:github", runID, "repo=hookpr", "pr=7")

	// gitea push (plain token auth) → 202 + scm.push (actor=scm:gitea).
	body = pushPayload(t, "owner/hookgitea", "refs/heads/main")
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/webhooks/gitea", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Gitea-Token", webhookTestSecret)
	req.Header.Set("X-Gitea-Event", "push")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("gitea push: %v", err)
	}
	var gout map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&gout)
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("gitea push: want 202, got %d (body=%v)", resp.StatusCode, gout)
	}
	checkSCMAudit(t, st, AuditSCMPush, "scm:gitea", int64(gout["run_id"].(float64)), "repo=hookgitea")

	// gitlab push (plain token auth) → 202 + scm.push (actor=scm:gitlab).
	labBody, _ := json.Marshal(map[string]any{
		"object_kind": "push",
		"ref":         "refs/heads/main",
		"project":     map[string]any{"path_with_namespace": "owner/hookgitlab"},
	})
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/api/webhooks/gitlab", bytes.NewReader(labBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Gitlab-Token", webhookTestSecret)
	req.Header.Set("X-Gitlab-Event", "Push Hook")
	resp, err = c.Do(req)
	if err != nil {
		t.Fatalf("gitlab push: %v", err)
	}
	var lout map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&lout)
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("gitlab push: want 202, got %d (body=%v)", resp.StatusCode, lout)
	}
	checkSCMAudit(t, st, AuditSCMPush, "scm:gitlab", int64(lout["run_id"].(float64)), "repo=hookgitlab")
}

// checkSCMAudit asserts the newest audit event for action has the given
// actor / run target / ok outcome and that detail contains all fragments.
func checkSCMAudit(t *testing.T, st *store.Store, action, actor string, runID int64, detailFragments ...string) {
	t.Helper()
	ev := latestAudit(t, st, action)
	target := fmt.Sprintf("run:%d", runID)
	if ev.Actor != actor || ev.Target != target || ev.Outcome != OutcomeOK {
		t.Fatalf("%s event = %+v, want actor=%q target=%q outcome=ok", action, ev, actor, target)
	}
	for _, frag := range detailFragments {
		if !strings.Contains(ev.Detail, frag) {
			t.Errorf("%s detail %q missing %q", action, ev.Detail, frag)
		}
	}
}
