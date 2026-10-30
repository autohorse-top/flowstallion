// P8①: table-driven tests for the Gitea webhook endpoint —
// signature + token auth, event filtering, push/PR dispatch, and run metadata.
package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// doGiteaWebhook POSTs body to the Gitea webhook endpoint with the given
// signature ("" omits X-Gitea-Signature), token ("" omits X-Gitea-Token)
// and event ("" omits X-Gitea-Event).
func doGiteaWebhook(t *testing.T, c *http.Client, base string, body []byte, sig, token, event string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, base+"/api/webhooks/gitea", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if sig != "" {
		req.Header.Set("X-Gitea-Signature", sig)
	}
	if token != "" {
		req.Header.Set("X-Gitea-Token", token)
	}
	if event != "" {
		req.Header.Set("X-Gitea-Event", event)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("POST gitea webhook: %v", err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if ct := resp.Header.Get("Content-Type"); strings.HasPrefix(ct, "application/json") {
		_ = json.NewDecoder(resp.Body).Decode(&out)
	}
	return resp.StatusCode, out
}

// giteaPRPayload builds a minimal Gitea pull_request payload (GitHub shape).
func giteaPRPayload(t *testing.T, repo, action, headRef, baseRef string, pr int) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"action": action,
		"pull_request": map[string]any{
			"number": pr,
			"head":   map[string]any{"sha": "abc1234", "ref": headRef},
			"base":   map[string]any{"ref": baseRef},
		},
		"repository": map[string]any{
			"full_name": repo,
			"html_url":  "https://gitea.example.com/" + repo,
		},
	})
	if err != nil {
		t.Fatalf("marshal pr payload: %v", err)
	}
	return b
}

func TestGiteaWebhook(t *testing.T) {
	cases := []struct {
		name          string
		pipelineYAML  string // "" = no pipeline upserted
		secret        string // "" = env var unset (503 expected)
		sig           string // "" = sign with the correct secret; "wrong" = wrong secret; "none" = omit
		token         string // "correct" = X-Gitea-Token=secret; "wrong" = bad token; "" = omit
		event         string
		body          map[string]any // payload; ignored when rawBody is set
		rawBody       []byte
		wantCode      int
		wantReason    string // substring; "" = triggered=true (202)
		wantTrigger   string
		wantSourceRef string
		wantSHA       string
	}{
		{
			name:          "push_hmac_ok_202",
			pipelineYAML:  webhookPushAllYAML,
			secret:        webhookTestSecret,
			event:         "push",
			body:          map[string]any{"ref": "refs/heads/main", "after": "cafe001", "repository": map[string]any{"full_name": "owner/hookdemo"}},
			wantCode:      http.StatusAccepted,
			wantTrigger:   "push",
			wantSourceRef: "main",
			wantSHA:       "cafe001",
		},
		{
			name:          "push_token_ok_202",
			pipelineYAML:  webhookPushAllYAML,
			secret:        webhookTestSecret,
			token:         "correct",
			event:         "push",
			body:          map[string]any{"ref": "refs/heads/main", "after": "cafe002", "repository": map[string]any{"full_name": "owner/hookdemo"}},
			wantCode:      http.StatusAccepted,
			wantTrigger:   "push",
			wantSourceRef: "main",
		},
		{
			name:     "push_hmac_wrong_403",
			secret:   webhookTestSecret,
			sig:      "wrong",
			event:    "push",
			body:     map[string]any{"ref": "refs/heads/main", "repository": map[string]any{"full_name": "owner/hookdemo"}},
			wantCode: http.StatusForbidden,
		},
		{
			name:     "push_token_wrong_403",
			secret:   webhookTestSecret,
			sig:      "none",
			token:    "wrong",
			event:    "push",
			body:     map[string]any{"ref": "refs/heads/main", "repository": map[string]any{"full_name": "owner/hookdemo"}},
			wantCode: http.StatusForbidden,
		},
		{
			name:     "push_no_credentials_403",
			secret:   webhookTestSecret,
			sig:      "none",
			event:    "push",
			body:     map[string]any{"ref": "refs/heads/main", "repository": map[string]any{"full_name": "owner/hookdemo"}},
			wantCode: http.StatusForbidden,
		},
		{
			name:     "secret_unset_503",
			secret:   "",
			event:    "push",
			body:     map[string]any{"ref": "refs/heads/main", "repository": map[string]any{"full_name": "owner/hookdemo"}},
			wantCode: http.StatusServiceUnavailable,
		},
		{
			name:         "push_branch_mismatch_200_false",
			pipelineYAML: webhookPushMainYAML,
			secret:       webhookTestSecret,
			event:        "push",
			body:         map[string]any{"ref": "refs/heads/dev", "repository": map[string]any{"full_name": "owner/hookdemo"}},
			wantCode:     http.StatusOK,
			wantReason:   "no matching push trigger rule",
		},
		{
			name:         "push_all_zero_after_200_false",
			pipelineYAML: webhookPushAllYAML,
			secret:       webhookTestSecret,
			event:        "push",
			body:         map[string]any{"ref": "refs/heads/main", "after": strings.Repeat("0", 40), "repository": map[string]any{"full_name": "owner/hookdemo"}},
			wantCode:     http.StatusOK,
			wantReason:   "branch deletion",
		},
		{
			name:       "unknown_event_200_false",
			secret:     webhookTestSecret,
			event:      "release",
			body:       map[string]any{"ref": "refs/heads/main"},
			wantCode:   http.StatusOK,
			wantReason: `event "release" not supported`,
		},
		{
			name:       "unknown_repo_200_false",
			secret:     webhookTestSecret,
			event:      "push",
			body:       map[string]any{"ref": "refs/heads/main", "repository": map[string]any{"full_name": "owner/no-such-repo"}},
			wantCode:   http.StatusOK,
			wantReason: "no pipeline for repository",
		},
		{
			name:         "push_non_branch_ref_200_false",
			pipelineYAML: webhookPushAllYAML,
			secret:       webhookTestSecret,
			event:        "push",
			body:         map[string]any{"ref": "refs/tags/v1.0", "after": "cafe003", "repository": map[string]any{"full_name": "owner/hookdemo"}},
			wantCode:     http.StatusOK,
			wantReason:   "non-branch ref",
		},
		{
			name:         "push_no_repo_name_200_false",
			pipelineYAML: webhookPushAllYAML,
			secret:       webhookTestSecret,
			event:        "push",
			body:         map[string]any{"ref": "refs/heads/main", "after": "cafe004"},
			wantCode:     http.StatusOK,
			wantReason:   "no repository name",
		},
		{
			name:     "bad_json_400",
			secret:   webhookTestSecret,
			event:    "push",
			rawBody:  []byte(`{not json`),
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "body_too_large_413",
			secret:   webhookTestSecret,
			rawBody:  make([]byte, maxWebhookBody+1),
			event:    "push",
			wantCode: http.StatusRequestEntityTooLarge,
		},
		{
			name:          "pr_opened_202_meta",
			pipelineYAML:  webhookPRAllYAML,
			secret:        webhookTestSecret,
			event:         "pull_request",
			body:          map[string]any{"action": "opened", "pull": 12},
			wantCode:      http.StatusAccepted,
			wantTrigger:   "pull_request",
			wantSourceRef: "feature/login",
		},
		{
			name:         "pr_synchronize_202",
			pipelineYAML: webhookPRAllYAML,
			secret:       webhookTestSecret,
			event:        "pull_request",
			body:         map[string]any{"action": "synchronize", "pull": 12},
			wantCode:     http.StatusAccepted,
		},
		{
			name:         "pr_reopened_202",
			pipelineYAML: webhookPRAllYAML,
			secret:       webhookTestSecret,
			event:        "pull_request",
			body:         map[string]any{"action": "reopened", "pull": 12},
			wantCode:     http.StatusAccepted,
		},
		{
			name:         "pr_closed_200_false",
			pipelineYAML: webhookPRAllYAML,
			secret:       webhookTestSecret,
			event:        "pull_request",
			body:         map[string]any{"action": "closed", "pull": 12},
			wantCode:     http.StatusOK,
			wantReason:   `pull_request action "closed" not supported`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts, srv := newTestServer(t)
			t.Cleanup(ts.Close)

			if tc.secret == "" {
				t.Setenv(WebhookSecretEnv, "")
			} else {
				t.Setenv(WebhookSecretEnv, webhookTestSecret)
			}

			if tc.pipelineYAML != "" {
				if _, err := srv.Store.UpsertPipeline("hookdemo", tc.pipelineYAML); err != nil {
					t.Fatalf("upsert pipeline: %v", err)
				}
			}

			var body []byte
			if tc.rawBody != nil {
				body = tc.rawBody
			} else if tc.event == "pull_request" {
				action, _ := tc.body["action"].(string)
				pr, _ := tc.body["pull"].(int)
				body = giteaPRPayload(t, "owner/hookdemo", action, "feature/login", "main", pr)
			} else {
				b, err := json.Marshal(tc.body)
				if err != nil {
					t.Fatalf("marshal payload: %v", err)
				}
				body = b
			}

			sig := ""
			switch tc.sig {
			case "":
				sig = signWebhook(body, webhookTestSecret)
			case "wrong":
				sig = signWebhook(body, "wrong-secret")
			}
			if tc.secret == "" {
				// signature is irrelevant; 503 fires before the auth check.
				sig = signWebhook(body, "anything")
			}
			var token string
			switch tc.token {
			case "correct":
				token = webhookTestSecret
			case "wrong":
				token = "wrong-token"
			}

			code, out := doGiteaWebhook(t, ts.Client(), ts.URL, body, sig, token, tc.event)
			if code != tc.wantCode {
				t.Fatalf("want %d, got %d (body=%v)", tc.wantCode, code, out)
			}
			if tc.wantReason != "" {
				requireNotTriggered(t, code, out, tc.wantReason)
				return
			}
			if code != http.StatusAccepted {
				return
			}
			if got, _ := out["triggered"].(bool); !got {
				t.Fatalf("want triggered=true, got %v", out)
			}
			runID, ok := out["run_id"].(float64)
			if !ok || int64(runID) < 1 {
				t.Fatalf("want run_id >= 1, got %v", out)
			}
			rn, err := srv.Store.GetRun(int64(runID))
			if err != nil {
				t.Fatalf("get run: %v", err)
			}
			if tc.wantTrigger != "" && rn.Trigger != tc.wantTrigger {
				t.Errorf("run trigger = %q, want %q", rn.Trigger, tc.wantTrigger)
			}
			if tc.wantSourceRef != "" && rn.SourceRef != tc.wantSourceRef {
				t.Errorf("run source_ref = %q, want %q", rn.SourceRef, tc.wantSourceRef)
			}
			if tc.wantSHA != "" && rn.SHA != tc.wantSHA {
				t.Errorf("run sha = %q, want %q", rn.SHA, tc.wantSHA)
			}
		})
	}
}

// TestGiteaPRRunMeta asserts the full PR metadata lands on the run row.
func TestGiteaPRRunMeta(t *testing.T) {
	ts, srv := newTestServer(t)
	t.Cleanup(ts.Close)
	t.Setenv(WebhookSecretEnv, webhookTestSecret)
	if _, err := srv.Store.UpsertPipeline("hookdemo", webhookPRAllYAML); err != nil {
		t.Fatalf("upsert pipeline: %v", err)
	}
	body := giteaPRPayload(t, "owner/hookdemo", "opened", "feature/x", "main", 12)
	code, out := doGiteaWebhook(t, ts.Client(), ts.URL, body, signWebhook(body, webhookTestSecret), "", "pull_request")
	if code != http.StatusAccepted {
		t.Fatalf("want 202, got %d (body=%v)", code, out)
	}
	runID, _ := out["run_id"].(float64)
	rn, err := srv.Store.GetRun(int64(runID))
	if err != nil {
		t.Fatalf("get run: %v", err)
	}
	if rn.Trigger != "pull_request" {
		t.Errorf("trigger = %q, want pull_request", rn.Trigger)
	}
	if rn.SourceRef != "feature/x" {
		t.Errorf("source_ref = %q, want feature/x", rn.SourceRef)
	}
	if rn.PR != 12 {
		t.Errorf("pr = %d, want 12", rn.PR)
	}
	if rn.HeadRef != "feature/x" {
		t.Errorf("head_ref = %q, want feature/x", rn.HeadRef)
	}
	if rn.BaseRef != "main" {
		t.Errorf("base_ref = %q, want main", rn.BaseRef)
	}
	if rn.RepoURL != "https://gitea.example.com/owner/hookdemo" {
		t.Errorf("repo_url = %q", rn.RepoURL)
	}
	if rn.SHA != "abc1234" {
		t.Errorf("sha = %q, want abc1234", rn.SHA)
	}
}

// TestGiteaWebhookConcurrency409: while a run from the first webhook is in
// flight on a concurrency-1 pipeline, a second webhook push gets 409.
func TestGiteaWebhookConcurrency409(t *testing.T) {
	ts, srv := newTestServer(t)
	t.Cleanup(ts.Close)
	t.Setenv(WebhookSecretEnv, webhookTestSecret)
	if _, err := srv.Store.UpsertPipeline("hookdemo", webhookSlowYAML); err != nil {
		t.Fatalf("upsert pipeline: %v", err)
	}

	body1, _ := json.Marshal(map[string]any{
		"ref": "refs/heads/main", "after": "cafe901",
		"repository": map[string]any{"full_name": "owner/hookdemo"},
	})
	code, out := doGiteaWebhook(t, ts.Client(), ts.URL, body1, signWebhook(body1, webhookTestSecret), "", "push")
	if code != http.StatusAccepted {
		t.Fatalf("first push: got %d, want 202 (body=%v)", code, out)
	}
	runID, _ := out["run_id"].(float64)
	done1 := make(chan error, 1)
	go fakeAgent(t, ts.Client(), ts.URL, "w1", int64(runID), 400*time.Millisecond, done1)

	body2, _ := json.Marshal(map[string]any{
		"ref": "refs/heads/main", "after": "cafe902",
		"repository": map[string]any{"full_name": "owner/hookdemo"},
	})
	code2, out2 := doGiteaWebhook(t, ts.Client(), ts.URL, body2, signWebhook(body2, webhookTestSecret), "", "push")
	if code2 != http.StatusConflict {
		t.Fatalf("second push while in flight: got %d, want 409 (body=%v)", code2, out2)
	}
}

// TestGiteaPing: a ping event answers 200 {"status":"ok"} regardless of
// payload content.
func TestGiteaPing(t *testing.T) {
	ts, _ := newTestServer(t)
	t.Cleanup(ts.Close)
	t.Setenv(WebhookSecretEnv, webhookTestSecret)
	body := []byte(`{"zen":"keep it easy"}`)
	code, out := doGiteaWebhook(t, ts.Client(), ts.URL, body, signWebhook(body, webhookTestSecret), "", "ping")
	if code != http.StatusOK {
		t.Fatalf("want 200, got %d", code)
	}
	if got, _ := out["status"].(string); got != "ok" {
		t.Fatalf("want status ok, got %v", out)
	}
}
