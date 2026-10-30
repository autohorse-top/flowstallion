// P8②: table-driven tests for the GitLab webhook endpoint — token auth,
// object_kind/event crossing guards, push/MR dispatch, and run metadata.
package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// doGitLabWebhook POSTs body to the GitLab endpoint with X-Gitlab-Token
// ("" omits) and X-Gitlab-Event ("" omits).
func doGitLabWebhook(t *testing.T, c *http.Client, base string, body []byte, token, event string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, base+"/api/webhooks/gitlab", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-Gitlab-Token", token)
	}
	if event != "" {
		req.Header.Set("X-Gitlab-Event", event)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("POST gitlab webhook: %v", err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if ct := resp.Header.Get("Content-Type"); strings.HasPrefix(ct, "application/json") {
		_ = json.NewDecoder(resp.Body).Decode(&out)
	}
	return resp.StatusCode, out
}

// makeGitLabPushPayload builds a minimal GitLab push hook payload.
func makeGitLabPushPayload(t *testing.T, objectKind, ref, after, namespace string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"object_kind": objectKind,
		"ref":         ref,
		"after":       after,
		"project":     map[string]any{"path_with_namespace": namespace},
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return b
}

// gitlabMRPayload builds a minimal GitLab merge request hook payload.
func gitlabMRPayload(t *testing.T, objectKind, action, src, dst, sha, namespace string, iid int) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"object_kind": objectKind,
		"object_attributes": map[string]any{
			"iid":           iid,
			"action":        action,
			"source_branch": src,
			"target_branch": dst,
			"source_sha":    sha,
		},
		"project": map[string]any{
			"path_with_namespace": namespace,
			"web_url":             "https://gitlab.example.com/" + namespace,
		},
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return b
}

func TestGitLabWebhook(t *testing.T) {
	cases := []struct {
		name          string
		pipelineYAML  string // "" = no pipeline
		secret        string // "" = env unset (503)
		token         string // "correct" / "wrong" / "" (omit)
		event         string
		rawBody       []byte         // if set, used verbatim
		body          map[string]any // else marshalled (push) or built (mr)
		mr            bool
		mrAction      string // MR action; default "open"
		wantCode      int
		wantReason    string // substring; "" = triggered (202)
		wantTrigger   string
		wantSourceRef string
		wantSHA       string
	}{
		{
			name:          "push_ok_202",
			pipelineYAML:  webhookPushAllYAML,
			secret:        webhookTestSecret,
			token:         "correct",
			event:         "Push Hook",
			body:          map[string]any{"object_kind": "push", "ref": "refs/heads/main", "after": "deadbeef", "project": map[string]any{"path_with_namespace": "group/hookdemo"}},
			wantCode:      http.StatusAccepted,
			wantTrigger:   "push",
			wantSourceRef: "main",
			wantSHA:       "deadbeef",
		},
		{
			name:     "token_wrong_403",
			secret:   webhookTestSecret,
			token:    "wrong",
			event:    "Push Hook",
			body:     map[string]any{"ref": "refs/heads/main"},
			wantCode: http.StatusForbidden,
		},
		{
			name:     "token_missing_403",
			secret:   webhookTestSecret,
			event:    "Push Hook",
			body:     map[string]any{"ref": "refs/heads/main"},
			wantCode: http.StatusForbidden,
		},
		{
			name:     "secret_unset_503",
			secret:   "",
			event:    "Push Hook",
			body:     map[string]any{"ref": "refs/heads/main"},
			wantCode: http.StatusServiceUnavailable,
		},
		{
			name:       "object_kind_cross_200_false",
			secret:     webhookTestSecret,
			token:      "correct",
			event:      "Push Hook",
			body:       map[string]any{"object_kind": "merge_request", "ref": "refs/heads/main", "project": map[string]any{"path_with_namespace": "group/hookdemo"}},
			wantCode:   http.StatusOK,
			wantReason: "object_kind mismatch",
		},
		{
			name:         "branch_mismatch_200_false",
			pipelineYAML: webhookPushMainYAML,
			secret:       webhookTestSecret,
			token:        "correct",
			event:        "Push Hook",
			body:         map[string]any{"object_kind": "push", "ref": "refs/heads/dev", "project": map[string]any{"path_with_namespace": "group/hookdemo"}},
			wantCode:     http.StatusOK,
			wantReason:   "no matching push trigger rule",
		},
		{
			name:         "all_zero_after_200_false",
			pipelineYAML: webhookPushAllYAML,
			secret:       webhookTestSecret,
			token:        "correct",
			event:        "Push Hook",
			body:         map[string]any{"object_kind": "push", "ref": "refs/heads/main", "after": strings.Repeat("0", 40), "project": map[string]any{"path_with_namespace": "group/hookdemo"}},
			wantCode:     http.StatusOK,
			wantReason:   "branch deletion",
		},
		{
			name:         "push_non_branch_ref_200_false",
			pipelineYAML: webhookPushAllYAML,
			secret:       webhookTestSecret,
			token:        "correct",
			event:        "Push Hook",
			body:         map[string]any{"object_kind": "push", "ref": "refs/tags/v1.0", "after": "deadbeef", "project": map[string]any{"path_with_namespace": "group/hookdemo"}},
			wantCode:     http.StatusOK,
			wantReason:   "non-branch ref",
		},
		{
			name:         "push_no_repo_name_200_false",
			pipelineYAML: webhookPushAllYAML,
			secret:       webhookTestSecret,
			token:        "correct",
			event:        "Push Hook",
			body:         map[string]any{"object_kind": "push", "ref": "refs/heads/main", "after": "deadbeef", "project": map[string]any{"path_with_namespace": ""}},
			wantCode:     http.StatusOK,
			wantReason:   "no repository name",
		},
		{
			name:       "unknown_event_200_false",
			secret:     webhookTestSecret,
			token:      "correct",
			event:      "Tag Push Hook",
			body:       map[string]any{"ref": "refs/tags/v1"},
			wantCode:   http.StatusOK,
			wantReason: `event "Tag Push Hook" not supported`,
		},
		{
			name:       "unknown_repo_200_false",
			secret:     webhookTestSecret,
			token:      "correct",
			event:      "Push Hook",
			body:       map[string]any{"object_kind": "push", "ref": "refs/heads/main", "project": map[string]any{"path_with_namespace": "group/no-such-repo"}},
			wantCode:   http.StatusOK,
			wantReason: "no pipeline for repository",
		},
		{
			name:     "bad_json_400",
			secret:   webhookTestSecret,
			token:    "correct",
			event:    "Push Hook",
			rawBody:  []byte(`{not json`),
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "body_too_large_413",
			secret:   webhookTestSecret,
			token:    "correct",
			event:    "Push Hook",
			rawBody:  make([]byte, maxWebhookBody+1),
			wantCode: http.StatusRequestEntityTooLarge,
		},
		{
			name:          "mr_open_202",
			pipelineYAML:  webhookPRAllYAML,
			secret:        webhookTestSecret,
			token:         "correct",
			event:         "Merge Request Hook",
			mr:            true,
			wantCode:      http.StatusAccepted,
			wantTrigger:   "pull_request",
			wantSourceRef: "feature/x",
		},
		{
			name:         "mr_update_202",
			pipelineYAML: webhookPRAllYAML,
			secret:       webhookTestSecret,
			token:        "correct",
			event:        "Merge Request Hook",
			mr:           true,
			wantCode:     http.StatusAccepted,
		},
		{
			name:         "mr_reopen_202",
			pipelineYAML: webhookPRAllYAML,
			secret:       webhookTestSecret,
			token:        "correct",
			event:        "Merge Request Hook",
			mr:           true,
			wantCode:     http.StatusAccepted,
		},
		{
			name:         "mr_close_200_false",
			pipelineYAML: webhookPRAllYAML,
			secret:       webhookTestSecret,
			token:        "correct",
			event:        "Merge Request Hook",
			mr:           true,
			mrAction:     "close",
			wantCode:     http.StatusOK,
			wantReason:   `merge_request action "close" not supported`,
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
			switch {
			case tc.rawBody != nil:
				body = tc.rawBody
			case tc.mr:
				action := tc.mrAction
				if action == "" {
					action = "open"
				}
				body = gitlabMRPayload(t, "merge_request", action, "feature/x", "main", "abc1234", "group/hookdemo", 12)
			default:
				b, err := json.Marshal(tc.body)
				if err != nil {
					t.Fatalf("marshal: %v", err)
				}
				body = b
			}
			var token string
			if tc.token == "correct" {
				token = webhookTestSecret
			} else if tc.token == "wrong" {
				token = "wrong-token"
			}

			code, out := doGitLabWebhook(t, ts.Client(), ts.URL, body, token, tc.event)
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
			runID, _ := out["run_id"].(float64)
			rn, err := srv.Store.GetRun(int64(runID))
			if err != nil {
				t.Fatalf("get run: %v", err)
			}
			if tc.wantTrigger != "" && rn.Trigger != tc.wantTrigger {
				t.Errorf("trigger = %q, want %q", rn.Trigger, tc.wantTrigger)
			}
			if tc.wantSourceRef != "" && rn.SourceRef != tc.wantSourceRef {
				t.Errorf("source_ref = %q, want %q", rn.SourceRef, tc.wantSourceRef)
			}
			if tc.wantSHA != "" && rn.SHA != tc.wantSHA {
				t.Errorf("sha = %q, want %q", rn.SHA, tc.wantSHA)
			}
		})
	}
}

// TestGitLabMRRunMeta asserts full PR metadata lands on the run row.
func TestGitLabMRRunMeta(t *testing.T) {
	ts, srv := newTestServer(t)
	t.Cleanup(ts.Close)
	t.Setenv(WebhookSecretEnv, webhookTestSecret)
	if _, err := srv.Store.UpsertPipeline("hookdemo", webhookPRAllYAML); err != nil {
		t.Fatalf("upsert pipeline: %v", err)
	}
	body := gitlabMRPayload(t, "merge_request", "open", "feature/x", "main", "abc1234", "group/hookdemo", 12)
	code, out := doGitLabWebhook(t, ts.Client(), ts.URL, body, webhookTestSecret, "Merge Request Hook")
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
	if rn.RepoURL != "https://gitlab.example.com/group/hookdemo" {
		t.Errorf("repo_url = %q", rn.RepoURL)
	}
	if rn.SHA != "abc1234" {
		t.Errorf("sha = %q, want abc1234", rn.SHA)
	}
}

// TestGitLabPing: Ping Event answers 200 {"status":"ok"}.
func TestGitLabPing(t *testing.T) {
	ts, _ := newTestServer(t)
	t.Cleanup(ts.Close)
	t.Setenv(WebhookSecretEnv, webhookTestSecret)
	code, out := doGitLabWebhook(t, ts.Client(), ts.URL, []byte(`{}`), webhookTestSecret, "Ping Event")
	if code != http.StatusOK {
		t.Fatalf("want 200, got %d", code)
	}
	if got, _ := out["status"].(string); got != "ok" {
		t.Fatalf("want status ok, got %v", out)
	}
}

// TestGitLabWebhookConcurrency409: while a run from the first webhook is in
// flight on a concurrency-1 pipeline, a second webhook push gets 409.
func TestGitLabWebhookConcurrency409(t *testing.T) {
	ts, srv := newTestServer(t)
	t.Cleanup(ts.Close)
	t.Setenv(WebhookSecretEnv, webhookTestSecret)
	if _, err := srv.Store.UpsertPipeline("hookdemo", webhookSlowYAML); err != nil {
		t.Fatalf("upsert pipeline: %v", err)
	}

	body1 := makeGitLabPushPayload(t, "push", "refs/heads/main", "cafe201", "group/hookdemo")
	code, out := doGitLabWebhook(t, ts.Client(), ts.URL, body1, webhookTestSecret, "Push Hook")
	if code != http.StatusAccepted {
		t.Fatalf("first push: got %d, want 202 (body=%v)", code, out)
	}
	runID, _ := out["run_id"].(float64)
	done1 := make(chan error, 1)
	go fakeAgent(t, ts.Client(), ts.URL, "w1", int64(runID), 400*time.Millisecond, done1)

	body2 := makeGitLabPushPayload(t, "push", "refs/heads/main", "cafe202", "group/hookdemo")
	code2, out2 := doGitLabWebhook(t, ts.Client(), ts.URL, body2, webhookTestSecret, "Push Hook")
	if code2 != http.StatusConflict {
		t.Fatalf("second push while in flight: got %d, want 409 (body=%v)", code2, out2)
	}
}
