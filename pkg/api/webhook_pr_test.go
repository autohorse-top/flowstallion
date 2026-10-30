// P7②: table-driven tests for the pull_request webhook path —
// supported actions, action filtering, signature checks, pipeline /
// branch matching, and PR metadata stored on the run row.
package api

import (
	"encoding/json"
	"net/http"
	"testing"
)

// webhookPRAllYAML declares a pull_request trigger with no branch filter.
const webhookPRAllYAML = `
version: 1
pipeline:
  name: hookdemo
  trigger:
    - event: pull_request
  steps:
    - id: a
      image: alpine
      commands:
        - echo a
`

// webhookPRMainYAML only triggers pull_request runs when head ref == main.
const webhookPRMainYAML = `
version: 1
pipeline:
  name: hookdemo
  trigger:
    - event: pull_request
      branches: [main]
  steps:
    - id: a
      image: alpine
      commands:
        - echo a
`

// prPayload builds a minimal GitHub pull_request payload.
func prPayload(t *testing.T, repo, action, headRef, baseRef string, pr int) []byte {
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
			"html_url":  "https://github.com/" + repo,
		},
	})
	if err != nil {
		t.Fatalf("marshal pr payload: %v", err)
	}
	return b
}

func TestWebhookPullRequestTable(t *testing.T) {
	cases := []struct {
		name         string
		pipelineYAML string // "" = no pipeline upserted
		secret       string // "" = env var unset (503 expected)
		sig          string // "" = signed with the correct secret; "wrong" = wrong secret; "none" = header omitted
		body         map[string]any
		wantCode     int
		wantReason   string // substring; "" = triggered=true (202)
		wantMeta     bool   // verify PR metadata on the run row
	}{
		{
			name:         "opened_triggers_202",
			pipelineYAML: webhookPRAllYAML,
			secret:       webhookTestSecret,
			body:         map[string]any{"action": "opened", "pr": 7},
			wantCode:     http.StatusAccepted,
			wantMeta:     true,
		},
		{
			name:         "synchronize_triggers_202",
			pipelineYAML: webhookPRAllYAML,
			secret:       webhookTestSecret,
			body:         map[string]any{"action": "synchronize", "pr": 7},
			wantCode:     http.StatusAccepted,
		},
		{
			name:         "reopened_triggers_202",
			pipelineYAML: webhookPRAllYAML,
			secret:       webhookTestSecret,
			body:         map[string]any{"action": "reopened", "pr": 7},
			wantCode:     http.StatusAccepted,
		},
		{
			name:         "closed_not_supported",
			pipelineYAML: webhookPRAllYAML,
			secret:       webhookTestSecret,
			body:         map[string]any{"action": "closed", "pr": 7},
			wantCode:     http.StatusOK,
			wantReason:   `action "closed" not supported`,
		},
		{
			name:         "edited_not_supported",
			pipelineYAML: webhookPRAllYAML,
			secret:       webhookTestSecret,
			body:         map[string]any{"action": "edited", "pr": 7},
			wantCode:     http.StatusOK,
			wantReason:   `action "edited" not supported`,
		},
		{
			name:         "bad_signature_403",
			pipelineYAML: webhookPRAllYAML,
			secret:       webhookTestSecret,
			sig:          "wrong",
			body:         map[string]any{"action": "opened", "pr": 7},
			wantCode:     http.StatusForbidden,
		},
		{
			name:         "missing_signature_403",
			pipelineYAML: webhookPRAllYAML,
			secret:       webhookTestSecret,
			sig:          "none", // omit the header entirely
			body:         map[string]any{"action": "opened", "pr": 7},
			wantCode:     http.StatusForbidden,
		},
		{
			name:     "secret_unset_503",
			secret:   "",
			body:     map[string]any{"action": "opened", "pr": 7},
			wantCode: http.StatusServiceUnavailable,
		},
		{
			name:       "unknown_repo_200_false",
			secret:     webhookTestSecret,
			body:       map[string]any{"action": "opened", "pr": 7, "repo": "owner/no-such-repo"},
			wantCode:   http.StatusOK,
			wantReason: "no pipeline for repository",
		},
		{
			name:         "pipeline_without_pr_trigger_200_false",
			pipelineYAML: webhookPushAllYAML, // push-only trigger
			secret:       webhookTestSecret,
			body:         map[string]any{"action": "opened", "pr": 7},
			wantCode:     http.StatusOK,
			wantReason:   "no matching pull_request trigger rule",
		},
		{
			name:         "branch_mismatch_200_false",
			pipelineYAML: webhookPRMainYAML, // branches: [main]
			secret:       webhookTestSecret,
			body:         map[string]any{"action": "opened", "pr": 7, "head": "develop"},
			wantCode:     http.StatusOK,
			wantReason:   "no matching pull_request trigger rule",
		},
		{
			name:         "branch_match_202",
			pipelineYAML: webhookPRMainYAML, // branches: [main]
			secret:       webhookTestSecret,
			body:         map[string]any{"action": "opened", "pr": 7, "head": "main"},
			wantCode:     http.StatusAccepted,
			wantMeta:     true,
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

			repo := "owner/hookdemo"
			if r, ok := tc.body["repo"].(string); ok {
				repo = r
			}
			head := "feature/login"
			if h, ok := tc.body["head"].(string); ok {
				head = h
			}
			action, _ := tc.body["action"].(string)
			pr, _ := tc.body["pr"].(int)
			body := prPayload(t, repo, action, head, "main", pr)

			sig := ""
			switch tc.sig {
			case "":
				sig = signWebhook(body, webhookTestSecret)
			case "wrong":
				sig = signWebhook(body, "wrong-secret")
			}
			// For the secret-unset case the signature is irrelevant (503 first);
			// pass whatever to exercise the code path.
			if tc.secret == "" {
				sig = signWebhook(body, "anything")
			}

			code, out := doWebhook(t, ts.Client(), ts.URL, body, sig, "pull_request")
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

			if tc.wantMeta {
				rn, err := srv.Store.GetRun(int64(runID))
				if err != nil {
					t.Fatalf("get run: %v", err)
				}
				if rn.Trigger != "pull_request" {
					t.Errorf("run trigger = %q, want pull_request", rn.Trigger)
				}
				if rn.SourceRef != head {
					t.Errorf("run source_ref = %q, want %q", rn.SourceRef, head)
				}
				if rn.PR != pr {
					t.Errorf("run PR = %d, want %d", rn.PR, pr)
				}
				if rn.HeadRef != head {
					t.Errorf("run head_ref = %q, want %q", rn.HeadRef, head)
				}
				if rn.BaseRef != "main" {
					t.Errorf("run base_ref = %q, want main", rn.BaseRef)
				}
				if rn.RepoURL != "https://github.com/"+repo {
					t.Errorf("run repo_url = %q", rn.RepoURL)
				}
			}
		})
	}
}

// TestWebhookPushRunHasNoPRMeta is the push-path regression check: a push
// run must carry zero PR metadata (all four fields zero/empty).
func TestWebhookPushRunHasNoPRMeta(t *testing.T) {
	ts, srv := newTestServer(t)
	t.Cleanup(ts.Close)
	t.Setenv(WebhookSecretEnv, webhookTestSecret)
	if _, err := srv.Store.UpsertPipeline("hookdemo", webhookPushAllYAML); err != nil {
		t.Fatalf("upsert pipeline: %v", err)
	}
	body := pushPayload(t, "owner/hookdemo", "refs/heads/main")
	code, out := doWebhook(t, ts.Client(), ts.URL, body, signWebhook(body, webhookTestSecret), "push")
	if code != http.StatusAccepted {
		t.Fatalf("want 202, got %d (body=%v)", code, out)
	}
	runID, _ := out["run_id"].(float64)
	rn, err := srv.Store.GetRun(int64(runID))
	if err != nil {
		t.Fatalf("get run: %v", err)
	}
	if rn.Trigger != "push" {
		t.Errorf("trigger = %q, want push", rn.Trigger)
	}
	if rn.PR != 0 || rn.BaseRef != "" || rn.HeadRef != "" || rn.RepoURL != "" {
		t.Errorf("push run must have zero PR metadata, got %+v", rn)
	}
}
