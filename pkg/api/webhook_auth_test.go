// P8③: regression test — with RBAC enabled the SCM webhook endpoints must
// remain open (they self-authenticate via signature/token, not user tokens).
package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
)

func TestWebhooksOpenWithAuth(t *testing.T) {
	ts := newAuthServer(t)
	t.Setenv(WebhookSecretEnv, webhookTestSecret)

	adminTok := loginToken(t, ts, "admin", "admin-pass-1")

	// Create pipelines via the API (admin token required).
	for _, name := range []string{"authhookgitea", "authhookgitlab"} {
		code, body := doReq(t, http.MethodPost, ts.URL+"/api/pipelines", adminTok, "",
			map[string]string{"name": name, "yaml": webhookPushAllYAML})
		if code != http.StatusCreated {
			t.Fatalf("create pipeline %s: got %d, body=%s", name, code, body)
		}
	}

	// --- Gitea: POST with valid HMAC signature, NO user Bearer token ---
	gBody, _ := json.Marshal(map[string]any{
		"ref":        "refs/heads/main",
		"after":      "aabbccdd",
		"repository": map[string]any{"full_name": "owner/authhookgitea"},
	})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/webhooks/gitea", bytes.NewReader(gBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Gitea-Signature", signWebhook(gBody, webhookTestSecret))
	req.Header.Set("X-Gitea-Event", "push")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("gitea webhook: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("gitea webhook with auth=on: got %d, want 202", resp.StatusCode)
	}

	// --- GitLab: POST with valid token, NO user Bearer token ---
	glBody, _ := json.Marshal(map[string]any{
		"object_kind": "push",
		"ref":         "refs/heads/main",
		"after":       "aabbccdd",
		"project":     map[string]any{"path_with_namespace": "group/authhookgitlab"},
	})
	req2, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/webhooks/gitlab", bytes.NewReader(glBody))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-Gitlab-Token", webhookTestSecret)
	req2.Header.Set("X-Gitlab-Event", "Push Hook")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("gitlab webhook: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusAccepted {
		t.Fatalf("gitlab webhook with auth=on: got %d, want 202", resp2.StatusCode)
	}

	// Negative: wrong token should still be 403 (not bypassed).
	req3, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/webhooks/gitlab", bytes.NewReader(glBody))
	req3.Header.Set("Content-Type", "application/json")
	req3.Header.Set("X-Gitlab-Token", "wrong")
	req3.Header.Set("X-Gitlab-Event", "Push Hook")
	resp3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatalf("gitlab webhook (wrong token): %v", err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusForbidden {
		t.Fatalf("gitlab wrong token: got %d, want 403", resp3.StatusCode)
	}
}
