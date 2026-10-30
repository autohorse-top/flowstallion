// Task ⑨ P2: rejected webhook deliveries are audited as scm.invalid.
//
//   - 403 (wrong signature / wrong token / no credentials) → one
//     scm.invalid event, actor=anonymous, target=scm:<provider>,
//     outcome=denied.
//   - 413 (payload over the cap) → one scm.invalid event, outcome=invalid,
//     detail "payload too large".
//   - 503 (secret not configured, fail-closed) → NO audit event (decided:
//     it reveals no credential attempt and would flood the table).
package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/flowstallion/flowstallion/pkg/store"
)

// doWebhookRaw POSTs a raw body to the given endpoint path with the given
// headers; returns status and parsed JSON (nil when not JSON).
func doWebhookRaw(t *testing.T, c *http.Client, base, path string, body []byte, hdr map[string]string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, base+path, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if ct := resp.Header.Get("Content-Type"); strings.HasPrefix(ct, "application/json") {
		_ = json.NewDecoder(resp.Body).Decode(&out)
	}
	return resp.StatusCode, out
}

// requireSCMInvalidAudit asserts the newest audit event is scm.invalid with
// the given actor/target/outcome/detail.
func requireSCMInvalidAudit(t *testing.T, st *store.Store, target, outcome, detail string) {
	t.Helper()
	ev := latestAudit(t, st, AuditSCMInvalid)
	if ev.Actor != "anonymous" {
		t.Errorf("actor = %q, want anonymous", ev.Actor)
	}
	if ev.Target != target {
		t.Errorf("target = %q, want %q", ev.Target, target)
	}
	if ev.Outcome != outcome {
		t.Errorf("outcome = %q, want %q", ev.Outcome, outcome)
	}
	if ev.Detail != detail {
		t.Errorf("detail = %q, want %q", ev.Detail, detail)
	}
}

func countSCMInvalid(t *testing.T, st *store.Store) int {
	t.Helper()
	evs, err := st.ListAuditEvents(store.AuditFilter{Action: AuditSCMInvalid, Limit: 200})
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	return len(evs)
}

func TestWebhookSCMInvalidAudit(t *testing.T) {
	cases := []struct {
		name        string
		path        string
		headers     map[string]string
		body        []byte
		wantCode    int
		wantTarget  string
		wantOutcome string
		wantDetail  string
	}{
		{
			name:        "github_wrong_signature_403",
			path:        "/api/webhooks/github",
			headers:     map[string]string{"X-Hub-Signature-256": signWebhook([]byte("{}"), "wrong-secret"), "X-GitHub-Event": "ping"},
			body:        []byte("{}"),
			wantCode:    http.StatusForbidden,
			wantTarget:  "scm:github",
			wantOutcome: OutcomeDenied,
			wantDetail:  "invalid signature",
		},
		{
			name:        "gitea_wrong_token_403",
			path:        "/api/webhooks/gitea",
			headers:     map[string]string{"X-Gitea-Token": "wrong-token", "X-Gitea-Event": "ping"},
			body:        []byte("{}"),
			wantCode:    http.StatusForbidden,
			wantTarget:  "scm:gitea",
			wantOutcome: OutcomeDenied,
			wantDetail:  "invalid signature or token",
		},
		{
			name:        "gitlab_wrong_token_403",
			path:        "/api/webhooks/gitlab",
			headers:     map[string]string{"X-Gitlab-Token": "wrong-token", "X-Gitlab-Event": "Ping Event"},
			body:        []byte("{}"),
			wantCode:    http.StatusForbidden,
			wantTarget:  "scm:gitlab",
			wantOutcome: OutcomeDenied,
			wantDetail:  "invalid token",
		},
		{
			name:        "github_payload_too_large_413",
			path:        "/api/webhooks/github",
			headers:     map[string]string{"X-GitHub-Event": "push"},
			body:        make([]byte, maxWebhookBody+1),
			wantCode:    http.StatusRequestEntityTooLarge,
			wantTarget:  "scm:github",
			wantOutcome: OutcomeInvalid,
			wantDetail:  "payload too large",
		},
		{
			name:        "gitea_payload_too_large_413",
			path:        "/api/webhooks/gitea",
			headers:     map[string]string{"X-Gitea-Event": "push"},
			body:        make([]byte, maxWebhookBody+1),
			wantCode:    http.StatusRequestEntityTooLarge,
			wantTarget:  "scm:gitea",
			wantOutcome: OutcomeInvalid,
			wantDetail:  "payload too large",
		},
		{
			name:        "gitlab_payload_too_large_413",
			path:        "/api/webhooks/gitlab",
			headers:     map[string]string{"X-Gitlab-Event": "Push Hook"},
			body:        make([]byte, maxWebhookBody+1),
			wantCode:    http.StatusRequestEntityTooLarge,
			wantTarget:  "scm:gitlab",
			wantOutcome: OutcomeInvalid,
			wantDetail:  "payload too large",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts, srv := newTestServer(t)
			t.Cleanup(ts.Close)
			t.Setenv(WebhookSecretEnv, webhookTestSecret)
			if tc.name == "gitea_payload_too_large_413" {
				// The gitea 413 fires before any credential check, so the
				// (valid) token is irrelevant — but set it to prove order.
				tc.headers["X-Gitea-Token"] = webhookTestSecret
			}
			if tc.name == "gitlab_payload_too_large_413" {
				tc.headers["X-Gitlab-Token"] = webhookTestSecret
			}
			code, _ := doWebhookRaw(t, ts.Client(), ts.URL, tc.path, tc.body, tc.headers)
			if code != tc.wantCode {
				t.Fatalf("want %d, got %d", tc.wantCode, code)
			}
			if got := countSCMInvalid(t, srv.Store); got != 1 {
				t.Fatalf("scm.invalid events = %d, want 1", got)
			}
			requireSCMInvalidAudit(t, srv.Store, tc.wantTarget, tc.wantOutcome, tc.wantDetail)
		})
	}
}

// TestWebhook503NotAudited pins the decided behaviour: the fail-closed 503
// (secret unset) writes no audit event, so an unconfigured server cannot be
// used as an audit flood / DoS vector.
func TestWebhook503NotAudited(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		headers map[string]string
	}{
		{"github", "/api/webhooks/github", map[string]string{"X-Hub-Signature-256": signWebhook([]byte("{}"), "anything"), "X-GitHub-Event": "ping"}},
		{"gitea", "/api/webhooks/gitea", map[string]string{"X-Gitea-Token": "anything", "X-Gitea-Event": "ping"}},
		{"gitlab", "/api/webhooks/gitlab", map[string]string{"X-Gitlab-Token": "anything", "X-Gitlab-Event": "Ping Event"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts, srv := newTestServer(t)
			t.Cleanup(ts.Close)
			t.Setenv(WebhookSecretEnv, "") // not configured
			code, _ := doWebhookRaw(t, ts.Client(), ts.URL, tc.path, []byte("{}"), tc.headers)
			if code != http.StatusServiceUnavailable {
				t.Fatalf("want 503, got %d", code)
			}
			if got := countSCMInvalid(t, srv.Store); got != 0 {
				t.Fatalf("scm.invalid events = %d after 503, want 0", got)
			}
		})
	}
}
