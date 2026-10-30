// Package api (webhook_gitea.go) implements the Gitea (self-hosted SCM)
// webhook endpoint. Gitea's push / pull_request payloads mirror the GitHub
// format, so the payload structs and action filter are shared with
// webhook.go; the response dispatch tail is shared via dispatchScmEvent.
//
// Auth: X-Gitea-Signature (HMAC-SHA256, "sha256=<hex>") if present,
// otherwise X-Gitea-Token (plain token). Both are compared in constant
// time against FLOWSTALLION_WEBHOOK_SECRET (same secret as the GitHub
// endpoint). Missing both credentials -> 403; unset secret -> 503.
package api

import (
	"crypto/hmac"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/flowstallion/flowstallion/pkg/store"
)

// handleGiteaWebhook serves POST /api/webhooks/gitea.
//
//	503  FLOWSTALLION_WEBHOOK_SECRET not configured (fail-closed)
//	403  missing or invalid X-Gitea-Signature / X-Gitea-Token
//	200  ping / unsupported event / unsupported action / no matching pipeline or trigger rule
//	409  pipeline concurrency limit reached
//	202  run enqueued
func (s *Server) handleGiteaWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxWebhookBody+1))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	if len(body) > maxWebhookBody {
		// task ⑨ P2: oversized payload is security-relevant — audit first.
		s.recordAs(r, "anonymous", AuditSCMInvalid, "scm:gitea",
			http.StatusRequestEntityTooLarge, "payload too large")
		writeErr(w, http.StatusRequestEntityTooLarge, "webhook payload too large")
		return
	}

	secret := os.Getenv(WebhookSecretEnv)
	if secret == "" {
		writeErr(w, http.StatusServiceUnavailable,
			"webhook secret not configured (set "+WebhookSecretEnv+")")
		return
	}
	if !giteaCredentialOK(body, r.Header.Get("X-Gitea-Signature"),
		r.Header.Get("X-Gitea-Token"), secret) {
		// task ⑨ P2: failed credential check (signature or token) — audit
		// as scm.invalid so brute-force attempts are observable.
		s.recordAs(r, "anonymous", AuditSCMInvalid, "scm:gitea",
			http.StatusForbidden, "invalid signature or token")
		writeErr(w, http.StatusForbidden, "invalid signature")
		return
	}

	switch event := r.Header.Get("X-Gitea-Event"); event {
	case "ping":
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	case "push":
		s.handleGiteaPush(w, r, body)
	case "pull_request":
		s.handleGiteaPullRequest(w, r, body)
	default:
		writeJSON(w, http.StatusOK, map[string]any{
			"triggered": false,
			"reason":    fmt.Sprintf("event %q not supported", event),
		})
	}
}

// giteaCredentialOK verifies the Gitea credential in constant time:
// X-Gitea-Signature (HMAC-SHA256 over body) takes precedence; otherwise
// the plain X-Gitea-Token is compared against the shared secret.
func giteaCredentialOK(body []byte, sig, token, secret string) bool {
	if sig != "" {
		return validWebhookSignature(body, sig, secret)
	}
	if token != "" {
		return hmac.Equal([]byte(token), []byte(secret))
	}
	return false
}

// handleGiteaPush maps a Gitea push payload (GitHub-compatible shape) to a
// pipeline run: pipeline name == last segment of repository.full_name.
func (s *Server) handleGiteaPush(w http.ResponseWriter, r *http.Request, body []byte) {
	var p githubPushPayload
	if err := json.Unmarshal(body, &p); err != nil {
		writeErr(w, http.StatusBadRequest, "bad payload: "+err.Error())
		return
	}
	const refPrefix = "refs/heads/"
	if !strings.HasPrefix(p.Ref, refPrefix) {
		writeJSON(w, http.StatusOK, map[string]any{"triggered": false, "reason": "non-branch ref"})
		return
	}
	branch := strings.TrimPrefix(p.Ref, refPrefix)

	// Gitea sends after=0000...0 (40 zeros) when a branch is deleted.
	if p.After == strings.Repeat("0", 40) {
		writeJSON(w, http.StatusOK, map[string]any{"triggered": false, "reason": "branch deletion (all-zero SHA)"})
		return
	}

	repo := repoName(p.Repository.FullName)
	if repo == "" {
		writeJSON(w, http.StatusOK, map[string]any{"triggered": false, "reason": "no repository name"})
		return
	}

	s.dispatchScmEvent(w, r, "gitea", repo, "push", branch, store.RunMeta{SHA: p.After})
}

// handleGiteaPullRequest maps a Gitea pull_request payload (GitHub-compatible
// shape) to a pipeline run. Actions follow the shared prActions set
// (opened/synchronize/reopened); the run carries PR metadata.
func (s *Server) handleGiteaPullRequest(w http.ResponseWriter, r *http.Request, body []byte) {
	var p githubPullRequestPayload
	if err := json.Unmarshal(body, &p); err != nil {
		writeErr(w, http.StatusBadRequest, "bad payload: "+err.Error())
		return
	}
	if !prActions[p.Action] {
		writeJSON(w, http.StatusOK, map[string]any{
			"triggered": false,
			"reason":    fmt.Sprintf("pull_request action %q not supported", p.Action),
		})
		return
	}
	repo := repoName(p.Repository.FullName)
	if repo == "" {
		writeJSON(w, http.StatusOK, map[string]any{"triggered": false, "reason": "no repository name"})
		return
	}
	if p.PullRequest.Head.Ref == "" {
		writeJSON(w, http.StatusOK, map[string]any{"triggered": false, "reason": "missing pull_request.head.ref"})
		return
	}

	s.dispatchScmEvent(w, r, "gitea", repo, "pull_request", p.PullRequest.Head.Ref, store.RunMeta{
		PR:      p.PullRequest.Number,
		HeadRef: p.PullRequest.Head.Ref,
		BaseRef: p.PullRequest.Base.Ref,
		RepoURL: p.Repository.HTMLURL,
		SHA:     p.PullRequest.Head.SHA,
	})
}
