// Package api (webhook_gitlab.go) implements the GitLab (self-hosted SCM)
// webhook endpoint. GitLab payloads differ from the GitHub/Gitea shape:
// push hooks carry project.path_with_namespace, merge request hooks carry
// object_attributes (iid / action / source_branch / target_branch /
// source_sha). Merge request hooks are normalised to FlowStallion
// pull_request semantics (run trigger "pull_request").
//
// Auth: plain X-Gitlab-Token header compared in constant time against
// FLOWSTALLION_WEBHOOK_SECRET (same secret as the other webhook endpoints).
// Missing or wrong token -> 403; unset secret -> 503 (fail-closed).
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

// gitlabPushPayload carries the fields a GitLab push hook handler needs.
type gitlabPushPayload struct {
	ObjectKind string `json:"object_kind"` // anti-crossing guard: must be "push"
	Ref        string `json:"ref"`
	After      string `json:"after"`
	Project    struct {
		PathWithNamespace string `json:"path_with_namespace"`
		WebURL            string `json:"web_url"`
	} `json:"project"`
}

// gitlabMergeRequestPayload carries the fields a GitLab merge request hook
// handler needs.
type gitlabMergeRequestPayload struct {
	ObjectKind       string `json:"object_kind"` // anti-crossing guard: must be "merge_request"
	ObjectAttributes struct {
		IID          int    `json:"iid"`
		Action       string `json:"action"`
		SourceBranch string `json:"source_branch"`
		TargetBranch string `json:"target_branch"`
		SourceSHA    string `json:"source_sha"`
	} `json:"object_attributes"`
	Project struct {
		PathWithNamespace string `json:"path_with_namespace"`
		WebURL            string `json:"web_url"`
	} `json:"project"`
}

// gitlabMRActions are the merge request hook actions that trigger a run,
// normalised to FlowStallion pull_request semantics.
var gitlabMRActions = map[string]bool{
	"open":   true,
	"update": true,
	"reopen": true,
}

// handleGitLabWebhook serves POST /api/webhooks/gitlab.
//
//	503  FLOWSTALLION_WEBHOOK_SECRET not configured (fail-closed)
//	403  missing or invalid X-Gitlab-Token
//	200  Ping Event / unsupported event / unsupported action / no matching pipeline or trigger rule
//	409  pipeline concurrency limit reached
//	202  run enqueued
func (s *Server) handleGitLabWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxWebhookBody+1))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	if len(body) > maxWebhookBody {
		// task ⑨ P2: oversized payload is security-relevant — audit first.
		s.recordAs(r, "anonymous", AuditSCMInvalid, "scm:gitlab",
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
	if !hmac.Equal([]byte(r.Header.Get("X-Gitlab-Token")), []byte(secret)) {
		// task ⑨ P2: failed token check — audit as scm.invalid.
		s.recordAs(r, "anonymous", AuditSCMInvalid, "scm:gitlab",
			http.StatusForbidden, "invalid token")
		writeErr(w, http.StatusForbidden, "invalid token")
		return
	}

	switch event := r.Header.Get("X-Gitlab-Event"); event {
	case "Ping Event":
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	case "Push Hook":
		s.handleGitLabPush(w, r, body)
	case "Merge Request Hook":
		s.handleGitLabMergeRequest(w, r, body)
	default:
		writeJSON(w, http.StatusOK, map[string]any{
			"triggered": false,
			"reason":    fmt.Sprintf("event %q not supported", event),
		})
	}
}

// handleGitLabPush maps a GitLab push hook payload to a pipeline run.
// Pipeline name == last segment of project.path_with_namespace.
func (s *Server) handleGitLabPush(w http.ResponseWriter, r *http.Request, body []byte) {
	var p gitlabPushPayload
	if err := json.Unmarshal(body, &p); err != nil {
		writeErr(w, http.StatusBadRequest, "bad payload: "+err.Error())
		return
	}
	// Anti-crossing guard: a Push Hook delivery must carry object_kind=push.
	if p.ObjectKind != "push" {
		writeJSON(w, http.StatusOK, map[string]any{
			"triggered": false,
			"reason":    fmt.Sprintf("object_kind mismatch: got %q, want %q", p.ObjectKind, "push"),
		})
		return
	}
	const refPrefix = "refs/heads/"
	if !strings.HasPrefix(p.Ref, refPrefix) {
		writeJSON(w, http.StatusOK, map[string]any{"triggered": false, "reason": "non-branch ref"})
		return
	}
	branch := strings.TrimPrefix(p.Ref, refPrefix)

	// GitLab sends after=0000...0 (40 zeros) when a branch is deleted.
	if p.After == strings.Repeat("0", 40) {
		writeJSON(w, http.StatusOK, map[string]any{"triggered": false, "reason": "branch deletion (all-zero SHA)"})
		return
	}

	repo := repoName(p.Project.PathWithNamespace)
	if repo == "" {
		writeJSON(w, http.StatusOK, map[string]any{"triggered": false, "reason": "no repository name"})
		return
	}

	s.dispatchScmEvent(w, r, "gitlab", repo, "push", branch, store.RunMeta{SHA: p.After})
}

// handleGitLabMergeRequest maps a GitLab merge request hook payload to a
// pipeline run. Actions open/update/reopen are normalised to the
// pull_request trigger; the run carries PR metadata (iid, source/target
// branch, project web URL, source SHA).
func (s *Server) handleGitLabMergeRequest(w http.ResponseWriter, r *http.Request, body []byte) {
	var p gitlabMergeRequestPayload
	if err := json.Unmarshal(body, &p); err != nil {
		writeErr(w, http.StatusBadRequest, "bad payload: "+err.Error())
		return
	}
	if p.ObjectKind != "merge_request" {
		writeJSON(w, http.StatusOK, map[string]any{
			"triggered": false,
			"reason":    fmt.Sprintf("object_kind mismatch: got %q, want %q", p.ObjectKind, "merge_request"),
		})
		return
	}
	if !gitlabMRActions[p.ObjectAttributes.Action] {
		writeJSON(w, http.StatusOK, map[string]any{
			"triggered": false,
			"reason":    fmt.Sprintf("merge_request action %q not supported", p.ObjectAttributes.Action),
		})
		return
	}
	if p.ObjectAttributes.SourceBranch == "" {
		writeJSON(w, http.StatusOK, map[string]any{"triggered": false, "reason": "missing source_branch"})
		return
	}
	repo := repoName(p.Project.PathWithNamespace)
	if repo == "" {
		writeJSON(w, http.StatusOK, map[string]any{"triggered": false, "reason": "no repository name"})
		return
	}

	s.dispatchScmEvent(w, r, "gitlab", repo, "pull_request", p.ObjectAttributes.SourceBranch, store.RunMeta{
		PR:      p.ObjectAttributes.IID,
		HeadRef: p.ObjectAttributes.SourceBranch,
		BaseRef: p.ObjectAttributes.TargetBranch,
		RepoURL: p.Project.WebURL,
		SHA:     p.ObjectAttributes.SourceSHA,
	})
}
