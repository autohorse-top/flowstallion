// Package api (webhook.go) implements the GitHub webhook endpoint:
// HMAC-SHA256 signature verification (X-Hub-Signature-256), event filtering
// (ping / push / pull_request), repo→pipeline mapping (pipeline name ==
// repository name), and branch matching against the pipeline's declared
// trigger rules. Pull_request runs carry PR metadata (number, head/base
// ref, repo URL) on the run row.
//
// The shared dispatch tail (dispatchScmEvent) is reused by the Gitea and
// GitLab webhook endpoints (webhook_gitea.go, webhook_gitlab.go).
package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/flowstallion/flowstallion/pkg/pipeline"
	"github.com/flowstallion/flowstallion/pkg/scheduler"
	"github.com/flowstallion/flowstallion/pkg/store"
)

// WebhookSecretEnv is the environment variable holding the shared secret
// used to sign GitHub webhook payloads (HMAC-SHA256).
const WebhookSecretEnv = "FLOWSTALLION_WEBHOOK_SECRET"

// maxWebhookBody caps webhook payloads at 10 MiB (GitHub payloads are small;
// this bounds memory and DoS surface).
const maxWebhookBody = 10 << 20

// githubPushPayload carries the fields a push handler needs.
type githubPushPayload struct {
	Ref        string `json:"ref"`
	After      string `json:"after"` // P7④: pushed commit SHA (feeds {{sha}})
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
}

// githubPullRequestPayload carries the fields a pull_request handler needs.
type githubPullRequestPayload struct {
	Action      string `json:"action"`
	PullRequest struct {
		Number int `json:"number"`
		Head   struct {
			SHA string `json:"sha"`
			Ref string `json:"ref"`
		} `json:"head"`
		Base struct {
			Ref string `json:"ref"`
		} `json:"base"`
	} `json:"pull_request"`
	Repository struct {
		FullName string `json:"full_name"`
		HTMLURL  string `json:"html_url"`
	} `json:"repository"`
}

// prActions are the pull_request event actions that trigger a run.
var prActions = map[string]bool{
	"opened":      true,
	"synchronize": true,
	"reopened":    true,
}

// handleGitHubWebhook serves POST /api/webhooks/github.
//
//	503  FLOWSTALLION_WEBHOOK_SECRET not configured (fail-closed)
//	403  missing or invalid X-Hub-Signature-256
//	200  ping / unsupported event / unsupported action / no matching pipeline or trigger rule
//	409  pipeline concurrency limit reached
//	202  run enqueued
func (s *Server) handleGitHubWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxWebhookBody+1))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	if len(body) > maxWebhookBody {
		// task ⑨ P2: oversized payloads are security-relevant (probing /
		// DoS) — audit as scm.invalid before the 413.
		s.recordAs(r, "anonymous", AuditSCMInvalid, "scm:github",
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
	if !validWebhookSignature(body, r.Header.Get("X-Hub-Signature-256"), secret) {
		// task ⑨ P2: failed signature verification is a credential
		// attempt — audit as scm.invalid (brute-force observable).
		s.recordAs(r, "anonymous", AuditSCMInvalid, "scm:github",
			http.StatusForbidden, "invalid signature")
		writeErr(w, http.StatusForbidden, "invalid signature")
		return
	}

	switch event := r.Header.Get("X-GitHub-Event"); event {
	case "ping":
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	case "push":
		s.handleGitHubPush(w, r, body)
	case "pull_request":
		s.handleGitHubPullRequest(w, r, body)
	default:
		writeJSON(w, http.StatusOK, map[string]any{
			"triggered": false,
			"reason":    fmt.Sprintf("event %q not supported", event),
		})
	}
}

// handleGitHubPush maps a signed push payload to a pipeline run.
//
// Pipeline selection: pipeline name == repository name (last segment of
// full_name). Branch filter: a declared push trigger rule with an empty
// branch list matches every branch; otherwise the branch must match
// exactly (P1: exact match only, no glob support yet).
func (s *Server) handleGitHubPush(w http.ResponseWriter, r *http.Request, body []byte) {
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

	// N2: GitHub sends after=0000...0 (40 zeros) when a branch is deleted;
	// there is no commit to build, so answer without creating a run.
	if p.After == strings.Repeat("0", 40) {
		writeJSON(w, http.StatusOK, map[string]any{"triggered": false, "reason": "branch deletion (all-zero SHA)"})
		return
	}

	repo := repoName(p.Repository.FullName)
	if repo == "" {
		writeJSON(w, http.StatusOK, map[string]any{"triggered": false, "reason": "no repository name"})
		return
	}

	s.dispatchScmEvent(w, r, "github", repo, "push", branch, store.RunMeta{SHA: p.After})
}

// handleGitHubPullRequest maps a signed pull_request payload to a pipeline run.
//
// Only actions opened/synchronize/reopened trigger runs; every other action
// (closed, edited, commented, ...) answers 200 triggered=false. Pipeline
// selection and branch filtering mirror the push handler, but branch
// matching is applied to the PR's head branch and the run row carries PR
// metadata (number, head/base ref, repo URL).
func (s *Server) handleGitHubPullRequest(w http.ResponseWriter, r *http.Request, body []byte) {
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

	s.dispatchScmEvent(w, r, "github", repo, "pull_request", p.PullRequest.Head.Ref, store.RunMeta{
		PR:      p.PullRequest.Number,
		HeadRef: p.PullRequest.Head.Ref,
		BaseRef: p.PullRequest.Base.Ref,
		RepoURL: p.Repository.HTMLURL,
		SHA:     p.PullRequest.Head.SHA,
	})
}

// dispatchScmEvent is the shared tail of every SCM webhook handler
// (GitHub/Gitea/GitLab push & PR/MR): pipeline lookup by repository name,
// YAML validation, branch-rule matching, run creation.
//
// Response contract (written exactly once per call):
//
//	200 {"triggered":false,"reason":...}  no pipeline / invalid pipeline /
//	                                       no matching trigger rule
//	409                                   pipeline concurrency limit reached
//	500                                   unexpected store/scheduler error
//	202 {"triggered":true,"run_id":id}    run enqueued
//
// triggerType is "push" or "pull_request"; it is used both as the run's
// trigger label and as the pipeline trigger-rule event to match against.
//
// provider ("github"/"gitea"/"gitlab") is used for the audit actor
// "scm:<provider>"; on successful run creation an audit event
// (scm.push / scm.pull_request) is recorded.
func (s *Server) dispatchScmEvent(w http.ResponseWriter, r *http.Request, provider, pipelineName, triggerType, ref string, meta store.RunMeta) {
	pl, err := s.Store.GetPipelineByName(pipelineName)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusOK, map[string]any{"triggered": false, "reason": "no pipeline for repository"})
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	parsed, err := pipeline.ParseYAML([]byte(pl.YAMLText))
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"triggered": false, "reason": "pipeline invalid: " + err.Error()})
		return
	}
	if !matchEventRule(parsed, triggerType, ref) {
		writeJSON(w, http.StatusOK, map[string]any{
			"triggered": false,
			"reason":    fmt.Sprintf("no matching %s trigger rule", triggerType),
		})
		return
	}

	runID, err := s.Sched.TriggerWithMeta(pipelineName, triggerType, ref, meta)
	if err != nil {
		if errors.Is(err, scheduler.ErrLimit) {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Audit: record the SCM-originated run (task ③). actor is "scm:<provider>";
	// detail carries repo + branch (push) or repo + PR number (pull_request).
	action, detail := AuditSCMPush, fmt.Sprintf("repo=%s ref=%s", pipelineName, ref)
	if triggerType == "pull_request" {
		action, detail = AuditSCMPullRequest, fmt.Sprintf("repo=%s pr=%d", pipelineName, meta.PR)
	}
	s.recordAs(r, "scm:"+provider, action, fmt.Sprintf("run:%d", runID), http.StatusAccepted, detail)
	writeJSON(w, http.StatusAccepted, map[string]any{"triggered": true, "run_id": runID})
}

// repoName returns the repository name (last segment) of a GitHub
// "owner/name" full_name; "" when full_name is empty.
func repoName(fullName string) string {
	if i := strings.LastIndex(fullName, "/"); i >= 0 {
		return fullName[i+1:]
	}
	return fullName
}

// validWebhookSignature reports whether sig ("sha256=<hex>") is the
// HMAC-SHA256 of body under secret. The comparison is constant-time.
func validWebhookSignature(body []byte, sig, secret string) bool {
	const want = "sha256="
	if !strings.HasPrefix(sig, want) {
		return false
	}
	got, err := hex.DecodeString(strings.TrimPrefix(sig, want))
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hmac.Equal(got, mac.Sum(nil))
}

// matchEventRule reports whether the pipeline declares a trigger rule for
// event whose branch filter applies to ref. An empty branch list matches
// every branch (P1: exact match only, no glob support yet).
func matchEventRule(pl pipeline.Pipeline, event, ref string) bool {
	for _, tr := range pl.Pipeline.Trigger {
		if tr.Event != event {
			continue
		}
		if len(tr.Branches) == 0 {
			return true
		}
		for _, b := range tr.Branches {
			if b == ref {
				return true
			}
		}
	}
	return false
}
