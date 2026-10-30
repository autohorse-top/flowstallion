// Audit-log core (task ③): action/outcome vocabulary, the best-effort
// record helpers every mutation/auth/SCM path calls, and the read endpoint
// GET /api/audit.
//
// Invariants:
//   - Recording is best-effort. A failed audit write logs to stderr and
//     never changes the response the main path already produced.
//   - Detail strings carry key=value / short JSON context and are capped
//     (detailMax). They must never contain passwords or secret values.
//   - The action vocabulary is a closed set (docs/audit.md).
package api

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/flowstallion/flowstallion/pkg/store"
)

// Action vocabulary (closed set).
const (
	AuditAuthLogin      = "auth.login"
	AuditAuthLogout     = "auth.logout"
	AuditAuthDeny       = "auth.deny"
	AuditPipelineUpsert = "pipeline.upsert"
	AuditRunTrigger     = "run.trigger"
	AuditRunCancel      = "run.cancel"
	AuditRunApprove     = "run.approve"
	AuditRunReject      = "run.reject"
	AuditScanSave       = "scan.save"
	AuditCanaryCreate   = "canary.create"
	AuditCanaryRollback = "canary.rollback"
	AuditUserCreate     = "user.create"
	AuditUserDelete     = "user.delete"
	AuditSecretUpsert   = "secret.upsert"
	AuditSecretDelete   = "secret.delete"
	AuditSCMPush        = "scm.push"
	AuditSCMPullRequest = "scm.pull_request"
	// AuditSCMInvalid records rejected webhook deliveries (403 bad
	// signature/token, 413 oversized payload) so brute-force and probing
	// attempts against the SCM endpoints are observable (task ⑨ P2). The
	// 503 fail-closed branch is deliberately not audited: it reveals no
	// credential attempt and would flood the table while the secret is
	// unset.
	AuditSCMInvalid = "scm.invalid"
)

// Outcome vocabulary (closed set).
const (
	OutcomeOK       = "ok"
	OutcomeInvalid  = "invalid"
	OutcomeDenied   = "denied"
	OutcomeNotFound = "not_found"
	OutcomeConflict = "conflict"
	OutcomeError    = "error"
)

// detailMax caps audit detail strings (rune-safe) so a large body cannot
// bloat the audit table.
const detailMax = 2000

// outcomeFromStatus maps an HTTP status to the audit outcome vocabulary.
// 2xx→ok; 400→invalid; 401/403→denied; 404→not_found; 409→conflict;
// 5xx→error. Any other 4xx maps to "invalid" (the request was rejected by
// the API, not by RBAC).
func outcomeFromStatus(status int) string {
	switch {
	case status >= 200 && status < 300:
		return OutcomeOK
	case status == http.StatusBadRequest:
		return OutcomeInvalid
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return OutcomeDenied
	case status == http.StatusNotFound:
		return OutcomeNotFound
	case status == http.StatusConflict:
		return OutcomeConflict
	case status >= 500:
		return OutcomeError
	default:
		return OutcomeInvalid
	}
}

// truncateDetail rune-safely truncates s to detailMax characters.
func truncateDetail(s string) string {
	if len(s) <= detailMax {
		return s
	}
	r := []rune(s)
	if len(r) > detailMax {
		return string(r[:detailMax])
	}
	return s
}

// remoteHost extracts the client IP from RemoteAddr (the host part); when
// RemoteAddr has no parseable host:port it is returned as-is, and "" when
// absent.
func remoteHost(r *http.Request) string {
	if r == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// actorFromRequest resolves the audit actor for an in-flight request: the
// authenticated username when auth is enabled and the request carries a
// valid user token, otherwise "anonymous". Callers without a user identity
// (webhooks, agent tokens) record with an explicit actor via recordAs.
func (s *Server) actorFromRequest(r *http.Request) string {
	if a := s.Auth; a != nil && a.Enabled() {
		if u, ok := a.UserFromRequest(r); ok {
			return u.Username
		}
	}
	return "anonymous"
}

// record appends an audit event for a completed request, resolving the actor
// from the request itself. Best-effort: failures log to stderr and never
// affect the response.
func (s *Server) record(r *http.Request, action, target string, status int, detail string) {
	s.recordAs(r, s.actorFromRequest(r), action, target, status, detail)
}

// sanitizeDetail flattens control characters that a client could use to
// forge extra audit lines out of one detail value (detail is a single
// key=value string): '\n', '\r' and '\t' become spaces. Applied once in
// recordAs — the single choke point every audit write goes through — so no
// call site can bypass it.
func sanitizeDetail(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', '\t':
			return ' '
		}
		return r
	}, s)
}

// recordAs appends an audit event with an explicit actor (used for webhook
// events "scm:<provider>" and for login, where the actor is the account
// being logged into, not the request's bearer).
func (s *Server) recordAs(r *http.Request, actor, action, target string, status int, detail string) {
	if s.Store == nil {
		return
	}
	if err := s.Store.AddAuditEvent(store.AuditEvent{
		Actor:   actor,
		Action:  action,
		Target:  target,
		Outcome: outcomeFromStatus(status),
		Detail:  truncateDetail(sanitizeDetail(detail)),
		Src:     remoteHost(r),
	}); err != nil {
		fmt.Fprintf(os.Stderr, "audit: record %s %s: %v\n", action, target, err)
	}
}

// auditEventJSON is the wire form of one audit event.
type auditEventJSON struct {
	ID      int64  `json:"id"`
	TS      string `json:"ts"`
	Actor   string `json:"actor"`
	Action  string `json:"action"`
	Target  string `json:"target"`
	Outcome string `json:"outcome"`
	Detail  string `json:"detail"`
	Src     string `json:"src"`
}

// handleListAudit: GET /api/audit (viewer). Query parameters:
//
//	actor / action / target — exact-match filters (optional)
//	after   — id cursor, only events with id < after (optional)
//	since   — RFC3339 time lower bound, only events with ts >= since (optional);
//	            combined with after when both are given (after is applied first
//	            via the store, both are AND-ed in SQL)
//	limit   — page size; default 50, capped at 200 by the store
func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.AuditFilter{
		Actor:  q.Get("actor"),
		Action: q.Get("action"),
		Target: q.Get("target"),
	}
	if v := q.Get("after"); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil || id <= 0 {
			writeErr(w, http.StatusBadRequest, "after must be a positive integer id")
			return
		}
		f.After = id
	}
	if v := q.Get("since"); v != "" {
		since, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeErr(w, http.StatusBadRequest, `since must be an RFC3339 timestamp, e.g. "2026-10-29T00:00:00Z"`)
			return
		}
		f.Since = since
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			writeErr(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		f.Limit = n
	}
	events, err := s.Store.ListAuditEvents(f)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]auditEventJSON, 0, len(events))
	for _, e := range events {
		out = append(out, auditEventJSON{
			ID: e.ID, TS: e.TS, Actor: e.Actor, Action: e.Action,
			Target: e.Target, Outcome: e.Outcome, Detail: e.Detail, Src: e.Src,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": out})
}
