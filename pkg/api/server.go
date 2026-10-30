package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/flowstallion/flowstallion/pkg/auth"
	"github.com/flowstallion/flowstallion/pkg/cd"
	"github.com/flowstallion/flowstallion/pkg/pipeline"
	"github.com/flowstallion/flowstallion/pkg/scheduler"
	"github.com/flowstallion/flowstallion/pkg/secret"
	"github.com/flowstallion/flowstallion/pkg/store"
)

// Server is the FlowStallion HTTP API. It serves the pipeline/run/log/query
// surface for the CLI and web console, the SSE event stream, and the
// runner-agent claim/finish protocol.
type Server struct {
	Store    *store.Store
	Sched    *scheduler.Scheduler
	Dispatch *Dispatcher
	// Auth is nil-safe: a nil or disabled Authenticator leaves every
	// endpoint open (pre-P6 behaviour).
	Auth *auth.Authenticator
	// Vault is nil when FLOWSTALLION_SECRET_KEY is unset; secret endpoints
	// then report 503 and ${NAME} injection is disabled (P6②).
	Vault *secret.Vault
	// CanaryCtl (P7⑧) drives operator-triggered canary rollbacks. Nil when
	// the scheduler process did not wire a K8s controller; the rollback
	// endpoint then reports 503.
	CanaryCtl *cd.Controller
}

// New wires a Server. The executor (AgentExecutor) is created by the caller
// and passed to the scheduler; the Server only needs the Dispatcher to
// service agent endpoints. Authentication starts disabled; the caller
// (scheduler) configures s.Auth from the environment.
func New(st *store.Store, sched *scheduler.Scheduler, disp *Dispatcher) *Server {
	return &Server{Store: st, Sched: sched, Dispatch: disp, Auth: auth.New(st, false, 0, "")}
}

// Handler builds the route table (Go 1.22 method + wildcard patterns).
//
// RBAC matrix (only enforced when s.Auth.Enabled()):
//
//	GET /healthz, POST /api/auth/login, POST /api/webhooks/{github,gitea,gitlab}  open
//	   (the webhooks self-authenticate via their signatures/tokens)
//	viewer  : all read-only /api/* (incl. /api/auth/me, /api/runs/{id}/scans, /api/cost)
//	operator: viewer + trigger / cancel / approve / reject / save scan /
//	            create canary / rollback canary
//	admin   : operator + create pipeline + user management + secret management
//	agent   : /api/agent/* and POST /api/runs/{id}/analysis —
//	           X-Agent-Token or a user token of operator+
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// open
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("POST /api/auth/login", s.handleAuthLogin)
	mux.HandleFunc("POST /api/webhooks/github", s.handleGitHubWebhook)
	mux.HandleFunc("POST /api/webhooks/gitea", s.handleGiteaWebhook)
	mux.HandleFunc("POST /api/webhooks/gitlab", s.handleGitLabWebhook)
	// auth session
	mux.HandleFunc("POST /api/auth/logout", s.requireRole(auth.RoleViewer, s.handleAuthLogout))
	mux.HandleFunc("GET /api/auth/me", s.requireRole(auth.RoleViewer, s.handleAuthMe))
	// user management (admin)
	mux.HandleFunc("GET /api/users", s.requireRole(auth.RoleAdmin, s.handleListUsers))
	mux.HandleFunc("POST /api/users", s.requireRole(auth.RoleAdmin, s.handleCreateUser))
	mux.HandleFunc("DELETE /api/users/{name}", s.requireRole(auth.RoleAdmin, s.handleDeleteUser))
	// secrets (admin)
	mux.HandleFunc("GET /api/secrets", s.requireRole(auth.RoleAdmin, s.handleListSecrets))
	mux.HandleFunc("POST /api/secrets", s.requireRole(auth.RoleAdmin, s.handleUpsertSecret))
	mux.HandleFunc("DELETE /api/secrets/{name}", s.requireRole(auth.RoleAdmin, s.handleDeleteSecret))
	// pipelines
	mux.HandleFunc("GET /api/pipelines", s.requireRole(auth.RoleViewer, s.handleListPipelines))
	mux.HandleFunc("POST /api/pipelines", s.requireRole(auth.RoleAdmin, s.handleUpsertPipeline))
	mux.HandleFunc("POST /api/pipelines/{name}/trigger", s.requireRole(auth.RoleOperator, s.handleTrigger))
	// runs
	mux.HandleFunc("GET /api/runs", s.requireRole(auth.RoleViewer, s.handleListRuns))
	mux.HandleFunc("GET /api/runs/{id}", s.requireRole(auth.RoleViewer, s.handleGetRun))
	mux.HandleFunc("POST /api/runs/{id}/cancel", s.requireRole(auth.RoleOperator, s.handleCancel))
	mux.HandleFunc("POST /api/runs/{id}/approve", s.requireRole(auth.RoleOperator, s.handleApprove))
	mux.HandleFunc("POST /api/runs/{id}/reject", s.requireRole(auth.RoleOperator, s.handleReject))
	mux.HandleFunc("GET /api/runs/{id}/logs", s.requireRole(auth.RoleViewer, s.handleLogs))
	mux.HandleFunc("GET /api/runs/{id}/events", s.requireRole(auth.RoleViewer, s.handleEvents))
	mux.HandleFunc("POST /api/runs/{id}/scans", s.requireRole(auth.RoleOperator, s.handleSaveScan))
	mux.HandleFunc("GET /api/runs/{id}/scans", s.requireRole(auth.RoleViewer, s.handleListScans))
	// canaries
	mux.HandleFunc("POST /api/canaries", s.requireRole(auth.RoleOperator, s.handleCreateCanary))
	mux.HandleFunc("GET /api/canaries", s.requireRole(auth.RoleViewer, s.handleListCanaries))
	mux.HandleFunc("GET /api/canaries/{id}", s.requireRole(auth.RoleViewer, s.handleGetCanary))
	mux.HandleFunc("POST /api/canaries/{id}/rollback", s.requireRole(auth.RoleOperator, s.handleRollbackCanary))
	// costs (P6④: shared FinOps ledger read)
	mux.HandleFunc("GET /api/cost", s.requireRole(auth.RoleViewer, s.handleCost))
	// audit (task ③: append-only event stream read)
	mux.HandleFunc("GET /api/audit", s.requireRole(auth.RoleViewer, s.handleListAudit))
	// machine endpoints (runner agent + AI agent)
	mux.HandleFunc("POST /api/agent/register", s.requireAgent(s.handleAgentRegister))
	mux.HandleFunc("GET /api/agent/jobs", s.requireAgent(s.handleAgentClaim))
	mux.HandleFunc("POST /api/agent/jobs/{runID}/{stepID}/logs", s.requireAgent(s.handleAgentLogs))
	mux.HandleFunc("POST /api/agent/jobs/{runID}/{stepID}", s.requireAgent(s.handleAgentFinish))
	mux.HandleFunc("POST /api/runs/{id}/analysis", s.requireAgent(s.handleSaveAnalysis))
	return s.logging(mux)
}

// logging is a minimal request logger (method, path, status, duration).
func (s *Server) logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(lw, r)
		if lw.status >= 400 || r.URL.Path != "/healthz" {
			fmt.Printf("%s %s -> %d (%s)\n", r.Method, r.URL.Path, lw.status, time.Since(start).Round(time.Millisecond))
		}
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// Flush forwards to the underlying writer so SSE works through the logging
// middleware.
func (w *statusWriter) Flush() {
	if fl, ok := w.ResponseWriter.(http.Flusher); ok {
		fl.Flush()
	}
}

// ---------------------------------------------------------------------------
// JSON DTOs
// ---------------------------------------------------------------------------

type pipelineJSON struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	// YAML is the raw pipeline definition. Exposed so the console's admin
	// YAML editor can pre-fill; pipeline definitions are operational config,
	// not secrets (secrets live in the separate secrets store).
	YAML      string `json:"yaml"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

type runJSON struct {
	ID         int64  `json:"id"`
	PipelineID int64  `json:"pipeline_id"`
	Status     string `json:"status"`
	Trigger    string `json:"trigger"`
	SourceRef  string `json:"source_ref"`
	// P7④: triggering commit SHA — the push payload "after" for push runs,
	// the PR head SHA for pull_request runs; "" for non-webhook triggers
	// (manual / schedule / canary).
	SHA string `json:"sha"`
	// P7: GitHub pull_request trigger metadata. pr==0 with empty refs/URL
	// means the run was not PR-triggered (push / manual / schedule / canary).
	PR      int    `json:"pr"`
	BaseRef string `json:"base_ref"`
	HeadRef string `json:"head_ref"`
	RepoURL string `json:"repo_url"`
	// P7⑧: operator-supplied reason for a policy-hold rejection; empty
	// unless the run was rejected with a reason.
	RejectReason string `json:"reject_reason,omitempty"`
	StartedAt    string `json:"started_at"`
	FinishedAt   string `json:"finished_at"`
	CreatedAt    string `json:"created_at"`
}

type stepJSON struct {
	ID         int64             `json:"id"`
	StepID     string            `json:"step_id"`
	StepIndex  int               `json:"step_index"`
	Status     string            `json:"status"`
	Image      string            `json:"image"`
	Command    []string          `json:"command,omitempty"`
	Outputs    map[string]string `json:"outputs,omitempty"` // P7④: step outputs (e.g. docker_build image_ref)
	StartedAt  string            `json:"started_at"`
	FinishedAt string            `json:"finished_at"`
}

// stepCommands decodes the JSON-encoded command list stored on a step row.
func stepCommands(raw string) []string {
	if raw == "" {
		return nil
	}
	var cmds []string
	if err := json.Unmarshal([]byte(raw), &cmds); err != nil || cmds == nil {
		return []string{raw}
	}
	return cmds
}

// stepOutputs decodes the JSON-encoded step outputs stored on a step row
// (P7④: e.g. {"image_ref": "..."} for docker_build steps).
func stepOutputs(raw string) map[string]string {
	if raw == "" {
		return nil
	}
	var out map[string]string
	if err := json.Unmarshal([]byte(raw), &out); err != nil || out == nil {
		return nil
	}
	return out
}

type logJSON struct {
	Seq  int64  `json:"seq"`
	Line string `json:"line"`
	TS   string `json:"ts"`
}

type analysisJSON struct {
	StepID       string `json:"step_id"`
	Kind         string `json:"kind"`
	RootCause    string `json:"root_cause"`
	Detail       string `json:"detail"`
	SuggestedFix string `json:"suggested_fix"`
	Command      string `json:"command,omitempty"`
	LogExcerpt   string `json:"log_excerpt,omitempty"`
	CreatedAt    string `json:"created_at"`
}

func toAnalysisJSON(a store.RunAnalysis) analysisJSON {
	return analysisJSON{
		StepID: a.StepID, Kind: a.Kind, RootCause: a.RootCause,
		Detail: a.Detail, SuggestedFix: a.SuggestedFix,
		Command: a.Command, LogExcerpt: a.LogExcerpt, CreatedAt: a.CreatedAt,
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":      "ok",
		"pending":     s.Dispatch.PendingCount(),
		"inflight":    s.Dispatch.InflightCount(),
		"active_runs": s.Sched.ActiveCount(),
	})
}

func (s *Server) handleListPipelines(w http.ResponseWriter, r *http.Request) {
	pls, err := s.Store.ListPipelines()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]pipelineJSON, 0, len(pls))
	for _, p := range pls {
		out = append(out, pipelineJSON{ID: p.ID, Name: p.Name, YAML: p.YAMLText, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt})
	}
	writeJSON(w, http.StatusOK, out)
}

// JSON request-body caps (task ⑨ P1): these endpoints used to decode r.Body
// unbounded. http.MaxBytesReader enforces the cap; an overflow surfaces as
// *http.MaxBytesError and is answered 413 "body too large" (same convention
// as the webhook 413s).
const (
	maxPipelineBody      = 512 << 10 // POST /api/pipelines
	maxTriggerBody       = 64 << 10  // POST /api/pipelines/{name}/trigger (body optional)
	maxAgentRegisterBody = 64 << 10  // POST /api/agent/register
	maxAgentLogsBody     = 4 << 20   // POST /api/agent/jobs/{runID}/{stepID}/logs (200 lines × 8192 chars + JSON overhead)
	maxAgentFinishBody   = 1 << 20   // POST /api/agent/jobs/{runID}/{stepID} (≤64 outputs × 512 chars + JSON overhead)
)

func (s *Server) handleUpsertPipeline(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
		YAML string `json:"yaml"`
	}
	var maxBytesErr *http.MaxBytesError
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxPipelineBody)).Decode(&body); err != nil {
		if errors.As(err, &maxBytesErr) {
			s.record(r, AuditPipelineUpsert, "pipeline:unknown", http.StatusRequestEntityTooLarge, "body too large")
			writeErr(w, http.StatusRequestEntityTooLarge, "body too large")
			return
		}
		s.record(r, AuditPipelineUpsert, "pipeline:unknown", http.StatusBadRequest, "invalid body")
		writeErr(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	if body.Name == "" {
		s.record(r, AuditPipelineUpsert, "pipeline:unknown", http.StatusBadRequest, "name required")
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	// Validate before persisting so a broken pipeline never lands in the DB.
	if _, err := pipeline.ParseYAML([]byte(body.YAML)); err != nil {
		code := http.StatusUnprocessableEntity
		if problems, ok := problemList(err); ok {
			s.record(r, AuditPipelineUpsert, "pipeline:"+body.Name, code,
				"invalid yaml: "+strings.Join(problems, "; "))
			writeJSON(w, code, map[string]any{"error": "pipeline invalid", "problems": problems})
			return
		}
		s.record(r, AuditPipelineUpsert, "pipeline:"+body.Name, code, "invalid yaml: "+err.Error())
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	id, err := s.Store.UpsertPipeline(body.Name, body.YAML)
	if err != nil {
		s.record(r, AuditPipelineUpsert, "pipeline:"+body.Name, http.StatusInternalServerError,
			"upsert: "+err.Error())
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.record(r, AuditPipelineUpsert, "pipeline:"+body.Name, http.StatusCreated,
		fmt.Sprintf("id=%d", id))
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "name": body.Name})
}

// problemList extracts aggregated field errors from a parse error.
func problemList(err error) ([]string, bool) {
	var multi interface{ Unwrap() []error }
	if !errors.As(err, &multi) {
		return nil, false
	}
	inner := multi.Unwrap()
	if len(inner) == 0 {
		return nil, false
	}
	out := make([]string, 0, len(inner))
	for _, e := range inner {
		out = append(out, e.Error())
	}
	return out, true
}

func (s *Server) handleTrigger(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, err := s.Store.GetPipelineByName(name); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.record(r, AuditRunTrigger, "run:unknown", http.StatusNotFound, "pipeline not found: "+name)
			writeErr(w, http.StatusNotFound, "pipeline not found: "+name)
		} else {
			s.record(r, AuditRunTrigger, "run:unknown", http.StatusInternalServerError, err.Error())
			writeErr(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	var body struct {
		Trigger   string `json:"trigger"`
		SourceRef string `json:"source_ref"`
	}
	var maxBytesErr *http.MaxBytesError
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxTriggerBody)).Decode(&body); err != nil {
		// Optional body: ordinary decode errors stay ignored, but an
		// over-cap body is an explicit 413 (task ⑨ P1).
		if errors.As(err, &maxBytesErr) {
			s.record(r, AuditRunTrigger, "run:unknown", http.StatusRequestEntityTooLarge, "body too large")
			writeErr(w, http.StatusRequestEntityTooLarge, "body too large")
			return
		}
	}
	if body.Trigger == "" {
		body.Trigger = "manual"
	}
	runID, err := s.Sched.Trigger(name, body.Trigger, body.SourceRef)
	if err != nil {
		switch {
		case errors.Is(err, scheduler.ErrSecrets):
			s.record(r, AuditRunTrigger, "run:unknown", http.StatusBadRequest, "trigger: "+err.Error())
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		case errors.Is(err, scheduler.ErrLimit):
			s.record(r, AuditRunTrigger, "run:unknown", http.StatusConflict, "trigger: "+err.Error())
			writeErr(w, http.StatusConflict, err.Error())
			return
		case strings.Contains(err.Error(), "invalid"):
			s.record(r, AuditRunTrigger, "run:unknown", http.StatusUnprocessableEntity,
				"invalid pipeline: "+err.Error())
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "pipeline invalid", "problems": []string{err.Error()}})
			return
		default:
			s.record(r, AuditRunTrigger, "run:unknown", http.StatusInternalServerError, "trigger: "+err.Error())
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	// task ③: detail carries trigger + source_ref per the audit design.
	detail := "trigger=" + body.Trigger
	if body.SourceRef != "" {
		detail += " source_ref=" + body.SourceRef
	}
	s.record(r, AuditRunTrigger, fmt.Sprintf("run:%d", runID), http.StatusAccepted, detail)
	writeJSON(w, http.StatusAccepted, map[string]any{"run_id": runID})
}

func (s *Server) handleListRuns(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var pipelineID int64
	if v := q.Get("pipeline_id"); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "pipeline_id must be an integer")
			return
		}
		pipelineID = id
	}
	limit := 50
	if v := q.Get("limit"); v != "" {
		l, err := strconv.Atoi(v)
		if err != nil || l < 1 {
			writeErr(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		if l > 200 {
			l = 200
		}
		limit = l
	}
	runs, err := s.Store.ListRuns(pipelineID, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]runJSON, 0, len(runs))
	for _, rn := range runs {
		out = append(out, toRunJSON(rn))
	}
	writeJSON(w, http.StatusOK, out)
}

func toRunJSON(rn store.Run) runJSON {
	return runJSON{
		ID: rn.ID, PipelineID: rn.PipelineID, Status: rn.Status,
		Trigger: rn.Trigger, SourceRef: rn.SourceRef, SHA: rn.SHA,
		PR: rn.PR, BaseRef: rn.BaseRef, HeadRef: rn.HeadRef, RepoURL: rn.RepoURL,
		RejectReason: rn.RejectReason,
		StartedAt:    rn.StartedAt, FinishedAt: rn.FinishedAt, CreatedAt: rn.CreatedAt,
	}
}

func (s *Server) handleGetRun(w http.ResponseWriter, r *http.Request) {
	runID, ok := parseRunID(r, w)
	if !ok {
		return
	}
	rn, err := s.Store.GetRun(runID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "run not found")
		} else {
			writeErr(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	steps, err := s.Store.ListRunSteps(runID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]stepJSON, 0, len(steps))
	for _, st := range steps {
		out = append(out, stepJSON{
			ID: st.ID, StepID: st.StepID, StepIndex: st.StepIndex,
			Status: st.Status, Image: st.Image, Command: stepCommands(st.Command),
			Outputs:   stepOutputs(st.Outputs),
			StartedAt: st.StartedAt, FinishedAt: st.FinishedAt,
		})
	}
	var analysis any
	if a, err := s.Store.GetRunAnalysis(runID); err == nil {
		analysis = toAnalysisJSON(a)
	}
	allAnalyses, err := s.Store.ListRunAnalyses(runID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	analysisList := make([]analysisJSON, 0, len(allAnalyses))
	for _, a := range allAnalyses {
		analysisList = append(analysisList, toAnalysisJSON(a))
	}
	scans, err := s.Store.ListRunScans(runID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"run": toRunJSON(rn), "steps": out,
		"analysis": analysis, "analyses": analysisList,
		"scans": scanDTOs(scans),
	})
}

// handleSaveAnalysis stores an analysis report for a run (one per kind,
// upsert). Validation: run exists, root_cause non-empty, kind in
// {rule, llm, pr_review, test_selection}, 1 MiB body cap. rule/llm (RCA)
// reports must reference an existing step of the run; the AI kinds
// (pr_review / test_selection) are run-level and may omit step_id.
func (s *Server) handleSaveAnalysis(w http.ResponseWriter, r *http.Request) {
	runID, ok := parseRunID(r, w)
	if !ok {
		return
	}
	if _, err := s.Store.GetRun(runID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "run not found")
		} else {
			writeErr(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	var body struct {
		StepID       string `json:"step_id"`
		Kind         string `json:"kind"`
		RootCause    string `json:"root_cause"`
		Detail       string `json:"detail"`
		SuggestedFix string `json:"suggested_fix"`
		Command      string `json:"command"`
		LogExcerpt   string `json:"log_excerpt"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	if body.RootCause == "" {
		writeErr(w, http.StatusBadRequest, "root_cause is required")
		return
	}
	if body.Kind == "" {
		body.Kind = "rule"
	}
	switch body.Kind {
	case "rule", "llm", "pr_review", "test_selection":
	default:
		writeErr(w, http.StatusBadRequest,
			`kind must be "rule", "llm", "pr_review" or "test_selection"`)
		return
	}
	// AI kinds (pr_review / test_selection) are run-level: step_id is
	// optional and stored as-is. RCA kinds must name an existing step.
	aiKind := body.Kind == "pr_review" || body.Kind == "test_selection"
	if body.StepID == "" && !aiKind {
		writeErr(w, http.StatusBadRequest, "step_id is required")
		return
	}
	if !aiKind {
		steps, err := s.Store.ListRunSteps(runID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		found := false
		for _, st := range steps {
			if st.StepID == body.StepID {
				found = true
				break
			}
		}
		if !found {
			writeErr(w, http.StatusNotFound, "step not found in run: "+body.StepID)
			return
		}
	}
	if err := s.Store.SaveRunAnalysis(store.RunAnalysis{
		RunID: runID, StepID: body.StepID, Kind: body.Kind,
		RootCause: body.RootCause, Detail: body.Detail,
		SuggestedFix: body.SuggestedFix, Command: body.Command,
		LogExcerpt: body.LogExcerpt,
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleCancel(w http.ResponseWriter, r *http.Request) {
	runID, ok := parseRunID(r, w)
	if !ok {
		s.record(r, AuditRunCancel, "run:unknown", http.StatusBadRequest, "bad run id")
		return
	}
	if _, err := s.Store.GetRun(runID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.record(r, AuditRunCancel, fmt.Sprintf("run:%d", runID), http.StatusNotFound, "run not found")
			writeErr(w, http.StatusNotFound, "run not found")
		} else {
			s.record(r, AuditRunCancel, fmt.Sprintf("run:%d", runID), http.StatusInternalServerError, err.Error())
			writeErr(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	if err := s.Sched.Cancel(runID); err != nil {
		s.record(r, AuditRunCancel, fmt.Sprintf("run:%d", runID), http.StatusInternalServerError, "cancel: "+err.Error())
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.record(r, AuditRunCancel, fmt.Sprintf("run:%d", runID), http.StatusOK, "")
	writeJSON(w, http.StatusOK, map[string]any{"run_id": runID, "status": "cancel_requested"})
}

// handleApprove releases a policy-held (pending_approval) run.
func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	runID, ok := parseRunID(r, w)
	if !ok {
		s.record(r, AuditRunApprove, "run:unknown", http.StatusBadRequest, "bad run id")
		return
	}
	if err := s.Sched.Approve(runID); err != nil {
		s.record(r, AuditRunApprove, fmt.Sprintf("run:%d", runID), runErrStatus(err), err.Error())
		writeRunErr(w, err)
		return
	}
	s.record(r, AuditRunApprove, fmt.Sprintf("run:%d", runID), http.StatusOK, "")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "run_id": runID, "status": "running"})
}

// handleReject dismisses a policy-held (pending_approval) run. The body may
// carry an optional {"reason": "..."} (P7⑧), recorded on the run and echoed
// in the run JSON; an empty or absent body rejects with no reason.
func (s *Server) handleReject(w http.ResponseWriter, r *http.Request) {
	runID, ok := parseRunID(r, w)
	if !ok {
		s.record(r, AuditRunReject, "run:unknown", http.StatusBadRequest, "bad run id")
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		s.record(r, AuditRunReject, fmt.Sprintf("run:%d", runID), http.StatusBadRequest, "invalid body")
		writeErr(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	if len(body.Reason) > 500 {
		s.record(r, AuditRunReject, fmt.Sprintf("run:%d", runID), http.StatusBadRequest, "reason too long")
		writeErr(w, http.StatusBadRequest, "reason must be at most 500 characters")
		return
	}
	if err := s.Sched.RejectWithReason(runID, body.Reason); err != nil {
		s.record(r, AuditRunReject, fmt.Sprintf("run:%d", runID), runErrStatus(err), "reason="+body.Reason)
		writeRunErr(w, err)
		return
	}
	s.record(r, AuditRunReject, fmt.Sprintf("run:%d", runID), http.StatusOK, "reason="+body.Reason)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "run_id": runID, "status": "rejected"})
}

// writeRunErr maps scheduler errors to HTTP codes: 404 unknown run, 409 wrong
// state, 500 otherwise.
func writeRunErr(w http.ResponseWriter, err error) {
	writeErr(w, runErrStatus(err), runErrMessage(err))
}

// runErrStatus mirrors writeRunErr's error→status mapping so audit records
// capture the exact code the client sees.
func runErrStatus(err error) int {
	if errors.Is(err, sql.ErrNoRows) {
		return http.StatusNotFound
	}
	if errors.Is(err, scheduler.ErrNotPending) {
		return http.StatusConflict
	}
	return http.StatusInternalServerError
}

func runErrMessage(err error) string {
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return "run not found"
	default:
		return err.Error()
	}
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	runID, ok := parseRunID(r, w)
	if !ok {
		return
	}
	if _, err := s.Store.GetRun(runID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "run not found")
		} else {
			writeErr(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	step := r.URL.Query().Get("step")
	after := int64(0)
	limit := 200
	if v := r.URL.Query().Get("after"); v != "" {
		a, err := strconv.ParseInt(v, 10, 64)
		if err != nil || a < 0 {
			writeErr(w, http.StatusBadRequest, "after must be a non-negative integer")
			return
		}
		after = a
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		l, err := strconv.Atoi(v)
		if err != nil || l < 1 {
			writeErr(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		if l > 1000 {
			l = 1000
		}
		limit = l
	}

	var rows []store.LogRow
	var err error
	if step != "" {
		// Validate the step id belongs to this run.
		steps, serr := s.Store.ListRunSteps(runID)
		if serr != nil {
			writeErr(w, http.StatusInternalServerError, serr.Error())
			return
		}
		found := false
		for _, st := range steps {
			if st.StepID == step {
				found = true
				break
			}
		}
		if !found {
			writeErr(w, http.StatusNotFound, "step not found in run: "+step)
			return
		}
		rows, err = s.Store.ListLogs(runID, step, after, int64(limit))
	} else {
		rows, err = s.Store.ListLogs(runID, "", after, int64(limit)) // "" -> all steps? no: see below
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]logJSON, 0, len(rows))
	for _, l := range rows {
		out = append(out, logJSON{Seq: l.Seq, Line: l.Line, TS: l.TS})
	}
	writeJSON(w, http.StatusOK, map[string]any{"logs": out})
}

// NOTE: ListLogs with stepID="" would match rows where step_id='' (none).
// For "all steps" we rely on the client passing step explicitly; P1 web
// console queries per-step. The no-step path is therefore a no-op that
// returns an empty list. This keeps the contract strict (no implicit
// cross-step mixing).

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	runID, ok := parseRunID(r, w)
	if !ok {
		return
	}
	if _, err := s.Store.GetRun(runID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "run not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	fmt.Fprintf(w, "retry: 3000\n\n")

	// Initial snapshot so a late subscriber can sync state.
	rn, _ := s.Store.GetRun(runID)
	steps, _ := s.Store.ListRunSteps(runID)
	stepsOut := make([]stepJSON, 0, len(steps))
	for _, st := range steps {
		stepsOut = append(stepsOut, stepJSON{
			ID: st.ID, StepID: st.StepID, StepIndex: st.StepIndex,
			Status: st.Status, Image: st.Image, Command: stepCommands(st.Command),
			Outputs:   stepOutputs(st.Outputs),
			StartedAt: st.StartedAt, FinishedAt: st.FinishedAt,
		})
	}
	snap, _ := json.Marshal(map[string]any{"type": "snapshot", "run": toRunJSON(rn), "steps": stepsOut})
	fmt.Fprintf(w, "data: %s\n\n", snap)
	fl.Flush()

	ch, cancelSub := s.Sched.Events.Subscribe()
	defer cancelSub()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-ch:
			if e.RunID != runID {
				continue
			}
			data, _ := json.Marshal(e)
			fmt.Fprintf(w, "data: %s\n\n", data)
			fl.Flush()
			if e.Type == scheduler.EvtRunFinished {
				return
			}
		}
	}
}

func (s *Server) handleAgentRegister(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	var maxBytesErr *http.MaxBytesError
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAgentRegisterBody)).Decode(&body); err != nil {
		if errors.As(err, &maxBytesErr) {
			writeErr(w, http.StatusRequestEntityTooLarge, "body too large")
			return
		}
		writeErr(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	if body.Name == "" || len(body.Name) > 128 {
		writeErr(w, http.StatusBadRequest, "agent name must be 1-128 chars")
		return
	}
	id, created, err := s.Store.RegisterAgent(body.Name)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"agent_id": id, "created": created})
}

func (s *Server) handleAgentClaim(w http.ResponseWriter, r *http.Request) {
	agent := r.URL.Query().Get("agent")
	if agent == "" || len(agent) > 128 {
		writeErr(w, http.StatusBadRequest, "agent query param required (1-128 chars)")
		return
	}
	job := s.Dispatch.Claim(agent)
	if job == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"job": job})
}

func (s *Server) handleAgentLogs(w http.ResponseWriter, r *http.Request) {
	runID, stepID, ok := parseAgentJob(w, r)
	if !ok {
		return
	}
	var body struct {
		Lines []string `json:"lines"`
	}
	var maxBytesErr *http.MaxBytesError
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAgentLogsBody)).Decode(&body); err != nil {
		if errors.As(err, &maxBytesErr) {
			writeErr(w, http.StatusRequestEntityTooLarge, "body too large")
			return
		}
		writeErr(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	if len(body.Lines) > 200 {
		writeErr(w, http.StatusBadRequest, "at most 200 lines per request")
		return
	}
	stored := 0
	for _, line := range body.Lines {
		if len(line) > 8192 {
			writeErr(w, http.StatusBadRequest, "log line exceeds 8192 chars")
			return
		}
		if _, err := s.Store.AddLog(runID, stepID, line); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		stored++
	}
	writeJSON(w, http.StatusOK, map[string]any{"stored": stored})
}

func (s *Server) handleAgentFinish(w http.ResponseWriter, r *http.Request) {
	runID, stepID, ok := parseAgentJob(w, r)
	if !ok {
		return
	}
	var body struct {
		Status  string            `json:"status"`
		Message string            `json:"message"`
		Outputs map[string]string `json:"outputs,omitempty"` // P7④: e.g. {"image_ref": "..."}
	}
	var maxBytesErr *http.MaxBytesError
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAgentFinishBody)).Decode(&body); err != nil {
		if errors.As(err, &maxBytesErr) {
			writeErr(w, http.StatusRequestEntityTooLarge, "body too large")
			return
		}
		writeErr(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	if body.Status != "success" && body.Status != "failed" {
		writeErr(w, http.StatusBadRequest, "status must be 'success' or 'failed'")
		return
	}
	if len(body.Outputs) > 64 {
		writeErr(w, http.StatusBadRequest, "at most 64 output keys")
		return
	}
	for k, v := range body.Outputs {
		if len(k) == 0 || len(k) > 64 {
			writeErr(w, http.StatusBadRequest, "output key must be 1-64 chars")
			return
		}
		if len(v) > 512 {
			writeErr(w, http.StatusBadRequest, "output value must be <=512 chars")
			return
		}
	}
	if !s.Dispatch.Finish(runID, stepID, body.Status, body.Message) {
		writeErr(w, http.StatusNotFound, "unknown or already-resolved job")
		return
	}
	if len(body.Outputs) > 0 {
		raw, _ := json.Marshal(body.Outputs)
		if err := s.Store.SetRunStepOutputs(runID, stepID, string(raw)); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---------------------------------------------------------------------------
// Path parsing helpers
// ---------------------------------------------------------------------------

func parseRunID(r *http.Request, w http.ResponseWriter) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, http.StatusBadRequest, "run id must be a positive integer")
		return 0, false
	}
	return id, true
}

func parseAgentJob(w http.ResponseWriter, r *http.Request) (int64, string, bool) {
	runID, err := strconv.ParseInt(r.PathValue("runID"), 10, 64)
	if err != nil || runID <= 0 {
		writeErr(w, http.StatusBadRequest, "runID must be a positive integer")
		return 0, "", false
	}
	stepID := r.PathValue("stepID")
	if stepID == "" || len(stepID) > 64 {
		writeErr(w, http.StatusBadRequest, "stepID must be 1-64 chars")
		return 0, "", false
	}
	return runID, stepID, true
}
