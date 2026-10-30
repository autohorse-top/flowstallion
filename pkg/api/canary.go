package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/flowstallion/flowstallion/pkg/cd"
	"github.com/flowstallion/flowstallion/pkg/store"
)

// canaryNameRe matches RFC-1123 label-style names (K8s object name rules,
// with a length cap enforced separately).
var canaryNameRe = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

func validCanaryName(s string) bool {
	return s != "" && len(s) <= 63 && canaryNameRe.MatchString(s)
}

// canarySourceRefRe allows full/short commit shas and branch/tag names:
// alphanumerics plus dot, underscore, dash and slash. Anything else (spaces,
// quotes, shell metacharacters, ...) is rejected (P4 source_ref validation).
var canarySourceRefRe = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)

// validCanarySourceRef reports whether sourceRef is an acceptable git ref:
// empty (omitted) or a non-empty string of at most 64 chars from the allowed
// charset.
func validCanarySourceRef(s string) bool {
	return s == "" || (len(s) <= 64 && canarySourceRefRe.MatchString(s))
}

type canaryJSON struct {
	ID             int64   `json:"id"`
	Name           string  `json:"name"`
	Namespace      string  `json:"namespace"`
	Strategy       string  `json:"strategy"`
	StableImage    string  `json:"stable_image"`
	CanaryImage    string  `json:"canary_image"`
	SourceRef      string  `json:"source_ref,omitempty"`
	RunID          int64   `json:"run_id,omitempty"`
	Replicas       int     `json:"replicas"`
	Port           int     `json:"port"`
	Threshold      float64 `json:"threshold"`
	MinSamples     int     `json:"min_samples"`
	WarmupS        float64 `json:"warmup_s"`
	ObserveS       float64 `json:"observe_s"`
	State          string  `json:"state"`
	Reason         string  `json:"reason,omitempty"`
	LastErrRate    float64 `json:"last_err_rate"`
	LastRequests   int64   `json:"last_requests"`
	LastErrors     int64   `json:"last_errors"`
	ScrapeFailures int     `json:"scrape_failures"`
	CanaryStart    string  `json:"canary_start,omitempty"`
	CreatedAt      string  `json:"created_at"`
	FinishedAt     string  `json:"finished_at,omitempty"`
}

type canaryEventJSON struct {
	ID     int64  `json:"id"`
	TS     string `json:"ts"`
	State  string `json:"state"`
	Detail string `json:"detail"`
}

func toCanaryJSON(r store.CanaryRelease) canaryJSON {
	return canaryJSON{
		ID: r.ID, Name: r.Name, Namespace: r.Namespace,
		Strategy:    r.Strategy,
		StableImage: r.StableImage, CanaryImage: r.CanaryImage, SourceRef: r.SourceRef,
		RunID:    r.RunID,
		Replicas: r.Replicas, Port: r.Port,
		Threshold: r.Threshold, MinSamples: r.MinSamples,
		WarmupS: r.WarmupS, ObserveS: r.ObserveS,
		State: r.State, Reason: r.Reason,
		LastErrRate: r.LastErrRate, LastRequests: r.LastRequests, LastErrors: r.LastErrors,
		ScrapeFailures: r.ScrapeFailures,
		CanaryStart:    r.CanaryStart,
		CreatedAt:      r.CreatedAt, FinishedAt: r.FinishedAt,
	}
}

// maxCanaryBody caps the create-request body (task ⑨ P1): the schema has
// bounded string fields, so anything over 64 KiB is a client bug or abuse,
// not a legitimate release descriptor.
const maxCanaryBody = 64 << 10

// handleCreateCanary: POST /api/canaries
// Creates a pending canary release. The background CD controller (in the
// scheduler process) picks it up and drives the K8s state machine.
func (s *Server) handleCreateCanary(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name        string   `json:"name"`
		Namespace   string   `json:"namespace"`
		Strategy    string   `json:"strategy"` // optional; "" -> "canary"
		StableImage string   `json:"stable_image"`
		CanaryImage string   `json:"canary_image"`
		Replicas    *int     `json:"replicas"`
		Port        *int     `json:"port"`
		Threshold   *float64 `json:"threshold"`
		MinSamples  *int     `json:"min_samples"`
		WarmupS     *float64 `json:"warmup_s"`
		ObserveS    *float64 `json:"observe_s"`
		SourceRef   string   `json:"source_ref"` // optional; "" when omitted
	}
	var maxBytesErr *http.MaxBytesError
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxCanaryBody)).Decode(&body); err != nil {
		if errors.As(err, &maxBytesErr) {
			s.record(r, AuditCanaryCreate, "canary:unknown", http.StatusRequestEntityTooLarge, "body too large")
			writeErr(w, http.StatusRequestEntityTooLarge, "body too large")
			return
		}
		s.record(r, AuditCanaryCreate, "canary:unknown", http.StatusBadRequest, "invalid body")
		writeErr(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	// Defaults apply only to omitted fields; explicit values must pass validation.
	if body.Namespace == "" {
		body.Namespace = "flowstallion"
	}
	replicas := 2
	if body.Replicas != nil {
		replicas = *body.Replicas
	}
	port := 8080
	if body.Port != nil {
		port = *body.Port
	}
	threshold := 0.3
	if body.Threshold != nil {
		threshold = *body.Threshold
	}
	minSamples := 20
	if body.MinSamples != nil {
		minSamples = *body.MinSamples
	}
	warmupS := 10.0
	if body.WarmupS != nil {
		warmupS = *body.WarmupS
	}
	observeS := 20.0
	if body.ObserveS != nil {
		observeS = *body.ObserveS
	}

	// Defaults for the optional strategy field.
	if body.Strategy == "" {
		body.Strategy = "canary"
	}

	// Validation (K8s name rules + sane ranges).
	var problems []string
	if !validCanaryName(body.Name) {
		problems = append(problems, `name must match ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ and be <= 63 chars`)
	}
	if body.Strategy != "canary" && body.Strategy != "blue_green" {
		problems = append(problems, `strategy must be "canary" or "blue_green"`)
	}
	// K8s object names cap at 63 chars; the alternate deployment name is
	// name + strategy suffix ("name-canary" / "name-alt"), so the base name
	// must leave room for it.
	alt := cd.AltName(body.Name, body.Strategy)
	if body.Name != "" && len(alt) > 63 {
		problems = append(problems,
			fmt.Sprintf("name too long for strategy %q: alternate object name %q exceeds 63 chars",
				body.Strategy, alt))
	}
	if !validCanaryName(body.Namespace) {
		problems = append(problems, `namespace must match ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ and be <= 63 chars`)
	}
	if body.StableImage == "" {
		problems = append(problems, "stable_image is required")
	} else if !cd.ValidImage(body.StableImage) {
		problems = append(problems, "stable_image is not a valid image reference")
	}
	if body.CanaryImage == "" {
		problems = append(problems, "canary_image is required")
	} else if !cd.ValidImage(body.CanaryImage) {
		problems = append(problems, "canary_image is not a valid image reference")
	}
	if replicas < 1 || replicas > 100 {
		problems = append(problems, "replicas must be in 1..100")
	}
	if port < 1 || port > 65535 {
		problems = append(problems, "port must be in 1..65535")
	}
	if threshold <= 0 || threshold > 1 {
		problems = append(problems, "threshold must be in (0, 1]")
	}
	if minSamples < 1 {
		problems = append(problems, "min_samples must be >= 1")
	}
	if !validCanarySourceRef(body.SourceRef) {
		problems = append(problems,
			`source_ref must be <= 64 chars and match ^[A-Za-z0-9._/-]+$ (commit sha or branch name)`)
	}
	if warmupS <= 0 || observeS <= 0 {
		problems = append(problems, "warmup_s and observe_s must be > 0")
	}
	if len(problems) > 0 {
		ct := "canary:" + body.Name
		if ct == "canary:" {
			ct = "canary:unknown"
		}
		s.record(r, AuditCanaryCreate, ct, http.StatusBadRequest, "invalid: "+strings.Join(problems, "; "))
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid canary request", "problems": problems})
		return
	}

	// m-1/F-3 (generalized to strategies): each release occupies the
	// stable-named object "P" and its strategy-specific alternate object
	// (P-canary / P-alt). Reject a new release whose own names — base or
	// alternate — would collide with any object owned by another active or
	// promoted release in the same namespace. An exact-name duplicate is
	// also caught here (and, atomically, by the partial unique index in
	// CreateCanary).
	newNames := []string{body.Name, cd.AltName(body.Name, body.Strategy)}
	checkCollision := func(pairs []store.CanaryPair, kind string) (string, bool) {
		for _, p := range pairs {
			owned := []string{p.Name, cd.AltName(p.Name, p.Strategy)}
			for _, nn := range newNames {
				for _, on := range owned {
					if nn == on {
						return fmt.Sprintf("name %s collides with %s release %s (objects %s / %s)",
							body.Name, kind, p.Name, p.Name, cd.AltName(p.Name, p.Strategy)), true
					}
				}
			}
		}
		return "", false
	}
	if pairs, err := s.Store.ActiveCanaryPairs(body.Namespace); err != nil {
		s.record(r, AuditCanaryCreate, "canary:"+body.Name, http.StatusInternalServerError, "active pairs: "+err.Error())
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	} else if msg, hit := checkCollision(pairs, "active"); hit {
		s.record(r, AuditCanaryCreate, "canary:"+body.Name, http.StatusConflict, msg)
		writeErr(w, http.StatusConflict, msg)
		return
	}
	if pairs, err := s.Store.PromotedCanaryPairs(body.Namespace); err != nil {
		s.record(r, AuditCanaryCreate, "canary:"+body.Name, http.StatusInternalServerError, "promoted pairs: "+err.Error())
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	} else if msg, hit := checkCollision(pairs, "promoted"); hit {
		s.record(r, AuditCanaryCreate, "canary:"+body.Name, http.StatusConflict, msg)
		writeErr(w, http.StatusConflict, msg)
		return
	}

	id, err := s.Store.CreateCanary(store.CanaryRelease{
		Name: body.Name, Namespace: body.Namespace,
		Strategy:    body.Strategy,
		StableImage: body.StableImage, CanaryImage: body.CanaryImage,
		SourceRef: body.SourceRef,
		Replicas:  replicas, Port: port,
		Threshold: threshold, MinSamples: minSamples,
		WarmupS: warmupS, ObserveS: observeS,
	})
	if err != nil {
		// M-2: the partial unique index is the atomic guard against
		// concurrent duplicate creates; map it to a friendly 409.
		if errors.Is(err, store.ErrCanaryConflict) {
			s.record(r, AuditCanaryCreate, "canary:"+body.Name, http.StatusConflict, "already exists")
			writeErr(w, http.StatusConflict,
				"an active canary named "+body.Name+" already exists")
			return
		}
		s.record(r, AuditCanaryCreate, "canary:"+body.Name, http.StatusInternalServerError, "create: "+err.Error())
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// task ③: detail carries name+namespace+strategy (design: no secret values, none here)
	s.record(r, AuditCanaryCreate, fmt.Sprintf("canary:%d", id), http.StatusCreated,
		fmt.Sprintf("name=%s ns=%s strategy=%s", body.Name, body.Namespace, body.Strategy))
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "state": store.CanaryPending})
}

// handleListCanaries: GET /api/canaries
func (s *Server) handleListCanaries(w http.ResponseWriter, r *http.Request) {
	cs, err := s.Store.ListCanaries()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]canaryJSON, 0, len(cs))
	for _, c := range cs {
		out = append(out, toCanaryJSON(c))
	}
	writeJSON(w, http.StatusOK, out)
}

// handleGetCanary: GET /api/canaries/{id}
func (s *Server) handleGetCanary(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, http.StatusBadRequest, "canary id must be a positive integer")
		return
	}
	cr, err := s.Store.GetCanary(id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "canary not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	evs, err := s.Store.EventsOfLimit(id, 500)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	events := make([]canaryEventJSON, 0, len(evs))
	for _, e := range evs {
		// ID makes the event key stable across scrapes: the API serves a
		// bounded (most-recent) window, so position-based keys would drift.
		events = append(events, canaryEventJSON{ID: e.ID, TS: e.TS, State: e.State, Detail: e.Detail})
	}
	writeJSON(w, http.StatusOK, map[string]any{"canary": toCanaryJSON(cr), "events": events})
}

// handleRollbackCanary: POST /api/canaries/{id}/rollback (P7⑧)
//
// Forces an active canary release back to the stable image: the controller
// deletes the canary Deployment and Service and marks the release
// rolled_back. The optional JSON body {"reason": "..."} (<= 500 chars)
// records why; it defaults to "manual rollback".
// Errors: 400 bad id/body, 503 controller not wired, 404 unknown release,
// 409 release already terminal or a concurrent driver won the state race
// (K1), 500 controller failure.
func (s *Server) handleRollbackCanary(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		s.record(r, AuditCanaryRollback, "canary:unknown", http.StatusBadRequest, "bad id")
		writeErr(w, http.StatusBadRequest, "canary id must be a positive integer")
		return
	}
	cr, err := s.Store.GetCanary(id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.record(r, AuditCanaryRollback, fmt.Sprintf("canary:%d", id), http.StatusNotFound, "canary not found")
			writeErr(w, http.StatusNotFound, "canary not found")
			return
		}
		s.record(r, AuditCanaryRollback, fmt.Sprintf("canary:%d", id), http.StatusInternalServerError, err.Error())
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.CanaryCtl == nil {
		s.record(r, AuditCanaryRollback, fmt.Sprintf("canary:%d", id), http.StatusServiceUnavailable, "controller unavailable")
		writeErr(w, http.StatusServiceUnavailable, "canary controller not available")
		return
	}
	if store.CanaryTerminal(cr.State) {
		s.record(r, AuditCanaryRollback, fmt.Sprintf("canary:%d", id), http.StatusConflict,
			fmt.Sprintf("already %s", cr.State))
		writeErr(w, http.StatusConflict, fmt.Sprintf("canary %d already %s", id, cr.State))
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		s.record(r, AuditCanaryRollback, fmt.Sprintf("canary:%d", id), http.StatusBadRequest, "invalid body")
		writeErr(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	if len(body.Reason) > 500 {
		s.record(r, AuditCanaryRollback, fmt.Sprintf("canary:%d", id), http.StatusBadRequest, "reason too long")
		writeErr(w, http.StatusBadRequest, "reason must be at most 500 characters")
		return
	}
	if body.Reason == "" {
		body.Reason = "manual rollback"
	}
	if err := s.CanaryCtl.Rollback(id, body.Reason); err != nil {
		code, msg := canaryRollbackStatus(id, err)
		s.record(r, AuditCanaryRollback, fmt.Sprintf("canary:%d", id), code, msg)
		writeErr(w, code, msg)
		return
	}
	s.record(r, AuditCanaryRollback, fmt.Sprintf("canary:%d", id), http.StatusOK, "reason="+body.Reason)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": id, "state": "rolled_back"})
}

// canaryRollbackStatus maps a rollback error to the appropriate HTTP status.
// A concurrent-state conflict (K1) becomes 409 so the client can retry;
// anything else is a server error (500).
func canaryRollbackStatus(id int64, err error) (int, string) {
	if errors.Is(err, store.ErrCanaryStateConflict) {
		return http.StatusConflict, fmt.Sprintf("canary %d was modified by a concurrent driver; please retry", id)
	}
	return http.StatusInternalServerError, err.Error()
}
