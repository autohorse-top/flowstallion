package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/flowstallion/flowstallion/pkg/auth"
)

// ---------------------------------------------------------------------------
// RBAC middleware
// ---------------------------------------------------------------------------

// requireRole wraps h with authentication and minimum-role enforcement.
// When authentication is disabled (or no Authenticator is set) the handler
// runs unchanged — pre-P6 open behaviour.
func (s *Server) requireRole(min auth.Role, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a := s.Auth
		if a == nil || !a.Enabled() {
			h(w, r)
			return
		}
		u, ok := a.UserFromRequest(r)
		if !ok {
			// task ③: denied access is audited (target names the endpoint).
			s.record(r, AuditAuthDeny, r.Method+" "+r.URL.Path, http.StatusUnauthorized, "unauthenticated")
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if !auth.Role(u.Role).AtLeast(min) {
			s.record(r, AuditAuthDeny, r.Method+" "+r.URL.Path, http.StatusForbidden, "requires "+string(min))
			writeErr(w, http.StatusForbidden, "forbidden: requires "+string(min))
			return
		}
		h(w, r)
	}
}

// requireAgent gates machine-facing endpoints (runner agent + AI agent).
// Semantics (P6 design):
//   - auth off: open (pre-P6 behaviour).
//   - auth on, agent token configured: request passes with a matching
//     X-Agent-Token, or a valid user token of operator+ (a human may operate
//     machine endpoints, e.g. POST /api/runs/{id}/analysis).
//   - auth on, agent token NOT configured: open — the scheduler logs a
//     startup warning; this deployment is considered machine-untrusted.
func (s *Server) requireAgent(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a := s.Auth
		if a == nil || !a.Enabled() {
			h(w, r)
			return
		}
		if !a.AgentTokenSet() {
			h(w, r)
			return
		}
		if a.CheckAgentToken(r) {
			h(w, r)
			return
		}
		if u, ok := a.UserFromRequest(r); ok && auth.Role(u.Role).AtLeast(auth.RoleOperator) {
			h(w, r)
			return
		}
		s.record(r, AuditAuthDeny, r.Method+" "+r.URL.Path, http.StatusUnauthorized, "agent auth failed")
		writeErr(w, http.StatusUnauthorized, "unauthorized")
	}
}

// ---------------------------------------------------------------------------
// Auth endpoints
// ---------------------------------------------------------------------------

// handleAuthLogin: POST /api/auth/login. Requires FLOWSTALLION_AUTH=on.
func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	a := s.Auth
	if a == nil || !a.Enabled() {
		s.record(r, AuditAuthLogin, "user:unknown", http.StatusForbidden, "auth disabled")
		writeErr(w, http.StatusForbidden, "auth disabled")
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		s.record(r, AuditAuthLogin, "user:unknown", http.StatusBadRequest, "invalid body")
		writeErr(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	// task ③: the login audit target names the account being attempted; the
	// detail carries the username only — never the password.
	target := "user:" + body.Username
	if target == "user:" {
		target = "user:unknown"
	}
	// MINOR-1: an empty username would record an empty actor; "" is "no
	// filter" in AuditFilter, so such a row could never be found by an
	// actor filter and falls outside the actor vocabulary. Fall back to
	// "anonymous" (the vocabulary entry for unresolvable identity).
	actor := body.Username
	if actor == "" {
		actor = "anonymous"
	}
	token, u, err := a.Login(body.Username, body.Password)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrAuthDisabled):
			s.recordAs(r, actor, AuditAuthLogin, target, http.StatusForbidden, "auth disabled")
			writeErr(w, http.StatusForbidden, "auth disabled")
		case errors.Is(err, auth.ErrInvalidCredentials):
			s.recordAs(r, actor, AuditAuthLogin, target, http.StatusUnauthorized, "username="+body.Username)
			writeErr(w, http.StatusUnauthorized, "invalid username or password")
		default:
			s.recordAs(r, actor, AuditAuthLogin, target, http.StatusInternalServerError, "login: "+err.Error())
			writeErr(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	s.recordAs(r, u.Username, AuditAuthLogin, "user:"+u.Username, http.StatusOK, "role="+u.Role)
	writeJSON(w, http.StatusOK, map[string]any{
		"token":      token,
		"username":   u.Username,
		"role":       u.Role,
		"expires_at": time.Now().UTC().Add(a.SessionTTL()).Format(time.RFC3339),
	})
}

// handleAuthLogout: POST /api/auth/logout. Invalidates the caller's session.
func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	u, _ := s.Auth.UserFromRequest(r) // resolved before the session is invalidated
	if err := s.Auth.LogoutRequest(r); err != nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	s.recordAs(r, u.Username, AuditAuthLogout, "user:"+u.Username, http.StatusOK, "")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleAuthMe: GET /api/auth/me. Caller identity.
func (s *Server) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	u, _ := s.Auth.UserFromRequest(r) // requireAuth(viewer) already enforced
	writeJSON(w, http.StatusOK, map[string]any{"username": u.Username, "role": u.Role})
}

// ---------------------------------------------------------------------------
// User management (admin)
// ---------------------------------------------------------------------------

type userJSON struct {
	Username  string `json:"username"`
	Role      string `json:"role"`
	CreatedAt string `json:"created_at"`
}

var usernameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{3,64}$`)

// handleListUsers: GET /api/users. Never returns password hashes.
func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.Store.ListUsers()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]userJSON, 0, len(users))
	for _, u := range users {
		out = append(out, userJSON{Username: u.Username, Role: u.Role, CreatedAt: u.CreatedAt})
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out})
}

// handleCreateUser: POST /api/users.
func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		s.record(r, AuditUserCreate, "user:unknown", http.StatusBadRequest, "invalid body")
		writeErr(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	if !usernameRe.MatchString(body.Username) {
		s.record(r, AuditUserCreate, "user:unknown", http.StatusBadRequest, "invalid username")
		writeErr(w, http.StatusBadRequest, "username must be 3-64 chars of [A-Za-z0-9._-]")
		return
	}
	if len(body.Password) < 8 {
		// task ③: detail names the account only — never the password.
		s.record(r, AuditUserCreate, "user:"+body.Username, http.StatusBadRequest, "password too short")
		writeErr(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}
	role, err := auth.ParseRole(body.Role)
	if err != nil {
		s.record(r, AuditUserCreate, "user:"+body.Username, http.StatusBadRequest, "bad role: "+body.Role)
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	hash, err := auth.HashPassword(body.Password)
	if err != nil {
		s.record(r, AuditUserCreate, "user:"+body.Username, http.StatusInternalServerError, "hash: "+err.Error())
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if _, err := s.Store.CreateUser(body.Username, hash, string(role)); err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			s.record(r, AuditUserCreate, "user:"+body.Username, http.StatusConflict, "already exists")
			writeErr(w, http.StatusConflict, "username already exists")
			return
		}
		s.record(r, AuditUserCreate, "user:"+body.Username, http.StatusInternalServerError, "create: "+err.Error())
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.record(r, AuditUserCreate, "user:"+body.Username, http.StatusCreated, "role="+string(role))
	writeJSON(w, http.StatusCreated, map[string]any{"username": body.Username, "role": string(role)})
}

// handleDeleteUser: DELETE /api/users/{name}.
// 409: deleting self; deleting the last admin. 404: unknown user.
func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	u, err := s.Store.GetUserByUsername(name)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.record(r, AuditUserDelete, "user:"+name, http.StatusNotFound, "user not found")
			writeErr(w, http.StatusNotFound, "user not found: "+name)
			return
		}
		s.record(r, AuditUserDelete, "user:"+name, http.StatusInternalServerError, err.Error())
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if caller, ok := s.Auth.UserFromRequest(r); ok && caller.Username == u.Username {
		s.record(r, AuditUserDelete, "user:"+name, http.StatusConflict, "cannot delete self")
		writeErr(w, http.StatusConflict, "cannot delete self")
		return
	}
	if u.Role == string(auth.RoleAdmin) {
		n, err := s.Store.CountUsersWithRole(string(auth.RoleAdmin))
		if err != nil {
			s.record(r, AuditUserDelete, "user:"+name, http.StatusInternalServerError, err.Error())
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if n <= 1 {
			s.record(r, AuditUserDelete, "user:"+name, http.StatusConflict, "last admin")
			writeErr(w, http.StatusConflict, "cannot delete last admin")
			return
		}
	}
	if err := s.Store.DeleteUser(name); err != nil {
		s.record(r, AuditUserDelete, "user:"+name, http.StatusInternalServerError, "delete: "+err.Error())
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.record(r, AuditUserDelete, "user:"+name, http.StatusNoContent, "role="+u.Role)
	w.WriteHeader(http.StatusNoContent)
}
