// Package web serves the FlowStallion console: Go-templated pages (home,
// pipeline detail, run detail, a cost dashboard, and a login page when
// authentication is on) plus static assets, mounted in front of the JSON API.
// Browsers talk to the API via /api/* with a Bearer session token; page
// navigation carries the same token in the "flowstallion" query parameter so the server
// can gate page renders.
package web

import (
	"embed"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/flowstallion/flowstallion/pkg/auth"
)

//go:embed templates
var tplFS embed.FS

//go:embed static
var staticFS embed.FS

// pageData is what a template can reference. The role flags drive
// server-side conditional rendering of action controls, so a viewer's
// HTML never contains operator/admin-only element ids (A6-6).
type pageData struct {
	Title        string
	PipelineName string
	RunID        int64
	Next         string // login page: where to go after a successful sign-in
	AuthEnabled  bool
	Role         string // "admin" | "operator" | "viewer"; "admin" when auth is off
	CanOperate   bool   // operator or admin (or auth off)
	CanAdmin     bool   // admin (or auth off)
}

// Handler serves the console pages and falls through to the API for every
// other path (including all /api/* and /healthz). Routing is an explicit
// method+prefix switch rather than a ServeMux: a "GET /" mux pattern is a
// subtree match that would shadow every API GET endpoint.
type Handler struct {
	api    http.Handler
	pages  map[string]*template.Template
	static http.Handler
	auth   *auth.Authenticator
}

// New wraps the API handler with the console pages. auther may be nil or
// disabled, in which case the console behaves exactly as pre-P6 (no login,
// no redirects).
func New(api http.Handler, auther *auth.Authenticator) http.Handler {
	pages := make(map[string]*template.Template, 7)
	for _, name := range []string{"index.html", "pipeline.html", "run.html", "cost.html", "login.html", "audit.html", "settings.html"} {
		t, err := template.ParseFS(tplFS, "templates/"+name)
		if err != nil {
			panic("web: parse " + name + ": " + err.Error())
		}
		pages[name] = t
	}
	staticSub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic("web: static subtree: " + err.Error())
	}
	return &Handler{
		api:    api,
		pages:  pages,
		static: http.FileServer(http.FS(staticSub)),
		auth:   auther,
	}
}

func (h *Handler) authOn() bool {
	return h.auth != nil && h.auth.Enabled()
}

// pageAccess resolves the "flowstallion" session token on page navigation (page GETs
// carry the token as a query parameter; the JSON API uses the Authorization
// header) and returns the role flags used for server-side template gating.
// When auth is off, everyone is treated as admin-equivalent, exactly like
// the JSON API's synthetic user.
func (h *Handler) pageAccess(r *http.Request) (pageData, bool) {
	if !h.authOn() {
		return pageData{Role: string(auth.RoleAdmin), CanOperate: true, CanAdmin: true}, true
	}
	tok := r.URL.Query().Get("flowstallion")
	if tok == "" {
		return pageData{}, false
	}
	u, err := h.auth.Validate(tok)
	if err != nil {
		return pageData{}, false
	}
	role := auth.Role(u.Role)
	return pageData{
		Role:       string(role),
		CanOperate: role.AtLeast(auth.RoleOperator),
		CanAdmin:   role.AtLeast(auth.RoleAdmin),
	}, true
}

// ServeHTTP routes GET /, /pipeline/{name}, /run/{id}, /cost, /audit,
// /settings, /login and /static/* to the console, and everything else
// (all /api/*, /healthz, POSTs) to the API. When authentication is enabled,
// unauthenticated page GETs are redirected to /login, and /settings is
// additionally gated to admin (non-admins are redirected back to /login).
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.secureHeaders(w, r)
	if r.Method != http.MethodGet {
		h.api.ServeHTTP(w, r)
		return
	}
	path := r.URL.Path
	switch {
	case path == "/login":
		if !h.authOn() {
			// No auth: there is no login page; let the API answer (404).
			h.api.ServeHTTP(w, r)
			return
		}
		next := r.URL.Query().Get("next")
		if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
			next = "/"
		}
		h.render(w, "login.html", pageData{Title: "Sign in", Next: next, AuthEnabled: true})
		return

	case path == "/" || path == "/cost" || path == "/audit" || path == "/settings" ||
		strings.HasPrefix(path, "/pipeline/") || strings.HasPrefix(path, "/run/"):
		pd, ok := h.pageAccess(r)
		if !ok {
			http.Redirect(w, r, "/login?next="+url.QueryEscape(path), http.StatusFound)
			return
		}
		pd.AuthEnabled = h.authOn()
		// /settings is admin-only: under auth, non-admins are sent back to the
		// login page (a 302, not a 403, keeps the token flow intact); with
		// auth off the synthetic admin already passed the gate above.
		if path == "/settings" && !pd.CanAdmin {
			http.Redirect(w, r, "/login?next="+url.QueryEscape(path), http.StatusFound)
			return
		}
		switch path {
		case "/":
			pd.Title = "FlowStallion"
			h.render(w, "index.html", pd)
		case "/cost":
			pd.Title = "Costs"
			h.render(w, "cost.html", pd)
		case "/audit":
			pd.Title = "Audit"
			h.render(w, "audit.html", pd)
		case "/settings":
			pd.Title = "Settings"
			h.render(w, "settings.html", pd)
		default:
			if strings.HasPrefix(path, "/pipeline/") {
				name := strings.TrimPrefix(path, "/pipeline/")
				if !validSegment(name) {
					http.NotFound(w, r)
					return
				}
				pd.Title = "Pipeline " + name
				pd.PipelineName = name
				h.render(w, "pipeline.html", pd)
				return
			}
			idStr := strings.TrimPrefix(path, "/run/")
			id, err := strconv.ParseInt(idStr, 10, 64)
			if err != nil || id < 1 || strings.Contains(idStr, "/") {
				http.NotFound(w, r)
				return
			}
			pd.Title = "Run " + idStr
			pd.RunID = id
			h.render(w, "run.html", pd)
		}
		return

	case strings.HasPrefix(path, "/static/"):
		// FileServer cleans the path, so ../ traversal is rejected.
		r.URL.Path = strings.TrimPrefix(path, "/static/")
		h.static.ServeHTTP(w, r)
		return
	}
	h.api.ServeHTTP(w, r)
}

// secureHeaders stamps the console security response headers on every
// response, before any handler writes:
//
//	X-Content-Type-Options: nosniff   — no MIME sniffing
//	X-Frame-Options: DENY             — console must not render in a frame
//	Referrer-Policy: no-referrer      — never leak the URL (it can carry
//	                                    the flowstallion session token) to third parties
//	Cache-Control: no-store           — HTML pages (role-gated markup + token)
//	Cache-Control: no-cache           — /static/*: revalidate on load so a
//	                                    deployed asset update is not shadowed
//	                                    by a stale copy (chart.js 404 lesson)
func (h *Handler) secureHeaders(w http.ResponseWriter, r *http.Request) {
	hdr := w.Header()
	hdr.Set("X-Content-Type-Options", "nosniff")
	hdr.Set("X-Frame-Options", "DENY")
	hdr.Set("Referrer-Policy", "no-referrer")
	if strings.HasPrefix(r.URL.Path, "/static/") {
		hdr.Set("Cache-Control", "no-cache")
	} else {
		hdr.Set("Cache-Control", "no-store")
	}
}

// validSegment reports whether s is a single non-empty path segment
// (no further slashes).
func validSegment(s string) bool {
	return s != "" && !strings.Contains(s, "/")
}

func (h *Handler) render(w http.ResponseWriter, name string, data pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.pages[name].Execute(w, data); err != nil {
		http.Error(w, "render: "+err.Error(), http.StatusInternalServerError)
	}
}
