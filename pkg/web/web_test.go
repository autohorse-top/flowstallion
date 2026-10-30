package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/flowstallion/flowstallion/pkg/api"
	"github.com/flowstallion/flowstallion/pkg/auth"
	"github.com/flowstallion/flowstallion/pkg/scheduler"
	"github.com/flowstallion/flowstallion/pkg/store"
)

// newTestHandler wires a real store + scheduler + API, wrapped by the web
// console, and returns the root handler.
func newTestHandler(t *testing.T) http.Handler {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "web-test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	disp := api.NewDispatcher()
	sched := scheduler.New(st, &api.AgentExecutor{D: disp})
	srv := api.New(st, sched, disp)
	return New(srv.Handler(), srv.Auth)
}

// newAuthTestHandler wires the console with authentication enabled and two
// seeded users (admin/viewer).
func newAuthTestHandler(t *testing.T) (http.Handler, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "web-auth.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	disp := api.NewDispatcher()
	sched := scheduler.New(st, &api.AgentExecutor{D: disp})
	srv := api.New(st, sched, disp)
	srv.Auth = auth.New(st, true, time.Hour, "agent-secret")
	for _, u := range []struct{ name, pw, role string }{
		{"admin", "admin-pass-1", "admin"},
		{"viewer", "viewer-pass-1", "viewer"},
	} {
		hash, err := auth.HashPassword(u.pw)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.CreateUser(u.name, hash, u.role); err != nil {
			t.Fatal(err)
		}
	}
	return New(srv.Handler(), srv.Auth), st
}

// loginToken obtains a session token over HTTP.
func loginToken(t *testing.T, h http.Handler, user, pass string) string {
	t.Helper()
	code, body := doPost(t, h, "/api/auth/login", map[string]string{"username": user, "password": pass})
	if code != http.StatusOK {
		t.Fatalf("login %s: got %d, want 200 (body=%s)", user, code, body)
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil || out.Token == "" {
		t.Fatalf("login response %q: %v", body, err)
	}
	return out.Token
}

func doGet(t *testing.T, h http.Handler, path string) (int, string, http.Header) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String(), rec.Header()
}

func doPost(t *testing.T, h http.Handler, path string, body any) (int, string) {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func TestHomePage(t *testing.T) {
	h := newTestHandler(t)
	code, body, hdr := doGet(t, h, "/")
	if code != http.StatusOK {
		t.Fatalf("GET /: got %d, want 200", code)
	}
	if ct := hdr.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("GET /: content-type %q, want text/html", ct)
	}
	for _, want := range []string{`data-page="home"`, "FlowStallion", "/static/style.css", "/static/app.js"} {
		if !strings.Contains(body, want) {
			t.Errorf("home page missing %q", want)
		}
	}
}

func TestPipelinePage(t *testing.T) {
	h := newTestHandler(t)
	code, body, _ := doGet(t, h, "/pipeline/e2e-demo")
	if code != http.StatusOK {
		t.Fatalf("GET /pipeline/e2e-demo: got %d, want 200", code)
	}
	for _, want := range []string{`data-page="pipeline"`, `data-name="e2e-demo"`, "Trigger run"} {
		if !strings.Contains(body, want) {
			t.Errorf("pipeline page missing %q", want)
		}
	}
}

func TestRunPage(t *testing.T) {
	h := newTestHandler(t)
	code, body, _ := doGet(t, h, "/run/42")
	if code != http.StatusOK {
		t.Fatalf("GET /run/42: got %d, want 200", code)
	}
	for _, want := range []string{`data-page="run"`, `data-run="42"`, "Cancel run", "Logs", "Root cause analysis", `id="rca"`, "Security scans", `id="scans"`, `id="pr-review-card"`, `id="pr-review"`, `id="test-selection-card"`, `id="test-selection"`} {
		if !strings.Contains(body, want) {
			t.Errorf("run page missing %q", want)
		}
	}
	for _, id := range []string{`id="scans"`, `id="pr-review"`, `id="test-selection"`} {
		if n := strings.Count(body, id); n != 1 {
			t.Errorf(`run page has %d %s elements, want exactly 1`, n, id)
		}
	}
}

func TestCostPage(t *testing.T) {
	h := newTestHandler(t)
	code, body, hdr := doGet(t, h, "/cost")
	if code != http.StatusOK {
		t.Fatalf("GET /cost: got %d, want 200", code)
	}
	if ct := hdr.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("GET /cost: content-type %q, want text/html", ct)
	}
	for _, want := range []string{`data-page="cost"`, `id="cost"`, `id="cost-total"`, "by team", "LLM only"} {
		if !strings.Contains(body, want) {
			t.Errorf("cost page missing %q", want)
		}
	}
}

func TestRunPageBadID(t *testing.T) {
	h := newTestHandler(t)
	for _, path := range []string{"/run/abc", "/run/0", "/run/-1", "/run/"} {
		code, _, _ := doGet(t, h, path)
		if code != http.StatusNotFound {
			t.Errorf("GET %s: got %d, want 404", path, code)
		}
	}
}

func TestStaticAssets(t *testing.T) {
	h := newTestHandler(t)
	code, css, hdr := doGet(t, h, "/static/style.css")
	if code != http.StatusOK {
		t.Fatalf("GET /static/style.css: got %d, want 200", code)
	}
	if !strings.Contains(css, "logbox") {
		t.Errorf("style.css missing expected content")
	}
	if ct := hdr.Get("Content-Type"); !strings.HasPrefix(ct, "text/css") {
		t.Errorf("style.css content-type %q", ct)
	}
	code, js, _ := doGet(t, h, "/static/app.js")
	if code != http.StatusOK {
		t.Fatalf("GET /static/app.js: got %d, want 200", code)
	}
	if !strings.Contains(js, "dataset.page") {
		t.Errorf("app.js missing expected content")
	}
}

// TestSecurityHeaders (Task 9): every response carries nosniff/DENY/
// no-referrer; HTML and API responses are no-store, static assets no-cache.
func TestSecurityHeaders(t *testing.T) {
	h := newTestHandler(t)
	cases := []struct {
		name   string
		path   string
		wantCC string
	}{
		{name: "html home", path: "/", wantCC: "no-store"},
		{name: "html pipeline", path: "/pipeline/e2e-demo", wantCC: "no-store"},
		{name: "html 404 page", path: "/run/abc", wantCC: "no-store"},
		{name: "static css", path: "/static/style.css", wantCC: "no-cache"},
		{name: "static js", path: "/static/app.js", wantCC: "no-cache"},
		{name: "api json", path: "/api/pipelines", wantCC: "no-store"},
		{name: "unknown 404", path: "/nope/nothing", wantCC: "no-store"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, hdr := doGet(t, h, tc.path)
			if got := hdr.Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("GET %s: X-Content-Type-Options = %q, want nosniff", tc.path, got)
			}
			if got := hdr.Get("X-Frame-Options"); got != "DENY" {
				t.Errorf("GET %s: X-Frame-Options = %q, want DENY", tc.path, got)
			}
			if got := hdr.Get("Referrer-Policy"); got != "no-referrer" {
				t.Errorf("GET %s: Referrer-Policy = %q, want no-referrer", tc.path, got)
			}
			if got := hdr.Get("Cache-Control"); got != tc.wantCC {
				t.Errorf("GET %s: Cache-Control = %q, want %q", tc.path, got, tc.wantCC)
			}
		})
	}
}

func TestAPIFallback(t *testing.T) {
	h := newTestHandler(t)
	// Empty store: /api/pipelines must still answer through the web mount.
	code, body, hdr := doGet(t, h, "/api/pipelines")
	if code != http.StatusOK {
		t.Fatalf("GET /api/pipelines: got %d, want 200", code)
	}
	if ct := hdr.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("content-type %q, want application/json", ct)
	}
	if strings.TrimSpace(body) != "[]" {
		t.Errorf("empty pipeline list, got %q", body)
	}
	code, _, _ = doGet(t, h, "/healthz")
	if code != http.StatusOK {
		t.Fatalf("GET /healthz: got %d, want 200", code)
	}
}

func TestUnknownPath404(t *testing.T) {
	h := newTestHandler(t)
	code, _, _ := doGet(t, h, "/nope/nothing")
	if code != http.StatusNotFound {
		t.Fatalf("GET /nope/nothing: got %d, want 404", code)
	}
}

const testYAML = `
version: 1
pipeline:
  name: demo
  steps:
    - id: a
      image: alpine
      commands:
        - echo a
`

func TestCreateTriggerAndRunPage(t *testing.T) {
	h := newTestHandler(t)
	code, body := doPost(t, h, "/api/pipelines", map[string]string{"name": "demo", "yaml": testYAML})
	if code != http.StatusCreated {
		t.Fatalf("create pipeline: got %d, want 201 (body=%s)", code, body)
	}
	code, body = doPost(t, h, "/api/pipelines/demo/trigger", map[string]string{"trigger": "manual"})
	if code != http.StatusAccepted {
		t.Fatalf("trigger: got %d, want 202 (body=%s)", code, body)
	}
	var out struct {
		RunID int64 `json:"run_id"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil || out.RunID < 1 {
		t.Fatalf("trigger response %q: %v", body, err)
	}
	// The run detail page must render for the new run id.
	idStr := strconv.FormatInt(out.RunID, 10)
	code, body, _ = doGet(t, h, "/run/"+idStr)
	if code != http.StatusOK {
		t.Fatalf("GET /run/%s: got %d, want 200", idStr, code)
	}
	if !strings.Contains(body, "data-run=\""+idStr+"\"") {
		t.Errorf("run page missing data-run=%s", idStr)
	}
}

func TestWebAuthOffNoLogin(t *testing.T) {
	h := newTestHandler(t)
	code, _, _ := doGet(t, h, "/")
	if code != http.StatusOK {
		t.Fatalf("GET / (auth off): got %d, want 200 (auth off must not redirect)", code)
	}
	code, _, _ = doGet(t, h, "/login")
	if code != http.StatusNotFound {
		t.Fatalf("GET /login (auth off): got %d, want 404", code)
	}
}

func TestWebAuthOnRedirectsAndLogin(t *testing.T) {
	h, _ := newAuthTestHandler(t)
	var body string
	code, _, hdr := doGet(t, h, "/")
	if code != http.StatusFound {
		t.Fatalf("GET / (auth on, no token): got %d, want 302", code)
	}
	if loc := hdr.Get("Location"); loc != "/login?next=%2F" {
		t.Fatalf("Location = %q, want %q", loc, "/login?next=%2F")
	}
	code, body, _ = doGet(t, h, "/login")
	if code != http.StatusOK || !strings.Contains(body, `data-page="login"`) {
		t.Fatalf("GET /login: got %d; login form missing from body", code)
	}
	code, _, _ = doGet(t, h, "/?flowstallion=not-a-token")
	if code != http.StatusFound {
		t.Fatalf("GET /?flowstallion=bad: got %d, want 302", code)
	}
	tok := loginToken(t, h, "admin", "admin-pass-1")
	code, body, _ = doGet(t, h, "/?flowstallion="+tok)
	if code != http.StatusOK || !strings.Contains(body, `data-page="home"`) {
		t.Fatalf("GET /?flowstallion=valid: got %d", code)
	}
	code, _, _ = doGet(t, h, "/pipeline/e2e?flowstallion="+tok)
	if code != http.StatusOK {
		t.Fatalf("GET /pipeline/e2e?flowstallion=valid: got %d, want 200", code)
	}
	code, _, _ = doGet(t, h, "/run/7?flowstallion="+tok)
	if code != http.StatusOK {
		t.Fatalf("GET /run/7?flowstallion=valid: got %d, want 200", code)
	}
	code, _, _ = doGet(t, h, "/cost")
	if code != http.StatusFound {
		t.Fatalf("GET /cost (auth on, no token): got %d, want 302", code)
	}
	code, body, _ = doGet(t, h, "/cost?by=team&flowstallion="+tok)
	if code != http.StatusOK || !strings.Contains(body, `data-page="cost"`) {
		t.Fatalf("GET /cost?flowstallion=valid: got %d", code)
	}
}

func TestWebAuthOnAPIRequiresToken(t *testing.T) {
	h, _ := newAuthTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/api/pipelines", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /api/pipelines without token: got %d, want 401", rec.Code)
	}
	tok := loginToken(t, h, "admin", "admin-pass-1")
	req = httptest.NewRequest(http.MethodGet, "/api/pipelines", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/pipelines with token: got %d, want 200", rec.Code)
	}
}

// allPages lists every console page for the gating matrix.
var allPages = []string{"/", "/cost", "/audit", "/settings", "/pipeline/e2e", "/run/7"}

func TestAuthOffPagesOpen(t *testing.T) {
	h := newTestHandler(t)
	for _, p := range allPages {
		code, _, _ := doGet(t, h, p)
		if code != http.StatusOK {
			t.Errorf("GET %s (auth off): got %d, want 200 (auth off must be fully open)", p, code)
		}
	}
}

func TestAuthOnPagesRequireToken(t *testing.T) {
	h, _ := newAuthTestHandler(t)
	for _, p := range allPages {
		code, _, hdr := doGet(t, h, p)
		if code != http.StatusFound {
			t.Errorf("GET %s (auth on, no token): got %d, want 302", p, code)
			continue
		}
		want := "/login?next=" + url.QueryEscape(p)
		if loc := hdr.Get("Location"); loc != want {
			t.Errorf("GET %s: Location %q, want %q", p, loc, want)
		}
	}
}

func TestAuthOnPagesOpenWithToken(t *testing.T) {
	h, _ := newAuthTestHandler(t)
	tok := loginToken(t, h, "admin", "admin-pass-1")
	for _, p := range allPages {
		code, _, _ := doGet(t, h, p+"?flowstallion="+tok)
		if code != http.StatusOK {
			t.Errorf("GET %s?flowstallion=admin: got %d, want 200", p, code)
		}
	}
}

func TestSettingsAdminOnly(t *testing.T) {
	h, st := newAuthTestHandler(t)
	// Seed an operator for the middle tier.
	hash, err := auth.HashPassword("operator-pass-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateUser("operator", hash, "operator"); err != nil {
		t.Fatal(err)
	}
	adminTok := loginToken(t, h, "admin", "admin-pass-1")
	viewerTok := loginToken(t, h, "viewer", "viewer-pass-1")
	operatorTok := loginToken(t, h, "operator", "operator-pass-1")

	// Admin: 200 with the users + secrets sections.
	code, body, _ := doGet(t, h, "/settings?flowstallion="+adminTok)
	if code != http.StatusOK {
		t.Fatalf("GET /settings (admin): got %d, want 200", code)
	}
	for _, want := range []string{`data-page="settings"`, `id="users"`, `id="secrets"`, `id="user-create"`, `id="secret-save"`} {
		if !strings.Contains(body, want) {
			t.Errorf("settings page (admin) missing %q", want)
		}
	}
	// Viewer and operator: 302 to login with next=/settings.
	for name, tok := range map[string]string{"viewer": viewerTok, "operator": operatorTok} {
		code, _, hdr := doGet(t, h, "/settings?flowstallion="+tok)
		if code != http.StatusFound {
			t.Fatalf("GET /settings (%s): got %d, want 302", name, code)
		}
		if loc := hdr.Get("Location"); loc != "/login?next=%2Fsettings" {
			t.Errorf("GET /settings (%s): Location %q, want %q", name, loc, "/login?next=%2Fsettings")
		}
	}
}

// TestLoginNoAccessMount pins m2: an authenticated viewer hitting /settings is
// 302'd to /login?next=/settings (the server-side RBAC decision is kept); that
// login page must carry the "no access" mount point the inline script reveals
// to break the redirect loop instead of "too many redirects". The JS probe
// behaviour itself is covered by the smoke script.
func TestLoginNoAccessMount(t *testing.T) {
	h, _ := newAuthTestHandler(t)
	viewerTok := loginToken(t, h, "viewer", "viewer-pass-1")

	code, _, hdr := doGet(t, h, "/settings?flowstallion="+viewerTok)
	if code != http.StatusFound {
		t.Fatalf("GET /settings (viewer): got %d, want 302", code)
	}
	if loc := hdr.Get("Location"); loc != "/login?next=%2Fsettings" {
		t.Fatalf("Location = %q, want %q", loc, "/login?next=%2Fsettings")
	}

	code, body, _ := doGet(t, h, "/login?next=%2Fsettings")
	if code != http.StatusOK {
		t.Fatalf("GET /login?next=/settings: got %d, want 200", code)
	}
	for _, want := range []string{`data-next="/settings"`, `id="no-access"`, "does not have access"} {
		if !strings.Contains(body, want) {
			t.Errorf("login page (next=/settings) missing %q", want)
		}
	}
}

func TestAuditPage(t *testing.T) {
	h, _ := newAuthTestHandler(t)
	tok := loginToken(t, h, "viewer", "viewer-pass-1")
	code, body, _ := doGet(t, h, "/audit?flowstallion="+tok)
	if code != http.StatusOK {
		t.Fatalf("GET /audit (viewer): got %d, want 200", code)
	}
	for _, want := range []string{`data-page="audit"`, `id="audit"`, `id="f-action"`, `id="audit-more"`, `value="auth.login"`, `value="run.trigger"`, `value="user.create"`} {
		if !strings.Contains(body, want) {
			t.Errorf("audit page missing %q", want)
		}
	}
}

// TestPageControlsGatedByRole pins A6-6: the viewer's HTML must not carry
// operator/admin control ids or the settings nav link.
func TestPageControlsGatedByRole(t *testing.T) {
	h, _ := newAuthTestHandler(t)
	adminTok := loginToken(t, h, "admin", "admin-pass-1")
	viewerTok := loginToken(t, h, "viewer", "viewer-pass-1")

	code, viewerPipe, _ := doGet(t, h, "/pipeline/e2e?flowstallion="+viewerTok)
	if code != http.StatusOK {
		t.Fatalf("GET /pipeline/e2e (viewer): got %d, want 200", code)
	}
	for _, id := range []string{`id="trigger"`, `id="yaml"`, `id="yaml-save"`} {
		if strings.Contains(viewerPipe, id) {
			t.Errorf("viewer pipeline page must not contain %s", id)
		}
	}
	if strings.Contains(viewerPipe, `href="/settings"`) {
		t.Error("viewer nav must not link to /settings")
	}

	code, adminPipe, _ := doGet(t, h, "/pipeline/e2e?flowstallion="+adminTok)
	if code != http.StatusOK {
		t.Fatalf("GET /pipeline/e2e (admin): got %d, want 200", code)
	}
	for _, id := range []string{`id="trigger"`, `id="yaml"`, `id="yaml-save"`} {
		if !strings.Contains(adminPipe, id) {
			t.Errorf("admin pipeline page missing %s", id)
		}
	}
	if !strings.Contains(adminPipe, `href="/settings"`) {
		t.Error("admin nav must link to /settings")
	}

	code, viewerRun, _ := doGet(t, h, "/run/7?flowstallion="+viewerTok)
	if code != http.StatusOK {
		t.Fatalf("GET /run/7 (viewer): got %d, want 200", code)
	}
	for _, id := range []string{`id="cancel"`, `id="approve"`, `id="reject"`} {
		if strings.Contains(viewerRun, id) {
			t.Errorf("viewer run page must not contain %s", id)
		}
	}

	code, adminRun, _ := doGet(t, h, "/run/7?flowstallion="+adminTok)
	if code != http.StatusOK {
		t.Fatalf("GET /run/7 (admin): got %d, want 200", code)
	}
	for _, id := range []string{`id="cancel"`, `id="approve"`, `id="reject"`} {
		if !strings.Contains(adminRun, id) {
			t.Errorf("admin run page missing %s", id)
		}
	}
}
