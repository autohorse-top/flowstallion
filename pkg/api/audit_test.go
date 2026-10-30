package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/flowstallion/flowstallion/pkg/auth"
	"github.com/flowstallion/flowstallion/pkg/scheduler"
	"github.com/flowstallion/flowstallion/pkg/store"
)

// newAuditTestServer builds a server (auth on/off) and returns the store so
// tests can inspect audit rows directly.
func newAuditTestServer(t *testing.T, authOn bool) (*httptest.Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	disp := NewDispatcher()
	sched := scheduler.New(st, &AgentExecutor{D: disp})
	srv := New(st, sched, disp)
	if authOn {
		srv.Auth = auth.New(st, true, time.Hour, "agent-secret")
		seedUsers(t, st)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() {
		ts.Close()
		if authOn {
			st.Close()
		}
	})
	return ts, st
}

// latestAudit returns the most recent audit event with the given action, or
// fails the test if none exists.
func latestAudit(t *testing.T, st *store.Store, action string) store.AuditEvent {
	t.Helper()
	evs, err := st.ListAuditEvents(store.AuditFilter{Action: action, Limit: 1})
	if err != nil {
		t.Fatalf("list audit %s: %v", action, err)
	}
	if len(evs) == 0 {
		t.Fatalf("no audit event for action %q", action)
	}
	return evs[0]
}

func countAudit(t *testing.T, st *store.Store, f store.AuditFilter) []store.AuditEvent {
	t.Helper()
	evs, err := st.ListAuditEvents(f)
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	return evs
}

// TestOutcomeFromStatus is the table-driven mapping spec:
// 2xx→ok, 400→invalid, 401/403→denied, 404→not_found, 409→conflict,
// 5xx→error, other 4xx→invalid.
func TestOutcomeFromStatus(t *testing.T) {
	cases := []struct {
		status int
		want   string
	}{
		{200, OutcomeOK}, {201, OutcomeOK}, {204, OutcomeOK}, {206, OutcomeOK},
		{301, OutcomeInvalid},
		{400, OutcomeInvalid},
		{401, OutcomeDenied}, {403, OutcomeDenied},
		{404, OutcomeNotFound},
		{405, OutcomeInvalid}, {409, OutcomeConflict}, {429, OutcomeInvalid},
		{500, OutcomeError}, {503, OutcomeError}, {504, OutcomeError},
	}
	for _, tc := range cases {
		if got := outcomeFromStatus(tc.status); got != tc.want {
			t.Errorf("outcomeFromStatus(%d) = %q, want %q", tc.status, got, tc.want)
		}
	}
}

// TestTruncateDetail is table-driven: short strings pass through, long
// strings are rune-safe capped at detailMax.
func TestTruncateDetail(t *testing.T) {
	one := strings.Repeat("a", detailMax)
	oneExtra := one + "b"
	// 1000 CJK chars = 3000 bytes but only 1000 runes.
	cjk := strings.Repeat("中", detailMax)
	cjkExtra := cjk + "x"
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"short", "len=42", "len=42"},
		{"exact", one, one},
		{"ascii over", oneExtra, one},
		{"cjk exact (3*bytes)", cjk, cjk},
		{"cjk over (rune-safe)", cjkExtra, cjk},
	}
	for _, tc := range cases {
		if got := truncateDetail(tc.in); got != tc.want {
			t.Errorf("%s: truncateDetail len=%d → len=%d, want len=%d",
				tc.name, len(tc.in), len(got), len(tc.want))
		}
	}
}

// TestRecordSanitizesControlChars pins the MINOR-2 fix: user-controlled
// detail fragments (e.g. a role string from POST /api/users) must not
// smuggle control characters into the audit log — a newline could forge a
// second audit line. recordAs (the single choke point) flattens \n, \r and
// \t to spaces before persisting.
func TestRecordSanitizesControlChars(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "sanitize.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()
	disp := NewDispatcher()
	srv := New(st, scheduler.New(st, &AgentExecutor{D: disp}), disp)
	req := httptest.NewRequest("GET", "/x", nil)
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"newline", "bad role: admin\nuser:fake detail=fake line", "bad role: admin user:fake detail=fake line"},
		{"carriage return", "a\rb", "a b"},
		{"tab", "a\tb", "a b"},
		{"mixed", "x\ny\rz\tw", "x y z w"},
		{"clean passes through", "role=operator", "role=operator"},
	}
	for _, tc := range cases {
		srv.recordAs(req, "bob", AuditUserCreate, "user:bob", http.StatusBadRequest, tc.in)
		ev := latestAudit(t, st, AuditUserCreate)
		if ev.Detail != tc.want {
			t.Errorf("%s: detail = %q, want %q", tc.name, ev.Detail, tc.want)
		}
	}
}

// TestActorFromRequestAndRemoteHost unit-tests actor resolution
// (auth off → anonymous, auth on + valid session → username,
// auth on + no token → anonymous) and RemoteAddr host extraction.
func TestActorFromRequestAndRemoteHost(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "actor.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()
	disp := NewDispatcher()
	sched := scheduler.New(st, &AgentExecutor{D: disp})
	srv := New(st, sched, disp) // auth disabled

	req := httptest.NewRequest("GET", "/x", nil)
	req.RemoteAddr = "10.1.2.3:1234"
	if got := srv.actorFromRequest(req); got != "anonymous" {
		t.Errorf("auth off actor = %q, want anonymous", got)
	}
	if got := remoteHost(req); got != "10.1.2.3" {
		t.Errorf("remoteHost = %q, want 10.1.2.3", got)
	}
	// RemoteAddr without a port is returned as-is (never panics).
	weird := httptest.NewRequest("GET", "/y", nil)
	weird.RemoteAddr = "10.9.8.7"
	if got := remoteHost(weird); got != "10.9.8.7" {
		t.Errorf("remoteHost (no port) = %q, want 10.9.8.7", got)
	}

	// auth on + valid session token → the session's username.
	srv.Auth = auth.New(st, true, time.Hour, "")
	hash, _ := auth.HashPassword("pw-pass-1")
	uid, err := st.CreateUser("dave", hash, "operator")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := st.CreateSession("tok123", uid,
		now.Format(time.RFC3339), now.Add(time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	authed := httptest.NewRequest("GET", "/z", nil)
	authed.Header.Set("Authorization", "Bearer tok123")
	if got := srv.actorFromRequest(authed); got != "dave" {
		t.Errorf("authed actor = %q, want dave", got)
	}
	// auth on, no token → anonymous.
	if got := srv.actorFromRequest(httptest.NewRequest("GET", "/q", nil)); got != "anonymous" {
		t.Errorf("no-token actor = %q, want anonymous", got)
	}
}

// TestAuditListEndpoint covers GET /api/audit: shape, ordering, filters,
// cursor, and parameter validation.
func TestAuditListEndpoint(t *testing.T) {
	ts, st := newAuditTestServer(t, true)
	adminTok := loginToken(t, ts, "admin", "admin-pass-1")
	viewTok := loginToken(t, ts, "viewer", "viewer-pass-1")

	for i, actor := range []string{"alice", "bob", "bob"} {
		if err := st.AddAuditEvent(store.AuditEvent{
			Actor: actor, Action: "run.trigger", Target: fmt.Sprintf("run:%d", i+1),
			Outcome: "ok", Detail: "d",
		}); err != nil {
			t.Fatal(err)
		}
	}

	get := func(q, token string) (int, []store.AuditEvent) {
		code, data := doReq(t, "GET", ts.URL+"/api/audit"+q, token, "", nil)
		var out struct {
			Events []store.AuditEvent `json:"events"`
		}
		if code == http.StatusOK {
			if err := json.Unmarshal(data, &out); err != nil {
				t.Fatalf("bad events JSON: %v (%s)", err, data)
			}
		}
		return code, out.Events
	}

	// auth off would be open; with auth on: no token → 401.
	if code, _ := get("", ""); code != http.StatusUnauthorized {
		t.Errorf("no token: got %d, want 401", code)
	}
	// viewer allowed; the seeded events (the test's own login/deny events
	// are excluded via the action filter) come back newest-first.
	code, evs := get("?action=run.trigger", viewTok)
	if code != http.StatusOK {
		t.Fatalf("viewer: got %d, want 200", code)
	}
	if len(evs) != 3 || evs[0].ID <= evs[1].ID || evs[1].ID <= evs[2].ID {
		t.Fatalf("ordering/length: %+v", evs)
	}
	// actor filter (exact)
	if _, evs = get("?action=run.trigger&actor=bob", viewTok); len(evs) != 2 {
		t.Errorf("actor=bob → %d rows, want 2", len(evs))
	}
	// target filter
	if _, evs = get("?action=run.trigger&target=run:1", viewTok); len(evs) != 1 || evs[0].Target != "run:1" {
		t.Errorf("target filter → %+v", evs)
	}
	// cursor: after=N keeps only events older than N (id < N). The three
	// seeded run.trigger events are consecutive ids (topID, topID-1, topID-2).
	if _, evs = get("?action=run.trigger", viewTok); len(evs) != 3 {
		t.Fatalf("re-list run.trigger for cursor: %d rows, want 3", len(evs))
	}
	topID := evs[0].ID
	if _, evs := get(fmt.Sprintf("?after=%d&action=run.trigger", topID), viewTok); len(evs) != 2 {
		t.Errorf("after newest → %d rows, want 2 (the two older seeded)", len(evs))
	}
	if _, evs = get(fmt.Sprintf("?after=%d&action=run.trigger", topID-1), viewTok); len(evs) != 1 {
		t.Errorf("after middle → %d rows, want 1 (the oldest seeded)", len(evs))
	}
	if _, evs = get(fmt.Sprintf("?after=%d&action=run.trigger", topID-2), viewTok); len(evs) != 0 {
		t.Errorf("after oldest → %d rows, want 0", len(evs))
	}
	// empty list is [] not null
	code, data := doReq(t, "GET", ts.URL+"/api/audit?action=nomatch", viewTok, "", nil)
	if code != http.StatusOK || !strings.Contains(string(data), `"events":[]`) {
		t.Errorf("empty list body = %s, want events:[]", data)
	}
	// bad params → 400
	for _, q := range []string{"?after=abc", "?after=0", "?after=-3", "?limit=0", "?limit=xyz"} {
		if code, _ := get(q, viewTok); code != http.StatusBadRequest {
			t.Errorf("q=%s: got %d, want 400", q, code)
		}
	}
	_ = adminTok
}

// TestAuditSinceFilter covers GET /api/audit?since=: an RFC3339 lower bound
// (ts >= since), inclusive, stacking with the after cursor, and 400 on
// malformed input.
func TestAuditSinceFilter(t *testing.T) {
	ts, st := newAuditTestServer(t, true)
	viewTok := loginToken(t, ts, "viewer", "viewer-pass-1")

	// Three scan.save events on fixed days (explicit TS is honored).
	for _, tsd := range []string{
		"2026-10-28T09:00:00Z", "2026-10-29T09:00:00Z", "2026-10-30T09:00:00Z",
	} {
		if err := st.AddAuditEvent(store.AuditEvent{
			Actor: "bot", Action: "scan.save", Target: "run:1",
			Outcome: "ok", Detail: "d", TS: tsd,
		}); err != nil {
			t.Fatal(err)
		}
	}

	get := func(q string) (int, []store.AuditEvent) {
		code, data := doReq(t, "GET", ts.URL+"/api/audit"+q, viewTok, "", nil)
		var out struct {
			Events []store.AuditEvent `json:"events"`
		}
		if code == http.StatusOK {
			if err := json.Unmarshal(data, &out); err != nil {
				t.Fatalf("bad events JSON: %v (%s)", err, data)
			}
		}
		return code, out.Events
	}

	t.Run("since between events", func(t *testing.T) {
		code, evs := get("?action=scan.save&since=2026-10-29T00:00:00Z")
		if code != http.StatusOK {
			t.Fatalf("got %d, want 200", code)
		}
		if len(evs) != 2 || evs[0].TS != "2026-10-30T09:00:00Z" || evs[1].TS != "2026-10-29T09:00:00Z" {
			t.Fatalf("since 10-29 → %+v, want the 10-30 and 10-29 events (newest first)", evs)
		}
	})

	t.Run("since inclusive (exact match)", func(t *testing.T) {
		_, evs := get("?action=scan.save&since=2026-10-28T09:00:00Z")
		if len(evs) != 3 {
			t.Fatalf("since exactly on oldest event → %d rows, want 3 (ts >= since)", len(evs))
		}
	})

	t.Run("since in the future", func(t *testing.T) {
		code, evs := get("?action=scan.save&since=2026-10-31T00:00:00Z")
		if code != http.StatusOK || len(evs) != 0 {
			t.Fatalf("since in future → code=%d rows=%d, want 200/0", code, len(evs))
		}
	})

	t.Run("since stacks with after", func(t *testing.T) {
		// after=<newest id> keeps only older ids; since then keeps >= 10-29.
		_, newest := get("?action=scan.save")
		code, evs := get(fmt.Sprintf("?action=scan.save&after=%d&since=2026-10-29T00:00:00Z", newest[0].ID))
		if code != http.StatusOK || len(evs) != 1 || evs[0].TS != "2026-10-29T09:00:00Z" {
			t.Fatalf("after+since → code=%d %+v, want only the 10-29 event", code, evs)
		}
	})

	for _, q := range []string{"?since=garbage", "?since=2026-10-29", "?since=2026-10-29 09:00:00Z"} {
		if code, _ := get(q); code != http.StatusBadRequest {
			t.Errorf("q=%s: got %d, want 400", q, code)
		}
	}
}

// TestAuditAuthDenyEvents checks requireRole and requireAgent denials land
// as auth.deny with the right target/actor/outcome.
func TestAuditAuthDenyEvents(t *testing.T) {
	ts, st := newAuditTestServer(t, true)
	viewTok := loginToken(t, ts, "viewer", "viewer-pass-1")

	// 403: viewer creates a user.
	code, _ := doReq(t, "POST", ts.URL+"/api/users", viewTok, "",
		map[string]string{"username": "x3", "password": "password123", "role": "viewer"})
	if code != http.StatusForbidden {
		t.Fatalf("viewer create user: got %d, want 403", code)
	}
	ev := latestAudit(t, st, AuditAuthDeny)
	if ev.Actor != "viewer" || ev.Target != "POST /api/users" || ev.Outcome != OutcomeDenied {
		t.Fatalf("403 event = %+v", ev)
	}

	// 401: no token reads runs.
	code, _ = doReq(t, "GET", ts.URL+"/api/runs", "", "", nil)
	if code != http.StatusUnauthorized {
		t.Fatalf("no token: got %d, want 401", code)
	}
	ev = latestAudit(t, st, AuditAuthDeny)
	if ev.Actor != "anonymous" || ev.Target != "GET /api/runs" || ev.Outcome != OutcomeDenied {
		t.Fatalf("401 event = %+v", ev)
	}

	// 401: agent endpoint with no valid token.
	code, _ = doReq(t, "POST", ts.URL+"/api/agent/register", "", "",
		map[string]string{"name": "a1"})
	if code != http.StatusUnauthorized {
		t.Fatalf("agent register: got %d, want 401", code)
	}
	ev = latestAudit(t, st, AuditAuthDeny)
	if ev.Target != "POST /api/agent/register" || ev.Outcome != OutcomeDenied {
		t.Fatalf("agent deny event = %+v", ev)
	}
}

// TestAuditLoginLogoutEvents checks login (ok + denied) and logout events,
// and that the attempted password never appears in any audit detail.
func TestAuditLoginLogoutEvents(t *testing.T) {
	ts, st := newAuditTestServer(t, true)
	const secretPw = "super-secret-9x"
	// create a user with a distinctive password via admin
	adminTok := loginToken(t, ts, "admin", "admin-pass-1")
	code, _ := doReq(t, "POST", ts.URL+"/api/users", adminTok, "",
		map[string]string{"username": "carol", "password": secretPw, "role": "viewer"})
	if code != http.StatusCreated {
		t.Fatalf("create carol: got %d, want 201", code)
	}

	// bad password → 401 + auth.login denied, username in detail, no password.
	code, _ = doReq(t, "POST", ts.URL+"/api/auth/login", "", "",
		map[string]string{"username": "carol", "password": "totally-wrong-1"})
	if code != http.StatusUnauthorized {
		t.Fatalf("bad login: got %d, want 401", code)
	}
	ev := latestAudit(t, st, AuditAuthLogin)
	if ev.Actor != "carol" || ev.Target != "user:carol" || ev.Outcome != OutcomeDenied {
		t.Fatalf("login denied event = %+v", ev)
	}
	if !strings.Contains(ev.Detail, "username=carol") {
		t.Errorf("detail %q should name the attempted username", ev.Detail)
	}
	if strings.Contains(ev.Detail, "totally-wrong-1") {
		t.Error("password must not appear in audit detail")
	}

	// good login → auth.login ok.
	tok := loginToken(t, ts, "carol", secretPw)
	ev = latestAudit(t, st, AuditAuthLogin)
	if ev.Actor != "carol" || ev.Outcome != OutcomeOK || ev.Target != "user:carol" {
		t.Fatalf("login ok event = %+v", ev)
	}
	if !strings.Contains(ev.Detail, "role=viewer") {
		t.Errorf("detail %q should carry the role", ev.Detail)
	}

	// logout → auth.logout ok.
	code, _ = doReq(t, "POST", ts.URL+"/api/auth/logout", tok, "", nil)
	if code != http.StatusOK {
		t.Fatalf("logout: got %d, want 200", code)
	}
	ev = latestAudit(t, st, AuditAuthLogout)
	if ev.Actor != "carol" || ev.Target != "user:carol" || ev.Outcome != OutcomeOK {
		t.Fatalf("logout event = %+v", ev)
	}

	// global invariant: no audit detail contains the password.
	for _, e := range countAudit(t, st, store.AuditFilter{Limit: 200}) {
		if strings.Contains(e.Detail, secretPw) {
			t.Fatalf("audit detail %q leaks password", e.Detail)
		}
	}
}

// TestAuditLoginEmptyUsername pins the MINOR-1 fix: logging in with an empty
// username must not leave an empty actor in the audit log. An empty actor is
// "no filter" in AuditFilter (the row can never be found by an actor query)
// and is not in the actor vocabulary; the event must land as
// actor "anonymous" / target "user:unknown" instead.
func TestAuditLoginEmptyUsername(t *testing.T) {
	ts, st := newAuditTestServer(t, true)
	code, _ := doReq(t, "POST", ts.URL+"/api/auth/login", "", "",
		map[string]string{"username": "", "password": "whatever"})
	if code != http.StatusUnauthorized {
		t.Fatalf("empty-username login: got %d, want 401", code)
	}
	ev := latestAudit(t, st, AuditAuthLogin)
	if ev.Actor != "anonymous" || ev.Target != "user:unknown" {
		t.Fatalf("event = actor=%q target=%q, want actor=anonymous target=user:unknown (%+v)",
			ev.Actor, ev.Target, ev)
	}
}

// TestAuditWriteFailureIsBypass proves a broken audit store never changes
// the main response: with the store closed, a 401 is still returned and no
// panic escapes.
func TestAuditWriteFailureIsBypass(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "audit-fail.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	disp := NewDispatcher()
	sched := scheduler.New(st, &AgentExecutor{D: disp})
	srv := New(st, sched, disp)
	srv.Auth = auth.New(st, true, time.Hour, "agent-secret")
	// seed one user so login works before the store is closed
	hash, _ := auth.HashPassword("admin-pass-1")
	if _, err := st.CreateUser("admin", hash, "admin"); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	if err := st.Close(); err != nil { // simulate audit write failure
		t.Fatalf("close store: %v", err)
	}

	code, data := doReq(t, "GET", ts.URL+"/api/pipelines", "", "", nil)
	if code != http.StatusUnauthorized {
		t.Fatalf("with broken store, got %d (body=%s), want 401", code, data)
	}
}
