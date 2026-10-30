package api

import (
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/flowstallion/flowstallion/pkg/auth"
	"github.com/flowstallion/flowstallion/pkg/scheduler"
	"github.com/flowstallion/flowstallion/pkg/secret"
	"github.com/flowstallion/flowstallion/pkg/store"
)

// newSecretServer builds a full API server with auth enabled, seeded users,
// and a secret vault (fixed test key).
func newSecretServer(t *testing.T) *httptest.Server {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "secret.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	disp := NewDispatcher()
	sched := scheduler.New(st, &AgentExecutor{D: disp})
	srv := New(st, sched, disp)
	key, err := secret.KeyFromString(strings.Repeat("0011223344556677", 4))
	if err != nil {
		t.Fatalf("test key: %v", err)
	}
	vault, err := secret.New(key)
	if err != nil {
		t.Fatalf("new vault: %v", err)
	}
	srv.Auth = auth.New(st, true, time.Hour, "agent-secret")
	srv.Vault = vault
	seedUsers(t, st)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

// TestSecretAPI covers the full admin CRUD cycle over HTTP.
func TestSecretAPI(t *testing.T) {
	ts := newSecretServer(t)

	// unauthenticated -> 401
	if code, _ := doReq(t, "GET", ts.URL+"/api/secrets", "", "", nil); code != 401 {
		t.Fatalf("GET secrets no token: got %d, want 401", code)
	}
	// operator (not admin) -> 403
	opTok := loginToken(t, ts, "operator", "operator-pass-1")
	if code, _ := doReq(t, "GET", ts.URL+"/api/secrets", opTok, "", nil); code != 403 {
		t.Fatalf("GET secrets as operator: got %d, want 403", code)
	}
	// admin can create
	adminTok := loginToken(t, ts, "admin", "admin-pass-1")
	code, data := doReq(t, "POST", ts.URL+"/api/secrets", adminTok, "",
		map[string]string{"name": "DB_PASSWORD", "value": "s3cr3t"})
	if code != 200 {
		t.Fatalf("POST secret: got %d, want 200 (body=%s)", code, string(data))
	}
	// list shows the name, never the value
	code, data = doReq(t, "GET", ts.URL+"/api/secrets", adminTok, "", nil)
	if code != 200 {
		t.Fatalf("GET secrets: got %d, want 200", code)
	}
	if strings.Contains(string(data), "s3cr3t") {
		t.Fatalf("list response leaks the secret value: %s", data)
	}
	if !strings.Contains(string(data), "DB_PASSWORD") {
		t.Fatalf("list response missing name: %s", data)
	}
	// upsert (update) works
	code, data = doReq(t, "POST", ts.URL+"/api/secrets", adminTok, "",
		map[string]string{"name": "DB_PASSWORD", "value": "newer"})
	if code != 200 {
		t.Fatalf("POST secret update: got %d, want 200 (body=%s)", code, string(data))
	}
	// delete
	code, _ = doReq(t, "DELETE", ts.URL+"/api/secrets/DB_PASSWORD", adminTok, "", nil)
	if code != 204 {
		t.Fatalf("DELETE secret: got %d, want 204", code)
	}
	// second delete -> 404
	code, _ = doReq(t, "DELETE", ts.URL+"/api/secrets/DB_PASSWORD", adminTok, "", nil)
	if code != 404 {
		t.Fatalf("DELETE missing secret: got %d, want 404", code)
	}
}

// TestSecretAPIValidation covers name/value validation rules.
func TestSecretAPIValidation(t *testing.T) {
	ts := newSecretServer(t)
	adminTok := loginToken(t, ts, "admin", "admin-pass-1")

	// bad name (space + bang)
	code, _ := doReq(t, "POST", ts.URL+"/api/secrets", adminTok, "",
		map[string]string{"name": "bad name!", "value": "x"})
	if code != 400 {
		t.Fatalf("POST bad name: got %d, want 400", code)
	}
	// name too long (129)
	code, _ = doReq(t, "POST", ts.URL+"/api/secrets", adminTok, "",
		map[string]string{"name": strings.Repeat("a", 129), "value": "x"})
	if code != 400 {
		t.Fatalf("POST long name: got %d, want 400", code)
	}
	// value too large (8193 bytes)
	code, _ = doReq(t, "POST", ts.URL+"/api/secrets", adminTok, "",
		map[string]string{"name": "BIG", "value": strings.Repeat("v", 8193)})
	if code != 400 {
		t.Fatalf("POST big value: got %d, want 400", code)
	}
	// boundary: 8192 is accepted
	code, _ = doReq(t, "POST", ts.URL+"/api/secrets", adminTok, "",
		map[string]string{"name": "EDGE", "value": strings.Repeat("v", 8192)})
	if code != 200 {
		t.Fatalf("POST 8192-byte value: got %d, want 200", code)
	}
}

// TestSecretAPIOversizedBody: bodies beyond the 64 KiB cap must be rejected
// (memory-DoS guard); the server must stay up afterwards.
func TestSecretAPIOversizedBody(t *testing.T) {
	ts := newSecretServer(t)
	adminTok := loginToken(t, ts, "admin", "admin-pass-1")

	// ~9 MiB of JSON far exceeds the 64 KiB reader cap.
	code, _ := doReq(t, "POST", ts.URL+"/api/secrets", adminTok, "",
		map[string]string{"name": "BIG", "value": strings.Repeat("v", 9<<20)})
	if code != 400 {
		t.Fatalf("POST oversized body: got %d, want 400", code)
	}
	// server still serves normal traffic
	code, _ = doReq(t, "POST", ts.URL+"/api/secrets", adminTok, "",
		map[string]string{"name": "OK", "value": "x"})
	if code != 200 {
		t.Fatalf("POST after oversized body: got %d, want 200", code)
	}
}

// TestSecretAPIDisabled: a server without a vault returns 503 on write and
// 200 with an empty list on read.
func TestSecretAPIDisabled(t *testing.T) {
	ts := newPlainServer(t) // no vault, auth off
	code, _ := doReq(t, "POST", ts.URL+"/api/secrets", "", "",
		map[string]string{"name": "X", "value": "y"})
	if code != 503 {
		t.Fatalf("POST secret without vault: got %d, want 503", code)
	}
	code, data := doReq(t, "GET", ts.URL+"/api/secrets", "", "", nil)
	if code != 200 {
		t.Fatalf("GET secrets without vault: got %d, want 200", code)
	}
	if !strings.Contains(string(data), `"secrets":[]`) && !strings.Contains(string(data), `"secrets": []`) {
		t.Fatalf("GET secrets without vault: want empty list, got %s", data)
	}
}
