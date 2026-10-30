// config_test.go: API client resolution (env vs saved config), P7⑧.
package main

import "testing"

// A scheduler in open mode (no auth) has no token, so FLOWSTALLION_SERVER alone
// must be usable without a saved config file.
func TestAPIClientServerEnvAlone(t *testing.T) {
	t.Setenv("FLOWSTALLION_SERVER", "http://127.0.0.1:19999")
	t.Setenv("FLOWSTALLION_TOKEN", "")
	t.Setenv("HOME", t.TempDir()) // no saved config

	c, err := apiClient()
	if err != nil {
		t.Fatalf("apiClient() error = %v; want success with FLOWSTALLION_SERVER set", err)
	}
	if c.base != "http://127.0.0.1:19999" {
		t.Fatalf("client base = %q", c.base)
	}
	if c.token != "" {
		t.Fatalf("client token = %q, want empty", c.token)
	}
}

func TestAPIClientNoServerNoConfig(t *testing.T) {
	t.Setenv("FLOWSTALLION_SERVER", "")
	t.Setenv("FLOWSTALLION_TOKEN", "")
	t.Setenv("HOME", t.TempDir())

	if _, err := apiClient(); err == nil {
		t.Fatal("apiClient() succeeded with no server configured; want error")
	}
}

// TestAPIClientServerEnvWinsOverConfig pins the resolution precedence (N7):
// when FLOWSTALLION_SERVER is set it wins over the saved config's server, and
// the saved config's token is NOT pulled in to go along with it — an env
// server override is an open-mode (no-auth) signal, so the client must not
// silently attach a Bearer token the operator never asked for.
func TestAPIClientServerEnvWinsOverConfig(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if err := saveConfig(config{Server: "http://saved-server:8080", User: "alice", Token: "saved-token"}); err != nil {
		t.Fatalf("saveConfig: %v", err)
	}
	t.Setenv("FLOWSTALLION_SERVER", "http://127.0.0.1:19999")
	t.Setenv("FLOWSTALLION_TOKEN", "")

	c, err := apiClient()
	if err != nil {
		t.Fatalf("apiClient() error = %v", err)
	}
	if c.base != "http://127.0.0.1:19999" {
		t.Fatalf("client base = %q, want env server to win over saved config", c.base)
	}
	if c.token != "" {
		t.Fatalf("client token = %q, want empty (saved token must not leak when env server wins)", c.token)
	}
}
