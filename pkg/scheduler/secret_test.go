package scheduler

import (
	"errors"
	"strings"
	"testing"

	"github.com/flowstallion/flowstallion/pkg/pipeline"
	"github.com/flowstallion/flowstallion/pkg/secret"
)

const secretTestKey = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

func newSecretTestScheduler(t *testing.T) *testScheduler {
	t.Helper()
	ts := newTestScheduler(t)
	key, err := secret.KeyFromString(secretTestKey)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	vault, err := secret.New(key)
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	ts.s.SecretVault = vault
	return ts
}

func mustStoreSecret(t *testing.T, ts *testScheduler, name, value string) {
	t.Helper()
	blob, err := ts.s.SecretVault.Seal([]byte(value))
	if err != nil {
		t.Fatalf("seal %s: %v", name, err)
	}
	if err := ts.st.UpsertSecret(name, blob); err != nil {
		t.Fatalf("store %s: %v", name, err)
	}
}

const secretPipeYAML = `
version: 1
pipeline:
  name: secret-pipe
  secrets: [DB_PASSWORD]
  env:
    GREETING: hello
  steps:
    - id: build
      image: alpine
      env:
        DB_PASSWORD: "${DB_PASSWORD}"
        PARTIAL: "x${DB_PASSWORD}y"
      commands:
        - echo build
`

// TestTriggerSecretsMissing: a declared secret that is not in the store must
// fail the trigger before any run row is created.
func TestTriggerSecretsMissing(t *testing.T) {
	ts := newSecretTestScheduler(t)
	ts.upsert("secret-pipe", secretPipeYAML)
	_, err := ts.s.Trigger("secret-pipe", "manual", "")
	if !errors.Is(err, ErrSecrets) {
		t.Fatalf("Trigger() err = %v, want ErrSecrets", err)
	}
	if !strings.Contains(err.Error(), `declared secret "DB_PASSWORD" not found in secret store`) {
		t.Fatalf("err = %q, want missing-secret message", err)
	}
	// no run row was created
	if runs, _ := ts.st.ListRuns(0, 0); len(runs) != 0 {
		t.Fatalf("runs created on failed secret check: %d", len(runs))
	}
}

// TestTriggerSecretsUndeclared: ${NAME} in an env value without a matching
// pipeline.secrets entry must fail the trigger.
func TestTriggerSecretsUndeclared(t *testing.T) {
	ts := newSecretTestScheduler(t)
	const yaml = `
version: 1
pipeline:
  name: undecl
  secrets: [DB_PASSWORD]
  steps:
    - id: build
      image: alpine
      env:
        OTHER: "${NOT_DECLARED}"
      commands:
        - echo x
`
	ts.upsert("undecl", yaml)
	_, err := ts.s.Trigger("undecl", "manual", "")
	if !errors.Is(err, ErrSecrets) {
		t.Fatalf("Trigger() err = %v, want ErrSecrets", err)
	}
	if !strings.Contains(err.Error(), "${NOT_DECLARED}") {
		t.Fatalf("err = %q, want undeclared-ref message", err)
	}
}

// TestTriggerSecretsNoVault: a scheduler without an encryption key must
// reject pipelines that declare secrets.
func TestTriggerSecretsNoVault(t *testing.T) {
	ts := newTestScheduler(t) // no vault
	ts.upsert("secret-pipe", secretPipeYAML)
	_, err := ts.s.Trigger("secret-pipe", "manual", "")
	if !errors.Is(err, ErrSecrets) {
		t.Fatalf("Trigger() err = %v, want ErrSecrets", err)
	}
	if !strings.Contains(err.Error(), "FLOWSTALLION_SECRET_KEY") {
		t.Fatalf("err = %q, want no-key message", err)
	}
}

// TestRunSecretInjection: a successful run sees the decrypted secret value in
// step env (exact ${NAME} only; partial references are left untouched).
func TestRunSecretInjection(t *testing.T) {
	ts := newSecretTestScheduler(t)
	mustStoreSecret(t, ts, "DB_PASSWORD", "s3cr3t-value")
	ts.upsert("secret-pipe", secretPipeYAML)

	runID, err := ts.s.Trigger("secret-pipe", "manual", "")
	if err != nil {
		t.Fatalf("Trigger(): %v", err)
	}
	run := ts.waitForTerminal(runID)
	if run.Status != "success" {
		t.Fatalf("run status = %q, want success", run.Status)
	}
	env := ts.fx.envFor("build")
	if env == nil {
		t.Fatal("step build never executed")
	}
	if env["DB_PASSWORD"] != "s3cr3t-value" {
		t.Fatalf("env[DB_PASSWORD] = %q, want decrypted value", env["DB_PASSWORD"])
	}
	if env["GREETING"] != "hello" {
		t.Fatalf("env[GREETING] = %q, want plain pipeline env", env["GREETING"])
	}
	if env["PARTIAL"] != "x${DB_PASSWORD}y" {
		t.Fatalf("env[PARTIAL] = %q, want untouched (exact-match only)", env["PARTIAL"])
	}
}

// TestRunNoSecretsRegression: pipelines without secrets behave as before even
// when a vault is configured.
func TestRunNoSecretsRegression(t *testing.T) {
	ts := newSecretTestScheduler(t)
	ts.upsert("linear", linearYAML)
	runID, err := ts.s.Trigger("linear", "manual", "")
	if err != nil {
		t.Fatalf("Trigger(): %v", err)
	}
	if run := ts.waitForTerminal(runID); run.Status != "success" {
		t.Fatalf("run status = %q, want success", run.Status)
	}
}

// TestTriggerSecretsUndeclaredNoDecls: a ${X} reference with an empty (absent)
// secrets declaration must fail, not silently pass (review major-2).
func TestTriggerSecretsUndeclaredNoDecls(t *testing.T) {
	ts := newSecretTestScheduler(t)
	const yaml = `
version: 1
pipeline:
  name: no-decl
  steps:
    - id: a
      image: alpine
      env:
        A: "${MISSING}"
      commands:
        - echo x
`
	ts.upsert("no-decl", yaml)
	_, err := ts.s.Trigger("no-decl", "manual", "")
	if !errors.Is(err, ErrSecrets) {
		t.Fatalf("Trigger() err = %v, want ErrSecrets", err)
	}
	if !strings.Contains(err.Error(), "${MISSING}") {
		t.Fatalf("err = %q, want undeclared-ref message", err)
	}
}

// TestTriggerSecretsPipelineLevelUndeclared: an undeclared ${X} in the
// pipeline-level env (merged into step env) must also fail (review minor-3).
func TestTriggerSecretsPipelineLevelUndeclared(t *testing.T) {
	ts := newSecretTestScheduler(t)
	mustStoreSecret(t, ts, "DB_PASSWORD", "x")
	const yaml = `
version: 1
pipeline:
  name: pipe-level
  secrets: [DB_PASSWORD]
  env:
    OTHER: "${NOT_DECLARED}"
  steps:
    - id: a
      image: alpine
      commands:
        - echo x
`
	ts.upsert("pipe-level", yaml)
	_, err := ts.s.Trigger("pipe-level", "manual", "")
	if !errors.Is(err, ErrSecrets) {
		t.Fatalf("Trigger() err = %v, want ErrSecrets", err)
	}
	if !strings.Contains(err.Error(), "${NOT_DECLARED}") {
		t.Fatalf("err = %q, want undeclared-ref message", err)
	}
}

// TestInjectSecretsRuntimeFailure: if the secret disappears between Trigger
// and execution, injectSecrets must fail (step fails, does not hang) — the
// only runtime path where injection can fail (review minor-3).
func TestInjectSecretsRuntimeFailure(t *testing.T) {
	ts := newSecretTestScheduler(t)
	mustStoreSecret(t, ts, "DB_PASSWORD", "s3cr3t-value")
	pl, err := pipeline.ParseYAML([]byte(secretPipeYAML))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	spec := pl.Pipeline
	env := map[string]string{"DB_PASSWORD": "${DB_PASSWORD}"}
	if err := ts.s.injectSecrets(spec, env); err != nil {
		t.Fatalf("inject with intact secret: %v", err)
	}
	if env["DB_PASSWORD"] != "s3cr3t-value" {
		t.Fatalf("env = %q, want decrypted", env["DB_PASSWORD"])
	}
	if err := ts.st.DeleteSecret("DB_PASSWORD"); err != nil {
		t.Fatalf("delete secret: %v", err)
	}
	env2 := map[string]string{"DB_PASSWORD": "${DB_PASSWORD}"}
	if err := ts.s.injectSecrets(spec, env2); err == nil {
		t.Fatal("injectSecrets after secret deleted: want error, got nil")
	}
}
