package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
)

func openSecretStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "secret.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// TestSecretCRUD covers upsert/get/exists/delete/list lifecycle.
func TestSecretCRUD(t *testing.T) {
	st := openSecretStore(t)

	if ok, err := st.SecretExists("tok"); err != nil || ok {
		t.Fatalf("pre-check exists: ok=%v err=%v", ok, err)
	}
	if err := st.UpsertSecret("tok", []byte("enc-1")); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	blob, err := st.GetSecret("tok")
	if err != nil || string(blob) != "enc-1" {
		t.Fatalf("get: blob=%q err=%v", blob, err)
	}
	ok, err := st.SecretExists("tok")
	if err != nil || !ok {
		t.Fatalf("exists after upsert: ok=%v err=%v", ok, err)
	}

	// upsert updates in place
	if err := st.UpsertSecret("tok", []byte("enc-2")); err != nil {
		t.Fatalf("upsert update: %v", err)
	}
	blob, _ = st.GetSecret("tok")
	if string(blob) != "enc-2" {
		t.Fatalf("updated blob = %q, want enc-2", blob)
	}

	if err := st.UpsertSecret("other", []byte("x")); err != nil {
		t.Fatal(err)
	}
	meta, err := st.ListSecrets()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(meta) != 2 {
		t.Fatalf("list len = %d, want 2", len(meta))
	}
	for _, m := range meta {
		if m.CreatedAt == "" || m.UpdatedAt == "" {
			t.Fatalf("missing timestamps: %+v", m)
		}
	}

	if err := st.DeleteSecret("other"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := st.DeleteSecret("other"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("delete missing: err=%v, want ErrNoRows", err)
	}
	meta, _ = st.ListSecrets()
	if len(meta) != 1 || meta[0].Name != "tok" {
		t.Fatalf("list after delete = %+v", meta)
	}
}

// TestSecretEmptyName guards against empty key names.
func TestSecretEmptyName(t *testing.T) {
	st := openSecretStore(t)
	if err := st.UpsertSecret("", []byte("x")); err == nil {
		t.Fatal("upsert empty name: want error")
	}
}
