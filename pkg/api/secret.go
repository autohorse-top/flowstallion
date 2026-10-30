package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/flowstallion/flowstallion/pkg/pipeline"
)

// MaxSecretValueBytes bounds a single secret value (design: ≤ 8 KiB).
const MaxSecretValueBytes = 8192

// secretJSON is the wire shape of a stored secret: name + timestamps only,
// the (encrypted) value is never returned by the API.
type secretJSON struct {
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// handleListSecrets — GET /api/secrets (admin).
func (s *Server) handleListSecrets(w http.ResponseWriter, r *http.Request) {
	meta, err := s.Store.ListSecrets()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]secretJSON, 0, len(meta))
	for _, m := range meta {
		out = append(out, secretJSON{Name: m.Name, CreatedAt: m.CreatedAt, UpdatedAt: m.UpdatedAt})
	}
	writeJSON(w, http.StatusOK, map[string]any{"secrets": out})
}

// handleUpsertSecret — POST /api/secrets (admin), body {name, value}.
func (s *Server) handleUpsertSecret(w http.ResponseWriter, r *http.Request) {
	if s.Vault == nil {
		s.record(r, AuditSecretUpsert, "secret:unknown", http.StatusServiceUnavailable, "vault disabled")
		writeErr(w, http.StatusServiceUnavailable, "secret store disabled: set FLOWSTALLION_SECRET_KEY on the scheduler")
		return
	}
	var body struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	// Bound the request body: value is capped at 8 KiB, so 64 KiB of JSON
	// overhead is far more than enough. Unbounded bodies are a memory-DoS
	// vector (every other POST endpoint in this package is bounded).
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		s.record(r, AuditSecretUpsert, "secret:unknown", http.StatusBadRequest, "invalid body")
		writeErr(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	if !pipeline.ValidSecretName(body.Name) {
		s.record(r, AuditSecretUpsert, "secret:unknown", http.StatusBadRequest, "invalid name")
		writeErr(w, http.StatusBadRequest, "invalid secret name: must match [a-zA-Z0-9_.-]+ and be at most 128 chars")
		return
	}
	if len([]byte(body.Value)) > MaxSecretValueBytes {
		// task ③: detail names the secret only — never the value.
		s.record(r, AuditSecretUpsert, "secret:"+body.Name, http.StatusBadRequest, "value too large")
		writeErr(w, http.StatusBadRequest, "secret value too large (max 8192 bytes)")
		return
	}
	blob, err := s.Vault.Seal([]byte(body.Value))
	if err != nil {
		s.record(r, AuditSecretUpsert, "secret:"+body.Name, http.StatusInternalServerError, "seal: "+err.Error())
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.Store.UpsertSecret(body.Name, blob); err != nil {
		s.record(r, AuditSecretUpsert, "secret:"+body.Name, http.StatusInternalServerError, "upsert: "+err.Error())
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.record(r, AuditSecretUpsert, "secret:"+body.Name, http.StatusOK, "name="+body.Name)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "name": body.Name})
}

// handleDeleteSecret — DELETE /api/secrets/{name} (admin).
// Note: unlike POST, DELETE does not require a configured vault — it only
// removes the metadata row (there is nothing to decrypt), so a leftover row
// from a previous key can still be cleaned up after the key is unset.
func (s *Server) handleDeleteSecret(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	err := s.Store.DeleteSecret(name)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.record(r, AuditSecretDelete, "secret:"+name, http.StatusNotFound, "secret not found")
			writeErr(w, http.StatusNotFound, "secret not found: "+name)
			return
		}
		s.record(r, AuditSecretDelete, "secret:"+name, http.StatusInternalServerError, err.Error())
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.record(r, AuditSecretDelete, "secret:"+name, http.StatusNoContent, "name="+name)
	w.WriteHeader(http.StatusNoContent)
}
