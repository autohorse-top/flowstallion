package store

import (
	"database/sql"
	"fmt"
)

// SecretMeta describes a stored secret without its (encrypted) value.
type SecretMeta struct {
	Name      string
	CreatedAt string
	UpdatedAt string
}

// UpsertSecret inserts or replaces the encrypted value for name.
func (s *Store) UpsertSecret(name string, data []byte) error {
	if name == "" {
		return fmt.Errorf("store: secret name is empty")
	}
	_, err := s.db.Exec(
		`INSERT INTO secrets (name, data, created_at, updated_at) VALUES (?, ?, ?, ?)
		 ON CONFLICT (name) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at`,
		name, data, now(), now(),
	)
	if err != nil {
		return fmt.Errorf("store: upsert secret %q: %w", name, err)
	}
	return nil
}

// GetSecret returns the encrypted blob for name (sql.ErrNoRows if missing).
func (s *Store) GetSecret(name string) ([]byte, error) {
	var data []byte
	err := s.db.QueryRow(`SELECT data FROM secrets WHERE name = ?`, name).Scan(&data)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// SecretExists reports whether name has a stored value.
func (s *Store) SecretExists(name string) (bool, error) {
	var one int
	err := s.db.QueryRow(`SELECT 1 FROM secrets WHERE name = ?`, name).Scan(&one)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// DeleteSecret removes a secret (sql.ErrNoRows if missing).
func (s *Store) DeleteSecret(name string) error {
	res, err := s.db.Exec(`DELETE FROM secrets WHERE name = ?`, name)
	if err != nil {
		return fmt.Errorf("store: delete secret %q: %w", name, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ListSecrets returns all secret names with timestamps (never the values).
func (s *Store) ListSecrets() ([]SecretMeta, error) {
	rows, err := s.db.Query(`SELECT name, created_at, updated_at FROM secrets ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SecretMeta
	for rows.Next() {
		var m SecretMeta
		if err := rows.Scan(&m.Name, &m.CreatedAt, &m.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
