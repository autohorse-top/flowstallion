package store

import (
	"database/sql"
	"fmt"
)

// User is a platform account (auth).
type User struct {
	ID           int64
	Username     string
	PasswordHash string
	Role         string
	CreatedAt    string
}

// CreateUser inserts a new user row.
func (s *Store) CreateUser(username, hash, role string) (int64, error) {
	if username == "" {
		return 0, fmt.Errorf("store: username is empty")
	}
	res, err := s.db.Exec(
		`INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)`,
		username, hash, role, now(),
	)
	if err != nil {
		return 0, fmt.Errorf("store: create user %q: %w", username, err)
	}
	return res.LastInsertId()
}

// GetUserByUsername returns the user with the given username.
func (s *Store) GetUserByUsername(name string) (User, error) {
	var u User
	err := s.db.QueryRow(
		`SELECT id, username, password_hash, role, created_at FROM users WHERE username = ?`, name,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.CreatedAt)
	if err != nil {
		return u, err
	}
	return u, nil
}

// ListUsers returns all users ordered by username.
func (s *Store) ListUsers() ([]User, error) {
	rows, err := s.db.Query(`SELECT id, username, password_hash, role, created_at FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// DeleteUser removes a user and their sessions.
func (s *Store) DeleteUser(username string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE user_id = (SELECT id FROM users WHERE username = ?)`, username)
	if err != nil {
		return fmt.Errorf("store: delete sessions for user %q: %w", username, err)
	}
	res, err := s.db.Exec(`DELETE FROM users WHERE username = ?`, username)
	if err != nil {
		return fmt.Errorf("store: delete user %q: %w", username, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// CountUsersWithRole returns the number of users with the given role.
func (s *Store) CountUsersWithRole(role string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE role = ?`, role).Scan(&n)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// CreateSession inserts a new session token.
func (s *Store) CreateSession(token string, userID int64, created, expires string) error {
	_, err := s.db.Exec(
		`INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		token, userID, created, expires,
	)
	if err != nil {
		return fmt.Errorf("store: create session: %w", err)
	}
	return nil
}

// GetSession returns the user for a valid (non-expired) session token.
// Returns sql.ErrNoRows if the token is unknown or expired.
func (s *Store) GetSession(token string) (User, error) {
	var u User
	err := s.db.QueryRow(
		`SELECT u.id, u.username, u.password_hash, u.role, u.created_at
		 FROM sessions s JOIN users u ON u.id = s.user_id
		 WHERE s.token = ? AND s.expires_at > ?`,
		token, now(),
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.CreatedAt)
	if err != nil {
		return u, err
	}
	return u, nil
}

// DeleteSession removes a session by token.
func (s *Store) DeleteSession(token string) error {
	res, err := s.db.Exec(`DELETE FROM sessions WHERE token = ?`, token)
	if err != nil {
		return fmt.Errorf("store: delete session: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// PurgeExpiredSessions removes sessions whose expiry is before the given time.
func (s *Store) PurgeExpiredSessions(nowStr string) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at <= ?`, nowStr)
	if err != nil {
		return 0, fmt.Errorf("store: purge expired sessions: %w", err)
	}
	return res.RowsAffected()
}
