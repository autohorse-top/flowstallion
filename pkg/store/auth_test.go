package store

import (
	"database/sql"
	"errors"
	"testing"
	"time"
)

func TestCreateUser(t *testing.T) {
	s := openTemp(t)

	// Empty username rejected.
	if _, err := s.CreateUser("", "hash", "admin"); err == nil {
		t.Fatal("CreateUser empty username: want error, got nil")
	}

	id, err := s.CreateUser("alice", "pbkdf2-sha256$100000$xx$yy", "operator")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if id <= 0 {
		t.Fatalf("CreateUser id = %d, want > 0", id)
	}

	// Duplicate username must fail (UNIQUE constraint).
	if _, err := s.CreateUser("alice", "hash2", "admin"); err == nil {
		t.Fatal("CreateUser duplicate: want error, got nil")
	}

	// Invalid role is rejected by CHECK constraint.
	if _, err := s.CreateUser("bob", "hash", "superuser"); err == nil {
		t.Fatal("CreateUser invalid role: want error, got nil")
	}
}

func TestGetUserByUsername(t *testing.T) {
	s := openTemp(t)
	if _, err := s.CreateUser("carol", "hash", "viewer"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	u, err := s.GetUserByUsername("carol")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if u.Username != "carol" || u.Role != "viewer" || u.PasswordHash != "hash" {
		t.Fatalf("user = %+v", u)
	}
	if u.ID <= 0 || u.CreatedAt == "" {
		t.Fatalf("user missing ID or CreatedAt: %+v", u)
	}

	// Non-existent user returns sql.ErrNoRows.
	if _, err := s.GetUserByUsername("ghost"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetUserByUsername ghost: err = %v, want ErrNoRows", err)
	}
}

func TestListUsers(t *testing.T) {
	s := openTemp(t)
	if _, err := s.CreateUser("zoe", "h1", "viewer"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser("alice", "h2", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser("bob", "h3", "operator"); err != nil {
		t.Fatal(err)
	}

	users, err := s.ListUsers()
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 3 {
		t.Fatalf("ListUsers = %d, want 3", len(users))
	}
	// Ordered by username.
	if users[0].Username != "alice" || users[1].Username != "bob" || users[2].Username != "zoe" {
		t.Fatalf("order = %v, want [alice bob zoe]", []string{users[0].Username, users[1].Username, users[2].Username})
	}
}

func TestDeleteUser(t *testing.T) {
	s := openTemp(t)
	id, _ := s.CreateUser("dave", "hash", "viewer")
	// Create a session for the user.
	if err := s.CreateSession("tok-1", id, time.Now().UTC().Format(time.RFC3339), time.Now().Add(24*time.Hour).UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	if err := s.DeleteUser("dave"); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	// User gone.
	if _, err := s.GetUserByUsername("dave"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("user still exists: %v", err)
	}
	// Session gone too.
	if _, err := s.GetSession("tok-1"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("session still exists: %v", err)
	}

	// Deleting non-existent user returns ErrNoRows.
	if err := s.DeleteUser("dave"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("delete nonexistent: err = %v, want ErrNoRows", err)
	}
}

func TestCountUsersWithRole(t *testing.T) {
	s := openTemp(t)
	s.CreateUser("a1", "h", "admin")
	s.CreateUser("a2", "h", "admin")
	s.CreateUser("o1", "h", "operator")
	s.CreateUser("v1", "h", "viewer")

	n, err := s.CountUsersWithRole("admin")
	if err != nil {
		t.Fatalf("CountUsersWithRole: %v", err)
	}
	if n != 2 {
		t.Fatalf("admin count = %d, want 2", n)
	}
	n, _ = s.CountUsersWithRole("viewer")
	if n != 1 {
		t.Fatalf("viewer count = %d, want 1", n)
	}
}

func TestSessionLifecycle(t *testing.T) {
	s := openTemp(t)
	uid, _ := s.CreateUser("eve", "hash", "operator")

	now := time.Now().UTC()
	exp := now.Add(24 * time.Hour)
	err := s.CreateSession("valid-tok", uid, now.Format(time.RFC3339), exp.Format(time.RFC3339))
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	u, err := s.GetSession("valid-tok")
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if u.Username != "eve" || u.Role != "operator" {
		t.Fatalf("session user = %+v", u)
	}

	// Expired session: create one with expiry in the past.
	past := now.Add(-1 * time.Hour)
	s.CreateSession("expired-tok", uid, past.Add(-24*time.Hour).Format(time.RFC3339), past.Format(time.RFC3339))
	if _, err := s.GetSession("expired-tok"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetSession expired: err = %v, want ErrNoRows", err)
	}

	// Unknown token.
	if _, err := s.GetSession("nope"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetSession unknown: err = %v, want ErrNoRows", err)
	}

	// Delete valid session.
	if err := s.DeleteSession("valid-tok"); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	if _, err := s.GetSession("valid-tok"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("session still exists after delete: %v", err)
	}
	// Double delete → ErrNoRows.
	if err := s.DeleteSession("valid-tok"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("double delete: err = %v, want ErrNoRows", err)
	}
}

func TestPurgeExpiredSessions(t *testing.T) {
	s := openTemp(t)
	uid, _ := s.CreateUser("purge", "h", "viewer")
	now := time.Now().UTC()

	// One expired, one valid.
	s.CreateSession("exp", uid, now.Add(-48*time.Hour).Format(time.RFC3339), now.Add(-24*time.Hour).Format(time.RFC3339))
	s.CreateSession("ok", uid, now.Add(-1*time.Hour).Format(time.RFC3339), now.Add(24*time.Hour).Format(time.RFC3339))

	n, err := s.PurgeExpiredSessions(now.Format(time.RFC3339))
	if err != nil {
		t.Fatalf("PurgeExpiredSessions: %v", err)
	}
	if n != 1 {
		t.Fatalf("purged = %d, want 1", n)
	}
	if _, err := s.GetSession("exp"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("expired session not purged")
	}
	if _, err := s.GetSession("ok"); err != nil {
		t.Fatalf("valid session purged: %v", err)
	}
}
