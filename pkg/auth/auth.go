package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/flowstallion/flowstallion/pkg/store"
)

// Role is a platform access level. Privilege order: viewer < operator < admin.
type Role string

// Role constants.
const (
	RoleViewer   Role = "viewer"
	RoleOperator Role = "operator"
	RoleAdmin    Role = "admin"
)

// Sentinel errors.
var (
	ErrAuthDisabled       = errors.New("auth: authentication is disabled")
	ErrInvalidCredentials = errors.New("auth: invalid username or password")
	ErrInvalidToken       = errors.New("auth: invalid or expired session token")
	ErrInvalidRole        = errors.New("auth: invalid role")
)

// Level returns the privilege rank of a role (higher is more privileged).
// Unknown roles rank 0.
func (r Role) Level() int {
	switch r {
	case RoleViewer:
		return 1
	case RoleOperator:
		return 2
	case RoleAdmin:
		return 3
	default:
		return 0
	}
}

// Valid reports whether r is one of the known roles.
func (r Role) Valid() bool { return r.Level() > 0 }

// AtLeast reports whether r has at least the privilege of other.
func (r Role) AtLeast(other Role) bool { return r.Level() >= other.Level() }

// ParseRole converts a string to Role, rejecting unknown values.
func ParseRole(s string) (Role, error) {
	r := Role(s)
	if !r.Valid() {
		return "", fmt.Errorf("%w: %q (want viewer, operator or admin)", ErrInvalidRole, s)
	}
	return r, nil
}

// newToken returns a cryptographically random 32-byte token, hex-encoded
// (64 chars).
func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth: generate token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// bearerToken extracts the token from an "Authorization: Bearer <t>" header.
// Returns "" when the header is absent or malformed.
func bearerToken(r *http.Request) string {
	const p = "Bearer "
	v := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(v, p) {
		return ""
	}
	return strings.TrimSpace(v[len(p):])
}

// Authenticator ties session validation to the store. When disabled (the
// default), every request is treated as the synthetic admin "system" user,
// preserving pre-P6 open behaviour exactly.
type Authenticator struct {
	st         *store.Store
	enabled    bool
	ttl        time.Duration
	agentToken string
}

// New builds an Authenticator. ttl <= 0 falls back to 168h (7 days).
func New(st *store.Store, enabled bool, ttl time.Duration, agentToken string) *Authenticator {
	if ttl <= 0 {
		ttl = 168 * time.Hour
	}
	return &Authenticator{st: st, enabled: enabled, ttl: ttl, agentToken: agentToken}
}

// Enabled reports whether authentication is enforced.
func (a *Authenticator) Enabled() bool { return a.enabled }

// AgentTokenSet reports whether a machine X-Agent-Token was configured.
// Callers (the scheduler) use this to log a startup warning when auth is on
// but no agent token was set, per the P6 design ("env unset = open + warning").
func (a *Authenticator) AgentTokenSet() bool { return a.agentToken != "" }

// SessionTTL returns the configured session lifetime.
func (a *Authenticator) SessionTTL() time.Duration { return a.ttl }

// syntheticUser represents the caller when authentication is disabled.
func syntheticUser() store.User {
	return store.User{ID: 0, Username: "system", Role: string(RoleAdmin)}
}

// Login validates credentials and opens a new session, returning the token
// and the user (PasswordHash blanked). Fails with ErrAuthDisabled when auth
// is off, ErrInvalidCredentials on bad username/password.
func (a *Authenticator) Login(username, password string) (string, store.User, error) {
	if !a.enabled {
		return "", store.User{}, ErrAuthDisabled
	}
	u, err := a.st.GetUserByUsername(username)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", store.User{}, ErrInvalidCredentials
		}
		return "", store.User{}, err
	}
	if !VerifyPassword(u.PasswordHash, password) {
		return "", store.User{}, ErrInvalidCredentials
	}
	token, err := newToken()
	if err != nil {
		return "", store.User{}, err
	}
	now := time.Now().UTC()
	if err := a.st.CreateSession(token, u.ID,
		now.Format(time.RFC3339), now.Add(a.ttl).Format(time.RFC3339)); err != nil {
		return "", store.User{}, err
	}
	u.PasswordHash = ""
	return token, u, nil
}

// Validate resolves a session token to its user. Unknown or expired tokens
// yield ErrInvalidToken.
func (a *Authenticator) Validate(token string) (store.User, error) {
	if token == "" {
		return store.User{}, ErrInvalidToken
	}
	u, err := a.st.GetSession(token)
	if err != nil {
		return store.User{}, ErrInvalidToken
	}
	return u, nil
}

// Logout invalidates a session token. A token that is unknown or already
// expired yields ErrInvalidToken.
func (a *Authenticator) Logout(token string) error {
	if token == "" {
		return ErrInvalidToken
	}
	if err := a.st.DeleteSession(token); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrInvalidToken
		}
		return err
	}
	return nil
}

// LogoutRequest resolves the Bearer token from r and invalidates the session.
func (a *Authenticator) LogoutRequest(r *http.Request) error {
	return a.Logout(bearerToken(r))
}

// UserFromRequest resolves the caller from the Authorization: Bearer header.
// When auth is disabled it returns the synthetic admin user so that all
// request paths keep their pre-P6 behaviour. ok=false means unauthenticated.
func (a *Authenticator) UserFromRequest(r *http.Request) (store.User, bool) {
	if !a.enabled {
		return syntheticUser(), true
	}
	u, err := a.Validate(bearerToken(r))
	if err != nil {
		return store.User{}, false
	}
	return u, true
}

// CheckAgentToken reports whether the request's X-Agent-Token header matches
// the configured machine token (constant-time compare). An unset agent token
// always returns false; callers decide what "unset" means for their gate.
func (a *Authenticator) CheckAgentToken(r *http.Request) bool {
	if a.agentToken == "" {
		return false
	}
	got := r.Header.Get("X-Agent-Token")
	return subtle.ConstantTimeCompare([]byte(got), []byte(a.agentToken)) == 1
}
