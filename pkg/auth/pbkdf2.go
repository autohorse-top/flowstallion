// Package auth provides FlowStallion's local authentication: PBKDF2-HMAC-SHA256
// password hashing (stdlib only, no external dependencies) and opaque
// session-token authentication with viewer/operator/admin roles.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// Password hashing parameters. Iteration count follows OWASP guidance for
// PBKDF2-HMAC-SHA256 (>= 100k for server-side).
const (
	hashPrefix = "pbkdf2-sha256"
	iterCount  = 100_000
	saltLen    = 16
	keyLen     = 32
)

// PBKDF2SHA256 derives keyLen bytes of key material using PBKDF2 with
// HMAC-SHA256 (RFC 2898 §5.2, RFC 7914). It is the raw primitive; callers
// normally use HashPassword/VerifyPassword.
func PBKDF2SHA256(password, salt []byte, iter, keyLen int) []byte {
	const blockLen = sha256.Size
	blocks := (keyLen + blockLen - 1) / blockLen
	var out []byte
	for block := 1; block <= blocks; block++ {
		u := pbkdf2Block(password, salt, iter, block)
		out = append(out, u...)
		if keyLen <= block*blockLen {
			break
		}
	}
	return out[:keyLen]
}

// pbkdf2Block computes F(P, S, c, i) for a single block index i (1-based):
// the XOR accumulation of the iterated HMAC chain (RFC 2898 §5.2).
func pbkdf2Block(password, salt []byte, iter, block int) []byte {
	buf := make([]byte, len(salt)+4)
	copy(buf, salt)
	binary.BigEndian.PutUint32(buf[len(salt):], uint32(block))
	u := hmacSHA256(password, buf)
	dk := make([]byte, len(u))
	copy(dk, u)
	for i := 2; i <= iter; i++ {
		u = hmacSHA256(password, u)
		for j := range u {
			dk[j] ^= u[j]
		}
	}
	return dk
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// HashPassword derives a salted PBKDF2-HMAC-SHA256 hash of password and
// returns it in the wire format "pbkdf2-sha256$<iter>$<saltB64>$<hashB64>".
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: read salt: %w", err)
	}
	dk := PBKDF2SHA256([]byte(password), salt, iterCount, keyLen)
	return fmt.Sprintf("%s$%d$%s$%s", hashPrefix, iterCount,
		base64.StdEncoding.EncodeToString(salt), base64.StdEncoding.EncodeToString(dk)), nil
}

// VerifyPassword reports whether password matches a stored hash produced by
// HashPassword. Malformed input always returns false (never panics) and the
// comparison is constant-time in the derived key.
func VerifyPassword(storedHash, password string) bool {
	parts := strings.Split(storedHash, "$")
	if len(parts) != 4 || parts[0] != hashPrefix {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1 || iter > 10_000_000 {
		return false
	}
	salt, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil || len(salt) == 0 {
		return false
	}
	want, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil || len(want) == 0 {
		return false
	}
	got := PBKDF2SHA256([]byte(password), salt, iter, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1
}
