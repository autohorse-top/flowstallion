package auth

import (
	"testing"
	"time"
)

// PBKDF2-HMAC-SHA256 test vectors: the first two are the official vectors
// from RFC 7914 §11 (both use dkLen=64, exercising the multi-block path
// since 64 > sha256.Size); the rest are cross-verified against CPython's
// hashlib.pbkdf2_hmac and an independent HMAC chain (2026-10-26).
func TestPBKDF2SHA256Vectors(t *testing.T) {
	tests := []struct {
		password string
		salt     string
		iter     int
		keyLen   int
		want     string // hex
	}{
		// RFC 7914 §11, vector 1.
		{"passwd", "salt", 1, 64,
			"55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc" +
				"49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"},
		// RFC 7914 §11, vector 2.
		{"Password", "NaCl", 80000, 64,
			"4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56" +
				"a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"},
		// Cross-verified vs CPython hashlib.pbkdf2_hmac (16-byte truncation).
		{"passwd", "salt", 2, 16, "2d412f896e76685e30df569f0a740634"},
		{"passwd", "salt", 4096, 16, "21943fd5b7a10905c38fad60157ff498"},
	}
	for _, tt := range tests {
		got := PBKDF2SHA256([]byte(tt.password), []byte(tt.salt), tt.iter, tt.keyLen)
		if gotHex := func() string {
			const hexDigits = "0123456789abcdef"
			out := make([]byte, 0, tt.keyLen*2)
			for _, b := range got {
				out = append(out, hexDigits[b>>4], hexDigits[b&0x0f])
			}
			return string(out)
		}(); gotHex != tt.want {
			t.Errorf("PBKDF2SHA256(%q, %q, c=%d, %d bytes) = %s, want %s",
				tt.password, tt.salt, tt.iter, tt.keyLen, gotHex, tt.want)
		}
	}
}

func TestHashVerifyRoundtrip(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !VerifyPassword(hash, "correct horse battery staple") {
		t.Error("VerifyPassword: valid password rejected")
	}
	if VerifyPassword(hash, "wrong password") {
		t.Error("VerifyPassword: wrong password accepted")
	}
	// Two hashes of the same password must differ (random salt).
	hash2, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword (2nd): %v", err)
	}
	if hash == hash2 {
		t.Error("two hashes of the same password are identical (missing salt?)")
	}
}

func TestVerifyPasswordRejectsMalformed(t *testing.T) {
	for _, stored := range []string{
		"",
		"argon2$1$2$3",
		"pbkdf2-sha256",
		"pbkdf2-sha256$1$!!notbase64!!$aGVsbG8=",
		"pbkdf2-sha256$0$YWJjZA==$YWJjZA==",
		"pbkdf2-sha256$10000000000$YWJjZA==$YWJjZA==", // iter > 10M cap
		"pbkdf2-sha256$100$YWJjZA==$",                 // empty hash
		"pbkdf2-sha256$100$YWJjZA==",                  // 3 parts
		"pbkdf2-sha256$100$YWJjZA==$YWJjZA==$extra",   // 5 parts
	} {
		if VerifyPassword(stored, "anything") {
			t.Errorf("VerifyPassword(%q) = true, want false", stored)
		}
	}
}

func TestRoles(t *testing.T) {
	if RoleViewer.Level() != 1 || RoleOperator.Level() != 2 || RoleAdmin.Level() != 3 {
		t.Error("role levels out of order")
	}
	if r := Role("superuser"); r.Level() != 0 || r.Valid() {
		t.Error("unknown role must have level 0 and be invalid")
	}
	tests := []struct {
		role Role
		want bool
	}{
		{RoleAdmin, true},
		{RoleOperator, true},
		{RoleViewer, false},
		{Role("nope"), false},
	}
	for _, tt := range tests {
		if got := tt.role.AtLeast(RoleOperator); got != tt.want {
			t.Errorf("(%q).AtLeast(operator) = %v, want %v", tt.role, got, tt.want)
		}
	}
}

func TestParseRole(t *testing.T) {
	for _, s := range []string{"viewer", "operator", "admin"} {
		r, err := ParseRole(s)
		if err != nil || string(r) != s {
			t.Errorf("ParseRole(%q) = %v, %v", s, r, err)
		}
	}
	for _, s := range []string{"", "Viewer", "ADMIN", "owner"} {
		if _, err := ParseRole(s); err == nil {
			t.Errorf("ParseRole(%q) accepted, want error", s)
		}
	}
}

func TestNewToken(t *testing.T) {
	a, b := "", ""
	var err error
	a, err = newToken()
	if err != nil || len(a) != 64 {
		t.Fatalf("newToken = %q, %v; want 64 hex chars", a, err)
	}
	b, err = newToken()
	if err != nil || len(b) != 64 {
		t.Fatalf("newToken = %q, %v; want 64 hex chars", b, err)
	}
	if a == b {
		t.Error("two generated tokens are identical")
	}
}

func TestAuthenticatorDisabled(t *testing.T) {
	a := New(nil, false, 0, "")
	if a.Enabled() {
		t.Error("New(nil, false): Enabled() = true")
	}
	if _, _, err := a.Login("x", "y"); err != ErrAuthDisabled {
		t.Errorf("Login when disabled = %v, want ErrAuthDisabled", err)
	}
	if a.SessionTTL() != 168*time.Hour {
		t.Errorf("SessionTTL fallback = %v, want 168h", a.SessionTTL())
	}
}
