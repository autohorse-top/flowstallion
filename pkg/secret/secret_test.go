package secret

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// TestKeyFromString covers accepted and rejected key encodings.
func TestKeyFromString(t *testing.T) {
	key32 := make([]byte, 32)
	for i := range key32 {
		key32[i] = byte(i)
	}
	hexs := hex.EncodeToString(key32)
	tt := map[string]struct {
		in   string
		want []byte
	}{
		"hex64":  {in: hexs, want: key32},
		"short":  {in: "abc", want: nil},
		"badhex": {in: strings.Repeat("z", 64), want: nil}, // not hex, not valid base64 -> error
		"63hex":  {in: hexs[:63], want: nil},
		"40hex":  {in: strings.Repeat("0", 40), want: nil},
	}
	for name, c := range tt {
		got, err := KeyFromString(c.in)
		if c.want == nil {
			if err == nil {
				t.Errorf("%s: want error, got key %x", name, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: unexpected error: %v", name, err)
			continue
		}
		if !bytes.Equal(got, c.want) {
			t.Errorf("%s: key mismatch\n got %x\nwant %x", name, got, c.want)
		}
	}
}

// TestSealOpenRoundtrip verifies Seal/Open round-trips for several payload sizes.
func TestSealOpenRoundtrip(t *testing.T) {
	key, _ := KeyFromString(strings.Repeat("0011223344556677", 4)) // 64 hex chars
	v, err := New(key)
	if err != nil {
		t.Fatal(err)
	}
	cases := []string{"", "hunter2", "héllo wörld ✓", strings.Repeat("x", 8192), strings.Repeat("y", 100_000)}
	for _, s := range cases {
		blob, err := v.Seal([]byte(s))
		if err != nil {
			t.Fatalf("Seal(%q): %v", s[:min(8, len(s))], err)
		}
		if len(blob) < 12+16 {
			t.Fatalf("Seal: blob too short (%d)", len(blob))
		}
		out, err := v.Open(blob)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if !bytes.Equal(out, []byte(s)) {
			t.Fatalf("roundtrip mismatch for len %d", len(s))
		}
	}
}

// TestSealRandomNonce: sealing the same plaintext twice must give different blobs.
func TestSealRandomNonce(t *testing.T) {
	v, _ := New([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32})
	b1, _ := v.Seal([]byte("same"))
	b2, _ := v.Seal([]byte("same"))
	if bytes.Equal(b1, b2) {
		t.Fatal("two seals of the same plaintext are identical (nonce not random?)")
	}
}

// TestOpenWrongKey: a different key must fail authentication.
func TestOpenWrongKey(t *testing.T) {
	v1, _ := New([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32})
	v2, _ := New([]byte{32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17,
		16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1})
	blob, _ := v1.Seal([]byte("top secret"))
	if _, err := v2.Open(blob); err == nil {
		t.Fatal("Open with wrong key succeeded (must fail)")
	}
}

// TestOpenCorrupt: flipping a ciphertext byte must fail authentication.
func TestOpenCorrupt(t *testing.T) {
	v, _ := New([]byte{9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 3, 4, 5, 6, 7, 8,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	blob, _ := v.Seal([]byte("integrity-check"))
	corrupt := make([]byte, len(blob))
	copy(corrupt, blob)
	corrupt[len(corrupt)/2] ^= 0xFF
	if _, err := v.Open(corrupt); err == nil {
		t.Fatal("Open of corrupted blob succeeded (must fail)")
	}
	if _, err := v.Open(blob[:10]); err == nil {
		t.Fatal("Open of truncated blob succeeded (must fail)")
	}
}
