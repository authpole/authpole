package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// tokenEntropyBytes is the number of random bytes behind every authorization
// code, state handle and refresh token. 32 bytes (256 bits) is far above the
// 128-bit floor RFC 6749 §10.10 requires for values that must be unguessable.
const tokenEntropyBytes = 32

// SecureToken returns prefix followed by a URL-safe, cryptographically random
// string.
//
// This exists because authorization codes and state handles were previously
// derived from time.Now().UnixNano(). A nanosecond clock reading is not a
// secret: it is monotonic, low-entropy and externally observable, so an attacker
// who saw one value could enumerate the small window of plausible neighbours and
// redeem a code that belonged to somebody else's in-flight login. Every such
// value MUST come from here.
func SecureToken(prefix string) (string, error) {
	b := make([]byte, tokenEntropyBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to read cryptographic randomness: %w", err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// SecureCompare reports whether two secrets are equal without leaking their
// contents through comparison timing. Use it for any value an attacker can
// submit repeatedly (client secrets, PKCE verifiers, code handles).
func SecureCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// S256Challenge returns the RFC 7636 §4.2 "S256" transformation of a PKCE code
// verifier: BASE64URL(SHA256(ASCII(verifier))), unpadded.
func S256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Fingerprint returns a short, non-reversible label for a secret, suitable for
// logs and storage keys. Callers must never log the secret itself.
func Fingerprint(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:8])
}
