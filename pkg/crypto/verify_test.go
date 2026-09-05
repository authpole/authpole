package crypto_test

import (
	"encoding/json"
	"testing"
	"time"

	"authpole/pkg/crypto"
	"authpole/pkg/models"
)

func TestAudienceAcceptsStringAndArray(t *testing.T) {
	var single models.Audience
	if err := json.Unmarshal([]byte(`"one"`), &single); err != nil {
		t.Fatalf("string form should decode: %v", err)
	}
	if len(single) != 1 || single[0] != "one" {
		t.Fatalf("unexpected decode: %#v", single)
	}

	var multi models.Audience
	if err := json.Unmarshal([]byte(`["a","b"]`), &multi); err != nil {
		t.Fatalf("array form should decode: %v", err)
	}
	if len(multi) != 2 {
		t.Fatalf("unexpected decode: %#v", multi)
	}

	// A single audience must re-marshal as a bare string for compatibility with
	// verifiers that only understand that form.
	encoded, err := json.Marshal(models.Audience{"solo"})
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if string(encoded) != `"solo"` {
		t.Fatalf("expected a bare string, got %s", encoded)
	}
}

func TestAudienceContainsFailsClosedOnEmpty(t *testing.T) {
	aud := models.Audience{"api"}
	if aud.Contains("") {
		t.Fatal("an empty expected audience must never match")
	}
	if !aud.Contains("api") {
		t.Fatal("expected a present audience to match")
	}
}

// TestUnknownKeyIDIsRejected covers the removal of the "fall back to any active
// key" behaviour: a token naming a key we do not have must be rejected outright
// rather than verified against an unrelated key.
func TestUnknownKeyIDIsRejected(t *testing.T) {
	signer, err := crypto.GenerateRSAKeyPair("acme", "app")
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	other, err := crypto.GenerateRSAKeyPair("acme", "app")
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}

	claims := &models.AuthClaims{
		Subject:   "user",
		Issuer:    "https://acme.example.test",
		Audience:  models.Audience{"api"},
		TokenUse:  models.TokenUseAccess,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}

	token, err := crypto.SignJWT(claims, signer.PrivateKeyPEM, signer.KID)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	// Only the unrelated key is offered, and the token names the signer's kid.
	if _, err := crypto.VerifyJWT(token, []*models.SigningKey{other}); err == nil {
		t.Fatal("a token whose kid names an unknown key must be rejected")
	}

	if _, err := crypto.VerifyJWT(token, []*models.SigningKey{signer}); err != nil {
		t.Fatalf("the correct key should verify: %v", err)
	}
}

func TestVerifyEnforcesIssuerAudienceAndUse(t *testing.T) {
	key, err := crypto.GenerateRSAKeyPair("acme", "app")
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	keys := []*models.SigningKey{key}

	claims := &models.AuthClaims{
		Subject:   "user",
		Issuer:    "https://acme.example.test",
		Audience:  models.Audience{"api"},
		TokenUse:  models.TokenUseAccess,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	token, err := crypto.SignJWT(claims, key.PrivateKeyPEM, key.KID)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	cases := []struct {
		name    string
		opts    crypto.VerifyOptions
		wantErr error
	}{
		{"correct expectations", crypto.VerifyOptions{
			ExpectedIssuer: "https://acme.example.test", ExpectedAudience: "api", ExpectedTokenUse: models.TokenUseAccess,
		}, nil},
		{"wrong issuer", crypto.VerifyOptions{
			ExpectedIssuer: "https://evil.example.test",
		}, crypto.ErrIssuerMismatch},
		{"wrong audience", crypto.VerifyOptions{
			ExpectedAudience: "other-api",
		}, crypto.ErrAudienceMismatch},
		{"wrong use", crypto.VerifyOptions{
			ExpectedTokenUse: models.TokenUseID,
		}, crypto.ErrTokenUseMismatch},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := crypto.VerifyJWTWithOptions(token, keys, tc.opts)
			if tc.wantErr == nil && err != nil {
				t.Fatalf("expected success, got %v", err)
			}
			if tc.wantErr != nil && err != tc.wantErr {
				t.Fatalf("expected %v, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestS256ChallengeMatchesKnownVector(t *testing.T) {
	// RFC 7636 Appendix B test vector.
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const want = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got := crypto.S256Challenge(verifier); got != want {
		t.Fatalf("S256 mismatch: got %q want %q", got, want)
	}
}

func TestSecureTokenIsRandomAndPrefixed(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 200; i++ {
		tok, err := crypto.SecureToken("code_")
		if err != nil {
			t.Fatalf("SecureToken failed: %v", err)
		}
		if len(tok) < len("code_")+43 {
			t.Fatalf("token too short: %q", tok)
		}
		if seen[tok] {
			t.Fatalf("SecureToken produced a duplicate: %q", tok)
		}
		seen[tok] = true
	}
}
