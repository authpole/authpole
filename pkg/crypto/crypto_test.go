package crypto_test

import (
	"testing"
	"time"

	"authpole/pkg/crypto"
	"authpole/pkg/models"
)

func TestCryptoJWTAndJWKS(t *testing.T) {
	orgID := "org_acme"
	appID := "app_portal"

	// 1. Generate RSA key pair
	keyPair, err := crypto.GenerateRSAKeyPair(orgID, appID)
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair failed: %v", err)
	}

	if keyPair.KID == "" || keyPair.PrivateKeyPEM == "" || keyPair.PublicKeyPEM == "" {
		t.Fatalf("Key pair generated incomplete fields: %+v", keyPair)
	}

	// 2. Build JWKS
	jwksBytes, err := crypto.BuildJWKS([]*models.SigningKey{keyPair})
	if err != nil {
		t.Fatalf("BuildJWKS failed: %v", err)
	}
	if len(jwksBytes) == 0 {
		t.Fatalf("BuildJWKS returned empty bytes")
	}

	// 3. Sign JWT
	claims := &models.AuthClaims{
		Subject:        "user_123",
		Issuer:         "https://authpole.io/organizations/" + orgID,
		Audience:       models.Audience{appID},
		OrganizationID: orgID,
		AppID:          appID,
		OriginalIDP:    "google",
		Email:          "user@example.com",
		IssuedAt:       time.Now().Unix(),
		ExpiresAt:      time.Now().Add(1 * time.Hour).Unix(),
	}

	tokenStr, err := crypto.SignJWT(claims, keyPair.PrivateKeyPEM, keyPair.KID)
	if err != nil {
		t.Fatalf("SignJWT failed: %v", err)
	}

	// 4. Verify JWT
	verifiedClaims, err := crypto.VerifyJWT(tokenStr, []*models.SigningKey{keyPair})
	if err != nil {
		t.Fatalf("VerifyJWT failed: %v", err)
	}

	if verifiedClaims.Subject != claims.Subject || verifiedClaims.Email != claims.Email {
		t.Fatalf("Verified claims mismatch. Got: %+v, Expected: %+v", verifiedClaims, claims)
	}
}
