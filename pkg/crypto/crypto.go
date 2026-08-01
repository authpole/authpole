package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"authpole/pkg/models"
)

var (
	ErrInvalidToken     = errors.New("invalid token signature or format")
	ErrTokenExpired     = errors.New("token has expired")
	ErrKeyNotFound      = errors.New("matching signing key not found")
	ErrUnsupportedAlgo  = errors.New("unsupported signing algorithm")
)

// GenerateRSAKeyPair generates a new 2048-bit RSA signing key pair for a tenant/app.
func GenerateRSAKeyPair(tenantID, appID string) (*models.SigningKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key pair: %w", err)
	}

	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	})

	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	// Compute deterministic KID from SHA-256 hash of public key bytes
	h := sha256.Sum256(pubBytes)
	kid := hex.EncodeToString(h[:12])

	keyID := fmt.Sprintf("key_%s", kid)

	return &models.SigningKey{
		ID:            keyID,
		TenantID:      tenantID,
		AppID:         appID,
		Algorithm:     "RS256",
		PrivateKeyPEM: string(privPEM),
		PublicKeyPEM:  string(pubPEM),
		KID:           kid,
		Active:        true,
		CreatedAt:     time.Now(),
		Version:       "1",
	}, nil
}

// JWK represents an individual JSON Web Key.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS represents a JSON Web Key Set container.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// BuildJWKS generates standard JWKS JSON payload from active signing keys.
func BuildJWKS(keys []*models.SigningKey) ([]byte, error) {
	var jwks JWKS

	for _, k := range keys {
		if !k.Active || k.Algorithm != "RS256" {
			continue
		}

		block, _ := pem.Decode([]byte(k.PublicKeyPEM))
		if block == nil {
			continue
		}

		pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			continue
		}

		rsaPub, ok := pubInterface.(*rsa.PublicKey)
		if !ok {
			continue
		}

		nBase64 := base64.RawURLEncoding.EncodeToString(rsaPub.N.Bytes())
		eBytes := big.NewInt(int64(rsaPub.E)).Bytes()
		eBase64 := base64.RawURLEncoding.EncodeToString(eBytes)

		jwks.Keys = append(jwks.Keys, JWK{
			Kty: "RSA",
			Use: "sig",
			Alg: "RS256",
			Kid: k.KID,
			N:   nBase64,
			E:   eBase64,
		})
	}

	return json.MarshalIndent(jwks, "", "  ")
}

// JWTHeader represents the header of an Auth Pole JWT.
type JWTHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// SignJWT creates and signs a JWT string using an RSA private key.
func SignJWT(claims *models.AuthClaims, privateKeyPEM string, kid string) (string, error) {
	header := JWTHeader{
		Alg: "RS256",
		Typ: "JWT",
		Kid: kid,
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedClaims := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signingInput := fmt.Sprintf("%s.%s", encodedHeader, encodedClaims)

	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return "", fmt.Errorf("failed to parse private key PEM block")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse PKCS1 private key: %w", err)
	}

	hashed := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)
	return fmt.Sprintf("%s.%s", signingInput, encodedSignature), nil
}

// VerifyJWT validates a JWT token string against a set of active public keys offline.
func VerifyJWT(tokenString string, keys []*models.SigningKey) (*models.AuthClaims, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrInvalidToken
	}

	var header JWTHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, ErrInvalidToken
	}

	if header.Alg != "RS256" {
		return nil, ErrUnsupportedAlgo
	}

	// Find matching key by KID
	var matchingKey *models.SigningKey
	for _, k := range keys {
		if k.KID == header.Kid && k.Active {
			matchingKey = k
			break
		}
	}

	if matchingKey == nil {
		return nil, ErrKeyNotFound
	}

	block, _ := pem.Decode([]byte(matchingKey.PublicKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to parse public key PEM block")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPub, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not RSA")
	}

	signingInput := fmt.Sprintf("%s.%s", parts[0], parts[1])
	signatureBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrInvalidToken
	}

	hashed := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hashed[:], signatureBytes); err != nil {
		return nil, ErrInvalidToken
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidToken
	}

	var claims models.AuthClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, ErrInvalidToken
	}

	if claims.ExpiresAt > 0 && time.Now().Unix() > claims.ExpiresAt {
		return nil, ErrTokenExpired
	}

	return &claims, nil
}
