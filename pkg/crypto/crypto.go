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

	"github.com/authpole/authpole/pkg/models"
)

var (
	ErrInvalidToken    = errors.New("invalid token signature or format")
	ErrTokenExpired    = errors.New("token has expired")
	ErrKeyNotFound     = errors.New("matching signing key not found")
	ErrUnsupportedAlgo = errors.New("unsupported signing algorithm")

	// ErrIssuerMismatch means the token was minted by a different issuer than the
	// verifier trusts. In a multi-tenant deployment each tenant is its own issuer,
	// so skipping this check lets one tenant's token authorize calls against
	// another tenant whenever the two happen to share a signing key.
	ErrIssuerMismatch = errors.New("token issuer does not match the expected issuer")

	// ErrAudienceMismatch means the token was not minted for this resource server.
	// Without it, a token a user consented to give application A is replayable
	// against application B inside the same tenant.
	ErrAudienceMismatch = errors.New("token audience does not include the expected audience")

	// ErrTokenUseMismatch means an ID token was presented where an access token
	// was required, or vice versa.
	ErrTokenUseMismatch = errors.New("token was issued for a different use")

	// ErrTokenNotYetValid means the token's nbf claim is in the future beyond the
	// allowed clock skew.
	ErrTokenNotYetValid = errors.New("token is not valid yet")
)

// VerifyOptions declares what a verifier requires of a token beyond a valid
// signature. Every field left empty disables the corresponding check, so callers
// that authorize requests should set ExpectedIssuer, ExpectedAudience and
// ExpectedTokenUse — a signature alone only proves the token was minted by a key
// in the set, not that it was minted for this tenant, this API, or this purpose.
type VerifyOptions struct {
	// ExpectedIssuer is the `iss` the token must carry.
	ExpectedIssuer string
	// ExpectedAudience must appear in the token's `aud`.
	ExpectedAudience string
	// ExpectedTokenUse is the required `token_use` (see models.TokenUse*).
	ExpectedTokenUse string
	// Leeway tolerates clock skew between issuer and verifier when checking the
	// exp and nbf claims. DefaultLeeway is used when zero.
	Leeway time.Duration
}

// DefaultLeeway is the clock-skew tolerance applied when VerifyOptions.Leeway is
// not set. Distributed nodes are rarely perfectly synchronized, and a token
// rejected purely because the verifier's clock ran slightly ahead of the
// issuer's is an outage, not a security win.
const DefaultLeeway = 60 * time.Second

// GenerateRSAKeyPair generates a new 2048-bit RSA signing key pair for an organization/app.
func GenerateRSAKeyPair(orgID, appID string) (*models.SigningKey, error) {
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
		ID:             keyID,
		OrganizationID: orgID,
		AppID:          appID,
		Algorithm:      "RS256",
		PrivateKeyPEM:  string(privPEM),
		PublicKeyPEM:   string(pubPEM),
		KID:            kid,
		Active:         true,
		CreatedAt:      time.Now(),
		Version:        "1",
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

// VerifyJWT validates a token's signature and time bounds against a set of
// public keys, offline.
//
// It deliberately does NOT check the issuer or the audience, so on its own it is
// NOT sufficient to authorize a request: it proves only that some key in `keys`
// signed the token. Anything making an access-control decision must call
// VerifyJWTWithOptions and supply the issuer, audience and token use it demands.
func VerifyJWT(tokenString string, keys []*models.SigningKey) (*models.AuthClaims, error) {
	return VerifyJWTWithOptions(tokenString, keys, VerifyOptions{})
}

// VerifyJWTWithOptions validates a token offline and enforces every non-empty
// expectation in opts.
func VerifyJWTWithOptions(tokenString string, keys []*models.SigningKey, opts VerifyOptions) (*models.AuthClaims, error) {
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

	// Pin the algorithm. Accepting whatever the token declares is the classic JWT
	// algorithm-confusion bug: "none" would skip verification entirely, and an
	// HMAC alg would invite the verifier to treat the RSA public key as a shared
	// secret that the attacker already knows.
	if header.Alg != "RS256" {
		return nil, ErrUnsupportedAlgo
	}

	// Resolve the signing key by exact key id.
	//
	// The previous implementation matched loosely (substring/suffix comparisons)
	// and then, on no match, fell back to "just use the first active key". Both
	// behaviours defeat key rotation: during a rollover the wrong key is selected
	// and valid tokens are rejected, while a token whose kid is unknown gets a
	// verification attempt it should never have received. A kid that names no
	// known key is now an error.
	var matchingKey *models.SigningKey
	for _, k := range keys {
		if k == nil || !k.Active {
			continue
		}
		if header.Kid != "" && (k.KID == header.Kid || k.ID == header.Kid) {
			matchingKey = k
			break
		}
	}

	// A token with no kid cannot be attributed to one key, so every active key is
	// a candidate and the signature decides. This stays supported because tokens
	// from third-party issuers do not always carry a kid.
	if matchingKey == nil && header.Kid == "" {
		for _, k := range keys {
			if k == nil || !k.Active {
				continue
			}
			if claims, err := verifyAgainstKey(tokenString, parts, k, opts); err == nil {
				return claims, nil
			}
		}
		return nil, ErrKeyNotFound
	}

	if matchingKey == nil {
		return nil, ErrKeyNotFound
	}

	return verifyAgainstKey(tokenString, parts, matchingKey, opts)
}

// verifyAgainstKey checks the signature with exactly one key and then validates
// the claim set.
func verifyAgainstKey(tokenString string, parts []string, key *models.SigningKey, opts VerifyOptions) (*models.AuthClaims, error) {
	block, _ := pem.Decode([]byte(key.PublicKeyPEM))
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

	if err := validateClaims(&claims, opts); err != nil {
		return nil, err
	}

	return &claims, nil
}

// validateClaims enforces the time bounds plus every expectation the caller
// declared. Each expectation is skipped only when the caller left it empty.
func validateClaims(claims *models.AuthClaims, opts VerifyOptions) error {
	leeway := opts.Leeway
	if leeway == 0 {
		leeway = DefaultLeeway
	}
	now := time.Now()

	if claims.ExpiresAt > 0 && now.Add(-leeway).Unix() > claims.ExpiresAt {
		return ErrTokenExpired
	}
	if claims.NotBefore > 0 && now.Add(leeway).Unix() < claims.NotBefore {
		return ErrTokenNotYetValid
	}

	if opts.ExpectedIssuer != "" && claims.Issuer != opts.ExpectedIssuer {
		return ErrIssuerMismatch
	}
	if opts.ExpectedAudience != "" && !claims.Audience.Contains(opts.ExpectedAudience) {
		return ErrAudienceMismatch
	}
	if opts.ExpectedTokenUse != "" && claims.TokenUse != opts.ExpectedTokenUse {
		return ErrTokenUseMismatch
	}

	return nil
}
