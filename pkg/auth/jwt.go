package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/authpole/authpole/pkg/cache"
	"github.com/authpole/authpole/pkg/crypto"
	"github.com/authpole/authpole/pkg/models"
)

type contextKey string

const ClaimsContextKey contextKey = "auth_hub_claims"

// KeySource loads a tenant's active signing keys when they are not cached.
//
// The validator takes this as an interface rather than a concrete storage handle
// so an embedding host can back it with whatever it already has (its own system
// database, a JWKS client for a remote issuer) without this package depending on
// a storage implementation.
type KeySource interface {
	SigningKeys(ctx context.Context, orgID, appID string) ([]*models.SigningKey, error)
}

// TokenValidator verifies Auth Pole issued JWTs, preferring in-memory keys and
// falling back to the configured KeySource.
type TokenValidator struct {
	cache  *cache.MemoryCache
	source KeySource
	// keyTTL is how long keys fetched from the source are cached.
	keyTTL time.Duration
}

// NewTokenValidator builds a cache-only validator.
//
// A validator with no KeySource rejects every token whose keys are not already
// cached, so prefer NewTokenValidatorWithSource for anything serving requests.
func NewTokenValidator(c *cache.MemoryCache) *TokenValidator {
	return &TokenValidator{cache: c, keyTTL: time.Hour}
}

// NewTokenValidatorWithSource builds a validator that can populate its own cache.
func NewTokenValidatorWithSource(c *cache.MemoryCache, source KeySource) *TokenValidator {
	return &TokenValidator{cache: c, source: source, keyTTL: time.Hour}
}

// ErrNoKeysAvailable means the validator could not obtain any key for the tenant,
// so it could neither accept nor refute the token. It is distinct from
// crypto.ErrKeyNotFound (keys were available, none matched the token's kid)
// because the two mean different things operationally: this one is an outage on
// our side, that one is a bad token.
var ErrNoKeysAvailable = errors.New("no signing keys available for tenant")

// Options declares what a caller requires of a token. See crypto.VerifyOptions:
// leaving Audience or Issuer empty disables that check, which is only ever
// appropriate for diagnostics, never for authorizing a request.
type Options struct {
	Issuer   string
	Audience string
	TokenUse string
}

// ValidateToken verifies a token's signature and expiry only.
//
// It does NOT bind the token to an issuer or an audience, so it must not be used
// to authorize a request - see ValidateAccessToken. It is retained for callers
// that only need to know a token is well-formed and unexpired.
func (v *TokenValidator) ValidateToken(orgID, appID, tokenString string) (*models.AuthClaims, error) {
	return v.Validate(context.Background(), orgID, appID, tokenString, Options{})
}

// ValidateAccessToken is the request-authorization entry point: it requires the
// token to be an access token minted by the expected issuer for the expected
// audience.
func (v *TokenValidator) ValidateAccessToken(ctx context.Context, orgID, appID, tokenString, issuer, audience string) (*models.AuthClaims, error) {
	return v.Validate(ctx, orgID, appID, tokenString, Options{
		Issuer:   issuer,
		Audience: audience,
		TokenUse: models.TokenUseAccess,
	})
}

// Validate verifies a token against the tenant's keys and the supplied options.
func (v *TokenValidator) Validate(ctx context.Context, orgID, appID, tokenString string, opts Options) (*models.AuthClaims, error) {
	keys, err := v.keysFor(ctx, orgID, appID)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, ErrNoKeysAvailable
	}

	return crypto.VerifyJWTWithOptions(tokenString, keys, crypto.VerifyOptions{
		ExpectedIssuer:   opts.Issuer,
		ExpectedAudience: opts.Audience,
		ExpectedTokenUse: opts.TokenUse,
	})
}

// keysFor returns the tenant's keys, consulting the cache first and the
// KeySource on a miss.
//
// The fallback is the point: previously a cache miss returned ErrKeyNotFound, so
// a freshly started node rejected every valid token until something else happened
// to warm the cache. Verification keys are public, and fetching them on demand is
// a bounded cost paid once per TTL.
func (v *TokenValidator) keysFor(ctx context.Context, orgID, appID string) ([]*models.SigningKey, error) {
	if keys, found := v.cache.GetSigningKeys(orgID, appID); found && len(keys) > 0 {
		return keys, nil
	}

	if v.source == nil {
		return nil, ErrNoKeysAvailable
	}

	keys, err := v.source.SigningKeys(ctx, orgID, appID)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, ErrNoKeysAvailable
	}

	ttl := v.keyTTL
	if ttl <= 0 {
		ttl = time.Hour
	}
	v.cache.SetSigningKeys(orgID, appID, keys, ttl)
	return keys, nil
}

// Middleware validates the Bearer access token on incoming requests. issuer and
// audience are required: a middleware that skips them would accept any token this
// tenant ever minted, for any application.
func (v *TokenValidator) Middleware(orgID, appID, issuer, audience string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				http.Error(w, `{"error":"unauthorized","message":"missing or invalid authorization header"}`, http.StatusUnauthorized)
				return
			}

			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			claims, err := v.ValidateAccessToken(r.Context(), orgID, appID, tokenString, issuer, audience)
			if err != nil {
				// Do not echo err to the caller: the typed reasons distinguish an
				// expired token from a wrong audience from an unknown key, which is
				// useful in logs and an oracle in a response body.
				status := http.StatusUnauthorized
				if errors.Is(err, ErrNoKeysAvailable) {
					status = http.StatusServiceUnavailable
				}
				http.Error(w, `{"error":"invalid_token","message":"token rejected"}`, status)
				return
			}

			ctx := context.WithValue(r.Context(), ClaimsContextKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ClaimsFromContext extracts validated AuthClaims from context.
func ClaimsFromContext(ctx context.Context) (*models.AuthClaims, bool) {
	claims, ok := ctx.Value(ClaimsContextKey).(*models.AuthClaims)
	return claims, ok
}
