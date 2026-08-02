package auth

import (
	"context"
	"net/http"
	"strings"

	"authpole/pkg/cache"
	"authpole/pkg/crypto"
	"authpole/pkg/models"
)

type contextKey string

const ClaimsContextKey contextKey = "auth_hub_claims"

// TokenValidator manages fast, zero-database access path token verification using in-memory cached signing keys.
type TokenValidator struct {
	cache *cache.MemoryCache
}

func NewTokenValidator(c *cache.MemoryCache) *TokenValidator {
	return &TokenValidator{cache: c}
}

// ValidateToken performs high-performance JWT validation strictly using in-memory cached keys.
func (v *TokenValidator) ValidateToken(orgID, appID, tokenString string) (*models.AuthClaims, error) {
	keys, found := v.cache.GetSigningKeys(orgID, appID)
	if !found || len(keys) == 0 {
		return nil, crypto.ErrKeyNotFound
	}
	return crypto.VerifyJWT(tokenString, keys)
}

// Middleware creates an HTTP middleware that extracts and validates the Bearer JWT token on incoming requests.
func (v *TokenValidator) Middleware(orgID, appID string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				http.Error(w, `{"error":"unauthorized","message":"missing or invalid authorization header"}`, http.StatusUnauthorized)
				return
			}

			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			claims, err := v.ValidateToken(orgID, appID, tokenString)
			if err != nil {
				http.Error(w, `{"error":"invalid_token","message":"`+err.Error()+`"}`, http.StatusUnauthorized)
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
