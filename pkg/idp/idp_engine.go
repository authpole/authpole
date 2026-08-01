package idp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sync"
	"time"

	"authpole/pkg/cache"
	"authpole/pkg/crypto"
	"authpole/pkg/models"
	"authpole/pkg/storage"
)

// AuthState stores active authorization transaction state between Relying Party redirect and Upstream IDP callback.
type AuthState struct {
	StateID      string
	TenantID     string
	AppID        string
	ClientID     string
	RedirectURI  string
	Scope        string
	OriginalState string
	UpstreamIDP  string
	CreatedAt    time.Time
}

// AuthCode stores issued single-use authorization code details waiting for token exchange.
type AuthCode struct {
	Code        string
	TenantID    string
	AppID       string
	ClientID    string
	RedirectURI string
	Claims      *models.AuthClaims
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

// IDPEngine manages authorization sessions, federated proxy authentication, and Auth Pole JWT issuing.
type IDPEngine struct {
	storage storage.Storage
	cache   *cache.MemoryCache
	mu      sync.Mutex
	states  map[string]*AuthState
	codes   map[string]*AuthCode
}

func NewIDPEngine(store storage.Storage, c *cache.MemoryCache) *IDPEngine {
	return &IDPEngine{
		storage: store,
		cache:   c,
		states:  make(map[string]*AuthState),
		codes:   make(map[string]*AuthCode),
	}
}

// PrepareAuthorization builds the upstream IDP authentication redirect URL.
func (e *IDPEngine) PrepareAuthorization(ctx context.Context, tenantID, clientID, redirectURI, scope, state, idpID string) (string, error) {
	// Lookup App
	appKey := storage.AppKey(tenantID, clientID)
	rec, err := e.storage.Get(ctx, appKey)
	if err != nil {
		return "", fmt.Errorf("invalid app or client_id: %w", err)
	}

	var app models.Application
	if err := json.Unmarshal(rec.Data, &app); err != nil {
		return "", fmt.Errorf("failed to parse application: %w", err)
	}

	// Validate Redirect URI
	validRedirect := false
	for _, u := range app.RedirectURIs {
		if u == redirectURI {
			validRedirect = true
			break
		}
	}
	if !validRedirect {
		return "", fmt.Errorf("redirect_uri %q is not authorized for app %s", redirectURI, app.ID)
	}

	// Select IDP
	selectedIDPID := idpID
	if selectedIDPID == "" {
		if len(app.AllowedIDPs) > 0 {
			selectedIDPID = app.AllowedIDPs[0]
		} else {
			return "", fmt.Errorf("no upstream IDP configured for this application")
		}
	}

	idpKey := storage.IDPKey(tenantID, selectedIDPID)
	idpRec, err := e.storage.Get(ctx, idpKey)
	if err != nil {
		return "", fmt.Errorf("upstream IDP %q not found: %w", selectedIDPID, err)
	}

	var upstreamIDP models.IdentityProvider
	if err := json.Unmarshal(idpRec.Data, &upstreamIDP); err != nil {
		return "", fmt.Errorf("failed to parse upstream IDP: %w", err)
	}

	// Create internal state token
	stateID := fmt.Sprintf("state_%d", time.Now().UnixNano())
	authState := &AuthState{
		StateID:       stateID,
		TenantID:      tenantID,
		AppID:         app.ID,
		ClientID:      clientID,
		RedirectURI:   redirectURI,
		Scope:         scope,
		OriginalState: state,
		UpstreamIDP:   selectedIDPID,
		CreatedAt:     time.Now(),
	}

	e.mu.Lock()
	e.states[stateID] = authState
	e.mu.Unlock()

	// Build Redirect URL to Upstream IDP
	if upstreamIDP.Type == "mock" || upstreamIDP.AuthorizeURL == "" {
		// Internal mock / test IDP redirect
		authURL := fmt.Sprintf("/oauth/v2/mock_login?state=%s", stateID)
		return authURL, nil
	}

	v := url.Values{}
	v.Set("client_id", upstreamIDP.ClientID)
	v.Set("redirect_uri", fmt.Sprintf("/oauth/v2/callback"))
	v.Set("response_type", "code")
	v.Set("scope", "openid profile email")
	v.Set("state", stateID)

	redirectTarget := fmt.Sprintf("%s?%s", upstreamIDP.AuthorizeURL, v.Encode())
	return redirectTarget, nil
}

// CompleteUpstreamAuthentication processes identity claims from upstream IDP and issues single-use authorization code.
func (e *IDPEngine) CompleteUpstreamAuthentication(stateID string, userClaims *models.AuthClaims) (redirectURL string, err error) {
	e.mu.Lock()
	state, exists := e.states[stateID]
	if exists {
		delete(e.states, stateID)
	}
	e.mu.Unlock()

	if !exists {
		return "", fmt.Errorf("invalid or expired authorization state session")
	}

	// Issue authorization code
	codeStr := fmt.Sprintf("code_%d_%s", time.Now().UnixNano(), state.AppID)
	authCode := &AuthCode{
		Code:        codeStr,
		TenantID:    state.TenantID,
		AppID:       state.AppID,
		ClientID:    state.ClientID,
		RedirectURI: state.RedirectURI,
		Claims:      userClaims,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}

	e.mu.Lock()
	e.codes[codeStr] = authCode
	e.mu.Unlock()

	v := url.Values{}
	v.Set("code", codeStr)
	if state.OriginalState != "" {
		v.Set("state", state.OriginalState)
	}

	return fmt.Sprintf("%s?%s", state.RedirectURI, v.Encode()), nil
}

// ExchangeCodeForToken exchanges single-use code for Auth Pole signed JWT tokens.
func (e *IDPEngine) ExchangeCodeForToken(ctx context.Context, tenantID, clientID, clientSecret, code, redirectURI string) (map[string]interface{}, error) {
	e.mu.Lock()
	authCode, exists := e.codes[code]
	if exists {
		delete(e.codes, code) // Single-use consumption
	}
	e.mu.Unlock()

	if !exists {
		return nil, fmt.Errorf("invalid or already consumed authorization code")
	}

	if time.Now().After(authCode.ExpiresAt) {
		return nil, fmt.Errorf("authorization code has expired")
	}

	if authCode.ClientID != clientID {
		return nil, fmt.Errorf("client_id mismatch")
	}

	// Fetch active signing key for tenant/app
	keys, found := e.cache.GetSigningKeys(tenantID, authCode.AppID)
	if !found || len(keys) == 0 {
		// Load from storage if cache miss
		list, err := e.storage.List(ctx, fmt.Sprintf("tenants/%s/keys/", tenantID))
		if err != nil || len(list) == 0 {
			// Generate auto signing key if none exists
			newKey, err := crypto.GenerateRSAKeyPair(tenantID, authCode.AppID)
			if err != nil {
				return nil, fmt.Errorf("failed to generate signing key: %w", err)
			}
			keyBytes, _ := json.Marshal(newKey)
			_, _ = e.storage.Put(ctx, storage.KeyPairKey(tenantID, newKey.ID), keyBytes, "")
			keys = []*models.SigningKey{newKey}
		} else {
			for _, rec := range list {
				var k models.SigningKey
				if err := json.Unmarshal(rec.Data, &k); err == nil && k.Active {
					keys = append(keys, &k)
				}
			}
		}
		e.cache.SetSigningKeys(tenantID, authCode.AppID, keys, 1*time.Hour)
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("no active signing key available")
	}

	activeKey := keys[0]

	now := time.Now()
	claims := authCode.Claims
	claims.Issuer = fmt.Sprintf("https://authpole.io/tenants/%s", tenantID)
	claims.Audience = clientID
	claims.TenantID = tenantID
	claims.AppID = authCode.AppID
	claims.IssuedAt = now.Unix()
	claims.ExpiresAt = now.Add(1 * time.Hour).Unix()

	idToken, err := crypto.SignJWT(claims, activeKey.PrivateKeyPEM, activeKey.KID)
	if err != nil {
		return nil, fmt.Errorf("failed to sign ID token: %w", err)
	}

	accessToken, err := crypto.SignJWT(claims, activeKey.PrivateKeyPEM, activeKey.KID)
	if err != nil {
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	return map[string]interface{}{
		"access_token":  accessToken,
		"id_token":      idToken,
		"token_type":    "Bearer",
		"expires_in":    3600,
		"scope":         "openid profile email",
		"tenant_id":     tenantID,
		"app_id":        authCode.AppID,
	}, nil
}
