package idp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"authpole/pkg/cache"
	"authpole/pkg/crypto"
	"authpole/pkg/models"
	"authpole/pkg/storage"
)

// AuthState stores active authorization transaction state between Relying Party redirect and Upstream IDP callback.
type AuthState struct {
	StateID        string
	OrganizationID string
	AppID          string
	ClientID       string
	RedirectURI    string
	Scope          string
	OriginalState  string
	UpstreamIDP    string
	CreatedAt      time.Time
}

// AuthCode stores issued single-use authorization code details waiting for token exchange.
type AuthCode struct {
	Code           string
	OrganizationID string
	AppID          string
	ClientID       string
	RedirectURI    string
	Claims         *models.AuthClaims
	CreatedAt      time.Time
	ExpiresAt      time.Time
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
func (e *IDPEngine) PrepareAuthorization(ctx context.Context, serverBaseURL, orgID, clientID, redirectURI, scope, state, idpID string) (string, error) {
	// Lookup App
	appKey := storage.AppKey(orgID, clientID)
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

	// Select and resolve IDP
	selectedIDPID := idpID
	if selectedIDPID == "" {
		if len(app.AllowedIDPs) > 0 {
			selectedIDPID = app.AllowedIDPs[0]
		} else {
			return "", fmt.Errorf("no upstream IDP configured for this application")
		}
	}

	upstreamIDP, err := e.resolveUpstreamIDP(ctx, orgID, clientID, selectedIDPID)
	if err != nil {
		return "", err
	}

	// Create internal state token
	stateID := fmt.Sprintf("state_%d", time.Now().UnixNano())
	authState := &AuthState{
		StateID:        stateID,
		OrganizationID: orgID,
		AppID:          app.ID,
		ClientID:       clientID,
		RedirectURI:    redirectURI,
		Scope:          scope,
		OriginalState:  state,
		UpstreamIDP:    selectedIDPID,
		CreatedAt:      time.Now(),
	}

	e.mu.Lock()
	e.states[stateID] = authState
	e.mu.Unlock()

	stateBytes, _ := json.Marshal(authState)
	_, _ = e.storage.Put(ctx, storage.AuthStateKey(stateID), stateBytes, "")

	upstreamCallbackURL := fmt.Sprintf("%s/oauth/v2/callback", serverBaseURL)
	scopesStr := "openid profile email"
	if len(upstreamIDP.Scopes) > 0 {
		scopesStr = strings.Join(upstreamIDP.Scopes, " ")
	}

	v := url.Values{}
	v.Set("client_id", upstreamIDP.ClientID)
	v.Set("redirect_uri", upstreamCallbackURL)
	v.Set("response_type", "code")
	v.Set("scope", scopesStr)
	v.Set("state", stateID)

	redirectTarget := fmt.Sprintf("%s?%s", upstreamIDP.AuthorizeURL, v.Encode())
	return redirectTarget, nil
}

func (e *IDPEngine) fetchAndConsumeAuthState(ctx context.Context, stateID string) (*AuthState, bool) {
	e.mu.Lock()
	state, exists := e.states[stateID]
	if exists {
		delete(e.states, stateID)
	}
	e.mu.Unlock()

	if exists {
		_ = e.storage.Delete(ctx, storage.AuthStateKey(stateID), "")
		return state, true
	}

	rec, err := e.storage.Get(ctx, storage.AuthStateKey(stateID))
	if err == nil {
		var s AuthState
		if err := json.Unmarshal(rec.Data, &s); err == nil {
			_ = e.storage.Delete(ctx, storage.AuthStateKey(stateID), "")
			return &s, true
		}
	}

	return nil, false
}

func (e *IDPEngine) fetchAndConsumeAuthCode(ctx context.Context, code string) (*AuthCode, bool) {
	e.mu.Lock()
	authCode, exists := e.codes[code]
	if exists {
		delete(e.codes, code)
	}
	e.mu.Unlock()

	if exists {
		_ = e.storage.Delete(ctx, storage.AuthCodeKey(code), "")
		return authCode, true
	}

	rec, err := e.storage.Get(ctx, storage.AuthCodeKey(code))
	if err == nil {
		var c AuthCode
		if err := json.Unmarshal(rec.Data, &c); err == nil {
			_ = e.storage.Delete(ctx, storage.AuthCodeKey(code), "")
			return &c, true
		}
	}

	return nil, false
}

// ProcessUpstreamCallback handles the OAuth authorization code exchange from Google/GitHub, fetches user profile claims, and returns the final redirect URL.
func (e *IDPEngine) ProcessUpstreamCallback(ctx context.Context, serverBaseURL, stateID, code string) (string, error) {
	state, exists := e.fetchAndConsumeAuthState(ctx, stateID)
	if !exists {
		return "", fmt.Errorf("invalid or expired state session")
	}

	upstreamIDP, err := e.resolveUpstreamIDP(ctx, state.OrganizationID, state.ClientID, state.UpstreamIDP)
	if err != nil {
		return "", fmt.Errorf("failed to resolve upstream IDP: %w", err)
	}

	upstreamCallbackURL := fmt.Sprintf("%s/oauth/v2/callback", serverBaseURL)

	// Step 1: Exchange code for access token at upstream IDP token endpoint
	v := url.Values{}
	v.Set("code", code)
	v.Set("client_id", upstreamIDP.ClientID)
	v.Set("client_secret", upstreamIDP.ClientSecret)
	v.Set("redirect_uri", upstreamCallbackURL)
	v.Set("grant_type", "authorization_code")

	req, err := http.NewRequestWithContext(ctx, "POST", upstreamIDP.TokenURL, strings.NewReader(v.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("token exchange HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("upstream token endpoint returned HTTP %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		IDToken     string `json:"id_token"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	if err := json.Unmarshal(bodyBytes, &tokenResp); err != nil {
		return "", fmt.Errorf("failed to parse upstream token response: %w", err)
	}
	if tokenResp.Error != "" {
		return "", fmt.Errorf("upstream token error: %s - %s", tokenResp.Error, tokenResp.ErrorDesc)
	}
	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("upstream IDP did not return an access token")
	}

	// Step 2: Fetch user profile info
	claims := &models.AuthClaims{
		OriginalIDP: upstreamIDP.ID,
		Roles:       []string{"user"},
	}

	if upstreamIDP.ID == "google" {
		userReq, _ := http.NewRequestWithContext(ctx, "GET", "https://openidconnect.googleapis.com/v1/userinfo", nil)
		userReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
		userResp, err := client.Do(userReq)
		if err != nil {
			return "", fmt.Errorf("failed to fetch Google user profile: %w", err)
		}
		defer userResp.Body.Close()
		userBytes, _ := io.ReadAll(userResp.Body)

		var gUser struct {
			Sub   string `json:"sub"`
			Name  string `json:"name"`
			Email string `json:"email"`
		}
		_ = json.Unmarshal(userBytes, &gUser)

		claims.Subject = fmt.Sprintf("google_%s", gUser.Sub)
		claims.Email = gUser.Email
		claims.Name = gUser.Name
		if claims.Name == "" {
			claims.Name = gUser.Email
		}
	} else if upstreamIDP.ID == "github" {
		userReq, _ := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
		userReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
		userReq.Header.Set("User-Agent", "AuthPole-Mediator")
		userResp, err := client.Do(userReq)
		if err != nil {
			return "", fmt.Errorf("failed to fetch GitHub user profile: %w", err)
		}
		defer userResp.Body.Close()
		userBytes, _ := io.ReadAll(userResp.Body)

		var ghUser struct {
			ID    interface{} `json:"id"`
			Login string      `json:"login"`
			Name  string      `json:"name"`
			Email string      `json:"email"`
		}
		_ = json.Unmarshal(userBytes, &ghUser)

		claims.Subject = fmt.Sprintf("github_%v", ghUser.ID)
		claims.Name = ghUser.Name
		if claims.Name == "" {
			claims.Name = ghUser.Login
		}
		claims.Email = ghUser.Email

		// If email is private/empty, fetch user emails list
		if claims.Email == "" {
			emailsReq, _ := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user/emails", nil)
			emailsReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
			emailsReq.Header.Set("User-Agent", "AuthPole-Mediator")
			emailsResp, err := client.Do(emailsReq)
			if err == nil {
				defer emailsResp.Body.Close()
				emailsBytes, _ := io.ReadAll(emailsResp.Body)
				var emailList []struct {
					Email    string `json:"email"`
					Primary  bool   `json:"primary"`
					Verified bool   `json:"verified"`
				}
				if err := json.Unmarshal(emailsBytes, &emailList); err == nil {
					for _, em := range emailList {
						if em.Primary && em.Verified {
							claims.Email = em.Email
							break
						}
					}
					if claims.Email == "" && len(emailList) > 0 {
						claims.Email = emailList[0].Email
					}
				}
			}
		}
	} else {
		// Generic fallback
		claims.Subject = fmt.Sprintf("%s_user", upstreamIDP.ID)
		claims.Email = fmt.Sprintf("user@%s.com", upstreamIDP.ID)
		claims.Name = fmt.Sprintf("Authenticated %s User", upstreamIDP.ID)
	}

	return e.CompleteUpstreamAuthenticationWithState(ctx, state, claims)
}

// CompleteUpstreamAuthenticationWithState issues authorization code for an already validated AuthState.
func (e *IDPEngine) CompleteUpstreamAuthenticationWithState(ctx context.Context, state *AuthState, userClaims *models.AuthClaims) (redirectURL string, err error) {
	// Issue authorization code
	codeStr := fmt.Sprintf("code_%d_%s", time.Now().UnixNano(), state.AppID)
	authCode := &AuthCode{
		Code:           codeStr,
		OrganizationID: state.OrganizationID,
		AppID:          state.AppID,
		ClientID:       state.ClientID,
		RedirectURI:    state.RedirectURI,
		Claims:         userClaims,
		CreatedAt:      time.Now(),
		ExpiresAt:      time.Now().Add(5 * time.Minute),
	}

	e.mu.Lock()
	e.codes[codeStr] = authCode
	e.mu.Unlock()

	codeBytes, _ := json.Marshal(authCode)
	_, _ = e.storage.Put(ctx, storage.AuthCodeKey(codeStr), codeBytes, "")

	v := url.Values{}
	v.Set("code", codeStr)
	if state.OriginalState != "" {
		v.Set("state", state.OriginalState)
	}

	return fmt.Sprintf("%s?%s", state.RedirectURI, v.Encode()), nil
}

// CompleteUpstreamAuthentication processes identity claims from upstream IDP and issues single-use authorization code.
func (e *IDPEngine) CompleteUpstreamAuthentication(ctx context.Context, stateID string, userClaims *models.AuthClaims) (redirectURL string, err error) {
	state, exists := e.fetchAndConsumeAuthState(ctx, stateID)
	if !exists {
		return "", fmt.Errorf("invalid or expired authorization state session")
	}
	return e.CompleteUpstreamAuthenticationWithState(ctx, state, userClaims)
}

// ExchangeCodeForToken exchanges single-use code for Auth Pole signed JWT tokens.
func (e *IDPEngine) ExchangeCodeForToken(ctx context.Context, orgID, clientID, clientSecret, code, redirectURI string) (map[string]interface{}, error) {
	authCode, exists := e.fetchAndConsumeAuthCode(ctx, code)
	if !exists {
		return nil, fmt.Errorf("invalid or already consumed authorization code")
	}

	if time.Now().After(authCode.ExpiresAt) {
		return nil, fmt.Errorf("authorization code has expired")
	}

	if authCode.ClientID != clientID {
		return nil, fmt.Errorf("client_id mismatch")
	}

	// Fetch active signing key for org/app
	keys, found := e.cache.GetSigningKeys(orgID, authCode.AppID)
	if !found || len(keys) == 0 {
		// Load from storage if cache miss
		list, err := e.storage.List(ctx, fmt.Sprintf("organizations/%s/keys/", orgID))
		if err != nil || len(list) == 0 {
			// Generate auto signing key if none exists
			newKey, err := crypto.GenerateRSAKeyPair(orgID, authCode.AppID)
			if err != nil {
				return nil, fmt.Errorf("failed to generate signing key: %w", err)
			}
			keyBytes, _ := json.Marshal(newKey)
			_, _ = e.storage.Put(ctx, storage.KeyPairKey(orgID, newKey.ID), keyBytes, "")
			keys = []*models.SigningKey{newKey}
		} else {
			for _, rec := range list {
				var k models.SigningKey
				if err := json.Unmarshal(rec.Data, &k); err == nil && k.Active {
					keys = append(keys, &k)
				}
			}
		}
		e.cache.SetSigningKeys(orgID, authCode.AppID, keys, 1*time.Hour)
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("no active signing key available")
	}

	activeKey := keys[0]

	now := time.Now()
	claims := authCode.Claims
	claims.Issuer = fmt.Sprintf("https://authpole.io/organizations/%s", orgID)
	claims.Audience = clientID
	claims.OrganizationID = orgID
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
		"access_token":    accessToken,
		"id_token":        idToken,
		"token_type":      "Bearer",
		"expires_in":      3600,
		"scope":           "openid profile email",
		"organization_id": orgID,
		"app_id":          authCode.AppID,
	}, nil
}

func (e *IDPEngine) resolveUpstreamIDP(ctx context.Context, orgID, clientID, idpID string) (*models.IdentityProvider, error) {
	isPlatformApp := clientID == "admin_console"

	// Platform-level credentials (for admin_console login) come ONLY from environment variables.
	// These are Auth Pole's own registered Google/GitHub OAuth app credentials.
	// They are NOT tenant-configurable IDP records.
	if isPlatformApp {
		switch idpID {
		case "google":
			clientIDVal := getFirstEnv("AUTHPOLE_GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_ID")
			clientSecretVal := getFirstEnv("AUTHPOLE_GOOGLE_CLIENT_SECRET", "GOOGLE_CLIENT_SECRET")
			if clientIDVal == "" {
				return nil, fmt.Errorf("Google sign-in is not available: AUTHPOLE_GOOGLE_CLIENT_ID is not set on this server. Run: make set-oauth-credentials GOOGLE_CLIENT_ID=... && make deploy-server")
			}
			return &models.IdentityProvider{
				ID:           "google",
				Name:         "Google",
				Type:         "oidc",
				ClientID:     clientIDVal,
				ClientSecret: clientSecretVal,
				AuthorizeURL: "https://accounts.google.com/o/oauth2/v2/auth",
				TokenURL:     "https://oauth2.googleapis.com/token",
				Scopes:       []string{"openid", "profile", "email"},
				Enabled:      true,
			}, nil
		case "github":
			clientIDVal := getFirstEnv("AUTHPOLE_GITHUB_CLIENT_ID", "GITHUB_CLIENT_ID")
			clientSecretVal := getFirstEnv("AUTHPOLE_GITHUB_CLIENT_SECRET", "GITHUB_CLIENT_SECRET")
			if clientIDVal == "" {
				return nil, fmt.Errorf("GitHub sign-in is not available: AUTHPOLE_GITHUB_CLIENT_ID is not set on this server. Run: make set-oauth-credentials GITHUB_CLIENT_ID=... && make deploy-server")
			}
			return &models.IdentityProvider{
				ID:           "github",
				Name:         "GitHub",
				Type:         "oauth2",
				ClientID:     clientIDVal,
				ClientSecret: clientSecretVal,
				AuthorizeURL: "https://github.com/login/oauth/authorize",
				TokenURL:     "https://github.com/login/oauth/access_token",
				Scopes:       []string{"user:email", "read:user"},
				Enabled:      true,
			}, nil
		default:
			return nil, fmt.Errorf("unsupported platform IDP %q: admin console only supports google and github", idpID)
		}
	}

	// Tenant-level IDP resolution: look up organization storage.
	// These are IDPs that tenants configure for their own applications.
	isPlaceholder := func(c string) bool {
		return c == "" || strings.HasPrefix(c, "google_oauth_client_id") || strings.HasPrefix(c, "github_oauth_client_id") || c == "authpole_proxy"
	}

	// 1. Try organization-specific storage
	idpKey := storage.IDPKey(orgID, idpID)
	rec, err := e.storage.Get(ctx, idpKey)
	if err == nil {
		var idp models.IdentityProvider
		if err := json.Unmarshal(rec.Data, &idp); err == nil && idp.Enabled && !isPlaceholder(idp.ClientID) {
			if idp.ID == "google" {
				idp.Type = "oidc"
				idp.AuthorizeURL = "https://accounts.google.com/o/oauth2/v2/auth"
				idp.TokenURL = "https://oauth2.googleapis.com/token"
			} else if idp.ID == "github" {
				idp.Type = "oauth2"
				idp.AuthorizeURL = "https://github.com/login/oauth/authorize"
				idp.TokenURL = "https://github.com/login/oauth/access_token"
			}
			return &idp, nil
		}
	}

	// 2. Fall back to default organization storage
	if orgID != "default" {
		defaultKey := storage.IDPKey("default", idpID)
		if recDefault, err := e.storage.Get(ctx, defaultKey); err == nil {
			var idp models.IdentityProvider
			if err := json.Unmarshal(recDefault.Data, &idp); err == nil && idp.Enabled && !isPlaceholder(idp.ClientID) {
				if idp.ID == "google" {
					idp.Type = "oidc"
					idp.AuthorizeURL = "https://accounts.google.com/o/oauth2/v2/auth"
					idp.TokenURL = "https://oauth2.googleapis.com/token"
				} else if idp.ID == "github" {
					idp.Type = "oauth2"
					idp.AuthorizeURL = "https://github.com/login/oauth/authorize"
					idp.TokenURL = "https://github.com/login/oauth/access_token"
				}
				return &idp, nil
			}
		}
	}

	return nil, fmt.Errorf("upstream identity provider %q is not configured for organization %q", idpID, orgID)
}

func getFirstEnv(keys ...string) string {
	for _, k := range keys {
		if val := os.Getenv(k); val != "" {
			return val
		}
	}
	return ""
}
