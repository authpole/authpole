package idp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/authpole/authpole/pkg/cache"
	"github.com/authpole/authpole/pkg/crypto"
	"github.com/authpole/authpole/pkg/models"
	"github.com/authpole/authpole/pkg/storage"
)

// pkceMethodS256 is the only PKCE transformation this server accepts. RFC 7636
// also defines "plain", where the verifier is sent as the challenge; that gives
// an attacker who can observe the authorization request everything needed to
// redeem the code, so it is refused.
const pkceMethodS256 = "S256"

// containsString reports whether v is present in list.
func containsString(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}

// Lifetimes for the short-lived artifacts of an authorization exchange.
const (
	// authStateTTL bounds how long an in-flight login may sit between the client
	// redirect and the upstream provider's callback.
	authStateTTL = 15 * time.Minute

	// authCodeTTL bounds authorization-code redemption. RFC 6749 §4.1.2 advises a
	// maximum of 10 minutes; a code is a bearer credential in a URL, so shorter is
	// better.
	authCodeTTL = 2 * time.Minute

	// accessTokenTTL is intentionally short: an access token lives in a browser and
	// cannot be revoked before it expires, so its lifetime IS its revocation window.
	accessTokenTTL = 15 * time.Minute

	// idTokenTTL matches the access token; the ID token is consumed immediately by
	// the client at login and never replayed against an API.
	idTokenTTL = 15 * time.Minute

	// refreshTokenTTL bounds the session a public client can silently extend.
	refreshTokenTTL = 14 * 24 * time.Hour
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
	// CodeChallenge / CodeChallengeMethod carry the client's PKCE commitment
	// (RFC 7636) from the authorization request through to redemption.
	CodeChallenge       string
	CodeChallengeMethod string
	// Nonce is echoed into the ID token so the client can prove the token belongs
	// to the login it started, defeating ID-token replay.
	Nonce     string
	CreatedAt time.Time
}

// AuthCode stores issued single-use authorization code details waiting for token exchange.
type AuthCode struct {
	Code           string
	OrganizationID string
	AppID          string
	ClientID       string
	RedirectURI    string
	Scope          string
	Claims         *models.AuthClaims
	// PKCE commitment copied from the authorization request. Redemption must
	// present a verifier that hashes to this challenge.
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string
	CreatedAt           time.Time
	ExpiresAt           time.Time
}

// RefreshToken is a persisted, rotating handle that lets a public client obtain a
// fresh access token without another user interaction.
//
// It is stored server-side (rather than being a self-contained JWT) precisely so
// it can be revoked and so rotation can detect reuse: a refresh token is spent on
// first use, and a second presentation of the same handle means it leaked.
type RefreshToken struct {
	Token          string             `json:"token"`
	OrganizationID string             `json:"organization_id"`
	AppID          string             `json:"app_id"`
	ClientID       string             `json:"client_id"`
	Subject        string             `json:"subject"`
	Scope          string             `json:"scope"`
	Claims         *models.AuthClaims `json:"claims"`
	FamilyID       string             `json:"family_id"`
	CreatedAt      time.Time          `json:"created_at"`
	ExpiresAt      time.Time          `json:"expires_at"`
}

// IssuerFunc maps a tenant to its OIDC issuer identifier.
//
// This is injectable because the issuer is deployment policy, not a property of
// this library. An embedding host that serves each tenant on its own hostname
// wants "https://{slug}.example.com"; the standalone server wants a path-based
// issuer under its own domain. The issuer is also security-relevant: it is what a
// verifier pins to decide a token was minted for its tenant, so it must be exactly
// the origin that publishes the matching JWKS.
type IssuerFunc func(orgID string) string

// IDPEngine manages authorization sessions, federated proxy authentication, and Auth Pole JWT issuing.
type IDPEngine struct {
	storage storage.Storage
	cache   *cache.MemoryCache
	mu      sync.Mutex
	states  map[string]*AuthState
	codes   map[string]*AuthCode

	// issuerFor resolves a tenant's issuer. Never call directly - use IssuerFor,
	// which applies the default when unset.
	issuerFor IssuerFunc
}

func NewIDPEngine(store storage.Storage, c *cache.MemoryCache) *IDPEngine {
	return &IDPEngine{
		storage: store,
		cache:   c,
		states:  make(map[string]*AuthState),
		codes:   make(map[string]*AuthCode),
	}
}

// SetIssuerResolver overrides how tenant issuers are derived. Embedding hosts are
// expected to call this at construction; passing nil restores the default.
func (e *IDPEngine) SetIssuerResolver(f IssuerFunc) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.issuerFor = f
}

// IssuerFor returns the issuer identifier for a tenant.
func (e *IDPEngine) IssuerFor(orgID string) string {
	e.mu.Lock()
	resolver := e.issuerFor
	e.mu.Unlock()

	if resolver != nil {
		if issuer := resolver(orgID); issuer != "" {
			return issuer
		}
	}
	return DefaultIssuerFor(orgID)
}

// DefaultIssuerBaseURL is the issuer prefix used when no resolver is installed. It
// is overridable via AUTHPOLE_ISSUER_BASE_URL so the standalone server does not
// have to be recompiled to be deployed under a different domain - the previous
// hardcoded literal made every deployment claim to be authpole.io, which breaks
// any verifier that pins the issuer.
func DefaultIssuerBaseURL() string {
	if v := strings.TrimRight(os.Getenv("AUTHPOLE_ISSUER_BASE_URL"), "/"); v != "" {
		return v
	}
	return "https://authpole.io"
}

// DefaultIssuerFor derives a path-based per-tenant issuer under the base URL.
func DefaultIssuerFor(orgID string) string {
	return fmt.Sprintf("%s/organizations/%s", DefaultIssuerBaseURL(), orgID)
}

// AuthorizationRequest carries an incoming /authorize request. It is a struct
// rather than a positional argument list because PKCE and nonce push the
// parameter count past the point where call sites can be read safely.
type AuthorizationRequest struct {
	ServerBaseURL  string
	OrganizationID string
	ClientID       string
	RedirectURI    string
	Scope          string
	State          string
	IDPID          string
	// CodeChallenge and CodeChallengeMethod are the client's PKCE commitment.
	// Mandatory for public clients; "S256" is the only accepted method.
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string
}

// PrepareAuthorization validates an authorization request and builds the upstream
// IDP authentication redirect URL.
func (e *IDPEngine) PrepareAuthorization(ctx context.Context, req AuthorizationRequest) (string, error) {
	// Lookup App
	appKey := storage.AppKey(req.OrganizationID, req.ClientID)
	rec, err := e.storage.Get(ctx, appKey)
	if err != nil {
		return "", fmt.Errorf("invalid app or client_id: %w", err)
	}

	var app models.Application
	if err := json.Unmarshal(rec.Data, &app); err != nil {
		return "", fmt.Errorf("failed to parse application: %w", err)
	}

	// Validate the redirect URI by exact string match against the registered set.
	// This is the anchor of the whole flow: the authorization code is delivered to
	// this URL, so any tolerance here (prefix matching, ignoring the query, allowing
	// a wildcard host) hands the code to an attacker-chosen endpoint.
	if !app.HasRedirectURI(req.RedirectURI) {
		return "", fmt.Errorf("redirect_uri %q is not authorized for app %s", req.RedirectURI, app.ID)
	}

	// PKCE. A public client (an SPA, a mobile app) cannot keep a client secret, so
	// the code challenge is the only thing preventing an attacker who intercepts
	// the authorization code from redeeming it. Enforce it before anything is
	// persisted, and reject "plain" outright - it offers no protection against an
	// attacker who can already read the authorization request.
	if app.IsPublicClient() && req.CodeChallenge == "" {
		return "", fmt.Errorf("code_challenge is required for public client %s (PKCE, RFC 7636)", app.ID)
	}
	if req.CodeChallenge != "" {
		method := req.CodeChallengeMethod
		if method == "" {
			// RFC 7636 §4.3 defaults to "plain" when the method is omitted. We do not
			// accept plain, so an omitted method is an error rather than a silent
			// downgrade.
			return "", fmt.Errorf("code_challenge_method is required and must be S256")
		}
		if method != pkceMethodS256 {
			return "", fmt.Errorf("unsupported code_challenge_method %q: only S256 is accepted", method)
		}
	}

	// Select and resolve IDP, and confirm the app is actually allowed to use it.
	// Without this check a caller could name any IDP in the tenant via ?idp= and
	// authenticate through a provider the application was never granted.
	selectedIDPID := req.IDPID
	if selectedIDPID == "" {
		if len(app.AllowedIDPs) > 0 {
			selectedIDPID = app.AllowedIDPs[0]
		} else {
			// An empty AllowedIDPs means the app is not restricted - which is exactly
			// how the check below reads it, since it only rejects a named provider when
			// the list is non-empty. So the default must come from what the TENANT has
			// configured. Previously this branch returned "no upstream IDP configured
			// for this application" whenever the list was empty, which was wrong twice
			// over: it reported a tenant with several working providers as having none,
			// and it made an unrestricted app the one kind that could not be used
			// without naming a provider.
			available, err := e.enabledIDPIDs(ctx, req.OrganizationID)
			if err != nil {
				return "", err
			}

			switch len(available) {
			case 0:
				return "", fmt.Errorf("no upstream identity provider is configured for this tenant")
			case 1:
				// Unambiguous, so do not make the caller say it.
				selectedIDPID = available[0]
			default:
				// Naming one is required rather than picking arbitrarily: which provider
				// authenticates a user is a security-relevant choice, and silently
				// preferring whichever sorted first would make the flow depend on
				// storage order.
				return "", fmt.Errorf("the idp parameter is required: this tenant has %d identity providers configured (%s)",
					len(available), strings.Join(available, ", "))
			}
		}
	} else if len(app.AllowedIDPs) > 0 && !containsString(app.AllowedIDPs, selectedIDPID) {
		return "", fmt.Errorf("identity provider %q is not enabled for app %s", selectedIDPID, app.ID)
	}

	upstreamIDP, err := e.resolveUpstreamIDP(ctx, req.OrganizationID, req.ClientID, selectedIDPID)
	if err != nil {
		return "", err
	}

	// Create internal state token. This value is the only thing tying the upstream
	// provider's callback back to this login attempt, so it must be unguessable -
	// see crypto.SecureToken on why a nanosecond timestamp was not.
	stateID, err := crypto.SecureToken("state_")
	if err != nil {
		return "", fmt.Errorf("failed to generate authorization state: %w", err)
	}
	authState := &AuthState{
		StateID:             stateID,
		OrganizationID:      req.OrganizationID,
		AppID:               app.ID,
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		Scope:               req.Scope,
		OriginalState:       req.State,
		UpstreamIDP:         selectedIDPID,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		Nonce:               req.Nonce,
		CreatedAt:           time.Now(),
	}

	stateBytes, err := json.Marshal(authState)
	if err != nil {
		return "", fmt.Errorf("failed to encode authorization state: %w", err)
	}

	// Persist BEFORE redirecting, and fail the request if it does not stick. The
	// callback is consumed through storage (it may land on a different node), so a
	// dropped write here becomes an unexplainable "invalid or expired state" for
	// the user at the end of a successful upstream login.
	if _, err := e.storage.Put(ctx, storage.AuthStateKey(stateID), stateBytes, ""); err != nil {
		return "", fmt.Errorf("failed to persist authorization state: %w", err)
	}

	e.mu.Lock()
	e.states[stateID] = authState
	e.mu.Unlock()

	upstreamCallbackURL := fmt.Sprintf("%s/oauth/v2/callback", req.ServerBaseURL)

	// Merge the provider record with its preset so a record that only supplies
	// credentials still gets the well-known endpoints and scopes.
	cfg := effectiveProvider(upstreamIDP)
	if cfg.AuthorizeURL == "" {
		return "", fmt.Errorf("identity provider %q has no authorize_url configured", upstreamIDP.ID)
	}

	scopesStr := "openid profile email"
	if len(cfg.Scopes) > 0 {
		scopesStr = strings.Join(cfg.Scopes, " ")
	}

	v := url.Values{}
	v.Set("client_id", cfg.ClientID)
	v.Set("redirect_uri", upstreamCallbackURL)
	v.Set("response_type", "code")
	v.Set("scope", scopesStr)
	v.Set("state", stateID)
	for key, value := range cfg.ExtraAuthParams {
		// Never let provider-specific extras overwrite the protocol parameters that
		// carry our own state and redirect.
		switch key {
		case "client_id", "redirect_uri", "response_type", "state":
			continue
		}
		v.Set(key, value)
	}

	redirectTarget := fmt.Sprintf("%s?%s", cfg.AuthorizeURL, v.Encode())
	return redirectTarget, nil
}

// claimSingleUse atomically consumes a one-time record, returning its payload to
// exactly one caller.
//
// Storage is the authority here, deliberately. The in-memory maps below are a
// latency cache for the record's *contents*, never the arbiter of whether it has
// been spent: only the node that created a code holds it in memory, so a peer
// serving the redemption would fall through to storage, and the previous
// read-then-unconditionally-delete sequence let both nodes read the same code
// before either delete landed and mint two token sets from one authorization.
//
// A CAS delete closes that window: both callers read the same version, both
// attempt to delete exactly that version, and the storage layer lets precisely
// one of them win (S3 If-Match -> ErrVersionMismatch for the loser).
func (e *IDPEngine) claimSingleUse(ctx context.Context, key string) ([]byte, bool) {
	rec, err := e.storage.Get(ctx, key)
	if err != nil || rec == nil || len(rec.Data) == 0 {
		return nil, false
	}

	// An empty version would degrade the delete to unconditional and reopen the
	// double-redemption window, so refuse to claim rather than race.
	if rec.Version == "" {
		return nil, false
	}

	if err := e.storage.Delete(ctx, key, rec.Version); err != nil {
		// Lost the race (or the record vanished) - the winner owns it.
		return nil, false
	}

	return rec.Data, true
}

func (e *IDPEngine) fetchAndConsumeAuthState(ctx context.Context, stateID string) (*AuthState, bool) {
	// Drop the local cache entry regardless of who wins the claim, so a lost race
	// cannot leave a spent state resident on this node.
	e.mu.Lock()
	delete(e.states, stateID)
	e.mu.Unlock()

	data, ok := e.claimSingleUse(ctx, storage.AuthStateKey(stateID))
	if !ok {
		return nil, false
	}

	var s AuthState
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, false
	}
	if time.Now().After(s.CreatedAt.Add(authStateTTL)) {
		return nil, false
	}
	return &s, true
}

func (e *IDPEngine) fetchAndConsumeAuthCode(ctx context.Context, code string) (*AuthCode, bool) {
	e.mu.Lock()
	delete(e.codes, code)
	e.mu.Unlock()

	data, ok := e.claimSingleUse(ctx, storage.AuthCodeKey(code))
	if !ok {
		return nil, false
	}

	var c AuthCode
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, false
	}
	return &c, true
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

	// Step 1: Exchange code for access token at upstream IDP token endpoint. Use the
	// preset-merged config so a provider record carrying only credentials still
	// resolves its well-known token endpoint.
	upstreamCfg := effectiveProvider(upstreamIDP)
	if upstreamCfg.TokenURL == "" {
		return "", fmt.Errorf("identity provider %q has no token_url configured", upstreamIDP.ID)
	}

	v := url.Values{}
	v.Set("code", code)
	v.Set("client_id", upstreamCfg.ClientID)
	v.Set("client_secret", upstreamCfg.ClientSecret)
	v.Set("redirect_uri", upstreamCallbackURL)
	v.Set("grant_type", "authorization_code")

	req, err := http.NewRequestWithContext(ctx, "POST", upstreamCfg.TokenURL, strings.NewReader(v.Encode()))
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

	// Step 2: Fetch and normalize the user profile through the provider's own
	// configuration. Every provider - preset or tenant-registered - goes through the
	// same path, so a tenant's own OIDC/OAuth2 provider is a first-class citizen
	// rather than falling into a stub that fabricated an identity.
	claims, err := e.fetchUpstreamClaims(ctx, client, upstreamIDP, tokenResp.AccessToken)
	if err != nil {
		return "", err
	}

	return e.CompleteUpstreamAuthenticationWithState(ctx, state, claims)
}

// CompleteUpstreamAuthenticationWithState issues authorization code for an already validated AuthState.
func (e *IDPEngine) CompleteUpstreamAuthenticationWithState(ctx context.Context, state *AuthState, userClaims *models.AuthClaims) (redirectURL string, err error) {
	// Issue authorization code. The code is a bearer credential that travels in a
	// URL (and therefore into browser history, Referer headers and access logs), so
	// it must be unguessable and short-lived. It previously encoded a nanosecond
	// timestamp and the app ID, which made neighbouring codes enumerable.
	codeStr, err := crypto.SecureToken("code_")
	if err != nil {
		return "", fmt.Errorf("failed to generate authorization code: %w", err)
	}

	now := time.Now()
	authCode := &AuthCode{
		Code:           codeStr,
		OrganizationID: state.OrganizationID,
		AppID:          state.AppID,
		ClientID:       state.ClientID,
		RedirectURI:    state.RedirectURI,
		Scope:          state.Scope,
		Claims:         userClaims,
		// Carry the PKCE commitment forward: redemption is where it is checked, and
		// dropping it here would silently turn PKCE into a no-op.
		CodeChallenge:       state.CodeChallenge,
		CodeChallengeMethod: state.CodeChallengeMethod,
		Nonce:               state.Nonce,
		CreatedAt:           now,
		ExpiresAt:           now.Add(authCodeTTL),
	}

	codeBytes, err := json.Marshal(authCode)
	if err != nil {
		return "", fmt.Errorf("failed to encode authorization code: %w", err)
	}

	// The code must be durably readable by whichever node handles the redemption,
	// and claimSingleUse needs a concrete version to CAS against, so a failed write
	// has to fail the login rather than redirect with a code nobody can spend.
	if _, err := e.storage.Put(ctx, storage.AuthCodeKey(codeStr), codeBytes, ""); err != nil {
		return "", fmt.Errorf("failed to persist authorization code: %w", err)
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

// CompleteUpstreamAuthentication processes identity claims from upstream IDP and issues single-use authorization code.
func (e *IDPEngine) CompleteUpstreamAuthentication(ctx context.Context, stateID string, userClaims *models.AuthClaims) (redirectURL string, err error) {
	state, exists := e.fetchAndConsumeAuthState(ctx, stateID)
	if !exists {
		return "", fmt.Errorf("invalid or expired authorization state session")
	}
	return e.CompleteUpstreamAuthenticationWithState(ctx, state, userClaims)
}

// ExchangeCodeForToken exchanges single-use code for Auth Pole signed JWT tokens.
// TokenRequest carries an incoming /token request for either supported grant.
type TokenRequest struct {
	GrantType      string
	OrganizationID string
	ClientID       string
	ClientSecret   string
	// Authorization-code grant.
	Code         string
	RedirectURI  string
	CodeVerifier string
	// Refresh-token grant.
	RefreshToken string
}

// TokenResponse is the RFC 6749 §5.1 token endpoint success response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
}

// Grant types supported by the token endpoint.
const (
	GrantAuthorizationCode = "authorization_code"
	GrantRefreshToken      = "refresh_token"
)

// ExchangeCodeForToken redeems an authorization code (or a refresh token) for a
// fresh token set.
func (e *IDPEngine) ExchangeCodeForToken(ctx context.Context, req TokenRequest) (*TokenResponse, error) {
	switch req.GrantType {
	case GrantRefreshToken:
		return e.exchangeRefreshToken(ctx, req)
	case GrantAuthorizationCode, "":
		return e.exchangeAuthorizationCode(ctx, req)
	default:
		return nil, fmt.Errorf("unsupported grant_type %q", req.GrantType)
	}
}

func (e *IDPEngine) exchangeAuthorizationCode(ctx context.Context, req TokenRequest) (*TokenResponse, error) {
	authCode, exists := e.fetchAndConsumeAuthCode(ctx, req.Code)
	if !exists {
		return nil, fmt.Errorf("invalid or already consumed authorization code")
	}

	if time.Now().After(authCode.ExpiresAt) {
		return nil, fmt.Errorf("authorization code has expired")
	}

	// Bind the code to the client it was issued to. Compared in constant time
	// because the client_id is submitted by the caller on every attempt.
	if !crypto.SecureCompare(authCode.ClientID, req.ClientID) {
		return nil, fmt.Errorf("client_id does not match the authorization code")
	}

	// RFC 6749 §4.1.3 requires redirect_uri to be replayed and to match. It ties the
	// redemption to the same registered endpoint the code was delivered to.
	if req.RedirectURI != "" && req.RedirectURI != authCode.RedirectURI {
		return nil, fmt.Errorf("redirect_uri does not match the authorization request")
	}

	app, err := e.loadApplication(ctx, authCode.OrganizationID, authCode.ClientID)
	if err != nil {
		return nil, err
	}

	// Authenticate the client. A public client proves possession with the PKCE
	// verifier; a confidential client proves it with its secret. Requiring the
	// correct one per client type is what stops a stolen code being redeemed by
	// whoever intercepted it.
	if app.IsPublicClient() {
		if err := verifyPKCE(authCode, req.CodeVerifier); err != nil {
			return nil, err
		}
	} else {
		if !crypto.SecureCompare(app.ClientSecret, req.ClientSecret) {
			return nil, fmt.Errorf("invalid client credentials")
		}
		// A confidential client that opted into PKCE still gets it enforced.
		if authCode.CodeChallenge != "" {
			if err := verifyPKCE(authCode, req.CodeVerifier); err != nil {
				return nil, err
			}
		}
	}

	return e.issueTokens(ctx, app, authCode.Claims, authCode.Scope, authCode.Nonce, "")
}

// verifyPKCE checks the presented verifier against the stored challenge.
func verifyPKCE(authCode *AuthCode, verifier string) error {
	if authCode.CodeChallenge == "" {
		// The code was minted without a challenge, so there is nothing to prove
		// possession against. Refuse rather than treat it as satisfied - reaching
		// here means a public client's authorization request bypassed the PKCE
		// requirement, and honouring the redemption would hide that.
		return fmt.Errorf("authorization code was issued without a PKCE challenge")
	}
	if verifier == "" {
		return fmt.Errorf("code_verifier is required (PKCE, RFC 7636)")
	}
	// RFC 7636 §4.1: the verifier must be 43-128 characters. A short verifier is
	// brute-forceable against the challenge.
	if len(verifier) < 43 || len(verifier) > 128 {
		return fmt.Errorf("code_verifier must be between 43 and 128 characters")
	}
	if authCode.CodeChallengeMethod != pkceMethodS256 {
		return fmt.Errorf("unsupported code_challenge_method %q", authCode.CodeChallengeMethod)
	}
	if !crypto.SecureCompare(authCode.CodeChallenge, crypto.S256Challenge(verifier)) {
		return fmt.Errorf("code_verifier does not match the code_challenge")
	}
	return nil
}

// exchangeRefreshToken rotates a refresh token and issues a new token set.
func (e *IDPEngine) exchangeRefreshToken(ctx context.Context, req TokenRequest) (*TokenResponse, error) {
	if req.RefreshToken == "" {
		return nil, fmt.Errorf("refresh_token is required")
	}

	// Rotation: the presented handle is consumed atomically, so a replay of the
	// same handle finds nothing. This is what makes a leaked refresh token
	// detectable and single-use rather than a standing credential.
	data, ok := e.claimSingleUse(ctx, storage.RefreshTokenKey(req.RefreshToken))
	if !ok {
		return nil, fmt.Errorf("invalid, expired or already used refresh token")
	}

	var stored RefreshToken
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, fmt.Errorf("invalid refresh token record")
	}

	if time.Now().After(stored.ExpiresAt) {
		return nil, fmt.Errorf("refresh token has expired")
	}
	if !crypto.SecureCompare(stored.ClientID, req.ClientID) {
		return nil, fmt.Errorf("refresh token was not issued to this client")
	}

	app, err := e.loadApplication(ctx, stored.OrganizationID, stored.ClientID)
	if err != nil {
		return nil, err
	}

	if !app.IsPublicClient() && !crypto.SecureCompare(app.ClientSecret, req.ClientSecret) {
		return nil, fmt.Errorf("invalid client credentials")
	}

	// No nonce on a refresh: the nonce binds an ID token to an interactive login,
	// and there is no user present here.
	return e.issueTokens(ctx, app, stored.Claims, stored.Scope, "", stored.FamilyID)
}

// issueTokens mints an access token, an ID token and a rotating refresh token.
func (e *IDPEngine) issueTokens(
	ctx context.Context,
	app *models.Application,
	base *models.AuthClaims,
	scope string,
	nonce string,
	familyID string,
) (*TokenResponse, error) {
	if base == nil {
		return nil, fmt.Errorf("cannot issue tokens without upstream identity claims")
	}

	orgID := app.OrganizationID
	signingKey, err := e.resolveSigningKey(ctx, orgID, app.ID)
	if err != nil {
		return nil, err
	}

	issuer := e.IssuerFor(orgID)
	now := time.Now()

	// Access token: audience is the resource server(s), use is "access".
	accessClaims := *base
	accessClaims.Issuer = issuer
	accessClaims.Audience = app.TokenAudiences()
	accessClaims.TokenUse = models.TokenUseAccess
	accessClaims.OrganizationID = orgID
	accessClaims.AppID = app.ID
	accessClaims.Scope = scope
	accessClaims.IssuedAt = now.Unix()
	accessClaims.NotBefore = now.Unix()
	accessClaims.ExpiresAt = now.Add(accessTokenTTL).Unix()
	accessClaims.Nonce = "" // a nonce belongs only to the ID token
	if accessClaims.JTI, err = crypto.SecureToken("jti_"); err != nil {
		return nil, fmt.Errorf("failed to generate token id: %w", err)
	}

	accessToken, err := crypto.SignJWT(&accessClaims, signingKey.PrivateKeyPEM, signingKey.KID)
	if err != nil {
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	// ID token: audience is the CLIENT, use is "id". Distinct claims and a distinct
	// use mean the two tokens are no longer interchangeable - previously both were
	// signed from one identical claim set, so an ID token was accepted anywhere an
	// access token was.
	idClaims := *base
	idClaims.Issuer = issuer
	idClaims.Audience = models.Audience{app.ClientID}
	idClaims.TokenUse = models.TokenUseID
	idClaims.OrganizationID = orgID
	idClaims.AppID = app.ID
	idClaims.Scope = ""
	idClaims.IssuedAt = now.Unix()
	idClaims.NotBefore = now.Unix()
	idClaims.ExpiresAt = now.Add(idTokenTTL).Unix()
	idClaims.Nonce = nonce
	if idClaims.JTI, err = crypto.SecureToken("jti_"); err != nil {
		return nil, fmt.Errorf("failed to generate token id: %w", err)
	}

	idToken, err := crypto.SignJWT(&idClaims, signingKey.PrivateKeyPEM, signingKey.KID)
	if err != nil {
		return nil, fmt.Errorf("failed to sign ID token: %w", err)
	}

	refreshToken, err := e.mintRefreshToken(ctx, app, base, scope, familyID)
	if err != nil {
		return nil, err
	}

	return &TokenResponse{
		AccessToken:  accessToken,
		IDToken:      idToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(accessTokenTTL.Seconds()),
		Scope:        scope,
	}, nil
}

// mintRefreshToken persists a new rotating refresh handle.
func (e *IDPEngine) mintRefreshToken(
	ctx context.Context,
	app *models.Application,
	base *models.AuthClaims,
	scope string,
	familyID string,
) (string, error) {
	handle, err := crypto.SecureToken("rt_")
	if err != nil {
		return "", fmt.Errorf("failed to generate refresh token: %w", err)
	}

	if familyID == "" {
		if familyID, err = crypto.SecureToken("rtf_"); err != nil {
			return "", fmt.Errorf("failed to generate refresh token family: %w", err)
		}
	}

	now := time.Now()
	record := &RefreshToken{
		Token:          handle,
		OrganizationID: app.OrganizationID,
		AppID:          app.ID,
		ClientID:       app.ClientID,
		Subject:        base.Subject,
		Scope:          scope,
		Claims:         base,
		FamilyID:       familyID,
		CreatedAt:      now,
		ExpiresAt:      now.Add(refreshTokenTTL),
	}

	payload, err := json.Marshal(record)
	if err != nil {
		return "", fmt.Errorf("failed to encode refresh token: %w", err)
	}
	if _, err := e.storage.Put(ctx, storage.RefreshTokenKey(handle), payload, ""); err != nil {
		return "", fmt.Errorf("failed to persist refresh token: %w", err)
	}

	return handle, nil
}

// loadApplication resolves a registered app by client ID, cache first.
func (e *IDPEngine) loadApplication(ctx context.Context, orgID, clientID string) (*models.Application, error) {
	if app, found := e.cache.GetApp(orgID, clientID); found && app != nil {
		return app, nil
	}

	rec, err := e.storage.Get(ctx, storage.AppKey(orgID, clientID))
	if err != nil {
		return nil, fmt.Errorf("invalid app or client_id: %w", err)
	}

	var app models.Application
	if err := json.Unmarshal(rec.Data, &app); err != nil {
		return nil, fmt.Errorf("failed to parse application: %w", err)
	}
	if app.OrganizationID == "" {
		app.OrganizationID = orgID
	}

	e.cache.SetApp(orgID, clientID, &app, 1*time.Minute)
	return &app, nil
}

// resolveSigningKey returns the active signing key for a tenant, creating one on
// first use.
//
// Creation is a create-only write so that concurrent nodes cannot each mint a
// different key and then sign with whichever they happened to store last: the
// loser of the race re-reads and adopts the winner's key. The previous code
// generated a key inside the token path with an unconditional Put and then picked
// keys[0], which under concurrency produced tokens signed by a key that was no
// longer the one published in JWKS.
func (e *IDPEngine) resolveSigningKey(ctx context.Context, orgID, appID string) (*models.SigningKey, error) {
	if keys, found := e.cache.GetSigningKeys(orgID, appID); found {
		if key := models.ActiveSigningKey(keys); key != nil {
			return key, nil
		}
	}

	keys, err := e.loadSigningKeys(ctx, orgID, appID)
	if err != nil {
		return nil, err
	}
	if key := models.ActiveSigningKey(keys); key != nil {
		e.cache.SetSigningKeys(orgID, appID, keys, 1*time.Hour)
		return key, nil
	}

	// None exists yet - create one, letting storage arbitrate the race.
	newKey, err := crypto.GenerateRSAKeyPair(orgID, appID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate signing key: %w", err)
	}
	payload, err := json.Marshal(newKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encode signing key: %w", err)
	}

	if _, err := e.storage.Put(ctx, storage.KeyPairKey(orgID, newKey.ID), payload, storage.MatchAnyVersion); err != nil {
		// Somebody else created a key first (or the write failed); re-read and use
		// whatever is now authoritative rather than signing with an unpublished key.
		keys, reloadErr := e.loadSigningKeys(ctx, orgID, appID)
		if reloadErr == nil {
			if key := models.ActiveSigningKey(keys); key != nil {
				e.cache.SetSigningKeys(orgID, appID, keys, 1*time.Hour)
				return key, nil
			}
		}
		return nil, fmt.Errorf("failed to persist signing key: %w", err)
	}

	e.cache.SetSigningKeys(orgID, appID, []*models.SigningKey{newKey}, 1*time.Hour)
	return newKey, nil
}

// SigningKeys implements auth.KeySource, returning the tenant's verification keys.
//
// Private key material is stripped from the returned copies. A verifier only ever
// needs the public half, and handing it a signing key would let any code path that
// can verify a token also mint one.
func (e *IDPEngine) SigningKeys(ctx context.Context, orgID, appID string) ([]*models.SigningKey, error) {
	keys, err := e.loadSigningKeys(ctx, orgID, appID)
	if err != nil {
		return nil, err
	}

	public := make([]*models.SigningKey, 0, len(keys))
	for _, k := range keys {
		if k == nil {
			continue
		}
		copied := *k
		copied.PrivateKeyPEM = ""
		public = append(public, &copied)
	}
	return public, nil
}

// loadSigningKeys reads a tenant's signing keys from storage.
func (e *IDPEngine) loadSigningKeys(ctx context.Context, orgID, appID string) ([]*models.SigningKey, error) {
	list, err := e.storage.List(ctx, fmt.Sprintf("organizations/%s/keys/", orgID))
	if err != nil {
		return nil, fmt.Errorf("failed to list signing keys: %w", err)
	}

	var keys []*models.SigningKey
	for _, rec := range list {
		var k models.SigningKey
		if err := json.Unmarshal(rec.Data, &k); err != nil {
			continue
		}
		if !k.Active {
			continue
		}
		// An app-scoped key only serves that app; an org-scoped key (empty AppID)
		// serves every app in the tenant.
		if k.AppID != "" && appID != "" && k.AppID != appID {
			continue
		}
		key := k
		keys = append(keys, &key)
	}
	return keys, nil
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

	// decodeUsable returns the stored provider if it is enabled and configured.
	//
	// It deliberately does NOT rewrite AuthorizeURL/TokenURL for records whose ID
	// happens to be "google" or "github". Doing so meant naming a provider "github"
	// silently forced it at github.com, so a tenant could not point that record at
	// GitHub Enterprise or any self-hosted deployment - its stored configuration was
	// accepted and then discarded. Defaults now come from effectiveProvider, which
	// only fills fields the record left empty.
	decodeUsable := func(data []byte) (*models.IdentityProvider, bool) {
		var provider models.IdentityProvider
		if err := json.Unmarshal(data, &provider); err != nil {
			return nil, false
		}
		if !provider.Enabled || isPlaceholder(provider.ClientID) {
			return nil, false
		}
		return &provider, true
	}

	// 1. Try organization-specific storage
	if rec, err := e.storage.Get(ctx, storage.IDPKey(orgID, idpID)); err == nil {
		if provider, ok := decodeUsable(rec.Data); ok {
			return provider, nil
		}
	}

	// 2. Fall back to default organization storage
	if orgID != "default" {
		if rec, err := e.storage.Get(ctx, storage.IDPKey("default", idpID)); err == nil {
			if provider, ok := decodeUsable(rec.Data); ok {
				return provider, nil
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

// enabledIDPIDs lists the ids of a tenant's enabled identity providers, sorted so the
// result does not depend on storage iteration order.
//
// Used to resolve a default provider and, when there is more than one, to tell the
// caller which are available. An unreadable record is skipped rather than failing the
// whole lookup: one corrupt entry must not make a tenant's other providers unusable.
func (e *IDPEngine) enabledIDPIDs(ctx context.Context, orgID string) ([]string, error) {
	records, err := e.storage.List(ctx, fmt.Sprintf("organizations/%s/idps/", orgID))
	if err != nil {
		return nil, fmt.Errorf("failed to list identity providers: %w", err)
	}

	ids := make([]string, 0, len(records))
	for _, record := range records {
		var idp models.IdentityProvider
		if err := json.Unmarshal(record.Data, &idp); err != nil {
			continue
		}
		if idp.Enabled && idp.ID != "" {
			ids = append(ids, idp.ID)
		}
	}

	sort.Strings(ids)
	return ids, nil
}
