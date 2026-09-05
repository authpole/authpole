package idp_test

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"authpole/pkg/cache"
	"authpole/pkg/crypto"
	"authpole/pkg/idp"
	"authpole/pkg/models"
	"authpole/pkg/storage"
)

// verifier is a valid RFC 7636 code verifier (43-128 chars).
const verifier = "test-code-verifier-that-is-long-enough-to-be-valid-0123456789"

func newEngine(t *testing.T) (*idp.IDPEngine, storage.Storage) {
	t.Helper()
	store, err := storage.NewMemoryStorage()
	if err != nil {
		t.Fatalf("failed to create memory storage: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	engine := idp.NewIDPEngine(store, cache.NewMemoryCache())
	engine.SetIssuerResolver(func(orgID string) string {
		return "https://" + orgID + ".example.test"
	})
	return engine, store
}

// seedApp registers an application and an upstream IDP for it.
func seedApp(t *testing.T, store storage.Storage, app *models.Application) {
	t.Helper()
	ctx := context.Background()

	payload, err := json.Marshal(app)
	if err != nil {
		t.Fatalf("failed to encode app: %v", err)
	}
	if _, err := store.Put(ctx, storage.AppKey(app.OrganizationID, app.ClientID), payload, ""); err != nil {
		t.Fatalf("failed to seed app: %v", err)
	}

	provider := &models.IdentityProvider{
		ID:             "mock",
		OrganizationID: app.OrganizationID,
		Name:           "Mock",
		Type:           "mock",
		ClientID:       "upstream-client",
		ClientSecret:   "upstream-secret",
		AuthorizeURL:   "https://upstream.example.test/authorize",
		TokenURL:       "https://upstream.example.test/token",
		Enabled:        true,
	}
	idpPayload, err := json.Marshal(provider)
	if err != nil {
		t.Fatalf("failed to encode idp: %v", err)
	}
	if _, err := store.Put(ctx, storage.IDPKey(app.OrganizationID, provider.ID), idpPayload, ""); err != nil {
		t.Fatalf("failed to seed idp: %v", err)
	}
}

func publicApp() *models.Application {
	return &models.Application{
		ID:             "app_spa",
		OrganizationID: "acme",
		Name:           "SPA",
		ClientID:       "spa-client",
		RedirectURIs:   []string{"https://spa.example.test/callback"},
		AllowedIDPs:    []string{"mock"},
		Public:         true,
		AllowedOrigins: []string{"https://spa.example.test"},
	}
}

// authorize drives PrepareAuthorization and returns the internal state id that
// the upstream provider would echo back.
func authorize(t *testing.T, engine *idp.IDPEngine, req idp.AuthorizationRequest) (string, error) {
	t.Helper()
	redirectURL, err := engine.PrepareAuthorization(context.Background(), req)
	if err != nil {
		return "", err
	}
	// The upstream redirect carries our state id in the state parameter.
	idx := strings.Index(redirectURL, "state=")
	if idx < 0 {
		t.Fatalf("no state in upstream redirect: %s", redirectURL)
	}
	state := redirectURL[idx+len("state="):]
	if amp := strings.Index(state, "&"); amp >= 0 {
		state = state[:amp]
	}
	return state, nil
}

func TestPublicClientRequiresPKCE(t *testing.T) {
	engine, store := newEngine(t)
	seedApp(t, store, publicApp())

	_, err := engine.PrepareAuthorization(context.Background(), idp.AuthorizationRequest{
		ServerBaseURL:  "https://acme.example.test",
		OrganizationID: "acme",
		ClientID:       "spa-client",
		RedirectURI:    "https://spa.example.test/callback",
	})
	if err == nil {
		t.Fatal("expected a public client without code_challenge to be rejected")
	}
	if !strings.Contains(err.Error(), "code_challenge is required") {
		t.Fatalf("expected a PKCE requirement error, got: %v", err)
	}
}

func TestPlainPKCEMethodRejected(t *testing.T) {
	engine, store := newEngine(t)
	seedApp(t, store, publicApp())

	_, err := engine.PrepareAuthorization(context.Background(), idp.AuthorizationRequest{
		ServerBaseURL:       "https://acme.example.test",
		OrganizationID:      "acme",
		ClientID:            "spa-client",
		RedirectURI:         "https://spa.example.test/callback",
		CodeChallenge:       crypto.S256Challenge(verifier),
		CodeChallengeMethod: "plain",
	})
	if err == nil {
		t.Fatal("expected code_challenge_method=plain to be rejected")
	}
}

func TestUnregisteredRedirectURIRejected(t *testing.T) {
	engine, store := newEngine(t)
	seedApp(t, store, publicApp())

	_, err := engine.PrepareAuthorization(context.Background(), idp.AuthorizationRequest{
		ServerBaseURL:       "https://acme.example.test",
		OrganizationID:      "acme",
		ClientID:            "spa-client",
		RedirectURI:         "https://attacker.example.test/callback",
		CodeChallenge:       crypto.S256Challenge(verifier),
		CodeChallengeMethod: "S256",
	})
	if err == nil {
		t.Fatal("expected an unregistered redirect_uri to be rejected")
	}
}

// completeLogin runs a full authorize -> upstream-complete cycle and returns the
// authorization code handed to the client.
func completeLogin(t *testing.T, engine *idp.IDPEngine) string {
	t.Helper()
	state, err := authorize(t, engine, idp.AuthorizationRequest{
		ServerBaseURL:       "https://acme.example.test",
		OrganizationID:      "acme",
		ClientID:            "spa-client",
		RedirectURI:         "https://spa.example.test/callback",
		Scope:               "openid profile",
		CodeChallenge:       crypto.S256Challenge(verifier),
		CodeChallengeMethod: "S256",
		Nonce:               "nonce-value",
	})
	if err != nil {
		t.Fatalf("authorization failed: %v", err)
	}

	redirect, err := engine.CompleteUpstreamAuthentication(context.Background(), state, &models.AuthClaims{
		Subject: "mock_user_1",
		Email:   "user@example.test",
		Name:    "Test User",
	})
	if err != nil {
		t.Fatalf("failed to complete upstream authentication: %v", err)
	}

	idx := strings.Index(redirect, "code=")
	if idx < 0 {
		t.Fatalf("no code in client redirect: %s", redirect)
	}
	code := redirect[idx+len("code="):]
	if amp := strings.Index(code, "&"); amp >= 0 {
		code = code[:amp]
	}
	return code
}

func TestAuthorizationCodeIsUnguessable(t *testing.T) {
	engine, store := newEngine(t)
	seedApp(t, store, publicApp())

	first := completeLogin(t, engine)
	second := completeLogin(t, engine)

	if first == second {
		t.Fatal("two logins produced the same authorization code")
	}
	// A timestamp-derived code was short and highly structured; a 256-bit random
	// value base64url-encodes to 43 characters.
	if len(strings.TrimPrefix(first, "code_")) < 43 {
		t.Fatalf("authorization code has too little entropy: %q", first)
	}
}

func TestTokenExchangeRequiresCorrectVerifier(t *testing.T) {
	engine, store := newEngine(t)
	seedApp(t, store, publicApp())
	code := completeLogin(t, engine)

	_, err := engine.ExchangeCodeForToken(context.Background(), idp.TokenRequest{
		GrantType:      idp.GrantAuthorizationCode,
		OrganizationID: "acme",
		ClientID:       "spa-client",
		Code:           code,
		RedirectURI:    "https://spa.example.test/callback",
		CodeVerifier:   "wrong-verifier-but-still-long-enough-to-pass-length-check",
	})
	if err == nil {
		t.Fatal("expected a mismatched code_verifier to be rejected")
	}
}

func TestTokenExchangeSucceedsAndSeparatesTokens(t *testing.T) {
	engine, store := newEngine(t)
	seedApp(t, store, publicApp())
	code := completeLogin(t, engine)

	resp, err := engine.ExchangeCodeForToken(context.Background(), idp.TokenRequest{
		GrantType:      idp.GrantAuthorizationCode,
		OrganizationID: "acme",
		ClientID:       "spa-client",
		Code:           code,
		RedirectURI:    "https://spa.example.test/callback",
		CodeVerifier:   verifier,
	})
	if err != nil {
		t.Fatalf("token exchange failed: %v", err)
	}

	if resp.AccessToken == "" || resp.IDToken == "" || resp.RefreshToken == "" {
		t.Fatal("expected access, id and refresh tokens to all be issued")
	}
	// The old implementation signed one identical claim set twice, so the two
	// tokens were byte-identical and interchangeable.
	if resp.AccessToken == resp.IDToken {
		t.Fatal("access token and ID token are identical")
	}

	keys, err := engine.SigningKeys(context.Background(), "acme", "app_spa")
	if err != nil {
		t.Fatalf("failed to load verification keys: %v", err)
	}

	access, err := crypto.VerifyJWTWithOptions(resp.AccessToken, keys, crypto.VerifyOptions{
		ExpectedIssuer:   "https://acme.example.test",
		ExpectedAudience: "spa-client",
		ExpectedTokenUse: models.TokenUseAccess,
	})
	if err != nil {
		t.Fatalf("access token failed verification: %v", err)
	}
	if access.Nonce != "" {
		t.Error("nonce must not appear on an access token")
	}

	idClaims, err := crypto.VerifyJWTWithOptions(resp.IDToken, keys, crypto.VerifyOptions{
		ExpectedIssuer:   "https://acme.example.test",
		ExpectedAudience: "spa-client",
		ExpectedTokenUse: models.TokenUseID,
	})
	if err != nil {
		t.Fatalf("ID token failed verification: %v", err)
	}
	if idClaims.Nonce != "nonce-value" {
		t.Errorf("expected the nonce to be echoed into the ID token, got %q", idClaims.Nonce)
	}

	// An ID token must not satisfy a verifier demanding an access token.
	if _, err := crypto.VerifyJWTWithOptions(resp.IDToken, keys, crypto.VerifyOptions{
		ExpectedTokenUse: models.TokenUseAccess,
	}); err == nil {
		t.Error("an ID token was accepted where an access token was required")
	}
}

func TestAuthorizationCodeIsSingleUse(t *testing.T) {
	engine, store := newEngine(t)
	seedApp(t, store, publicApp())
	code := completeLogin(t, engine)

	req := idp.TokenRequest{
		GrantType:      idp.GrantAuthorizationCode,
		OrganizationID: "acme",
		ClientID:       "spa-client",
		Code:           code,
		RedirectURI:    "https://spa.example.test/callback",
		CodeVerifier:   verifier,
	}

	if _, err := engine.ExchangeCodeForToken(context.Background(), req); err != nil {
		t.Fatalf("first redemption should succeed: %v", err)
	}
	if _, err := engine.ExchangeCodeForToken(context.Background(), req); err == nil {
		t.Fatal("replaying an authorization code must fail")
	}
}

// TestConcurrentRedemptionYieldsOneWinner is the regression test for the
// read-then-delete race: two nodes redeeming the same code concurrently both used
// to succeed and mint two token sets from one authorization.
func TestConcurrentRedemptionYieldsOneWinner(t *testing.T) {
	engine, store := newEngine(t)
	seedApp(t, store, publicApp())
	code := completeLogin(t, engine)

	const racers = 8
	var wg sync.WaitGroup
	results := make([]error, racers)

	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(slot int) {
			defer wg.Done()
			_, err := engine.ExchangeCodeForToken(context.Background(), idp.TokenRequest{
				GrantType:      idp.GrantAuthorizationCode,
				OrganizationID: "acme",
				ClientID:       "spa-client",
				Code:           code,
				RedirectURI:    "https://spa.example.test/callback",
				CodeVerifier:   verifier,
			})
			results[slot] = err
		}(i)
	}
	wg.Wait()

	succeeded := 0
	for _, err := range results {
		if err == nil {
			succeeded++
		}
	}
	if succeeded != 1 {
		t.Fatalf("expected exactly one concurrent redemption to succeed, got %d", succeeded)
	}
}

func TestRefreshTokenRotatesAndCannotBeReused(t *testing.T) {
	engine, store := newEngine(t)
	seedApp(t, store, publicApp())
	code := completeLogin(t, engine)

	first, err := engine.ExchangeCodeForToken(context.Background(), idp.TokenRequest{
		GrantType:      idp.GrantAuthorizationCode,
		OrganizationID: "acme",
		ClientID:       "spa-client",
		Code:           code,
		RedirectURI:    "https://spa.example.test/callback",
		CodeVerifier:   verifier,
	})
	if err != nil {
		t.Fatalf("token exchange failed: %v", err)
	}

	refreshReq := idp.TokenRequest{
		GrantType:      idp.GrantRefreshToken,
		OrganizationID: "acme",
		ClientID:       "spa-client",
		RefreshToken:   first.RefreshToken,
	}

	rotated, err := engine.ExchangeCodeForToken(context.Background(), refreshReq)
	if err != nil {
		t.Fatalf("refresh should succeed: %v", err)
	}
	if rotated.RefreshToken == first.RefreshToken {
		t.Fatal("refresh token was not rotated")
	}

	if _, err := engine.ExchangeCodeForToken(context.Background(), refreshReq); err == nil {
		t.Fatal("reusing a spent refresh token must fail")
	}
}

func TestIssuerResolverOverridesDefault(t *testing.T) {
	engine, _ := newEngine(t)
	if got := engine.IssuerFor("acme"); got != "https://acme.example.test" {
		t.Fatalf("expected the injected resolver to win, got %q", got)
	}

	engine.SetIssuerResolver(nil)
	if got := engine.IssuerFor("acme"); !strings.Contains(got, "acme") {
		t.Fatalf("default issuer should still identify the tenant, got %q", got)
	}
}

func TestIDPNotEnabledForAppRejected(t *testing.T) {
	engine, store := newEngine(t)
	app := publicApp()
	app.AllowedIDPs = []string{"mock"}
	seedApp(t, store, app)

	_, err := engine.PrepareAuthorization(context.Background(), idp.AuthorizationRequest{
		ServerBaseURL:       "https://acme.example.test",
		OrganizationID:      "acme",
		ClientID:            "spa-client",
		RedirectURI:         "https://spa.example.test/callback",
		IDPID:               "some-other-idp",
		CodeChallenge:       crypto.S256Challenge(verifier),
		CodeChallengeMethod: "S256",
	})
	if err == nil {
		t.Fatal("expected an IDP outside the app's allow-list to be rejected")
	}
}
