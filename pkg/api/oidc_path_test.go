package api_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/authpole/authpole"
	"github.com/authpole/authpole/pkg/api"
	"github.com/authpole/authpole/pkg/cache"
	"github.com/authpole/authpole/pkg/crypto"
	"github.com/authpole/authpole/pkg/models"
	"github.com/authpole/authpole/pkg/storage"
)

func TestOrganizationScopedOIDCEndpoints(t *testing.T) {
	store, err := storage.NewMemoryStorage()
	if err != nil {
		t.Fatalf("memory storage: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	memCache := cache.NewMemoryCache()
	srv := api.NewServer(store, memCache)
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)

	srv.IDPEngine().SetIssuerResolver(func(orgID string) string {
		return ts.URL + "/organizations/" + orgID
	})

	ctx := context.Background()
	app := &models.Application{
		ID:             "swiish_portal",
		OrganizationID: "acme",
		Name:           "Swiish Portal",
		ClientID:       "swiish_portal",
		ClientSecret:   "portal-secret",
		RedirectURIs:   []string{"https://portal.swii.sh/_swiish/callback"},
		AllowedIDPs:    []string{"mock_id[118;1:3up"},
		Scopes:         []string{"openid", "profile", "email"},
	}
	appBytes, _ := json.Marshal(app)
	if _, err := store.Put(ctx, storage.AppKey("acme", "swiish_portal"), appBytes, ""); err != nil {
		t.Fatalf("seed app: %v", err)
	}

	mockIDP := &models.IdentityProvider{
		ID:             "mock_idp",
		OrganizationID: "acme",
		Name:           "Mock IDP",
		Type:           "mock",
		ClientID:       "mock",
		AuthorizeURL:   ts.URL + "/oauth/v2/mock_login",
		Enabled:        true,
	}
	idpBytes, _ := json.Marshal(mockIDP)
	if _, err := store.Put(ctx, storage.IDPKey("acme", "mock_idp"), idpBytes, ""); err != nil {
		t.Fatalf("seed idp: %v", err)
	}

	// 1. Discovery at /organizations/acme/.well-known/openid-configuration
	resp, err := http.Get(ts.URL + "/organizations/acme/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("discovery get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery status = %d", resp.StatusCode)
	}

	var disc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	if disc["issuer"] != ts.URL+"/organizations/acme" {
		t.Fatalf("unexpected issuer: %v", disc["issuer"])
	}
	authEndpoint, _ := disc["authorization_endpoint"].(string)
	tokenEndpoint, _ := disc["token_endpoint"].(string)
	jwksURI, _ := disc["jwks_uri"].(string)
	if authEndpoint != ts.URL+"/organizations/acme/oauth/v2/authorize" {
		t.Fatalf("unexpected authorization_endpoint: %s", authEndpoint)
	}
	if tokenEndpoint != ts.URL+"/organizations/acme/oauth/v2/token" {
		t.Fatalf("unexpected token_endpoint: %s", tokenEndpoint)
	}
	if jwksURI != ts.URL+"/organizations/acme/.well-known/jwks.json" {
		t.Fatalf("unexpected jwks_uri: %s", jwksURI)
	}

	// 2. JWKS at /organizations/acme/.well-known/jwks.json
	jwksResp, err := http.Get(jwksURI)
	if err != nil {
		t.Fatalf("jwks get: %v", err)
	}
	defer jwksResp.Body.Close()
	if jwksResp.StatusCode != http.StatusOK {
		t.Fatalf("jwks status = %d", jwksResp.StatusCode)
	}
	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.NewDecoder(jwksResp.Body).Decode(&jwks); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	if len(jwks.Keys) == 0 {
		t.Fatal("expected JWKS keys for org acme")
	}

	// 3. Full authorization code + PKCE S256 flow via org-scoped endpoints
	verifier := "test-pkce-verifier-with-sufficient-entropy-0123456789abcdef"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	noRedirect := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	q := url.Values{}
	q.Set("client_id", "swiish_portal")
	q.Set("redirect_uri", "https://portal.swii.sh/_swiish/callback")
	q.Set("response_type", "code")
	q.Set("scope", "openid profile email")
	q.Set("state", "portal-state-1")
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")

	authResp, err := noRedirect.Get(authEndpoint + "?" + q.Encode())
	if err != nil {
		t.Fatalf("authorize get: %v", err)
	}
	authResp.Body.Close()
	if authResp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d", authResp.StatusCode)
	}

	loc, err := url.Parse(authResp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	internalState := loc.Query().Get("state")
	if internalState == "" {
		t.Fatal("expected internal state in mock_login redirect")
	}

	// Complete mock login
	mockForm := url.Values{}
	mockForm.Set("email", "alice@acme.test")
	mockForm.Set("name", "Alice")
	mockResp, err := noRedirect.PostForm(ts.URL+"/oauth/v2/mock_login?state="+url.QueryEscape(internalState), mockForm)
	if err != nil {
		t.Fatalf("mock_login post: %v", err)
	}
	mockResp.Body.Close()
	if mockResp.StatusCode != http.StatusFound {
		t.Fatalf("mock_login status = %d", mockResp.StatusCode)
	}

	cbLoc, err := url.Parse(mockResp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse callback redirect: %v", err)
	}
	code := cbLoc.Query().Get("code")
	if code == "" {
		t.Fatal("expected authorization code")
	}
	if cbLoc.Query().Get("state") != "portal-state-1" {
		t.Fatalf("expected state portal-state-1, got %q", cbLoc.Query().Get("state"))
	}

	// Exchange code at org-scoped token endpoint
	tokForm := url.Values{}
	tokForm.Set("grant_type", "authorization_code")
	tokForm.Set("code", code)
	tokForm.Set("redirect_uri", "https://portal.swii.sh/_swiish/callback")
	tokForm.Set("client_id", "swiish_portal")
	tokForm.Set("client_secret", "portal-secret")
	tokForm.Set("code_verifier", verifier)

	tokResp, err := http.Post(tokenEndpoint, "application/x-www-form-urlencoded", strings.NewReader(tokForm.Encode()))
	if err != nil {
		t.Fatalf("token post: %v", err)
	}
	defer tokResp.Body.Close()
	if tokResp.StatusCode != http.StatusOK {
		t.Fatalf("token status = %d", tokResp.StatusCode)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if err := json.NewDecoder(tokResp.Body).Decode(&tok); err != nil {
		t.Fatalf("decode token: %v", err)
	}
	if tok.AccessToken == "" || tok.IDToken == "" {
		t.Fatal("expected both access_token and id_token")
	}
}

func TestPathCannotOverrideHostPinnedTenant(t *testing.T) {
	store, err := storage.NewMemoryStorage()
	if err != nil {
		t.Fatalf("memory storage: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	provider, err := authpole.New(authpole.Config{
		Storage:        store,
		IssuerResolver: authpole.IssuerFromHostPattern("https://%s.example.test"),
		TenantResolver: authpole.TenantFromHost("example.test", "app", "admin"),
		RequireTenant:  true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ts := httptest.NewServer(provider.Handler())
	t.Cleanup(ts.Close)

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/organizations/globex/.well-known/openid-configuration", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = "acme.example.test"

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()

	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if doc["issuer"] != "https://acme.example.test" {
		t.Fatalf("path overrode host-pinned tenant: got issuer %v", doc["issuer"])
	}
}

func TestPublicPKCEUserTokenProvisionsPortalApp(t *testing.T) {
	store, err := storage.NewMemoryStorage()
	if err != nil {
		t.Fatalf("memory storage: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	srv := api.NewServer(store, cache.NewMemoryCache())
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)

	ctx := context.Background()
	swiishApp := &models.Application{
		ID:             "swiish",
		OrganizationID: "default",
		Name:           "swiish Portal Gateway",
		ClientID:       "swiish",
		RedirectURIs:   []string{"https://web.swii.sh/sh/authpole/callback"},
		AllowedIDPs:    []string{"mock_idp"},
		Scopes:         []string{"openid", "profile", "email"},
		Public:         true,
	}
	appBytes, _ := json.Marshal(swiishApp)
	if _, err := store.Put(ctx, storage.AppKey("default", "swiish"), appBytes, ""); err != nil {
		t.Fatalf("seed swiish app: %v", err)
	}

	mockIDP := &models.IdentityProvider{
		ID:             "mock_idp",
		OrganizationID: "default",
		Name:           "Mock IDP",
		Type:           "mock",
		ClientID:       "mock",
		AuthorizeURL:   ts.URL + "/oauth/v2/mock_login",
		Enabled:        true,
	}
	idpBytes, _ := json.Marshal(mockIDP)
	if _, err := store.Put(ctx, storage.IDPKey("default", "mock_idp"), idpBytes, ""); err != nil {
		t.Fatalf("seed mock idp: %v", err)
	}

	verifier := "swiish-public-pkce-verifier-with-enough-entropy-0123456789"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	noRedirect := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	q := url.Values{}
	q.Set("client_id", "swiish")
	q.Set("redirect_uri", "https://web.swii.sh/sh/authpole/callback")
	q.Set("response_type", "code")
	q.Set("scope", "openid profile email")
	q.Set("state", "st_1")
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")

	authResp, err := noRedirect.Get(ts.URL + "/oauth/v2/authorize?" + q.Encode())
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	authResp.Body.Close()
	if authResp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d", authResp.StatusCode)
	}

	loc, _ := url.Parse(authResp.Header.Get("Location"))
	internalState := loc.Query().Get("state")

	mockResp, err := noRedirect.PostForm(ts.URL+"/oauth/v2/mock_login?state="+url.QueryEscape(internalState), url.Values{
		"email": {"owner@swii.sh"},
		"name":  {"Portal Owner"},
	})
	if err != nil {
		t.Fatalf("mock_login: %v", err)
	}
	mockResp.Body.Close()
	cbLoc, _ := url.Parse(mockResp.Header.Get("Location"))
	code := cbLoc.Query().Get("code")

	tokForm := url.Values{}
	tokForm.Set("grant_type", "authorization_code")
	tokForm.Set("code", code)
	tokForm.Set("redirect_uri", "https://web.swii.sh/sh/authpole/callback")
	tokForm.Set("client_id", "swiish")
	tokForm.Set("code_verifier", verifier)

	tokResp, err := http.Post(ts.URL+"/oauth/v2/token", "application/x-www-form-urlencoded", strings.NewReader(tokForm.Encode()))
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer tokResp.Body.Close()
	if tokResp.StatusCode != http.StatusOK {
		t.Fatalf("token status = %d", tokResp.StatusCode)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(tokResp.Body).Decode(&tok); err != nil {
		t.Fatalf("decode token: %v", err)
	}

	// Provision a portal app in org "acme" using ONLY the user's OIDC access token
	portalReqBody := `{"id":"swiish_my_app","client_id":"swiish_my_app","client_secret":"s1","redirect_uris":["https://my-app.swii.sh/_swiish/callback"]}`
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/apps", strings.NewReader(portalReqBody))
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	req.Header.Set("X-Organization-ID", "acme")
	req.Header.Set("Content-Type", "application/json")

	appResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("provision app: %v", err)
	}
	defer appResp.Body.Close()
	if appResp.StatusCode != http.StatusOK {
		t.Fatalf("provision app status = %d", appResp.StatusCode)
	}
}

func TestPortalAppPlatformIDPFallbackAndJWKSCacheInvalidation(t *testing.T) {
	t.Setenv("AUTHPOLE_GITHUB_CLIENT_ID", "platform-gh-client")
	t.Setenv("AUTHPOLE_GITHUB_CLIENT_SECRET", "platform-gh-secret")

	store, err := storage.NewMemoryStorage()
	if err != nil {
		t.Fatalf("memory storage: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	srv := api.NewServer(store, cache.NewMemoryCache())
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)

	ctx := context.Background()

	// Seed a placeholder github IDP and an app-scoped demo_app key (matching legacy seedInitialData).
	placeholderGH, _ := json.Marshal(&models.IdentityProvider{
		ID:             "github",
		OrganizationID: "default",
		Name:           "GitHub Enterprise",
		Type:           "oauth2",
		ClientID:       "github_oauth_client_id",
		ClientSecret:   "github_oauth_client_secret",
		Enabled:        true,
	})
	_, _ = store.Put(ctx, storage.IDPKey("default", "github"), placeholderGH, "")

	demoKey, err := crypto.GenerateRSAKeyPair("default", "demo_app")
	if err != nil {
		t.Fatalf("demo key: %v", err)
	}
	dkBytes, _ := json.Marshal(demoKey)
	_, _ = store.Put(ctx, storage.KeyPairKey("default", demoKey.ID), dkBytes, "")

	// Seed a provisioned portal app (client_id != "swiish").
	portalApp, _ := json.Marshal(&models.Application{
		ID:             "swiish_demo_swii_sh",
		OrganizationID: "default",
		Name:           "Demo Portal",
		ClientID:       "swiish_demo_swii_sh",
		ClientSecret:   "portal-sec",
		RedirectURIs:   []string{"https://demo.swii.sh/_swiish/callback"},
		AllowedIDPs:    []string{"github", "mock_idp"},
		Scopes:         []string{"openid", "profile", "email"},
	})
	_, _ = store.Put(ctx, storage.AppKey("default", "swiish_demo_swii_sh"), portalApp, "")

	mockIDP, _ := json.Marshal(&models.IdentityProvider{
		ID:             "mock_idp",
		OrganizationID: "default",
		Name:           "Mock",
		Type:           "mock",
		ClientID:       "mock",
		AuthorizeURL:   ts.URL + "/oauth/v2/mock_login",
		Enabled:        true,
	})
	_, _ = store.Put(ctx, storage.IDPKey("default", "mock_idp"), mockIDP, "")

	// Warm the org-wide JWKS cache BEFORE any token is issued for swiish_demo_swii_sh.
	jwksBefore, err := http.Get(ts.URL + "/organizations/default/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("jwks before: %v", err)
	}
	jwksBefore.Body.Close()

	noRedirect := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// 1. Portal app with idp=github must fall back to AUTHPOLE_GITHUB_CLIENT_ID rather than failing on placeholder.
	ghQ := url.Values{
		"client_id":     {"swiish_demo_swii_sh"},
		"redirect_uri":  {"https://demo.swii.sh/_swiish/callback"},
		"response_type": {"code"},
		"scope":         {"openid profile email"},
		"state":         {"st_gh"},
		"idp":           {"github"},
	}
	ghResp, err := noRedirect.Get(ts.URL + "/oauth/v2/authorize?" + ghQ.Encode())
	if err != nil {
		t.Fatalf("authorize github: %v", err)
	}
	ghResp.Body.Close()
	if ghResp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 redirect to GitHub, got %d", ghResp.StatusCode)
	}
	if !strings.Contains(ghResp.Header.Get("Location"), "client_id=platform-gh-client") {
		t.Fatalf("expected redirect to use platform-gh-client, got %q", ghResp.Header.Get("Location"))
	}

	// 2. Issuing tokens for swiish_demo_swii_sh lazily generates a new app key and MUST invalidate org JWKS cache.
	mockQ := url.Values{
		"client_id":     {"swiish_demo_swii_sh"},
		"redirect_uri":  {"https://demo.swii.sh/_swiish/callback"},
		"response_type": {"code"},
		"scope":         {"openid profile email"},
		"state":         {"st_mock"},
		"idp":           {"mock_idp"},
	}
	mAuth, _ := noRedirect.Get(ts.URL + "/oauth/v2/authorize?" + mockQ.Encode())
	mAuth.Body.Close()
	loc, _ := url.Parse(mAuth.Header.Get("Location"))
	mLogin, _ := noRedirect.PostForm(ts.URL+"/oauth/v2/mock_login?state="+url.QueryEscape(loc.Query().Get("state")), url.Values{
		"email": {"u@example.com"},
		"name":  {"User"},
	})
	mLogin.Body.Close()
	cb, _ := url.Parse(mLogin.Header.Get("Location"))

	tokResp, err := http.PostForm(ts.URL+"/oauth/v2/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {cb.Query().Get("code")},
		"redirect_uri":  {"https://demo.swii.sh/_swiish/callback"},
		"client_id":     {"swiish_demo_swii_sh"},
		"client_secret": {"portal-sec"},
	})
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer tokResp.Body.Close()
	var tok struct {
		IDToken string `json:"id_token"`
	}
	_ = json.NewDecoder(tokResp.Body).Decode(&tok)
	if tok.IDToken == "" {
		t.Fatal("expected id_token")
	}

	// Re-fetching /.well-known/jwks.json immediately must now include the newly minted key!
	jwksAfterResp, err := http.Get(ts.URL + "/organizations/default/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("jwks after: %v", err)
	}
	defer jwksAfterResp.Body.Close()
	var jwksAfter struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	_ = json.NewDecoder(jwksAfterResp.Body).Decode(&jwksAfter)
	if len(jwksAfter.Keys) < 2 {
		t.Fatalf("expected org JWKS cache to be invalidated and return >=2 keys, got %d", len(jwksAfter.Keys))
	}
}
