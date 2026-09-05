package idp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/authpole/authpole/pkg/cache"
	"github.com/authpole/authpole/pkg/crypto"
	"github.com/authpole/authpole/pkg/idp"
	"github.com/authpole/authpole/pkg/models"
	"github.com/authpole/authpole/pkg/storage"
)

// upstream stands in for a tenant-registered OAuth2/OIDC provider.
func upstream(t *testing.T, profile map[string]any, emails []map[string]any) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "upstream-access-token",
			"token_type":   "Bearer",
		})
	})

	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer upstream-access-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(profile)
	})

	mux.HandleFunc("/emails", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(emails)
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

// seedCustomProvider registers an app plus a fully custom upstream provider.
func seedCustomProvider(t *testing.T, store storage.Storage, provider *models.IdentityProvider) *models.Application {
	t.Helper()
	ctx := context.Background()

	app := publicApp()
	app.AllowedIDPs = []string{provider.ID}

	appPayload, err := json.Marshal(app)
	if err != nil {
		t.Fatalf("encode app: %v", err)
	}
	if _, err := store.Put(ctx, storage.AppKey(app.OrganizationID, app.ClientID), appPayload, ""); err != nil {
		t.Fatalf("seed app: %v", err)
	}

	idpPayload, err := json.Marshal(provider)
	if err != nil {
		t.Fatalf("encode idp: %v", err)
	}
	if _, err := store.Put(ctx, storage.IDPKey(app.OrganizationID, provider.ID), idpPayload, ""); err != nil {
		t.Fatalf("seed idp: %v", err)
	}
	return app
}

// runCallback drives authorize -> upstream callback and returns the client redirect.
func runCallback(t *testing.T, engine *idp.IDPEngine, idpID string) (string, error) {
	t.Helper()
	state, err := authorize(t, engine, idp.AuthorizationRequest{
		ServerBaseURL:       "https://acme.example.test",
		OrganizationID:      "acme",
		ClientID:            "spa-client",
		RedirectURI:         "https://spa.example.test/callback",
		IDPID:               idpID,
		CodeChallenge:       pkceChallenge,
		CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatalf("authorize failed: %v", err)
	}
	return engine.ProcessUpstreamCallback(context.Background(), "https://acme.example.test", state, "upstream-code")
}

// RFC 7636 Appendix B pair, reused so the verifier and challenge always agree.
const (
	pkceVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	pkceChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

// federatedClaims runs a full federated login and returns the claims that ended up
// inside the issued access token - i.e. the identity Auth Pole actually captured.
func federatedClaims(t *testing.T, engine *idp.IDPEngine, idpID string) *models.AuthClaims {
	t.Helper()

	redirect, err := runCallback(t, engine, idpID)
	if err != nil {
		t.Fatalf("callback failed: %v", err)
	}

	idx := strings.Index(redirect, "code=")
	if idx < 0 {
		t.Fatalf("no authorization code in redirect: %s", redirect)
	}
	code := redirect[idx+len("code="):]
	if amp := strings.Index(code, "&"); amp >= 0 {
		code = code[:amp]
	}

	resp, err := engine.ExchangeCodeForToken(context.Background(), idp.TokenRequest{
		GrantType:      idp.GrantAuthorizationCode,
		OrganizationID: "acme",
		ClientID:       "spa-client",
		Code:           code,
		RedirectURI:    "https://spa.example.test/callback",
		CodeVerifier:   pkceVerifier,
	})
	if err != nil {
		t.Fatalf("token exchange failed: %v", err)
	}

	keys, err := engine.SigningKeys(context.Background(), "acme", "app_spa")
	if err != nil {
		t.Fatalf("load verification keys: %v", err)
	}

	claims, err := crypto.VerifyJWTWithOptions(resp.AccessToken, keys, crypto.VerifyOptions{
		ExpectedIssuer:   "https://acme.example.test",
		ExpectedAudience: "spa-client",
		ExpectedTokenUse: models.TokenUseAccess,
	})
	if err != nil {
		t.Fatalf("access token failed verification: %v", err)
	}
	return claims
}

func newEngineWithStore(t *testing.T) (*idp.IDPEngine, storage.Storage) {
	t.Helper()
	store, err := storage.NewMemoryStorage()
	if err != nil {
		t.Fatalf("memory storage: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	engine := idp.NewIDPEngine(store, cache.NewMemoryCache())
	engine.SetIssuerResolver(func(orgID string) string { return "https://" + orgID + ".example.test" })
	return engine, store
}

// TestCustomProviderIdentityIsRead is the regression test for the old stub that
// gave every user of a non-preset provider the identical subject "<idp>_user".
func TestCustomProviderIdentityIsRead(t *testing.T) {
	server := upstream(t, map[string]any{
		"user_id":    "abc-123",
		"mail":       "person@corp.test",
		"full_name":  "Real Person",
		"login_name": "rperson",
	}, nil)

	engine, store := newEngineWithStore(t)
	seedCustomProvider(t, store, &models.IdentityProvider{
		ID:             "corp-okta",
		OrganizationID: "acme",
		Name:           "Corp Okta",
		Type:           "oidc",
		ClientID:       "corp-client",
		ClientSecret:   "corp-secret",
		AuthorizeURL:   server.URL + "/authorize",
		TokenURL:       server.URL + "/token",
		UserInfoURL:    server.URL + "/userinfo",
		Enabled:        true,
		ClaimMapping: models.ClaimMapping{
			Subject:  "user_id",
			Email:    "mail",
			Name:     "full_name",
			Username: "login_name",
		},
	})

	claims := federatedClaims(t, engine, "corp-okta")

	if claims.UpstreamSubject != "abc-123" {
		t.Errorf("expected upstream subject abc-123, got %q", claims.UpstreamSubject)
	}
	if claims.Subject != "corp-okta_abc-123" {
		t.Errorf("expected namespaced subject, got %q", claims.Subject)
	}
	if claims.Email != "person@corp.test" {
		t.Errorf("expected mapped email, got %q", claims.Email)
	}
	if claims.Name != "Real Person" {
		t.Errorf("expected mapped name, got %q", claims.Name)
	}
	if claims.PreferredUser != "rperson" {
		t.Errorf("expected mapped username, got %q", claims.PreferredUser)
	}
}

// TestNumericSubjectIsNotMangled covers GitHub/Facebook numeric IDs, which decode
// as float64 and would render in scientific notation via %v.
func TestNumericSubjectIsNotMangled(t *testing.T) {
	server := upstream(t, map[string]any{
		"id":    float64(1330196780),
		"login": "octocat",
		"name":  "The Octocat",
		"email": "octo@github.test",
	}, nil)

	engine, store := newEngineWithStore(t)
	seedCustomProvider(t, store, &models.IdentityProvider{
		ID:             "github",
		OrganizationID: "acme",
		Name:           "GitHub",
		Preset:         "github",
		ClientID:       "gh-client",
		ClientSecret:   "gh-secret",
		AuthorizeURL:   server.URL + "/authorize",
		TokenURL:       server.URL + "/token",
		UserInfoURL:    server.URL + "/userinfo",
		Enabled:        true,
	})

	// A mangled float would have produced "1.33019678e+09" and permanently keyed the
	// account on a corrupted identifier.
	claims := federatedClaims(t, engine, "github")
	if claims.UpstreamSubject != "1330196780" {
		t.Fatalf("numeric subject was mangled: %q", claims.UpstreamSubject)
	}
}

func TestMissingSubjectMappingIsRejected(t *testing.T) {
	server := upstream(t, map[string]any{"email": "nobody@corp.test"}, nil)

	engine, store := newEngineWithStore(t)
	seedCustomProvider(t, store, &models.IdentityProvider{
		ID:             "broken",
		OrganizationID: "acme",
		Name:           "Broken",
		Type:           "oauth2",
		ClientID:       "c",
		ClientSecret:   "s",
		AuthorizeURL:   server.URL + "/authorize",
		TokenURL:       server.URL + "/token",
		UserInfoURL:    server.URL + "/userinfo",
		Enabled:        true,
		ClaimMapping:   models.ClaimMapping{Subject: "user_id"},
	})

	_, err := runCallback(t, engine, "broken")
	if err == nil {
		t.Fatal("expected a provider returning no subject to be rejected, not given a fabricated identity")
	}
	if !strings.Contains(err.Error(), "subject") {
		t.Fatalf("expected a subject-related error, got: %v", err)
	}
}

func TestUnverifiedEmailIsRejected(t *testing.T) {
	server := upstream(t, map[string]any{
		"sub":            "u-1",
		"email":          "spoofed@victim.test",
		"email_verified": false,
		"name":           "Spoofer",
	}, nil)

	engine, store := newEngineWithStore(t)
	seedCustomProvider(t, store, &models.IdentityProvider{
		ID:             "google",
		OrganizationID: "acme",
		Name:           "Google",
		Preset:         "google",
		ClientID:       "g",
		ClientSecret:   "s",
		AuthorizeURL:   server.URL + "/authorize",
		TokenURL:       server.URL + "/token",
		UserInfoURL:    server.URL + "/userinfo",
		Enabled:        true,
	})

	if _, err := runCallback(t, engine, "google"); err == nil {
		t.Fatal("expected an unverified email address to be refused")
	}
}

func TestSecondaryEmailEndpointRequiresVerified(t *testing.T) {
	server := upstream(t,
		map[string]any{"id": "77", "login": "priv", "name": "Private"},
		[]map[string]any{
			{"email": "unverified@x.test", "primary": true, "verified": false},
			{"email": "verified@x.test", "primary": false, "verified": true},
		},
	)

	engine, store := newEngineWithStore(t)
	seedCustomProvider(t, store, &models.IdentityProvider{
		ID:             "github",
		OrganizationID: "acme",
		Name:           "GitHub",
		Preset:         "github",
		ClientID:       "g",
		ClientSecret:   "s",
		AuthorizeURL:   server.URL + "/authorize",
		TokenURL:       server.URL + "/token",
		UserInfoURL:    server.URL + "/userinfo",
		EmailsURL:      server.URL + "/emails",
		Enabled:        true,
	})

	claims := federatedClaims(t, engine, "github")
	if claims.Email != "verified@x.test" {
		t.Fatalf("expected the verified address to win, got %q", claims.Email)
	}
}

func TestPresetsCoverRequestedProviders(t *testing.T) {
	for _, name := range []string{"google", "github", "microsoft", "facebook", "instagram"} {
		preset, ok := idp.PresetFor(name)
		if !ok {
			t.Errorf("missing preset for %q", name)
			continue
		}
		if preset.AuthorizeURL == "" || preset.TokenURL == "" {
			t.Errorf("preset %q is missing endpoints", name)
		}
		if preset.Mapping.Subject == "" {
			t.Errorf("preset %q has no subject mapping", name)
		}
	}
}
