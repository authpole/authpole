package authpole_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/authpole/authpole"
	"github.com/authpole/authpole/pkg/storage"
)

func newProvider(t *testing.T) *authpole.Provider {
	t.Helper()
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
	return provider
}

func TestStorageIsRequired(t *testing.T) {
	if _, err := authpole.New(authpole.Config{}); err == nil {
		t.Fatal("a Provider without storage must not be constructible")
	}
}

func TestIssuerResolverIsUsed(t *testing.T) {
	provider := newProvider(t)
	if got := provider.IssuerFor("acme"); got != "https://acme.example.test" {
		t.Fatalf("expected the configured issuer, got %q", got)
	}
}

// TestTenantFromHost covers the multi-tenant resolution rules. A tenant must be a
// single label under the base domain, and reserved system hostnames must never
// resolve to a tenant.
func TestTenantFromHost(t *testing.T) {
	resolve := authpole.TenantFromHost("example.test", "app", "admin")

	cases := []struct {
		host string
		want string
	}{
		{"acme.example.test", "acme"},
		{"acme.example.test:8443", "acme"},
		{"ACME.EXAMPLE.TEST", "acme"},
		// Reserved system hostnames are not tenants.
		{"app.example.test", ""},
		{"admin.example.test", ""},
		// The apex is not a tenant.
		{"example.test", ""},
		// Only a single label counts, so a nested host is not tenant "a.b".
		{"a.b.example.test", ""},
		// A different domain must never yield a tenant.
		{"acme.attacker.test", ""},
		{"", ""},
	}

	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = tc.host
		if got := resolve(req); got != tc.want {
			t.Errorf("host %q: expected tenant %q, got %q", tc.host, tc.want, got)
		}
	}
}

// TestQueryResolverIsSingleTenantOnly documents the default's limitation: it
// returns whatever the caller asked for, which is why TenantFromHost exists.
func TestQueryResolverIsSingleTenantOnly(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?organization=someone-elses-tenant", nil)
	if got := authpole.TenantFromQuery(req); got != "someone-elses-tenant" {
		t.Fatalf("expected the caller-supplied value, got %q", got)
	}
}

// TestDiscoveryServesHostDerivedIssuer is the regression test for a Provider that
// stored its TenantResolver without applying it. The handlers read the tenant from
// an "organization" query parameter and fall back to "default", so before the fix
// every hostname was served the "default" tenant's issuer - which a test that only
// asserted "issuer is non-empty", or that passed ?organization= explicitly, could
// not see.
func TestDiscoveryServesHostDerivedIssuer(t *testing.T) {
	provider := newProvider(t)

	server := httptest.NewServer(provider.Handler())
	t.Cleanup(server.Close)

	for _, tenant := range []string{"acme", "globex"} {
		doc := fetchDiscovery(t, server.URL, tenant+".example.test", "")
		want := "https://" + tenant + ".example.test"
		if doc["issuer"] != want {
			t.Errorf("host %s.example.test: issuer = %v, want %s", tenant, doc["issuer"], want)
		}
		// PKCE must be advertised or client libraries will not send a challenge.
		methods, ok := doc["code_challenge_methods_supported"].([]any)
		if !ok || len(methods) == 0 || methods[0] != "S256" {
			t.Errorf("expected S256 to be advertised, got %v", doc["code_challenge_methods_supported"])
		}
	}
}

// TestCallerCannotChooseTenant covers the isolation half of the same bug: with the
// selector left in place, ?organization=<other> on one tenant's hostname served
// that other tenant's issuer and keys.
func TestCallerCannotChooseTenant(t *testing.T) {
	provider := newProvider(t)

	server := httptest.NewServer(provider.Handler())
	t.Cleanup(server.Close)

	doc := fetchDiscovery(t, server.URL, "acme.example.test", "?organization=globex&tenant=globex")
	if doc["issuer"] != "https://acme.example.test" {
		t.Fatalf("caller-supplied tenant overrode the host: issuer = %v", doc["issuer"])
	}
}

// TestNonTenantHostIsRefused covers RequireTenant: the apex and reserved hostnames
// must not be served the default tenant's metadata.
func TestNonTenantHostIsRefused(t *testing.T) {
	provider := newProvider(t)

	server := httptest.NewServer(provider.Handler())
	t.Cleanup(server.Close)

	for _, host := range []string{"example.test", "app.example.test", "admin.example.test"} {
		req, err := http.NewRequest(http.MethodGet, server.URL+"/.well-known/openid-configuration", nil)
		if err != nil {
			t.Fatalf("request build failed: %v", err)
		}
		req.Host = host

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		_ = resp.Body.Close()

		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("host %s returned %d; a non-tenant hostname must not be served tenant metadata", host, resp.StatusCode)
		}
	}
}

// fetchDiscovery reads the discovery document as a client on the given hostname.
func fetchDiscovery(t *testing.T, base, host, query string) map[string]any {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, base+"/.well-known/openid-configuration"+query, nil)
	if err != nil {
		t.Fatalf("request build failed: %v", err)
	}
	req.Host = host

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("discovery request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("host %s: discovery status %d", host, resp.StatusCode)
	}

	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	return doc
}

func TestVerifyAccessTokenRequiresTenantAndAudience(t *testing.T) {
	provider := newProvider(t)
	ctx := t.Context()

	if _, err := provider.VerifyAccessToken(ctx, "", "api", "token"); err == nil {
		t.Error("verification without a tenant must fail closed")
	}
	if _, err := provider.VerifyAccessToken(ctx, "acme", "", "token"); err == nil {
		t.Error("verification without an audience must fail closed")
	}
}

func TestJWKSIsPubliclyReadable(t *testing.T) {
	provider := newProvider(t)

	server := httptest.NewServer(provider.Handler())
	t.Cleanup(server.Close)

	// Addressed by tenant hostname, not ?organization= - the caller-supplied
	// selector is stripped now, and RequireTenant refuses a non-tenant host.
	req, err := http.NewRequest(http.MethodGet, server.URL+"/.well-known/jwks.json", nil)
	if err != nil {
		t.Fatalf("request build failed: %v", err)
	}
	req.Host = "acme.example.test"

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("jwks request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from JWKS, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("JWKS must stay publicly readable, got origin header %q", got)
	}

	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	if len(jwks.Keys) == 0 {
		t.Fatal("expected at least one key to be published")
	}
	// A private key must never appear in JWKS.
	for _, key := range jwks.Keys {
		if _, leaked := key["d"]; leaked {
			t.Fatal("JWKS leaked private key material")
		}
	}
}

// TestTokenEndpointIsNotWildcardCORS guards the narrowed policy: a browser origin
// that is not registered on an app must not be granted access to /token.
func TestTokenEndpointIsNotWildcardCORS(t *testing.T) {
	provider := newProvider(t)

	server := httptest.NewServer(provider.Handler())
	t.Cleanup(server.Close)

	req, err := http.NewRequest(http.MethodOptions, server.URL+"/oauth/v2/token", nil)
	if err != nil {
		t.Fatalf("request build failed: %v", err)
	}
	// A real tenant hostname, so this exercises the CORS policy rather than the
	// unknown-tenant refusal.
	req.Host = "acme.example.test"
	req.Header.Set("Origin", "https://evil.example")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("preflight failed: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("token endpoint granted CORS to an unregistered origin: %q", got)
	}
}
