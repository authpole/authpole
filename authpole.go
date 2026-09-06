// Package authpole embeds Auth Pole's mediator OIDC provider into a host
// application.
//
// The standalone server in cmd/server is one consumer of this package; a host that
// already owns its HTTP surface, its storage and its tenancy model is the other.
// The embedding contract is deliberately small:
//
//   - Storage is supplied by the host, so identity records live in whatever the
//     host already operates rather than a second database.
//   - TenantResolver decides which tenant a request belongs to. The default reads
//     a query parameter, which is fine for a single-tenant dev server and wrong for
//     anything multi-tenant: a client-supplied parameter must never select the
//     tenant whose data is returned. A host serving tenants on hostnames should
//     pass TenantFromHost.
//   - IssuerResolver decides each tenant's OIDC issuer. It must be the exact origin
//     that serves the tenant's discovery document and JWKS, or conformant clients
//     will reject the tokens.
//
// Nothing here starts a listener or reads global configuration; the host mounts
// Handler() wherever it wants.
package authpole

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/authpole/authpole/pkg/api"
	"github.com/authpole/authpole/pkg/auth"
	"github.com/authpole/authpole/pkg/cache"
	"github.com/authpole/authpole/pkg/idp"
	"github.com/authpole/authpole/pkg/models"
	"github.com/authpole/authpole/pkg/storage"
)

// TenantResolver maps an inbound request to a tenant (organization) ID. Returning
// an empty string means "no tenant could be determined", which callers must treat
// as a failure rather than silently substituting a default.
type TenantResolver func(r *http.Request) string

// Config configures an embedded Provider. Storage is required; everything else has
// a documented default.
type Config struct {
	// Storage persists organizations, apps, upstream IDPs, signing keys and the
	// short-lived artifacts of an authorization exchange. Required.
	Storage storage.Storage

	// Cache is an optional shared in-memory cache. One is created when nil.
	Cache *cache.MemoryCache

	// IssuerResolver returns a tenant's OIDC issuer identifier. Strongly
	// recommended: the default derives a path-based issuer under
	// AUTHPOLE_ISSUER_BASE_URL, which is unlikely to match a host's own origins.
	IssuerResolver idp.IssuerFunc

	// TenantResolver determines the tenant for a request. Defaults to
	// TenantFromQuery, which is only appropriate for single-tenant use.
	TenantResolver TenantResolver

	// RequireTenant refuses a request whose hostname does not identify a tenant,
	// instead of letting it fall through to the "default" tenant. Set it in a
	// multi-tenant deployment: serving the default tenant's issuer and JWKS on the
	// apex or on a reserved hostname advertises an issuer no client should use.
	RequireTenant bool
}

// Provider is an embedded Auth Pole instance.
type Provider struct {
	cfg       Config
	cache     *cache.MemoryCache
	engine    *idp.IDPEngine
	validator *auth.TokenValidator
	server    *api.Server
}

// ErrStorageRequired is returned when a Provider is constructed without storage.
var ErrStorageRequired = errors.New("authpole: Config.Storage is required")

// New builds an embedded Provider.
func New(cfg Config) (*Provider, error) {
	if cfg.Storage == nil {
		return nil, ErrStorageRequired
	}

	memCache := cfg.Cache
	if memCache == nil {
		memCache = cache.NewMemoryCache()
	}

	server := api.NewServer(cfg.Storage, memCache)
	engine := server.IDPEngine()
	if cfg.IssuerResolver != nil {
		engine.SetIssuerResolver(cfg.IssuerResolver)
	}

	if cfg.TenantResolver == nil {
		cfg.TenantResolver = TenantFromQuery
	}

	return &Provider{
		cfg:       cfg,
		cache:     memCache,
		engine:    engine,
		validator: auth.NewTokenValidatorWithSource(memCache, engine),
		server:    server,
	}, nil
}

// Handler returns the provider's HTTP surface: discovery, JWKS, authorize, token,
// the upstream callback, the admin API and the SPIFFE endpoints. Mount it wherever
// the host wants; it does not assume it owns the root.
//
// The returned handler applies the configured TenantResolver before the protocol
// handlers run. That is not a convenience: the handlers themselves read the tenant
// from an "organization" query parameter and fall back to "default", so a Provider
// that merely stored a resolver would serve the "default" tenant's issuer and JWKS
// on every hostname, and would let any caller pick a tenant by appending
// ?organization=<other>. Resolving here, and stripping the caller's own parameters,
// is what makes TenantResolver load-bearing rather than decorative.
func (p *Provider) Handler() http.Handler { return p.withResolvedTenant(p.server) }

// withResolvedTenant pins the resolved tenant onto the request and removes any
// tenant selector the caller supplied.
func (p *Provider) withResolvedTenant(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenant := p.cfg.TenantResolver(r)

		if tenant == "" && p.cfg.RequireTenant {
			// A multi-tenant deployment reached on a hostname that is not a tenant
			// (the apex, or a reserved label such as app.<domain>). Serving the
			// "default" tenant's metadata there would advertise an issuer nobody
			// should use, so refuse instead.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"unknown_tenant","message":"this hostname does not identify a tenant"}`))
			return
		}

		// Strip the caller-controlled selectors unconditionally, including when the
		// resolver found nothing: leaving them in place is precisely what would let
		// a client choose whose issuer and keys it is served.
		query := r.URL.Query()
		query.Del("organization")
		query.Del("tenant")
		if tenant != "" {
			query.Set("organization", tenant)
		}

		scoped := r.Clone(r.Context())
		scoped.URL.RawQuery = query.Encode()

		// Several handlers read the tenant from a header instead of the query.
		scoped.Header.Del("X-Organization-ID")
		scoped.Header.Del("X-Tenant-ID")
		if tenant != "" {
			scoped.Header.Set("X-Organization-ID", tenant)
		}

		next.ServeHTTP(w, scoped)
	})
}

// Validator verifies tokens this provider issued. It reads keys from the shared
// cache and falls back to storage, so a cold process does not reject valid tokens.
func (p *Provider) Validator() *auth.TokenValidator { return p.validator }

// Engine exposes the lower-level IDP engine for hosts that need to drive the
// authorization exchange directly rather than through HTTP.
func (p *Provider) Engine() *idp.IDPEngine { return p.engine }

// IssuerFor returns a tenant's issuer identifier - the value a resource server must
// pin when verifying that tenant's tokens.
func (p *Provider) IssuerFor(orgID string) string { return p.engine.IssuerFor(orgID) }

// TenantFor resolves the tenant for a request using the configured resolver.
func (p *Provider) TenantFor(r *http.Request) string { return p.cfg.TenantResolver(r) }

// VerifyAccessToken validates a bearer access token for one tenant and audience.
//
// This is the method a host's own request path should call: it demands the issuer,
// the audience and token_use=access, so a token minted for a different tenant, a
// different API, or as an ID token is refused.
func (p *Provider) VerifyAccessToken(ctx context.Context, orgID, audience, token string) (*models.AuthClaims, error) {
	if orgID == "" {
		return nil, errors.New("authpole: organization is required to verify a token")
	}
	if audience == "" {
		return nil, errors.New("authpole: audience is required to verify a token")
	}
	return p.validator.Validate(ctx, orgID, "", token, auth.Options{
		Issuer:   p.engine.IssuerFor(orgID),
		Audience: audience,
		TokenUse: models.TokenUseAccess,
	})
}

// IssueSVID mints a short-lived JWT-SVID for a registered workload.
//
// The caller MUST have proven possession of the certificate's private key before
// calling this - through a real mutual-TLS handshake - and passes only the
// resulting fingerprint. Nothing here can establish possession: a certificate is
// public, so a fingerprint the caller merely read is not authentication. An
// embedding host obtains that proof at its transport boundary (a terminated mTLS
// connection, or a CDN that terminated one and is itself authenticated) and calls
// this with the verified fingerprint.
func (p *Provider) IssueSVID(ctx context.Context, req idp.SVIDRequest) (*idp.SVIDResponse, error) {
	return p.engine.IssueSVID(ctx, req)
}

// TenantFromQuery reads the tenant from the "organization" (or "tenant") query
// parameter.
//
// Only safe when there is exactly one tenant. A query parameter is chosen by the
// caller, so in a multi-tenant deployment this lets any client ask for any tenant.
func TenantFromQuery(r *http.Request) string {
	if v := r.URL.Query().Get("organization"); v != "" {
		return v
	}
	return r.URL.Query().Get("tenant")
}

// TenantFromHost builds a resolver that derives the tenant from the request's
// hostname, given a base domain: "acme.example.com" with base "example.com" yields
// "acme".
//
// Prefer this in multi-tenant deployments. The Host header is still client-supplied,
// but it is what routed the request and what TLS was negotiated for, so it cannot be
// varied freely the way a query parameter can. Reserved labels are excluded so a
// system hostname such as app.example.com is never mistaken for a tenant.
func TenantFromHost(baseDomain string, reserved ...string) TenantResolver {
	base := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(baseDomain), "."))
	blocked := map[string]bool{}
	for _, label := range reserved {
		blocked[strings.ToLower(strings.TrimSpace(label))] = true
	}

	return func(r *http.Request) string {
		host := r.Host
		if host == "" {
			host = r.URL.Host
		}
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.ToLower(strings.TrimSpace(host))

		if base == "" || !strings.HasSuffix(host, "."+base) {
			return ""
		}
		label := strings.TrimSuffix(host, "."+base)
		// Only a single label is a tenant; "a.b.example.com" is not tenant "a.b".
		if label == "" || strings.Contains(label, ".") || blocked[label] {
			return ""
		}
		return label
	}
}

// IssuerFromHostPattern builds an issuer resolver from a pattern containing one
// "%s" placeholder for the tenant, e.g. "https://%s.example.com".
func IssuerFromHostPattern(pattern string) idp.IssuerFunc {
	return func(orgID string) string {
		if orgID == "" {
			return ""
		}
		return fmt.Sprintf(pattern, orgID)
	}
}
