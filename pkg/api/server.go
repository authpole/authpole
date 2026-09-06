package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/authpole/authpole/pkg/auth"
	"github.com/authpole/authpole/pkg/cache"
	"github.com/authpole/authpole/pkg/idp"
	"github.com/authpole/authpole/pkg/models"
	"github.com/authpole/authpole/pkg/storage"
)

type Server struct {
	storage   storage.Storage
	cache     *cache.MemoryCache
	idpEngine *idp.IDPEngine
	oidc      *OIDCHandler
	admin     *AdminHandler
	spiffe    *SPIFFEHandler
	validator *auth.TokenValidator
	mux       *http.ServeMux
}

func NewServer(store storage.Storage, c *cache.MemoryCache) *Server {
	engine := idp.NewIDPEngine(store, c)
	admin := NewAdminHandler(store, c)
	oidc := NewOIDCHandler(store, c, engine, admin)
	spiffe := NewSPIFFEHandler(store, c, admin)
	// The engine doubles as the validator's key source, so a node that has just
	// started can fetch verification keys on demand instead of rejecting every
	// token until its cache happens to be warmed.
	validator := auth.NewTokenValidatorWithSource(c, engine)

	s := &Server{
		storage:   store,
		cache:     c,
		idpEngine: engine,
		oidc:      oidc,
		admin:     admin,
		spiffe:    spiffe,
		validator: validator,
		mux:       http.NewServeMux(),
	}

	s.routes()
	return s
}

func (s *Server) routes() {
	// OIDC Protocol Endpoints
	s.mux.HandleFunc("/.well-known/openid-configuration", s.oidc.WellKnownConfig)
	s.mux.HandleFunc("/.well-known/jwks.json", s.oidc.JWKS)

	orgSubHandler := func(w http.ResponseWriter, r *http.Request) {
		if len(r.URL.Path) >= 20 && r.URL.Path[len(r.URL.Path)-16:] == ".well-known/jwks.json" {
			s.oidc.JWKS(w, r)
			return
		}
		if len(r.URL.Path) >= 30 && r.URL.Path[len(r.URL.Path)-25:] == ".well-known/spiffe-bundle.json" {
			s.spiffe.TrustBundle(w, r)
			return
		}
		http.NotFound(w, r)
	}
	s.mux.HandleFunc("/organizations/", orgSubHandler)
	s.mux.HandleFunc("/tenants/", orgSubHandler)

	s.mux.HandleFunc("/oauth/v2/authorize", s.oidc.Authorize)
	s.mux.HandleFunc("/oauth/v2/token", s.oidc.Token)
	s.mux.HandleFunc("/oauth/v2/callback", s.oidc.Callback)
	s.mux.HandleFunc("/oauth/v2/mock_login", s.oidc.MockLogin)

	// Machine-to-Machine (M2M) & SPIFFE Provider Endpoints
	s.mux.HandleFunc("/api/v1/spiffe/svid", s.spiffe.IssueSVID)
	s.mux.HandleFunc("/spiffe/v1/svid", s.spiffe.IssueSVID)
	s.mux.HandleFunc("/.well-known/spiffe/bundle", s.spiffe.TrustBundle)

	// High-Performance Access Path Token Verification API
	s.mux.HandleFunc("/api/v1/auth/validate", func(w http.ResponseWriter, r *http.Request) {
		if s.admin.EnableCORS(w, r) {
			return
		}
		orgID := r.Header.Get("X-Organization-ID")
		if orgID == "" {
			orgID = r.Header.Get("X-Tenant-ID")
		}
		if orgID == "" {
			orgID = "default"
		}
		appID := r.Header.Get("X-App-ID")

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, `{"error":"unauthorized","message":"missing bearer token"}`, http.StatusUnauthorized)
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

		// A resource server asks this endpoint "may I trust this token for MY api?",
		// which cannot be answered without knowing which audience it is asking about.
		// X-Expected-Audience is therefore required: answering `valid: true` from a
		// signature check alone would let any token minted anywhere in the tenant
		// pass as authorization for every service in it.
		audience := r.Header.Get("X-Expected-Audience")
		if audience == "" {
			http.Error(w, `{"error":"invalid_request","message":"X-Expected-Audience header is required"}`, http.StatusBadRequest)
			return
		}

		claims, err := s.validator.Validate(r.Context(), orgID, appID, tokenStr, auth.Options{
			Issuer:   s.idpEngine.IssuerFor(orgID),
			Audience: audience,
			TokenUse: models.TokenUseAccess,
		})
		if err != nil {
			status := http.StatusUnauthorized
			if errors.Is(err, auth.ErrNoKeysAvailable) {
				status = http.StatusServiceUnavailable
			}
			http.Error(w, `{"error":"invalid_token","message":"token rejected"}`, status)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"valid":  true,
			"claims": claims,
		})
	})

	// Admin Console REST APIs (CAS Versioned)
	s.mux.HandleFunc("/api/v1/user/organizations", s.admin.HandleUserOrganizations)
	s.mux.HandleFunc("/api/v1/organizations", s.admin.HandleOrganizations)
	s.mux.HandleFunc("/api/v1/organizations/", s.admin.HandleOrganizations)
	s.mux.HandleFunc("/api/v1/tenants", s.admin.HandleOrganizations)
	s.mux.HandleFunc("/api/v1/tenants/", s.admin.HandleOrganizations)
	s.mux.HandleFunc("/api/v1/apps", s.admin.HandleApps)
	s.mux.HandleFunc("/api/v1/apps/", s.admin.HandleApps)
	s.mux.HandleFunc("/api/v1/idps", s.admin.HandleIDPs)
	s.mux.HandleFunc("/api/v1/idps/", s.admin.HandleIDPs)
	s.mux.HandleFunc("/api/v1/keys", s.admin.HandleKeys)
	s.mux.HandleFunc("/api/v1/admin/users", s.admin.HandleAdminUsers)
	s.mux.HandleFunc("/api/v1/admin/users/", s.admin.HandleAdminUsers)
	s.mux.HandleFunc("/api/v1/admin/teams", s.admin.HandleTeams)
	s.mux.HandleFunc("/api/v1/admin/roles", s.admin.HandleRoles)
	s.mux.HandleFunc("/api/v1/admin/spiffe/workloads", s.spiffe.HandleWorkloads)
	s.mux.HandleFunc("/api/v1/admin/spiffe/workloads/", s.spiffe.HandleWorkloads)

	// Health check
	s.mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if s.admin.EnableCORS(w, r) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","service":"authpole"}`))
	})
}

// publicReadPaths are safe to expose to any origin: they return only public
// verification material and protocol metadata, no caller-specific data.
var publicReadPaths = map[string]bool{
	"/.well-known/openid-configuration": true,
	"/.well-known/jwks.json":            true,
	"/.well-known/spiffe/bundle":        true,
	"/healthz":                          true,
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.applyCORS(w, r)

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	s.mux.ServeHTTP(w, r)
}

// IDPEngine exposes the engine backing this server so an embedding host can
// install its own issuer resolver and reuse the engine as a token key source.
func (s *Server) IDPEngine() *idp.IDPEngine { return s.idpEngine }

// Validator exposes the server's token validator.
func (s *Server) Validator() *auth.TokenValidator { return s.validator }

// applyCORS decides the cross-origin policy for a request.
//
// The previous behaviour set `Access-Control-Allow-Origin: *` on every route,
// including /oauth/v2/token. A wildcard there means any web page can drive a token
// redemption or a validation probe from a visitor's browser. Discovery and JWKS
// are genuinely public and stay wildcard-open; everything else reflects only an
// origin registered on the tenant's application, which is what makes the browser
// refuse the cross-site call instead of us.
func (s *Server) applyCORS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers",
		"Content-Type, Authorization, X-Expected-Version, X-Organization-ID, X-Tenant-ID, X-Admin-Token, X-App-ID, X-Expected-Audience")

	if publicReadPaths[r.URL.Path] || strings.HasSuffix(r.URL.Path, "/.well-known/jwks.json") {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		return
	}

	origin := r.Header.Get("Origin")
	if origin == "" {
		// Not a browser cross-origin request; nothing to negotiate.
		return
	}

	if s.originAllowed(r, origin) {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		// Vary is required whenever the header depends on the request, or a shared
		// cache will serve one tenant's allowed origin to another's request.
		w.Header().Add("Vary", "Origin")
	}
}

// originAllowed reports whether origin is registered on an application in the
// tenant addressed by this request.
func (s *Server) originAllowed(r *http.Request, origin string) bool {
	orgID := r.Header.Get("X-Organization-ID")
	if orgID == "" {
		orgID = r.Header.Get("X-Tenant-ID")
	}
	if orgID == "" {
		orgID = r.URL.Query().Get("organization")
	}
	if orgID == "" {
		orgID = r.FormValue("organization")
	}
	if orgID == "" {
		return false
	}

	clientID := r.URL.Query().Get("client_id")
	if clientID == "" {
		clientID = r.FormValue("client_id")
	}

	// With a client_id we can check exactly one app's registered origins.
	if clientID != "" {
		if rec, err := s.storage.Get(r.Context(), storage.AppKey(orgID, clientID)); err == nil {
			var app models.Application
			if json.Unmarshal(rec.Data, &app) == nil {
				return app.HasAllowedOrigin(origin)
			}
		}
		return false
	}

	// Otherwise fall back to any app in the tenant that registered this origin.
	list, err := s.storage.List(r.Context(), fmt.Sprintf("organizations/%s/apps/", orgID))
	if err != nil {
		return false
	}
	for _, rec := range list {
		var app models.Application
		if json.Unmarshal(rec.Data, &app) != nil {
			continue
		}
		if app.HasAllowedOrigin(origin) {
			return true
		}
	}
	return false
}
