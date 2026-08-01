package api

import (
	"encoding/json"
	"net/http"

	"authpole/pkg/auth"
	"authpole/pkg/cache"
	"authpole/pkg/idp"
	"authpole/pkg/storage"
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
	validator := auth.NewTokenValidator(c)

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
	s.mux.HandleFunc("/tenants/", func(w http.ResponseWriter, r *http.Request) {
		if len(r.URL.Path) >= 20 && r.URL.Path[len(r.URL.Path)-16:] == ".well-known/jwks.json" {
			s.oidc.JWKS(w, r)
			return
		}
		if len(r.URL.Path) >= 30 && r.URL.Path[len(r.URL.Path)-25:] == ".well-known/spiffe-bundle.json" {
			s.spiffe.TrustBundle(w, r)
			return
		}
		http.NotFound(w, r)
	})

	s.mux.HandleFunc("/oauth/v2/authorize", s.oidc.Authorize)
	s.mux.HandleFunc("/oauth/v2/token", s.oidc.Token)
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
		tenantID := r.Header.Get("X-Tenant-ID")
		if tenantID == "" {
			tenantID = "default"
		}
		appID := r.Header.Get("X-App-ID")

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, `{"error":"unauthorized","message":"missing bearer token"}`, http.StatusUnauthorized)
			return
		}

		tokenStr := authHeader
		if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
			tokenStr = authHeader[7:]
		}

		claims, err := s.validator.ValidateToken(tenantID, appID, tokenStr)
		if err != nil {
			http.Error(w, `{"error":"invalid_token","message":"`+err.Error()+`"}`, http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"valid":  true,
			"claims": claims,
		})
	})

	// Admin Console REST APIs (CAS Versioned)
	s.mux.HandleFunc("/api/v1/tenants", s.admin.HandleTenants)
	s.mux.HandleFunc("/api/v1/tenants/", s.admin.HandleTenants)
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

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}
