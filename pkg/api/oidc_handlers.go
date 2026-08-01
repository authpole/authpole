package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"authpole/pkg/cache"
	"authpole/pkg/crypto"
	"authpole/pkg/idp"
	"authpole/pkg/models"
	"authpole/pkg/storage"
)

type OIDCHandler struct {
	storage storage.Storage
	cache   *cache.MemoryCache
	engine  *idp.IDPEngine
	admin   *AdminHandler
}

func NewOIDCHandler(store storage.Storage, c *cache.MemoryCache, eng *idp.IDPEngine, admin *AdminHandler) *OIDCHandler {
	return &OIDCHandler{
		storage: store,
		cache:   c,
		engine:  eng,
		admin:   admin,
	}
}

// WellKnownConfig handles standard OIDC Discovery endpoint: /.well-known/openid-configuration
func (h *OIDCHandler) WellKnownConfig(w http.ResponseWriter, r *http.Request) {
	if h.admin != nil && h.admin.EnableCORS(w, r) {
		return
	}

	tenantID := r.URL.Query().Get("tenant")
	if tenantID == "" {
		tenantID = "default"
	}

	issuer := fmt.Sprintf("https://authpole.io/tenants/%s", tenantID)

	config := map[string]interface{}{
		"issuer":                                issuer,
		"authorization_endpoint":                "/oauth/v2/authorize",
		"token_endpoint":                        "/oauth/v2/token",
		"userinfo_endpoint":                     "/oauth/v2/userinfo",
		"jwks_uri":                              fmt.Sprintf("/tenants/%s/.well-known/jwks.json", tenantID),
		"introspection_endpoint":                "/oauth/v2/introspect",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "email", "name", "tenant_id", "app_id"},
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(config)
}

// JWKS handles standard JSON Web Key Set endpoint: /.well-known/jwks.json and /tenants/{tenant}/.well-known/jwks.json
func (h *OIDCHandler) JWKS(w http.ResponseWriter, r *http.Request) {
	if h.admin != nil && h.admin.EnableCORS(w, r) {
		return
	}

	tenantID := r.URL.Query().Get("tenant")
	if tenantID == "" {
		tenantID = "default"
	}
	appID := r.URL.Query().Get("app_id")

	// Check cache
	cachedJWKS, found := h.cache.GetJWKS(tenantID, appID)
	if found {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_, _ = w.Write(cachedJWKS)
		return
	}

	// Fetch keys from storage
	list, err := h.storage.List(r.Context(), fmt.Sprintf("tenants/%s/keys/", tenantID))
	var keys []*models.SigningKey
	if err == nil {
		for _, rec := range list {
			var k models.SigningKey
			if err := json.Unmarshal(rec.Data, &k); err == nil && k.Active {
				if appID == "" || k.AppID == "" || k.AppID == appID {
					keys = append(keys, &k)
				}
			}
		}
	}

	if len(keys) == 0 {
		// Generate key if none exists
		newKey, err := crypto.GenerateRSAKeyPair(tenantID, appID)
		if err == nil {
			keyBytes, _ := json.Marshal(newKey)
			_, _ = h.storage.Put(r.Context(), storage.KeyPairKey(tenantID, newKey.ID), keyBytes, "")
			keys = append(keys, newKey)
		}
	}

	jwksBytes, err := crypto.BuildJWKS(keys)
	if err != nil {
		http.Error(w, `{"error":"server_error","message":"failed to build JWKS"}`, http.StatusInternalServerError)
		return
	}

	// Cache JWKS payload
	h.cache.SetJWKS(tenantID, appID, jwksBytes, 1*time.Minute)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(jwksBytes)
}

// Authorize handles OIDC authorization request: /oauth/v2/authorize
func (h *OIDCHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	if h.admin != nil && h.admin.EnableCORS(w, r) {
		return
	}

	tenantID := r.URL.Query().Get("tenant")
	if tenantID == "" {
		tenantID = "default"
	}

	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	scope := r.URL.Query().Get("scope")
	state := r.URL.Query().Get("state")
	idpID := r.URL.Query().Get("idp")

	if clientID == "" || redirectURI == "" {
		http.Error(w, `{"error":"invalid_request","message":"missing client_id or redirect_uri"}`, http.StatusBadRequest)
		return
	}

	redirectURL, err := h.engine.PrepareAuthorization(r.Context(), tenantID, clientID, redirectURI, scope, state, idpID)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"invalid_request","message":"%s"}`, err.Error()), http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// Token handles OIDC token exchange endpoint: /oauth/v2/token
func (h *OIDCHandler) Token(w http.ResponseWriter, r *http.Request) {
	if h.admin != nil && h.admin.EnableCORS(w, r) {
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"invalid_request","message":"method must be POST"}`, http.StatusMethodNotAllowed)
		return
	}

	_ = r.ParseForm()
	tenantID := r.FormValue("tenant")
	if tenantID == "" {
		tenantID = "default"
	}

	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")

	if code == "" || clientID == "" {
		http.Error(w, `{"error":"invalid_request","message":"missing code or client_id"}`, http.StatusBadRequest)
		return
	}

	resp, err := h.engine.ExchangeCodeForToken(r.Context(), tenantID, clientID, clientSecret, code, redirectURI)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"invalid_grant","message":"%s"}`, err.Error()), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// MockLogin handles developer testing mock login page: /oauth/v2/mock_login
func (h *OIDCHandler) MockLogin(w http.ResponseWriter, r *http.Request) {
	if h.admin != nil && h.admin.EnableCORS(w, r) {
		return
	}

	stateID := r.URL.Query().Get("state")

	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		email := r.FormValue("email")
		name := r.FormValue("name")

		claims := &models.AuthClaims{
			Subject:       fmt.Sprintf("usr_%d", time.Now().Unix()),
			Email:         email,
			Name:          name,
			PreferredUser: email,
			OriginalIDP:   "mock_idp",
			Roles:         []string{"user", "developer"},
		}

		redirectURL, err := h.engine.CompleteUpstreamAuthentication(stateID, claims)
		if err != nil {
			http.Error(w, fmt.Sprintf("Authentication error: %v", err), http.StatusBadRequest)
			return
		}

		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>Auth Pole - Federated Proxy Login</title>
<style>
body { font-family: -apple-system, sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
.card { background: rgba(30, 41, 59, 0.8); border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; padding: 2rem; width: 340px; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.5); }
h2 { font-size: 1.25rem; margin-top: 0; color: #38bdf8; }
input { width: 100%%; padding: 0.75rem; margin: 0.5rem 0 1rem; border-radius: 6px; border: 1px solid #334155; background: #0f172a; color: #fff; box-sizing: border-box; }
button { width: 100%%; padding: 0.75rem; background: linear-gradient(135deg, #0ea5e9, #6366f1); border: none; border-radius: 6px; color: white; font-weight: bold; cursor: pointer; }
</style>
</head>
<body>
<div class="card">
  <h2>⚡ Auth Pole Mediator Proxy</h2>
  <p style="font-size: 0.85rem; color: #94a3b8;">Simulating upstream IDP login authentication flow.</p>
  <form method="POST">
    <label>Email Address</label>
    <input type="email" name="email" value="alex.developer@example.com" required />
    <label>Full Name</label>
    <input type="text" name="name" value="Alex Developer" required />
    <button type="submit">Complete Authentication & Return to App</button>
  </form>
</div>
</body>
</html>`)
}
