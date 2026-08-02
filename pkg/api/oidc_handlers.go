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

func (h *OIDCHandler) computeServerBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s", scheme, r.Host)
}

// WellKnownConfig handles standard OIDC Discovery endpoint: /.well-known/openid-configuration
func (h *OIDCHandler) WellKnownConfig(w http.ResponseWriter, r *http.Request) {
	if h.admin != nil && h.admin.EnableCORS(w, r) {
		return
	}

	orgID := r.URL.Query().Get("organization")
	if orgID == "" {
		orgID = r.URL.Query().Get("tenant")
	}
	if orgID == "" {
		orgID = "default"
	}

	issuer := fmt.Sprintf("https://authpole.io/organizations/%s", orgID)

	config := map[string]interface{}{
		"issuer":                                issuer,
		"authorization_endpoint":                "/oauth/v2/authorize",
		"token_endpoint":                        "/oauth/v2/token",
		"userinfo_endpoint":                     "/oauth/v2/userinfo",
		"jwks_uri":                              fmt.Sprintf("/organizations/%s/.well-known/jwks.json", orgID),
		"introspection_endpoint":                "/oauth/v2/introspect",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "email", "name", "organization_id", "app_id"},
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(config)
}

// JWKS handles standard JSON Web Key Set endpoint: /.well-known/jwks.json and /organizations/{organization}/.well-known/jwks.json
func (h *OIDCHandler) JWKS(w http.ResponseWriter, r *http.Request) {
	if h.admin != nil && h.admin.EnableCORS(w, r) {
		return
	}

	orgID := r.URL.Query().Get("organization")
	if orgID == "" {
		orgID = r.URL.Query().Get("tenant")
	}
	if orgID == "" {
		orgID = "default"
	}
	appID := r.URL.Query().Get("app_id")

	// Check cache
	cachedJWKS, found := h.cache.GetJWKS(orgID, appID)
	if found {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_, _ = w.Write(cachedJWKS)
		return
	}

	// Fetch keys from storage
	list, err := h.storage.List(r.Context(), fmt.Sprintf("organizations/%s/keys/", orgID))
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
		newKey, err := crypto.GenerateRSAKeyPair(orgID, appID)
		if err == nil {
			keyBytes, _ := json.Marshal(newKey)
			_, _ = h.storage.Put(r.Context(), storage.KeyPairKey(orgID, newKey.ID), keyBytes, "")
			keys = append(keys, newKey)
		}
	}

	jwksBytes, err := crypto.BuildJWKS(keys)
	if err != nil {
		http.Error(w, `{"error":"server_error","message":"failed to build JWKS"}`, http.StatusInternalServerError)
		return
	}

	// Cache JWKS payload
	h.cache.SetJWKS(orgID, appID, jwksBytes, 1*time.Minute)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(jwksBytes)
}

// Authorize handles OIDC authorization request: /oauth/v2/authorize
func (h *OIDCHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	if h.admin != nil && h.admin.EnableCORS(w, r) {
		return
	}

	orgID := r.URL.Query().Get("organization")
	if orgID == "" {
		orgID = r.URL.Query().Get("tenant")
	}
	if orgID == "" {
		orgID = "default"
	}

	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	scope := r.URL.Query().Get("scope")
	state := r.URL.Query().Get("state")
	idpID := r.URL.Query().Get("idp")
	if idpID == "" {
		idpID = r.URL.Query().Get("idp_hint")
	}

	if clientID == "" || redirectURI == "" {
		http.Error(w, `{"error":"invalid_request","message":"missing client_id or redirect_uri"}`, http.StatusBadRequest)
		return
	}

	serverBaseURL := h.computeServerBaseURL(r)

	redirectURL, err := h.engine.PrepareAuthorization(r.Context(), serverBaseURL, orgID, clientID, redirectURI, scope, state, idpID)
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
	orgID := r.FormValue("organization")
	if orgID == "" {
		orgID = r.FormValue("tenant")
	}
	if orgID == "" {
		orgID = "default"
	}

	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")

	if code == "" || clientID == "" {
		http.Error(w, `{"error":"invalid_request","message":"missing code or client_id"}`, http.StatusBadRequest)
		return
	}

	resp, err := h.engine.ExchangeCodeForToken(r.Context(), orgID, clientID, clientSecret, code, redirectURI)
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

		redirectURL, err := h.engine.CompleteUpstreamAuthentication(r.Context(), stateID, claims)
		if err != nil {
			http.Error(w, fmt.Sprintf("Authentication error: %v", err), http.StatusBadRequest)
			return
		}

		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8" />
<title>Auth Pole - Dev Mock Login</title>
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
  <p style="font-size: 0.85rem; color: #94a3b8;">Simulating upstream identity provider authentication.</p>
  <form method="POST">
    <label>Email Address</label>
    <input type="email" name="email" placeholder="admin@example.com" required />
    <label>Full Name</label>
    <input type="text" name="name" placeholder="Admin Name" required />
    <button type="submit">Complete Authentication & Return</button>
  </form>
</div>
</body>
</html>`)
}

func (h *OIDCHandler) Callback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	stateID := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	errParam := r.URL.Query().Get("error")

	if errParam != "" {
		errDesc := r.URL.Query().Get("error_description")
		http.Error(w, fmt.Sprintf("Upstream identity provider returned error: %s - %s", errParam, errDesc), http.StatusBadRequest)
		return
	}

	if stateID == "" || code == "" {
		http.Error(w, "Missing state or code query parameter from identity provider callback", http.StatusBadRequest)
		return
	}

	serverBaseURL := h.computeServerBaseURL(r)
	redirectURL, err := h.engine.ProcessUpstreamCallback(ctx, serverBaseURL, stateID, code)
	if err != nil {
		http.Error(w, fmt.Sprintf("Authentication failed: %v", err), http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, redirectURL, http.StatusFound)
}
