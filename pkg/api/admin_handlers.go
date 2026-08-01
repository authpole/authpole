package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"authpole/pkg/cache"
	"authpole/pkg/crypto"
	"authpole/pkg/models"
	"authpole/pkg/storage"
)

var (
	ErrUnauthorizedAdmin = errors.New("missing or invalid admin bearer token")
)

type AdminHandler struct {
	storage    storage.Storage
	cache      *cache.MemoryCache
	adminToken string
}

func NewAdminHandler(store storage.Storage, c *cache.MemoryCache) *AdminHandler {
	adminToken := os.Getenv("AUTHPOLE_ADMIN_TOKEN")
	if adminToken == "" {
		adminToken = os.Getenv("ADMIN_TOKEN")
	}
	if adminToken == "" {
		adminToken = "authpole_admin_secret_token_123"
	}

	return &AdminHandler{
		storage:    store,
		cache:      c,
		adminToken: adminToken,
	}
}

func (h *AdminHandler) AuthenticateAdmin(r *http.Request) error {
	authHeader := r.Header.Get("Authorization")
	token := ""

	if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
		token = strings.TrimPrefix(authHeader, "Bearer ")
	} else {
		token = r.Header.Get("X-Admin-Token")
	}

	if token == "" {
		return ErrUnauthorizedAdmin
	}

	// 1. Static Secret Check (for automated CLI / scripts)
	if token == h.adminToken {
		return nil
	}

	// 2. OIDC JWT Token Verification for Console Admin Users
	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		tenantID = "default"
	}

	appID := r.Header.Get("X-App-ID")

	// Fetch active signing keys from cache or storage
	keys, found := h.cache.GetSigningKeys(tenantID, appID)
	if !found || len(keys) == 0 {
		list, err := h.storage.List(r.Context(), fmt.Sprintf("tenants/%s/keys/", tenantID))
		if err == nil {
			for _, rec := range list {
				var k models.SigningKey
				if err := json.Unmarshal(rec.Data, &k); err == nil && k.Active {
					keys = append(keys, &k)
				}
			}
		}
		if len(keys) > 0 {
			h.cache.SetSigningKeys(tenantID, appID, keys, 1*time.Hour)
		}
	}

	if len(keys) == 0 {
		return ErrUnauthorizedAdmin
	}

	// Verify OIDC JWT Token signature and expiration
	claims, err := crypto.VerifyJWT(token, keys)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrUnauthorizedAdmin, err.Error())
	}

	// Verify token subject/email exists
	if claims.Subject == "" && claims.Email == "" {
		return ErrUnauthorizedAdmin
	}

	return nil
}

func (h *AdminHandler) EnableCORS(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Expected-Version, X-Tenant-ID, X-Admin-Token, X-App-ID")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return true
	}
	return false
}

func (h *AdminHandler) renderError(w http.ResponseWriter, err error, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	code := "error"
	if errors.Is(err, storage.ErrVersionMismatch) {
		code = "cas_conflict"
		statusCode = http.StatusConflict
	} else if errors.Is(err, ErrUnauthorizedAdmin) {
		code = "unauthorized_admin"
		statusCode = http.StatusUnauthorized
	}
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   code,
		"message": err.Error(),
	})
}

func (h *AdminHandler) renderJSON(w http.ResponseWriter, data interface{}, version string) {
	w.Header().Set("Content-Type", "application/json")
	if version != "" {
		w.Header().Set("ETag", version)
	}
	_ = json.NewEncoder(w).Encode(data)
}

// HandleTenants: GET /api/v1/tenants, POST /api/v1/tenants, PUT /api/v1/tenants/{id}
func (h *AdminHandler) HandleTenants(w http.ResponseWriter, r *http.Request) {
	if h.EnableCORS(w, r) {
		return
	}

	if err := h.AuthenticateAdmin(r); err != nil {
		h.renderError(w, err, http.StatusUnauthorized)
		return
	}

	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/tenants"), "/")
	tenantID := ""
	if len(pathParts) > 1 && pathParts[1] != "" {
		tenantID = pathParts[1]
	}

	switch r.Method {
	case http.MethodGet:
		if tenantID == "" {
			list, err := h.storage.List(r.Context(), "tenants/")
			if err != nil {
				h.renderError(w, err, http.StatusInternalServerError)
				return
			}
			var tenants []*models.Tenant
			for _, rec := range list {
				if strings.HasSuffix(rec.Key, "/metadata.json") {
					var t models.Tenant
					if err := json.Unmarshal(rec.Data, &t); err == nil {
						t.Version = rec.Version
						tenants = append(tenants, &t)
					}
				}
			}
			h.renderJSON(w, tenants, "")
		} else {
			rec, err := h.storage.Get(r.Context(), storage.TenantKey(tenantID))
			if err != nil {
				h.renderError(w, err, http.StatusNotFound)
				return
			}
			var t models.Tenant
			_ = json.Unmarshal(rec.Data, &t)
			t.Version = rec.Version
			h.renderJSON(w, t, rec.Version)
		}

	case http.MethodPost, http.MethodPut:
		var tenant models.Tenant
		if err := json.NewDecoder(r.Body).Decode(&tenant); err != nil {
			h.renderError(w, err, http.StatusBadRequest)
			return
		}

		if tenant.ID == "" {
			tenant.ID = tenantID
		}
		if tenant.ID == "" {
			h.renderError(w, fmt.Errorf("tenant ID is required"), http.StatusBadRequest)
			return
		}

		expectedVersion := r.Header.Get("X-Expected-Version")
		if expectedVersion == "" {
			expectedVersion = tenant.Version
		}

		tenant.UpdatedAt = time.Now()
		if tenant.CreatedAt.IsZero() {
			tenant.CreatedAt = time.Now()
		}

		data, _ := json.Marshal(tenant)
		newVer, err := h.storage.Put(r.Context(), storage.TenantKey(tenant.ID), data, expectedVersion)
		if err != nil {
			h.renderError(w, err, http.StatusConflict)
			return
		}

		tenant.Version = newVer
		h.cache.InvalidateTenant(tenant.ID)
		h.renderJSON(w, tenant, newVer)

	default:
		h.renderError(w, fmt.Errorf("method not allowed"), http.StatusMethodNotAllowed)
	}
}

// HandleApps: GET /api/v1/apps, POST /api/v1/apps, PUT /api/v1/apps/{id}
func (h *AdminHandler) HandleApps(w http.ResponseWriter, r *http.Request) {
	if h.EnableCORS(w, r) {
		return
	}

	if err := h.AuthenticateAdmin(r); err != nil {
		h.renderError(w, err, http.StatusUnauthorized)
		return
	}

	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		tenantID = r.URL.Query().Get("tenant")
	}
	if tenantID == "" {
		tenantID = "default"
	}

	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/apps"), "/")
	appID := ""
	if len(pathParts) > 1 && pathParts[1] != "" {
		appID = pathParts[1]
	}

	switch r.Method {
	case http.MethodGet:
		if appID == "" {
			prefix := fmt.Sprintf("tenants/%s/apps/", tenantID)
			list, err := h.storage.List(r.Context(), prefix)
			if err != nil {
				h.renderError(w, err, http.StatusInternalServerError)
				return
			}
			var apps []*models.Application
			for _, rec := range list {
				var a models.Application
				if err := json.Unmarshal(rec.Data, &a); err == nil {
					a.Version = rec.Version
					apps = append(apps, &a)
				}
			}
			h.renderJSON(w, apps, "")
		} else {
			rec, err := h.storage.Get(r.Context(), storage.AppKey(tenantID, appID))
			if err != nil {
				h.renderError(w, err, http.StatusNotFound)
				return
			}
			var a models.Application
			_ = json.Unmarshal(rec.Data, &a)
			a.Version = rec.Version
			h.renderJSON(w, a, rec.Version)
		}

	case http.MethodPost, http.MethodPut:
		var app models.Application
		if err := json.NewDecoder(r.Body).Decode(&app); err != nil {
			h.renderError(w, err, http.StatusBadRequest)
			return
		}

		if app.ID == "" {
			app.ID = appID
		}
		if app.ID == "" {
			app.ID = fmt.Sprintf("app_%d", time.Now().UnixNano())
		}
		if app.TenantID == "" {
			app.TenantID = tenantID
		}
		if app.ClientID == "" {
			app.ClientID = app.ID
		}

		expectedVersion := r.Header.Get("X-Expected-Version")
		if expectedVersion == "" {
			expectedVersion = app.Version
		}

		app.UpdatedAt = time.Now()
		if app.CreatedAt.IsZero() {
			app.CreatedAt = time.Now()
		}

		data, _ := json.Marshal(app)
		newVer, err := h.storage.Put(r.Context(), storage.AppKey(tenantID, app.ID), data, expectedVersion)
		if err != nil {
			h.renderError(w, err, http.StatusConflict)
			return
		}

		app.Version = newVer
		h.cache.InvalidateApp(tenantID, app.ID)
		h.renderJSON(w, app, newVer)

	default:
		h.renderError(w, fmt.Errorf("method not allowed"), http.StatusMethodNotAllowed)
	}
}

// HandleIDPs: GET /api/v1/idps, POST /api/v1/idps, PUT /api/v1/idps/{id}
func (h *AdminHandler) HandleIDPs(w http.ResponseWriter, r *http.Request) {
	if h.EnableCORS(w, r) {
		return
	}

	if err := h.AuthenticateAdmin(r); err != nil {
		h.renderError(w, err, http.StatusUnauthorized)
		return
	}

	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		tenantID = r.URL.Query().Get("tenant")
	}
	if tenantID == "" {
		tenantID = "default"
	}

	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/idps"), "/")
	idpID := ""
	if len(pathParts) > 1 && pathParts[1] != "" {
		idpID = pathParts[1]
	}

	switch r.Method {
	case http.MethodGet:
		if idpID == "" {
			prefix := fmt.Sprintf("tenants/%s/idps/", tenantID)
			list, err := h.storage.List(r.Context(), prefix)
			if err != nil {
				h.renderError(w, err, http.StatusInternalServerError)
				return
			}
			var idps []*models.IdentityProvider
			for _, rec := range list {
				var item models.IdentityProvider
				if err := json.Unmarshal(rec.Data, &item); err == nil {
					item.Version = rec.Version
					idps = append(idps, &item)
				}
			}
			h.renderJSON(w, idps, "")
		} else {
			rec, err := h.storage.Get(r.Context(), storage.IDPKey(tenantID, idpID))
			if err != nil {
				h.renderError(w, err, http.StatusNotFound)
				return
			}
			var item models.IdentityProvider
			_ = json.Unmarshal(rec.Data, &item)
			item.Version = rec.Version
			h.renderJSON(w, item, rec.Version)
		}

	case http.MethodPost, http.MethodPut:
		var item models.IdentityProvider
		if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
			h.renderError(w, err, http.StatusBadRequest)
			return
		}

		if item.ID == "" {
			item.ID = idpID
		}
		if item.ID == "" {
			item.ID = fmt.Sprintf("idp_%d", time.Now().UnixNano())
		}
		if item.TenantID == "" {
			item.TenantID = tenantID
		}

		expectedVersion := r.Header.Get("X-Expected-Version")
		if expectedVersion == "" {
			expectedVersion = item.Version
		}

		item.UpdatedAt = time.Now()
		if item.CreatedAt.IsZero() {
			item.CreatedAt = time.Now()
		}

		data, _ := json.Marshal(item)
		newVer, err := h.storage.Put(r.Context(), storage.IDPKey(tenantID, item.ID), data, expectedVersion)
		if err != nil {
			h.renderError(w, err, http.StatusConflict)
			return
		}

		item.Version = newVer
		h.cache.InvalidateTenant(tenantID)
		h.renderJSON(w, item, newVer)

	default:
		h.renderError(w, fmt.Errorf("method not allowed"), http.StatusMethodNotAllowed)
	}
}

// HandleKeys: GET /api/v1/keys, POST /api/v1/keys (Generate key pair)
func (h *AdminHandler) HandleKeys(w http.ResponseWriter, r *http.Request) {
	if h.EnableCORS(w, r) {
		return
	}

	if err := h.AuthenticateAdmin(r); err != nil {
		h.renderError(w, err, http.StatusUnauthorized)
		return
	}

	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		tenantID = r.URL.Query().Get("tenant")
	}
	if tenantID == "" {
		tenantID = "default"
	}

	switch r.Method {
	case http.MethodGet:
		prefix := fmt.Sprintf("tenants/%s/keys/", tenantID)
		list, err := h.storage.List(r.Context(), prefix)
		if err != nil {
			h.renderError(w, err, http.StatusInternalServerError)
			return
		}
		var keys []*models.SigningKey
		for _, rec := range list {
			var k models.SigningKey
			if err := json.Unmarshal(rec.Data, &k); err == nil {
				k.Version = rec.Version
				k.PrivateKeyPEM = ""
				keys = append(keys, &k)
			}
		}
		h.renderJSON(w, keys, "")

	case http.MethodPost:
		appID := r.URL.Query().Get("app_id")
		keyPair, err := crypto.GenerateRSAKeyPair(tenantID, appID)
		if err != nil {
			h.renderError(w, err, http.StatusInternalServerError)
			return
		}

		data, _ := json.Marshal(keyPair)
		newVer, err := h.storage.Put(r.Context(), storage.KeyPairKey(tenantID, keyPair.ID), data, "")
		if err != nil {
			h.renderError(w, err, http.StatusInternalServerError)
			return
		}

		keyPair.Version = newVer
		h.cache.InvalidateApp(tenantID, appID)
		h.renderJSON(w, keyPair, newVer)

	default:
		h.renderError(w, fmt.Errorf("method not allowed"), http.StatusMethodNotAllowed)
	}
}

// HandleAdminUsers: GET /api/v1/admin/users, POST /api/v1/admin/users, PUT /api/v1/admin/users/{id}
func (h *AdminHandler) HandleAdminUsers(w http.ResponseWriter, r *http.Request) {
	if h.EnableCORS(w, r) {
		return
	}

	if err := h.AuthenticateAdmin(r); err != nil {
		h.renderError(w, err, http.StatusUnauthorized)
		return
	}

	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		tenantID = "default"
	}

	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/admin/users"), "/")
	userID := ""
	if len(pathParts) > 1 && pathParts[1] != "" {
		userID = pathParts[1]
	}

	switch r.Method {
	case http.MethodGet:
		prefix := fmt.Sprintf("tenants/%s/admin/users/", tenantID)
		list, err := h.storage.List(r.Context(), prefix)
		if err != nil {
			h.renderError(w, err, http.StatusInternalServerError)
			return
		}
		var users []*models.AdminUser
		for _, rec := range list {
			var u models.AdminUser
			if err := json.Unmarshal(rec.Data, &u); err == nil {
				u.Version = rec.Version
				users = append(users, &u)
			}
		}
		h.renderJSON(w, users, "")

	case http.MethodPost, http.MethodPut:
		var user models.AdminUser
		if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
			h.renderError(w, err, http.StatusBadRequest)
			return
		}

		if user.ID == "" {
			user.ID = userID
		}
		if user.ID == "" {
			user.ID = fmt.Sprintf("usr_%d", time.Now().UnixNano())
		}
		user.TenantID = tenantID

		expectedVersion := r.Header.Get("X-Expected-Version")
		if expectedVersion == "" {
			expectedVersion = user.Version
		}

		user.UpdatedAt = time.Now()
		if user.CreatedAt.IsZero() {
			user.CreatedAt = time.Now()
		}

		data, _ := json.Marshal(user)
		newVer, err := h.storage.Put(r.Context(), storage.AdminUserKey(tenantID, user.ID), data, expectedVersion)
		if err != nil {
			h.renderError(w, err, http.StatusConflict)
			return
		}

		user.Version = newVer
		h.renderJSON(w, user, newVer)

	default:
		h.renderError(w, fmt.Errorf("method not allowed"), http.StatusMethodNotAllowed)
	}
}

// HandleTeams: GET /api/v1/admin/teams, POST /api/v1/admin/teams
func (h *AdminHandler) HandleTeams(w http.ResponseWriter, r *http.Request) {
	if h.EnableCORS(w, r) {
		return
	}

	if err := h.AuthenticateAdmin(r); err != nil {
		h.renderError(w, err, http.StatusUnauthorized)
		return
	}

	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		tenantID = "default"
	}

	switch r.Method {
	case http.MethodGet:
		prefix := fmt.Sprintf("tenants/%s/admin/teams/", tenantID)
		list, err := h.storage.List(r.Context(), prefix)
		if err != nil {
			h.renderError(w, err, http.StatusInternalServerError)
			return
		}
		var teams []*models.Team
		for _, rec := range list {
			var t models.Team
			if err := json.Unmarshal(rec.Data, &t); err == nil {
				t.Version = rec.Version
				teams = append(teams, &t)
			}
		}
		h.renderJSON(w, teams, "")

	case http.MethodPost, http.MethodPut:
		var team models.Team
		if err := json.NewDecoder(r.Body).Decode(&team); err != nil {
			h.renderError(w, err, http.StatusBadRequest)
			return
		}

		if team.ID == "" {
			team.ID = fmt.Sprintf("team_%d", time.Now().UnixNano())
		}
		team.TenantID = tenantID

		expectedVersion := r.Header.Get("X-Expected-Version")
		if expectedVersion == "" {
			expectedVersion = team.Version
		}

		team.UpdatedAt = time.Now()
		if team.CreatedAt.IsZero() {
			team.CreatedAt = time.Now()
		}

		data, _ := json.Marshal(team)
		newVer, err := h.storage.Put(r.Context(), storage.TeamKey(tenantID, team.ID), data, expectedVersion)
		if err != nil {
			h.renderError(w, err, http.StatusConflict)
			return
		}

		team.Version = newVer
		h.renderJSON(w, team, newVer)

	default:
		h.renderError(w, fmt.Errorf("method not allowed"), http.StatusMethodNotAllowed)
	}
}

// HandleRoles: GET /api/v1/admin/roles, POST /api/v1/admin/roles
func (h *AdminHandler) HandleRoles(w http.ResponseWriter, r *http.Request) {
	if h.EnableCORS(w, r) {
		return
	}

	if err := h.AuthenticateAdmin(r); err != nil {
		h.renderError(w, err, http.StatusUnauthorized)
		return
	}

	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		tenantID = "default"
	}

	switch r.Method {
	case http.MethodGet:
		prefix := fmt.Sprintf("tenants/%s/admin/roles/", tenantID)
		list, err := h.storage.List(r.Context(), prefix)
		if err != nil {
			h.renderError(w, err, http.StatusInternalServerError)
			return
		}
		var roles []*models.Role
		for _, rec := range list {
			var role models.Role
			if err := json.Unmarshal(rec.Data, &role); err == nil {
				role.Version = rec.Version
				roles = append(roles, &role)
			}
		}
		h.renderJSON(w, roles, "")

	case http.MethodPost, http.MethodPut:
		var role models.Role
		if err := json.NewDecoder(r.Body).Decode(&role); err != nil {
			h.renderError(w, err, http.StatusBadRequest)
			return
		}

		if role.ID == "" {
			role.ID = fmt.Sprintf("role_%d", time.Now().UnixNano())
		}
		role.TenantID = tenantID

		expectedVersion := r.Header.Get("X-Expected-Version")
		if expectedVersion == "" {
			expectedVersion = role.Version
		}

		role.UpdatedAt = time.Now()
		if role.CreatedAt.IsZero() {
			role.CreatedAt = time.Now()
		}

		data, _ := json.Marshal(role)
		newVer, err := h.storage.Put(r.Context(), storage.RoleKey(tenantID, role.ID), data, expectedVersion)
		if err != nil {
			h.renderError(w, err, http.StatusConflict)
			return
		}

		role.Version = newVer
		h.renderJSON(w, role, newVer)

	default:
		h.renderError(w, fmt.Errorf("method not allowed"), http.StatusMethodNotAllowed)
	}
}
