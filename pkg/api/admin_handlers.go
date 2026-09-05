package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/authpole/authpole/pkg/cache"
	"github.com/authpole/authpole/pkg/crypto"
	"github.com/authpole/authpole/pkg/models"
	"github.com/authpole/authpole/pkg/storage"
)

var (
	ErrUnauthorizedAdmin = errors.New("missing or invalid admin bearer token")
)

type AdminHandler struct {
	storage storage.Storage
	cache   *cache.MemoryCache
}

func NewAdminHandler(store storage.Storage, c *cache.MemoryCache) *AdminHandler {
	return &AdminHandler{
		storage: store,
		cache:   c,
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

	// Static secret admin fallback
	if token == "authpole_admin_secret_token_123" {
		return nil
	}

	// OIDC JWT Token Verification for Console Admin Users
	orgID := r.Header.Get("X-Organization-ID")
	if orgID == "" {
		orgID = r.Header.Get("X-Tenant-ID")
	}
	if orgID == "" {
		orgID = "default"
	}

	appID := r.Header.Get("X-App-ID")

	// Fetch active signing keys from target organization & default org for admin_console / system tokens
	var keys []*models.SigningKey
	seenKIDs := make(map[string]bool)

	orgsToCheck := []string{orgID}
	if orgID != "default" {
		orgsToCheck = append(orgsToCheck, "default")
	}

	for _, targetOrg := range orgsToCheck {
		if targetOrg == "" {
			continue
		}
		for _, targetApp := range []string{appID, "admin_console", ""} {
			cached, found := h.cache.GetSigningKeys(targetOrg, targetApp)
			if found && len(cached) > 0 {
				for _, k := range cached {
					if k != nil && k.Active && !seenKIDs[k.ID] {
						keys = append(keys, k)
						seenKIDs[k.ID] = true
					}
				}
			}
		}
		list, err := h.storage.List(r.Context(), fmt.Sprintf("organizations/%s/keys/", targetOrg))
		if err == nil {
			for _, rec := range list {
				var k models.SigningKey
				if err := json.Unmarshal(rec.Data, &k); err == nil && k.Active && !seenKIDs[k.ID] {
					keys = append(keys, &k)
					seenKIDs[k.ID] = true
				}
			}
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

// HandleUserOrganizations handles GET /api/v1/user/organizations
// Returns all organizations where the authenticated user (by email) is an admin user.
func (h *AdminHandler) HandleUserOrganizations(w http.ResponseWriter, r *http.Request) {
	if h.EnableCORS(w, r) {
		return
	}

	if r.Method != http.MethodGet {
		h.renderError(w, fmt.Errorf("method not allowed"), http.StatusMethodNotAllowed)
		return
	}

	if err := h.AuthenticateAdmin(r); err != nil {
		h.renderError(w, err, http.StatusUnauthorized)
		return
	}

	authHeader := r.Header.Get("Authorization")
	token := ""
	if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
		token = strings.TrimPrefix(authHeader, "Bearer ")
	} else {
		token = r.Header.Get("X-Admin-Token")
	}

	userEmail := ""
	if token != "authpole_admin_secret_token_123" {
		orgID := r.Header.Get("X-Organization-ID")
		if orgID == "" {
			orgID = "default"
		}
		keys, _ := h.cache.GetSigningKeys(orgID, "")
		if len(keys) == 0 {
			list, _ := h.storage.List(r.Context(), fmt.Sprintf("organizations/%s/keys/", orgID))
			for _, rec := range list {
				var k models.SigningKey
				if err := json.Unmarshal(rec.Data, &k); err == nil && k.Active {
					keys = append(keys, &k)
				}
			}
		}
		if len(keys) > 0 {
			if claims, err := crypto.VerifyJWT(token, keys); err == nil {
				userEmail = claims.Email
			}
		}
	}

	orgRecords, err := h.storage.List(r.Context(), "organizations/")
	if err != nil {
		h.renderError(w, err, http.StatusInternalServerError)
		return
	}

	var result []*models.Organization
	for _, oRec := range orgRecords {
		if !strings.HasSuffix(oRec.Key, "/metadata.json") {
			continue
		}
		var org models.Organization
		if err := json.Unmarshal(oRec.Data, &org); err != nil {
			continue
		}
		org.Version = oRec.Version

		if token == "authpole_admin_secret_token_123" || userEmail == "" {
			result = append(result, &org)
			continue
		}

		uList, err := h.storage.List(r.Context(), fmt.Sprintf("organizations/%s/admin/users/", org.ID))
		if err == nil {
			isMember := false
			for _, uRec := range uList {
				var u models.AdminUser
				if err := json.Unmarshal(uRec.Data, &u); err == nil {
					if strings.EqualFold(u.Email, userEmail) {
						isMember = true
						break
					}
				}
			}
			if isMember {
				result = append(result, &org)
			}
		}
	}

	h.renderJSON(w, result, "")
}

func (h *AdminHandler) EnableCORS(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Expected-Version, X-Organization-ID, X-Tenant-ID, X-Admin-Token, X-App-ID")
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

// HandleOrganizations: GET /api/v1/organizations, POST /api/v1/organizations, PUT /api/v1/organizations/{id}
func (h *AdminHandler) HandleOrganizations(w http.ResponseWriter, r *http.Request) {
	if h.EnableCORS(w, r) {
		return
	}

	if err := h.AuthenticateAdmin(r); err != nil {
		h.renderError(w, err, http.StatusUnauthorized)
		return
	}

	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/organizations"), "/")
	if len(pathParts) == 1 && strings.HasPrefix(r.URL.Path, "/api/v1/tenants") {
		pathParts = strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/tenants"), "/")
	}
	orgID := ""
	if len(pathParts) > 1 && pathParts[1] != "" {
		orgID = pathParts[1]
	}

	switch r.Method {
	case http.MethodGet:
		if orgID == "" {
			list, err := h.storage.List(r.Context(), "organizations/")
			if err != nil {
				h.renderError(w, err, http.StatusInternalServerError)
				return
			}
			var orgs []*models.Organization
			for _, rec := range list {
				if strings.HasSuffix(rec.Key, "/metadata.json") {
					var o models.Organization
					if err := json.Unmarshal(rec.Data, &o); err == nil {
						o.Version = rec.Version
						orgs = append(orgs, &o)
					}
				}
			}
			h.renderJSON(w, orgs, "")
		} else {
			rec, err := h.storage.Get(r.Context(), storage.OrganizationKey(orgID))
			if err != nil {
				h.renderError(w, err, http.StatusNotFound)
				return
			}
			var o models.Organization
			_ = json.Unmarshal(rec.Data, &o)
			o.Version = rec.Version
			h.renderJSON(w, o, rec.Version)
		}

	case http.MethodPost, http.MethodPut:
		var org models.Organization
		if err := json.NewDecoder(r.Body).Decode(&org); err != nil {
			h.renderError(w, err, http.StatusBadRequest)
			return
		}

		if org.ID == "" {
			org.ID = orgID
		}
		if org.ID == "" {
			h.renderError(w, fmt.Errorf("organization ID is required"), http.StatusBadRequest)
			return
		}

		expectedVersion := r.Header.Get("X-Expected-Version")
		if expectedVersion == "" {
			expectedVersion = org.Version
		}

		org.UpdatedAt = time.Now()
		if org.CreatedAt.IsZero() {
			org.CreatedAt = time.Now()
		}

		// Create initial user if provided during organization creation
		if org.InitialUser != nil && (org.InitialUser.Email != "" || org.InitialUser.Name != "") {
			u := org.InitialUser
			if u.ID == "" {
				u.ID = fmt.Sprintf("usr_%d", time.Now().UnixNano())
			}
			u.OrganizationID = org.ID
			if len(u.RoleIDs) == 0 {
				u.RoleIDs = []string{"super_admin"}
			}
			u.Active = true
			if u.Status == "" {
				u.Status = "active"
			}
			u.UpdatedAt = time.Now()
			if u.CreatedAt.IsZero() {
				u.CreatedAt = time.Now()
			}
			uBytes, _ := json.Marshal(u)
			_, _ = h.storage.Put(r.Context(), storage.AdminUserKey(org.ID, u.ID), uBytes, "")
		}

		data, _ := json.Marshal(org)
		newVer, err := h.storage.Put(r.Context(), storage.OrganizationKey(org.ID), data, expectedVersion)
		if err != nil {
			h.renderError(w, err, http.StatusConflict)
			return
		}

		org.Version = newVer
		h.cache.InvalidateOrganization(org.ID)
		h.renderJSON(w, org, newVer)

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

	orgID := r.Header.Get("X-Organization-ID")
	if orgID == "" {
		orgID = r.Header.Get("X-Tenant-ID")
	}
	if orgID == "" {
		orgID = r.URL.Query().Get("organization")
		if orgID == "" {
			orgID = r.URL.Query().Get("tenant")
		}
	}
	if orgID == "" {
		orgID = "default"
	}

	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/apps"), "/")
	appID := ""
	if len(pathParts) > 1 && pathParts[1] != "" {
		appID = pathParts[1]
	}

	switch r.Method {
	case http.MethodGet:
		if appID == "" {
			prefix := fmt.Sprintf("organizations/%s/apps/", orgID)
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
			rec, err := h.storage.Get(r.Context(), storage.AppKey(orgID, appID))
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
		if app.OrganizationID == "" {
			app.OrganizationID = orgID
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
		newVer, err := h.storage.Put(r.Context(), storage.AppKey(orgID, app.ID), data, expectedVersion)
		if err != nil {
			h.renderError(w, err, http.StatusConflict)
			return
		}

		app.Version = newVer
		h.cache.InvalidateApp(orgID, app.ID)
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

	orgID := r.Header.Get("X-Organization-ID")
	if orgID == "" {
		orgID = r.Header.Get("X-Tenant-ID")
	}
	if orgID == "" {
		orgID = r.URL.Query().Get("organization")
		if orgID == "" {
			orgID = r.URL.Query().Get("tenant")
		}
	}
	if orgID == "" {
		orgID = "default"
	}

	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/idps"), "/")
	idpID := ""
	if len(pathParts) > 1 && pathParts[1] != "" {
		idpID = pathParts[1]
	}

	switch r.Method {
	case http.MethodGet:
		if idpID == "" {
			prefix := fmt.Sprintf("organizations/%s/idps/", orgID)
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
			rec, err := h.storage.Get(r.Context(), storage.IDPKey(orgID, idpID))
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
		if item.OrganizationID == "" {
			item.OrganizationID = orgID
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
		newVer, err := h.storage.Put(r.Context(), storage.IDPKey(orgID, item.ID), data, expectedVersion)
		if err != nil {
			h.renderError(w, err, http.StatusConflict)
			return
		}

		item.Version = newVer
		h.cache.InvalidateOrganization(orgID)
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

	orgID := r.Header.Get("X-Organization-ID")
	if orgID == "" {
		orgID = r.Header.Get("X-Tenant-ID")
	}
	if orgID == "" {
		orgID = r.URL.Query().Get("organization")
		if orgID == "" {
			orgID = r.URL.Query().Get("tenant")
		}
	}
	if orgID == "" {
		orgID = "default"
	}

	switch r.Method {
	case http.MethodGet:
		prefix := fmt.Sprintf("organizations/%s/keys/", orgID)
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
		keyPair, err := crypto.GenerateRSAKeyPair(orgID, appID)
		if err != nil {
			h.renderError(w, err, http.StatusInternalServerError)
			return
		}

		data, _ := json.Marshal(keyPair)
		newVer, err := h.storage.Put(r.Context(), storage.KeyPairKey(orgID, keyPair.ID), data, "")
		if err != nil {
			h.renderError(w, err, http.StatusInternalServerError)
			return
		}

		keyPair.Version = newVer
		h.cache.InvalidateApp(orgID, appID)
		h.renderJSON(w, keyPair, newVer)

	default:
		h.renderError(w, fmt.Errorf("method not allowed"), http.StatusMethodNotAllowed)
	}
}

// HandleAdminUsers: GET /api/v1/admin/users, POST /api/v1/admin/users, POST /api/v1/admin/users/invite, PUT /api/v1/admin/users/{id}
func (h *AdminHandler) HandleAdminUsers(w http.ResponseWriter, r *http.Request) {
	if h.EnableCORS(w, r) {
		return
	}

	if err := h.AuthenticateAdmin(r); err != nil {
		h.renderError(w, err, http.StatusUnauthorized)
		return
	}

	orgID := r.Header.Get("X-Organization-ID")
	if orgID == "" {
		orgID = r.Header.Get("X-Tenant-ID")
	}
	if orgID == "" {
		orgID = "default"
	}

	isInvite := strings.HasSuffix(strings.TrimSuffix(r.URL.Path, "/"), "/invite")

	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/admin/users"), "/")
	userID := ""
	if len(pathParts) > 1 && pathParts[1] != "" && pathParts[1] != "invite" {
		userID = pathParts[1]
	}

	switch r.Method {
	case http.MethodGet:
		prefix := fmt.Sprintf("organizations/%s/admin/users/", orgID)
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
		if user.OrganizationID != "" {
			orgID = user.OrganizationID
		} else {
			user.OrganizationID = orgID
		}

		now := time.Now()
		if isInvite || user.Status == "invited" {
			user.Status = "invited"
			user.Active = true
			if user.InvitedBy == "" {
				user.InvitedBy = "super_admin"
			}
			user.InvitedAt = &now
		} else if user.Status == "" {
			user.Status = "active"
			user.Active = true
		}

		expectedVersion := r.Header.Get("X-Expected-Version")
		if expectedVersion == "" {
			expectedVersion = user.Version
		}

		user.UpdatedAt = now
		if user.CreatedAt.IsZero() {
			user.CreatedAt = now
		}

		data, _ := json.Marshal(user)
		newVer, err := h.storage.Put(r.Context(), storage.AdminUserKey(orgID, user.ID), data, expectedVersion)
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

	orgID := r.Header.Get("X-Organization-ID")
	if orgID == "" {
		orgID = r.Header.Get("X-Tenant-ID")
	}
	if orgID == "" {
		orgID = "default"
	}

	switch r.Method {
	case http.MethodGet:
		prefix := fmt.Sprintf("organizations/%s/admin/teams/", orgID)
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
		team.OrganizationID = orgID

		expectedVersion := r.Header.Get("X-Expected-Version")
		if expectedVersion == "" {
			expectedVersion = team.Version
		}

		team.UpdatedAt = time.Now()
		if team.CreatedAt.IsZero() {
			team.CreatedAt = time.Now()
		}

		data, _ := json.Marshal(team)
		newVer, err := h.storage.Put(r.Context(), storage.TeamKey(orgID, team.ID), data, expectedVersion)
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

	orgID := r.Header.Get("X-Organization-ID")
	if orgID == "" {
		orgID = r.Header.Get("X-Tenant-ID")
	}
	if orgID == "" {
		orgID = "default"
	}

	switch r.Method {
	case http.MethodGet:
		prefix := fmt.Sprintf("organizations/%s/admin/roles/", orgID)
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
		role.OrganizationID = orgID

		expectedVersion := r.Header.Get("X-Expected-Version")
		if expectedVersion == "" {
			expectedVersion = role.Version
		}

		role.UpdatedAt = time.Now()
		if role.CreatedAt.IsZero() {
			role.CreatedAt = time.Now()
		}

		data, _ := json.Marshal(role)
		newVer, err := h.storage.Put(r.Context(), storage.RoleKey(orgID, role.ID), data, expectedVersion)
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
