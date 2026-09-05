package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"authpole/pkg/cache"
	"authpole/pkg/crypto"
	"authpole/pkg/models"
	"authpole/pkg/spiffe"
	"authpole/pkg/storage"
)

type SPIFFEHandler struct {
	storage storage.Storage
	cache   *cache.MemoryCache
	admin   *AdminHandler
}

func NewSPIFFEHandler(store storage.Storage, c *cache.MemoryCache, admin *AdminHandler) *SPIFFEHandler {
	return &SPIFFEHandler{
		storage: store,
		cache:   c,
		admin:   admin,
	}
}

// IssueSVID handles POST /api/v1/spiffe/svid - Workload exchanges long-expiry SPIFFE cert for short-lived SVID token
func (h *SPIFFEHandler) IssueSVID(w http.ResponseWriter, r *http.Request) {
	if h.admin.EnableCORS(w, r) {
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"invalid_request","message":"method must be POST"}`, http.StatusMethodNotAllowed)
		return
	}

	orgID := r.Header.Get("X-Organization-ID")
	if orgID == "" {
		orgID = r.Header.Get("X-Tenant-ID")
	}
	if orgID == "" {
		orgID = "default"
	}

	// Obtain a certificate whose private key the caller has PROVEN possession of.
	//
	// This deliberately ignores any certificate in the request body or in an
	// untrusted header. A certificate is public data, so accepting one as a
	// credential let anybody who had ever seen it impersonate the workload
	// indefinitely - no better than the long-lived bearer key SPIFFE replaces.
	clientCert, err := spiffe.VerifiedClientCert(r)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"mtls_required","message":"%s"}`, err.Error()), http.StatusUnauthorized)
		return
	}

	var reqBody struct {
		WorkloadID      string   `json:"workload_id"`
		Audience        string   `json:"audience"`
		RequestedScopes []string `json:"requested_scopes"`
	}

	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&reqBody)
	}

	workloadID := reqBody.WorkloadID
	if workloadID == "" {
		workloadID = r.URL.Query().Get("workload_id")
	}

	if workloadID == "" {
		http.Error(w, `{"error":"invalid_request","message":"workload_id is required"}`, http.StatusBadRequest)
		return
	}

	// Fetch SPIFFE Workload definition from storage
	rec, err := h.storage.Get(r.Context(), storage.SPIFFEWorkloadKey(orgID, workloadID))
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"workload_not_found","message":"workload %q not found"}`, workloadID), http.StatusNotFound)
		return
	}

	var workload models.SPIFFEWorkload
	if err := json.Unmarshal(rec.Data, &workload); err != nil || !workload.Active {
		http.Error(w, `{"error":"unauthorized_workload","message":"workload is inactive or invalid"}`, http.StatusUnauthorized)
		return
	}

	// Bind the proven certificate to this workload. Always enforced: a workload with
	// no registered fingerprint is now refused rather than authenticating anyone who
	// knows its ID.
	if err := spiffe.ValidateWorkloadCert(clientCert, &workload); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"invalid_client_certificate","message":"%s"}`, err.Error()), http.StatusUnauthorized)
		return
	}

	// Validate requested scopes against workload's allowed scopes
	var grantedScopes []string
	if len(reqBody.RequestedScopes) > 0 {
		for _, s := range reqBody.RequestedScopes {
			allowed := false
			for _, a := range workload.AllowedScopes {
				if a == "*" || a == s {
					allowed = true
					break
				}
			}
			if allowed {
				grantedScopes = append(grantedScopes, s)
			}
		}
	} else {
		grantedScopes = workload.AllowedScopes
	}

	// Get active organization signing key
	keys, found := h.cache.GetSigningKeys(orgID, "")
	if !found || len(keys) == 0 {
		list, _ := h.storage.List(r.Context(), fmt.Sprintf("organizations/%s/keys/", orgID))
		for _, kRec := range list {
			var k models.SigningKey
			if err := json.Unmarshal(kRec.Data, &k); err == nil && k.Active {
				keys = append(keys, &k)
			}
		}
		if len(keys) == 0 {
			newKey, err := crypto.GenerateRSAKeyPair(orgID, "")
			if err != nil {
				http.Error(w, `{"error":"server_error","message":"failed to generate signing key"}`, http.StatusInternalServerError)
				return
			}
			kBytes, _ := json.Marshal(newKey)
			_, _ = h.storage.Put(r.Context(), storage.KeyPairKey(orgID, newKey.ID), kBytes, "")
			keys = append(keys, newKey)
		}
		h.cache.SetSigningKeys(orgID, "", keys, 1*time.Hour)
	}

	activeKey := keys[0]
	spiffeID := workload.SPIFFEID
	if spiffeID == "" {
		spiffeID = spiffe.BuildSPIFFEID("authpole.local", orgID, workloadID)
	}

	audience := reqBody.Audience
	if audience == "" {
		audience = fmt.Sprintf("spiffe://%s/ns/%s", "authpole.local", orgID)
	}

	claims := &models.AuthClaims{
		Subject:        spiffeID,
		Issuer:         fmt.Sprintf("https://authpole.io/organizations/%s", orgID),
		Audience:       models.Audience{audience},
		OrganizationID: orgID,
		WorkloadID:     workload.ID,
		SPIFFEID:       spiffeID,
		Scope:          strings.Join(grantedScopes, " "),
	}

	// Issue short-lived SPIFFE JWT-SVID (15 minutes expiry)
	svidToken, err := spiffe.IssueJWTSVID(claims, activeKey, 15)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"svid_issuance_failed","message":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	resp := map[string]interface{}{
		"svid":            svidToken,
		"token_type":      "Bearer",
		"spiffe_id":       spiffeID,
		"expires_in":      900, // 15 minutes
		"scope":           strings.Join(grantedScopes, " "),
		"organization_id": orgID,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// TrustBundle handles GET /.well-known/spiffe/bundle - Authorizing machines refresh signing certs and JWKS to validate SVIDs
func (h *SPIFFEHandler) TrustBundle(w http.ResponseWriter, r *http.Request) {
	if h.admin.EnableCORS(w, r) {
		return
	}

	orgID := r.URL.Query().Get("organization")
	if orgID == "" {
		orgID = r.URL.Query().Get("tenant")
	}
	if orgID == "" {
		orgID = "default"
	}

	list, err := h.storage.List(r.Context(), fmt.Sprintf("organizations/%s/keys/", orgID))
	var keys []*models.SigningKey
	if err == nil {
		for _, rec := range list {
			var k models.SigningKey
			if err := json.Unmarshal(rec.Data, &k); err == nil && k.Active {
				keys = append(keys, &k)
			}
		}
	}

	jwksBytes, err := crypto.BuildJWKS(keys)
	if err != nil {
		http.Error(w, `{"error":"server_error","message":"failed to build trust bundle"}`, http.StatusInternalServerError)
		return
	}

	var jwksObj interface{}
	_ = json.Unmarshal(jwksBytes, &jwksObj)

	bundle := &models.SPIFFETrustBundle{
		SPIFFEID:       spiffe.BuildSPIFFEID("authpole.local", orgID, "trust-bundle"),
		OrganizationID: orgID,
		Domain:         "authpole.local",
		Keys:           jwksObj,
		UpdatedAt:      time.Now(),
		Version:        fmt.Sprintf("tb_%d", time.Now().Unix()),
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300") // 5 minutes cache refresh
	w.Header().Set("ETag", bundle.Version)
	_ = json.NewEncoder(w).Encode(bundle)
}

// HandleWorkloads handles Admin CRUD for SPIFFE Workloads: GET/POST/PUT /api/v1/admin/spiffe/workloads
func (h *SPIFFEHandler) HandleWorkloads(w http.ResponseWriter, r *http.Request) {
	if h.admin.EnableCORS(w, r) {
		return
	}

	if err := h.admin.AuthenticateAdmin(r); err != nil {
		h.admin.renderError(w, err, http.StatusUnauthorized)
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
		prefix := fmt.Sprintf("organizations/%s/spiffe/workloads/", orgID)
		list, err := h.storage.List(r.Context(), prefix)
		if err != nil {
			h.admin.renderError(w, err, http.StatusInternalServerError)
			return
		}
		var workloads []*models.SPIFFEWorkload
		for _, rec := range list {
			var item models.SPIFFEWorkload
			if err := json.Unmarshal(rec.Data, &item); err == nil {
				item.Version = rec.Version
				workloads = append(workloads, &item)
			}
		}
		h.admin.renderJSON(w, workloads, "")

	case http.MethodPost, http.MethodPut:
		var item models.SPIFFEWorkload
		if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
			h.admin.renderError(w, err, http.StatusBadRequest)
			return
		}

		if item.ID == "" {
			item.ID = fmt.Sprintf("workload_%d", time.Now().UnixNano())
		}
		item.OrganizationID = orgID
		if item.SPIFFEID == "" {
			item.SPIFFEID = spiffe.BuildSPIFFEID("authpole.local", orgID, item.ID)
		}

		// Compute fingerprint if client cert PEM provided
		if item.ClientCertPEM != "" && item.CertFingerprint == "" {
			fp, _ := spiffe.ComputeCertFingerprint(item.ClientCertPEM)
			item.CertFingerprint = fp
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
		newVer, err := h.storage.Put(r.Context(), storage.SPIFFEWorkloadKey(orgID, item.ID), data, expectedVersion)
		if err != nil {
			h.admin.renderError(w, err, http.StatusConflict)
			return
		}

		item.Version = newVer
		h.admin.renderJSON(w, item, newVer)

	default:
		h.admin.renderError(w, fmt.Errorf("method not allowed"), http.StatusMethodNotAllowed)
	}
}
