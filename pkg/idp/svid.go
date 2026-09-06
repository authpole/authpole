package idp

// SPIFFE SVID issuance.
//
// This lives on the engine rather than in the HTTP layer because issuing an SVID
// needs the tenant's signing key, and key material must not cross a package
// boundary. The engine already owns key resolution (resolveSigningKey), which is
// CAS-safe on creation and picks a deterministic active key, so an SVID is signed
// with the same key JWKS publishes.
//
// The caller is responsible for proving possession of the certificate's private
// key BEFORE calling this - through a real mutual-TLS handshake - and passes only
// the resulting fingerprint. Nothing here can establish possession, so a caller
// that passes a fingerprint it merely read would be authenticating with public
// data. See the transport layer for where that proof is obtained.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/authpole/authpole/pkg/crypto"
	"github.com/authpole/authpole/pkg/models"
	"github.com/authpole/authpole/pkg/spiffe"
	"github.com/authpole/authpole/pkg/storage"
)

// svidTTLMinutes is how long an issued JWT-SVID is valid.
//
// Short by design: an SVID cannot be revoked before it expires, so its lifetime IS
// its revocation window. Fifteen minutes keeps "stop issuing" an effective control
// without making refresh traffic significant.
const svidTTLMinutes = 15

// SVIDRequest asks for a JWT-SVID on behalf of one registered workload.
type SVIDRequest struct {
	OrganizationID string
	WorkloadID     string

	// CertFingerprint is the SHA-256 hex digest of the client certificate whose
	// private key the caller has ALREADY proven possession of. It is compared
	// against the fingerprint registered for the workload.
	CertFingerprint string

	// Audience is the resource server the SVID is for. It must appear in the
	// workload's AllowedAudiences when that list is non-empty.
	Audience string

	// RequestedScopes narrows the granted scopes. Omitted means "all allowed".
	RequestedScopes []string
}

// SVIDResponse is an issued JWT-SVID.
type SVIDResponse struct {
	SVID           string `json:"svid"`
	SPIFFEID       string `json:"spiffe_id"`
	TokenType      string `json:"token_type"`
	ExpiresIn      int    `json:"expires_in"`
	Scope          string `json:"scope,omitempty"`
	OrganizationID string `json:"organization_id"`
}

// Errors an SVID request can fail with. They are deliberately coarse at the
// transport boundary - a caller that has not authenticated should not learn which
// specific check it tripped - but distinct here so the server can log the reason.
var (
	ErrWorkloadNotFound    = fmt.Errorf("workload is not registered")
	ErrWorkloadInactive    = fmt.Errorf("workload is not active")
	ErrFingerprintMismatch = fmt.Errorf("certificate does not match the workload's registered fingerprint")
	ErrAudienceNotAllowed  = fmt.Errorf("requested audience is not allowed for this workload")
	ErrWorkloadUnbound     = fmt.Errorf("workload has no registered certificate fingerprint")
	ErrNoSPIFFEID          = fmt.Errorf("workload has no SPIFFE ID")
)

// IssueSVID mints a short-lived JWT-SVID for a registered workload.
func (e *IDPEngine) IssueSVID(ctx context.Context, req SVIDRequest) (*SVIDResponse, error) {
	orgID := strings.TrimSpace(req.OrganizationID)
	workloadID := strings.TrimSpace(req.WorkloadID)
	if orgID == "" || workloadID == "" {
		return nil, fmt.Errorf("organization and workload id are required")
	}

	rec, err := e.storage.Get(ctx, storage.SPIFFEWorkloadKey(orgID, workloadID))
	if err != nil || rec == nil {
		return nil, ErrWorkloadNotFound
	}

	var workload models.SPIFFEWorkload
	if err := json.Unmarshal(rec.Data, &workload); err != nil {
		return nil, ErrWorkloadNotFound
	}
	if !workload.Active {
		return nil, ErrWorkloadInactive
	}

	// A workload with no registered fingerprint cannot be authenticated against
	// anything, so it must never be issued an SVID. Refusing here mirrors
	// ValidateWorkloadCert: before that guard existed, an unbound workload
	// authenticated ANY caller who knew its id.
	registered := strings.ToLower(strings.TrimSpace(workload.CertFingerprint))
	if registered == "" {
		return nil, ErrWorkloadUnbound
	}

	presented := strings.ToLower(strings.TrimSpace(req.CertFingerprint))
	if presented == "" || !crypto.SecureCompare(registered, presented) {
		return nil, ErrFingerprintMismatch
	}

	// The SPIFFE ID is taken from the registration, never rebuilt from the request:
	// the registered value is what an operator reviewed and what any authorizer's
	// policy refers to.
	spiffeID := strings.TrimSpace(workload.SPIFFEID)
	if spiffeID == "" {
		return nil, ErrNoSPIFFEID
	}

	audience, err := resolveSVIDAudience(&workload, req.Audience)
	if err != nil {
		return nil, err
	}

	// Org-level key (empty appID): an SVID belongs to the tenant, not to any one
	// OIDC application, and a verifier fetches the tenant's JWKS to check it.
	signingKey, err := e.resolveSigningKey(ctx, orgID, "")
	if err != nil {
		return nil, fmt.Errorf("failed to resolve signing key: %w", err)
	}

	granted := grantScopes(&workload, req.RequestedScopes)

	claims := &models.AuthClaims{
		Subject:        spiffeID,
		Issuer:         e.IssuerFor(orgID),
		Audience:       models.Audience{audience},
		TokenUse:       models.TokenUseAccess,
		OrganizationID: orgID,
		WorkloadID:     workload.ID,
		SPIFFEID:       spiffeID,
		Scope:          strings.Join(granted, " "),
		NotBefore:      time.Now().Unix(),
	}
	if claims.JTI, err = crypto.SecureToken("jti_"); err != nil {
		return nil, fmt.Errorf("failed to generate token id: %w", err)
	}

	svid, err := spiffe.IssueJWTSVID(claims, signingKey, svidTTLMinutes)
	if err != nil {
		return nil, fmt.Errorf("failed to sign SVID: %w", err)
	}

	return &SVIDResponse{
		SVID:           svid,
		SPIFFEID:       spiffeID,
		TokenType:      "Bearer",
		ExpiresIn:      svidTTLMinutes * 60,
		Scope:          strings.Join(granted, " "),
		OrganizationID: orgID,
	}, nil
}

// resolveSVIDAudience picks the audience and enforces the workload's allow-list.
//
// AllowedAudiences was previously carried on the model and never checked, so a
// workload could mint an SVID naming ANY audience - including another service's,
// which is exactly the confusion an audience claim exists to prevent.
func resolveSVIDAudience(workload *models.SPIFFEWorkload, requested string) (string, error) {
	requested = strings.TrimSpace(requested)

	if len(workload.AllowedAudiences) == 0 {
		// No allow-list configured. Require the caller to name one rather than
		// inventing a default: a guessed audience either fails at the verifier or,
		// worse, happens to match one it accepts.
		if requested == "" {
			return "", fmt.Errorf("audience is required: this workload has no allowed_audiences configured")
		}
		return requested, nil
	}

	if requested == "" {
		// Unambiguous only when exactly one audience is permitted.
		if len(workload.AllowedAudiences) == 1 {
			return workload.AllowedAudiences[0], nil
		}
		return "", fmt.Errorf("audience is required: this workload allows %d audiences", len(workload.AllowedAudiences))
	}

	for _, allowed := range workload.AllowedAudiences {
		if allowed == requested {
			return requested, nil
		}
	}
	return "", ErrAudienceNotAllowed
}

// grantScopes intersects the requested scopes with what the workload may have.
// An empty request grants everything the workload is allowed.
func grantScopes(workload *models.SPIFFEWorkload, requested []string) []string {
	if len(requested) == 0 {
		return workload.AllowedScopes
	}

	granted := make([]string, 0, len(requested))
	for _, want := range requested {
		for _, allowed := range workload.AllowedScopes {
			if allowed == "*" || allowed == want {
				granted = append(granted, want)
				break
			}
		}
	}
	return granted
}
