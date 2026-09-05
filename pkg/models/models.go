package models

import (
	"encoding/json"
	"fmt"
	"time"
)

// Token use values carried in the `token_use` claim. An ID token and an access
// token must never be interchangeable: an ID token describes *who the user is*
// to the client that requested the login, while an access token authorizes calls
// against a resource server. Minting them as the same bytes lets a client replay
// an identity assertion as an authorization grant, so every issued token is
// stamped and every verifier is expected to demand the use it needs.
const (
	TokenUseAccess  = "access"
	TokenUseID      = "id"
	TokenUseRefresh = "refresh"
)

// Audience models the JWT `aud` claim. RFC 7519 §4.1.3 allows either a single
// string or an array of strings, and tokens in the wild use both, so this type
// accepts either on the wire and re-marshals a single element as a bare string
// for compatibility with verifiers that only understand that form.
type Audience []string

// MarshalJSON emits a lone audience as a string and multiple as an array.
func (a Audience) MarshalJSON() ([]byte, error) {
	switch len(a) {
	case 0:
		return []byte(`""`), nil
	case 1:
		return json.Marshal(a[0])
	default:
		return json.Marshal([]string(a))
	}
}

// UnmarshalJSON accepts either the string or the array form of `aud`.
func (a *Audience) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		if single == "" {
			*a = nil
			return nil
		}
		*a = Audience{single}
		return nil
	}

	var multi []string
	if err := json.Unmarshal(data, &multi); err != nil {
		return fmt.Errorf("aud claim must be a string or an array of strings: %w", err)
	}
	*a = Audience(multi)
	return nil
}

// Contains reports whether want is one of the audiences. An empty want never
// matches, so a verifier that forgot to configure its audience fails closed
// instead of accepting every token.
func (a Audience) Contains(want string) bool {
	if want == "" {
		return false
	}
	for _, aud := range a {
		if aud == want {
			return true
		}
	}
	return false
}

// Organization represents a multi-tenant isolation unit in Auth Pole.
type Organization struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Domain      string     `json:"domain"`
	InitialUser *AdminUser `json:"initial_user,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	Version     string     `json:"version"` // CAS version (ETag / Revision ID)
}

// Application represents a Relying Party / Service Provider app registered in Auth Pole.
type Application struct {
	ID             string   `json:"id"`
	OrganizationID string   `json:"organization_id"`
	Name           string   `json:"name"`
	ClientID       string   `json:"client_id"`
	ClientSecret   string   `json:"client_secret"`
	RedirectURIs   []string `json:"redirect_uris"`
	AllowedIDPs    []string `json:"allowed_idps"` // Upstream IDP IDs enabled for this app
	Scopes         []string `json:"scopes"`
	// Public marks a client that cannot hold a secret - a browser SPA or a mobile
	// app, where any embedded secret ships to the user. Public clients authenticate
	// their token request with PKCE instead of a secret, and must never be allowed
	// to fall back to secret-based authentication.
	Public bool `json:"public"`
	// AllowedOrigins lists the web origins permitted to call the token endpoint
	// with CORS. A public client's token request comes from a browser, so the
	// endpoint cannot be wildcard-open without letting any site drive a redemption.
	AllowedOrigins []string `json:"allowed_origins,omitempty"`
	// Audiences lists the resource servers tokens for this app may be minted for.
	// Empty means the client's own ID is the only audience.
	Audiences []string  `json:"audiences,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Version   string    `json:"version"` // CAS version
}

// IsPublicClient reports whether the app must use PKCE instead of a client secret.
// An app with no registered secret is treated as public even when the flag was not
// set, so a half-configured record fails safe (PKCE required) rather than open
// (neither a secret nor a challenge demanded).
func (a *Application) IsPublicClient() bool {
	if a == nil {
		return false
	}
	return a.Public || a.ClientSecret == ""
}

// HasRedirectURI reports whether uri exactly matches a registered redirect URI.
// Matching is exact by design: prefix or wildcard matching on a redirect target is
// how authorization codes end up delivered to attacker-controlled endpoints.
func (a *Application) HasRedirectURI(uri string) bool {
	if a == nil || uri == "" {
		return false
	}
	for _, registered := range a.RedirectURIs {
		if registered == uri {
			return true
		}
	}
	return false
}

// HasAllowedOrigin reports whether origin may call the token endpoint via CORS.
func (a *Application) HasAllowedOrigin(origin string) bool {
	if a == nil || origin == "" {
		return false
	}
	for _, allowed := range a.AllowedOrigins {
		if allowed == origin {
			return true
		}
	}
	return false
}

// TokenAudiences returns the audiences to stamp into an access token for this app,
// defaulting to the client's own identifier.
func (a *Application) TokenAudiences() Audience {
	if a == nil {
		return nil
	}
	if len(a.Audiences) > 0 {
		return Audience(a.Audiences)
	}
	if a.ClientID != "" {
		return Audience{a.ClientID}
	}
	return nil
}

// IdentityProvider represents an upstream federated IDP (e.g., Google, GitHub, Okta, OIDC/OAuth2/SAML provider).
type IdentityProvider struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	Name           string    `json:"name"`
	Type           string    `json:"type"` // "oidc", "oauth2", "saml", "mock"
	IssuerURL      string    `json:"issuer_url,omitempty"`
	ClientID       string    `json:"client_id"`
	ClientSecret   string    `json:"client_secret"`
	AuthorizeURL   string    `json:"authorize_url"`
	TokenURL       string    `json:"token_url"`
	UserInfoURL    string    `json:"user_info_url,omitempty"`
	Scopes         []string  `json:"scopes"`
	Enabled        bool      `json:"enabled"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	Version        string    `json:"version"` // CAS version
}

// SigningKey represents asymmetric key pair used for signing Auth Pole JWT tokens per organization/app.
type SigningKey struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	AppID          string    `json:"app_id,omitempty"`
	Algorithm      string    `json:"algorithm"` // "RS256" or "EdDSA"
	PrivateKeyPEM  string    `json:"private_key_pem,omitempty"`
	PublicKeyPEM   string    `json:"public_key_pem"`
	KID            string    `json:"kid"`
	Active         bool      `json:"active"`
	CreatedAt      time.Time `json:"created_at"`
	Version        string    `json:"version"` // CAS version
}

// ActiveSigningKey picks the key to sign new tokens with: the newest active key
// that still holds a private key.
//
// Selection is deterministic on purpose. Picking an arbitrary map/slice element
// means two nodes can sign with two different keys during a rotation, and a
// verifier that fetched JWKS a moment earlier rejects half the traffic. Newest
// wins so that publishing a new key rotates signing forward while the previous
// key stays in JWKS to verify tokens already in flight.
func ActiveSigningKey(keys []*SigningKey) *SigningKey {
	var chosen *SigningKey
	for _, k := range keys {
		if k == nil || !k.Active || k.PrivateKeyPEM == "" {
			continue
		}
		if chosen == nil || k.CreatedAt.After(chosen.CreatedAt) {
			chosen = k
		}
	}
	return chosen
}

// AdminUser represents a console administrator with assigned roles and teams.
type AdminUser struct {
	ID             string     `json:"id"`
	OrganizationID string     `json:"organization_id"`
	Email          string     `json:"email"`
	Name           string     `json:"name"`
	RoleIDs        []string   `json:"role_ids"`
	TeamIDs        []string   `json:"team_ids"`
	Active         bool       `json:"active"`
	Status         string     `json:"status,omitempty"` // "active", "invited"
	InvitedBy      string     `json:"invited_by,omitempty"`
	InvitedAt      *time.Time `json:"invited_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	Version        string     `json:"version"` // CAS version
}

// Team represents an administrative grouping of users in the console.
type Team struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	Name           string    `json:"name"`
	Description    string    `json:"description"`
	RoleIDs        []string  `json:"role_ids"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	Version        string    `json:"version"` // CAS version
}

// Role represents administrative permissions in the console.
type Role struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	Name           string    `json:"name"`
	Description    string    `json:"description"`
	Permissions    []string  `json:"permissions"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	Version        string    `json:"version"` // CAS version
}

// SPIFFEWorkload represents a registered M2M workload identity in Auth Pole.
type SPIFFEWorkload struct {
	ID               string    `json:"id"`
	OrganizationID   string    `json:"organization_id"`
	SPIFFEID         string    `json:"spiffe_id"` // e.g. spiffe://authpole.local/ns/default/sa/payment-service
	Name             string    `json:"name"`
	CertFingerprint  string    `json:"cert_fingerprint,omitempty"` // SHA-256 fingerprint of long-expiry cert
	ClientCertPEM    string    `json:"client_cert_pem,omitempty"`
	AllowedScopes    []string  `json:"allowed_scopes"`
	AllowedAudiences []string  `json:"allowed_audiences"`
	Active           bool      `json:"active"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
	Version          string    `json:"version"` // CAS version
}

// SPIFFETrustBundle represents the SPIFFE trust bundle for authorizing machines.
type SPIFFETrustBundle struct {
	SPIFFEID       string      `json:"spiffe_id"`
	OrganizationID string      `json:"organization_id"`
	Domain         string      `json:"domain"`
	Keys           interface{} `json:"keys"` // JWKS payload for validating SPIFFE JWT-SVIDs
	CACerts        []string    `json:"ca_certs,omitempty"`
	UpdatedAt      time.Time   `json:"updated_at"`
	Version        string      `json:"version"`
}

// StoredRecord wraps data stored in S3 object store with its CAS Version metadata.
type StoredRecord struct {
	Key     string `json:"key"`
	Version string `json:"version"`
	Data    []byte `json:"data"`
}

// AuthClaims represents normalized claims contained within Auth Pole issued JWT tokens.
type AuthClaims struct {
	Subject        string   `json:"sub"`
	Issuer         string   `json:"iss"`
	Audience       Audience `json:"aud"`
	TokenUse       string   `json:"token_use,omitempty"`
	JTI            string   `json:"jti,omitempty"`
	OrganizationID string   `json:"organization_id"`
	AppID          string   `json:"app_id,omitempty"`
	WorkloadID     string   `json:"workload_id,omitempty"`
	SPIFFEID       string   `json:"spiffe_id,omitempty"`
	Scope          string   `json:"scope,omitempty"`
	OriginalIDP    string   `json:"original_idp,omitempty"`
	Email          string   `json:"email,omitempty"`
	Name           string   `json:"name,omitempty"`
	PreferredUser  string   `json:"preferred_username,omitempty"`
	Roles          []string `json:"roles,omitempty"`
	Groups         []string `json:"groups,omitempty"`
	IssuedAt       int64    `json:"iat"`
	NotBefore      int64    `json:"nbf,omitempty"`
	ExpiresAt      int64    `json:"exp"`
	Nonce          string   `json:"nonce,omitempty"`
}
