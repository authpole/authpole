package models

import (
	"time"
)

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
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	Name           string    `json:"name"`
	ClientID       string    `json:"client_id"`
	ClientSecret   string    `json:"client_secret"`
	RedirectURIs   []string  `json:"redirect_uris"`
	AllowedIDPs    []string  `json:"allowed_idps"` // Upstream IDP IDs enabled for this app
	Scopes         []string  `json:"scopes"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	Version        string    `json:"version"` // CAS version
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
	Audience       string   `json:"aud"`
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
	ExpiresAt      int64    `json:"exp"`
	Nonce          string   `json:"nonce,omitempty"`
}
