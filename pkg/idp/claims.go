package idp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"authpole/pkg/models"
)

// Preset holds sensible defaults for a well-known upstream provider.
//
// Presets are defaults only. Previously the callback branched on the provider's ID
// with the endpoints and field names compiled in, so a tenant registering its own
// OIDC provider fell through to a stub that gave EVERY user the same subject. Now
// every provider is driven by configuration, and these presets just save an
// operator from typing the well-known parts.
type Preset struct {
	Type         string
	AuthorizeURL string
	TokenURL     string
	UserInfoURL  string
	EmailsURL    string
	Scopes       []string
	Mapping      models.ClaimMapping
}

// presets are keyed by lowercase provider name.
var presets = map[string]Preset{
	"google": {
		Type:         "oidc",
		AuthorizeURL: "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:     "https://oauth2.googleapis.com/token",
		UserInfoURL:  "https://openidconnect.googleapis.com/v1/userinfo",
		Scopes:       []string{"openid", "email", "profile"},
		Mapping: models.ClaimMapping{
			Subject: "sub", Email: "email", EmailVerified: "email_verified",
			Name: "name", Username: "email",
		},
	},
	"github": {
		Type:         "oauth2",
		AuthorizeURL: "https://github.com/login/oauth/authorize",
		TokenURL:     "https://github.com/login/oauth/access_token",
		UserInfoURL:  "https://api.github.com/user",
		EmailsURL:    "https://api.github.com/user/emails",
		Scopes:       []string{"read:user", "user:email"},
		Mapping: models.ClaimMapping{
			Subject: "id", Email: "email", Name: "name", Username: "login",
		},
	},
	"microsoft": {
		Type:         "oidc",
		AuthorizeURL: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
		TokenURL:     "https://login.microsoftonline.com/common/oauth2/v2.0/token",
		UserInfoURL:  "https://graph.microsoft.com/oidc/userinfo",
		Scopes:       []string{"openid", "email", "profile"},
		Mapping: models.ClaimMapping{
			Subject: "sub", Email: "email", Name: "name", Username: "preferred_username",
		},
	},
	"facebook": {
		// Facebook is OAuth2, not OIDC: there is no id_token, so identity comes from
		// the Graph profile endpoint.
		Type:         "oauth2",
		AuthorizeURL: "https://www.facebook.com/v19.0/dialog/oauth",
		TokenURL:     "https://graph.facebook.com/v19.0/oauth/access_token",
		UserInfoURL:  "https://graph.facebook.com/me?fields=id,name,email",
		Scopes:       []string{"public_profile", "email"},
		Mapping: models.ClaimMapping{
			Subject: "id", Email: "email", Name: "name",
		},
	},
	"instagram": {
		// Instagram Basic Display returns no email at all, so a tenant relying on it
		// must not require one. It is OAuth2 with a username-only profile.
		Type:         "oauth2",
		AuthorizeURL: "https://api.instagram.com/oauth/authorize",
		TokenURL:     "https://api.instagram.com/oauth/access_token",
		UserInfoURL:  "https://graph.instagram.com/me?fields=id,username",
		Scopes:       []string{"user_profile"},
		Mapping: models.ClaimMapping{
			Subject: "id", Username: "username", Name: "username",
		},
	},
}

// PresetFor returns the built-in defaults for a provider name.
func PresetFor(name string) (Preset, bool) {
	p, ok := presets[strings.ToLower(strings.TrimSpace(name))]
	return p, ok
}

// effectiveProvider merges a stored provider record with its preset defaults.
// Explicit configuration always wins.
func effectiveProvider(p *models.IdentityProvider) models.IdentityProvider {
	merged := *p

	presetName := p.Preset
	if presetName == "" {
		presetName = p.ID
	}
	preset, ok := PresetFor(presetName)
	if !ok {
		return merged
	}

	if merged.Type == "" {
		merged.Type = preset.Type
	}
	if merged.AuthorizeURL == "" {
		merged.AuthorizeURL = preset.AuthorizeURL
	}
	if merged.TokenURL == "" {
		merged.TokenURL = preset.TokenURL
	}
	if merged.UserInfoURL == "" {
		merged.UserInfoURL = preset.UserInfoURL
	}
	if merged.EmailsURL == "" {
		merged.EmailsURL = preset.EmailsURL
	}
	if len(merged.Scopes) == 0 {
		merged.Scopes = preset.Scopes
	}

	m := &merged.ClaimMapping
	if m.Subject == "" {
		m.Subject = preset.Mapping.Subject
	}
	if m.Email == "" {
		m.Email = preset.Mapping.Email
	}
	if m.EmailVerified == "" {
		m.EmailVerified = preset.Mapping.EmailVerified
	}
	if m.Name == "" {
		m.Name = preset.Mapping.Name
	}
	if m.Username == "" {
		m.Username = preset.Mapping.Username
	}
	if m.Groups == "" {
		m.Groups = preset.Mapping.Groups
	}
	if m.Roles == "" {
		m.Roles = preset.Mapping.Roles
	}

	return merged
}

// lookupField resolves a possibly-dotted field path in a decoded JSON object.
func lookupField(profile map[string]any, path string) (any, bool) {
	if path == "" {
		return nil, false
	}
	segments := strings.Split(path, ".")
	var current any = profile
	for _, segment := range segments {
		obj, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = obj[segment]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

// stringField coerces a mapped field to a string.
//
// JSON numbers decode to float64, and provider user IDs are frequently numeric
// (GitHub, Facebook). Formatting via %v would render large IDs in scientific
// notation and silently corrupt the account key, so integral floats are formatted
// as integers.
func stringField(profile map[string]any, path string) string {
	raw, ok := lookupField(profile, path)
	if !ok || raw == nil {
		return ""
	}
	switch v := raw.(type) {
	case string:
		return v
	case bool:
		return strconv.FormatBool(v)
	case float64:
		if v == float64(int64(v)) {
			return strconv.FormatInt(int64(v), 10)
		}
		return strconv.FormatFloat(v, 'f', -1, 64)
	case json.Number:
		return v.String()
	default:
		return fmt.Sprintf("%v", v)
	}
}

// boolField reads a mapped boolean, tolerating the string forms providers emit.
func boolField(profile map[string]any, path string) (value bool, present bool) {
	raw, ok := lookupField(profile, path)
	if !ok || raw == nil {
		return false, false
	}
	switch v := raw.(type) {
	case bool:
		return v, true
	case string:
		parsed, err := strconv.ParseBool(v)
		return parsed, err == nil
	default:
		return false, false
	}
}

// stringsField reads a mapped list of strings (groups, roles).
func stringsField(profile map[string]any, path string) []string {
	raw, ok := lookupField(profile, path)
	if !ok || raw == nil {
		return nil
	}
	switch v := raw.(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		if v == "" {
			return nil
		}
		return strings.Split(v, " ")
	default:
		return nil
	}
}

// fetchUpstreamClaims retrieves and normalizes the authenticated user's profile
// from any configured upstream provider.
//
// Identity is taken from the profile endpoint, authenticated with the access token
// we just received over TLS from the provider's own token endpoint. It is
// deliberately NOT taken from the upstream id_token, because verifying that would
// require fetching and pinning the provider's JWKS; an unverified id_token is
// attacker-supplied data and must never be trusted for identity.
func (e *IDPEngine) fetchUpstreamClaims(
	ctx context.Context,
	client *http.Client,
	provider *models.IdentityProvider,
	accessToken string,
) (*models.AuthClaims, error) {
	cfg := effectiveProvider(provider)

	if cfg.UserInfoURL == "" {
		return nil, fmt.Errorf("identity provider %q has no user_info_url configured and no preset supplies one", provider.ID)
	}
	if cfg.ClaimMapping.Subject == "" {
		return nil, fmt.Errorf("identity provider %q has no subject claim mapping; refusing to guess a user identifier", provider.ID)
	}

	profile, err := fetchJSONObject(ctx, client, cfg.UserInfoURL, accessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch profile from %s: %w", provider.ID, err)
	}

	subject := stringField(profile, cfg.ClaimMapping.Subject)
	if subject == "" {
		// Without a stable subject there is nothing safe to key the account on. The
		// old code invented one here ("<idp>_user"), which collapsed every user of a
		// custom provider into a single shared account.
		return nil, fmt.Errorf("identity provider %q did not return a value for subject field %q",
			provider.ID, cfg.ClaimMapping.Subject)
	}

	email := stringField(profile, cfg.ClaimMapping.Email)

	// Secondary email endpoint, for providers that omit a private address from the
	// main profile response.
	if email == "" && cfg.EmailsURL != "" {
		if fetched := fetchPrimaryEmail(ctx, client, cfg.EmailsURL, accessToken); fetched != "" {
			email = fetched
		}
	}

	// Refuse an address the provider itself says is unverified.
	if email != "" && cfg.ClaimMapping.EmailVerified != "" {
		if verified, present := boolField(profile, cfg.ClaimMapping.EmailVerified); present && !verified {
			return nil, fmt.Errorf("identity provider %q reported the email address as unverified", provider.ID)
		}
	}

	username := stringField(profile, cfg.ClaimMapping.Username)
	name := stringField(profile, cfg.ClaimMapping.Name)
	if name == "" {
		if username != "" {
			name = username
		} else {
			name = email
		}
	}

	claims := &models.AuthClaims{
		// Namespace the subject by provider so two providers cannot collide on the
		// same identifier, and keep the raw value so a host application can key
		// accounts on the (provider, subject) tuple.
		Subject:         fmt.Sprintf("%s_%s", provider.ID, subject),
		UpstreamSubject: subject,
		OriginalIDP:     provider.ID,
		Email:           email,
		Name:            name,
		PreferredUser:   username,
		Groups:          stringsField(profile, cfg.ClaimMapping.Groups),
		Roles:           stringsField(profile, cfg.ClaimMapping.Roles),
	}
	if len(claims.Roles) == 0 {
		claims.Roles = []string{"user"}
	}

	return claims, nil
}

// maxProfileBytes bounds a profile response so a hostile or broken upstream cannot
// exhaust memory.
const maxProfileBytes = 1 << 20 // 1 MiB

// fetchJSONObject GETs a bearer-authenticated JSON object.
func fetchJSONObject(ctx context.Context, client *http.Client, url, accessToken string) (map[string]any, error) {
	body, err := fetchBody(ctx, client, url, accessToken)
	if err != nil {
		return nil, err
	}

	var profile map[string]any
	if err := json.Unmarshal(body, &profile); err != nil {
		return nil, fmt.Errorf("profile response was not a JSON object: %w", err)
	}
	return profile, nil
}

func fetchBody(ctx context.Context, client *http.Client, url, accessToken string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	// GitHub rejects requests without a User-Agent; harmless elsewhere.
	req.Header.Set("User-Agent", "AuthPole-Mediator")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProfileBytes))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("profile endpoint returned HTTP %d", resp.StatusCode)
	}
	return body, nil
}

// fetchPrimaryEmail reads a provider's separate email-list endpoint and returns the
// primary verified address. Only a verified address is accepted.
func fetchPrimaryEmail(ctx context.Context, client *http.Client, url, accessToken string) string {
	body, err := fetchBody(ctx, client, url, accessToken)
	if err != nil {
		return ""
	}

	var list []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return ""
	}

	for _, entry := range list {
		if entry.Primary && entry.Verified {
			return entry.Email
		}
	}
	// Fall back to any verified address, but never an unverified one: an
	// unverified address is user-typed input, not an identity assertion.
	for _, entry := range list {
		if entry.Verified {
			return entry.Email
		}
	}
	return ""
}
