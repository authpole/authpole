package idp_test

// Tests for default upstream-provider selection.
//
// The behaviour under test was previously wrong in a way that read as a configuration
// error: an app with no AllowedIDPs restriction reported "no upstream IDP configured
// for this application" even when the tenant had several working providers. That is the
// message jaydb-cloud's console hit on app.jaydb.com with Google AND GitHub both
// registered and enabled.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/authpole/authpole/pkg/idp"
	"github.com/authpole/authpole/pkg/models"
	"github.com/authpole/authpole/pkg/storage"
)

const (
	idpTestOrg      = "acme"
	idpTestClientID = "spa"
	idpTestRedirect = "https://acme.example.com/callback"
	idpTestVerifier = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

// seedAppWithoutIDP registers a public client and NO identity provider. Distinct from
// seedApp in idp_engine_test.go, which also seeds a "mock" provider - that would defeat
// every test here, since what is under test is how the absent, single and multiple
// provider cases resolve.
func seedAppWithoutIDP(t *testing.T, store storage.Storage, allowedIDPs []string) {
	t.Helper()

	app := &models.Application{
		ID:             idpTestClientID,
		OrganizationID: idpTestOrg,
		ClientID:       idpTestClientID,
		Name:           "SPA",
		Public:         true,
		RedirectURIs:   []string{idpTestRedirect},
		AllowedIDPs:    allowedIDPs,
	}
	payload, err := json.Marshal(app)
	if err != nil {
		t.Fatalf("encode app: %v", err)
	}
	if _, err := store.Put(context.Background(), storage.AppKey(idpTestOrg, app.ID), payload, ""); err != nil {
		t.Fatalf("seed app: %v", err)
	}
}

func seedTenantIDP(t *testing.T, store storage.Storage, id string, enabled bool) {
	t.Helper()

	provider := &models.IdentityProvider{
		ID:             id,
		OrganizationID: idpTestOrg,
		Name:           strings.ToUpper(id),
		Type:           "oauth2",
		Preset:         id,
		ClientID:       id + "-client",
		ClientSecret:   id + "-secret",
		Enabled:        enabled,
	}
	payload, err := json.Marshal(provider)
	if err != nil {
		t.Fatalf("encode idp: %v", err)
	}
	if _, err := store.Put(context.Background(), storage.IDPKey(idpTestOrg, id), payload, ""); err != nil {
		t.Fatalf("seed idp: %v", err)
	}
}

func authorizeRequest(idpID string) idp.AuthorizationRequest {
	return idp.AuthorizationRequest{
		OrganizationID:      idpTestOrg,
		ClientID:            idpTestClientID,
		RedirectURI:         idpTestRedirect,
		CodeChallenge:       idpTestVerifier,
		CodeChallengeMethod: "S256",
		IDPID:               idpID,
	}
}

// TestSingleTenantIDPIsImpliedWhenAppIsUnrestricted is the ergonomic half: with exactly
// one provider there is nothing ambiguous to resolve, so the caller should not have to
// name it.
func TestSingleTenantIDPIsImpliedWhenAppIsUnrestricted(t *testing.T) {
	engine, store := newEngine(t)
	seedAppWithoutIDP(t, store, nil)
	seedTenantIDP(t, store, "google", true)

	url, err := engine.PrepareAuthorization(context.Background(), authorizeRequest(""))
	if err != nil {
		t.Fatalf("a lone tenant provider should be implied: %v", err)
	}
	if !strings.Contains(url, "google") && !strings.Contains(url, "accounts.google.com") {
		t.Errorf("expected a redirect to the tenant's only provider, got %q", url)
	}
}

// TestSeveralTenantIDPsRequireNamingOne is the corrected error. It must say the choice
// is required and name the options, not claim nothing is configured.
func TestSeveralTenantIDPsRequireNamingOne(t *testing.T) {
	engine, store := newEngine(t)
	seedAppWithoutIDP(t, store, nil)
	seedTenantIDP(t, store, "google", true)
	seedTenantIDP(t, store, "github", true)

	_, err := engine.PrepareAuthorization(context.Background(), authorizeRequest(""))
	if err == nil {
		t.Fatal("with two providers and none named the request must be refused")
	}

	message := err.Error()
	if strings.Contains(message, "no upstream IDP configured for this application") {
		t.Errorf("the old misleading message is back: %q", message)
	}
	for _, want := range []string{"idp", "google", "github"} {
		if !strings.Contains(message, want) {
			t.Errorf("error should mention %q so the caller can act on it; got %q", want, message)
		}
	}
}

// TestNoTenantIDPsSaysSoAboutTheTENANT keeps the genuinely-unconfigured case accurate:
// the thing missing configuration is the tenant, not the application.
func TestNoTenantIDPsSaysSoAboutTheTENANT(t *testing.T) {
	engine, store := newEngine(t)
	seedAppWithoutIDP(t, store, nil)

	_, err := engine.PrepareAuthorization(context.Background(), authorizeRequest(""))
	if err == nil {
		t.Fatal("with no providers at all the request must be refused")
	}
	if !strings.Contains(err.Error(), "tenant") {
		t.Errorf("error should attribute the missing configuration to the tenant, got %q", err.Error())
	}
}

// TestDisabledIDPIsNotAvailable: a disabled provider must not be implied as the default,
// or disabling one would silently keep it in use.
func TestDisabledIDPIsNotAvailable(t *testing.T) {
	engine, store := newEngine(t)
	seedAppWithoutIDP(t, store, nil)
	seedTenantIDP(t, store, "google", false)

	if _, err := engine.PrepareAuthorization(context.Background(), authorizeRequest("")); err == nil {
		t.Fatal("a disabled provider must not be selected as the default")
	}
}

// TestAllowedIDPsStillWins keeps the restriction authoritative: when an app names its
// providers, the tenant's wider set must not widen the app's.
func TestAllowedIDPsStillWins(t *testing.T) {
	engine, store := newEngine(t)
	seedAppWithoutIDP(t, store, []string{"google"})
	seedTenantIDP(t, store, "google", true)
	seedTenantIDP(t, store, "github", true)

	if _, err := engine.PrepareAuthorization(context.Background(), authorizeRequest("github")); err == nil {
		t.Fatal("an app restricted to google must not authenticate through github")
	}
}
