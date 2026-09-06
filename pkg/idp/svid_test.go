package idp_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/authpole/authpole/pkg/crypto"
	"github.com/authpole/authpole/pkg/idp"
	"github.com/authpole/authpole/pkg/models"
	"github.com/authpole/authpole/pkg/storage"
)

const (
	testOrg         = "acme"
	testWorkload    = "importer"
	testSPIFFEID    = "spiffe://jaydb.com/ns/acme/sa/importer"
	testFingerprint = "01fbf94fef5569753420c349f49adbfd80af5275377816e3ab1fb371b29cb586"
)

// seedWorkload registers a SPIFFE workload for the issuance tests.
func seedWorkload(t *testing.T, store storage.Storage, mutate func(*models.SPIFFEWorkload)) {
	t.Helper()

	workload := &models.SPIFFEWorkload{
		ID:               testWorkload,
		OrganizationID:   testOrg,
		SPIFFEID:         testSPIFFEID,
		Name:             "Importer",
		CertFingerprint:  testFingerprint,
		AllowedScopes:    []string{"docs:read", "docs:write"},
		AllowedAudiences: []string{"jaydb-data"},
		Active:           true,
	}
	if mutate != nil {
		mutate(workload)
	}

	payload, err := json.Marshal(workload)
	if err != nil {
		t.Fatalf("encode workload: %v", err)
	}
	if _, err := store.Put(context.Background(),
		storage.SPIFFEWorkloadKey(testOrg, workload.ID), payload, ""); err != nil {
		t.Fatalf("seed workload: %v", err)
	}
}

func svidEngine(t *testing.T, mutate func(*models.SPIFFEWorkload)) *idp.IDPEngine {
	t.Helper()
	engine, store := newEngine(t)
	seedWorkload(t, store, mutate)
	return engine
}

func baseRequest() idp.SVIDRequest {
	return idp.SVIDRequest{
		OrganizationID:  testOrg,
		WorkloadID:      testWorkload,
		CertFingerprint: testFingerprint,
		Audience:        "jaydb-data",
	}
}

func TestIssueSVIDSucceeds(t *testing.T) {
	engine := svidEngine(t, nil)

	resp, err := engine.IssueSVID(context.Background(), baseRequest())
	if err != nil {
		t.Fatalf("IssueSVID: %v", err)
	}

	if resp.SPIFFEID != testSPIFFEID {
		t.Errorf("spiffe_id = %q, want %q", resp.SPIFFEID, testSPIFFEID)
	}
	if resp.ExpiresIn != 15*60 {
		t.Errorf("expires_in = %d, want 900 (short lifetime is the revocation window)", resp.ExpiresIn)
	}

	// The SVID must verify against the tenant's PUBLIC keys - the same set JWKS
	// publishes - with the per-tenant issuer pinned.
	keys, err := engine.SigningKeys(context.Background(), testOrg, "")
	if err != nil {
		t.Fatalf("load verification keys: %v", err)
	}
	claims, err := crypto.VerifyJWTWithOptions(resp.SVID, keys, crypto.VerifyOptions{
		ExpectedIssuer:   engine.IssuerFor(testOrg),
		ExpectedAudience: "jaydb-data",
		ExpectedTokenUse: models.TokenUseAccess,
	})
	if err != nil {
		t.Fatalf("SVID failed verification: %v", err)
	}
	if claims.SPIFFEID != testSPIFFEID {
		t.Errorf("spiffe_id claim = %q", claims.SPIFFEID)
	}
	if claims.WorkloadID != testWorkload {
		t.Errorf("workload_id claim = %q", claims.WorkloadID)
	}
}

// TestFingerprintMismatchIsRefused is the core authentication check: a caller
// presenting a certificate that is not the registered one gets nothing.
func TestFingerprintMismatchIsRefused(t *testing.T) {
	engine := svidEngine(t, nil)

	req := baseRequest()
	req.CertFingerprint = strings.Repeat("ab", 32)

	if _, err := engine.IssueSVID(context.Background(), req); !errors.Is(err, idp.ErrFingerprintMismatch) {
		t.Fatalf("expected a fingerprint mismatch, got %v", err)
	}
}

func TestMissingFingerprintIsRefused(t *testing.T) {
	engine := svidEngine(t, nil)

	req := baseRequest()
	req.CertFingerprint = ""

	if _, err := engine.IssueSVID(context.Background(), req); err == nil {
		t.Fatal("an empty fingerprint must not authenticate")
	}
}

// TestUnboundWorkloadIsRefused covers a workload registered without a
// fingerprint: before this guard, such a record authenticated any caller who knew
// its id.
func TestUnboundWorkloadIsRefused(t *testing.T) {
	engine := svidEngine(t, func(w *models.SPIFFEWorkload) {
		w.CertFingerprint = ""
	})

	if _, err := engine.IssueSVID(context.Background(), baseRequest()); !errors.Is(err, idp.ErrWorkloadUnbound) {
		t.Fatalf("expected the unbound-workload refusal, got %v", err)
	}
}

func TestInactiveWorkloadIsRefused(t *testing.T) {
	engine := svidEngine(t, func(w *models.SPIFFEWorkload) {
		w.Active = false
	})

	if _, err := engine.IssueSVID(context.Background(), baseRequest()); !errors.Is(err, idp.ErrWorkloadInactive) {
		t.Fatalf("expected the inactive refusal, got %v", err)
	}
}

func TestUnknownWorkloadIsRefused(t *testing.T) {
	engine := svidEngine(t, nil)

	req := baseRequest()
	req.WorkloadID = "not-registered"

	if _, err := engine.IssueSVID(context.Background(), req); !errors.Is(err, idp.ErrWorkloadNotFound) {
		t.Fatalf("expected not-found, got %v", err)
	}
}

// TestAudienceAllowListIsEnforced is the regression test for AllowedAudiences
// being carried on the model and never checked: a workload could mint an SVID
// naming any audience, including another service's.
func TestAudienceAllowListIsEnforced(t *testing.T) {
	engine := svidEngine(t, nil)

	req := baseRequest()
	req.Audience = "someone-elses-api"

	if _, err := engine.IssueSVID(context.Background(), req); !errors.Is(err, idp.ErrAudienceNotAllowed) {
		t.Fatalf("expected the audience allow-list to refuse this, got %v", err)
	}
}

// TestSingleAllowedAudienceIsImplied keeps the common case ergonomic without
// guessing when the choice is ambiguous.
func TestSingleAllowedAudienceIsImplied(t *testing.T) {
	engine := svidEngine(t, nil)

	req := baseRequest()
	req.Audience = ""

	resp, err := engine.IssueSVID(context.Background(), req)
	if err != nil {
		t.Fatalf("a lone allowed audience should be implied: %v", err)
	}
	if resp == nil {
		t.Fatal("expected a response")
	}
}

func TestAmbiguousAudienceRequiresAChoice(t *testing.T) {
	engine := svidEngine(t, func(w *models.SPIFFEWorkload) {
		w.AllowedAudiences = []string{"api-a", "api-b"}
	})

	req := baseRequest()
	req.Audience = ""

	if _, err := engine.IssueSVID(context.Background(), req); err == nil {
		t.Fatal("with several allowed audiences the caller must name one")
	}
}

func TestScopesAreFilteredToTheAllowList(t *testing.T) {
	engine := svidEngine(t, nil)

	req := baseRequest()
	req.RequestedScopes = []string{"docs:read", "admin:everything"}

	resp, err := engine.IssueSVID(context.Background(), req)
	if err != nil {
		t.Fatalf("IssueSVID: %v", err)
	}

	if !strings.Contains(resp.Scope, "docs:read") {
		t.Errorf("allowed scope was dropped: %q", resp.Scope)
	}
	if strings.Contains(resp.Scope, "admin:everything") {
		t.Errorf("a scope outside the allow-list was granted: %q", resp.Scope)
	}
}

func TestNoRequestedScopesGrantsAllAllowed(t *testing.T) {
	engine := svidEngine(t, nil)

	resp, err := engine.IssueSVID(context.Background(), baseRequest())
	if err != nil {
		t.Fatalf("IssueSVID: %v", err)
	}
	for _, want := range []string{"docs:read", "docs:write"} {
		if !strings.Contains(resp.Scope, want) {
			t.Errorf("expected %q in granted scopes, got %q", want, resp.Scope)
		}
	}
}
