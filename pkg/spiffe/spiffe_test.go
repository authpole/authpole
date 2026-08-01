package spiffe_test

import (
	"testing"
	"time"

	"authpole/pkg/crypto"
	"authpole/pkg/models"
	"authpole/pkg/spiffe"
)

func TestSPIFFEIDParsing(t *testing.T) {
	tenantID := "default"
	workloadID := "billing-service"
	spiffeID := spiffe.BuildSPIFFEID("authpole.local", tenantID, workloadID)

	expected := "spiffe://authpole.local/ns/default/sa/billing-service"
	if spiffeID != expected {
		t.Fatalf("Expected SPIFFE ID %s, got %s", expected, spiffeID)
	}

	domain, parsedTenant, parsedWorkload, err := spiffe.ParseSPIFFEID(spiffeID)
	if err != nil {
		t.Fatalf("ParseSPIFFEID failed: %v", err)
	}

	if domain != "authpole.local" || parsedTenant != tenantID || parsedWorkload != workloadID {
		t.Fatalf("Parsed components mismatch: domain=%s, tenant=%s, workload=%s", domain, parsedTenant, parsedWorkload)
	}
}

func TestLongExpiryCertValidation(t *testing.T) {
	spiffeID := "spiffe://authpole.local/ns/default/sa/payment-service"
	certPEM, _, fingerprint, err := spiffe.GenerateSelfSignedLongExpiryCert(spiffeID, 5)
	if err != nil {
		t.Fatalf("GenerateSelfSignedLongExpiryCert failed: %v", err)
	}

	workload := &models.SPIFFEWorkload{
		ID:              "payment_service",
		TenantID:        "default",
		SPIFFEID:        spiffeID,
		Name:            "Payment Processing Service",
		CertFingerprint: fingerprint,
		Active:          true,
	}

	if err := spiffe.ValidateLongExpiryCert(certPEM, workload); err != nil {
		t.Fatalf("ValidateLongExpiryCert failed: %v", err)
	}
}

func TestJWTSVIDIssuance(t *testing.T) {
	tenantID := "default"
	workloadID := "payment_service"
	spiffeID := spiffe.BuildSPIFFEID("authpole.local", tenantID, workloadID)

	keyPair, err := crypto.GenerateRSAKeyPair(tenantID, "")
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair failed: %v", err)
	}

	claims := &models.AuthClaims{
		Subject:    spiffeID,
		Issuer:     "https://authpole.io/tenants/" + tenantID,
		Audience:   "spiffe://authpole.local/ns/default",
		TenantID:   tenantID,
		WorkloadID: workloadID,
		SPIFFEID:   spiffeID,
		Scope:      "read:transactions write:payments",
	}

	tokenStr, err := spiffe.IssueJWTSVID(claims, keyPair, 15)
	if err != nil {
		t.Fatalf("IssueJWTSVID failed: %v", err)
	}

	// Verify token offline
	verified, err := crypto.VerifyJWT(tokenStr, []*models.SigningKey{keyPair})
	if err != nil {
		t.Fatalf("VerifyJWT failed for SVID: %v", err)
	}

	if verified.Subject != spiffeID || verified.WorkloadID != workloadID {
		t.Fatalf("Verified claims mismatch: %+v", verified)
	}

	if verified.ExpiresAt <= time.Now().Unix() {
		t.Fatalf("Issued SVID token is already expired")
	}
}
