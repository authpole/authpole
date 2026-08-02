package spiffe_test

import (
	"testing"
	"time"

	"authpole/pkg/crypto"
	"authpole/pkg/models"
	"authpole/pkg/spiffe"
)

func TestSPIFFEIDParsing(t *testing.T) {
	orgID := "default"
	workloadID := "billing-service"
	spiffeID := spiffe.BuildSPIFFEID("authpole.local", orgID, workloadID)

	expected := "spiffe://authpole.local/ns/default/sa/billing-service"
	if spiffeID != expected {
		t.Fatalf("Expected SPIFFE ID %s, got %s", expected, spiffeID)
	}

	domain, parsedOrg, parsedWorkload, err := spiffe.ParseSPIFFEID(spiffeID)
	if err != nil {
		t.Fatalf("ParseSPIFFEID failed: %v", err)
	}

	if domain != "authpole.local" || parsedOrg != orgID || parsedWorkload != workloadID {
		t.Fatalf("Parsed components mismatch: domain=%s, org=%s, workload=%s", domain, parsedOrg, parsedWorkload)
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
		OrganizationID:  "default",
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
	orgID := "default"
	workloadID := "payment_service"
	spiffeID := spiffe.BuildSPIFFEID("authpole.local", orgID, workloadID)

	keyPair, err := crypto.GenerateRSAKeyPair(orgID, "")
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair failed: %v", err)
	}

	claims := &models.AuthClaims{
		Subject:        spiffeID,
		Issuer:         "https://authpole.io/organizations/" + orgID,
		Audience:       "spiffe://authpole.local/ns/default",
		OrganizationID: orgID,
		WorkloadID:     workloadID,
		SPIFFEID:       spiffeID,
		Scope:          "read:transactions write:payments",
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
