package spiffe_test

import (
	"testing"
	"time"

	"github.com/authpole/authpole/pkg/crypto"
	"github.com/authpole/authpole/pkg/models"
	"github.com/authpole/authpole/pkg/spiffe"
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

	cert, err := spiffe.ParseCertPEM(certPEM)
	if err != nil {
		t.Fatalf("ParseCertPEM failed: %v", err)
	}

	workload := &models.SPIFFEWorkload{
		ID:              "payment_service",
		OrganizationID:  "default",
		SPIFFEID:        spiffeID,
		Name:            "Payment Processing Service",
		CertFingerprint: fingerprint,
		Active:          true,
	}

	if err := spiffe.ValidateWorkloadCert(cert, workload); err != nil {
		t.Fatalf("ValidateWorkloadCert failed: %v", err)
	}
}

// TestWorkloadWithoutFingerprintIsRefused covers the removed bypass: validation
// used to be skipped entirely when neither a certificate nor a stored fingerprint
// was present, so a workload registered without one issued SVIDs to any caller who
// knew its ID.
func TestWorkloadWithoutFingerprintIsRefused(t *testing.T) {
	spiffeID := "spiffe://authpole.local/ns/default/sa/payment-service"
	certPEM, _, _, err := spiffe.GenerateSelfSignedLongExpiryCert(spiffeID, 5)
	if err != nil {
		t.Fatalf("cert generation failed: %v", err)
	}
	cert, err := spiffe.ParseCertPEM(certPEM)
	if err != nil {
		t.Fatalf("ParseCertPEM failed: %v", err)
	}

	workload := &models.SPIFFEWorkload{
		ID:             "payment_service",
		OrganizationID: "default",
		SPIFFEID:       spiffeID,
		Active:         true,
		// CertFingerprint deliberately empty.
	}

	if err := spiffe.ValidateWorkloadCert(cert, workload); err == nil {
		t.Fatal("a workload with no registered fingerprint must not authenticate anyone")
	}
}

// TestForeignCertIsRejected confirms a valid certificate for a different workload
// cannot be used to obtain this workload's identity.
func TestForeignCertIsRejected(t *testing.T) {
	ourID := "spiffe://authpole.local/ns/default/sa/payment-service"
	_, _, ourFingerprint, err := spiffe.GenerateSelfSignedLongExpiryCert(ourID, 5)
	if err != nil {
		t.Fatalf("cert generation failed: %v", err)
	}

	foreignPEM, _, _, err := spiffe.GenerateSelfSignedLongExpiryCert(
		"spiffe://authpole.local/ns/default/sa/attacker", 5)
	if err != nil {
		t.Fatalf("cert generation failed: %v", err)
	}
	foreign, err := spiffe.ParseCertPEM(foreignPEM)
	if err != nil {
		t.Fatalf("ParseCertPEM failed: %v", err)
	}

	workload := &models.SPIFFEWorkload{
		ID:              "payment_service",
		OrganizationID:  "default",
		SPIFFEID:        ourID,
		CertFingerprint: ourFingerprint,
		Active:          true,
	}

	if err := spiffe.ValidateWorkloadCert(foreign, workload); err == nil {
		t.Fatal("a certificate for another workload must be rejected")
	}
}

// TestSPIFFEIDMustAppearAsURISAN covers the case where a certificate carries no
// URI SANs at all, which previously skipped the SPIFFE ID check.
func TestSPIFFEIDMustAppearAsURISAN(t *testing.T) {
	otherID := "spiffe://authpole.local/ns/default/sa/other"
	certPEM, _, fingerprint, err := spiffe.GenerateSelfSignedLongExpiryCert(otherID, 5)
	if err != nil {
		t.Fatalf("cert generation failed: %v", err)
	}
	cert, err := spiffe.ParseCertPEM(certPEM)
	if err != nil {
		t.Fatalf("ParseCertPEM failed: %v", err)
	}

	// Fingerprint matches, but the certificate asserts a different SPIFFE ID.
	workload := &models.SPIFFEWorkload{
		ID:              "payment_service",
		OrganizationID:  "default",
		SPIFFEID:        "spiffe://authpole.local/ns/default/sa/payment-service",
		CertFingerprint: fingerprint,
		Active:          true,
	}

	if err := spiffe.ValidateWorkloadCert(cert, workload); err == nil {
		t.Fatal("a certificate that does not assert the workload's SPIFFE ID must be rejected")
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
		Audience:       models.Audience{"spiffe://authpole.local/ns/default"},
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
