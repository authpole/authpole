package spiffe

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"

	"math/big"

	"net/url"
	"strings"
	"time"

	"github.com/authpole/authpole/pkg/crypto"
	"github.com/authpole/authpole/pkg/models"
)

var (
	ErrInvalidSPIFFEID = errors.New("invalid spiffe id uri format")
	ErrCertExpired     = errors.New("long-expiry client certificate has expired")
	ErrFingerprint     = errors.New("certificate fingerprint mismatch")
	ErrUnauthorized    = errors.New("unauthorized workload or scope")
)

// BuildSPIFFEID constructs standard SPIFFE URI format: spiffe://<domain>/ns/<organization>/sa/<workload>
func BuildSPIFFEID(domain, orgID, workloadID string) string {
	if domain == "" {
		domain = "authpole.local"
	}
	return fmt.Sprintf("spiffe://%s/ns/%s/sa/%s", domain, orgID, workloadID)
}

// ParseSPIFFEID extracts domain, orgID, and workloadID from a SPIFFE URI string.
func ParseSPIFFEID(spiffeID string) (domain, orgID, workloadID string, err error) {
	u, err := url.Parse(spiffeID)
	if err != nil || u.Scheme != "spiffe" {
		return "", "", "", ErrInvalidSPIFFEID
	}

	domain = u.Host
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(parts) < 4 || parts[0] != "ns" || parts[2] != "sa" {
		return "", "", "", ErrInvalidSPIFFEID
	}

	return domain, parts[1], parts[3], nil
}

// ComputeCertFingerprint calculates the SHA-256 hex fingerprint of a PEM encoded certificate.
func ComputeCertFingerprint(certPEM string) (string, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return "", errors.New("failed to decode certificate PEM block")
	}

	return ComputeCertFingerprintDER(block.Bytes), nil
}

// ComputeCertFingerprintDER returns the SHA-256 fingerprint of raw DER bytes.
//
// This is the form used against a verified *x509.Certificate (cert.Raw), so a
// fingerprint check never has to round-trip back through PEM text - which is both
// wasteful and an opportunity to fingerprint something other than the certificate
// the TLS stack actually validated.
func ComputeCertFingerprintDER(der []byte) string {
	h := sha256.Sum256(der)
	return hex.EncodeToString(h[:])
}

// ValidateWorkloadCert checks an ALREADY-VERIFIED client certificate against a
// registered workload.
//
// It takes a parsed *x509.Certificate rather than a PEM string on purpose. The
// previous signature accepted a PEM from anywhere, which made it trivially
// reachable with a certificate the caller merely copied - a certificate carries
// only a public key, so possessing its bytes proves nothing. Callers must obtain
// the certificate from VerifiedClientCert, which only yields one whose private key
// was proven through a TLS handshake.
func ValidateWorkloadCert(cert *x509.Certificate, workload *models.SPIFFEWorkload) error {
	if cert == nil {
		return ErrNoClientCertificate
	}
	if workload == nil {
		return errors.New("workload is required")
	}

	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return ErrCertExpired
	}

	// A registered fingerprint is mandatory. Previously validation was skipped
	// entirely when both the presented cert and the stored fingerprint were absent,
	// so a workload registered without a fingerprint would issue an SVID to anyone
	// who knew its ID. There is no safe way to authenticate against nothing.
	if strings.TrimSpace(workload.CertFingerprint) == "" {
		return ErrWorkloadNotBound
	}

	fp := ComputeCertFingerprintDER(cert.Raw)
	if !strings.EqualFold(fp, strings.TrimSpace(workload.CertFingerprint)) {
		return ErrFingerprint
	}

	// The SPIFFE ID must appear as a URI SAN. This was previously skipped whenever
	// the certificate carried no URIs at all, which let a certificate with no SPIFFE
	// identity authenticate as a workload that declared one.
	if workload.SPIFFEID != "" {
		matched := false
		for _, uri := range cert.URIs {
			if uri.String() == workload.SPIFFEID {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("certificate does not carry SPIFFE ID %q as a URI SAN", workload.SPIFFEID)
		}
	}

	return nil
}

// GenerateSelfSignedLongExpiryCert generates a long-expiry (e.g. 5 year) self-signed SPIFFE workload certificate for testing.
func GenerateSelfSignedLongExpiryCert(spiffeID string, durationYears int) (certPEM string, keyPEM string, fingerprint string, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", "", err
	}

	spiffeURL, err := url.Parse(spiffeID)
	if err != nil {
		return "", "", "", err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return "", "", "", err
	}

	notBefore := time.Now().Add(-1 * time.Hour)
	notAfter := notBefore.Add(time.Duration(durationYears) * 365 * 24 * time.Hour)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Auth Pole SPIFFE Workloads"},
			CommonName:   spiffeID,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{spiffeURL},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return "", "", "", err
	}

	certPEMBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	keyBytes := x509.MarshalPKCS1PrivateKey(priv)
	keyPEMBlock := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes})

	h := sha256.Sum256(certBytes)
	fp := hex.EncodeToString(h[:])

	return string(certPEMBlock), string(keyPEMBlock), fp, nil
}

// IssueJWTSVID creates a short-lived SPIFFE JWT-SVID for M2M requests.
func IssueJWTSVID(claims *models.AuthClaims, key *models.SigningKey, durationMinutes int) (string, error) {
	if durationMinutes <= 0 {
		durationMinutes = 15 // Default short expiration (15 mins) for SVIDs
	}

	now := time.Now()
	claims.IssuedAt = now.Unix()
	claims.ExpiresAt = now.Add(time.Duration(durationMinutes) * time.Minute).Unix()

	return crypto.SignJWT(claims, key.PrivateKeyPEM, key.KID)
}
