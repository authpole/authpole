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

	"authpole/pkg/crypto"
	"authpole/pkg/models"
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

	h := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(h[:]), nil
}

// ValidateLongExpiryCert validates a presented client certificate against workload identity constraints.
func ValidateLongExpiryCert(certPEM string, workload *models.SPIFFEWorkload) error {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return errors.New("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse x509 certificate: %w", err)
	}

	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return ErrCertExpired
	}

	// Validate Fingerprint if configured
	if workload.CertFingerprint != "" {
		fp, err := ComputeCertFingerprint(certPEM)
		if err != nil {
			return err
		}
		if !strings.EqualFold(fp, workload.CertFingerprint) {
			return ErrFingerprint
		}
	}

	// Check URI SAN matches SPIFFE ID
	if workload.SPIFFEID != "" {
		matchedSAN := false
		for _, uri := range cert.URIs {
			if uri.String() == workload.SPIFFEID {
				matchedSAN = true
				break
			}
		}
		if !matchedSAN && len(cert.URIs) > 0 {
			// If cert has URIs but none matched expected SPIFFE ID
			return fmt.Errorf("certificate SPIFFE SAN mismatch")
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
