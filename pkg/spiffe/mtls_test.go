package spiffe_test

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/url"
	"testing"

	"github.com/authpole/authpole/pkg/spiffe"
)

func testCert(t *testing.T, spiffeID string) (*x509.Certificate, string) {
	t.Helper()
	pemStr, _, _, err := spiffe.GenerateSelfSignedLongExpiryCert(spiffeID, 5)
	if err != nil {
		t.Fatalf("cert generation failed: %v", err)
	}
	cert, err := spiffe.ParseCertPEM(pemStr)
	if err != nil {
		t.Fatalf("ParseCertPEM failed: %v", err)
	}
	return cert, pemStr
}

// TestClientSuppliedCertHeaderIsRefused is the regression test for the replay bug.
// A certificate is public data, so presenting one in a header proves nothing; with
// proxy trust disabled it must not be accepted at all.
func TestClientSuppliedCertHeaderIsRefused(t *testing.T) {
	spiffe.ResetProxyTrustConfigForTest()
	t.Setenv(spiffe.EnvTrustProxyCert, "")

	_, pemStr := testCert(t, "spiffe://authpole.local/ns/default/sa/svc")

	for _, header := range []string{
		"X-SPIFFE-Client-Cert",
		"X-Client-Cert",
		spiffe.DefaultProxyCertHeader,
	} {
		t.Run(header, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, "https://authpole.test/api/v1/spiffe/svid", nil)
			if err != nil {
				t.Fatalf("request build failed: %v", err)
			}
			req.RemoteAddr = "203.0.113.7:44321"
			req.Header.Set(header, pemStr)

			if _, err := spiffe.VerifiedClientCert(req); err == nil {
				t.Fatalf("a caller-supplied certificate in %s must not authenticate a workload", header)
			}
		})
	}
}

// TestMutualTLSCertificateIsAccepted covers the authoritative path: the TLS stack
// completed a mutual handshake, which proves possession of the private key.
func TestMutualTLSCertificateIsAccepted(t *testing.T) {
	spiffe.ResetProxyTrustConfigForTest()
	t.Setenv(spiffe.EnvTrustProxyCert, "")

	cert, _ := testCert(t, "spiffe://authpole.local/ns/default/sa/svc")

	req, err := http.NewRequest(http.MethodPost, "https://authpole.test/api/v1/spiffe/svid", nil)
	if err != nil {
		t.Fatalf("request build failed: %v", err)
	}
	req.RemoteAddr = "203.0.113.7:44321"
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}

	got, err := spiffe.VerifiedClientCert(req)
	if err != nil {
		t.Fatalf("a mutual-TLS certificate should be accepted: %v", err)
	}
	if !got.Equal(cert) {
		t.Fatal("returned certificate is not the one presented in the handshake")
	}
}

func TestProxyHeaderRequiresTrustedPeer(t *testing.T) {
	_, pemStr := testCert(t, "spiffe://authpole.local/ns/default/sa/svc")

	newReq := func(remote string) *http.Request {
		req, err := http.NewRequest(http.MethodPost, "https://authpole.test/api/v1/spiffe/svid", nil)
		if err != nil {
			t.Fatalf("request build failed: %v", err)
		}
		req.RemoteAddr = remote
		// ALB sends the PEM URL-encoded.
		req.Header.Set(spiffe.DefaultProxyCertHeader, url.QueryEscape(pemStr))
		return req
	}

	t.Run("untrusted peer refused", func(t *testing.T) {
		spiffe.ResetProxyTrustConfigForTest()
		t.Setenv(spiffe.EnvTrustProxyCert, "true")
		t.Setenv(spiffe.EnvTrustedProxies, "10.0.0.0/8")

		if _, err := spiffe.VerifiedClientCert(newReq("203.0.113.7:44321")); err == nil {
			t.Fatal("a peer outside the allow-list must not be able to assert a certificate")
		}
	})

	t.Run("trusted peer accepted", func(t *testing.T) {
		spiffe.ResetProxyTrustConfigForTest()
		t.Setenv(spiffe.EnvTrustProxyCert, "true")
		t.Setenv(spiffe.EnvTrustedProxies, "10.0.0.0/8")

		got, err := spiffe.VerifiedClientCert(newReq("10.1.2.3:44321"))
		if err != nil {
			t.Fatalf("a trusted proxy should be able to forward a verified certificate: %v", err)
		}
		if got == nil {
			t.Fatal("expected a certificate")
		}
	})

	t.Run("disabled ignores trusted peer", func(t *testing.T) {
		spiffe.ResetProxyTrustConfigForTest()
		t.Setenv(spiffe.EnvTrustProxyCert, "false")
		t.Setenv(spiffe.EnvTrustedProxies, "10.0.0.0/8")

		if _, err := spiffe.VerifiedClientCert(newReq("10.1.2.3:44321")); err == nil {
			t.Fatal("proxy trust is off, so even an allow-listed peer must not assert a certificate")
		}
	})
}

func TestNoCertificateAtAllIsRefused(t *testing.T) {
	spiffe.ResetProxyTrustConfigForTest()
	t.Setenv(spiffe.EnvTrustProxyCert, "")

	req, err := http.NewRequest(http.MethodPost, "https://authpole.test/api/v1/spiffe/svid", nil)
	if err != nil {
		t.Fatalf("request build failed: %v", err)
	}
	req.RemoteAddr = "10.1.2.3:44321"

	if _, err := spiffe.VerifiedClientCert(req); err == nil {
		t.Fatal("a request with no certificate must be refused")
	}
}

func TestParseCertPEMHandlesEscapedNewlines(t *testing.T) {
	_, pemStr := testCert(t, "spiffe://authpole.local/ns/default/sa/svc")

	// Headers cannot carry real newlines, so senders escape them.
	escaped := ""
	for _, r := range pemStr {
		if r == '\n' {
			escaped += `\n`
			continue
		}
		escaped += string(r)
	}

	if _, err := spiffe.ParseCertPEM(escaped); err != nil {
		t.Fatalf("escaped-newline PEM should parse: %v", err)
	}
}
