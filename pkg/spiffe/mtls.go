package spiffe

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
)

// Why this file exists
//
// A workload used to authenticate by POSTing its certificate PEM in the
// X-SPIFFE-Client-Cert header, which the server parsed and fingerprint-matched
// against a registered value. A certificate contains only a PUBLIC key: it is not
// secret, it is designed to be handed out, and it turns up in logs, proxy dumps and
// config files. So anyone who ever observed that PEM could replay it forever and
// mint SVIDs at will - the credential was no stronger than the long-lived bearer
// API key SPIFFE is supposed to replace, and weaker in practice because
// certificates are treated as non-sensitive.
//
// Possession of the matching PRIVATE key is the only thing that proves identity,
// and the only standard way to demonstrate that over HTTP is a TLS handshake. So a
// certificate is accepted from exactly two places:
//
//  1. r.TLS.PeerCertificates - this process terminated TLS and completed a mutual
//     handshake, so the peer demonstrably signed with the private key.
//  2. A header written by a terminating proxy that performed that handshake itself
//     (ALB mTLS, nginx, Envoy). This is trusted ONLY when explicitly enabled and
//     only when the immediate peer is on an allow-list, because a header is
//     otherwise attacker-settable and would restore the original bug.
//
// A client-supplied certificate header is never trusted on its own.

const (
	// EnvTrustProxyCert enables reading a client certificate from a proxy header.
	// Off by default: enabling it means the deployment promises that a proxy in
	// front of this server performs mutual TLS and overwrites the header.
	EnvTrustProxyCert = "AUTHPOLE_TRUST_PROXY_CLIENT_CERT"

	// EnvTrustedProxies restricts which immediate peers may set the header, as a
	// comma-separated list of IPs and/or CIDRs. Strongly recommended: without it any
	// caller that can reach this server directly can assert a certificate.
	EnvTrustedProxies = "AUTHPOLE_TRUSTED_PROXIES"

	// EnvProxyCertHeader overrides the header name carrying the verified certificate.
	EnvProxyCertHeader = "AUTHPOLE_PROXY_CLIENT_CERT_HEADER"

	// DefaultProxyCertHeader is what AWS Application Load Balancer sends in mTLS
	// passthrough mode: a URL-encoded PEM of the certificate it already validated.
	DefaultProxyCertHeader = "X-Amzn-Mtls-Clientcert"
)

var (
	// ErrNoClientCertificate means the request carried no certificate that this
	// server is willing to treat as proven.
	ErrNoClientCertificate = errors.New("no verified client certificate presented: mutual TLS is required to obtain an SVID")

	// ErrUntrustedCertSource means a certificate was presented in a header that
	// this deployment does not trust.
	ErrUntrustedCertSource = errors.New("client certificate header is not trusted from this peer; configure " + EnvTrustProxyCert + " and " + EnvTrustedProxies)

	// ErrWorkloadNotBound means the workload record has no registered certificate
	// to compare against, so no caller can be authenticated as it.
	ErrWorkloadNotBound = errors.New("workload has no registered certificate fingerprint; register one before requesting an SVID")
)

type proxyTrust struct {
	enabled bool
	header  string
	nets    []*net.IPNet
	ips     []net.IP
}

var (
	proxyTrustOnce sync.Once
	proxyTrustCfg  proxyTrust
)

func proxyTrustConfig() proxyTrust {
	proxyTrustOnce.Do(func() {
		proxyTrustCfg.enabled = parseBool(os.Getenv(EnvTrustProxyCert))
		proxyTrustCfg.header = strings.TrimSpace(os.Getenv(EnvProxyCertHeader))
		if proxyTrustCfg.header == "" {
			proxyTrustCfg.header = DefaultProxyCertHeader
		}
		if !proxyTrustCfg.enabled {
			return
		}

		for _, raw := range strings.Split(os.Getenv(EnvTrustedProxies), ",") {
			entry := strings.TrimSpace(raw)
			if entry == "" {
				continue
			}
			if _, network, err := net.ParseCIDR(entry); err == nil {
				proxyTrustCfg.nets = append(proxyTrustCfg.nets, network)
				continue
			}
			if ip := net.ParseIP(entry); ip != nil {
				proxyTrustCfg.ips = append(proxyTrustCfg.ips, ip)
			}
		}
	})
	return proxyTrustCfg
}

// ResetProxyTrustConfigForTest re-reads the environment. Tests only.
func ResetProxyTrustConfigForTest() {
	proxyTrustOnce = sync.Once{}
	proxyTrustCfg = proxyTrust{}
}

func parseBool(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// trustsPeer reports whether remoteAddr may assert a client certificate.
func (p proxyTrust) trustsPeer(remoteAddr string) bool {
	if !p.enabled {
		return false
	}
	// Enabled with no allow-list: honour the operator's intent, but this is a
	// deliberately loud configuration - anything that can reach the port can now
	// claim to be a workload.
	if len(p.nets) == 0 && len(p.ips) == 0 {
		return true
	}

	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return false
	}
	for _, allowed := range p.ips {
		if allowed.Equal(ip) {
			return true
		}
	}
	for _, network := range p.nets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// VerifiedClientCert returns the client certificate whose private key the caller
// has demonstrably proven possession of.
//
// It returns ErrNoClientCertificate rather than falling back to a client-supplied
// header, because that fallback is precisely the replay bug this replaces.
func VerifiedClientCert(r *http.Request) (*x509.Certificate, error) {
	// 1. Genuine mutual TLS terminated by this process. The handshake already
	//    proved possession of the private key.
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return r.TLS.PeerCertificates[0], nil
	}

	// 2. A terminating proxy that performed mutual TLS on our behalf.
	cfg := proxyTrustConfig()
	raw := r.Header.Get(cfg.header)
	if raw == "" {
		return nil, ErrNoClientCertificate
	}
	if !cfg.trustsPeer(r.RemoteAddr) {
		return nil, ErrUntrustedCertSource
	}

	cert, err := ParseCertPEM(raw)
	if err != nil {
		return nil, fmt.Errorf("proxy-forwarded client certificate is unusable: %w", err)
	}
	return cert, nil
}

// ParseCertPEM decodes a certificate that may be URL-encoded (as ALB sends it)
// and/or have literal "\n" escapes instead of real newlines.
func ParseCertPEM(raw string) (*x509.Certificate, error) {
	candidate := strings.TrimSpace(raw)

	// ALB URL-encodes the PEM.
	if strings.Contains(candidate, "%") {
		if decoded, err := url.QueryUnescape(candidate); err == nil {
			candidate = decoded
		}
	}
	// Headers cannot carry real newlines, so senders escape them.
	if strings.Contains(candidate, `\n`) {
		candidate = strings.ReplaceAll(candidate, `\n`, "\n")
	}

	block, _ := pem.Decode([]byte(candidate))
	if block == nil {
		return nil, errors.New("failed to decode certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse x509 certificate: %w", err)
	}
	return cert, nil
}
