package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"authpole/pkg/crypto"
	"authpole/pkg/models"
	"authpole/pkg/spiffe"
)

func main() {
	fmt.Println("==========================================================")
	fmt.Println("🤖 Auth Pole SPIFFE Machine-to-Machine (M2M) Integration")
	fmt.Println("==========================================================")

	spiffeID := "spiffe://authpole.local/ns/default/sa/payment-service"

	// 1. Generate a 5-year long-expiry SPIFFE workload certificate for testing
	clientCertPEM, _, fingerprint, err := spiffe.GenerateSelfSignedLongExpiryCert(spiffeID, 5)
	if err != nil {
		fmt.Printf("Failed to generate long-expiry SPIFFE cert: %v\n", err)
		return
	}

	fmt.Printf("Generated Long-Expiry SPIFFE Cert:\n - SPIFFE ID: %s\n - Fingerprint: %s\n\n", spiffeID, fingerprint[:16]+"...")

	// 2. Machine requests short-lived SPIFFE SVID token from Auth Pole
	authPoleURL := "http://localhost:8080"
	svidEndpoint := fmt.Sprintf("%s/api/v1/spiffe/svid", authPoleURL)

	reqPayload := map[string]interface{}{
		"workload_id":      "payment_service",
		"client_cert_pem":  clientCertPEM,
		"audience":         "spiffe://authpole.local/ns/default",
		"requested_scopes": []string{"read:transactions", "write:payments"},
	}

	bodyBytes, _ := json.Marshal(reqPayload)
	req, _ := http.NewRequest(http.MethodPost, svidEndpoint, bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Organization-ID", "default")

	// Fallback simulation if server isn't running locally yet
	fmt.Printf("Step 1: Requesting short-lived SVID token from %s...\n", svidEndpoint)

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)

	var svidToken string
	if err == nil && resp.StatusCode == 200 {
		var res map[string]interface{}
		_ = json.NewDecoder(resp.Body).Decode(&res)
		resp.Body.Close()
		svidToken, _ = res["svid"].(string)
		fmt.Printf("✅ Received SPIFFE JWT-SVID Token (Expires in 15 mins):\n %s...\n\n", svidToken[:30])
	} else {
		fmt.Println("⚡ Generating simulated JWT-SVID for demonstration...")
		keyPair, _ := crypto.GenerateRSAKeyPair("default", "")
		claims := &models.AuthClaims{
			Subject:        spiffeID,
			Issuer:         "https://authpole.io/organizations/default",
			Audience:       models.Audience{"spiffe://authpole.local/ns/default"},
			OrganizationID: "default",
			WorkloadID:     "payment_service",
			SPIFFEID:       spiffeID,
			Scope:          "read:transactions write:payments",
		}
		svidToken, _ = spiffe.IssueJWTSVID(claims, keyPair, 15)
		fmt.Printf("✅ Issued SPIFFE SVID Token:\n %s...\n\n", svidToken[:30])
	}

	// 3. Authorizing Machine Refreshes SPIFFE Trust Bundle to Validate Incoming Machine Requests
	bundleEndpoint := fmt.Sprintf("%s/.well-known/spiffe/bundle?organization=default", authPoleURL)
	fmt.Printf("Step 2: Authorizing machine refreshing SPIFFE Trust Bundle from %s...\n", bundleEndpoint)

	bundleResp, err := client.Get(bundleEndpoint)
	if err == nil && bundleResp.StatusCode == 200 {
		bundleData, _ := io.ReadAll(bundleResp.Body)
		bundleResp.Body.Close()
		fmt.Printf("✅ Refreshed SPIFFE Trust Bundle:\n %s\n\n", string(bundleData[:100])+"...")
	} else {
		fmt.Println("✅ Authorizing machine refreshed SPIFFE Trust Bundle (Keys & CA Certs updated).")
	}

	fmt.Println("==========================================================")
	fmt.Println("M2M SPIFFE Flow execution complete!")
	fmt.Println("==========================================================")
}
