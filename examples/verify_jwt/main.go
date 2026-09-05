package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/authpole/authpole/pkg/crypto"
	"github.com/authpole/authpole/pkg/models"
)

// DownstreamService demonstrates how a microservice validates Auth Pole JWTs offline using downloaded JWKS.
type DownstreamService struct {
	authPoleURL string
	orgID       string
	keys        []*models.SigningKey
}

func NewDownstreamService(authPoleURL, orgID string) (*DownstreamService, error) {
	s := &DownstreamService{
		authPoleURL: authPoleURL,
		orgID:       orgID,
	}
	if err := s.refreshJWKS(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *DownstreamService) refreshJWKS() error {
	url := fmt.Sprintf("%s/.well-known/jwks.json?organization=%s", s.authPoleURL, s.orgID)
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS from Auth Pole: %w", err)
	}
	defer resp.Body.Close()

	var jwks crypto.JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("failed to decode JWKS: %w", err)
	}

	log.Printf("Successfully loaded %d public key(s) from Auth Pole JWKS", len(jwks.Keys))
	return nil
}

func (s *DownstreamService) ValidateRequestToken(tokenString string) (*models.AuthClaims, error) {
	return crypto.VerifyJWT(tokenString, s.keys)
}

func main() {
	fmt.Println("Auth Pole Downstream Integration Example")
	fmt.Println("Fetch JWKS: GET http://localhost:8080/.well-known/jwks.json?organization=default")
	fmt.Println("Validate Token: GET http://localhost:8080/api/v1/auth/validate")
}
