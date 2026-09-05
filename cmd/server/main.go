package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/authpole/authpole/pkg/api"
	"github.com/authpole/authpole/pkg/cache"
	"github.com/authpole/authpole/pkg/crypto"
	"github.com/authpole/authpole/pkg/models"
	"github.com/authpole/authpole/pkg/storage"
)

func main() {
	port := flag.String("port", "8080", "Port to listen on")
	dataDir := flag.String("data-dir", "./data", "Directory for S3 emulator storage persistence")
	s3Bucket := flag.String("s3-bucket", "", "AWS S3 Bucket name (optional, uses emulator if empty)")
	s3Endpoint := flag.String("s3-endpoint", "", "AWS S3 Endpoint URL")
	flag.Parse()

	if envPort := os.Getenv("PORT"); envPort != "" {
		*port = envPort
	}

	loadOAuthCredentialsFromSSM()

	var store storage.Storage
	var err error

	if *s3Bucket != "" {
		log.Printf("Initializing JayDB S3 Embedded Storage (Bucket: %s)", *s3Bucket)
		store, err = storage.NewS3Storage(*s3Bucket, "us-east-1", *s3Endpoint)
	} else if *dataDir != "" {
		log.Printf("Initializing JayDB FS Embedded Storage (Data directory: %s)", *dataDir)
		store, err = storage.NewFSStorage(*dataDir)
	} else {
		log.Printf("Initializing JayDB Memory Embedded Storage")
		store, err = storage.NewMemoryStorage()
	}
	if err != nil {
		log.Fatalf("Failed to initialize JayDB storage: %v", err)
	}
	defer store.Close()

	memoryCache := cache.NewMemoryCache()

	// Seed initial data if empty
	seedInitialData(store, memoryCache)

	server := api.NewServer(store, memoryCache)

	httpServer := &http.Server{
		Addr:         ":" + *port,
		Handler:      server,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("=====================================================")
		log.Printf("⚡ Auth Pole Mediator IDP Server running on :%s", *port)
		log.Printf("🔑 OIDC Discovery:   http://localhost:%s/.well-known/openid-configuration", *port)
		log.Printf("📜 JWKS Endpoint:    http://localhost:%s/.well-known/jwks.json", *port)
		log.Printf("🤖 SPIFFE SVID Issue: http://localhost:%s/api/v1/spiffe/svid", *port)
		log.Printf("📦 SPIFFE Bundle:    http://localhost:%s/.well-known/spiffe/bundle", *port)
		log.Printf("⚡ Access Path:      http://localhost:%s/api/v1/auth/validate", *port)
		log.Printf("⚙️ Admin API:        http://localhost:%s/api/v1/organizations", *port)
		log.Printf("=====================================================")

		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP)
	sig := <-stop

	log.Printf("Received signal %v. Shutting down Auth Pole gracefully...", sig)
	httpServer.SetKeepAlivesEnabled(false)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("Graceful shutdown timeout (%v), forcing server close...", err)
		_ = httpServer.Close()
	}
	log.Println("Server stopped cleanly.")
	os.Exit(0)
}

func seedInitialData(store storage.Storage, c *cache.MemoryCache) {
	ctx := context.Background()

	// Check if default organization exists
	orgKey := storage.OrganizationKey("default")
	_, err := store.Get(ctx, orgKey)
	if err == storage.ErrNotFound {
		log.Println("Seeding default organization, application, upstream IDP, and signing keys...")

		// 1. Default Organization
		org := &models.Organization{
			ID:        "default",
			Name:      "Default Organization",
			Domain:    "authpole.local",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		tBytes, _ := json.Marshal(org)
		tVer, _ := store.Put(ctx, orgKey, tBytes, "")
		org.Version = tVer

		// 2. Default Application
		app := &models.Application{
			ID:             "demo_app",
			OrganizationID: "default",
			Name:           "Demo Client App",
			ClientID:       "demo_app",
			ClientSecret:   "secret_12345",
			RedirectURIs:   []string{"http://localhost:3000/callback", "http://localhost:8080/oauth/v2/mock_login"},
			AllowedIDPs:    []string{"mock_idp"},
			Scopes:         []string{"openid", "profile", "email"},
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		}
		aBytes, _ := json.Marshal(app)
		aVer, _ := store.Put(ctx, storage.AppKey("default", "demo_app"), aBytes, "")
		app.Version = aVer
		c.SetApp("default", "demo_app", app, 1*time.Hour)

		// 2b. System Admin Console Application
		adminApp := &models.Application{
			ID:             "admin_console",
			OrganizationID: "default",
			Name:           "Authpole Admin Console",
			ClientID:       "admin_console",
			ClientSecret:   "admin_console_secret",
			RedirectURIs: []string{
				"http://localhost:3000",
				"http://localhost:3000/callback.html",
				"http://localhost:8080/admin/",
				"https://authpole-admin.swii.sh",
				"https://authpole-admin.swii.sh/callback.html",
			},
			AllowedIDPs: []string{"google", "github"},
			Scopes:      []string{"openid", "profile", "email"},
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
		adminAppBytes, _ := json.Marshal(adminApp)
		adminAppVer, _ := store.Put(ctx, storage.AppKey("default", "admin_console"), adminAppBytes, "")
		adminApp.Version = adminAppVer
		c.SetApp("default", "admin_console", adminApp, 1*time.Hour)

		// 3. Upstream IDPs (Google, GitHub)
		idpGoogle := &models.IdentityProvider{
			ID:             "google",
			OrganizationID: "default",
			Name:           "Google Workspace",
			Type:           "oidc",
			ClientID:       "google_oauth_client_id.apps.googleusercontent.com",
			ClientSecret:   "google_oauth_client_secret",
			AuthorizeURL:   "https://accounts.google.com/o/oauth2/v2/auth",
			TokenURL:       "https://oauth2.googleapis.com/token",
			Scopes:         []string{"openid", "profile", "email"},
			Enabled:        true,
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		}
		iGoogleBytes, _ := json.Marshal(idpGoogle)
		_, _ = store.Put(ctx, storage.IDPKey("default", "google"), iGoogleBytes, "")

		idpGithub := &models.IdentityProvider{
			ID:             "github",
			OrganizationID: "default",
			Name:           "GitHub Enterprise",
			Type:           "oauth2",
			ClientID:       "github_oauth_client_id",
			ClientSecret:   "github_oauth_client_secret",
			AuthorizeURL:   "https://github.com/login/oauth/authorize",
			TokenURL:       "https://github.com/login/oauth/access_token",
			Scopes:         []string{"user:email", "read:user"},
			Enabled:        true,
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		}
		iGithubBytes, _ := json.Marshal(idpGithub)
		_, _ = store.Put(ctx, storage.IDPKey("default", "github"), iGithubBytes, "")

		// 4. Default RSA Key Pair
		keyPair, err := crypto.GenerateRSAKeyPair("default", "demo_app")
		if err == nil {
			kBytes, _ := json.Marshal(keyPair)
			kVer, _ := store.Put(ctx, storage.KeyPairKey("default", keyPair.ID), kBytes, "")
			keyPair.Version = kVer
			c.SetSigningKeys("default", "demo_app", []*models.SigningKey{keyPair}, 1*time.Hour)
		}

		// 5. Default Admin User, Team, and Role
		adminUser := &models.AdminUser{
			ID:             "admin_root",
			OrganizationID: "default",
			Email:          "admin@authpole.io",
			Name:           "System Admin",
			RoleIDs:        []string{"super_admin"},
			TeamIDs:        []string{"core_ops"},
			Active:         true,
			Status:         "active",
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		}
		uBytes, _ := json.Marshal(adminUser)
		_, _ = store.Put(ctx, storage.AdminUserKey("default", adminUser.ID), uBytes, "")

		role := &models.Role{
			ID:             "super_admin",
			OrganizationID: "default",
			Name:           "Super Administrator",
			Description:    "Full access to all Auth Pole organization configurations and settings",
			Permissions:    []string{"organization:read", "organization:write", "app:manage", "idp:manage", "keys:manage"},
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		}
		rBytes, _ := json.Marshal(role)
		_, _ = store.Put(ctx, storage.RoleKey("default", role.ID), rBytes, "")

		team := &models.Team{
			ID:             "core_ops",
			OrganizationID: "default",
			Name:           "Core Operations Team",
			Description:    "Platform operations and auth pole configuration maintainers",
			RoleIDs:        []string{"super_admin"},
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		}
		tmBytes, _ := json.Marshal(team)
		_, _ = store.Put(ctx, storage.TeamKey("default", team.ID), tmBytes, "")

		// 6. Default SPIFFE Workload Identity
		spiffeWorkload := &models.SPIFFEWorkload{
			ID:               "payment_service",
			OrganizationID:   "default",
			SPIFFEID:         "spiffe://authpole.local/ns/default/sa/payment-service",
			Name:             "Payment Processing Service",
			AllowedScopes:    []string{"read:transactions", "write:payments"},
			AllowedAudiences: []string{"spiffe://authpole.local/ns/default"},
			Active:           true,
			CreatedAt:        time.Now(),
			UpdatedAt:        time.Now(),
		}
		swBytes, _ := json.Marshal(spiffeWorkload)
		_, _ = store.Put(ctx, storage.SPIFFEWorkloadKey("default", spiffeWorkload.ID), swBytes, "")
	}
}

func loadOAuthCredentialsFromSSM() {
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}

	params := []struct {
		envKey   string
		ssmName  string
		isSecret bool
	}{
		{"AUTHPOLE_GOOGLE_CLIENT_ID", "/authpole/production/google_client_id", false},
		{"AUTHPOLE_GOOGLE_CLIENT_SECRET", "/authpole/production/google_client_secret", true},
		{"AUTHPOLE_GITHUB_CLIENT_ID", "/authpole/production/github_client_id", false},
		{"AUTHPOLE_GITHUB_CLIENT_SECRET", "/authpole/production/github_client_secret", true},
	}

	for _, p := range params {
		if os.Getenv(p.envKey) == "" {
			args := []string{"ssm", "get-parameter", "--name", p.ssmName, "--query", "Parameter.Value", "--output", "text", "--region", region}
			if p.isSecret {
				args = append(args, "--with-decryption")
			}
			out, err := exec.Command("aws", args...).Output()
			if err == nil {
				val := strings.TrimSpace(string(out))
				if val != "" && val != "None" {
					os.Setenv(p.envKey, val)
					log.Printf("Loaded %s from AWS SSM Parameter Store (%s)", p.envKey, p.ssmName)
				}
			}
		}
	}
}
