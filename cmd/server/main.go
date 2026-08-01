package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"authpole/pkg/api"
	"authpole/pkg/cache"
	"authpole/pkg/crypto"
	"authpole/pkg/models"
	"authpole/pkg/storage"
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

	var store storage.Storage
	var err error

	if *s3Bucket != "" {
		log.Printf("Connecting to production S3 bucket: %s", *s3Bucket)
		store = storage.NewS3CASStorage(*s3Bucket, "us-east-1", *s3Endpoint)
	} else {
		log.Printf("Initializing S3 CAS Storage Emulator (Data directory: %s)", *dataDir)
		store, err = storage.NewMemoryCASStorage(*dataDir)
		if err != nil {
			log.Fatalf("Failed to initialize storage: %v", err)
		}
	}

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
		log.Printf("⚙️ Admin API:        http://localhost:%s/api/v1/tenants", *port)
		log.Printf("=====================================================")

		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	log.Println("Shutting down Auth Pole gracefully...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_ = httpServer.Shutdown(ctx)
	log.Println("Server stopped cleanly.")
}

func seedInitialData(store storage.Storage, c *cache.MemoryCache) {
	ctx := context.Background()

	// Check if default tenant exists
	tenantKey := storage.TenantKey("default")
	_, err := store.Get(ctx, tenantKey)
	if err == storage.ErrNotFound {
		log.Println("Seeding default tenant, application, upstream IDP, and signing keys...")

		// 1. Default Tenant
		tenant := &models.Tenant{
			ID:        "default",
			Name:      "Default Tenant",
			Domain:    "authpole.local",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		tBytes, _ := json.Marshal(tenant)
		tVer, _ := store.Put(ctx, tenantKey, tBytes, "")
		tenant.Version = tVer

		// 2. Default Application
		app := &models.Application{
			ID:           "demo_app",
			TenantID:     "default",
			Name:         "Demo Client App",
			ClientID:     "demo_app",
			ClientSecret: "secret_12345",
			RedirectURIs: []string{"http://localhost:3000/callback", "http://localhost:8080/oauth/v2/mock_login"},
			AllowedIDPs:  []string{"mock_idp"},
			Scopes:       []string{"openid", "profile", "email"},
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		}
		aBytes, _ := json.Marshal(app)
		aVer, _ := store.Put(ctx, storage.AppKey("default", "demo_app"), aBytes, "")
		app.Version = aVer
		c.SetApp("default", "demo_app", app, 1*time.Hour)

		// 2b. System Admin Console Application
		adminApp := &models.Application{
			ID:           "admin_console",
			TenantID:     "default",
			Name:         "Authpole Admin Console",
			ClientID:     "admin_console",
			ClientSecret: "admin_console_secret",
			RedirectURIs: []string{"http://localhost:3000", "http://localhost:3000/callback.html", "http://localhost:8080/admin/"},
			AllowedIDPs:  []string{"mock_idp"},
			Scopes:       []string{"openid", "profile", "email"},
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		}
		adminAppBytes, _ := json.Marshal(adminApp)
		adminAppVer, _ := store.Put(ctx, storage.AppKey("default", "admin_console"), adminAppBytes, "")
		adminApp.Version = adminAppVer
		c.SetApp("default", "admin_console", adminApp, 1*time.Hour)

		// 3. Upstream IDP
		idp := &models.IdentityProvider{
			ID:        "mock_idp",
			TenantID:  "default",
			Name:      "Demo Upstream IDP",
			Type:      "mock",
			ClientID:  "auth_hub_proxy",
			Scopes:    []string{"openid", "profile", "email"},
			Enabled:   true,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		iBytes, _ := json.Marshal(idp)
		_, _ = store.Put(ctx, storage.IDPKey("default", "mock_idp"), iBytes, "")

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
			ID:        "admin_root",
			TenantID:  "default",
			Email:     "admin@authpole.io",
			Name:      "System Admin",
			RoleIDs:   []string{"super_admin"},
			TeamIDs:   []string{"core_ops"},
			Active:    true,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		uBytes, _ := json.Marshal(adminUser)
		_, _ = store.Put(ctx, storage.AdminUserKey("default", adminUser.ID), uBytes, "")

		role := &models.Role{
			ID:          "super_admin",
			TenantID:    "default",
			Name:        "Super Administrator",
			Description: "Full access to all Auth Pole tenant configurations and settings",
			Permissions: []string{"tenant:read", "tenant:write", "app:manage", "idp:manage", "keys:manage"},
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
		rBytes, _ := json.Marshal(role)
		_, _ = store.Put(ctx, storage.RoleKey("default", role.ID), rBytes, "")

		team := &models.Team{
			ID:          "core_ops",
			TenantID:    "default",
			Name:        "Core Operations Team",
			Description: "Platform operations and auth pole configuration maintainers",
			RoleIDs:     []string{"super_admin"},
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
		tmBytes, _ := json.Marshal(team)
		_, _ = store.Put(ctx, storage.TeamKey("default", team.ID), tmBytes, "")

		// 6. Default SPIFFE Workload Identity
		spiffeWorkload := &models.SPIFFEWorkload{
			ID:               "payment_service",
			TenantID:         "default",
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
