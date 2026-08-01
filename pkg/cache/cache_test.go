package cache_test

import (
	"testing"
	"time"

	"authpole/pkg/cache"
	"authpole/pkg/models"
)

func TestShardsAndCache(t *testing.T) {
	tenantID := "tenant_fintech"
	appID := "app_mobile"

	// Test sharding key excludes KeyID to minimize cluster memory footprint
	shardKey := cache.ShardKey(tenantID, appID)
	if shardKey != "tenant_fintech:app_mobile" {
		t.Fatalf("Unexpected shard key format: %s", shardKey)
	}

	hashVal := cache.ShardHash(tenantID, appID)
	if hashVal == 0 {
		t.Fatalf("Shard hash returned 0")
	}

	nodeIdx := cache.DetermineNode(tenantID, appID, 5)
	if nodeIdx < 0 || nodeIdx >= 5 {
		t.Fatalf("DetermineNode returned invalid node index: %d", nodeIdx)
	}

	// Test Memory Cache
	c := cache.NewMemoryCache()

	app := &models.Application{
		ID:       appID,
		TenantID: tenantID,
		Name:     "Fintech App",
	}

	c.SetApp(tenantID, appID, app, 1*time.Minute)

	fetchedApp, found := c.GetApp(tenantID, appID)
	if !found || fetchedApp.Name != "Fintech App" {
		t.Fatalf("Cache lookup failed: %+v", fetchedApp)
	}

	// Test Cache Invalidation
	c.InvalidateApp(tenantID, appID)
	_, foundAfterInvalidate := c.GetApp(tenantID, appID)
	if foundAfterInvalidate {
		t.Fatalf("Expected app to be evicted from cache after invalidation")
	}
}
