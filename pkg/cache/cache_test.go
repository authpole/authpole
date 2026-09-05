package cache_test

import (
	"testing"
	"time"

	"github.com/authpole/authpole/pkg/cache"
	"github.com/authpole/authpole/pkg/models"
)

func TestShardsAndCache(t *testing.T) {
	orgID := "org_fintech"
	appID := "app_mobile"

	// Test sharding key excludes KeyID to minimize cluster memory footprint
	shardKey := cache.ShardKey(orgID, appID)
	if shardKey != "org_fintech:app_mobile" {
		t.Fatalf("Unexpected shard key format: %s", shardKey)
	}

	hashVal := cache.ShardHash(orgID, appID)
	if hashVal == 0 {
		t.Fatalf("Shard hash returned 0")
	}

	nodeIdx := cache.DetermineNode(orgID, appID, 5)
	if nodeIdx < 0 || nodeIdx >= 5 {
		t.Fatalf("DetermineNode returned invalid node index: %d", nodeIdx)
	}

	// Test Memory Cache
	c := cache.NewMemoryCache()

	app := &models.Application{
		ID:             appID,
		OrganizationID: orgID,
		Name:           "Fintech App",
	}

	c.SetApp(orgID, appID, app, 1*time.Minute)

	fetchedApp, found := c.GetApp(orgID, appID)
	if !found || fetchedApp.Name != "Fintech App" {
		t.Fatalf("Cache lookup failed: %+v", fetchedApp)
	}

	// Test Cache Invalidation
	c.InvalidateApp(orgID, appID)
	_, foundAfterInvalidate := c.GetApp(orgID, appID)
	if foundAfterInvalidate {
		t.Fatalf("Expected app to be evicted from cache after invalidation")
	}
}
