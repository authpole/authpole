package cache

import (
	"fmt"
	"sync"
	"time"

	"github.com/authpole/authpole/pkg/models"
)

type CacheItem struct {
	Value     interface{}
	ExpiresAt time.Time
}

// MemoryCache provides zero-latency in-memory lookup for tenant settings, app configs, signing keys, and JWKS JSON payloads.
type MemoryCache struct {
	mu    sync.RWMutex
	items map[string]CacheItem
}

func NewMemoryCache() *MemoryCache {
	c := &MemoryCache{
		items: make(map[string]CacheItem),
	}
	go c.startJanitor(1 * time.Minute)
	return c
}

func (c *MemoryCache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	item, found := c.items[key]
	if !found {
		return nil, false
	}

	if !item.ExpiresAt.IsZero() && time.Now().After(item.ExpiresAt) {
		return nil, false
	}

	return item.Value, true
}

func (c *MemoryCache) Set(key string, value interface{}, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var expiresAt time.Time
	if ttl > 0 {
		expiresAt = time.Now().Add(ttl)
	}

	c.items[key] = CacheItem{
		Value:     value,
		ExpiresAt: expiresAt,
	}
}

func (c *MemoryCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.items, key)
}

// InvalidateOrganization removes all cached items for a given organization.
func (c *MemoryCache) InvalidateOrganization(orgID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	prefix := fmt.Sprintf("o:%s:", orgID)
	for k := range c.items {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			delete(c.items, k)
		}
	}
}

// InvalidateApp removes cached items for a specific organization application.
func (c *MemoryCache) InvalidateApp(orgID, appID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	appPrefix := fmt.Sprintf("o:%s:app:%s", orgID, appID)
	keyPrefix := fmt.Sprintf("o:%s:keys:%s", orgID, appID)
	jwksPrefix := fmt.Sprintf("o:%s:jwks:%s", orgID, appID)

	for k := range c.items {
		if k == appPrefix || k == keyPrefix || k == jwksPrefix {
			delete(c.items, k)
		}
	}
}

func (c *MemoryCache) startJanitor(interval time.Duration) {
	ticker := time.NewTicker(interval)
	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for k, item := range c.items {
			if !item.ExpiresAt.IsZero() && now.After(item.ExpiresAt) {
				delete(c.items, k)
			}
		}
		c.mu.Unlock()
	}
}

// Helpers for type-safe cache keys

func CacheKeyOrganization(orgID string) string {
	return fmt.Sprintf("o:%s:meta", orgID)
}

func CacheKeyApp(orgID, appID string) string {
	return fmt.Sprintf("o:%s:app:%s", orgID, appID)
}

func CacheKeyIDP(orgID, idpID string) string {
	return fmt.Sprintf("o:%s:idp:%s", orgID, idpID)
}

func CacheKeySigningKeys(orgID, appID string) string {
	return fmt.Sprintf("o:%s:keys:%s", orgID, appID)
}

func CacheKeyJWKS(orgID, appID string) string {
	return fmt.Sprintf("o:%s:jwks:%s", orgID, appID)
}

// Typed getter & setter methods

func (c *MemoryCache) GetApp(orgID, appID string) (*models.Application, bool) {
	val, found := c.Get(CacheKeyApp(orgID, appID))
	if !found {
		return nil, false
	}
	app, ok := val.(*models.Application)
	return app, ok
}

func (c *MemoryCache) SetApp(orgID, appID string, app *models.Application, ttl time.Duration) {
	c.Set(CacheKeyApp(orgID, appID), app, ttl)
}

func (c *MemoryCache) GetSigningKeys(orgID, appID string) ([]*models.SigningKey, bool) {
	val, found := c.Get(CacheKeySigningKeys(orgID, appID))
	if !found {
		return nil, false
	}
	keys, ok := val.([]*models.SigningKey)
	return keys, ok
}

func (c *MemoryCache) SetSigningKeys(orgID, appID string, keys []*models.SigningKey, ttl time.Duration) {
	c.Set(CacheKeySigningKeys(orgID, appID), keys, ttl)
}

func (c *MemoryCache) GetJWKS(orgID, appID string) ([]byte, bool) {
	val, found := c.Get(CacheKeyJWKS(orgID, appID))
	if !found {
		return nil, false
	}
	jwks, ok := val.([]byte)
	return jwks, ok
}

func (c *MemoryCache) SetJWKS(orgID, appID string, jwks []byte, ttl time.Duration) {
	c.Set(CacheKeyJWKS(orgID, appID), jwks, ttl)
}
