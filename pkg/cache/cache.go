package cache

import (
	"fmt"
	"sync"
	"time"

	"authpole/pkg/models"
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

// InvalidateTenant removes all cached items for a given tenant.
func (c *MemoryCache) InvalidateTenant(tenantID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	prefix := fmt.Sprintf("t:%s:", tenantID)
	for k := range c.items {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			delete(c.items, k)
		}
	}
}

// InvalidateApp removes cached items for a specific tenant application.
func (c *MemoryCache) InvalidateApp(tenantID, appID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	appPrefix := fmt.Sprintf("t:%s:app:%s", tenantID, appID)
	keyPrefix := fmt.Sprintf("t:%s:keys:%s", tenantID, appID)
	jwksPrefix := fmt.Sprintf("t:%s:jwks:%s", tenantID, appID)

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

func CacheKeyTenant(tenantID string) string {
	return fmt.Sprintf("t:%s:meta", tenantID)
}

func CacheKeyApp(tenantID, appID string) string {
	return fmt.Sprintf("t:%s:app:%s", tenantID, appID)
}

func CacheKeyIDP(tenantID, idpID string) string {
	return fmt.Sprintf("t:%s:idp:%s", tenantID, idpID)
}

func CacheKeySigningKeys(tenantID, appID string) string {
	return fmt.Sprintf("t:%s:keys:%s", tenantID, appID)
}

func CacheKeyJWKS(tenantID, appID string) string {
	return fmt.Sprintf("t:%s:jwks:%s", tenantID, appID)
}

// Typed getter & setter methods

func (c *MemoryCache) GetApp(tenantID, appID string) (*models.Application, bool) {
	val, found := c.Get(CacheKeyApp(tenantID, appID))
	if !found {
		return nil, false
	}
	app, ok := val.(*models.Application)
	return app, ok
}

func (c *MemoryCache) SetApp(tenantID, appID string, app *models.Application, ttl time.Duration) {
	c.Set(CacheKeyApp(tenantID, appID), app, ttl)
}

func (c *MemoryCache) GetSigningKeys(tenantID, appID string) ([]*models.SigningKey, bool) {
	val, found := c.Get(CacheKeySigningKeys(tenantID, appID))
	if !found {
		return nil, false
	}
	keys, ok := val.([]*models.SigningKey)
	return keys, ok
}

func (c *MemoryCache) SetSigningKeys(tenantID, appID string, keys []*models.SigningKey, ttl time.Duration) {
	c.Set(CacheKeySigningKeys(tenantID, appID), keys, ttl)
}

func (c *MemoryCache) GetJWKS(tenantID, appID string) ([]byte, bool) {
	val, found := c.Get(CacheKeyJWKS(tenantID, appID))
	if !found {
		return nil, false
	}
	jwks, ok := val.([]byte)
	return jwks, ok
}

func (c *MemoryCache) SetJWKS(tenantID, appID string, jwks []byte, ttl time.Duration) {
	c.Set(CacheKeyJWKS(tenantID, appID), jwks, ttl)
}
