package storage_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"authpole/pkg/storage"
)

func TestMemoryCASStorage(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "authpole_storage_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	store, err := storage.NewMemoryCASStorage(tempDir)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}

	ctx := context.Background()
	key := "organizations/test_org/metadata.json"
	data1 := []byte(`{"id":"test_org","name":"Initial Organization Name"}`)

	// 1. Initial Put (no expected version)
	v1, err := store.Put(ctx, key, data1, "")
	if err != nil {
		t.Fatalf("Initial put failed: %v", err)
	}
	if v1 == "" {
		t.Fatalf("Expected non-empty version ID")
	}

	// 2. Get and verify version
	rec, err := store.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if rec.Version != v1 {
		t.Fatalf("Expected version %s, got %s", v1, rec.Version)
	}

	// 3. Stale Put with wrong expected version -> Must fail with ErrVersionMismatch (409 Conflict)
	data2 := []byte(`{"id":"test_org","name":"Conflicting Update"}`)
	_, err = store.Put(ctx, key, data2, "invalid_stale_version_999")
	if !errors.Is(err, storage.ErrVersionMismatch) {
		t.Fatalf("Expected ErrVersionMismatch on stale CAS put, got: %v", err)
	}

	// 4. Valid CAS Put with matching version v1 -> Should succeed
	v2, err := store.Put(ctx, key, data2, v1)
	if err != nil {
		t.Fatalf("Valid CAS put failed: %v", err)
	}
	if v2 == v1 {
		t.Fatalf("Expected new version ID to be generated after update")
	}

	// 5. Verify updated data
	rec2, err := store.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if rec2.Version != v2 {
		t.Fatalf("Expected version %s, got %s", v2, rec2.Version)
	}
}
