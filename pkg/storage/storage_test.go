package storage_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"authpole/pkg/storage"
)

func TestJayDBMemoryStorage(t *testing.T) {
	store, err := storage.NewMemoryStorage()
	if err != nil {
		t.Fatalf("Failed to create JayDB memory storage: %v", err)
	}
	defer store.Close()

	testStorageOperations(t, store)
}

func TestJayDBFSStorage(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "authpole_jaydb_storage_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	store, err := storage.NewFSStorage(tempDir)
	if err != nil {
		t.Fatalf("Failed to create JayDB FS storage: %v", err)
	}
	defer store.Close()

	testStorageOperations(t, store)
}

func testStorageOperations(t *testing.T, store storage.Storage) {
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
	if string(rec.Data) != string(data1) {
		t.Fatalf("Expected data %s, got %s", string(data1), string(rec.Data))
	}

	// 3. Stale Put with wrong expected version -> Must fail with ErrVersionMismatch
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

	// 6. List records by prefix
	records, err := store.List(ctx, "organizations/")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("Expected 1 listed record, got %d", len(records))
	}

	// 7. Delete with CAS check
	err = store.Delete(ctx, key, v2)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// 8. Verify record deleted
	_, err = store.Get(ctx, key)
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("Expected ErrNotFound after delete, got: %v", err)
	}
}
