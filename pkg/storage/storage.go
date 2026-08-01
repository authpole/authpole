package storage

import (
	"context"
	"errors"
	"fmt"
	"authpole/pkg/models"
)

var (
	// ErrVersionMismatch is returned when a CAS update fails because expected version does not match current version.
	ErrVersionMismatch = errors.New("cas conflict: object version has changed")
	// ErrNotFound is returned when an object key does not exist.
	ErrNotFound = errors.New("object not found")
)

// Storage defines the interface for S3 object persistence with Compare-And-Swap (CAS) logic.
type Storage interface {
	// Get retrieves a record by object key and returns its payload alongside its current Version ID.
	Get(ctx context.Context, key string) (*models.StoredRecord, error)

	// Put writes data to an object key with CAS validation.
	// If expectedVersion is non-empty, the write fails with ErrVersionMismatch if current version != expectedVersion.
	// Returns the newly assigned Version ID.
	Put(ctx context.Context, key string, data []byte, expectedVersion string) (newVersion string, err error)

	// Delete removes an object key with optional CAS validation.
	Delete(ctx context.Context, key string, expectedVersion string) error

	// List returns all records matching a key prefix.
	List(ctx context.Context, prefix string) ([]*models.StoredRecord, error)
}

// StorageKey helper functions to standardize object key formats in S3
func TenantKey(tenantID string) string {
	return fmt.Sprintf("tenants/%s/metadata.json", tenantID)
}

func AppKey(tenantID, appID string) string {
	return fmt.Sprintf("tenants/%s/apps/%s.json", tenantID, appID)
}

func IDPKey(tenantID, idpID string) string {
	return fmt.Sprintf("tenants/%s/idps/%s.json", tenantID, idpID)
}

func KeyPairKey(tenantID, keyID string) string {
	return fmt.Sprintf("tenants/%s/keys/%s.json", tenantID, keyID)
}

func AdminUserKey(tenantID, userID string) string {
	return fmt.Sprintf("tenants/%s/admin/users/%s.json", tenantID, userID)
}

func TeamKey(tenantID, teamID string) string {
	return fmt.Sprintf("tenants/%s/admin/teams/%s.json", tenantID, teamID)
}

func RoleKey(tenantID, roleID string) string {
	return fmt.Sprintf("tenants/%s/admin/roles/%s.json", tenantID, roleID)
}

func SPIFFEWorkloadKey(tenantID, workloadID string) string {
	return fmt.Sprintf("tenants/%s/spiffe/workloads/%s.json", tenantID, workloadID)
}

