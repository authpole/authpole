package storage

import (
	"context"
	"errors"
	"fmt"
	"github.com/authpole/authpole/pkg/models"
)

var (
	// ErrVersionMismatch is returned when a CAS update fails because expected version does not match current version.
	ErrVersionMismatch = errors.New("cas conflict: object version has changed")
	// ErrNotFound is returned when an object key does not exist.
	ErrNotFound = errors.New("object not found")
)

// MatchAnyVersion is passed as expectedVersion to make a Put create-only: the
// write succeeds only if the key does not already exist (S3 If-None-Match: *),
// and returns ErrVersionMismatch otherwise.
//
// This is the primitive that lets several nodes race to create the same record
// and have exactly one win, which matters for anything where a second copy would
// be actively wrong - a tenant's signing key, for example.
const MatchAnyVersion = "*"

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

	// Close releases any resources used by the storage engine.
	Close() error
}

// StorageKey helper functions to standardize object key formats in S3
func OrganizationKey(orgID string) string {
	return fmt.Sprintf("organizations/%s/metadata.json", orgID)
}

func AppKey(orgID, appID string) string {
	return fmt.Sprintf("organizations/%s/apps/%s.json", orgID, appID)
}

func IDPKey(orgID, idpID string) string {
	return fmt.Sprintf("organizations/%s/idps/%s.json", orgID, idpID)
}

func KeyPairKey(orgID, keyID string) string {
	return fmt.Sprintf("organizations/%s/keys/%s.json", orgID, keyID)
}

func AdminUserKey(orgID, userID string) string {
	return fmt.Sprintf("organizations/%s/admin/users/%s.json", orgID, userID)
}

func TeamKey(orgID, teamID string) string {
	return fmt.Sprintf("organizations/%s/admin/teams/%s.json", orgID, teamID)
}

func RoleKey(orgID, roleID string) string {
	return fmt.Sprintf("organizations/%s/admin/roles/%s.json", orgID, roleID)
}

func SPIFFEWorkloadKey(orgID, workloadID string) string {
	return fmt.Sprintf("organizations/%s/spiffe/workloads/%s.json", orgID, workloadID)
}

func AuthStateKey(stateID string) string {
	return fmt.Sprintf("sessions/states/%s.json", stateID)
}

func AuthCodeKey(code string) string {
	return fmt.Sprintf("sessions/codes/%s.json", code)
}

// RefreshTokenKey locates a persisted refresh-token handle.
//
// Refresh tokens are stored server-side rather than being self-contained JWTs so
// that they can be revoked and so that rotation is enforceable: consumption is a
// CAS delete, which makes a second presentation of the same handle fail.
func RefreshTokenKey(handle string) string {
	return fmt.Sprintf("sessions/refresh/%s.json", handle)
}
