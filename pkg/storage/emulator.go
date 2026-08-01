package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"authpole/pkg/models"
)

// MemoryCASStorage implements S3-compatible CAS storage in memory with optional disk persistence for local dev & testing.
type MemoryCASStorage struct {
	mu        sync.RWMutex
	records   map[string]*models.StoredRecord
	dataDir   string
	persistent bool
}

// NewMemoryCASStorage creates a new memory-backed S3 CAS emulator.
func NewMemoryCASStorage(dataDir string) (*MemoryCASStorage, error) {
	s := &MemoryCASStorage{
		records:    make(map[string]*models.StoredRecord),
		dataDir:    dataDir,
		persistent: dataDir != "",
	}

	if s.persistent {
		if err := os.MkdirAll(dataDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create data dir: %w", err)
		}
		if err := s.loadFromDisk(); err != nil {
			return nil, fmt.Errorf("failed to load initial data from disk: %w", err)
		}
	}

	return s, nil
}

func (s *MemoryCASStorage) Get(ctx context.Context, key string) (*models.StoredRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rec, exists := s.records[key]
	if !exists {
		return nil, ErrNotFound
	}

	// Return a copy to prevent external mutation
	dataCopy := make([]byte, len(rec.Data))
	copy(dataCopy, rec.Data)

	return &models.StoredRecord{
		Key:     rec.Key,
		Version: rec.Version,
		Data:    dataCopy,
	}, nil
}

func (s *MemoryCASStorage) Put(ctx context.Context, key string, data []byte, expectedVersion string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	current, exists := s.records[key]

	// CAS Check
	if expectedVersion != "" {
		if !exists {
			return "", fmt.Errorf("%w: object does not exist but expected version %q was provided", ErrVersionMismatch, expectedVersion)
		}
		if current.Version != expectedVersion {
			return "", fmt.Errorf("%w: current version %q != expected version %q", ErrVersionMismatch, current.Version, expectedVersion)
		}
	}

	// Compute new version tag (SHA-256 hash + timestamp digest)
	newVersion := generateVersion(data)

	record := &models.StoredRecord{
		Key:     key,
		Version: newVersion,
		Data:    append([]byte(nil), data...),
	}

	s.records[key] = record

	if s.persistent {
		if err := s.saveToDisk(key, record); err != nil {
			return "", err
		}
	}

	return newVersion, nil
}

func (s *MemoryCASStorage) Delete(ctx context.Context, key string, expectedVersion string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	current, exists := s.records[key]
	if !exists {
		return ErrNotFound
	}

	if expectedVersion != "" && current.Version != expectedVersion {
		return fmt.Errorf("%w: current version %q != expected version %q", ErrVersionMismatch, current.Version, expectedVersion)
	}

	delete(s.records, key)

	if s.persistent {
		filePath := filepath.Join(s.dataDir, filepath.FromSlash(key))
		_ = os.Remove(filePath)
	}

	return nil
}

func (s *MemoryCASStorage) List(ctx context.Context, prefix string) ([]*models.StoredRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*models.StoredRecord
	for k, rec := range s.records {
		if strings.HasPrefix(k, prefix) {
			dataCopy := make([]byte, len(rec.Data))
			copy(dataCopy, rec.Data)
			result = append(result, &models.StoredRecord{
				Key:     rec.Key,
				Version: rec.Version,
				Data:    dataCopy,
			})
		}
	}
	return result, nil
}

func generateVersion(data []byte) string {
	h := sha256.New()
	h.Write(data)
	h.Write([]byte(fmt.Sprintf(":%d", time.Now().UnixNano())))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func (s *MemoryCASStorage) saveToDisk(key string, rec *models.StoredRecord) error {
	filePath := filepath.Join(s.dataDir, filepath.FromSlash(key))
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Write version tag in metadata header file or comment header
	content := append([]byte(fmt.Sprintf("// VERSION:%s\n", rec.Version)), rec.Data...)
	return os.WriteFile(filePath, content, 0644)
}

func (s *MemoryCASStorage) loadFromDisk() error {
	return filepath.Walk(s.dataDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		relPath, err := filepath.Rel(s.dataDir, path)
		if err != nil {
			return err
		}
		key := filepath.ToSlash(relPath)

		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		version := "1"
		data := content

		if strings.HasPrefix(string(content), "// VERSION:") {
			lines := strings.SplitN(string(content), "\n", 2)
			if len(lines) == 2 {
				version = strings.TrimPrefix(lines[0], "// VERSION:")
				data = []byte(lines[1])
			}
		}

		s.records[key] = &models.StoredRecord{
			Key:     key,
			Version: version,
			Data:    data,
		}
		return nil
	})
}
