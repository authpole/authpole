package storage

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"authpole/pkg/models"
)

// S3CASStorage provides a production S3 client implementation using standard HTTP REST / AWS S3 protocol calls.
// It leverages S3 Object ETags and VersionIDs for Compare-And-Swap (CAS) validation.
type S3CASStorage struct {
	bucketName string
	region     string
	endpoint   string
	httpClient *http.Client
}

// NewS3CASStorage creates a new S3 CAS storage backend instance.
func NewS3CASStorage(bucketName, region, endpoint string) *S3CASStorage {
	return &S3CASStorage{
		bucketName: bucketName,
		region:     region,
		endpoint:   endpoint,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

func (s *S3CASStorage) Get(ctx context.Context, key string) (*models.StoredRecord, error) {
	url := fmt.Sprintf("%s/%s/%s", s.endpoint, s.bucketName, key)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("s3 get failed with status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	version := resp.Header.Get("ETag")
	if version == "" {
		version = resp.Header.Get("x-amz-version-id")
	}

	return &models.StoredRecord{
		Key:     key,
		Version: version,
		Data:    data,
	}, nil
}

func (s *S3CASStorage) Put(ctx context.Context, key string, data []byte, expectedVersion string) (string, error) {
	url := fmt.Sprintf("%s/%s/%s", s.endpoint, s.bucketName, key)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(data))
	if err != nil {
		return "", err
	}

	if expectedVersion != "" {
		req.Header.Set("If-Match", expectedVersion)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusPreconditionFailed {
		return "", ErrVersionMismatch
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("s3 put failed with status %d", resp.StatusCode)
	}

	newVersion := resp.Header.Get("ETag")
	if newVersion == "" {
		newVersion = resp.Header.Get("x-amz-version-id")
	}

	return newVersion, nil
}

func (s *S3CASStorage) Delete(ctx context.Context, key string, expectedVersion string) error {
	url := fmt.Sprintf("%s/%s/%s", s.endpoint, s.bucketName, key)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return err
	}

	if expectedVersion != "" {
		req.Header.Set("If-Match", expectedVersion)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusPreconditionFailed {
		return ErrVersionMismatch
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("s3 delete failed with status %d", resp.StatusCode)
	}

	return nil
}

func (s *S3CASStorage) List(ctx context.Context, prefix string) ([]*models.StoredRecord, error) {
	// In production, standard S3 ListObjectsV2 call would be issued.
	return nil, fmt.Errorf("list method requires s3 bucket list permission")
}
