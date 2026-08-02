package storage

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"authpole/pkg/models"
)

// S3CASStorage provides a production S3 client using AWS SDK v2 with SigV4 signing.
// On EC2 it automatically picks up credentials from the instance IAM role via IMDS.
// When endpoint is non-empty (e.g. MinIO for local dev) it uses path-style addressing.
type S3CASStorage struct {
	bucketName string
	client     *s3.Client
}

// NewS3CASStorage creates a new S3 CAS storage backend.
// region: AWS region (e.g. "us-east-1")
// endpoint: optional override for local dev (e.g. "http://localhost:9000"); empty = real AWS S3
func NewS3CASStorage(bucketName, region, endpoint string) *S3CASStorage {
	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(region),
	)
	if err != nil {
		panic(fmt.Sprintf("failed to load AWS config: %v", err))
	}

	opts := []func(*s3.Options){}
	if endpoint != "" {
		// Local dev: MinIO or other S3-compatible store — use path-style
		opts = append(opts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(endpoint)
			o.UsePathStyle = true
		})
	}

	return &S3CASStorage{
		bucketName: bucketName,
		client:     s3.NewFromConfig(cfg, opts...),
	}
}

func (s *S3CASStorage) Get(ctx context.Context, key string) (*models.StoredRecord, error) {
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucketName),
		Key:    aws.String(key),
	})
	if err != nil {
		if isS3NotFound(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("s3 get %q: %w", key, err)
	}
	defer out.Body.Close()

	data, err := io.ReadAll(out.Body)
	if err != nil {
		return nil, fmt.Errorf("s3 read body %q: %w", key, err)
	}

	version := ""
	if out.ETag != nil {
		version = *out.ETag
	} else if out.VersionId != nil {
		version = *out.VersionId
	}

	return &models.StoredRecord{
		Key:     key,
		Version: version,
		Data:    data,
	}, nil
}

func (s *S3CASStorage) Put(ctx context.Context, key string, data []byte, expectedVersion string) (string, error) {
	input := &s3.PutObjectInput{
		Bucket: aws.String(s.bucketName),
		Key:    aws.String(key),
		Body:   bytes.NewReader(data),
	}
	if expectedVersion != "" {
		input.IfMatch = aws.String(expectedVersion)
	}

	out, err := s.client.PutObject(ctx, input)
	if err != nil {
		if isS3PreconditionFailed(err) {
			return "", ErrVersionMismatch
		}
		return "", fmt.Errorf("s3 put %q: %w", key, err)
	}

	newVersion := ""
	if out.ETag != nil {
		newVersion = *out.ETag
	} else if out.VersionId != nil {
		newVersion = *out.VersionId
	}
	return newVersion, nil
}

func (s *S3CASStorage) Delete(ctx context.Context, key string, expectedVersion string) error {
	input := &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucketName),
		Key:    aws.String(key),
	}
	if expectedVersion != "" {
		input.IfMatch = aws.String(expectedVersion)
	}

	_, err := s.client.DeleteObject(ctx, input)
	if err != nil {
		if isS3PreconditionFailed(err) {
			return ErrVersionMismatch
		}
		return fmt.Errorf("s3 delete %q: %w", key, err)
	}
	return nil
}

func (s *S3CASStorage) List(ctx context.Context, prefix string) ([]*models.StoredRecord, error) {
	out, err := s.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucketName),
		Prefix: aws.String(prefix),
	})
	if err != nil {
		return nil, fmt.Errorf("s3 list %q: %w", prefix, err)
	}

	var records []*models.StoredRecord
	for _, obj := range out.Contents {
		if obj.Key == nil {
			continue
		}
		rec, err := s.Get(ctx, *obj.Key)
		if err != nil {
			continue // skip unreadable objects rather than aborting
		}
		records = append(records, rec)
	}
	return records, nil
}

// isS3NotFound returns true for 404 / NoSuchKey errors.
func isS3NotFound(err error) bool {
	if err == nil {
		return false
	}
	switch err.(type) {
	case *types.NoSuchKey:
		return true
	}
	// Fallback: check error string (covers 404 from non-versioned buckets)
	return containsAny(err.Error(), "NoSuchKey", "404", "NotFound")
}

// isS3PreconditionFailed returns true for 412 Precondition Failed (ETag mismatch).
func isS3PreconditionFailed(err error) bool {
	if err == nil {
		return false
	}
	return containsAny(err.Error(), "PreconditionFailed", "412")
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}
