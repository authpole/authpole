package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"authpole/pkg/models"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/avivklas/jaydb/pkg/db"
	"github.com/avivklas/jaydb/pkg/encoding"
	jaydbStorage "github.com/avivklas/jaydb/pkg/storage"
	"github.com/avivklas/jaydb/pkg/storage/fs"
	"github.com/avivklas/jaydb/pkg/storage/memory"
)

// JayDBStorage implements authpole's Storage interface using the embedded JayDB engine.
type JayDBStorage struct {
	database db.DB
}

// NewJayDBStorage wraps an existing JayDB database instance.
func NewJayDBStorage(database db.DB) *JayDBStorage {
	return &JayDBStorage{database: database}
}

// NewMemoryStorage creates an in-memory JayDB storage engine.
func NewMemoryStorage() (*JayDBStorage, error) {
	drv := memory.NewDriver()
	database, err := db.Open(db.Options{
		Storage:       drv,
		Codec:         encoding.NewRawCodec(),
		ShardingDepth: 2,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open JayDB memory store: %w", err)
	}
	return NewJayDBStorage(database), nil
}

// NewFSStorage creates a filesystem-backed JayDB storage engine.
func NewFSStorage(dataDir string) (*JayDBStorage, error) {
	drv, err := fs.NewDriver(dataDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create JayDB fs driver: %w", err)
	}
	database, err := db.Open(db.Options{
		Storage:       drv,
		Codec:         encoding.NewRawCodec(),
		ShardingDepth: 2,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open JayDB fs store: %w", err)
	}
	return NewJayDBStorage(database), nil
}

// NewS3Storage creates an AWS S3-backed JayDB storage engine using SigV4 AWS SDK v2 signing.
func NewS3Storage(bucketName, region, endpoint string) (*JayDBStorage, error) {
	drv := NewAWSS3Driver(bucketName, region, endpoint)
	database, err := db.Open(db.Options{
		Storage:       drv,
		Codec:         encoding.NewRawCodec(),
		ShardingDepth: 2,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open JayDB S3 store: %w", err)
	}
	return NewJayDBStorage(database), nil
}

func (s *JayDBStorage) Get(ctx context.Context, key string) (*models.StoredRecord, error) {
	var data []byte
	meta, err := s.database.Get(ctx, key, &data)
	if err != nil {
		if errors.Is(err, jaydbStorage.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return &models.StoredRecord{
		Key:     key,
		Version: meta.ETag,
		Data:    data,
	}, nil
}

func (s *JayDBStorage) Put(ctx context.Context, key string, data []byte, expectedVersion string) (string, error) {
	var opts []db.PutOption
	if expectedVersion != "" {
		opts = append(opts, db.WithExpectedETag(expectedVersion))
	}

	meta, err := s.database.Put(ctx, key, data, opts...)
	if err != nil {
		if errors.Is(err, jaydbStorage.ErrVersionMismatch) || errors.Is(err, jaydbStorage.ErrAlreadyExists) || errors.Is(err, jaydbStorage.ErrNotFound) {
			return "", ErrVersionMismatch
		}
		return "", err
	}

	return meta.ETag, nil
}

func (s *JayDBStorage) Delete(ctx context.Context, key string, expectedVersion string) error {
	var opts []db.DeleteOption
	if expectedVersion != "" {
		opts = append(opts, db.WithDeleteExpectedETag(expectedVersion))
	}

	err := s.database.Delete(ctx, key, opts...)
	if err != nil {
		if errors.Is(err, jaydbStorage.ErrNotFound) {
			return ErrNotFound
		}
		if errors.Is(err, jaydbStorage.ErrVersionMismatch) {
			return ErrVersionMismatch
		}
		return err
	}

	return nil
}

func (s *JayDBStorage) List(ctx context.Context, prefix string) ([]*models.StoredRecord, error) {
	items, err := s.database.List(ctx, prefix, 0)
	if err != nil {
		return nil, err
	}

	var records []*models.StoredRecord
	for _, item := range items {
		rec, err := s.Get(ctx, item.Meta.Key)
		if err != nil {
			continue
		}
		records = append(records, rec)
	}

	return records, nil
}

func (s *JayDBStorage) Close() error {
	return s.database.Close()
}

// AWSS3Driver implements JayDB's storage.Driver using AWS SDK v2 with SigV4 signing.
type AWSS3Driver struct {
	bucket string
	client *s3.Client
}

func NewAWSS3Driver(bucketName, region, endpoint string) jaydbStorage.Driver {
	if region == "" {
		region = "us-east-1"
	}
	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(region),
	)
	if err != nil {
		panic(fmt.Sprintf("failed to load AWS config: %v", err))
	}

	opts := []func(*s3.Options){}
	if endpoint != "" {
		opts = append(opts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(endpoint)
			o.UsePathStyle = true
		})
	}

	return &AWSS3Driver{
		bucket: bucketName,
		client: s3.NewFromConfig(cfg, opts...),
	}
}

func (d *AWSS3Driver) Get(ctx context.Context, key string) (*jaydbStorage.Object, error) {
	out, err := d.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(d.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		if isS3NotFound(err) {
			return nil, jaydbStorage.ErrNotFound
		}
		return nil, fmt.Errorf("s3 get %q: %w", key, err)
	}
	defer out.Body.Close()

	data, err := io.ReadAll(out.Body)
	if err != nil {
		return nil, fmt.Errorf("s3 read body %q: %w", key, err)
	}

	etag := ""
	if out.ETag != nil {
		etag = fmt.Sprintf(`"%s"`, strings.Trim(*out.ETag, `"`))
	}

	modTime := time.Now()
	if out.LastModified != nil {
		modTime = *out.LastModified
	}

	return &jaydbStorage.Object{
		Key:     key,
		Value:   data,
		ETag:    etag,
		ModTime: modTime,
	}, nil
}

func (d *AWSS3Driver) Put(ctx context.Context, key string, value []byte, expectedETag string) (*jaydbStorage.Object, error) {
	input := &s3.PutObjectInput{
		Bucket: aws.String(d.bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(value),
	}
	if expectedETag != "" {
		if expectedETag == jaydbStorage.MatchAnyETag {
			input.IfNoneMatch = aws.String("*")
		} else {
			input.IfMatch = aws.String(expectedETag)
		}
	}

	out, err := d.client.PutObject(ctx, input)
	if err != nil {
		if isS3PreconditionFailed(err) {
			if expectedETag == jaydbStorage.MatchAnyETag {
				return nil, jaydbStorage.ErrAlreadyExists
			}
			return nil, jaydbStorage.ErrVersionMismatch
		}
		return nil, fmt.Errorf("s3 put %q: %w", key, err)
	}

	newETag := ""
	if out.ETag != nil {
		newETag = fmt.Sprintf(`"%s"`, strings.Trim(*out.ETag, `"`))
	} else {
		newETag = fmt.Sprintf(`"%x"`, time.Now().UnixNano())
	}

	return &jaydbStorage.Object{
		Key:     key,
		Value:   append([]byte(nil), value...),
		ETag:    newETag,
		ModTime: time.Now(),
	}, nil
}

func (d *AWSS3Driver) Delete(ctx context.Context, key string, expectedETag string) error {
	input := &s3.DeleteObjectInput{
		Bucket: aws.String(d.bucket),
		Key:    aws.String(key),
	}
	if expectedETag != "" && expectedETag != jaydbStorage.MatchAnyETag {
		input.IfMatch = aws.String(expectedETag)
	}

	_, err := d.client.DeleteObject(ctx, input)
	if err != nil {
		if isS3PreconditionFailed(err) {
			return jaydbStorage.ErrVersionMismatch
		}
		if isS3NotFound(err) {
			return jaydbStorage.ErrNotFound
		}
		return fmt.Errorf("s3 delete %q: %w", key, err)
	}

	return nil
}

func (d *AWSS3Driver) List(ctx context.Context, prefix string, opts jaydbStorage.ListOptions) ([]*jaydbStorage.KeyMeta, string, error) {
	input := &s3.ListObjectsV2Input{
		Bucket: aws.String(d.bucket),
	}
	if prefix != "" {
		input.Prefix = aws.String(prefix)
	}
	if opts.Limit > 0 {
		input.MaxKeys = aws.Int32(int32(opts.Limit))
	}
	if opts.Cursor != "" {
		input.ContinuationToken = aws.String(opts.Cursor)
	}
	if opts.Delimiter != "" {
		input.Delimiter = aws.String(opts.Delimiter)
	}

	out, err := d.client.ListObjectsV2(ctx, input)
	if err != nil {
		return nil, "", fmt.Errorf("s3 list %q: %w", prefix, err)
	}

	var metas []*jaydbStorage.KeyMeta
	for _, obj := range out.Contents {
		if obj.Key == nil {
			continue
		}
		etag := ""
		if obj.ETag != nil {
			etag = fmt.Sprintf(`"%s"`, strings.Trim(*obj.ETag, `"`))
		}
		modTime := time.Now()
		if obj.LastModified != nil {
			modTime = *obj.LastModified
		}
		var size int64
		if obj.Size != nil {
			size = *obj.Size
		}
		metas = append(metas, &jaydbStorage.KeyMeta{
			Key:     *obj.Key,
			Size:    size,
			ETag:    etag,
			ModTime: modTime,
		})
	}

	nextCursor := ""
	if out.NextContinuationToken != nil {
		nextCursor = *out.NextContinuationToken
	}

	return metas, nextCursor, nil
}

func (d *AWSS3Driver) Close() error {
	return nil
}

func isS3NotFound(err error) bool {
	if err == nil {
		return false
	}
	var nsk *types.NoSuchKey
	if errors.As(err, &nsk) {
		return true
	}
	return containsAny(err.Error(), "NoSuchKey", "404", "NotFound")
}

func isS3PreconditionFailed(err error) bool {
	if err == nil {
		return false
	}
	return containsAny(err.Error(), "PreconditionFailed", "412")
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
