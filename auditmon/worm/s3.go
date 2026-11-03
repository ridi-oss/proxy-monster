package worm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// S3Config configures an S3-compatible WORM bucket. Endpoint + UsePathStyle target MinIO/on-prem;
type S3Config struct {
	Bucket       string
	Endpoint     string
	Region       string
	UsePathStyle bool
}

type s3Store struct {
	client *s3.Client
	bucket string
}

// NewS3 builds an S3-backed ObjectStore. Credentials/region come from the ambient AWS config
// (LoadDefaultConfig); the monitor's IAM principal is the sole holder of bucket access.
func NewS3(ctx context.Context, cfg S3Config) (ObjectStore, error) {
	var opts []func(*awsconfig.LoadOptions) error
	if cfg.Region != "" {
		opts = append(opts, awsconfig.WithRegion(cfg.Region))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("worm: load aws config: %w", err)
	}
	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		if cfg.Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
			o.UsePathStyle = true
		}
		if cfg.UsePathStyle {
			o.UsePathStyle = true
		}
	})
	return &s3Store{client: client, bucket: cfg.Bucket}, nil
}

func (s *s3Store) Put(key string, body []byte) error {
	in := &s3.PutObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(body),
	}
	if _, err := s.client.PutObject(context.Background(), in); err != nil {
		return fmt.Errorf("worm: put %q: %w", key, err)
	}
	return nil
}

func (s *s3Store) List(prefix string) ([]string, error) {
	var keys []string
	p := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucket),
		Prefix: aws.String(prefix),
	})
	for p.HasMorePages() {
		page, err := p.NextPage(context.Background())
		if err != nil {
			return nil, fmt.Errorf("worm: list %q: %w", prefix, err)
		}
		for _, obj := range page.Contents {
			if obj.Key != nil {
				keys = append(keys, *obj.Key)
			}
		}
	}
	return keys, nil
}

func (s *s3Store) ListObjects(prefix string) ([]ObjectInfo, error) {
	var out []ObjectInfo
	p := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucket),
		Prefix: aws.String(prefix),
	})
	for p.HasMorePages() {
		page, err := p.NextPage(context.Background())
		if err != nil {
			return nil, fmt.Errorf("worm: list %q: %w", prefix, err)
		}
		for _, obj := range page.Contents {
			if obj.Key == nil {
				continue
			}
			out = append(out, ObjectInfo{
				Key:     *obj.Key,
				Version: aws.ToString(obj.ETag) + "@" + aws.ToTime(obj.LastModified).UTC().Format(time.RFC3339Nano),
			})
		}
	}
	return out, nil
}

func (s *s3Store) Get(key string) ([]byte, error) {
	out, err := s.client.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		// Distinguish a genuinely absent object from one that could not be read: a caller deciding whether it
		// is safe to overwrite must never mistake a throttle, an outage, or a denied read for "nothing there".
		var missing *types.NoSuchKey
		var notFound *types.NotFound
		if errors.As(err, &missing) || errors.As(err, &notFound) {
			return nil, fmt.Errorf("worm: get %q: %w", key, ErrNotFound)
		}
		return nil, fmt.Errorf("worm: get %q: %w", key, err)
	}
	defer out.Body.Close()
	body, err := io.ReadAll(out.Body)
	if err != nil {
		return nil, fmt.Errorf("worm: read %q: %w", key, err)
	}
	return body, nil
}
