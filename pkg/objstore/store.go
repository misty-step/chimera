// Package objstore is Chimera's evidence store surface: write-once objects in
// an S3-compatible bucket (SigV4, no cloud SDK), a local directory with the
// same semantics, and a loopback fake that verifies signatures for tests.
package objstore

import (
	"context"
	"errors"
	"fmt"
	"net/url"
)

// ErrNotFound reports a missing object.
var ErrNotFound = errors.New("object not found")

// ErrUnavailable marks a request whose outcome is unknown: the store did not
// answer, or answered with a transient status. The request may be retried.
var ErrUnavailable = errors.New("store unavailable")

// UnavailableError is an ErrUnavailable with its operation. It never carries
// the request, so no header or credential can leak through it.
type UnavailableError struct {
	Op, Key string
	Status  int // 0 for a transport failure
}

func (e *UnavailableError) Error() string {
	if e.Status == 0 {
		return fmt.Sprintf("%s %s: no answer from the store", e.Op, e.Key)
	}
	return fmt.Sprintf("%s %s: status %d", e.Op, e.Key, e.Status)
}

// Is reports ErrUnavailable.
func (e *UnavailableError) Is(target error) bool { return target == ErrUnavailable }

// Store is the whole object-store surface Chimera needs.
type Store interface {
	// Put writes key only if it does not exist (If-None-Match: *). created is
	// false when the key was already present; the caller must read back and
	// compare before treating that as success.
	Put(ctx context.Context, key string, body []byte) (created bool, err error)
	// Get returns the object or ErrNotFound.
	Get(ctx context.Context, key string) ([]byte, error)
	// List returns every key with the given prefix, sorted.
	List(ctx context.Context, prefix string) ([]string, error)
}

// Open returns the Store for an endpoint: file:///abs/dir is a local
// directory store; http(s) is an S3-compatible bucket.
func Open(endpoint, bucket, region string, cr Credentials) (Store, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("store.endpoint not configured")
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("store.endpoint is not a URL")
	}
	switch u.Scheme {
	case "file":
		return NewDir(u.Path), nil
	case "http", "https":
		if bucket == "" {
			return nil, fmt.Errorf("store.bucket not configured")
		}
		if cr.AccessKeyID == "" || cr.SecretAccessKey == "" {
			return nil, fmt.Errorf("store credentials not set (CHIMERA_S3_ACCESS_KEY_ID, CHIMERA_S3_SECRET_ACCESS_KEY)")
		}
		if region == "" {
			region = "auto"
		}
		return &S3{Endpoint: endpoint, Bucket: bucket, Region: region, Credentials: cr}, nil
	}
	return nil, fmt.Errorf("store.endpoint scheme %q not supported", u.Scheme)
}
