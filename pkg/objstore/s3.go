package objstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// S3 is a minimal path-style S3 client: conditional PUT, GET, and
// ListObjectsV2, each signed with SigV4.
type S3 struct {
	Endpoint    string
	Bucket      string
	Region      string
	Credentials Credentials
	Client      *http.Client     // nil means a client with a 60s timeout
	Now         func() time.Time // nil means time.Now
}

var defaultClient = &http.Client{Timeout: 60 * time.Second}

func (s *S3) do(ctx context.Context, method, key string, query url.Values, body []byte, hdr map[string]string) (int, []byte, error) {
	u, err := url.Parse(strings.TrimRight(s.Endpoint, "/") + "/" + s.Bucket)
	if err != nil {
		return 0, nil, fmt.Errorf("bad endpoint")
	}
	if key != "" {
		u.Path += "/" + key
	}
	u.RawPath = canonicalPath(u)
	u.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return 0, nil, fmt.Errorf("bad request")
	}
	sum := sha256.Sum256(body)
	hash := hex.EncodeToString(sum[:])
	req.Header.Set("X-Amz-Content-Sha256", hash)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	Sign(req, hash, s.Credentials, s.Region, "s3", now())
	client := s.Client
	if client == nil {
		client = defaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		// Never include the request (and so its headers) in the error.
		return 0, nil, fmt.Errorf("%s %s: transport error", method, key)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, fmt.Errorf("%s %s: short read", method, key)
	}
	return resp.StatusCode, data, nil
}

// Put implements Store with If-None-Match: *.
func (s *S3) Put(ctx context.Context, key string, body []byte) (bool, error) {
	for attempt := 0; ; attempt++ {
		code, _, err := s.do(ctx, http.MethodPut, key, nil, body, map[string]string{"If-None-Match": "*"})
		switch {
		case err != nil:
			return false, err
		case code == http.StatusOK || code == http.StatusCreated:
			return true, nil
		case code == http.StatusPreconditionFailed:
			return false, nil
		case code == http.StatusConflict && attempt < 4:
			// A concurrent conditional write is in flight; retry settles to 412.
			select {
			case <-ctx.Done():
				return false, ctx.Err()
			case <-time.After(time.Duration(attempt+1) * 50 * time.Millisecond):
			}
		default:
			return false, fmt.Errorf("PUT %s: status %d", key, code)
		}
	}
}

// Get implements Store.
func (s *S3) Get(ctx context.Context, key string) ([]byte, error) {
	code, data, err := s.do(ctx, http.MethodGet, key, nil, nil, nil)
	switch {
	case err != nil:
		return nil, err
	case code == http.StatusOK:
		return data, nil
	case code == http.StatusNotFound:
		return nil, ErrNotFound
	}
	return nil, fmt.Errorf("GET %s: status %d", key, code)
}

type listResult struct {
	Keys      []string `xml:"Contents>Key"`
	Truncated bool     `xml:"IsTruncated"`
	Next      string   `xml:"NextContinuationToken"`
}

// List implements Store with ListObjectsV2.
func (s *S3) List(ctx context.Context, prefix string) ([]string, error) {
	var keys []string
	token := ""
	for {
		q := url.Values{"list-type": {"2"}, "prefix": {prefix}}
		if token != "" {
			q.Set("continuation-token", token)
		}
		code, data, err := s.do(ctx, http.MethodGet, "", q, nil, nil)
		if err != nil {
			return nil, err
		}
		if code != http.StatusOK {
			return nil, fmt.Errorf("LIST %s: status %d", prefix, code)
		}
		var res listResult
		if err := xml.Unmarshal(data, &res); err != nil {
			return nil, fmt.Errorf("LIST %s: malformed response", prefix)
		}
		keys = append(keys, res.Keys...)
		if !res.Truncated || res.Next == "" {
			break
		}
		token = res.Next
	}
	sort.Strings(keys)
	return keys, nil
}
