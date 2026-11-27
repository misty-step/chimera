package objstore

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Credentials sign requests. They come only from the environment.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

const (
	sigAlgorithm  = "AWS4-HMAC-SHA256"
	amzDateFormat = "20060102T150405Z"
	// EmptySHA256 is the SHA-256 of the empty string.
	EmptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// Sign adds AWS Signature Version 4 headers to r. Every header already on the
// request, plus Host and X-Amz-Date, is signed. payloadHash is the lowercase
// hex SHA-256 of the body.
func Sign(r *http.Request, payloadHash string, cr Credentials, region, service string, now time.Time) {
	now = now.UTC()
	r.Header.Set("X-Amz-Date", now.Format(amzDateFormat))
	if cr.SessionToken != "" {
		r.Header.Set("X-Amz-Security-Token", cr.SessionToken)
	}
	names := []string{"host"}
	for k := range r.Header {
		names = append(names, strings.ToLower(k))
	}
	sort.Strings(names)
	scope := now.Format("20060102") + "/" + region + "/" + service + "/aws4_request"
	sig := signature(r, names, payloadHash, cr.SecretAccessKey, scope, now)
	r.Header.Set("Authorization", fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		sigAlgorithm, cr.AccessKeyID, scope, strings.Join(names, ";"), sig))
}

func signature(r *http.Request, signed []string, payloadHash, secret, scope string, now time.Time) string {
	creq := canonicalRequest(r, signed, payloadHash)
	sum := sha256.Sum256([]byte(creq))
	toSign := sigAlgorithm + "\n" + now.Format(amzDateFormat) + "\n" + scope + "\n" + hex.EncodeToString(sum[:])
	parts := strings.Split(scope, "/") // date/region/service/aws4_request
	k := hmacSHA256([]byte("AWS4"+secret), parts[0])
	for _, p := range parts[1:] {
		k = hmacSHA256(k, p)
	}
	return hex.EncodeToString(hmacSHA256(k, toSign))
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func canonicalRequest(r *http.Request, signed []string, payloadHash string) string {
	var b strings.Builder
	b.WriteString(r.Method + "\n")
	b.WriteString(canonicalPath(r.URL) + "\n")
	b.WriteString(canonicalQuery(r.URL.Query()) + "\n")
	for _, name := range signed {
		var v string
		if name == "host" {
			v = r.Host
			if v == "" {
				v = r.URL.Host
			}
		} else {
			v = strings.Join(r.Header.Values(name), ",")
		}
		b.WriteString(name + ":" + strings.Join(strings.Fields(v), " ") + "\n")
	}
	b.WriteString("\n" + strings.Join(signed, ";") + "\n" + payloadHash)
	return b.String()
}

// canonicalPath URI-encodes each path segment once (the S3 rule).
func canonicalPath(u *url.URL) string {
	p := u.Path
	if p == "" {
		return "/"
	}
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = uriEncode(s)
	}
	return strings.Join(segs, "/")
}

func canonicalQuery(q url.Values) string {
	var pairs []string
	for k, vs := range q {
		for _, v := range vs {
			pairs = append(pairs, uriEncode(k)+"="+uriEncode(v))
		}
	}
	sort.Strings(pairs)
	return strings.Join(pairs, "&")
}

// uriEncode percent-encodes everything but RFC 3986 unreserved characters.
func uriEncode(s string) string {
	const hexd = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if ('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z') || ('0' <= c && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexd[c>>4])
		b.WriteByte(hexd[c&15])
	}
	return b.String()
}

// VerifySignature checks r's SigV4 Authorization header against the secret
// returned by lookup. It is what the loopback fake uses to reject unsigned or
// mis-signed requests. bodyHash is the SHA-256 of the body actually received.
func VerifySignature(r *http.Request, bodyHash string, lookup func(accessKeyID string) (secret string, ok bool)) error {
	auth := r.Header.Get("Authorization")
	rest, ok := strings.CutPrefix(auth, sigAlgorithm+" ")
	if !ok {
		return fmt.Errorf("missing %s authorization", sigAlgorithm)
	}
	fields := map[string]string{}
	for _, part := range strings.Split(rest, ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
		fields[k] = v
	}
	cred := strings.SplitN(fields["Credential"], "/", 2)
	if len(cred) != 2 || fields["SignedHeaders"] == "" || fields["Signature"] == "" {
		return fmt.Errorf("malformed authorization")
	}
	secret, ok := lookup(cred[0])
	if !ok {
		return fmt.Errorf("unknown access key")
	}
	scope := cred[1]
	if sp := strings.Split(scope, "/"); len(sp) != 4 || sp[3] != "aws4_request" {
		return fmt.Errorf("malformed credential scope")
	}
	when, err := time.Parse(amzDateFormat, r.Header.Get("X-Amz-Date"))
	if err != nil || !strings.HasPrefix(scope, when.Format("20060102")+"/") {
		return fmt.Errorf("bad x-amz-date")
	}
	signed := strings.Split(fields["SignedHeaders"], ";")
	hasHost := false
	for _, h := range signed {
		hasHost = hasHost || h == "host"
	}
	if !hasHost {
		return fmt.Errorf("host header not signed")
	}
	payload := r.Header.Get("X-Amz-Content-Sha256")
	if payload == "" {
		payload = bodyHash
	}
	if payload != bodyHash {
		return fmt.Errorf("x-amz-content-sha256 does not match the body")
	}
	want := signature(r, signed, payload, secret, scope, when)
	if subtle.ConstantTimeCompare([]byte(want), []byte(fields["Signature"])) != 1 {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

func shaHex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
