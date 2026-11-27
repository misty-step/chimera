package inlet

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Identity is what a verified edge token says about its bearer.
type Identity struct {
	Email   string // lower-cased
	Subject string
}

// ErrToken is the single error Verify returns for any token it does not
// accept. It never says why: the caller treats every failure alike, so the
// endpoint cannot be used as an oracle.
var ErrToken = errors.New("token not accepted")

// KeySource resolves a token's "kid" to a public key.
type KeySource interface {
	// Key returns the keys that may have signed a token with this kid. An
	// empty kid asks for the set's only key.
	Key(ctx context.Context, kid string) ([]jwk, error)
}

// jwk is one parsed public key of a JWKS.
type jwk struct {
	kid, alg string
	key      crypto.PublicKey
}

// KeySet is a parsed JWKS.
type KeySet struct{ keys []jwk }

// Len reports how many usable signature keys the set holds.
func (s *KeySet) Len() int { return len(s.keys) }

// Key implements KeySource.
func (s *KeySet) Key(_ context.Context, kid string) ([]jwk, error) {
	if kid == "" {
		if len(s.keys) == 1 {
			return s.keys, nil
		}
		return nil, ErrToken
	}
	var out []jwk
	for _, k := range s.keys {
		if k.kid == kid {
			out = append(out, k)
		}
	}
	if len(out) == 0 {
		return nil, ErrToken
	}
	return out, nil
}

func b64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// ParseJWKS parses a JSON Web Key Set, keeping RSA (≥ 2048 bit), P-256, and
// Ed25519 signature keys. Keys of any other kind are ignored; a set with no
// usable key is an error.
func ParseJWKS(raw []byte) (*KeySet, error) {
	var doc struct {
		Keys []struct {
			Kty, Kid, Use, Alg, Crv string
			N, E, X, Y              string
		} `json:"keys"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("jwks: malformed")
	}
	set := &KeySet{}
	for _, k := range doc.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		var pub crypto.PublicKey
		switch {
		case k.Kty == "RSA":
			n, err1 := b64(k.N)
			e, err2 := b64(k.E)
			if err1 != nil || err2 != nil || len(e) == 0 || len(e) > 4 {
				continue
			}
			exp := 0
			for _, b := range e {
				exp = exp<<8 | int(b)
			}
			key := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exp}
			if key.N.BitLen() < 2048 || exp < 3 || exp%2 == 0 {
				continue
			}
			pub = key
		case k.Kty == "EC" && k.Crv == "P-256":
			x, err1 := b64(k.X)
			y, err2 := b64(k.Y)
			if err1 != nil || err2 != nil || len(x) != 32 || len(y) != 32 {
				continue
			}
			// ecdh validates that the point is on the curve.
			if _, err := ecdh.P256().NewPublicKey(append(append([]byte{4}, x...), y...)); err != nil {
				continue
			}
			pub = &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		case k.Kty == "OKP" && k.Crv == "Ed25519":
			x, err := b64(k.X)
			if err != nil || len(x) != ed25519.PublicKeySize {
				continue
			}
			pub = ed25519.PublicKey(x)
		default:
			continue
		}
		set.keys = append(set.keys, jwk{kid: k.Kid, alg: k.Alg, key: pub})
	}
	if len(set.keys) == 0 {
		return nil, fmt.Errorf("jwks: no usable signature key")
	}
	return set, nil
}

// RemoteKeys is a JWKS fetched over HTTPS and kept in memory. It is loaded
// once, before the inlet serves anything, and refreshed by a background
// ticker. Verifying a token only ever reads the cached set: no request,
// whatever "kid" it claims, can make the inlet call the identity provider
// (PRODUCT.md §2.6: unauthenticated input triggers no compute beyond the
// append).
type RemoteKeys struct {
	URL     string
	Client  *http.Client     // nil means http.DefaultTransport with a 10s timeout
	Now     func() time.Time // nil means time.Now
	Refresh time.Duration    // 0 means DefaultJWKSRefresh
	MaxAge  time.Duration    // 0 means DefaultJWKSMaxAge
	Log     func(format string, args ...any)

	mu     sync.RWMutex
	set    *KeySet
	loaded time.Time

	startOnce, stopOnce sync.Once
	stop                chan struct{}
	done                chan struct{}
}

// JWKS refresh policy.
const (
	DefaultJWKSRefresh = 5 * time.Minute
	// DefaultJWKSMaxAge is how long a set is trusted without one successful
	// refresh. Beyond it the set is dropped and nobody is an owner until the
	// identity provider answers again: a key it has withdrawn is not trusted
	// forever because the refresh keeps failing.
	DefaultJWKSMaxAge = 24 * time.Hour
	jwksTimeout       = 10 * time.Second
	maxJWKSBytes      = 1 << 20
)

func (r *RemoteKeys) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// jwksURL refuses a JWKS location that could be read or rewritten in
// transit: https only, except on loopback.
func jwksURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil {
		return nil, fmt.Errorf("jwks: invalid url")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && loopbackHost(u.Hostname())) {
		return nil, fmt.Errorf("jwks: url must be https")
	}
	return u, nil
}

// Load fetches the JWKS once and replaces the cached set on success. It
// never holds the lock across the network.
func (r *RemoteKeys) Load(ctx context.Context) error {
	u, err := jwksURL(r.URL)
	if err != nil {
		return err
	}
	client := &http.Client{}
	if r.Client != nil {
		*client = *r.Client
	}
	// A redirect may not leave the host the operator configured.
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 || req.URL.Host != u.Host || req.URL.Scheme != u.Scheme {
			return fmt.Errorf("redirect refused")
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, jwksTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return fmt.Errorf("jwks: invalid url")
	}
	req.Header.Set("Accept", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("jwks: no answer")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks: status %d", res.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxJWKSBytes+1))
	if err != nil {
		return fmt.Errorf("jwks: unreadable")
	}
	if len(raw) > maxJWKSBytes {
		return fmt.Errorf("jwks: larger than %d bytes", maxJWKSBytes)
	}
	set, err := ParseJWKS(raw)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.set, r.loaded = set, r.now()
	r.mu.Unlock()
	return nil
}

// Start refreshes the set in the background until Close. A failed refresh
// keeps the set it has; Key stops trusting a set older than MaxAge.
func (r *RemoteKeys) Start() {
	r.startOnce.Do(func() {
		r.stop, r.done = make(chan struct{}), make(chan struct{})
		every := r.Refresh
		if every <= 0 {
			every = DefaultJWKSRefresh
		}
		go func() {
			defer close(r.done)
			for {
				// Jitter of ±10% keeps a fleet from refreshing in step.
				wait := every - every/10 + time.Duration(rand.Int63n(int64(every/5)+1))
				timer := time.NewTimer(wait)
				select {
				case <-r.stop:
					timer.Stop()
					return
				case <-timer.C:
				}
				// Detached from every request: nobody's disconnect can cancel it.
				if err := r.Load(context.Background()); err != nil && r.Log != nil {
					r.Log("inlet: jwks refresh failed: %v", err)
				}
			}
		}()
	})
}

// Close stops the background refresh.
func (r *RemoteKeys) Close() {
	r.stopOnce.Do(func() {
		if r.stop != nil {
			close(r.stop)
			<-r.done
		}
	})
}

// Key implements KeySource from the cached set alone.
func (r *RemoteKeys) Key(ctx context.Context, kid string) ([]jwk, error) {
	maxAge := r.MaxAge
	if maxAge <= 0 {
		maxAge = DefaultJWKSMaxAge
	}
	r.mu.RLock()
	set, loaded := r.set, r.loaded
	r.mu.RUnlock()
	if set == nil || r.now().Sub(loaded) > maxAge {
		return nil, ErrToken
	}
	return set.Key(ctx, kid)
}

// Verifier checks an edge-issued JWT/OIDC token (PRODUCT.md §2.6): compact
// JWS signed with RS256, ES256, or EdDSA by a key of the configured issuer.
type Verifier struct {
	Issuer   string // required "iss"
	Audience string // required member of "aud"; a verifier without one accepts nothing
	Keys     KeySource
	// EmailVerifiedIfPresent accepts a token without an email_verified claim
	// (edges that assert the email by issuance carry none). The default is to
	// require email_verified: true. A claim that is present and not true
	// always refuses.
	EmailVerifiedIfPresent bool
	Now                    func() time.Time // nil means time.Now
}

// leeway tolerates clock skew on nbf and iat.
const leeway = 60 * time.Second

// maxToken bounds the work an unverified token can cause.
const maxToken = 8 << 10

type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if json.Unmarshal(b, &one) == nil {
		*a = []string{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

// Verify returns the identity a token proves, or ErrToken. The order is
// fixed: algorithm allow-list, key, signature, and only then the claims.
func (v *Verifier) Verify(ctx context.Context, token string) (Identity, error) {
	if v.Issuer == "" || v.Audience == "" || v.Keys == nil || len(token) > maxToken {
		return Identity{}, ErrToken
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Identity{}, ErrToken
	}
	rawHeader, err := b64(parts[0])
	if err != nil {
		return Identity{}, ErrToken
	}
	var header struct {
		Alg  string          `json:"alg"`
		Kid  string          `json:"kid"`
		Crit json.RawMessage `json:"crit"`
	}
	if json.Unmarshal(rawHeader, &header) != nil || header.Crit != nil {
		return Identity{}, ErrToken
	}
	switch header.Alg {
	case "RS256", "ES256", "EdDSA":
	default: // "none", HS*, and everything else
		return Identity{}, ErrToken
	}
	sig, err := b64(parts[2])
	if err != nil || len(sig) == 0 {
		return Identity{}, ErrToken
	}
	rawClaims, err := b64(parts[1])
	if err != nil {
		return Identity{}, ErrToken
	}
	keys, err := v.Keys.Key(ctx, header.Kid)
	if err != nil {
		return Identity{}, ErrToken
	}
	signed := []byte(parts[0] + "." + parts[1])
	ok := false
	for _, k := range keys {
		if k.alg != "" && k.alg != header.Alg {
			continue
		}
		if verifySignature(header.Alg, k.key, signed, sig) {
			ok = true
			break
		}
	}
	if !ok {
		return Identity{}, ErrToken
	}

	var claims struct {
		Iss           string   `json:"iss"`
		Aud           audience `json:"aud"`
		Exp           *float64 `json:"exp"`
		Nbf           *float64 `json:"nbf"`
		Iat           *float64 `json:"iat"`
		Sub           string   `json:"sub"`
		Email         string   `json:"email"`
		EmailVerified any      `json:"email_verified"`
	}
	dec := json.NewDecoder(bytes.NewReader(rawClaims))
	if dec.Decode(&claims) != nil {
		return Identity{}, ErrToken
	}
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	unix := func(f float64) time.Time { return time.Unix(int64(f), 0) }
	email, emailOK := asciiEmail(claims.Email)
	verified := claims.EmailVerified == true || (claims.EmailVerified == nil && v.EmailVerifiedIfPresent)
	switch {
	case claims.Iss != v.Issuer:
	case !contains(claims.Aud, v.Audience):
	case claims.Exp == nil || !now.Before(unix(*claims.Exp)):
	case claims.Nbf != nil && now.Add(leeway).Before(unix(*claims.Nbf)):
	case claims.Iat != nil && now.Add(leeway).Before(unix(*claims.Iat)):
	case !emailOK:
	case !verified:
	default:
		return Identity{Email: email, Subject: claims.Sub}, nil
	}
	return Identity{}, ErrToken
}

// asciiEmail returns the email lower-cased, or false. Only printable ASCII
// without spaces is an email here, and only ASCII letters are folded: Unicode
// case folding maps look-alikes (the Kelvin sign, a dotted capital I) onto
// plain letters, and an owner list must never be matched by a look-alike.
// Nothing is trimmed: a claim is taken as the issuer wrote it.
func asciiEmail(s string) (string, bool) {
	if s == "" || len(s) > 254 || strings.Count(s, "@") != 1 || strings.HasPrefix(s, "@") || strings.HasSuffix(s, "@") {
		return "", false
	}
	b := []byte(s)
	for i, c := range b {
		switch {
		case c <= ' ' || c >= 0x7f:
			return "", false
		case c >= 'A' && c <= 'Z':
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b), true
}

// verifySignature checks sig over signed. The key's type must be the one the
// algorithm calls for, so a key can never be used under another algorithm.
func verifySignature(alg string, key crypto.PublicKey, signed, sig []byte) bool {
	switch alg {
	case "RS256":
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return false
		}
		sum := sha256.Sum256(signed)
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig) == nil
	case "ES256":
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok || len(sig) != 64 {
			return false
		}
		sum := sha256.Sum256(signed)
		return ecdsa.Verify(pub, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
	case "EdDSA":
		pub, ok := key.(ed25519.PublicKey)
		return ok && ed25519.Verify(pub, signed, sig)
	}
	return false
}

func contains(vs []string, want string) bool {
	for _, v := range vs {
		if v == want {
			return true
		}
	}
	return false
}
