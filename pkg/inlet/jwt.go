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
	"net/http"
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

// RemoteKeys fetches a JWKS over HTTP and caches it. An unknown kid triggers
// a re-fetch at most once per minute, so a stream of forged tokens cannot
// turn the inlet into a client of the identity provider.
type RemoteKeys struct {
	URL    string
	Client *http.Client     // nil means a client with a 10s timeout
	Now    func() time.Time // nil means time.Now

	mu      sync.Mutex
	set     *KeySet
	fetched time.Time
}

const jwksRefetch = time.Minute

var jwksClient = &http.Client{Timeout: 10 * time.Second}

func (r *RemoteKeys) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *RemoteKeys) fetch(ctx context.Context) error {
	client := r.Client
	if client == nil {
		client = jwksClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.URL, nil)
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
	raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("jwks: unreadable")
	}
	set, err := ParseJWKS(raw)
	if err != nil {
		return err
	}
	r.set = set
	return nil
}

// Key implements KeySource.
func (r *RemoteKeys) Key(ctx context.Context, kid string) ([]jwk, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.set != nil {
		if keys, err := r.set.Key(ctx, kid); err == nil {
			return keys, nil
		}
	}
	now := r.now()
	if !r.fetched.IsZero() && now.Sub(r.fetched) < jwksRefetch {
		return nil, ErrToken
	}
	r.fetched = now
	if err := r.fetch(ctx); err != nil {
		return nil, ErrToken
	}
	return r.set.Key(ctx, kid)
}

// Verifier checks an edge-issued JWT/OIDC token (PRODUCT.md §2.6): compact
// JWS signed with RS256, ES256, or EdDSA by a key of the configured issuer.
type Verifier struct {
	Issuer   string // required "iss"
	Audience string // required member of "aud"; empty skips the check
	Keys     KeySource
	Now      func() time.Time // nil means time.Now
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
	if v.Issuer == "" || v.Keys == nil || len(token) > maxToken {
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
		EmailVerified *bool    `json:"email_verified"`
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
	switch {
	case claims.Iss != v.Issuer:
	case v.Audience != "" && !contains(claims.Aud, v.Audience):
	case claims.Exp == nil || !now.Before(unix(*claims.Exp)):
	case claims.Nbf != nil && now.Add(leeway).Before(unix(*claims.Nbf)):
	case claims.Iat != nil && now.Add(leeway).Before(unix(*claims.Iat)):
	case strings.TrimSpace(claims.Email) == "" || !strings.Contains(claims.Email, "@"):
	case claims.EmailVerified != nil && !*claims.EmailVerified:
	default:
		return Identity{Email: strings.ToLower(strings.TrimSpace(claims.Email)), Subject: claims.Sub}, nil
	}
	return Identity{}, ErrToken
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
