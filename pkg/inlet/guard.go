package inlet

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

// InFence reports whether a path may appear in the Folio-only pull request:
// exactly PRODUCT.md or DESIGN.md, or a file under folio/ (PRODUCT.md §2.6).
//
// The fence is an allow-list, not a clean-up: every segment must be made of
// ASCII letters, digits, '.', '_' and '-' only and must not start with a dot.
// That leaves no room for "..", an empty segment, a backslash, a control or
// format character, a glob metacharacter, a space, or any spelling of ".git".
func InFence(p string) bool {
	if p == "" || len(p) > 512 {
		return false
	}
	segs := strings.Split(p, "/")
	for _, s := range segs {
		if s == "" || s[0] == '.' {
			return false
		}
		for i := 0; i < len(s); i++ {
			c := s[i]
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
			default:
				return false
			}
		}
	}
	if len(segs) == 1 {
		return p == "PRODUCT.md" || p == "DESIGN.md"
	}
	return segs[0] == "folio"
}

// origin is a normalized web origin. port is always the effective port.
type origin struct{ scheme, host, port string }

func defaultPort(scheme string) string {
	switch scheme {
	case "http":
		return "80"
	case "https":
		return "443"
	}
	return ""
}

// parseOrigin reads the origin of a URL or an Origin header value. The host
// loses its brackets, its trailing dot, and its case; the port is filled in
// from the scheme.
func parseOrigin(raw string) (origin, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Hostname() == "" || u.Opaque != "" {
		return origin{}, false
	}
	o := origin{scheme: strings.ToLower(u.Scheme), host: strings.ToLower(strings.TrimSuffix(u.Hostname(), ".")), port: u.Port()}
	if o.port == "" {
		o.port = defaultPort(o.scheme)
	}
	return o, true
}

// parseAllowedOrigin reads one AllowedOrigins entry: an exact origin,
// "scheme://host[:port]", nothing more. Wildcards are refused: a page that
// may post with the owner's session is named, never matched.
func parseAllowedOrigin(entry string) (origin, error) {
	if strings.Contains(entry, "*") {
		return origin{}, fmt.Errorf("allowed origin must be exact; wildcards are refused")
	}
	u, err := url.Parse(entry)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return origin{}, fmt.Errorf("allowed origin must be scheme://host[:port]")
	}
	o, _ := parseOrigin(entry)
	return o, nil
}

// previewPattern is one PreviewOrigins entry: "scheme://host[:port]" whose
// host may contain "*" wildcards ("https://*.preview.example.com"). A pattern
// without a port matches any port.
type previewPattern struct{ scheme, host, port string }

func parsePreviewPattern(entry string) (previewPattern, error) {
	scheme, rest, ok := strings.Cut(strings.ToLower(entry), "://")
	if !ok || (scheme != "http" && scheme != "https") {
		return previewPattern{}, fmt.Errorf("preview origin must start with http:// or https://")
	}
	rest = strings.TrimSuffix(rest, "/")
	if rest == "" || strings.ContainsAny(rest, "/?#@ ") {
		return previewPattern{}, fmt.Errorf("preview origin must be scheme://host[:port], without a path")
	}
	p := previewPattern{scheme: scheme}
	if strings.HasPrefix(rest, "[") { // bracketed IPv6 literal
		end := strings.IndexByte(rest, ']')
		if end < 0 {
			return previewPattern{}, fmt.Errorf("preview origin has an unclosed bracket")
		}
		p.host, rest = rest[1:end], rest[end+1:]
		if rest != "" {
			if !strings.HasPrefix(rest, ":") {
				return previewPattern{}, fmt.Errorf("preview origin is malformed after the bracket")
			}
			p.port = rest[1:]
		}
	} else if h, port, found := strings.Cut(rest, ":"); found {
		p.host, p.port = h, port
	} else {
		p.host = rest
	}
	p.host = strings.TrimSuffix(p.host, ".")
	if p.host == "" {
		return previewPattern{}, fmt.Errorf("preview origin names no host")
	}
	for _, c := range p.port {
		if c < '0' || c > '9' {
			return previewPattern{}, fmt.Errorf("preview origin port must be a number; only the host may use a wildcard")
		}
	}
	return p, nil
}

func (p previewPattern) match(o origin) bool {
	if p.scheme != o.scheme || (p.port != "" && p.port != o.port) {
		return false
	}
	return wildcard(p.host, o.host)
}

// wildcard matches s against a pattern in which "*" stands for any run of
// characters, including none.
func wildcard(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == s
	}
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	last := parts[len(parts)-1]
	for _, mid := range parts[1 : len(parts)-1] {
		i := strings.Index(s, mid)
		if i < 0 {
			return false
		}
		s = s[i+len(mid):]
	}
	return strings.HasSuffix(s, last)
}

func matchPreview(patterns []previewPattern, raw string) bool {
	if raw == "" {
		return false
	}
	o, ok := parseOrigin(raw)
	if !ok {
		return false
	}
	for _, p := range patterns {
		if p.match(o) {
			return true
		}
	}
	return false
}

// sameOrigin reports whether an Origin header names the host the request
// itself was sent to.
func sameOrigin(o origin, host string) bool {
	h, port := host, ""
	if hh, pp, err := net.SplitHostPort(host); err == nil {
		h, port = hh, pp
	}
	h = strings.ToLower(strings.TrimSuffix(strings.Trim(h, "[]"), "."))
	if port == "" {
		port = defaultPort(o.scheme)
	}
	return h != "" && h == o.host && port == o.port
}

// isBot reports whether an actor name is a bot: listed, or carrying the
// "[bot]" suffix forges give machine accounts.
func isBot(bots []string, actor string) bool {
	actor = strings.ToLower(strings.TrimSpace(actor))
	if actor == "" {
		return false
	}
	if strings.HasSuffix(actor, "[bot]") || strings.HasSuffix(strings.SplitN(actor, "@", 2)[0], "[bot]") {
		return true
	}
	for _, b := range bots {
		if strings.ToLower(strings.TrimSpace(b)) == actor {
			return true
		}
	}
	return false
}

// clientAddr is the address the triage rate limit keys on. With a trusted
// header it is the RIGHTMOST address there — the hop the edge itself
// appended; everything to its left is whatever the client chose to send. It
// falls back to the connection's address. IPv6 is masked to its /64, the
// unit one subscriber controls. The zero Addr is the bucket of every request
// whose address cannot be read.
func clientAddr(r *http.Request, header string) netip.Addr {
	var addr netip.Addr
	if header != "" {
		vals := strings.Split(strings.Join(r.Header.Values(header), ","), ",")
		for i := len(vals) - 1; i >= 0; i-- {
			if v := strings.TrimSpace(vals[i]); v != "" {
				if len(v) <= 64 {
					addr = parseAddr(v)
				}
				break // only the rightmost element is trusted
			}
		}
	}
	if !addr.IsValid() {
		addr = parseAddr(r.RemoteAddr)
	}
	if !addr.IsValid() {
		return netip.Addr{}
	}
	addr = addr.Unmap().WithZone("")
	if addr.Is6() {
		if p, err := addr.Prefix(64); err == nil {
			addr = p.Addr()
		}
	}
	return addr
}

func parseAddr(s string) netip.Addr {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr()
	}
	if a, err := netip.ParseAddr(strings.Trim(s, "[]")); err == nil {
		return a
	}
	return netip.Addr{}
}

// maxClients bounds the limiter's memory. Beyond it, clients not yet tracked
// share one overflow bucket: they are slowed together, never refused outright
// and never remembered one by one.
const maxClients = 4096

// limiter is a token bucket per client plus one global bucket ten times as
// deep. It is the only thing between the open internet and the triage inbox.
type limiter struct {
	perMinute int
	mu        sync.Mutex
	clients   map[netip.Addr]*bucket
	overflow  bucket
	global    bucket
}

type bucket struct {
	tokens float64
	seen   time.Time
}

func newLimiter(perMinute int) *limiter {
	return &limiter{perMinute: perMinute, clients: map[netip.Addr]*bucket{}}
}

func (b *bucket) refill(now time.Time, capacity float64) {
	if b.seen.IsZero() {
		b.tokens = capacity
	} else if d := now.Sub(b.seen); d > 0 {
		b.tokens += d.Minutes() * capacity
		if b.tokens > capacity {
			b.tokens = capacity
		}
	}
	b.seen = now
}

func (b *bucket) take(now time.Time, capacity float64) bool {
	b.refill(now, capacity)
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// allow spends one token of the client's bucket and one of the global one.
// The global bucket is consulted first, so a flood that it already refuses
// cannot even make the limiter remember a new client.
func (l *limiter) allow(client netip.Addr, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	capacity := float64(l.perMinute)
	l.global.refill(now, capacity*10)
	if l.global.tokens < 1 {
		return false
	}
	b, ok := l.clients[client]
	if !ok {
		if len(l.clients) >= maxClients { // forget clients whose bucket has refilled
			for k, c := range l.clients {
				if now.Sub(c.seen) >= time.Minute {
					delete(l.clients, k)
				}
			}
		}
		if len(l.clients) >= maxClients {
			b = &l.overflow
		} else {
			b = &bucket{}
			l.clients[client] = b
		}
	}
	if !b.take(now, capacity) {
		return false
	}
	l.global.tokens--
	return true
}
