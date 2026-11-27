package inlet

import (
	"net/url"
	"path"
	"strings"
	"sync"
	"time"
)

// InFence reports whether a path may appear in the Folio-only pull request:
// exactly PRODUCT.md or DESIGN.md, or a file under folio/ (PRODUCT.md §2.6).
// The path must already be clean and relative: no "..", no ".", no empty
// segment, no backslash, no leading slash, and no ".git" segment.
func InFence(p string) bool {
	if p == "" || strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\\\x00\n\r") || path.Clean(p) != p {
		return false
	}
	segs := strings.Split(p, "/")
	for _, s := range segs {
		if s == "" || s == "." || s == ".." || strings.EqualFold(s, ".git") || strings.TrimSpace(s) != s {
			return false
		}
	}
	if len(segs) == 1 {
		return p == "PRODUCT.md" || p == "DESIGN.md"
	}
	return segs[0] == "folio"
}

// origin is a normalized web origin.
type origin struct{ scheme, host, port string }

func parseOrigin(raw string) (origin, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Hostname() == "" {
		return origin{}, false
	}
	o := origin{scheme: strings.ToLower(u.Scheme), host: strings.ToLower(strings.TrimSuffix(u.Hostname(), ".")), port: u.Port()}
	if (o.scheme == "http" && o.port == "80") || (o.scheme == "https" && o.port == "443") {
		o.port = ""
	}
	return o, true
}

// matchOrigin matches an origin against a pattern "scheme://host[:port]"
// whose host may contain "*" wildcards ("https://*.preview.example.com"). A
// pattern without a port matches any port; without a scheme, any scheme.
func matchOrigin(pattern, raw string) bool {
	o, ok := parseOrigin(raw)
	if !ok {
		return false
	}
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	scheme, rest, hasScheme := strings.Cut(pattern, "://")
	if !hasScheme {
		scheme, rest = "", pattern
	}
	rest = strings.TrimSuffix(rest, "/")
	host, port := rest, ""
	if i := strings.LastIndexByte(rest, ':'); i >= 0 && !strings.Contains(rest[i:], "]") {
		host, port = rest[:i], rest[i+1:]
	}
	if host == "" || (scheme != "" && scheme != o.scheme) || (port != "" && port != "*" && port != o.port) {
		return false
	}
	return wildcard(host, o.host)
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

func matchAnyOrigin(patterns []string, raw string) bool {
	if raw == "" {
		return false
	}
	for _, p := range patterns {
		if matchOrigin(p, raw) {
			return true
		}
	}
	return false
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

// limiter is a token bucket per client plus one global bucket ten times as
// deep. It is the only thing between the open internet and the triage inbox.
type limiter struct {
	perMinute int
	mu        sync.Mutex
	clients   map[string]*bucket
	global    bucket
}

type bucket struct {
	tokens float64
	seen   time.Time
}

func newLimiter(perMinute int) *limiter {
	return &limiter{perMinute: perMinute, clients: map[string]*bucket{}}
}

func (b *bucket) take(now time.Time, capacity float64) bool {
	if b.seen.IsZero() {
		b.tokens = capacity
	} else if d := now.Sub(b.seen); d > 0 {
		b.tokens += d.Minutes() * capacity
		if b.tokens > capacity {
			b.tokens = capacity
		}
	}
	b.seen = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// allow spends one token of the client's bucket and one of the global one.
func (l *limiter) allow(client string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	capacity := float64(l.perMinute)
	b, ok := l.clients[client]
	if !ok {
		if len(l.clients) >= 4096 { // forget clients whose bucket has refilled
			for k, c := range l.clients {
				if now.Sub(c.seen) >= time.Minute {
					delete(l.clients, k)
				}
			}
		}
		if len(l.clients) >= 8192 {
			return false // more distinct clients than can be tracked: refuse
		}
		b = &bucket{}
		l.clients[client] = b
	}
	if !b.take(now, capacity) {
		return false
	}
	return l.global.take(now, capacity*10)
}
