package objstore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
)

// Fake is the loopback S3 fake: an http.Handler that stores objects in
// memory, honors If-None-Match: *, and rejects any request whose SigV4
// signature does not verify. Tests serve it on a loopback listener.
type Fake struct {
	accessKeyID, secret string

	mu       sync.Mutex
	objects  map[string][]byte // "bucket/key" → bytes
	requests int               // every request that reached the handler
	rejected int               // requests refused for a bad signature
	writes   map[string]int    // successful creates per "bucket/key"
	// CorruptPut, when set, may return different bytes to store for a key.
	corruptPut func(key string, body []byte) []byte
}

// NewFake returns a fake that accepts requests signed with the given pair.
func NewFake(accessKeyID, secretAccessKey string) *Fake {
	return &Fake{accessKeyID: accessKeyID, secret: secretAccessKey, objects: map[string][]byte{}, writes: map[string]int{}}
}

// CorruptOnPut makes the fake store f(key, body) instead of body.
func (f *Fake) CorruptOnPut(fn func(key string, body []byte) []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.corruptPut = fn
}

// Corrupt flips the first byte of every stored object whose key ends in suffix
// and reports how many it changed.
func (f *Fake) Corrupt(suffix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for k, v := range f.objects {
		if strings.HasSuffix(k, suffix) && len(v) > 0 {
			c := append([]byte{}, v...)
			c[0] ^= 0xff
			f.objects[k] = c
			n++
		}
	}
	return n
}

// Requests reports how many requests reached the fake.
func (f *Fake) Requests() int { f.mu.Lock(); defer f.mu.Unlock(); return f.requests }

// Rejected reports how many requests failed signature verification.
func (f *Fake) Rejected() int { f.mu.Lock(); defer f.mu.Unlock(); return f.rejected }

// Writes returns the number of successful creates per "bucket/key".
func (f *Fake) Writes() map[string]int {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]int, len(f.writes))
	for k, v := range f.writes {
		out[k] = v
	}
	return out
}

// Keys lists stored "bucket/key" names, sorted.
func (f *Fake) Keys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.objects))
	for k := range f.objects {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (f *Fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests++
	if err != nil {
		http.Error(w, "short body", http.StatusBadRequest)
		return
	}
	sum := sha256.Sum256(body)
	if err := VerifySignature(r, hex.EncodeToString(sum[:]), func(id string) (string, bool) {
		return f.secret, id == f.accessKeyID
	}); err != nil {
		f.rejected++
		http.Error(w, "SignatureDoesNotMatch: "+err.Error(), http.StatusForbidden)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/") // bucket/key
	bucket, key, _ := strings.Cut(name, "/")
	switch {
	case r.Method == http.MethodGet && key == "" && r.URL.Query().Get("list-type") == "2":
		prefix := bucket + "/" + r.URL.Query().Get("prefix")
		type contents struct {
			Key string `xml:"Key"`
		}
		res := struct {
			XMLName     xml.Name   `xml:"ListBucketResult"`
			IsTruncated bool       `xml:"IsTruncated"`
			Contents    []contents `xml:"Contents"`
		}{}
		for k := range f.objects {
			if strings.HasPrefix(k, prefix) {
				res.Contents = append(res.Contents, contents{Key: strings.TrimPrefix(k, bucket+"/")})
			}
		}
		sort.Slice(res.Contents, func(i, j int) bool { return res.Contents[i].Key < res.Contents[j].Key })
		w.Header().Set("Content-Type", "application/xml")
		xml.NewEncoder(w).Encode(res)
	case r.Method == http.MethodGet && key != "":
		data, ok := f.objects[name]
		if !ok {
			http.Error(w, "NoSuchKey", http.StatusNotFound)
			return
		}
		w.Write(data)
	case r.Method == http.MethodPut && key != "":
		if _, exists := f.objects[name]; exists && r.Header.Get("If-None-Match") == "*" {
			http.Error(w, "PreconditionFailed", http.StatusPreconditionFailed)
			return
		}
		if f.corruptPut != nil {
			body = f.corruptPut(key, body)
		}
		f.objects[name] = append([]byte{}, body...)
		f.writes[name]++
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "MethodNotAllowed", http.StatusMethodNotAllowed)
	}
}
