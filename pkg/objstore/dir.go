package objstore

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// Dir is a local directory with the same write-once semantics as the bucket:
// objects are written to a temporary file, synced, then hard-linked into
// place, so a key either holds its complete bytes or does not exist, and an
// existing key is never replaced.
type Dir struct{ root string }

// NewDir returns a directory store rooted at root (created on first Put).
func NewDir(root string) *Dir { return &Dir{root: root} }

func (d *Dir) path(key string) (string, error) {
	if key == "" || strings.HasPrefix(key, "/") || path.Clean(key) != key || key == ".." || strings.HasPrefix(key, "../") {
		return "", fmt.Errorf("invalid object key")
	}
	return filepath.Join(d.root, filepath.FromSlash(key)), nil
}

// Put implements Store.
func (d *Dir) Put(ctx context.Context, key string, body []byte) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	dst, err := d.path(key)
	if err != nil {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return false, fmt.Errorf("PUT %s: cannot create directory", key)
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".put-*")
	if err != nil {
		return false, fmt.Errorf("PUT %s: cannot create temporary file", key)
	}
	defer os.Remove(tmp.Name())
	_, werr := tmp.Write(body)
	if werr == nil {
		werr = tmp.Chmod(0o444)
	}
	if werr == nil {
		werr = tmp.Sync()
	}
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return false, fmt.Errorf("PUT %s: write failed", key)
	}
	if err := os.Link(tmp.Name(), dst); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return false, nil
		}
		return false, fmt.Errorf("PUT %s: cannot commit", key)
	}
	return true, nil
}

// Get implements Store.
func (d *Dir) Get(ctx context.Context, key string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p, err := d.path(key)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("GET %s: unreadable", key)
	}
	return data, nil
}

// List implements Store.
func (d *Dir) List(ctx context.Context, prefix string) ([]string, error) {
	var keys []string
	err := filepath.WalkDir(d.root, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) && p == d.root {
				return fs.SkipAll
			}
			return err
		}
		if e.IsDir() || strings.HasPrefix(e.Name(), ".put-") {
			return nil
		}
		rel, _ := filepath.Rel(d.root, p)
		if key := filepath.ToSlash(rel); strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
		return ctx.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("LIST %s: unreadable", prefix)
	}
	sort.Strings(keys)
	return keys, nil
}
