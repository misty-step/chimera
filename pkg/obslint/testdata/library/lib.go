// Package lib is a pure library: it serves nothing.
package lib

import "net/http"

// Fetch is a client; a client is not a service surface.
func Fetch(url string) (*http.Response, error) { return http.Get(url) }
