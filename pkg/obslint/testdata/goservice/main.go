// A plain HTTP service: no worker config, so telemetry is server-side error
// forwarding to a sink whose DSN comes from the environment.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"runtime/debug"

	"github.com/getsentry/sentry-go"
)

func main() {
	if err := sentry.Init(sentry.ClientOptions{Dsn: os.Getenv("SENTRY_DSN"), Environment: os.Getenv("APP_ENV")}); err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", health)
	log.Fatal(http.ListenAndServe(":8080", mux))
}

func health(w http.ResponseWriter, r *http.Request) {
	rev := "unknown"
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" {
				rev = s.Value
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "environment": os.Getenv("APP_ENV"), "release": rev})
}
