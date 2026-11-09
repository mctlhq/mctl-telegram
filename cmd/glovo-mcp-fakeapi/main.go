//go:build glovofake

// Command glovo-mcp-fakeapi runs the in-memory mctl-api HARNESS locally so
// cmd/glovo-mcp and an MCP client can be exercised end to end. It is never
// part of the facade image and is not mctl-api.
//
//	go run -tags glovofake ./cmd/glovo-mcp-fakeapi
package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/glovo/mctlapi/fakeapi"
)

func main() {
	env := func(k, d string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return d
	}
	addr := env("GLOVO_FAKE_ADDR", "127.0.0.1:9000")
	opt := fakeapi.Options{
		Issuer:     env("GLOVO_FAKE_ISSUER", "http://"+addr),
		Resource:   env("GLOVO_FAKE_RESOURCE", "http://127.0.0.1:8080/mcp"),
		Credential: env("GLOVO_FAKE_CREDENTIAL", "fake-workload-credential"),
	}
	f := fakeapi.New(opt)
	fmt.Printf("fake mctl-api on http://%s (issuer %s, resource %s)\n", addr, opt.Issuer, opt.Resource)
	fmt.Printf("alice token (team-alpha, 10m): %s\n", f.Mint(fakeapi.MintOpts{Sub: fakeapi.Alice, Tenant: fakeapi.TeamAlpha}))
	srv := &http.Server{Addr: addr, Handler: f.Handler(), ReadHeaderTimeout: 10 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
