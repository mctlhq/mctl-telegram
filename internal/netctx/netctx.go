// Package netctx carries the real TCP peer address through the request context.
//
// The http.Server ConnContext hook stashes the socket peer address before any
// middleware runs, so handlers can read the authoritative client address even
// after chi middleware.RealIP overwrites r.RemoteAddr from X-Forwarded-For /
// X-Real-IP headers. Security controls that key on the client identity (CIDR
// allowlists, brute-force rate limits) MUST use this value, not r.RemoteAddr,
// which a client can forge via those headers.
package netctx

import "context"

type socketPeerKey struct{}

// WithPeer returns a context carrying the real TCP peer address (host:port).
// Call it from the http.Server ConnContext hook.
func WithPeer(ctx context.Context, addr string) context.Context {
	return context.WithValue(ctx, socketPeerKey{}, addr)
}

// Peer returns the real TCP peer address stored by WithPeer, or "" when it was
// not set (e.g. in tests that bypass the ConnContext hook).
func Peer(ctx context.Context) string {
	addr, _ := ctx.Value(socketPeerKey{}).(string)
	return addr
}
