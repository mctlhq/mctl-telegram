package main

import (
	"fmt"
	"net"
	"strings"

	"github.com/mctlhq/mctl-telegram/internal/config"
)

// checkBootGuard turns the invariant documented in SECURITY.md's
// "Authentication-required mode" section into an enforced, fatal boot-time
// check: a wide-open combination (local-dev auth bypass and/or no session
// encryption) must never boot on an interface anything other than the
// operator's own loopback, and must never boot at all in production
// regardless of ADDR.
//
// It performs no I/O and no DNS resolution — it is a pure function of the
// already-loaded config, matching the selectProvider/selectBridgeProvider
// pattern in main.go that main_test.go already exercises without booting a
// server.
func checkBootGuard(cfg *config.Config) error {
	exposed := isProductionEnv(cfg.Environment) || !isLoopbackAddr(cfg.Addr)
	if !exposed {
		// Loopback bind outside production is today's documented local-dev
		// posture (see README.md/CONTRIBUTING.md Quick Start) and stays
		// unchanged.
		return nil
	}

	var problems []string
	if insecureAuth(cfg) {
		problems = append(problems, fmt.Sprintf(
			"AUTH_MODE=%q AUTH_REQUIRED=%v grants unauthenticated platform-admin access (see internal/auth/localdev) — set AUTH_MODE to local-jwt or shared-hmac with AUTH_REQUIRED=true",
			cfg.AuthMode, cfg.AuthRequired))
	}
	if len(cfg.EncryptionKey) == 0 {
		problems = append(problems, "ENCRYPTION_KEY is not set — Telegram session blobs would be stored UNENCRYPTED — set a 64-hex-char (32-byte) key")
	}
	if len(problems) == 0 {
		// A correctly configured deployment (real auth mode + encryption
		// key) is allowed on a public bind or in production.
		return nil
	}

	return fmt.Errorf(
		"refusing to start: ADDR=%q ENV=%q is not a loopback/non-production bind, and: %s "+
			"(bind ADDR to a loopback address such as 127.0.0.1:8080 for local development, "+
			"or fix the listed setting(s) for a real deployment)",
		cfg.Addr, cfg.Environment, strings.Join(problems, "; "))
}

// insecureAuth reports whether cfg grants the local-dev auth bypass: either
// AUTH_MODE is (case-insensitively) "local-dev", which unconditionally
// returns a fixed platform-admin identity for every request
// (internal/auth/localdev), or AUTH_REQUIRED is false, which disables
// credential enforcement regardless of AUTH_MODE.
func insecureAuth(cfg *config.Config) bool {
	return strings.EqualFold(cfg.AuthMode, "local-dev") || !cfg.AuthRequired
}

// isProductionEnv reports whether env names a production deployment tier,
// compared case-insensitively (consistent with how AUTH_MODE is compared
// elsewhere in this file).
func isProductionEnv(env string) bool {
	return strings.EqualFold(env, "production")
}

// isLoopbackAddr reports whether addr (an ADDR-shaped host:port, as passed
// to http.Server.Addr / net.Listen) is restricted to a loopback interface.
//
// This is a static string check, not a network probe: it never resolves
// DNS and never inspects actual interfaces, so it is deterministic and safe
// to call at boot before anything else has started.
//
// An empty host (e.g. ":8080", the documented former default) is treated as
// non-loopback: Go's net.Listen binds an empty host to all interfaces,
// identically to "0.0.0.0", so treating it as "close enough to loopback"
// would silently defeat the guard for the exact default this proposal
// exists to close.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// No port present (e.g. a bare hostname) — treat the whole value as
		// the host rather than failing closed on a SplitHostPort error alone.
		host = addr
	}
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	// An unresolvable/unknown hostname is not known to be loopback. Fail
	// closed: the guard does not perform DNS resolution at boot.
	return false
}
