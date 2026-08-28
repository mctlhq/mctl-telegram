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
// operator's own loopback, and must never boot at all on a deployment tier
// that is not a recognized local one, regardless of ADDR.
//
// It performs no I/O and no DNS resolution — it is a pure function of the
// already-loaded config, matching the selectProvider/selectBridgeProvider
// pattern in main.go that main_test.go already exercises without booting a
// server.
func checkBootGuard(cfg *config.Config) error {
	exposed := !isLocalEnv(cfg.Environment) || !isLoopbackAddr(cfg.Addr)
	if !exposed {
		// Loopback bind on a local ENV is today's documented local-dev
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
		// key) is allowed on a public bind or any deployment tier.
		return nil
	}

	return fmt.Errorf(
		"refusing to start: ADDR=%q ENV=%q is not a loopback bind on a recognized local development tier, and: %s "+
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

// localEnvNames are the ENV values the boot guard accepts as "this is a
// developer's own machine". The empty string is included: it is the default
// in internal/config, and what a bare `go run ./cmd/server` sees.
//
// Including "" is a deliberate, documented residual risk (see SECURITY.md's
// "Authentication-required mode"): config alone cannot distinguish "a
// developer never set ENV" from "ops never wired ENV", so an unset ENV is
// treated exactly like an explicit local tier. A deployment that leaves ENV
// unset AND binds ADDR to loopback (e.g. behind an in-pod reverse proxy or
// sidecar) therefore still boots with an insecure auth mode or a missing
// ENCRYPTION_KEY — the loopback bind is the only thing between it and an
// exposed admin bypass. Real deployments must set ENV; the intentionality of
// this gap is pinned by TestCheckBootGuardUnsetEnvOnLoopbackIsIntentionallyAllowed.
var localEnvNames = []string{"", "local", "local-dev", "localdev", "dev", "development", "test", "ci"}

// isLocalEnv reports whether env names a local development tier, compared
// case-insensitively after trimming surrounding whitespace (consistent with
// how AUTH_MODE is compared elsewhere in this file).
//
// ENV is free-text — internal/config sources it straight from the environment
// with no enum validation — so this deliberately fails CLOSED, exactly as
// isLoopbackAddr does below: an unrecognized value such as "prod", "prd",
// "staging" or "PRODUCTION_ENV" is not known to be a developer machine, so it
// is treated as a real deployment where the checks above apply. Recognizing
// only an exact "production" spelling would mean a deployment that labels its
// tier any other way silently skips this clause — the "safety net that is not
// one" failure mode this guard exists to prevent. Widening the guard is safe
// in the other direction: a correctly configured deployment (real auth mode +
// encryption key) still boots on any ENV.
func isLocalEnv(env string) bool {
	env = strings.TrimSpace(env)
	for _, name := range localEnvNames {
		if strings.EqualFold(env, name) {
			return true
		}
	}
	return false
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
