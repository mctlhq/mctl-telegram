package oauth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/mctlhq/mctl-telegram/internal/oauth/cimd"
)

// CIMDResolver resolves an https URL client_id to its validated Client ID
// Metadata Document. *cimd.Resolver satisfies it; tests inject a stub.
type CIMDResolver interface {
	Resolve(ctx context.Context, clientID string) (cimd.Document, error)
}

// maxClientIDBytes caps a client_id at /oauth/authorize and on every CIMD
// resolve.
const maxClientIDBytes = 256

// errCIMDRefused is the single answer a refused CIMD client gets. The reason
// (host not allowed, fetch failed, invalid document, unsupported auth method)
// goes to the WARN log only: it describes the client's own configuration and
// our allowlist, neither of which an anonymous caller needs.
var errCIMDRefused = errors.New("client metadata document could not be used for this client_id")

// errCIMDUnavailable is a document that could not be fetched, or whose fetch
// was refused by the per-host rate limit. That observed nothing about the
// client, so it must never be answered as invalid_client, which tells a
// client its configuration is wrong: the token endpoint answers it as a
// retryable server error (mctl-api#694 reached the same rule).
var errCIMDUnavailable = errors.New("client metadata document is temporarily unavailable; retry later")

// errCIMDAuthMethod refuses a document whose client authenticates at the
// token endpoint. Only public clients (PKCE alone) are supported until
// private_key_jwt lands (mctl-telegram#773, stage 2).
var errCIMDAuthMethod = errors.New("cimd: token_endpoint_auth_method " + cimd.AuthMethodPrivateKeyJWT + " is not supported yet")

// resolveCIMDClient reports whether clientID is handled as a CIMD client and,
// if so, resolves it. isCIMD is false when CIMD is off or clientID is not
// URL-shaped: the caller then takes its unchanged DCR/pre-registered path. A
// CIMD client that cannot be used returns isCIMD=true and errCIMDRefused, and
// never falls through to that path. A fetch that failed or was rate-limited
// returns errCIMDUnavailable instead.
func (s *Server) resolveCIMDClient(ctx context.Context, clientID, where string) (doc cimd.Document, isCIMD bool, err error) {
	if s.cfg.CIMD == nil || !cimd.IsCIMDURL(clientID) {
		return cimd.Document{}, false, nil
	}
	if len(clientID) > maxClientIDBytes {
		// The same cap /oauth/authorize applies, enforced here so the token
		// grants cannot resolve a client_id no authorization could have used.
		slog.Warn("oauth: cimd client refused", "where", where, "err", "client_id exceeds 256 bytes")
		return cimd.Document{}, true, errCIMDRefused
	}
	doc, err = s.cfg.CIMD.Resolve(ctx, clientID)
	if err == nil && doc.AuthMethod != cimd.AuthMethodNone {
		err = errCIMDAuthMethod
	}
	if err != nil {
		slog.Warn("oauth: cimd client refused", "where", where, "client_id", clientID, "err", err)
		if errors.Is(err, cimd.ErrFetch) || errors.Is(err, cimd.ErrRateLimited) {
			return cimd.Document{}, true, errCIMDUnavailable
		}
		return cimd.Document{}, true, errCIMDRefused
	}
	return doc, true, nil
}

// validateCIMDRedirect checks redirectURI against a resolved document. The
// match is exact, except for an http redirect on 127.0.0.1 or [::1], where
// any port is accepted (RFC 8252 section 7.3).
func validateCIMDRedirect(doc cimd.Document, redirectURI string) error {
	if cimd.RedirectAllowed(doc.RedirectURIs, redirectURI) {
		return nil
	}
	// The detail goes to the log only: the caller gets the same refusal as
	// for any other unusable document.
	slog.Warn("oauth: cimd redirect_uri not in document",
		"client_id", doc.ClientID, "redirect_uri", redirectURI,
		"dropped_redirect_uris", doc.DroppedRedirectURIs)
	return errCIMDRefused
}

// writeCIMDTokenError answers a token request whose CIMD client could not be
// resolved: invalid_client for a refused document, a retryable 503
// server_error when the document could not be observed.
func writeCIMDTokenError(w http.ResponseWriter, err error) {
	if errors.Is(err, errCIMDUnavailable) {
		w.Header().Set("Retry-After", "30")
		writeTokenError(w, "server_error", err.Error(), http.StatusServiceUnavailable)
		return
	}
	writeTokenError(w, "invalid_client", err.Error(), http.StatusBadRequest)
}
