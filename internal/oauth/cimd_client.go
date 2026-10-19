package oauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/mctlhq/mctl-telegram/internal/oauth/cimd"
)

// CIMDResolver resolves an https URL client_id to its validated Client ID
// Metadata Document. *cimd.Resolver satisfies it; tests inject a stub.
type CIMDResolver interface {
	Resolve(ctx context.Context, clientID string) (cimd.Document, error)
}

// errCIMDRefused is the single answer a refused CIMD client gets. The reason
// (host not allowed, fetch failed, invalid document, unsupported auth method)
// goes to the WARN log only: it describes the client's own configuration and
// our allowlist, neither of which an anonymous caller needs.
var errCIMDRefused = errors.New("client metadata document could not be used for this client_id")

// errCIMDAuthMethod refuses a document whose client authenticates at the
// token endpoint. Only public clients (PKCE alone) are supported until
// private_key_jwt lands (mctl-telegram#773, stage 2).
var errCIMDAuthMethod = errors.New("cimd: token_endpoint_auth_method " + cimd.AuthMethodPrivateKeyJWT + " is not supported yet")

// resolveCIMDClient reports whether clientID is handled as a CIMD client and,
// if so, resolves it. isCIMD is false when CIMD is off or clientID is not
// URL-shaped: the caller then takes its unchanged DCR/pre-registered path. A
// CIMD client that cannot be used returns isCIMD=true and errCIMDRefused, and
// never falls through to that path.
func (s *Server) resolveCIMDClient(ctx context.Context, clientID, where string) (doc cimd.Document, isCIMD bool, err error) {
	if s.cfg.CIMD == nil || !cimd.IsCIMDURL(clientID) {
		return cimd.Document{}, false, nil
	}
	doc, err = s.cfg.CIMD.Resolve(ctx, clientID)
	if err == nil && doc.AuthMethod != cimd.AuthMethodNone {
		err = errCIMDAuthMethod
	}
	if err != nil {
		slog.Warn("oauth: cimd client refused", "where", where, "client_id", clientID, "err", err)
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
	slog.Warn("oauth: cimd redirect_uri not in document",
		"client_id", doc.ClientID, "dropped_redirect_uris", doc.DroppedRedirectURIs)
	return fmt.Errorf("redirect_uri %q is not listed in the client metadata document for client_id %q", redirectURI, doc.ClientID)
}
