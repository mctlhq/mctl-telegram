package oauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/oauth/cimd"
)

// CIMDResolver resolves an https URL client_id to its validated Client ID
// Metadata Document and verifies private_key_jwt client assertions against
// it. *cimd.Resolver satisfies it; tests inject a stub.
type CIMDResolver interface {
	Resolve(ctx context.Context, clientID string) (cimd.Document, error)
	VerifyAssertion(ctx context.Context, doc cimd.Document, assertion string, audiences []string) (cimd.Assertion, error)
}

// ClientAssertionTypeJWT is the only client_assertion_type accepted (RFC 7523
// section 2.2).
const ClientAssertionTypeJWT = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// errCIMDRefused is the single answer a refused CIMD client gets. The reason
// (host not allowed, invalid document) goes to the WARN log only: it
// describes the client's own configuration and our allowlist, neither of
// which an anonymous caller needs.
var errCIMDRefused = errors.New("client metadata document could not be used for this client_id")

// errCIMDUnavailable is a document or key set that could not be fetched, or
// whose fetch was refused by the per-host rate limit. That observed nothing
// about the client, so it must never be answered as invalid_client, which
// tells a client its configuration is wrong: the token endpoint answers it
// as a retryable server error (mctl-api#694 reached the same rule).
var errCIMDUnavailable = errors.New("client metadata document is temporarily unavailable; retry later")

// errCIMDAuthFailed is a token request whose client authentication does not
// match what the client's document declares, including a replayed jti.
var errCIMDAuthFailed = errors.New("client authentication failed")

// errJTIStore is a replay store that could not be read or written. It is a
// server error, never a pass.
var errJTIStore = errors.New("could not record the client assertion; retry later")

// cimdEnabled reports whether URL client_ids are resolved as CIMD.
func (s *Server) cimdEnabled() bool { return s.cfg.CIMD != nil }

// cimdAdvertised reports whether discovery announces CIMD: only while it is
// resolved and CIMDAdvertise is on.
func (s *Server) cimdAdvertised() bool { return s.cimdEnabled() && s.cfg.CIMDAdvertise }

// resolveCIMDClient reports whether clientID is handled as a CIMD client and,
// if so, resolves it. isCIMD is false when CIMD is off or clientID is not
// URL-shaped: the caller then takes its unchanged DCR/pre-registered path. A
// CIMD client that cannot be used returns isCIMD=true and errCIMDRefused, and
// never falls through to that path. A fetch that failed or was rate-limited
// returns errCIMDUnavailable instead.
func (s *Server) resolveCIMDClient(ctx context.Context, clientID, where string) (doc cimd.Document, isCIMD bool, err error) {
	if !s.cimdEnabled() || !cimd.IsCIMDURL(clientID) {
		return cimd.Document{}, false, nil
	}
	doc, err = s.cfg.CIMD.Resolve(ctx, clientID)
	if err == nil && doc.AuthMethod != cimd.AuthMethodNone && doc.AuthMethod != cimd.AuthMethodPrivateKeyJWT {
		err = fmt.Errorf("%w: unsupported token_endpoint_auth_method %q", cimd.ErrInvalidDocument, doc.AuthMethod)
	}
	if err != nil {
		return cimd.Document{}, true, cimdFailure(where, clientID, err)
	}
	return doc, true, nil
}

// cimdFailure logs err with its reason and maps it to the caller-facing
// error, which never carries the reason.
func cimdFailure(where, clientID string, err error) error {
	slog.Warn("oauth: cimd client refused", "where", where, "client_id", clientID, "err", err)
	switch {
	case errors.Is(err, cimd.ErrFetch), errors.Is(err, cimd.ErrRateLimited):
		return errCIMDUnavailable
	case errors.Is(err, errJTIStore):
		return errJTIStore
	case errors.Is(err, cimd.ErrAssertion), errors.Is(err, errCIMDAuthFailed):
		return errCIMDAuthFailed
	}
	return errCIMDRefused
}

// authenticateCIMDClient resolves a CIMD client at the token endpoint and
// checks the client authentication its document declares: none must send no
// client assertion, private_key_jwt must send a valid one on every request,
// with a jti not seen before. isCIMD=false leaves a non-CIMD client on its
// unchanged public-client path.
func (s *Server) authenticateCIMDClient(r *http.Request, clientID, where string) (isCIMD bool, err error) {
	doc, isCIMD, err := s.resolveCIMDClient(r.Context(), clientID, where)
	if !isCIMD || err != nil {
		return isCIMD, err
	}
	assertionType := r.FormValue("client_assertion_type")
	assertion := r.FormValue("client_assertion")
	switch doc.AuthMethod {
	case cimd.AuthMethodNone:
		if assertionType != "" || assertion != "" {
			return true, cimdFailure(where, clientID,
				fmt.Errorf("%w: client declares none and must not send a client assertion", errCIMDAuthFailed))
		}
		return true, nil
	case cimd.AuthMethodPrivateKeyJWT:
		if assertionType != ClientAssertionTypeJWT || assertion == "" {
			return true, cimdFailure(where, clientID,
				fmt.Errorf("%w: private_key_jwt client must send client_assertion_type %s and client_assertion", errCIMDAuthFailed, ClientAssertionTypeJWT))
		}
		a, err := s.cfg.CIMD.VerifyAssertion(r.Context(), doc, assertion, s.assertionAudiences())
		if err != nil {
			return true, cimdFailure(where, clientID, err)
		}
		if err := s.consumeJTI(r.Context(), clientID, a); err != nil {
			return true, cimdFailure(where, clientID, err)
		}
		return true, nil
	}
	return true, cimdFailure(where, clientID,
		fmt.Errorf("%w: unsupported token_endpoint_auth_method %q", errCIMDAuthFailed, doc.AuthMethod))
}

// assertionAudiences are the aud values a client assertion may carry: the
// issuer or the token endpoint URL, compared as exact strings.
func (s *Server) assertionAudiences() []string {
	return []string{s.cfg.Issuer, s.cfg.Issuer + "/oauth/token"}
}

// consumeJTI records a's jti for its remaining lifetime and refuses one
// already recorded. With Postgres the record is shared by every replica;
// without it the in-memory map serves the single process.
func (s *Server) consumeJTI(ctx context.Context, clientID string, a cimd.Assertion) error {
	ttl := max(a.RememberFor, time.Second)
	now := s.clock()
	if s.useDB {
		fresh, err := s.store.RecordClientAssertionJTI(ctx, clientID, a.JTI, now.Add(ttl))
		if err != nil {
			return fmt.Errorf("%w: %v", errJTIStore, err)
		}
		if !fresh {
			return fmt.Errorf("%w: client assertion jti was already used", errCIMDAuthFailed)
		}
		return nil
	}
	key := clientID + "\x00" + a.JTI
	s.mu.Lock()
	defer s.mu.Unlock()
	if exp, ok := s.jtis[key]; ok && now.Before(exp) {
		return fmt.Errorf("%w: client assertion jti was already used", errCIMDAuthFailed)
	}
	s.jtis[key] = now.Add(ttl)
	return nil
}

// sweepJTIs drops expired in-memory jti records.
func (s *Server) sweepJTIs(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, exp := range s.jtis {
		if !now.Before(exp) {
			delete(s.jtis, k)
		}
	}
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

// writeCIMDTokenError answers a token request whose CIMD client could not be
// used: a retryable 503 server_error when nothing about the client could be
// observed or recorded, invalid_client otherwise.
func writeCIMDTokenError(w http.ResponseWriter, err error) {
	if errors.Is(err, errCIMDUnavailable) || errors.Is(err, errJTIStore) {
		w.Header().Set("Retry-After", "30")
		writeTokenError(w, "server_error", err.Error(), http.StatusServiceUnavailable)
		return
	}
	writeTokenError(w, "invalid_client", err.Error(), http.StatusBadRequest)
}
