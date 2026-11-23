package connector

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/pa"
	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
)

// refreshConns answers RefreshAccess with a fixed connection.
type refreshConns struct {
	noConns
	next connection.Connection
	err  error
}

func (r refreshConns) RefreshAccess(context.Context, int64, string, int64, int64) (connection.Secret, connection.Connection, error) {
	return connection.NewSecret("fake-at-refreshed"), r.next, r.err
}

// A refresh that hands back another connection than the one the call is
// bound to is refused as unbound, never used (#1318 slice C2b).
func TestRefreshAccess_RefusesAnotherConnection(t *testing.T) {
	bound := pa.ConnectionRevision{ConnectionID: "pac_a", AuthorityRevision: 5}
	good := connection.Connection{ID: "pac_a", Principal: 4242001, Server: connection.ServerTG}
	for name, c := range map[string]struct {
		next connection.Connection
		ok   bool
	}{
		"same":            {good, true},
		"other id":        {connection.Connection{ID: "pac_b", Principal: 4242001, Server: connection.ServerTG}, false},
		"other principal": {connection.Connection{ID: "pac_a", Principal: 4242002, Server: connection.ServerTG}, false},
		"other server":    {connection.Connection{ID: "pac_a", Principal: 4242001, Server: "alice"}, false},
	} {
		e := newSurfaceEnv(t)
		e.d.cfg.Connections = refreshConns{next: c.next}
		tok, _, ref := e.d.refreshAccess(context.Background(), 4242001, "tg", bound, good)
		if c.ok != (ref == nil) || (c.ok && tok.Reveal() != "fake-at-refreshed") {
			t.Errorf("%s: token %q refusal %+v", name, tok.Reveal(), ref)
		}
		if !c.ok && (ref.reason != ReasonConnectionUnbound || ref.code != http.StatusForbidden) {
			t.Errorf("%s: refusal %+v, want connection_unbound 403", name, ref)
		}
	}
}

// What a failed refresh is answered with: a transient failure, even one
// whose expiry could not be recorded, is never reported as an expiry.
func TestConnectionRefusal_Refresh(t *testing.T) {
	for _, c := range []struct {
		err    error
		reason string
		code   int
	}{
		{connection.ErrExpired, ReasonConnectionExpired, http.StatusForbidden},
		{connection.ErrInvalidGrant, ReasonConnectionExpired, http.StatusForbidden},
		{connection.ErrNoRefreshToken, ReasonConnectionExpired, http.StatusForbidden},
		{connection.ErrRefreshInProgress, ReasonRefreshUnavailable, http.StatusServiceUnavailable},
		{fmt.Errorf("%w: down", connection.ErrRefreshFailed), ReasonRefreshUnavailable, http.StatusServiceUnavailable},
		{connection.ErrRefreshUnavailable, ReasonRefreshUnavailable, http.StatusServiceUnavailable},
		{errors.Join(connection.ErrRefreshFailed, connection.ErrInvalidGrant, errors.New("disk")), ReasonRefreshUnavailable, http.StatusServiceUnavailable},
		{connection.ErrNotActive, ReasonConnectionInactive, http.StatusForbidden},
		{connection.ErrRefreshTokenReuse, ReasonConnectionInactive, http.StatusForbidden},
	} {
		if got := connectionRefusal(c.err); got.reason != c.reason || got.code != c.code {
			t.Errorf("%v: %+v, want %s %d", c.err, got, c.reason, c.code)
		}
	}
}
