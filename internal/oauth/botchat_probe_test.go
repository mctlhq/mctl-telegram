package oauth

import (
	"context"
	"errors"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/auth/telegramoidc"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/notify"
)

// probeServer builds a server whose BotChatProbe returns err and counts calls.
func probeServer(t *testing.T, err error) (*Server, *mockRouter, *int, *int64) {
	t.Helper()
	calls := 0
	var gotID int64
	srv := newTestServer(t, func(c *Config) {
		c.BotChatProbe = func(_ context.Context, id int64) error {
			calls++
			gotID = id
			return err
		}
	})
	mux := newMockRouter()
	srv.Register(mux)
	return srv, mux, &calls, &gotID
}

func reachabilityRow(t *testing.T, srv *Server, uid int64) *db.BotReachability {
	t.Helper()
	r, err := srv.store.GetBotReachability(context.Background(), uid)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// #930: Telegram never reports the grant, so a successful getChat after the
// sign-in is what records the user as reachable.
func TestTelegramCallback_BotChatProbeSuccessRecordsReachable(t *testing.T) {
	srv, mux, calls, gotID := probeServer(t, nil)
	uid := signInWithBotAccess(t, srv, mux, telegramoidc.BotAccessUnknown)
	if *calls != 1 || *gotID != 500100101 {
		t.Fatalf("probe calls=%d id=%d, want 1 call for 500100101", *calls, *gotID)
	}
	r := reachabilityRow(t, srv, uid)
	if r == nil || r.State != notify.StateReachable || r.Source != notify.SourceOIDCGetChat || r.ReasonCode != notify.SourceOIDCGetChat {
		t.Fatalf("row = %+v, want reachable/%s", r, notify.SourceOIDCGetChat)
	}
}

// A "chat not found" answer, an inconclusive API error and a transport error
// all write nothing and still complete the sign-in.
func TestTelegramCallback_BotChatProbeFailureWritesNothing(t *testing.T) {
	for name, err := range map[string]error{
		"chat not found": &notify.APIError{StatusCode: 400, Description: "Bad Request: chat not found"},
		"rate limited":   &notify.APIError{StatusCode: 429, Description: "Too Many Requests"},
		"transport":      errors.New("telegram request failed: timeout"),
	} {
		srv, mux, calls, _ := probeServer(t, err)
		uid := signInWithBotAccess(t, srv, mux, telegramoidc.BotAccessUnknown)
		if *calls != 1 {
			t.Errorf("%s: probe calls = %d", name, *calls)
		}
		if r := reachabilityRow(t, srv, uid); r != nil {
			t.Errorf("%s: wrote %+v", name, r)
		}
	}
}

// A reported grant is recorded as such and needs no probe.
func TestTelegramCallback_GrantedSkipsBotChatProbe(t *testing.T) {
	srv, mux, calls, _ := probeServer(t, nil)
	uid := signInWithBotAccess(t, srv, mux, telegramoidc.BotAccessGranted)
	if *calls != 0 {
		t.Fatalf("probe called %d times on a reported grant", *calls)
	}
	if r := reachabilityRow(t, srv, uid); r == nil || r.Source != notify.SourceOIDCBotAccess {
		t.Fatalf("row = %+v", r)
	}
}

// A probe success never unblocks: a stored blocked row stays.
func TestTelegramCallback_BotChatProbeKeepsBlocked(t *testing.T) {
	srv, mux, _, _ := probeServer(t, nil)
	uid := signInWithBotAccess(t, srv, mux, telegramoidc.BotAccessUnknown)
	if err := srv.store.RecordBotReachability(context.Background(), uid,
		notify.DeliveryOutcome{State: notify.StateBlocked, ReasonCode: "bot_blocked", Conclusive: true}, "digest_delivery"); err != nil {
		t.Fatal(err)
	}
	signInWithBotAccess(t, srv, mux, telegramoidc.BotAccessUnknown)
	if r := reachabilityRow(t, srv, uid); r == nil || r.State != notify.StateBlocked {
		t.Fatalf("row = %+v, want blocked kept", r)
	}
}

// The DB write must not inherit the probe's deadline: a probe that succeeds
// only after its timeout context has expired is still recorded.
func TestTelegramCallback_BotChatProbeWriteOutlivesProbeDeadline(t *testing.T) {
	srv := newTestServer(t, func(c *Config) {
		c.BotChatProbe = func(ctx context.Context, _ int64) error {
			<-ctx.Done() // succeed only once the probe deadline has passed
			return nil
		}
	})
	mux := newMockRouter()
	srv.Register(mux)
	uid := signInWithBotAccess(t, srv, mux, telegramoidc.BotAccessUnknown)
	if r := reachabilityRow(t, srv, uid); r == nil || r.Source != notify.SourceOIDCGetChat {
		t.Fatalf("row = %+v, want reachable/%s", r, notify.SourceOIDCGetChat)
	}
}
