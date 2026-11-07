package oauth

import (
	"context"
	"database/sql"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

// A send-code timeout records the stage the flow was stuck in, so the
// timeouts in mctl-telegram#1162 can be classified from the database
// instead of from expired logs: still queued on the per-user lock, dialling
// Telegram, or connected with the code request outstanding.
func TestEnableStart_TimeoutRecordsTheStage(t *testing.T) {
	prev := enableSendCodeWait
	enableSendCodeWait = 150 * time.Millisecond
	t.Cleanup(func() { enableSendCodeWait = prev })

	for _, tc := range []struct {
		name      string
		holdLock  bool
		connected bool
		want      string
	}{
		{"queued on the lock", true, false, loginStageQueued},
		{"dial never finished", false, false, loginStageDialing},
		{"code request outstanding", false, true, loginStageConnected},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, mux := newEnableTestServer(t, func(ctx context.Context, apiID int, apiHash string, store *db.Store,
				uid int64, phone string,
				askCode func(context.Context) (string, error),
				askPassword func(context.Context) (string, error),
				cfgs ...telegram.LoginConfig,
			) (int64, string, string, error) {
				if tc.connected && len(cfgs) > 0 && cfgs[0].OnConnected != nil {
					cfgs[0].OnConnected()
				}
				<-ctx.Done()
				return 0, "", "", ctx.Err()
			}, func(c *Config) { c.CodeTTL = 10 * time.Second })
			esTok := driveToPhone(t, mux)

			var (
				release func()
				parked  chan struct{}
			)
			if tc.holdLock {
				uid, err := srv.store.EnsureUserByTelegramID(context.Background(), 500100101, "dana_tg", "Dana")
				if err != nil {
					t.Fatalf("ensure user: %v", err)
				}
				parked = make(chan struct{})
				srv.loginFlowParked = sync.OnceFunc(func() { close(parked) })
				ul := srv.uidLoginMutex(uid)
				ul.Lock()
				release = ul.Unlock
			}
			rec := postForm(t, mux, "/oauth/telegram/enable_access/start",
				url.Values{"es": {esTok}, "phone": {"+14155551234"}})
			if parked != nil {
				// The flow must really have been waiting on the lock when the
				// handler gave up, or "queued" would be the default talking.
				select {
				case <-parked:
				case <-time.After(2 * time.Second):
					release()
					t.Fatal("the flow never queued on the uid mutex")
				}
			}
			if release != nil {
				release()
			}
			if !strings.Contains(rec.Body.String(), "Timed out contacting Telegram") {
				t.Fatalf("expected the timeout phone form; body=%s", rec.Body.String())
			}
			var n int
			var reason sql.NullString
			err := srv.store.DB.QueryRow(`SELECT COUNT(*), MAX(reason) FROM audit_logs WHERE tool_name = 'connect:failed:timeout'`).Scan(&n, &reason)
			if err != nil {
				t.Fatalf("read audit: %v", err)
			}
			if n != 1 || reason.String != tc.want {
				t.Errorf("timeout rows = %d, reason = %q, want 1 row with %q", n, reason.String, tc.want)
			}
		})
	}
}
