package linking_test

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/linking"
)

// TestLinking_HappyPathTG: the whole flow for tg ends active, with the
// principal's users row created as a PA row, and the authorization request
// carries PKCE S256, a bound state, RFC 8707 resource and prompt=consent
// (checked by the fake authorization server).
func TestLinking_HappyPathTG(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		h := newHarness(t, s, false)
		card := h.toConfirm(connection.ServerTG, h.tgLogin(h.alice))
		if h.state(connection.ServerTG) != connection.StatePendingConfirm {
			t.Fatalf("state %s, want pending_confirm", h.state(connection.ServerTG))
		}
		confirm, _ := confirmData(card)
		handled, err := h.svc.HandleCallback(ctx, callbackUpdate(t, h.alice, confirm))
		if !handled || err != nil {
			t.Fatalf("confirm: handled=%v err=%v", handled, err)
		}
		c := h.connection(connection.ServerTG)
		if c.State != connection.StateActive || c.AccountID != "telegram:"+strconv.FormatInt(h.alice, 10) {
			t.Fatalf("connection %+v", c)
		}
		uid, err := s.UserIDByTelegramID(ctx, h.alice)
		if err != nil || uid <= 0 {
			t.Fatalf("no users row for the principal: %v", err)
		}
		var provider string
		if err := s.DB.QueryRow(`SELECT provider FROM users WHERE id = $1`, uid).Scan(&provider); err != nil || provider != db.PAProvider {
			t.Fatalf("provider %q (%v), want %q", provider, err, db.PAProvider)
		}
	})
}

// S1-L1: forged or expired initData, and initDataUnsafe sent alone, are
// refused. None of the refusals burns the link token.
func TestLinking_S1L1_ForgedExpiredOrUnsafeInitDataRefused(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		h := newHarness(t, s, false)
		link := h.start(connection.ServerTG)

		valid := h.initData(h.alice, "")
		vals, _ := url.ParseQuery(valid)
		// Forged: the user is swapped after signing.
		forged := url.Values{}
		for k, v := range vals {
			forged[k] = v
		}
		forged.Set("user", `{"id":`+strconv.FormatInt(h.alice, 10)+`,"first_name":"Bob"}`)
		// Expired: signed correctly, six minutes old.
		expired := signInitData(paBotToken, initDataFields(h.alice, "Alice", h.clock.Now().Add(-6*time.Minute), ""))
		// initDataUnsafe alone: the client's parsed fields with no hash.
		unsafe := url.Values{"user": {vals.Get("user")}, "auth_date": {vals.Get("auth_date")}}.Encode()
		// A duplicated key cannot smuggle a second user past the signature.
		dup := valid + "&user=" + url.QueryEscape(`{"id":`+strconv.FormatInt(h.bob, 10)+`}`)

		for name, c := range map[string]struct {
			raw  string
			want error
		}{
			"forged":  {forged.Encode(), linking.ErrInitDataSignature},
			"expired": {expired, linking.ErrInitDataExpired},
			"unsafe":  {unsafe, linking.ErrInitDataMalformed},
			"empty":   {"", linking.ErrInitDataMissing},
			"dup":     {dup, linking.ErrInitDataMalformed},
		} {
			if _, err := h.svc.BeginOAuth(ctx, c.raw, link); !errors.Is(err, c.want) {
				t.Fatalf("%s: err %v, want %v", name, err, c.want)
			}
		}
		if h.state(connection.ServerTG) != connection.StatePendingLink {
			t.Fatalf("state moved on a refused initData")
		}
		h.begin(link) // still usable by its principal
	})
}

// S1-L2: initData signed with the login bot's token is refused, and a
// configuration that uses one token for both bots does not start.
func TestLinking_S1L2_LoginBotInitDataRefused(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		h := newHarness(t, s, false)
		link := h.start(connection.ServerTG)
		raw := signInitData(loginBotToken, initDataFields(h.alice, "Alice", h.clock.Now(), ""))
		if _, err := h.svc.BeginOAuth(ctx, raw, link); !errors.Is(err, linking.ErrInitDataSignature) {
			t.Fatalf("login-bot initData: %v", err)
		}
		cfg := linking.Config{
			BotToken: loginBotToken, LoginBotToken: loginBotToken, BotUsername: "fake_pa_bot", MiniAppName: "link",
			AppURL: appURL, Servers: h.servers, Manager: h.m, Store: s, Tokens: tokenClient{h.as},
			Accounts: h.accounts, Messenger: h.msgr, Allowed: h.allow,
		}
		if _, err := linking.New(cfg); !errors.Is(err, linking.ErrConfig) {
			t.Fatalf("same token for both bots accepted: %v", err)
		}
		cfg.BotToken = paBotToken
		if _, err := linking.New(cfg); err != nil {
			t.Fatalf("distinct tokens refused: %v", err)
		}
	})
}

// S1-L3: initData of another user at step 1 is refused. Bob holding Alice's
// link token neither starts OAuth nor burns the token.
func TestLinking_S1L3_OtherUserAtStartRefused(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		h := newHarness(t, s, false)
		link := h.start(connection.ServerTG)
		if _, err := h.svc.BeginOAuth(ctx, h.initData(h.bob, ""), link); !errors.Is(err, linking.ErrWrongUser) {
			t.Fatalf("Bob's initData: %v", err)
		}
		if h.state(connection.ServerTG) != connection.StatePendingLink {
			t.Fatalf("state moved for another user")
		}
		h.begin(link)
	})
}

// S1-L4: link token reuse is refused, and so is a link token past its TTL.
func TestLinking_S1L4_LinkTokenReuseRefused(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		h := newHarness(t, s, false)
		link := h.start(connection.ServerTG)
		h.begin(link)
		if _, err := h.svc.BeginOAuth(ctx, h.initData(h.alice, ""), link); !errors.Is(err, linking.ErrRefused) {
			t.Fatalf("reuse: %v", err)
		}
		link2, err := h.svc.StartLink(ctx, principal(t, h.alice), connection.ServerTG)
		if err != nil {
			t.Fatal(err)
		}
		h.clock.Add(linking.LinkTokenTTL)
		if _, err := h.svc.BeginOAuth(ctx, h.initData(h.alice, ""), linkFromURL(t, link2)); !errors.Is(err, linking.ErrRefused) {
			t.Fatalf("expired link token: %v", err)
		}
	})
}

// S1-L5: state replay, a wrong state, a wrong or missing iss and a wrong
// redirect are refused. None but the replay consumes the state, and the
// connection stays in pending_oauth.
func TestLinking_S1L5_CallbackChecks(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		h := newHarness(t, s, true)
		cb := h.toCallback(connection.ServerTG, h.tgLogin(h.alice))
		with := func(k, v string) url.Values {
			q := url.Values{}
			for kk, vv := range cb {
				q[kk] = append([]string(nil), vv...)
			}
			if v == "" {
				q.Del(k)
			} else {
				q.Set(k, v)
			}
			return q
		}
		dupState := with("state", "")
		dupState["state"] = []string{cb.Get("state"), cb.Get("state")}
		for name, c := range map[string]struct {
			server connection.Server
			q      url.Values
		}{
			"wrong state":     {connection.ServerTG, with("state", strings.Repeat("A", 43))},
			"no state":        {connection.ServerTG, with("state", "")},
			"duplicate state": {connection.ServerTG, dupState},
			"wrong iss":       {connection.ServerTG, with("iss", "https://as.evil.example.test")},
			"missing iss":     {connection.ServerTG, with("iss", "")},
			// The state was minted for the tg redirect URI; arriving on
			// alice's is a wrong redirect.
			"wrong redirect": {connection.ServerAlice, with("iss", h.as[connection.ServerAlice].issuer)},
		} {
			if _, err := h.svc.Callback(ctx, c.server, c.q); err == nil {
				t.Fatalf("%s: accepted", name)
			}
		}
		if h.state(connection.ServerTG) != connection.StatePendingOAuth {
			t.Fatalf("state moved on a refused callback")
		}
		if _, err := h.svc.Callback(ctx, connection.ServerTG, cb); err != nil {
			t.Fatalf("the genuine callback after the refusals: %v", err)
		}
		if _, err := h.svc.Callback(ctx, connection.ServerTG, cb); !errors.Is(err, linking.ErrRefused) {
			t.Fatalf("replay: %v", err)
		}
		if h.state(connection.ServerTG) != connection.StatePendingReturn {
			t.Fatalf("state %s, want pending_return", h.state(connection.ServerTG))
		}
	})
}

// S1-L6: a valid callback whose completion code is opened by a different
// Telegram user does not exchange the code, and the connection never
// leaves pending_return. The code stays usable by the principal.
func TestLinking_S1L6_CompletionByOtherUserDoesNotExchange(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		h := newHarness(t, s, false)
		code := h.toCompletion(connection.ServerTG, h.tgLogin(h.alice))
		if err := h.svc.Complete(ctx, h.initData(h.bob, code)); !errors.Is(err, linking.ErrWrongUser) {
			t.Fatalf("Bob opened the completion code: %v", err)
		}
		if n := h.as[connection.ServerTG].exchangeCount(); n != 0 {
			t.Fatalf("code exchanged %d times for another user", n)
		}
		if h.state(connection.ServerTG) != connection.StatePendingReturn {
			t.Fatalf("state %s, want pending_return", h.state(connection.ServerTG))
		}
		if err := h.svc.Complete(ctx, h.initData(h.alice, code)); err != nil {
			t.Fatalf("the principal after Bob: %v", err)
		}
	})
}

// S1-L7: completion code reuse or expiry is refused, without an exchange.
func TestLinking_S1L7_CompletionReuseOrExpiryRefused(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		h := newHarness(t, s, false)
		code := h.toCompletion(connection.ServerTG, h.tgLogin(h.alice))
		if err := h.svc.Complete(ctx, h.initData(h.alice, code)); err != nil {
			t.Fatal(err)
		}
		if err := h.svc.Complete(ctx, h.initData(h.alice, code)); !errors.Is(err, linking.ErrRefused) {
			t.Fatalf("reuse: %v", err)
		}
		if n := h.as[connection.ServerTG].exchangeCount(); n != 1 {
			t.Fatalf("exchanges %d, want 1", n)
		}

		h2 := newHarness(t, s, false)
		code2 := h2.toCompletion(connection.ServerTG, h2.tgLogin(h2.alice))
		h2.clock.Add(linking.CompletionTTL)
		if err := h2.svc.Complete(ctx, h2.initData(h2.alice, code2)); !errors.Is(err, linking.ErrRefused) {
			t.Fatalf("expired: %v", err)
		}
		if n := h2.as[connection.ServerTG].exchangeCount(); n != 0 {
			t.Fatalf("expired code exchanged")
		}
	})
}

// S1-L8: the connection is unusable in every pending_* state.
func TestLinking_S1L8_PendingConnectionUnusable(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		h := newHarness(t, s, false)
		unusable := func(stage string) {
			t.Helper()
			c := h.connection(connection.ServerTG)
			if _, err := h.m.Authorize(ctx, h.alice, c.ID, c.AuthorityRevision); err == nil {
				t.Fatalf("%s (%s): Authorize succeeded", stage, c.State)
			}
			if _, _, err := h.m.AccessToken(ctx, h.alice, c.ID, c.AuthorityRevision); err == nil {
				t.Fatalf("%s (%s): AccessToken succeeded", stage, c.State)
			}
		}
		link := h.start(connection.ServerTG)
		unusable("pending_link")
		cb := h.as[connection.ServerTG].authorize(t, h.begin(link), h.tgLogin(h.alice))
		unusable("pending_oauth")
		res, err := h.svc.Callback(ctx, connection.ServerTG, cb)
		if err != nil {
			t.Fatal(err)
		}
		unusable("pending_return")
		deep, _, err := h.svc.Handoff(ctx, res.Handoff)
		if err != nil {
			t.Fatal(err)
		}
		if err := h.svc.Complete(ctx, h.initData(h.alice, startapp(t, deep))); err != nil {
			t.Fatal(err)
		}
		unusable("pending_confirm")
	})
}

// S1-L9: a confirm callback_query from another user, or after expiry, is
// refused. An expired card fails the connection and revokes its tokens.
func TestLinking_S1L9_ConfirmFromOtherUserOrExpiredRefused(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		h := newHarness(t, s, false)
		confirm, cancel := confirmData(h.toConfirm(connection.ServerTG, h.tgLogin(h.alice)))
		for _, data := range []string{confirm, cancel} {
			handled, err := h.svc.HandleCallback(ctx, callbackUpdate(t, h.bob, data))
			if !handled || !errors.Is(err, linking.ErrWrongUser) {
				t.Fatalf("Bob pressed %q: handled=%v err=%v", data, handled, err)
			}
		}
		if h.state(connection.ServerTG) != connection.StatePendingConfirm {
			t.Fatalf("state %s after Bob, want pending_confirm", h.state(connection.ServerTG))
		}
		if _, err := s.UserIDByTelegramID(ctx, h.bob); !errors.Is(err, db.ErrUserNotFound) {
			t.Fatalf("Bob got a users row: %v", err)
		}

		h.clock.Add(linking.ConfirmTTL)
		handled, err := h.svc.HandleCallback(ctx, callbackUpdate(t, h.alice, confirm))
		if !handled || err == nil {
			t.Fatalf("expired confirm: handled=%v err=%v", handled, err)
		}
		if h.state(connection.ServerTG) != connection.StateFailed {
			t.Fatalf("state %s after an expired confirm, want failed", h.state(connection.ServerTG))
		}
		if !h.revoker.has("fake-at-tg-2") || !h.revoker.has("fake-rt-tg-2") {
			t.Fatalf("tokens of the expired connection not revoked: %v", h.revoker.tokens)
		}
	})
}

// S1-L10: the card shows the stable account id, not the display name.
func TestLinking_S1L10_CardShowsStableID(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		h := newHarness(t, s, true)
		card := h.toConfirm(connection.ServerAlice, linking.Account{ID: "yandex-uid-4242", DisplayName: "Bank Support Team"})
		if !strings.Contains(card.Text, "yandex-uid-4242") || strings.Contains(card.Text, "Bank Support") {
			t.Fatalf("alice card %q", card.Text)
		}
		tg := h.toConfirm(connection.ServerTG, h.tgLogin(h.alice))
		if !strings.Contains(tg.Text, "telegram:"+strconv.FormatInt(h.alice, 10)) || strings.Contains(tg.Text, "Alice") {
			t.Fatalf("tg card %q", tg.Text)
		}
		for _, b := range append(card.Buttons, tg.Buttons...) {
			if len(b.Data) > 64 {
				t.Fatalf("callback_data %d bytes, over Telegram's 64", len(b.Data))
			}
		}
	})
}

// An account source that answers without an account id links nothing: the
// id is all the confirm card can show for a server whose accounts are not
// Telegram identities, so no card is sent and no connection waits for a
// confirmation.
func TestLinking_EmptyAccountIDLinksNothing(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		h := newHarness(t, s, true)
		code := h.toCompletion(connection.ServerAlice, linking.Account{DisplayName: "Bob"})
		before := len(h.msgr.all())
		if err := h.svc.Complete(context.Background(), h.initData(h.alice, code)); err == nil {
			t.Fatal("completion with no account id succeeded")
		}
		if cards := h.msgr.all(); len(cards) != before {
			t.Fatalf("a confirm card was sent: %+v", cards[before:])
		}
		if st := h.state(connection.ServerAlice); st == connection.StatePendingConfirm || st == connection.StateActive {
			t.Fatalf("connection is %s", st)
		}
	})
}

// S1-L11: a completion code opened by the principal succeeds even when the
// provider login was done by someone else. This pins the exact scope of the
// step 4 check: it binds the Telegram user who opens the link, not the
// person who signed in at the provider. For alice that is the residual risk
// S1-L14 gates; for tg, step 6 (S1-L13) closes it.
func TestLinking_S1L11_StepFourBindsOpenerOnly(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		h := newHarness(t, s, true)
		// Bob signed in at alice's provider; Alice opens the completion code.
		h.toConfirm(connection.ServerAlice, linking.Account{ID: "yandex-uid-bob", DisplayName: "Bob"})
		c := h.connection(connection.ServerAlice)
		if c.State != connection.StatePendingConfirm || c.AccountID != "yandex-uid-bob" {
			t.Fatalf("connection %+v", c)
		}
	})
}

// S1-L12: a completion code passed anywhere but the signed start_param is
// ignored: as a URL parameter, as a body field, or as an unsigned
// start_param appended to initData.
func TestLinking_S1L12_CompletionCodeOnlyFromSignedStartParam(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		h := newHarness(t, s, false)
		code := h.toCompletion(connection.ServerTG, h.tgLogin(h.alice))
		srv := h.server(t)

		noParam := h.initData(h.alice, "")
		body := `{"init_data":` + quote(noParam) + `,"code":"` + code + `","start_param":"` + code + `"}`
		if st := srv.post(t, linking.CompletePath+"?startapp="+code+"&tgWebAppStartParam="+code+"&code="+code, body); st != 403 {
			t.Fatalf("code in URL/body: status %d, want 403", st)
		}
		appended := noParam + "&start_param=" + code
		if st := srv.post(t, linking.CompletePath, `{"init_data":`+quote(appended)+`}`); st != 403 {
			t.Fatalf("unsigned start_param: status %d, want 403", st)
		}
		if n := h.as[connection.ServerTG].exchangeCount(); n != 0 {
			t.Fatalf("exchanged %d times without a signed start_param", n)
		}
		if st := srv.post(t, linking.CompletePath, `{"init_data":`+quote(h.initData(h.alice, code))+`}`); st != 200 {
			t.Fatalf("signed start_param: status %d", st)
		}
	})
}

// S1-L13: a tg connection whose get_my_identity returns a different
// telegram_id, a zero id or an error never reaches pending_confirm, and the
// token is revoked. No card is sent.
func TestLinking_S1L13_TGIdentityMustBePrincipal(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		for name, setup := range map[string]func(h *harness){
			"other id": func(h *harness) {
				h.accounts.override = &linking.Account{ID: "telegram:x", TelegramID: h.bob}
			},
			"zero id": func(h *harness) { h.accounts.override = &linking.Account{ID: "telegram:0"} },
			"error":   func(h *harness) { h.accounts.err = errors.New("get_my_identity: 500") },
		} {
			t.Run(name, func(t *testing.T) {
				ctx := context.Background()
				h := newHarness(t, s, false)
				setup(h)
				code := h.toCompletion(connection.ServerTG, h.tgLogin(h.alice))
				if err := h.svc.Complete(ctx, h.initData(h.alice, code)); err == nil {
					t.Fatal("completed")
				}
				c := h.connection(connection.ServerTG)
				if c.State != connection.StateFailed || c.AccountID != "" {
					t.Fatalf("connection %+v, want failed with no account", c)
				}
				if !h.revoker.has("fake-at-tg-2") || !h.revoker.has("fake-rt-tg-2") {
					t.Fatalf("issued tokens not revoked: %v", h.revoker.tokens)
				}
				if len(h.msgr.all()) != 0 {
					t.Fatal("a confirm card was sent")
				}
			})
		}
	})
}

// S1-L14: linking for a server without a recorded owner acceptance is
// refused while its flag is off. alice is off by default, is refused at
// every step when its flag goes off mid-flow, and asks for iot:view only.
func TestLinking_S1L14_ServerFlagGatesLinking(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()

		for _, srv := range linking.FlagServers() {
			if on, err := linking.ServerFlag(func(string) string { return "" }, srv); err != nil || on {
				t.Fatalf("%s default %v %v, want off", srv, on, err)
			}
		}
		if _, err := linking.ServerFlag(func(k string) string {
			if k == "PA_SERVER_ALICE_ENABLED" {
				return "yes"
			}
			return ""
		}, connection.ServerAlice); !errors.Is(err, linking.ErrConfig) {
			t.Fatalf("a non-boolean flag accepted: %v", err)
		}

		h := newHarness(t, s, false)
		if _, err := h.svc.StartLink(ctx, principal(t, h.alice), connection.ServerAlice); !errors.Is(err, linking.ErrServerDisabled) {
			t.Fatalf("alice with the flag off: %v", err)
		}
		if cs, err := h.m.List(ctx, h.alice); err != nil || len(cs) != 0 {
			t.Fatalf("a connection was created with the flag off: %d %v", len(cs), err)
		}

		// Turned off mid-flow: each later step refuses.
		h.setEnabled(connection.ServerAlice, true)
		authURL := h.begin(h.start(connection.ServerAlice))
		if scope := mustQuery(t, authURL).Get("scope"); scope != "iot:view" {
			t.Fatalf("alice scope %q, want iot:view", scope)
		}
		cb := h.as[connection.ServerAlice].authorize(t, authURL, linking.Account{ID: "yandex-uid-1"})
		h.setEnabled(connection.ServerAlice, false)
		if _, err := h.svc.Callback(ctx, connection.ServerAlice, cb); !errors.Is(err, linking.ErrServerDisabled) {
			t.Fatalf("callback with the flag off: %v", err)
		}
		h.setEnabled(connection.ServerAlice, true)
		res, err := h.svc.Callback(ctx, connection.ServerAlice, cb)
		if err != nil {
			t.Fatal(err)
		}
		deep, _, err := h.svc.Handoff(ctx, res.Handoff)
		if err != nil {
			t.Fatal(err)
		}
		h.setEnabled(connection.ServerAlice, false)
		if err := h.svc.Complete(ctx, h.initData(h.alice, startapp(t, deep))); !errors.Is(err, linking.ErrServerDisabled) {
			t.Fatalf("complete with the flag off: %v", err)
		}
		if n := h.as[connection.ServerAlice].exchangeCount(); n != 0 {
			t.Fatalf("exchanged with the flag off")
		}
		h.setEnabled(connection.ServerAlice, true)
		if err := h.svc.Complete(ctx, h.initData(h.alice, startapp(t, deep))); err != nil {
			t.Fatal(err)
		}
		confirm, _ := confirmData(h.msgr.all()[0].card)
		h.setEnabled(connection.ServerAlice, false)
		if _, err := h.svc.HandleCallback(ctx, callbackUpdate(t, h.alice, confirm)); !errors.Is(err, linking.ErrServerDisabled) {
			t.Fatalf("confirm with the flag off: %v", err)
		}
		if h.state(connection.ServerAlice) == connection.StateActive {
			t.Fatal("alice active with the flag off")
		}
	})
}

func mustQuery(t *testing.T, raw string) url.Values {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query()
}

// TestLinking_CancelAndSweep: Cancel fails the connection and revokes its
// tokens; the sweeper fails a connection whose card was never answered.
func TestLinking_CancelAndSweep(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		h := newHarness(t, s, false)
		_, cancel := confirmData(h.toConfirm(connection.ServerTG, h.tgLogin(h.alice)))
		if handled, err := h.svc.HandleCallback(ctx, callbackUpdate(t, h.alice, cancel)); !handled || err != nil {
			t.Fatalf("cancel: %v", err)
		}
		if h.state(connection.ServerTG) != connection.StateFailed || !h.revoker.has("fake-at-tg-2") {
			t.Fatalf("cancel: state %s, revoked %v", h.state(connection.ServerTG), h.revoker.tokens)
		}

		h2 := newHarness(t, s, false)
		h2.toConfirm(connection.ServerTG, h2.tgLogin(h2.alice))
		h2.clock.Add(linking.ConfirmTTL)
		res, err := h2.svc.ExpireStale(ctx, 1000)
		if err != nil || res.Failed < 1 {
			t.Fatalf("sweep: %+v %v", res, err)
		}
		if h2.state(connection.ServerTG) != connection.StateFailed || !h2.revoker.has("fake-at-tg-2") {
			t.Fatalf("sweep: state %s, revoked %v", h2.state(connection.ServerTG), h2.revoker.tokens)
		}
		again, err := h2.svc.ExpireStale(ctx, 1000)
		if err != nil {
			t.Fatal(err)
		}
		_ = again // other tests' rows may be listed on a shared Postgres; ours is retired
		if _, err := h2.svc.HandleCallback(ctx, callbackUpdate(t, h2.alice, "pa:lc:"+strings.Repeat("A", 43))); err == nil {
			t.Fatal("unknown confirm accepted")
		}
	})
}

// TestLinking_UnrelatedCallbackNotHandled: a callback that is not a linking
// button is left for the next handler.
func TestLinking_UnrelatedCallbackNotHandled(t *testing.T) {
	h := newHarness(t, newSQLiteStore(t), false)
	if handled, err := h.svc.HandleCallback(context.Background(), callbackUpdate(t, h.alice, "pa:cv:xyz")); handled || err != nil {
		t.Fatalf("handled=%v err=%v", handled, err)
	}
}

// flakyStore fails the sealed read once armed, as an unreadable row would.
type flakyStore struct {
	connection.Store
	armed *bool
}

func (f flakyStore) GetPAConnectionSealed(ctx context.Context, p int64, id string) (connection.Connection, connection.Sealed, error) {
	if *f.armed {
		return connection.Connection{}, connection.Sealed{}, errors.New("injected: row unreadable")
	}
	return f.Store.GetPAConnectionSealed(ctx, p, id)
}

// armingTokens arms the store as the code exchange returns, so the next
// sealed read (CompleteExchange's) fails.
type armingTokens struct {
	linking.TokenClient
	armed *bool
}

func (a armingTokens) ExchangeCode(ctx context.Context, server connection.Server, req linking.ExchangeRequest) ([]byte, error) {
	raw, err := a.TokenClient.ExchangeCode(ctx, server, req)
	*a.armed = true
	return raw, err
}

// TestLinking_CompleteExchangeUnreadableRowRevokes is the caller half of the
// CompleteExchange contract (#1332 follow-up): when the row cannot be read
// after the exchange, the manager cannot revoke what was issued, so
// Complete revokes from the raw response itself.
func TestLinking_CompleteExchangeUnreadableRowRevokes(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		h := newHarness(t, s, false)
		armed := false
		h.rebuild(flakyStore{Store: s, armed: &armed}, armingTokens{TokenClient: tokenClient{h.as}, armed: &armed})
		code := h.toCompletion(connection.ServerTG, h.tgLogin(h.alice))
		err := h.svc.Complete(ctx, h.initData(h.alice, code))
		if !errors.Is(err, connection.ErrUnreadable) {
			t.Fatalf("err %v, want ErrUnreadable", err)
		}
		if !h.revoker.has("fake-at-tg-2") || !h.revoker.has("fake-rt-tg-2") {
			t.Fatalf("tokens of an unreadable row not revoked: %v", h.revoker.tokens)
		}
		if len(h.msgr.all()) != 0 {
			t.Fatal("card sent")
		}
	})
}

// faultStore injects manager-store failures after a linking secret has
// been consumed.
type faultStore struct {
	connection.Store
	mu          *sync.Mutex
	failTo      connection.State // fail transitions into this state
	failSealed  bool             // fail every sealed read
	failSealFor string           // fail sealed reads of this connection id
	// beforeActivate runs once, just before a pending_confirm -> active
	// transition reaches the store.
	beforeActivate func()
}

func (f *faultStore) TransitionPAConnection(ctx context.Context, p int64, id string, t connection.Transition) (connection.Connection, error) {
	f.mu.Lock()
	to := f.failTo
	before := f.beforeActivate
	if t.To == connection.StateActive {
		f.beforeActivate = nil
	}
	f.mu.Unlock()
	if before != nil && t.To == connection.StateActive {
		before()
	}
	if to != "" && t.To == to {
		return connection.Connection{}, errors.New("injected: transition write failed")
	}
	return f.Store.TransitionPAConnection(ctx, p, id, t)
}

// ActivatePAConnection is the activation edge Manager.Confirm takes; it
// gets the same injected faults as a transition into active.
func (f *faultStore) ActivatePAConnection(ctx context.Context, p int64, id string, t connection.Transition) (connection.Connection, []connection.Superseded, error) {
	f.mu.Lock()
	to := f.failTo
	before := f.beforeActivate
	f.beforeActivate = nil
	f.mu.Unlock()
	if before != nil {
		before()
	}
	if to == connection.StateActive {
		return connection.Connection{}, nil, errors.New("injected: activation write failed")
	}
	return f.Store.ActivatePAConnection(ctx, p, id, t)
}

func (f *faultStore) GetPAConnectionSealed(ctx context.Context, p int64, id string) (connection.Connection, connection.Sealed, error) {
	f.mu.Lock()
	fail := f.failSealed || (f.failSealFor != "" && f.failSealFor == id)
	f.mu.Unlock()
	if fail {
		return connection.Connection{}, connection.Sealed{}, errors.New("injected: row unreadable")
	}
	return f.Store.GetPAConnectionSealed(ctx, p, id)
}

func (f *faultStore) set(fn func(f *faultStore)) { f.mu.Lock(); fn(f); f.mu.Unlock() }

// TestLinking_StrandedConfirmIsSweptAndRevoked: the confirm nonce is
// consumed, then the activation write fails. The row is left in
// pending_confirm holding live tokens, and a second press is refused
// because the nonce is spent. The pending-age sweep must fail it and
// revoke its tokens (T1 step 5, T3).
func TestLinking_StrandedConfirmIsSweptAndRevoked(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		h := newHarness(t, s, false)
		fs := &faultStore{Store: s, mu: &sync.Mutex{}}
		h.rebuild(fs, tokenClient{h.as})
		confirm, _ := confirmData(h.toConfirm(connection.ServerTG, h.tgLogin(h.alice)))
		fs.set(func(f *faultStore) { f.failTo = connection.StateActive })
		if _, err := h.svc.HandleCallback(ctx, callbackUpdate(t, h.alice, confirm)); err == nil {
			t.Fatal("confirm succeeded despite the failed write")
		}
		fs.set(func(f *faultStore) { f.failTo = "" })
		if _, err := h.svc.HandleCallback(ctx, callbackUpdate(t, h.alice, confirm)); !errors.Is(err, linking.ErrRefused) {
			t.Fatalf("second press: %v", err)
		}
		if h.state(connection.ServerTG) != connection.StatePendingConfirm || h.revoker.count() != 0 {
			t.Fatalf("precondition: state %s, revoked %v", h.state(connection.ServerTG), h.revoker.tokens)
		}
		// The store stamps transitions with the wall clock; the margins
		// cover the test's own run time.
		h.clock.Add(linking.PendingMaxAge - time.Minute)
		if _, err := h.svc.ExpireStale(ctx, 1000); err != nil {
			t.Fatal(err)
		}
		if h.state(connection.ServerTG) != connection.StatePendingConfirm {
			t.Fatal("swept before PendingMaxAge")
		}
		h.clock.Add(2 * time.Minute)
		res, err := h.svc.ExpireStale(ctx, 1000)
		if err != nil || res.Failed < 1 {
			t.Fatalf("sweep %+v %v", res, err)
		}
		if h.state(connection.ServerTG) != connection.StateFailed || !h.revoker.has("fake-at-tg-2") || !h.revoker.has("fake-rt-tg-2") {
			t.Fatalf("stranded confirm: state %s, revoked %v", h.state(connection.ServerTG), h.revoker.tokens)
		}
	})
}

// TestLinking_StrandedReturnIsSwept: the completion code is consumed, then
// reading the sealed authorization code fails. The connection stays in
// pending_return with no live secret; the sweep fails it.
func TestLinking_StrandedReturnIsSwept(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		h := newHarness(t, s, false)
		fs := &faultStore{Store: s, mu: &sync.Mutex{}}
		h.rebuild(fs, tokenClient{h.as})
		code := h.toCompletion(connection.ServerTG, h.tgLogin(h.alice))
		fs.set(func(f *faultStore) { f.failSealed = true })
		if err := h.svc.Complete(ctx, h.initData(h.alice, code)); err == nil {
			t.Fatal("completed with an unreadable code")
		}
		fs.set(func(f *faultStore) { f.failSealed = false })
		if n := h.as[connection.ServerTG].exchangeCount(); n != 0 {
			t.Fatalf("exchanged %d times", n)
		}
		h.clock.Add(linking.PendingMaxAge + time.Minute)
		if res, err := h.svc.ExpireStale(ctx, 1000); err != nil || res.Failed < 1 {
			t.Fatalf("sweep %+v %v", res, err)
		}
		if h.state(connection.ServerTG) != connection.StateFailed {
			t.Fatalf("state %s, want failed", h.state(connection.ServerTG))
		}
	})
}

// TestLinking_SweepContinuesPastUnreadableRow: one connection the sweep
// cannot read is counted and skipped; the others behind it still expire.
func TestLinking_SweepContinuesPastUnreadableRow(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		h := newHarness(t, s, true)
		fs := &faultStore{Store: s, mu: &sync.Mutex{}}
		h.rebuild(fs, tokenClient{h.as})
		h.toConfirm(connection.ServerTG, h.tgLogin(h.alice))
		h.clock.Add(time.Second) // the tg row sorts first by age
		h.toConfirm(connection.ServerAlice, linking.Account{ID: "yandex-uid-1"})
		bad := h.connection(connection.ServerTG)
		fs.set(func(f *faultStore) { f.failSealFor = bad.ID })
		h.clock.Add(linking.PendingMaxAge)
		res, err := h.svc.ExpireStale(ctx, 1000)
		if err == nil || res.Errors < 1 {
			t.Fatalf("sweep %+v %v: the unreadable row is not reported", res, err)
		}
		if h.state(connection.ServerAlice) != connection.StateFailed {
			t.Fatalf("the row behind the unreadable one was not swept: %s", h.state(connection.ServerAlice))
		}
		if h.state(connection.ServerTG) != connection.StatePendingConfirm {
			t.Fatalf("unreadable row state %s", h.state(connection.ServerTG))
		}
		fs.set(func(f *faultStore) { f.failSealFor = "" })
		if _, err := h.svc.ExpireStale(ctx, 1000); err != nil {
			t.Fatal(err)
		}
		if h.state(connection.ServerTG) != connection.StateFailed {
			t.Fatalf("not retried on the next sweep: %s", h.state(connection.ServerTG))
		}
	})
}

// The pending-age sweep must never fail a legitimate slow flow. For every
// pending state, the user waits until one second before that step's secret
// expires, a sweep runs, and the flow still completes to active. A row left
// in the same state past PendingMaxAge is failed. The store stamps
// transitions with the Manager's clock, so the ages here are exact.
func TestLinking_SweepSparesSlowFlowInEveryPendingState(t *testing.T) {
	steps := []struct {
		state connection.State
		wait  time.Duration
	}{
		{connection.StatePendingLink, linking.LinkTokenTTL},
		{connection.StatePendingOAuth, linking.StateTTL},
		{connection.StatePendingReturn, linking.CompletionTTL},
		{connection.StatePendingConfirm, linking.ConfirmTTL},
	}
	for _, st := range steps {
		t.Run(string(st.state), func(t *testing.T) {
			forEachDialect(t, func(t *testing.T, s *db.Store) {
				ctx := context.Background()
				for _, slow := range []bool{true, false} {
					h := newHarness(t, s, false)
					// Run an hour ahead of the wall clock: a row stamped with
					// the store's own clock would look an hour old and be swept
					// mid-flow.
					h.clock.Add(time.Hour)
					login := h.tgLogin(h.alice)
					server := connection.ServerTG
					// pause runs at the step under test: a wait just short of
					// the step's secret TTL (the flow must survive it), or past
					// PendingMaxAge (the row must be failed).
					pause := func(at connection.State) bool {
						if at != st.state {
							return true
						}
						if got := h.state(server); got != st.state {
							t.Fatalf("at %s the row is %s", st.state, got)
						}
						if slow {
							h.clock.Add(st.wait - time.Second)
						} else {
							h.clock.Add(linking.PendingMaxAge + time.Second)
						}
						if _, err := h.svc.ExpireStale(ctx, 1000); err != nil {
							t.Fatal(err)
						}
						if !slow {
							if got := h.state(server); got != connection.StateFailed {
								t.Fatalf("%s past PendingMaxAge: state %s, want failed", st.state, got)
							}
							return false
						}
						if got := h.state(server); got != st.state {
							t.Fatalf("slow %s flow swept: state %s", st.state, got)
						}
						return true
					}
					link := h.start(server)
					if !pause(connection.StatePendingLink) {
						continue
					}
					authURL := h.begin(link)
					if !pause(connection.StatePendingOAuth) {
						continue
					}
					res, err := h.svc.Callback(ctx, server, h.as[server].authorize(t, authURL, login))
					if err != nil {
						t.Fatalf("callback: %v", err)
					}
					if !pause(connection.StatePendingReturn) {
						continue
					}
					deep, _, err := h.svc.Handoff(ctx, res.Handoff)
					if err != nil {
						t.Fatalf("handoff: %v", err)
					}
					if err := h.svc.Complete(ctx, h.initData(h.alice, startapp(t, deep))); err != nil {
						t.Fatalf("complete: %v", err)
					}
					if !pause(connection.StatePendingConfirm) {
						continue
					}
					cards := h.msgr.all()
					confirm, _ := confirmData(cards[len(cards)-1].card)
					if _, err := h.svc.HandleCallback(ctx, callbackUpdate(t, h.alice, confirm)); err != nil {
						t.Fatalf("confirm after a slow %s: %v", st.state, err)
					}
					if got := h.state(server); got != connection.StateActive {
						t.Fatalf("slow %s flow ended %s, want active", st.state, got)
					}
				}
			})
		})
	}
}

// sealedTokens is the length of the connection's stored token blob: zero
// once a terminal state wiped it.
func (h *harness) sealedTokens(id string) int {
	h.t.Helper()
	var b []byte
	if err := h.s.DB.QueryRow(`SELECT sealed_tokens FROM pa_connections WHERE id = $1`, id).Scan(&b); err != nil {
		h.t.Fatal(err)
	}
	return len(b)
}

// A confirm needs the principal's current consent, read again at the press:
// with the link secrets still in place (so only this check stands in the
// way), no consent row, a withdrawn one, one for an older text, or one that
// cannot be read each fail the connection, wipe its tokens and revoke them
// at the server. Nothing is activated and no users row is created.
func TestLinking_ConfirmNeedsConsent(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		for name, lose := range map[string]string{
			"no row":     `DELETE FROM pa_consents WHERE principal = $1`,
			"withdrawn":  `UPDATE pa_consents SET state = 'withdrawn' WHERE principal = $1`,
			"stale":      `UPDATE pa_consents SET version = 'pa-data-flow/v0' WHERE principal = $1`,
			"unreadable": `UPDATE pa_consents SET state = 'bogus' WHERE principal = $1`,
		} {
			t.Run(name, func(t *testing.T) {
				ctx := context.Background()
				h := newHarness(t, s, false)
				confirm, _ := confirmData(h.toConfirm(connection.ServerTG, h.tgLogin(h.alice)))
				if _, err := s.DB.Exec(lose, h.alice); err != nil {
					t.Fatal(err)
				}
				handled, err := h.svc.HandleCallback(ctx, callbackUpdate(t, h.alice, confirm))
				if !handled || !errors.Is(err, linking.ErrNoConsent) {
					t.Fatalf("confirm without consent: handled=%v err=%v", handled, err)
				}
				c := h.connection(connection.ServerTG)
				if c.State != connection.StateFailed || h.sealedTokens(c.ID) != 0 || h.revoker.count() == 0 {
					t.Fatalf("state %s, sealed %d bytes, %d revoked", c.State, h.sealedTokens(c.ID), h.revoker.count())
				}
				if _, err := s.UserIDByTelegramID(ctx, h.alice); !errors.Is(err, db.ErrUserNotFound) {
					t.Fatalf("a users row was created without consent: %v", err)
				}
			})
		}
	})
}

// /forget and /consent withdraw delete the principal's link secrets in
// their own transaction, so a confirm card shown before them cannot finish
// after them, even with consent still in place (/forget keeps it).
// AbandonPending then fails the pending connection and revokes its tokens,
// and leaves an active connection alone.
func TestLinking_ForgetAndWithdrawRetireUnfinishedLinks(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		for name, forget := range map[string]func(h *harness, tx *sql.Tx) error{
			"forget": func(h *harness, tx *sql.Tx) error {
				return s.ForgetPAConversations(context.Background(), tx, h.alice)
			},
			"withdraw": func(h *harness, tx *sql.Tx) error {
				return s.WithdrawPAConsent(context.Background(), tx, h.alice, h.clock.Now())
			},
		} {
			t.Run(name, func(t *testing.T) {
				ctx := context.Background()
				h := newHarness(t, s, true)
				// An active alice connection, then an unfinished tg link.
				aliceConfirm, _ := confirmData(h.toConfirm(connection.ServerAlice, linking.Account{ID: "alice:acct-1", DisplayName: "Alice"}))
				if _, err := h.svc.HandleCallback(ctx, callbackUpdate(t, h.alice, aliceConfirm)); err != nil {
					t.Fatalf("alice confirm: %v", err)
				}
				confirm, _ := confirmData(h.toConfirm(connection.ServerTG, h.tgLogin(h.alice)))
				h.inTx(func(tx *sql.Tx) error { return forget(h, tx) })
				var left int
				if err := s.DB.QueryRow(`SELECT COUNT(*) FROM pa_link_secrets WHERE principal = $1`, h.alice).Scan(&left); err != nil || left != 0 {
					t.Fatalf("%d link secrets left (%v)", left, err)
				}
				if name == "forget" {
					// /forget keeps consent, so only the deleted secret refuses this.
					h.consent(h.alice)
				}
				handled, err := h.svc.HandleCallback(ctx, callbackUpdate(t, h.alice, confirm))
				if !handled || err == nil || h.state(connection.ServerTG) == connection.StateActive {
					t.Fatalf("confirm after %s: handled=%v err=%v state %s", name, handled, err, h.state(connection.ServerTG))
				}
				before := h.revoker.count()
				n, err := h.svc.AbandonPending(ctx, h.alice)
				if err != nil || n != 1 {
					t.Fatalf("AbandonPending: %d %v", n, err)
				}
				c := h.connection(connection.ServerTG)
				if c.State != connection.StateFailed || h.sealedTokens(c.ID) != 0 || h.revoker.count() <= before {
					t.Fatalf("tg after retire: state %s, sealed %d bytes, revoked %d->%d", c.State, h.sealedTokens(c.ID), before, h.revoker.count())
				}
				if st := h.state(connection.ServerAlice); st != connection.StateActive {
					t.Fatalf("the finished alice link was touched: %s", st)
				}
			})
		}
	})
}

// The review's race on the confirm button: a /consent withdraw that
// commits after the button's own consent check and before the activation.
// The activation reads consent again under the principal lock, refuses
// (connection.ErrNoConsent), and the button fails the connection and
// revokes its tokens: no active connection and no stored tokens remain.
func TestLinking_WithdrawAfterConsentCheckRefusesConfirm(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		h := newHarness(t, s, false)
		fs := &faultStore{Store: s, mu: &sync.Mutex{}}
		h.rebuild(fs, tokenClient{h.as})
		confirm, _ := confirmData(h.toConfirm(connection.ServerTG, h.tgLogin(h.alice)))
		fs.set(func(f *faultStore) {
			f.beforeActivate = func() {
				h.inTx(func(tx *sql.Tx) error {
					if err := s.LockPAPrincipal(ctx, tx, h.alice); err != nil {
						return err
					}
					return s.WithdrawPAConsent(ctx, tx, h.alice, h.clock.Now())
				})
			}
		})
		before := h.revoker.count()
		handled, err := h.svc.HandleCallback(ctx, callbackUpdate(t, h.alice, confirm))
		if !handled || !errors.Is(err, linking.ErrNoConsent) || !errors.Is(err, connection.ErrNoConsent) {
			t.Fatalf("confirm after a racing withdraw: handled=%v err=%v", handled, err)
		}
		c := h.connection(connection.ServerTG)
		if c.State != connection.StateFailed || h.sealedTokens(c.ID) != 0 || h.revoker.count() <= before {
			t.Fatalf("state %s, sealed %d bytes, revoked %d->%d", c.State, h.sealedTokens(c.ID), before, h.revoker.count())
		}
	})
}

// TestLinking_DisableAfterAdmissionRefusesConfirm (#1318 C2b, review P3 of
// #1390): an admin disable that commits after HandleCallback's admission
// check is still seen by the activation, under the principal lock; the
// connection is failed and its tokens revoked, never activated.
func TestLinking_DisableAfterAdmissionRefusesConfirm(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		h := newHarness(t, s, false)
		fs := &faultStore{Store: s, mu: &sync.Mutex{}}
		h.rebuild(fs, tokenClient{h.as})
		confirm, _ := confirmData(h.toConfirm(connection.ServerTG, h.tgLogin(h.alice)))
		fs.set(func(f *faultStore) {
			f.beforeActivate = func() {
				if err := s.SetPAPrincipalDisabled(ctx, h.alice, 4242001, "test", h.clock.Now()); err != nil {
					t.Error(err)
				}
			}
		})
		t.Cleanup(func() { _ = s.ClearPAPrincipalDisabled(context.Background(), h.alice) })
		before := h.revoker.count()
		handled, err := h.svc.HandleCallback(ctx, callbackUpdate(t, h.alice, confirm))
		if !handled || !errors.Is(err, linking.ErrPrincipalRefused) || !errors.Is(err, connection.ErrPrincipalDisabled) {
			t.Fatalf("confirm after a racing disable: handled=%v err=%v", handled, err)
		}
		c := h.connection(connection.ServerTG)
		if c.State != connection.StateFailed || h.sealedTokens(c.ID) != 0 || h.revoker.count() <= before {
			t.Fatalf("state %s, sealed %d bytes, revoked %d->%d", c.State, h.sealedTokens(c.ID), before, h.revoker.count())
		}
	})
}
