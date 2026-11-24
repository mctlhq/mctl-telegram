package pa_test

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"slices"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/pa"
	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/connector"
	"github.com/mctlhq/mctl-telegram/internal/pa/convo"
	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
)

// actionEnv is a permEnv with the seam the tool resolver will use
// (pa.ActionGate) over the same switch and scope table as the rest.
type actionEnv struct {
	*permEnv
	gate *pa.ActionGate
}

func newActionEnv(t *testing.T, s *db.Store) *actionEnv {
	t.Helper()
	return newActionEnvScopes(t, s, testWriteScopes(t))
}

// newActionEnvScopes is newActionEnv over scopes; nil is the compiled
// table.
func newActionEnvScopes(t *testing.T, s *db.Store, scopes *connection.WriteScopes) *actionEnv {
	t.Helper()
	e := &actionEnv{permEnv: newPermEnvScopes(t, s, scopes)}
	var err error
	e.gate, err = pa.NewActionGate(s, func() (bool, error) {
		if e.writesErr.Load() {
			// The value next to the error is what a careless reader would use.
			return true, errInjected
		}
		return e.writes.Load(), nil
	}, scopes)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

var errInjected = sql.ErrConnDone

// v1Only removes user's consent to actions: the principal of a deployment
// that turned writes on after they consented to the data flow.
func (e *actionEnv) v1Only(user int64) {
	e.t.Helper()
	if _, err := e.store.DB.Exec(`DELETE FROM pa_action_consents WHERE principal = $1`, user); err != nil {
		e.t.Fatal(err)
	}
}

// offered is what a claim may carry for conn: the write tools of tools and
// why the others are withheld.
func (e *actionEnv) offered(user int64, conn connection.Connection, tools ...string) ([]string, pa.WithheldReason) {
	e.t.Helper()
	var out []string
	var why pa.WithheldReason
	e.inTx(func(tx *sql.Tx) error {
		var err error
		out, why, err = e.gate.Offer(context.Background(), tx, user, conn.ID, tools)
		return err
	})
	return out, why
}

func (e *actionEnv) actionConsent(user int64) string {
	e.t.Helper()
	got := e.strings(`SELECT version || '|' || text_sha256 || '|' || state FROM pa_action_consents WHERE principal = $1`, user)
	if len(got) > 1 {
		e.t.Fatalf("%d action consent rows", len(got))
	}
	if len(got) == 0 {
		return ""
	}
	return got[0]
}

// actionArtifacts counts everything the consent to actions and the write
// scope can leave behind: prompts, their buttons and the two notices.
func (e *actionEnv) actionArtifacts() int {
	e.t.Helper()
	return e.h.Count(`SELECT COUNT(*) FROM pa_callbacks WHERE action LIKE 'actions_accept%'`) +
		e.h.Count(`SELECT COUNT(*) FROM pa_outbox WHERE kind IN ('action_consent_prompt', 'action_consent_prompt_ru',
			'action_consent_accepted', 'action_consent_needed', 'write_scope_needed')`)
}

func (e *actionEnv) texts(user int64) []string {
	var out []string
	for _, m := range e.h.MessagesTo(user) {
		out = append(out, m.Text)
	}
	return out
}

func count(list []string, v string) int {
	n := 0
	for _, s := range list {
		if s == v {
			n++
		}
	}
	return n
}

// ask sends text as user and returns what answered it: the replies the
// conversation layer queued and the texts of the screens a /permissions
// command sent.
func (e *actionEnv) ask(user int64, text string) (replies []pa.Reply, screens []string) {
	e.t.Helper()
	before := len(e.h.Replies(user))
	for _, m := range e.say(user, text) {
		screens = append(screens, m.Text)
	}
	return e.h.Replies(user)[before:], screens
}

// wantActionPrompt asserts text is answered with the English
// action-consent prompt and nothing else, and returns its button.
func (e *actionEnv) wantActionPrompt(user int64, text string) string {
	e.t.Helper()
	replies, screens := e.ask(user, text)
	if !slices.Equal(replies, []pa.Reply{pa.ReplyActionConsentPrompt}) || len(screens) != 0 {
		e.t.Fatalf("%q: answered %v and %q, want the consent to actions alone", text, replies, screens)
	}
	r, button := e.h.LastReply(user)
	if r != pa.ReplyActionConsentPrompt || button == "" {
		e.t.Fatalf("%q: prompt %q with the button %q", text, r, button)
	}
	return button
}

// wantReply asserts text is answered with the one reply want and no
// screen.
func (e *actionEnv) wantReply(user int64, text string, want pa.Reply) {
	e.t.Helper()
	if replies, screens := e.ask(user, text); !slices.Equal(replies, []pa.Reply{want}) || len(screens) != 0 {
		e.t.Fatalf("%q: answered %v and %q, want %q", text, replies, screens, want)
	}
}

// TestActionConsent_DataFlowConsentAloneGetsNoAction is the v1-only
// principal with writes on (#1320 P2-S14c): the claim carries no write
// tool, a forged write call and an approved action are refused,
// /permissions shows the consent to actions instead of granting, and
// reads work as before. Accepting it allows all of that; /consent
// withdraw takes both consents away again.
func TestActionConsent_DataFlowConsentAloneGetsNoAction(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newActionEnv(t, s)
		e.v1Only(alice)

		// The claim: no write tool, for the consent.
		if got, why := e.offered(alice, e.home, permTool, "alice_media_control"); len(got) != 0 || why != pa.WithheldConsent {
			t.Fatalf("offered %v (%s) without the consent to actions", got, why)
		}
		// Bob consented, and is offered the tools of his own connection.
		if got, why := e.offered(bob, e.bobHome, permTool); !slices.Equal(got, []string{permTool}) || why != pa.WithheldNone {
			t.Fatalf("Bob is offered %v (%s)", got, why)
		}

		// A forged write call: refused, nothing written, and Alice is told
		// once, however often the model asks.
		for range 2 {
			a := e.call(e.token, writeCall(writeArgs))
			e.h.Loop().WaitDeliveries()
			if a.code != http.StatusForbidden || a.Stop != connector.ReasonActionConsentRequired {
				t.Fatalf("forged write call answered %+v", a)
			}
		}
		e.nothingWritten()
		if n := count(e.texts(alice), safetext.TextActionConsentNeeded.String()); n != 1 {
			t.Fatalf("the notice was sent %d times, want once", n)
		}

		// An approval that exists anyway is not sent.
		a := e.writeEnv.approved(writeArgs)
		if out := e.dispatch(a.ID); out.Status != connector.StatusRefused || out.Reason != connector.ReasonActionConsentRequired {
			t.Fatalf("approved action without the consent: %+v", out)
		}
		e.h.DeliverNow(alice)
		if n := len(e.ep.sent()); n != 0 {
			t.Fatalf("%d writes sent without the consent to actions", n)
		}
		// That approval was made by hand for the run this test calls from,
		// and a run gets one card: it is removed, so the card asked for
		// below is the run's first.
		if _, err := s.DB.Exec(`DELETE FROM pa_approvals WHERE id = $1`, a.ID); err != nil {
			t.Fatal(err)
		}

		// /permissions and a grant show the consent to actions; nothing is
		// listed or granted.
		e.wantActionPrompt(alice, "/permissions")
		accept := e.wantActionPrompt(alice, grantCmd)
		e.nothingGranted("without the consent to actions")
		// Revoking needs no consent to actions: it only removes authority.
		if replies, screens := e.ask(alice, "/permissions revoke prm_none"); len(replies) != 0 ||
			!slices.Equal(screens, []string{safetext.TextPermissionGone.String()}) {
			t.Fatalf("a revoke without the consent to actions answered %v and %q", replies, screens)
		}

		// Reads are what they were.
		if a := e.call(e.token, req("tg", "get_messages", e.connA.ID)); a.code != http.StatusOK {
			t.Fatalf("a read without the consent to actions: %+v", a)
		}
		// So is an ordinary message: no prompt.
		if replies, screens := e.ask(alice, "what is in my inbox?"); len(replies) != 0 ||
			slices.Contains(screens, safetext.TextActionConsentNeeded.String()) {
			t.Fatalf("an ordinary message was answered with %v and %q", replies, screens)
		}

		// Accepting records the version and the hash of the text shown.
		if r := e.press(alice, accept); r != pa.ReplyActionConsentAccepted {
			t.Fatalf("press answered %q", r)
		}
		want := convo.ActionConsentVersion + "|" + convo.ActionConsentTextSHA256For(false) + "|accepted"
		if got := e.actionConsent(alice); got != want {
			t.Fatalf("action consent row %q, want %q", got, want)
		}
		if r := e.press(alice, accept); r != pa.ReplyUnknownButton {
			t.Fatalf("second press answered %q", r)
		}

		// Now everything is allowed.
		if got, why := e.offered(alice, e.home, permTool); !slices.Equal(got, []string{permTool}) || why != pa.WithheldNone {
			t.Fatalf("offered %v (%s) with the consent to actions", got, why)
		}
		if r := e.press(alice, e.button(e.one(alice, grantCmd), safetext.LabelPermissionGrant)); r != pa.ReplyPermissionGranted {
			t.Fatalf("grant answered %q", r)
		}
		if rows := e.rows(); len(rows) != 1 || rows[0].revoked != 0 {
			t.Fatalf("permission rows %+v", rows)
		}
		if a := e.call(e.token, writeCall(writeArgs)); a.code != http.StatusOK || a.Status != connector.StatusApprovalPending {
			t.Fatalf("write call with the consent to actions: %+v", a)
		}
		e.h.Loop().WaitDeliveries()
		pending := e.strings(`SELECT id FROM pa_approvals WHERE principal = $1 AND status = 'pending'`, alice)
		if len(pending) != 1 {
			t.Fatalf("pending approvals %v", pending)
		}

		// /consent withdraw: both consents are gone, the card is cancelled
		// and the permission revoked.
		e.h.Text(alice, "/consent withdraw")
		want = convo.ActionConsentVersion + "|" + convo.ActionConsentTextSHA256For(false) + "|withdrawn"
		if got := e.actionConsent(alice); got != want {
			t.Fatalf("action consent row after withdraw %q", got)
		}
		if rows := e.rows(); len(rows) != 1 || rows[0].revoked == 0 {
			t.Fatalf("permission rows after withdraw %+v", rows)
		}
		if got := e.strings(`SELECT id FROM pa_approvals WHERE principal = $1 AND status IN ('pending', 'approved')`, alice); len(got) != 0 {
			t.Fatalf("waiting actions after withdraw: %v", got)
		}
		if got, why := e.offered(alice, e.home, permTool); len(got) != 0 || why != pa.WithheldConsent {
			t.Fatalf("offered %v (%s) after withdraw", got, why)
		}
		e.wantReply(alice, "/permissions", pa.ReplyConsentPrompt)

		// The data-flow consent given again is not the consent to actions.
		e.h.Consent(alice)
		if got, why := e.offered(alice, e.home, permTool); len(got) != 0 || why != pa.WithheldConsent {
			t.Fatalf("offered %v (%s) after the data-flow consent alone", got, why)
		}
		e.wantActionPrompt(alice, "/permissions")
	})
}

// TestActionConsent_ShownOnConsentCommand: with writes on, /consent shows
// the data-flow text to a principal who has not given it and the actions
// text to one who has; the actions button of someone without the
// data-flow consent records nothing. The Russian prompt binds the Russian
// text.
func TestActionConsent_ShownOnConsentCommand(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newActionEnv(t, s)
		e.v1Only(alice)
		accept := e.wantActionPrompt(alice, "/consent")

		// Withdrawn in between: the button asks for the data-flow consent
		// and records nothing.
		if _, err := s.DB.Exec(`UPDATE pa_consents SET state = $1 WHERE principal = $2`, string(convo.ConsentWithdrawn), alice); err != nil {
			t.Fatal(err)
		}
		if r := e.press(alice, accept); r != pa.ReplyConsentPrompt {
			t.Fatalf("press without the data-flow consent answered %q", r)
		}
		if got := e.actionConsent(alice); got != "" {
			t.Fatalf("action consent recorded without the data-flow consent: %q", got)
		}
		// /consent now shows the data-flow text first.
		e.wantReply(alice, "/consent", pa.ReplyConsentPrompt)
		e.h.Consent(alice)
		if r := e.press(alice, e.wantActionPrompt(alice, "/consent")); r != pa.ReplyActionConsentAccepted {
			t.Fatalf("press answered %q", r)
		}
		// Both given: /consent is the data-flow prompt it always was.
		e.wantReply(alice, "/consent", pa.ReplyConsentPrompt)
	})
}

// TestActionConsent_WritesOffNeverShown: with PA_WRITES_ENABLED off, or
// unreadable, nobody is shown the consent to actions and every answer is
// the one a build without it gives, whether or not the principal accepted
// it earlier. An acceptance outlives the switch.
func TestActionConsent_WritesOffNeverShown(t *testing.T) {
	script := []string{"/consent", "/permissions", grantCmd, "/permissions revoke prm_none", "/consent nonsense"}
	transcript := func(e *actionEnv) []string {
		var out []string
		for _, cmd := range script {
			replies, screens := e.ask(alice, cmd)
			for _, r := range replies {
				out = append(out, cmd+" -> reply "+string(r))
			}
			for _, text := range screens {
				out = append(out, cmd+" -> "+text)
			}
		}
		return out
	}
	// What main answers with writes off (TestPermissions_InertWithoutWiringOrWrites
	// holds the /permissions half of it there).
	want := []string{
		"/consent -> reply " + string(pa.ReplyConsentPrompt),
		"/permissions -> " + safetext.TextPermissionsNone.String(),
		grantCmd + " -> " + safetext.TextPermissionsUnavailable.String(),
		"/permissions revoke prm_none -> " + safetext.TextPermissionGone.String(),
		"/consent nonsense -> reply " + string(pa.ReplyConsentPrompt),
	}
	for name, off := range map[string]func(e *actionEnv){
		"off": func(e *actionEnv) {
			e.writes.Store(false)
			e.flags.Store(&connector.Flags{ExternalTools: true, Servers: map[string]bool{"tg": true}})
		},
		"unreadable": func(e *actionEnv) {
			e.writesErr.Store(true)
			e.flags.Store(&connector.Flags{ExternalTools: true, Writes: true, WritesErr: errInjected, Servers: map[string]bool{"tg": true}})
		},
	} {
		for _, accepted := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s accepted=%v", name, accepted), func(t *testing.T) {
				forEachDialect(t, func(t *testing.T, s *db.Store) {
					e := newActionEnv(t, s)
					if !accepted {
						e.v1Only(alice)
					}
					off(e)
					if got := transcript(e); !slices.Equal(got, want) {
						t.Fatalf("transcript\n%q\nwant\n%q", got, want)
					}
					if got, why := e.offered(alice, e.home, permTool); len(got) != 0 || why != pa.WithheldWritesOff {
						t.Fatalf("offered %v (%s)", got, why)
					}
					a := e.call(e.token, writeCall(writeArgs))
					e.h.Loop().WaitDeliveries()
					if a.code != http.StatusForbidden || a.Stop != connector.ReasonWritesOff {
						t.Fatalf("write call answered %+v", a)
					}
					if n := e.actionArtifacts(); n != 0 {
						t.Fatalf("%d prompts, buttons or notices of the consent to actions", n)
					}
				})
			})
		}
	}

	forEachDialect(t, func(t *testing.T, s *db.Store) {
		// Accepted while on, switched off and on again: still accepted.
		e := newActionEnv(t, s)
		e.writes.Store(false)
		if got, why := e.offered(alice, e.home, permTool); len(got) != 0 || why != pa.WithheldWritesOff {
			t.Fatalf("with the switch off: offered %v (%s)", got, why)
		}
		e.writes.Store(true)
		if got, why := e.offered(alice, e.home, permTool); !slices.Equal(got, []string{permTool}) || why != pa.WithheldNone {
			t.Fatalf("after the switch went off and on: offered %v (%s)", got, why)
		}
		// A prompt shown while on is honoured after the switch went off.
		e.v1Only(alice)
		accept := e.wantActionPrompt(alice, "/permissions")
		e.writes.Store(false)
		if r := e.press(alice, accept); r != pa.ReplyActionConsentAccepted {
			t.Fatalf("press with writes off answered %q", r)
		}
	})
}

// TestActionConsent_TextChangeNeedsConsentAgain is S1-N3 for the consent
// to actions: a record of another version or another text is no consent,
// and a button of an earlier text records nothing and shows the current
// one.
func TestActionConsent_TextChangeNeedsConsentAgain(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newActionEnv(t, s)
		for _, stale := range []string{
			`UPDATE pa_action_consents SET text_sha256 = 'an-earlier-text' WHERE principal = $1`,
			`UPDATE pa_action_consents SET version = 'pa-actions/v0' WHERE principal = $1`,
			`UPDATE pa_action_consents SET state = 'withdrawn' WHERE principal = $1`,
		} {
			e.h.ConsentActions(alice)
			if got, why := e.offered(alice, e.home, permTool); !slices.Equal(got, []string{permTool}) || why != pa.WithheldNone {
				t.Fatalf("offered %v (%s) with the current consent", got, why)
			}
			// A grant screen shown while the consent was current.
			grant := e.button(e.one(alice, grantCmd), safetext.LabelPermissionGrant)
			if _, err := s.DB.Exec(stale, alice); err != nil {
				t.Fatal(err)
			}
			if got, why := e.offered(alice, e.home, permTool); len(got) != 0 || why != pa.WithheldConsent {
				t.Fatalf("%s: offered %v (%s)", stale, got, why)
			}
			a := e.writeEnv.approved(writeArgs)
			if out := e.dispatch(a.ID); out.Status != connector.StatusRefused || out.Reason != connector.ReasonActionConsentRequired {
				t.Fatalf("%s: approved action: %+v", stale, out)
			}
			e.h.DeliverNow(alice)
			// The consent is read again at the press: the screen is older
			// than the change, nothing is granted and the text is shown.
			if r := e.press(alice, grant); r != pa.ReplyActionConsentPrompt {
				t.Fatalf("%s: press on the earlier grant screen answered %q", stale, r)
			}
			e.nothingGranted(stale)
		}
		e.v1Only(alice)

		// A button bound to an earlier text.
		accept := e.wantActionPrompt(alice, "/permissions")
		if _, err := s.DB.Exec(`UPDATE pa_callbacks SET action = $1 WHERE id = $2`,
			"actions_accept:"+convo.ActionConsentVersion+":an-earlier-text", accept); err != nil {
			t.Fatal(err)
		}
		before := len(e.h.Replies(alice))
		if code := e.h.Press(alice, accept); code != http.StatusOK {
			t.Fatalf("press: %d", code)
		}
		if got := e.h.Replies(alice)[before:]; !slices.Equal(got, []pa.Reply{pa.ReplyConsentStale, pa.ReplyActionConsentPrompt}) {
			t.Fatalf("stale button answered %v", got)
		}
		_, fresh := e.h.LastReply(alice)
		if got := e.actionConsent(alice); got != "" {
			t.Fatalf("a stale button recorded %q", got)
		}
		if r := e.press(alice, fresh); r != pa.ReplyActionConsentAccepted {
			t.Fatalf("fresh button answered %q", r)
		}
	})
}
