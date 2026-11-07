package broadcast

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/notify"
)

const htmlBody = `<b>Release</b> notes: <a href="https://example.com/notes">read more</a>`

func (e *env) prepareFormat(f Format, text string) (*Preview, error) {
	return e.svc.Prepare(context.Background(), e.op, PrepareRequest{Selector: Selector{Category: "maintenance"}, Text: text, Format: f})
}

func (w *wenv) approvedFormat(f Format, text string) *Preview {
	w.t.Helper()
	p, err := w.prepareFormat(f, text)
	if err != nil {
		w.t.Fatalf("prepare: %v", err)
	}
	if err := w.svc.Approve(context.Background(), w.op, p.CampaignID, p.ContentHash, p.SelectorHash); err != nil {
		w.t.Fatalf("approve: %v", err)
	}
	return p
}

func TestPrepare_FormatDefaultsToPlain(t *testing.T) {
	e := newEnv(t)
	e.user(123450001, db.TierClient)
	plain, err := e.prepareFormat("", "a < b")
	if err != nil || plain.Format != FormatPlain || plain.ContentHash != Hash("a < b") {
		t.Fatalf("default: %+v, %v", plain, err)
	}
}

func TestPrepare_HTMLStoredWithFormatBoundHash(t *testing.T) {
	e := newEnv(t)
	e.user(123450001, db.TierClient)
	p, err := e.prepareFormat(FormatHTML, htmlBody)
	if err != nil {
		t.Fatal(err)
	}
	c, err := e.store.GetBroadcastCampaign(context.Background(), p.CampaignID)
	if err != nil {
		t.Fatal(err)
	}
	if c.ContentFormat != "html" || p.Format != FormatHTML {
		t.Fatalf("format not stored: %q / %q", c.ContentFormat, p.Format)
	}
	if p.ContentHash != ContentHashFor(FormatHTML, htmlBody) || p.ContentHash == Hash(htmlBody) {
		t.Fatalf("hash is not format-bound: %s", p.ContentHash)
	}
}

func TestPrepare_RefusesInvalidHTMLAndUnknownFormat(t *testing.T) {
	e := newEnv(t)
	e.user(123450001, db.TierClient)
	for name, text := range map[string]string{
		"script": "<script>x</script>", "unclosed": "<b>x", "bare lt": "1 < 2", "http link": `<a href="http://e.com">x</a>`,
	} {
		if _, err := e.prepareFormat(FormatHTML, text); err == nil {
			t.Errorf("%s: invalid html prepared", name)
		}
	}
	if _, err := e.prepareFormat("markdown", "x"); err == nil {
		t.Error("unknown format prepared")
	}
	// The same text is fine as plain: a literal < is not an error there.
	if _, err := e.prepareFormat(FormatPlain, "1 < 2"); err != nil {
		t.Errorf("plain: %v", err)
	}
}

// The approval is bound to the format: flipping it after preview must be
// refused, in both directions, even though the text did not change.
func TestApprove_RefusedWhenFormatChangedAfterPrepare(t *testing.T) {
	for _, tc := range []struct {
		name     string
		prepared Format
		flipTo   string
		text     string
	}{
		{"html to plain", FormatHTML, "plain", htmlBody},
		{"plain to html", FormatPlain, "html", "<b>bold</b>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.user(123450001, db.TierClient)
			p, err := e.prepareFormat(tc.prepared, tc.text)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := e.store.DB.Exec(`UPDATE broadcast_campaigns SET content_format = $1 WHERE id = $2`, tc.flipTo, p.CampaignID); err != nil {
				t.Fatal(err)
			}
			err = e.svc.Approve(context.Background(), e.op, p.CampaignID, p.ContentHash, p.SelectorHash)
			if !errors.Is(err, db.ErrCampaignMismatch) {
				t.Fatalf("approve after format flip = %v, want ErrCampaignMismatch", err)
			}
			if st := e.state(p.CampaignID); st != db.CampaignPrepared {
				t.Fatalf("state = %s", st)
			}
		})
	}
}

func TestWorker_SendsHTMLCampaignWithHTMLMethodAndPlainWithPlain(t *testing.T) {
	w := newWorkerEnv(t)
	u := w.user(123450001, db.TierClient)
	p := w.approvedFormat(FormatHTML, htmlBody)
	w.tick()
	if st, reason, _ := w.delivery(p.CampaignID, u); st != db.DeliveryDelivered {
		t.Fatalf("html delivery = %s/%s", st, reason)
	}
	if len(w.sender.sent) != 1 || !w.sender.sent[0].html || w.sender.sent[0].text != htmlBody {
		t.Fatalf("sent = %+v, want one html send of the approved text", w.sender.sent)
	}

	w2 := newWorkerEnv(t)
	u2 := w2.user(123450001, db.TierClient)
	p2 := w2.approvedFormat(FormatPlain, "Plain <text>")
	w2.tick()
	if st, _, _ := w2.delivery(p2.CampaignID, u2); st != db.DeliveryDelivered {
		t.Fatal("plain not delivered")
	}
	if len(w2.sender.sent) != 1 || w2.sender.sent[0].html {
		t.Fatalf("plain campaign went out as html: %+v", w2.sender.sent)
	}
}

// Telegram refusing the markup at send time is a permanent failure of that
// delivery. It is never retried and never re-sent as plain text, which
// would put a message other than the approved one in front of the person.
func TestWorker_HTMLRejectedByTelegramIsPermanentNeverPlainFallback(t *testing.T) {
	w := newWorkerEnv(t)
	u := w.user(123450001, db.TierClient)
	w.sender.results[123450001] = []error{&notify.APIError{StatusCode: 400, Description: "Bad Request: can't parse entities: Unsupported start tag"}}
	p := w.approvedFormat(FormatHTML, htmlBody)
	w.tick()
	w.tick()
	st, reason, attempts := w.delivery(p.CampaignID, u)
	if st != db.DeliveryFailed || !strings.HasPrefix(reason, ReasonRejected) {
		t.Fatalf("delivery = %s/%s, want failed/%s_*", st, reason, ReasonRejected)
	}
	if attempts != 1 || len(w.sender.sent) != 1 {
		t.Fatalf("attempts=%d sends=%+v, want exactly one html attempt", attempts, w.sender.sent)
	}
	for _, s := range w.sender.sent {
		if !s.html {
			t.Fatal("a rejected html message was re-sent as plain text")
		}
	}
	// The refusal is about the message, not the person: reachability untouched.
	if r := w.reach(u); r == notify.StateBlocked || r == notify.StateCannotInitiate {
		t.Fatalf("a markup rejection changed reachability to %s", r)
	}
}

// A row whose format changes after approval is halted by the integrity check
// and nothing is sent.
func TestWorker_FormatChangedAfterApprovalSendsNothing(t *testing.T) {
	w := newWorkerEnv(t)
	u := w.user(123450001, db.TierClient)
	p := w.approvedFormat(FormatHTML, htmlBody)
	if _, err := w.store.DB.Exec(`UPDATE broadcast_campaigns SET content_format = 'plain' WHERE id = $1`, p.CampaignID); err != nil {
		t.Fatal(err)
	}
	w.tick()
	if len(w.sender.sent) != 0 {
		t.Fatalf("sent after a format change: %+v", w.sender.sent)
	}
	if st, _, _ := w.delivery(p.CampaignID, u); st == db.DeliveryDelivered {
		t.Fatal("delivered despite format change")
	}
}

func TestCampaignFormat_UnknownIsNotPlain(t *testing.T) {
	c := &db.BroadcastCampaign{ID: "c1", Content: "x", ContentFormat: "markdownv2"}
	c.ContentHash = Hash("x")
	if _, err := CampaignFormat(c); err == nil {
		t.Fatal("unknown format read as plain")
	}
	if ContentMatches(c) {
		t.Fatal("a row with an unreadable format must not match its hash")
	}
}
