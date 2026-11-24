package pa

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
)

type draftRecorder struct {
	mu    sync.Mutex
	texts []string
	ids   []int64
}

func (r *draftRecorder) SendDraft(_ context.Context, _ int64, id int64, t safetext.Text) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.texts = append(r.texts, t.String())
	r.ids = append(r.ids, id)
	return nil
}

func (r *draftRecorder) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.texts...)
}

func withDrafts(r *draftRecorder, flag string) rlOption {
	return func(c *RunLoopConfig, _ *runLoopHarness) {
		c.Typing = &typingRecorder{}
		c.Drafts = r
		c.Getenv = func(k string) string {
			if k == StreamingFlagEnv {
				return flag
			}
			return ""
		}
	}
}

func TestStreamingOn(t *testing.T) {
	for in, want := range map[string]bool{"": false, "false": false, "true": true, " true ": true} {
		if got, err := streamingOn(func(string) string { return in }); err != nil || got != want {
			t.Errorf("%q: %v %v", in, got, err)
		}
	}
	if on, err := streamingOn(func(string) string { return "yes" }); err == nil || on {
		t.Errorf("unreadable flag must be off and an error")
	}
}

func TestToolStatusCoversPinnedReads(t *testing.T) {
	pin, err := catalog.LoadPin()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for server, sp := range pin.Servers {
		for name, tl := range sp.Tools {
			if tl.Tier == catalog.TierAuto && tl.Class == catalog.ClassRead {
				n++
				if !hasToolStatus(server + "/" + name) {
					t.Errorf("no tool status for %s/%s", server, name)
				}
			}
		}
	}
	if n == 0 {
		t.Fatal("no pinned reads")
	}
}

func TestDraftLimiter(t *testing.T) {
	d := newDraftLimiter()
	now := time.Unix(1000, 0)
	if !d.allow(1, now) || d.allow(1, now.Add(time.Millisecond)) {
		t.Fatal("min interval not enforced")
	}
	for i := 1; i < draftMaxPerJob; i++ {
		now = now.Add(time.Second)
		if !d.allow(1, now) {
			t.Fatalf("draft %d refused", i)
		}
	}
	if d.allow(1, now.Add(time.Second)) {
		t.Fatal("per-job cap not enforced")
	}
}

func TestServeDraft_FlagOffSendsNothing(t *testing.T) {
	for _, flag := range []string{"", "false", "bogus"} {
		t.Run("flag="+flag, func(t *testing.T) { serveDraftFlagOff(t, flag) })
	}
}

func serveDraftFlagOff(t *testing.T, flag string) {
	{
		rec := &draftRecorder{}
		h := newRunLoopHarness(t, withDrafts(rec, flag))
		h.consent(aliceID)
		h.text(aliceID, "hello")
		c := h.mustClaim()
		if c.Streaming {
			t.Fatalf("flag %q: claim says streaming", flag)
		}
		w := h.post(RouteDraft, c.Token, draftRequest{Text: "Hello there, friend. "})
		if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "streaming_off") {
			t.Fatalf("flag %q: %d %s", flag, w.Code, w.Body)
		}
		if got := rec.all(); len(got) != 0 {
			t.Fatalf("flag %q: drafts sent %q", flag, got)
		}
	}
}

func TestServeDraft_ShowsRenderedPartialAndReplyStillQueuesOnce(t *testing.T) {
	rec := &draftRecorder{}
	h := newRunLoopHarness(t, withDrafts(rec, "true"))
	h.consent(aliceID)
	h.text(aliceID, "hello")
	c := h.mustClaim()
	if !c.Streaming {
		t.Fatal("claim does not say streaming")
	}
	// The trailing unfinished token is withheld; a disallowed URL is defanged.
	w := h.post(RouteDraft, c.Token, draftRequest{Text: "See https://evil.example/p now and unfin"})
	if w.Code != http.StatusOK {
		t.Fatalf("draft: %d %s", w.Code, w.Body)
	}
	var out map[string]bool
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if !out["shown"] {
		t.Fatalf("not shown: %s", w.Body)
	}
	got := rec.all()
	want, err := safetext.RenderPartial("See https://evil.example/p now and unfin", safetext.AllowFromUserText("hello"))
	if err != nil || len(got) != 1 || got[0] != want.String() {
		t.Fatalf("draft %q, want %q (%v)", got, want.String(), err)
	}
	if strings.Contains(got[0], "unfin") {
		t.Fatalf("unfinished token shown: %q", got[0])
	}
	if sent := h.sender.to(aliceID); len(sent) != 0 {
		t.Fatalf("a draft was sent as a message: %q", sent)
	}
	if w := h.post(RouteReply, c.Token, replyRequest{Text: "final answer"}); w.Code != http.StatusOK {
		t.Fatalf("reply: %d %s", w.Code, w.Body)
	}
	if sent := h.sender.to(aliceID); len(sent) != 1 || sent[0] != "final answer" {
		t.Fatalf("sent %q", sent)
	}
	// After the reply no draft is shown, and the job is over.
	before := len(rec.all())
	h.post(RouteDraft, c.Token, draftRequest{Text: "late partial. "})
	if len(rec.all()) != before {
		t.Fatal("draft sent after the reply")
	}
}

func TestServeDraft_StoppedRunSendsNothing(t *testing.T) {
	rec := &draftRecorder{}
	h := newRunLoopHarness(t, withDrafts(rec, "true"))
	h.consent(aliceID)
	h.text(aliceID, "hello")
	c := h.mustClaim()
	if w := h.post(RouteDraft, c.Token, draftRequest{Text: "first part. "}); w.Code != http.StatusOK {
		t.Fatalf("draft: %d %s", w.Code, w.Body)
	}
	n := len(rec.all())
	h.text(aliceID, "/consent withdraw")
	h.loop.limiter.drop(c.JobID)
	if w := h.post(RouteDraft, c.Token, draftRequest{Text: "second part. "}); w.Code != http.StatusConflict {
		t.Fatalf("draft after withdrawal: %d %s", w.Code, w.Body)
	}
	if len(rec.all()) != n {
		t.Fatal("draft sent after consent was withdrawn")
	}
}

func TestServeDraft_OverLongIsSkipped(t *testing.T) {
	rec := &draftRecorder{}
	h := newRunLoopHarness(t, withDrafts(rec, "true"))
	h.consent(aliceID)
	h.text(aliceID, "hello")
	c := h.mustClaim()
	w := h.post(RouteDraft, c.Token, draftRequest{Text: strings.Repeat("word ", safetext.MaxPartUTF16/4)})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"shown":false`) || len(rec.all()) != 0 {
		t.Fatalf("%d %s drafts=%d", w.Code, w.Body, len(rec.all()))
	}
}

func TestAdmitToolCall_ShowsStatusOnlyWithFlag(t *testing.T) {
	for _, flag := range []string{"true", ""} {
		t.Run("flag="+flag, func(t *testing.T) { statusWithFlag(t, flag) })
	}
}

func statusWithFlag(t *testing.T, flag string) {
	{
		rec := &draftRecorder{}
		h := newRunLoopHarness(t, withDrafts(rec, flag))
		h.tools = []string{"tg/get_messages"}
		h.consent(aliceID)
		h.text(aliceID, "hello")
		c := h.mustClaim()
		job := h.paJob(c.Token)
		if _, err := h.loop.AdmitToolCall(context.Background(), job, "tg", "get_messages"); err != nil {
			t.Fatal(err)
		}
		if flag == "true" {
			waitFor(t, "status draft", func() bool { return len(rec.all()) >= 1 })
			if got := rec.all()[0]; got != safetext.TextStatusReadingMessages.String() {
				t.Fatalf("status %q", got)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
		if got := rec.all(); len(got) != 0 {
			t.Fatalf("flag off: drafts %q", got)
		}
	}
}
