package pa

// streaming_test.go: draft streaming (#1431) on the server. A draft is
// presentation only, so every test here asks the same two questions: what
// reached the draft sender, and that nothing else changed.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
	"github.com/mctlhq/mctl-telegram/internal/pa/convo"
	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
)

// draftRecorder records the drafts sent: the English text, the chat and
// the draft id.
type draftRecorder struct {
	mu    sync.Mutex
	texts []string
	chats []int64
	ids   []int64
	err   error
}

func (r *draftRecorder) SendDraft(_ context.Context, chat, id int64, t safetext.Text) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.texts = append(r.texts, t.String())
	r.chats = append(r.chats, chat)
	r.ids = append(r.ids, id)
	return r.err
}

func (r *draftRecorder) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.texts)
}

func (r *draftRecorder) count() int { return len(r.all()) }

// streamFlag is a PA_STREAMING_ENABLED value a test can change.
type streamFlag struct{ v atomic.Value }

func newStreamFlag(v string) *streamFlag {
	f := &streamFlag{}
	f.v.Store(v)
	return f
}

func (f *streamFlag) set(v string) { f.v.Store(v) }

func (f *streamFlag) getenv(k string) string {
	if k == StreamingFlagEnv {
		return f.v.Load().(string)
	}
	return ""
}

// withStreaming wires a draft sender, a typing sender and the flag.
func withStreaming(r *draftRecorder, typing *typingRecorder, flag *streamFlag) rlOption {
	return func(c *RunLoopConfig, _ *runLoopHarness) {
		c.Typing = typing
		c.Drafts = r
		c.Getenv = flag.getenv
	}
}

func withDrafts(r *draftRecorder, flag string) rlOption {
	return withStreaming(r, &typingRecorder{}, newStreamFlag(flag))
}

// streamingHarness is a harness with the flag on, one claimed job of
// Alice's and no pause between drafts.
func streamingHarness(t *testing.T, opts ...rlOption) (*runLoopHarness, *draftRecorder, claimResponse) {
	t.Helper()
	rec := &draftRecorder{}
	h := newRunLoopHarness(t, append([]rlOption{withDrafts(rec, "true")}, opts...)...)
	h.loop.limiter.minInterval = 0
	fastTyping(t, h.loop) // before any presence loop reads the interval
	h.consent(aliceID)
	h.text(aliceID, "hello")
	c := h.mustClaim()
	if !c.Streaming {
		t.Fatal("claim does not say streaming")
	}
	return h, rec, c
}

func shownOf(t *testing.T, w *httptest.ResponseRecorder) bool {
	t.Helper()
	var out struct {
		Shown *bool `json:"shown"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || out.Shown == nil {
		t.Fatalf("draft answer %d %s", w.Code, w.Body)
	}
	return *out.Shown
}

func TestStreamingOn(t *testing.T) {
	for in, want := range map[string]bool{"": false, "false": false, "true": true, " true ": true} {
		if got, err := streamingOn(func(string) string { return in }); err != nil || got != want {
			t.Errorf("%q: %v %v", in, got, err)
		}
	}
	// Anything else is unreadable: an error, and never on.
	for _, in := range []string{"yes", "1", "TRUE", "on", "true,false"} {
		if on, err := streamingOn(func(string) string { return in }); err == nil || on {
			t.Errorf("%q: on=%v err=%v, want an error and off", in, on, err)
		}
	}
}

// TestToolStatus: every tool the pin admits without approval has its own
// status, so a newly pinned read is a visible decision; any other name gets
// the generic one. Every status has an English and a different Russian
// text and no placeholder, so nothing of a call can be put into it.
func TestToolStatus(t *testing.T) {
	pin, err := catalog.LoadPin()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	seen := map[safetext.Template]bool{safetext.TextStatusUsingTool: true}
	for server, sp := range pin.Servers {
		for name, tl := range sp.Tools {
			if tl.Tier == catalog.TierAuto && tl.Class == catalog.ClassRead {
				n++
				if !hasToolStatus(server + "/" + name) {
					t.Errorf("no tool status for %s/%s", server, name)
				}
				seen[toolStatus(server+"/"+name)] = true
			}
		}
	}
	if n == 0 {
		t.Fatal("no pinned reads")
	}
	for _, unknown := range []string{"", "tg/send_message", "tg/get_messages ", "x/y", "https://evil.example/p"} {
		if toolStatus(unknown) != safetext.TextStatusUsingTool {
			t.Errorf("%q: not the generic status", unknown)
		}
	}
	for tpl := range seen {
		en, ru := tpl.String(), tpl.In(safetext.LangRU)
		if strings.TrimSpace(en) == "" || strings.TrimSpace(ru) == "" || en == ru {
			t.Errorf("status %q / %q: needs an English and a Russian text", en, ru)
		}
		if strings.ContainsAny(en+ru, "%{}<>") {
			t.Errorf("status %q / %q holds a placeholder", en, ru)
		}
		if txt := safetext.ServerText(tpl); txt.Parts() != 1 {
			t.Errorf("status %q is %d parts", en, txt.Parts())
		}
	}
}

func TestDraftLimiter(t *testing.T) {
	d := newDraftLimiter()
	ref := jobs.Ref{JobID: 1, Attempt: 1}
	now := time.Unix(1000, 0)
	if !d.allow(ref, now) {
		t.Fatal("first draft refused")
	}
	if d.allow(ref, now.Add(draftMinInterval-time.Millisecond)) {
		t.Fatal("min interval not enforced")
	}
	for i := 1; i < draftMaxPerJob; i++ {
		now = now.Add(time.Second)
		if !d.allow(ref, now) {
			t.Fatalf("draft %d refused", i)
		}
	}
	if d.allow(ref, now.Add(time.Minute)) {
		t.Fatal("per-job cap not enforced")
	}
	// Another attempt and another job have their own count.
	if !d.allow(jobs.Ref{JobID: 1, Attempt: 2}, now) || !d.allow(jobs.Ref{JobID: 2, Attempt: 1}, now) {
		t.Fatal("the cap of one attempt refused another")
	}
	// Old entries are forgotten once the table is large; a live one is not.
	for i := int64(10); i < 10+draftLimiterSweep+1; i++ {
		d.allow(jobs.Ref{JobID: i, Attempt: 1}, now)
	}
	later := now.Add(draftLimiterTTL + time.Second)
	d.allow(jobs.Ref{JobID: 5, Attempt: 1}, later)
	if len(d.jobs) != 1 {
		t.Fatalf("entries after the sweep = %d, want 1", len(d.jobs))
	}
}

// TestStreaming_FlagOff: with the flag off, missing or unreadable, or with
// no draft sender wired, the claim is today's (no streaming field at all),
// the draft route answers 404 and a tool admission shows no status.
// Nothing reaches the draft sender.
func TestStreaming_FlagOff(t *testing.T) {
	base := newRunLoopHarness(t)
	base.tools = []string{"tg/get_messages"}
	base.consent(aliceID)
	base.text(aliceID, "hello")
	want := claimKeys(t, base)

	cases := map[string]rlOption{}
	recs := map[string]*draftRecorder{}
	for _, flag := range []string{"", "false", "bogus", "TRUE", "1"} {
		rec := &draftRecorder{}
		recs["flag="+flag] = rec
		cases["flag="+flag] = withDrafts(rec, flag)
	}
	cases["no draft sender"] = func(c *RunLoopConfig, _ *runLoopHarness) {
		c.Typing = &typingRecorder{}
		c.Getenv = newStreamFlag("true").getenv
	}
	for name, opt := range cases {
		t.Run(name, func(t *testing.T) {
			h := newRunLoopHarness(t, opt)
			h.tools = []string{"tg/get_messages"}
			fastTyping(t, h.loop)
			h.consent(aliceID)
			h.text(aliceID, "hello")
			w := h.post(RouteClaim, h.pool, nil)
			if w.Code != http.StatusOK {
				t.Fatalf("claim: %d", w.Code)
			}
			var raw map[string]json.RawMessage
			var c claimResponse
			if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
				t.Fatal(err)
			}
			_ = json.Unmarshal(w.Body.Bytes(), &c)
			if got := sortedKeys(raw); !slices.Equal(got, want) || strings.Contains(w.Body.String(), "streaming") {
				t.Fatalf("claim fields %v, want today's %v", got, want)
			}
			d := h.post(RouteDraft, c.Token, draftRequest{Text: "Hello there, friend. "})
			if d.Code != http.StatusNotFound || stopOf(d) != "streaming_off" {
				t.Fatalf("draft: %d %s", d.Code, d.Body)
			}
			if _, err := h.loop.AdmitToolCall(context.Background(), h.paJob(c.Token), "tg", "get_messages"); err != nil {
				t.Fatal(err)
			}
			time.Sleep(50 * time.Millisecond)
			if rec := recs[name]; rec != nil && rec.count() != 0 {
				t.Fatalf("drafts sent %q", rec.all())
			}
			// The run is untouched by the refused draft.
			if w := h.post(RouteReply, c.Token, replyRequest{Text: "final answer"}); w.Code != http.StatusOK {
				t.Fatalf("reply: %d %s", w.Code, w.Body)
			}
			if sent := h.sender.to(aliceID); len(sent) != 1 || sent[0] != "final answer" {
				t.Fatalf("sent %q", sent)
			}
		})
	}
}

func claimKeys(t *testing.T, h *runLoopHarness) []string {
	t.Helper()
	w := h.post(RouteClaim, h.pool, nil)
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil || w.Code != http.StatusOK {
		t.Fatalf("claim: %d %v", w.Code, err)
	}
	return sortedKeys(raw)
}

func sortedKeys(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// TestStreaming_FlagRereadPerJobAndDraft: the flag is read again at every
// claim, draft, tool status and refresh, not once at start.
func TestStreaming_FlagRereadPerJobAndDraft(t *testing.T) {
	rec, flag := &draftRecorder{}, newStreamFlag("false")
	h := newRunLoopHarness(t, withStreaming(rec, &typingRecorder{}, flag))
	h.tools = []string{"tg/get_messages"}
	h.loop.limiter.minInterval = 0
	fastTyping(t, h.loop)
	h.consent(aliceID)
	h.text(aliceID, "hello")
	c := h.mustClaim()
	if c.Streaming {
		t.Fatal("claim says streaming with the flag off")
	}
	if w := h.post(RouteReply, c.Token, replyRequest{Text: "first"}); w.Code != http.StatusOK {
		t.Fatalf("reply: %d", w.Code)
	}

	flag.set("true")
	h.text(aliceID, "again")
	c = h.mustClaim()
	if !c.Streaming {
		t.Fatal("the next job's claim does not say streaming")
	}
	if w := h.post(RouteDraft, c.Token, draftRequest{Text: "One sentence. "}); w.Code != http.StatusOK || !shownOf(t, w) {
		t.Fatalf("draft: %d %s", w.Code, w.Body)
	}
	n := rec.count()

	// Turned off mid-run: the next draft is refused, a tool shows no
	// status and the refresher stops re-sending.
	flag.set("false")
	if w := h.post(RouteDraft, c.Token, draftRequest{Text: "One sentence. And another. "}); w.Code != http.StatusNotFound || stopOf(w) != "streaming_off" {
		t.Fatalf("draft with the flag off: %d %s", w.Code, w.Body)
	}
	if _, err := h.loop.AdmitToolCall(context.Background(), h.paJob(c.Token), "tg", "get_messages"); err != nil {
		t.Fatal(err)
	}
	fastPresence(h.loop)
	waitFor(t, "presence to end", func() bool { return h.loop.typing.active() == 0 })
	if got := rec.all(); len(got) != n {
		t.Fatalf("drafts after the flag went off: %q", got[n:])
	}
	// The run itself goes on.
	if w := h.post(RouteReply, c.Token, replyRequest{Text: "second"}); w.Code != http.StatusOK {
		t.Fatalf("reply: %d %s", w.Code, w.Body)
	}
}

// TestServeDraft_ShowsRenderedPartial: an accepted partial is sent as the
// job's draft exactly as safetext.RenderPartial makes it with the reply's
// allow-list, to the principal's chat under the job's non-zero draft id.
// It is not a message, a fragment or an outbox row, and the reply after it
// is stored, queued and sent once as without streaming.
func TestServeDraft_ShowsRenderedPartial(t *testing.T) {
	h, rec, c := streamingHarness(t)
	frags, outbox := h.fragments(aliceID), h.count(`SELECT count(*) FROM pa_outbox`)

	const partial = "See https://evil.example/p now and unfin"
	w := h.post(RouteDraft, c.Token, draftRequest{Text: partial})
	if w.Code != http.StatusOK || !shownOf(t, w) {
		t.Fatalf("draft: %d %s", w.Code, w.Body)
	}
	want, err := safetext.RenderPartial(partial, safetext.AllowFromUserText("hello"))
	if err != nil {
		t.Fatal(err)
	}
	got := rec.all()
	if len(got) != 1 || got[0] != want.String() || got[0] != "See https[:]//evil[.]example/p now and " {
		t.Fatalf("draft %q, want %q", got, want.String())
	}
	if rec.chats[0] != aliceID || rec.ids[0] != c.JobID || rec.ids[0] == 0 {
		t.Fatalf("draft to chat %d with id %d, want chat %d id %d", rec.chats[0], rec.ids[0], aliceID, c.JobID)
	}
	if sent := h.sender.to(aliceID); len(sent) != 0 {
		t.Fatalf("a draft was sent as a message: %q", sent)
	}
	if f, o := h.fragments(aliceID), h.count(`SELECT count(*) FROM pa_outbox`); f != frags || o != outbox {
		t.Fatalf("a draft was stored: fragments %d -> %d, outbox %d -> %d", frags, f, outbox, o)
	}

	if w := h.post(RouteReply, c.Token, replyRequest{Text: "final answer"}); w.Code != http.StatusOK {
		t.Fatalf("reply: %d %s", w.Code, w.Body)
	}
	if sent := h.sender.to(aliceID); len(sent) != 1 || sent[0] != "final answer" {
		t.Fatalf("sent %q", sent)
	}
	if f, o := h.fragments(aliceID), h.count(`SELECT count(*) FROM pa_outbox`); f != frags+1 || o != outbox+1 {
		t.Fatalf("after the reply: fragments %d -> %d, outbox %d -> %d; want one more of each", frags, f, outbox, o)
	}
	// After the reply no draft is shown, and the job is over.
	if w := h.post(RouteDraft, c.Token, draftRequest{Text: "late partial. "}); w.Code != http.StatusConflict {
		t.Fatalf("draft after the reply: %d %s", w.Code, w.Body)
	}
	if rec.count() != 1 {
		t.Fatalf("draft sent after the reply: %q", rec.all())
	}
}

// TestServeDraft_Skipped: a partial that cannot be shown whole is skipped
// with 200 {"shown": false}: not cut to fit, not an error that could end
// the run, and nothing is sent.
func TestServeDraft_Skipped(t *testing.T) {
	h, rec, c := streamingHarness(t)
	for name, body := range map[string]any{
		"over one part":     draftRequest{Text: strings.Repeat("word ", safetext.MaxPartUTF16/4)},
		"over the limit":    draftRequest{Text: strings.Repeat("a ", safetext.MaxParts*safetext.MaxPartUTF16)},
		"over the body cap": draftRequest{Text: strings.Repeat("a", maxDraftBody)},
		"empty":             draftRequest{},
		"blank":             draftRequest{Text: " \n "},
		"no finished token": draftRequest{Text: "Hel"},
		"not an object":     []int{1},
	} {
		w := h.post(RouteDraft, c.Token, body)
		if w.Code != http.StatusOK || shownOf(t, w) {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	if rec.count() != 0 {
		t.Fatalf("a skipped draft was sent: %d", rec.count())
	}
	// A draft the sender could not deliver is skipped the same way.
	rec.err = errors.New("Too Many Requests")
	if w := h.post(RouteDraft, c.Token, draftRequest{Text: "A sentence. "}); w.Code != http.StatusOK || shownOf(t, w) {
		t.Fatalf("failed send: %d %s", w.Code, w.Body)
	}
	rec.err = nil
	if w := h.post(RouteReply, c.Token, replyRequest{Text: "final answer"}); w.Code != http.StatusOK {
		t.Fatalf("reply after skipped drafts: %d %s", w.Code, w.Body)
	}
}

// TestServeDraft_RateCap: one attempt may ask for a draft at most once per
// draftMinInterval and draftMaxPerJob times; beyond that the route answers
// 429 and sends nothing, and the run is not affected.
func TestServeDraft_RateCap(t *testing.T) {
	rec := &draftRecorder{}
	h := newRunLoopHarness(t, withDrafts(rec, "true"))
	h.consent(aliceID)
	h.text(aliceID, "hello")
	c := h.mustClaim()
	if w := h.post(RouteDraft, c.Token, draftRequest{Text: "One. "}); w.Code != http.StatusOK || !shownOf(t, w) {
		t.Fatalf("first draft: %d %s", w.Code, w.Body)
	}
	// The harness clock stands still: the second request is inside the
	// interval.
	if w := h.post(RouteDraft, c.Token, draftRequest{Text: "One. Two. "}); w.Code != http.StatusTooManyRequests {
		t.Fatalf("second draft at once: %d %s", w.Code, w.Body)
	}
	h.loop.limiter.minInterval = 0
	h.loop.limiter.maxPerJob = 2
	if w := h.post(RouteDraft, c.Token, draftRequest{Text: "One. Two. Three. "}); w.Code != http.StatusOK || !shownOf(t, w) {
		t.Fatalf("third request: %d %s", w.Code, w.Body)
	}
	if w := h.post(RouteDraft, c.Token, draftRequest{Text: "One. Two. Three. Four. "}); w.Code != http.StatusTooManyRequests {
		t.Fatalf("over the per-job cap: %d %s", w.Code, w.Body)
	}
	if got := rec.all(); len(got) != 2 {
		t.Fatalf("drafts sent %q, want 2", got)
	}
	if w := h.post(RouteReply, c.Token, replyRequest{Text: "final answer"}); w.Code != http.StatusOK {
		t.Fatalf("reply: %d %s", w.Code, w.Body)
	}
}

// stopCases are the ways a run stops being the caller's to continue. Each
// prepares the stop and returns the token to use.
var stopCases = map[string]func(t *testing.T, h *runLoopHarness, c claimResponse) string{
	"consent withdrawn": func(_ *testing.T, h *runLoopHarness, c claimResponse) string {
		h.text(aliceID, "/consent withdraw")
		return c.Token
	},
	"conversation closed by /new": func(_ *testing.T, h *runLoopHarness, c claimResponse) string {
		h.text(aliceID, "/new")
		return c.Token
	},
	"conversation forgotten": func(_ *testing.T, h *runLoopHarness, c claimResponse) string {
		h.text(aliceID, "/forget")
		return c.Token
	},
	"conversation expired": func(t *testing.T, h *runLoopHarness, c claimResponse) string {
		if _, err := h.convoHarness.store.DB.Exec(`UPDATE pa_conversations SET expires_at_ms = 1 WHERE principal = $1`, aliceID); err != nil {
			t.Fatal(err)
		}
		return c.Token
	},
	"principal disabled": func(t *testing.T, h *runLoopHarness, c claimResponse) string {
		disable(t, h.convoHarness.store, aliceID)
		return c.Token
	},
	"principal off the allowlist": func(_ *testing.T, h *runLoopHarness, c claimResponse) string {
		h.allow.deny(aliceID)
		return c.Token
	},
	"stale attempt": func(t *testing.T, h *runLoopHarness, c claimResponse) string {
		return forgedJobToken(t, h, localjwt.PAJob{Principal: aliceID, JobID: c.JobID, Attempt: c.Attempt + 1, ContextDigest: strings.Repeat("a", 64)})
	},
	"another context digest": func(t *testing.T, h *runLoopHarness, c claimResponse) string {
		return forgedJobToken(t, h, localjwt.PAJob{Principal: aliceID, JobID: c.JobID, Attempt: c.Attempt, ContextDigest: strings.Repeat("b", 64)})
	},
	"another principal": func(t *testing.T, h *runLoopHarness, c claimResponse) string {
		return forgedJobToken(t, h, localjwt.PAJob{Principal: bobID, JobID: c.JobID, Attempt: c.Attempt, ContextDigest: strings.Repeat("a", 64)})
	},
}

func forgedJobToken(t *testing.T, h *runLoopHarness, j localjwt.PAJob) string {
	t.Helper()
	tok, err := h.issuer.MintPAJob(j, "pool-jti", 0, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// TestServeDraft_StoppedRunSendsNothing: a draft for a run that is no
// longer the caller's to continue is answered exactly as /turn answers it
// in the same state, and nothing is sent: not this draft, and no refresh
// of the one shown before.
func TestServeDraft_StoppedRunSendsNothing(t *testing.T) {
	for name, stopIt := range stopCases {
		t.Run(name, func(t *testing.T) {
			// What /turn answers in this state.
			var turn *httptest.ResponseRecorder
			t.Run("turn", func(t *testing.T) {
				ht, _, ct := streamingHarness(t)
				turn = ht.post(RouteTurn, stopIt(t, ht, ct), turnRequest{ContextTokens: 10})
			})
			if turn == nil || turn.Code == http.StatusOK {
				t.Fatalf("/turn admitted a stopped run")
			}

			h, rec, c := streamingHarness(t)
			if w := h.post(RouteDraft, c.Token, draftRequest{Text: "first part. "}); w.Code != http.StatusOK || !shownOf(t, w) {
				t.Fatalf("draft: %d %s", w.Code, w.Body)
			}
			tok := stopIt(t, h, c)
			w := h.post(RouteDraft, tok, draftRequest{Text: "first part. second part. "})
			if w.Code != turn.Code || stopOf(w) != stopOf(turn) {
				t.Fatalf("draft answered %d %q, /turn answers %d %q", w.Code, stopOf(w), turn.Code, stopOf(turn))
			}
			if got := rec.all(); len(got) != 1 {
				t.Fatalf("draft sent for a stopped run: %q", got)
			}
			// The answer is the same again, and still nothing is sent.
			if w := h.post(RouteDraft, tok, draftRequest{Text: "first part. second part. third. "}); w.Code/100 == 2 {
				t.Fatalf("second draft for a stopped run: %d %s", w.Code, w.Body)
			}
			if got := rec.all(); len(got) != 1 {
				t.Fatalf("draft sent for a stopped run: %q", got)
			}
		})
	}
}

// TestPresence_CancelledRunSendsNoFurtherDraft: the refresher re-sends a
// draft only for a run that still passes the run gate. Once the run is
// cancelled, with no further request from the worker at all, the
// refresher's next check ends the job's presence and nothing more is sent.
func TestPresence_CancelledRunSendsNoFurtherDraft(t *testing.T) {
	for _, name := range []string{"consent withdrawn", "conversation closed by /new", "conversation expired", "principal disabled", "principal off the allowlist"} {
		t.Run(name, func(t *testing.T) {
			h, rec, c := streamingHarness(t)
			fastPresence(h.loop)
			if w := h.post(RouteDraft, c.Token, draftRequest{Text: "first part. "}); w.Code != http.StatusOK || !shownOf(t, w) {
				t.Fatalf("draft: %d %s", w.Code, w.Body)
			}
			// The refresher is alive: the same draft is re-sent.
			waitFor(t, "a refreshed draft", func() bool { return rec.count() >= 3 })
			stopCases[name](t, h, c)
			waitFor(t, "presence to end", func() bool { return h.loop.typing.active() == 0 })
			n := rec.count()
			time.Sleep(60 * time.Millisecond)
			if m := rec.count(); m != n {
				t.Fatalf("drafts still sent after the run was cancelled: %d -> %d", n, m)
			}
			for _, d := range rec.all() {
				if d != "first part. " {
					t.Fatalf("a refresh sent another text: %q", d)
				}
			}
		})
	}
}

// fastPresence makes every shown draft due for a refresh at the loop's
// next tick.
func fastPresence(l *RunLoop) {
	l.typing.mu.Lock()
	l.typing.refresh = 0
	l.typing.mu.Unlock()
}

// TestPresence_UnreadableRunStopsTheRefresher: a run gate that cannot be
// read is not "still running": the draft is not re-sent.
func TestPresence_UnreadableRunStopsTheRefresher(t *testing.T) {
	var fail atomic.Bool
	h, rec, c := streamingHarness(t, withStore(func(s *db.Store) RunLoopStore { return &toggleReads{Store: s, consent: &fail} }))
	if w := h.post(RouteDraft, c.Token, draftRequest{Text: "first part. "}); w.Code != http.StatusOK || !shownOf(t, w) {
		t.Fatalf("draft: %d %s", w.Code, w.Body)
	}
	fail.Store(true)
	fastPresence(h.loop)
	waitFor(t, "presence to end", func() bool { return h.loop.typing.active() == 0 })
	n := rec.count()
	// A draft request in that state is refused too, and sends nothing.
	if w := h.post(RouteDraft, c.Token, draftRequest{Text: "first part. second part. "}); w.Code/100 == 2 {
		t.Fatalf("draft with an unreadable consent: %d %s", w.Code, w.Body)
	}
	time.Sleep(40 * time.Millisecond)
	if m := rec.count(); m != n {
		t.Fatalf("drafts sent on an unreadable run: %d -> %d", n, m)
	}
}

// toggleReads fails the consent read or the fragment read on demand.
type toggleReads struct {
	*db.Store
	consent   *atomic.Bool
	fragments *atomic.Bool
}

func (s *toggleReads) GetPAConsent(ctx context.Context, tx *sql.Tx, p int64) (convo.ConsentRecord, error) {
	if s.consent != nil && s.consent.Load() {
		return convo.ConsentRecord{}, errors.New("injected consent read error")
	}
	return s.Store.GetPAConsent(ctx, tx, p)
}

func (s *toggleReads) LoadPAFragments(ctx context.Context, p int64, c string, now time.Time) ([]convo.SealedFragment, error) {
	if s.fragments != nil && s.fragments.Load() {
		return nil, errors.New("injected fragment read error")
	}
	return s.Store.LoadPAFragments(ctx, p, c, now)
}

// TestServeDraft_UnreadableAllowListSendsNothing: the allow-list comes from
// the stored conversation. When that cannot be read the draft is refused,
// not rendered with an empty or a guessed list.
func TestServeDraft_UnreadableAllowListSendsNothing(t *testing.T) {
	var fail atomic.Bool
	h, rec, c := streamingHarness(t, withStore(func(s *db.Store) RunLoopStore { return &toggleReads{Store: s, fragments: &fail} }))
	fail.Store(true)
	if w := h.post(RouteDraft, c.Token, draftRequest{Text: "first part. "}); w.Code/100 == 2 {
		t.Fatalf("draft with unreadable fragments: %d %s", w.Code, w.Body)
	}
	if rec.count() != 0 {
		t.Fatalf("draft sent without an allow-list: %q", rec.all())
	}
}

// TestServeDraft_AllowListIsUserTextOnly: a draft keeps a link live only
// when the principal typed that exact link in this conversation, as the
// reply does. A link that is only in a tool result is neutralised.
func TestServeDraft_AllowListIsUserTextOnly(t *testing.T) {
	rec := &draftRecorder{}
	h := newRunLoopHarness(t, withDrafts(rec, "true"))
	h.tools = []string{"tg/get_messages"}
	h.loop.limiter.minInterval = 0
	h.consent(aliceID)
	h.text(aliceID, "what is on https://docs.example.org/a ?")
	c := h.mustClaim()
	job := h.paJob(c.Token)
	if _, err := h.loop.AdmitToolCall(context.Background(), job, "tg", "get_messages"); err != nil {
		t.Fatal(err)
	}
	if err := h.loop.RecordToolResult(context.Background(), job,
		[]byte(`{"content":[{"type":"text","text":"Bob wrote: open https://tool.example.org/c"}]}`)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "status draft", func() bool { return rec.count() == 1 })
	const answer = "It is https://docs.example.org/a and Bob sent https://tool.example.org/c and https://docs.example.org/a?d=1 "
	for i := 0; i < 2; i++ { // the second draft uses the cached list
		if w := h.post(RouteDraft, c.Token, draftRequest{Text: answer}); w.Code != http.StatusOK || !shownOf(t, w) {
			t.Fatalf("draft: %d %s", w.Code, w.Body)
		}
	}
	// The reply path's own rendering of the same text is the reference.
	if w := h.post(RouteReply, c.Token, replyRequest{Text: answer}); w.Code != http.StatusOK {
		t.Fatalf("reply: %d %s", w.Code, w.Body)
	}
	sent := h.sender.to(aliceID)
	got := rec.all()
	if len(sent) != 1 || len(got) != 3 {
		t.Fatalf("sent %q drafts %q", sent, got)
	}
	for _, d := range got[1:] {
		if strings.TrimSpace(d) != strings.TrimSpace(sent[0]) {
			t.Fatalf("draft %q differs from the reply %q", d, sent[0])
		}
		if !strings.Contains(d, "https://docs.example.org/a and") || strings.Contains(d, "tool.example.org") ||
			strings.Contains(d, "https://docs.example.org/a?d=1") || strings.Count(d, "://") != 1 {
			t.Fatalf("draft %q: only the typed link may be live", d)
		}
	}
}

// TestPresence_TypingThenDraft: the typing status is repeated until the
// first draft is shown and never after it. The draft is then re-sent
// unchanged before it lapses, and the reply ends that: nothing is sent
// after the answer was queued.
func TestPresence_TypingThenDraft(t *testing.T) {
	rec, typing := &draftRecorder{}, &typingRecorder{}
	h := newRunLoopHarness(t, withStreaming(rec, typing, newStreamFlag("true")))
	h.loop.limiter.minInterval = 0
	fastTyping(t, h.loop)
	h.consent(aliceID)
	h.text(aliceID, "hello")
	c := h.mustClaim()
	waitFor(t, "typing before the first draft", func() bool { return typing.count(aliceID) >= 3 })
	if rec.count() != 0 {
		t.Fatalf("a draft before any was asked for: %q", rec.all())
	}
	if w := h.post(RouteDraft, c.Token, draftRequest{Text: "first part. "}); w.Code != http.StatusOK || !shownOf(t, w) {
		t.Fatalf("draft: %d %s", w.Code, w.Body)
	}
	// One status may have been on its way when the draft was shown.
	time.Sleep(20 * time.Millisecond)
	settled(t, typing, aliceID)
	// Not due yet: the draft is not re-sent on every tick.
	if n := rec.count(); n != 1 {
		t.Fatalf("draft re-sent before it was due: %d sends", n)
	}
	fastPresence(h.loop)
	waitFor(t, "a refreshed draft", func() bool { return rec.count() >= 3 })
	settled(t, typing, aliceID)

	if w := h.post(RouteReply, c.Token, replyRequest{Text: "final answer"}); w.Code != http.StatusOK {
		t.Fatalf("reply: %d %s", w.Code, w.Body)
	}
	n := rec.count()
	if h.loop.typing.active() != 0 {
		t.Fatal("presence still running after the reply")
	}
	time.Sleep(60 * time.Millisecond)
	if m := rec.count(); m != n {
		t.Fatalf("drafts sent after the reply: %d -> %d", n, m)
	}
	for _, d := range rec.all() {
		if d != "first part. " {
			t.Fatalf("a refresh sent another text: %q", d)
		}
	}
	settled(t, typing, aliceID)
	if sent := h.sender.to(aliceID); len(sent) != 1 || sent[0] != "final answer" {
		t.Fatalf("sent %q", sent)
	}
}

// TestPresence_NoDraftAfterStop: a request that still holds a job's
// presence when the run is stopped sends nothing afterwards.
func TestPresence_NoDraftAfterStop(t *testing.T) {
	rec := &draftRecorder{}
	tr := newTypingTracker(&typingRecorder{}, time.Now)
	tr.drafts = rec
	tr.interval = time.Hour
	ref := jobs.Ref{Principal: aliceID, JobID: 1, Attempt: 1}
	tr.begin(ref, time.Now().Add(time.Minute))
	held := tr.run(1)
	text := safetext.ServerText(safetext.TextStatusUsingTool)
	if !tr.showDraft(context.Background(), ref, text) {
		t.Fatal("draft not shown for a live run")
	}
	tr.stop(1)
	if tr.showDraft(context.Background(), ref, text) {
		t.Fatal("draft shown for a job with no presence")
	}
	if err := tr.sendDraft(context.Background(), held, aliceID, 1, text); err == nil {
		t.Fatal("draft sent through a stopped run")
	}
	// A loop that ended on its own (the lease) refuses the same way.
	tr.begin(jobs.Ref{Principal: aliceID, JobID: 2, Attempt: 1}, time.Now().Add(10*time.Millisecond))
	held = tr.run(2)
	waitFor(t, "lease end", func() bool { return tr.active() == 0 })
	<-held.done
	if err := tr.sendDraft(context.Background(), held, aliceID, 2, text); err == nil {
		t.Fatal("draft sent through a run whose loop ended")
	}
	if rec.count() != 1 {
		t.Fatalf("drafts sent: %d, want 1", rec.count())
	}
}

// TestAdmitToolCall_ShowsServerStatus: with the flag on an admitted tool
// call shows that tool's server template as the job's draft. AdmitToolCall
// is given the pinned name only: no argument and no model text reaches it.
func TestAdmitToolCall_ShowsServerStatus(t *testing.T) {
	rec := &draftRecorder{}
	h := newRunLoopHarness(t, withDrafts(rec, "true"))
	h.tools = []string{"tg/get_messages", "tg/list_dialogs"}
	h.consent(aliceID)
	h.text(aliceID, "summarise the chat Secret Plans with Bob")
	c := h.mustClaim()
	job := h.paJob(c.Token)
	for i, tc := range []struct {
		tool string
		want safetext.Template
	}{{"get_messages", safetext.TextStatusReadingMessages}, {"list_dialogs", safetext.TextStatusListingChats}} {
		if _, err := h.loop.AdmitToolCall(context.Background(), job, "tg", tc.tool); err != nil {
			t.Fatal(err)
		}
		waitFor(t, "status draft", func() bool { return rec.count() == i+1 })
		if got := rec.all()[i]; got != tc.want.String() || strings.Contains(got, "Secret") || strings.Contains(got, "Bob") {
			t.Fatalf("status %q, want %q", got, tc.want.String())
		}
	}
	if rec.ids[0] != c.JobID || rec.chats[0] != aliceID {
		t.Fatalf("status to chat %d with id %d", rec.chats[0], rec.ids[0])
	}
	// A refused call shows nothing.
	if _, err := h.loop.AdmitToolCall(context.Background(), job, "tg", "search_messages"); err == nil {
		t.Fatal("a tool outside the signed set was admitted")
	}
	time.Sleep(40 * time.Millisecond)
	if rec.count() != 2 {
		t.Fatalf("status for a refused call: %q", rec.all())
	}
}

// TestStreaming_NeverStoresOrQueues: the draft path cannot store a fragment
// or queue an outbox row, because the code that makes drafts names none of
// the functions that do. serveDraft and the files that hold the presence
// loop, the flag and the statuses are checked as source.
func TestStreaming_NeverStoresOrQueues(t *testing.T) {
	forbidden := []string{"appendFragment", "appendAssistant", "EnqueuePAOutbox", "FinishPAJob", "enqueueReply", "AppendPAFragment", "SendFrom", "deliverAfter", "deliver"}
	fset := token.NewFileSet()
	check := func(file string, n ast.Node) {
		ast.Inspect(n, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if ok && slices.Contains(forbidden, id.Name) {
				t.Errorf("%s: %s names %s", fset.Position(id.Pos()), file, id.Name)
			}
			return true
		})
	}
	for _, file := range []string{"typing.go", "streaming.go", "toolstatus.go"} {
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		check(file, f)
	}
	f, err := parser.ParseFile(fset, "runloop.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == "serveDraft" {
			found = true
			check("serveDraft", fn)
		}
	}
	if !found {
		t.Fatal("serveDraft not found in runloop.go")
	}
	// The guard can fail: serveReply does name them.
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == "serveReply" {
			n := 0
			ast.Inspect(fn, func(x ast.Node) bool {
				if id, ok := x.(*ast.Ident); ok && slices.Contains(forbidden, id.Name) {
					n++
				}
				return true
			})
			if n == 0 {
				t.Fatal("the forbidden list matches nothing in serveReply: the guard is blind")
			}
		}
	}
}

// TestPresence_ReclaimUpdatesRef: a job claimed again keeps its presence
// entry, and the refresher's check must ask about the attempt that runs
// now. Asking about the old attempt would read "stale" and drop the
// drafts of a live run.
func TestPresence_ReclaimUpdatesRef(t *testing.T) {
	var mu sync.Mutex
	var asked []int
	tr := newTypingTracker(&typingRecorder{}, time.Now)
	tr.interval = 2 * time.Millisecond
	tr.refresh = 0
	tr.drafts = &draftRecorder{}
	tr.check = func(_ context.Context, ref jobs.Ref) error {
		mu.Lock()
		defer mu.Unlock()
		asked = append(asked, ref.Attempt)
		return nil
	}
	first := jobs.Ref{Principal: TestAliceID, JobID: 7, Attempt: 1, Digest: "d1"}
	second := jobs.Ref{Principal: TestAliceID, JobID: 7, Attempt: 2, Digest: "d2"}
	tr.begin(first, time.Now().Add(time.Minute))
	t.Cleanup(func() { tr.stop(7) })
	if !tr.showDraft(context.Background(), first, safetext.ServerText(safetext.TextStatusUsingTool)) {
		t.Fatal("first draft not shown")
	}
	tr.begin(second, time.Now().Add(time.Minute))
	mu.Lock()
	asked = nil
	mu.Unlock()
	waitFor(t, "a check after the re-claim", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(asked) >= 3
	})
	mu.Lock()
	defer mu.Unlock()
	// One check may have been in flight when the job was claimed again.
	if got := asked[len(asked)-1]; got != 2 {
		t.Fatalf("checks asked about attempts %v after the re-claim; want attempt 2", asked)
	}
}
