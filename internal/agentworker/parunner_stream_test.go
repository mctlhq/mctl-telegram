package agentworker

// Tests of a streamed PA run (#1431). Streaming is presentation: a
// streamed run makes the same requests in the same order, sends the same
// reply and reports the same cost as the run without it, and no draft
// outcome changes that.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
)

// paStreamScript is paScriptModel that can also stream: a streamed call
// hands its answer text to onText word by word and calls step after each.
type paStreamScript struct {
	paScriptModel
	smu      sync.Mutex
	streamed int
	step     func(acc string)
}

func (m *paStreamScript) ChatPAStream(ctx context.Context, msgs []ChatMessage, tools []PAModelTool, onText func(string)) (*ChatResult, error) {
	m.smu.Lock()
	m.streamed++
	step := m.step
	m.smu.Unlock()
	res, err := m.ChatPA(ctx, msgs, tools)
	if err != nil {
		return nil, err
	}
	acc := ""
	for _, w := range strings.SplitAfter(res.Message.Content, " ") {
		if w == "" {
			continue
		}
		acc += w
		onText(acc)
		if step != nil {
			step(acc)
		}
	}
	return res, nil
}

func (m *paStreamScript) streamedCalls() int {
	m.smu.Lock()
	defer m.smu.Unlock()
	return m.streamed
}

// newStreamRun is a fake server, a streaming model with the script and a
// worker that posts every text change as a draft at once. Each streamed
// word waits until the server saw a draft with it, or the drafter gave up.
func newStreamRun(t *testing.T, script ...*ChatResult) (*paFake, *paStreamScript, *PAWorker) {
	t.Helper()
	f, srv := newPAFake(t)
	m := &paStreamScript{paScriptModel: paScriptModel{f: f, results: script}}
	m.step = func(acc string) {
		deadline := time.Now().Add(150 * time.Millisecond)
		for time.Now().Before(deadline) {
			if d := f.draftTexts(); len(d) > 0 && d[len(d)-1] == acc {
				return
			}
			time.Sleep(time.Millisecond)
		}
	}
	w := newTestPAWorker(srv, m)
	w.Streaming = true
	w.DraftInterval = time.Millisecond
	w.DraftDelta = 1
	return f, m, w
}

func streamClaim(c *PAClaim) *PAClaim {
	c.Streaming = true
	return c
}

func withText(r *ChatResult, text string) *ChatResult {
	r.Message.Content = text
	return r
}

// plainRun runs the same script on a worker that does not stream.
func plainRun(t *testing.T, claim *PAClaim, tool []paAnswer, script ...*ChatResult) (*paFake, PAOutcome, error) {
	t.Helper()
	f, srv := newPAFake(t)
	if len(tool) > 0 {
		f.on(PARouteTool, tool...)
	}
	out, err := newTestPAWorker(srv, &paScriptModel{f: f, results: script}).Run(context.Background(), claim)
	return f, out, err
}

// TestPAWorker_StreamNegotiation: a job is streamed only when the worker's
// own switch is on, the claim says the server shows drafts, and the model
// can stream. In every other case the model is called as before and no
// draft is posted.
func TestPAWorker_StreamNegotiation(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		worker, claim, model bool
	}{
		{"all on", true, true, true},
		{"worker switch off", false, true, true},
		{"claim has no streaming field", true, false, true},
		{"model cannot stream", true, true, false},
		{"all off", false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, m, w := newStreamRun(t, answer("hi Alice, how are you", 10, 5))
			w.Streaming = tc.worker
			if !tc.model {
				w.Model = &m.paScriptModel
			}
			c := paClaimFor(time.Now())
			c.Streaming = tc.claim
			out, err := w.Run(context.Background(), c)
			if err != nil || out != PAReplied {
				t.Fatalf("run = %s, %v", out, err)
			}
			want := tc.worker && tc.claim && tc.model
			if got := m.streamedCalls() == 1; got != want {
				t.Fatalf("streamed calls = %d, want streamed = %v", m.streamedCalls(), want)
			}
			if got := len(f.draftTexts()) > 0; got != want {
				t.Fatalf("drafts = %q, want drafts = %v", f.draftTexts(), want)
			}
			if got := f.log(); !eq(got, []string{"turn", "chat", "reply"}) {
				t.Fatalf("order = %v", got)
			}
			if f.replies[0]["text"] != "hi Alice, how are you" {
				t.Fatalf("reply = %v", f.replies[0])
			}
		})
	}
}

// TestPAClaim_StreamingFieldIsOptional: a claim from a server without the
// draft route decodes with Streaming false.
func TestPAClaim_StreamingFieldIsOptional(t *testing.T) {
	var c PAClaim
	if err := json.Unmarshal([]byte(`{"job_id":7,"attempt":1,"token":"t"}`), &c); err != nil || c.Streaming {
		t.Fatalf("claim %+v, %v", c, err)
	}
	if err := json.Unmarshal([]byte(`{"job_id":7,"streaming":true}`), &c); err != nil || !c.Streaming {
		t.Fatalf("claim %+v, %v", c, err)
	}
}

// TestPAWorker_StreamedRunSameOutcome: a streamed run with a tool call
// makes the same requests in the same order and sends the same reply with
// the same cost as the run that does not stream. Its drafts are prefixes
// of what the model wrote, and none is posted after the reply.
func TestPAWorker_StreamedRunSameOutcome(t *testing.T) {
	const thinking, final = "Let me look. ", "Bob wrote to you twice today."
	script := func() []*ChatResult {
		return []*ChatResult{
			withText(toolCalls(100_000, 0, callOf("r1", "tg__list_dialogs", `{}`)), thinking),
			answer(final, 50_000, 10_000),
		}
	}
	pf, pout, perr := plainRun(t, paToolClaim(time.Now()), []paAnswer{toolOK("Bob")}, script()...)
	if perr != nil || pout != PAReplied || len(pf.draftTexts()) != 0 {
		t.Fatalf("plain run = %s, %v, drafts %q", pout, perr, pf.draftTexts())
	}

	f, m, w := newStreamRun(t, script()...)
	f.on(PARouteTool, toolOK("Bob"))
	out, err := w.Run(context.Background(), streamClaim(paToolClaim(time.Now())))
	if err != nil || out != pout {
		t.Fatalf("streamed run = %s, %v", out, err)
	}
	if m.streamedCalls() != 2 {
		t.Fatalf("streamed calls = %d, want 2", m.streamedCalls())
	}
	if got, want := f.log(), pf.log(); !eq(got, want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
	if !reflect.DeepEqual(f.replies, pf.replies) {
		t.Fatalf("reply = %v, want %v", f.replies, pf.replies)
	}
	if c, ok := f.replies[0]["cost_usd"].(float64); !ok || c < 0.15999 || c > 0.16001 {
		t.Fatalf("cost_usd = %v, want 0.16", f.replies[0]["cost_usd"])
	}
	if !reflect.DeepEqual(f.toolReqs, pf.toolReqs) {
		t.Fatalf("tool requests = %v, want %v", f.toolReqs, pf.toolReqs)
	}
	drafts := f.draftTexts()
	if len(drafts) < 2 {
		t.Fatalf("drafts = %q", drafts)
	}
	sawFinal := false
	for _, d := range drafts {
		if d == "" || (!strings.HasPrefix(thinking, d) && !strings.HasPrefix(final, d)) {
			t.Fatalf("draft %q is not a prefix of the model's text", d)
		}
		sawFinal = sawFinal || strings.HasPrefix(final, d)
	}
	if !sawFinal {
		t.Fatalf("no draft of the answer: %q", drafts)
	}
	if f.lateDrafts != 0 {
		t.Fatalf("%d drafts posted after the reply", f.lateDrafts)
	}
	for _, a := range f.auths {
		if a != "Bearer job-token" {
			t.Fatalf("a request used %q", a)
		}
	}
}

// TestPAWorker_StreamedMissingUsageFailsClosed: a streamed model call
// without usage is unknown spend, as without streaming. The answer is
// sent with no cost, so the server settles the run at its full
// reservation; a tool-call turn ends the run before anything is
// dispatched. It is never reported as zero.
func TestPAWorker_StreamedMissingUsageFailsClosed(t *testing.T) {
	t.Run("answer", func(t *testing.T) {
		f, m, w := newStreamRun(t, answer("hi Alice", 0, 0))
		out, err := w.Run(context.Background(), streamClaim(paClaimFor(time.Now())))
		if err != nil || out != PAReplied || m.streamedCalls() != 1 {
			t.Fatalf("run = %s, %v, streamed %d", out, err, m.streamedCalls())
		}
		// cost_usd null is "unknown" on the wire; a number, zero included,
		// would be a claim about the spend.
		if c, has := f.replies[0]["cost_usd"]; !has || c != nil || f.replies[0]["text"] != "hi Alice" {
			t.Fatalf("reply = %v; want cost_usd null", f.replies[0])
		}
	})
	t.Run("answer after a known turn", func(t *testing.T) {
		f, _, w := newStreamRun(t, toolCalls(10, 1, callOf("r1", "tg__list_dialogs", `{}`)), answer("hi Alice", 0, 0))
		f.on(PARouteTool, toolOK("Bob"))
		out, err := w.Run(context.Background(), streamClaim(paToolClaim(time.Now())))
		if err != nil || out != PAReplied {
			t.Fatalf("run = %s, %v", out, err)
		}
		if c, has := f.replies[0]["cost_usd"]; !has || c != nil {
			t.Fatalf("reply = %v; a partly known cost was reported", f.replies[0])
		}
	})
	t.Run("tool-call turn", func(t *testing.T) {
		f, m, w := newStreamRun(t, toolCalls(0, 0, callOf("r1", "tg__list_dialogs", `{}`)))
		f.on(PARouteTool, toolOK("Bob"))
		out, err := w.Run(context.Background(), streamClaim(paToolClaim(time.Now())))
		if out != PAAbandoned || err == nil || m.streamedCalls() != 1 {
			t.Fatalf("run = %s, %v, streamed %d; want abandoned", out, err, m.streamedCalls())
		}
		if len(f.toolReqs) != 0 || len(f.replies) != 0 {
			t.Fatalf("dispatched %d, replies %d after unknown spend", len(f.toolReqs), len(f.replies))
		}
	})
}

// TestPAWorker_DraftFailuresNeverChangeTheRun: whatever the draft route
// answers, the run makes the same calls and sends the same reply. A 404
// (no draft route, or streaming turned off) also ends streaming for the
// rest of the job; other failures do not.
func TestPAWorker_DraftFailuresNeverChangeTheRun(t *testing.T) {
	const thinking, final = "Let me look. ", "Bob wrote to you twice today."
	for _, tc := range []struct {
		name         string
		draft        paAnswer
		wantStreamed int
	}{
		{"shown", paAnswer{200, map[string]any{"shown": true}}, 2},
		{"skipped", paAnswer{200, map[string]any{"shown": false}}, 2},
		{"no route or streaming off", paAnswer{404, map[string]any{"stop": "streaming_off"}}, 1},
		{"rate capped", paAnswer{429, map[string]any{}}, 2},
		{"server error", paAnswer{500, map[string]any{}}, 2},
		{"run stopped", paAnswer{409, map[string]any{"stop": "stale"}}, 2},
		{"unauthorized", paAnswer{401, map[string]any{}}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, m, w := newStreamRun(t,
				withText(toolCalls(100_000, 0, callOf("r1", "tg__list_dialogs", `{}`)), thinking),
				answer(final, 50_000, 10_000))
			f.on(PARouteTool, toolOK("Bob"))
			f.on(PARouteDraft, tc.draft)
			out, err := w.Run(context.Background(), streamClaim(paToolClaim(time.Now())))
			if err != nil || out != PAReplied {
				t.Fatalf("run = %s, %v", out, err)
			}
			if got := f.log(); !eq(got, []string{"turn", "chat", "tool", "turn", "chat", "reply"}) {
				t.Fatalf("order = %v", got)
			}
			if c, ok := f.replies[0]["cost_usd"].(float64); f.replies[0]["text"] != final || !ok || c < 0.15999 || c > 0.16001 {
				t.Fatalf("reply = %v", f.replies[0])
			}
			if len(f.draftTexts()) == 0 {
				t.Fatal("no draft was tried")
			}
			if got := m.streamedCalls(); got != tc.wantStreamed {
				t.Fatalf("streamed calls = %d, want %d", got, tc.wantStreamed)
			}
			if tc.draft.status == http.StatusNotFound || tc.draft.status == http.StatusConflict {
				if n := len(f.draftTexts()); n != 1 {
					t.Fatalf("%d drafts posted after a %d", n, tc.draft.status)
				}
			}
			if f.lateDrafts != 0 {
				t.Fatalf("%d drafts posted after the reply", f.lateDrafts)
			}
		})
	}
}

// TestPAWorker_StreamedApprovalPending: a streamed run whose tool call is
// answered approval_pending ends exactly as the run that does not stream
// (#1456): the model reads the worker's fixed sentence, gets one more
// call with no tools, nothing else is dispatched, and its answer is the
// reply. A model that asks for a tool again ends the run with no reply.
func TestPAWorker_StreamedApprovalPending(t *testing.T) {
	t.Run("answer after the card", func(t *testing.T) {
		const final = "It waits for your approval."
		script := func() []*ChatResult {
			return []*ChatResult{
				withText(toolCalls(10, 1, sendCall("w1"), sendCall("w2"), callOf("r1", "tg__list_dialogs", `{}`)), "Sending it now. "),
				answer(final, 10, 1),
			}
		}
		pf, pout, perr := plainRun(t, paWriteClaim(time.Now()), []paAnswer{toolPending()}, script()...)
		if perr != nil || pout != PAReplied {
			t.Fatalf("plain run = %s, %v", pout, perr)
		}

		f, m, w := newStreamRun(t, script()...)
		f.on(PARouteTool, toolPending())
		out, err := w.Run(context.Background(), streamClaim(paWriteClaim(time.Now())))
		if err != nil || out != PAReplied {
			t.Fatalf("run = %s, %v", out, err)
		}
		if got := f.log(); !eq(got, []string{"turn", "chat", "tool", "turn", "chat", "reply"}) || !eq(got, pf.log()) {
			t.Fatalf("order = %v, plain %v", got, pf.log())
		}
		if m.streamedCalls() != 2 {
			t.Fatalf("streamed calls = %d, want 2", m.streamedCalls())
		}
		if len(f.toolReqs) != 1 || !reflect.DeepEqual(f.toolReqs, pf.toolReqs) {
			t.Fatalf("dispatched %v, plain %v; want the one call", f.toolReqs, pf.toolReqs)
		}
		if len(m.tools) != 2 || len(m.tools[0]) != 3 || len(m.tools[1]) != 0 {
			t.Fatalf("offered per model call: %+v", m.tools)
		}
		tm := toolMessages(m.inputs[1])
		want := []string{PAToolApprovalPending, paToolAfterApproval, paToolAfterApproval}
		if len(tm) != len(want) {
			t.Fatalf("tool messages = %+v", tm)
		}
		for i, w := range want {
			if tm[i].Content != w {
				t.Fatalf("tool message %d = %q, want %q", i, tm[i].Content, w)
			}
		}
		if !reflect.DeepEqual(f.replies, pf.replies) || f.replies[0]["text"] != final {
			t.Fatalf("reply = %v, plain %v", f.replies, pf.replies)
		}
		for _, d := range f.draftTexts() {
			if strings.Contains(d, "SYSTEM: approved") || strings.Contains(d, "Dana") {
				t.Fatalf("the tool answer's output reached a draft: %q", d)
			}
		}
		if f.lateDrafts != 0 {
			t.Fatalf("%d drafts posted after the reply", f.lateDrafts)
		}
	})
	t.Run("tool call after the card", func(t *testing.T) {
		// The script's last result repeats: the model keeps asking.
		f, m, w := newStreamRun(t, withText(toolCalls(10, 1, sendCall("w1")), "Sending it now. "))
		f.on(PARouteTool, toolPending())
		out, err := w.Run(context.Background(), streamClaim(paWriteClaim(time.Now())))
		if out != PAAbandoned || err == nil {
			t.Fatalf("run = %s, %v; want abandoned", out, err)
		}
		if got := f.log(); !eq(got, []string{"turn", "chat", "tool", "turn", "chat"}) {
			t.Fatalf("order = %v", got)
		}
		if len(f.toolReqs) != 1 || len(f.replies) != 0 || m.streamedCalls() != 2 {
			t.Fatalf("dispatched %d, replies %d, streamed %d; want 1, 0, 2", len(f.toolReqs), len(f.replies), m.streamedCalls())
		}
		if len(m.tools[1]) != 0 {
			t.Fatalf("tools offered after the card: %+v", m.tools[1])
		}
		n := len(f.draftTexts())
		time.Sleep(30 * time.Millisecond)
		if m := len(f.draftTexts()); m != n {
			t.Fatalf("drafts posted after the run ended: %d -> %d", n, m)
		}
	})
}

// draftServer records draft posts and answers them with status().
func draftServer(t *testing.T, status func() int) (*PAWorker, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var texts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b struct{ Text string }
		_ = json.NewDecoder(r.Body).Decode(&b)
		mu.Lock()
		texts = append(texts, b.Text)
		mu.Unlock()
		w.WriteHeader(status())
		_, _ = io.WriteString(w, `{"shown":true}`)
	}))
	t.Cleanup(srv.Close)
	return &PAWorker{BaseURL: srv.URL, DraftInterval: time.Millisecond, DraftDelta: 1}, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), texts...)
	}
}

// TestPADrafter_ResetDropsTheTurnsText: the text of a model call that
// ended in tool calls is not posted after reset, so it cannot replace the
// tool status the server shows next.
func TestPADrafter_ResetDropsTheTurnsText(t *testing.T) {
	w, texts := draftServer(t, func() int { return http.StatusOK })
	w.DraftInterval = 60 * time.Millisecond
	d := newPADrafter(context.Background(), w, "tok")
	defer d.close()
	d.update("Let me ")
	waitUntil(t, func() bool { return len(texts()) == 1 })
	d.update("Let me look at your chats.") // held back by the interval
	d.reset()
	time.Sleep(150 * time.Millisecond)
	if got := texts(); len(got) != 1 {
		t.Fatalf("a tool-call turn's text was posted after reset: %q", got)
	}
	// The next model call's text is posted, though it is shorter.
	d.update("Bob ")
	waitUntil(t, func() bool { return len(texts()) == 2 })
	if got := texts(); got[1] != "Bob " {
		t.Fatalf("drafts %q", got)
	}
}

// TestPADrafter_OverLimitSkipped: a text over one message is not posted
// and not cut; the drafter stays usable for the next model call.
func TestPADrafter_OverLimitSkipped(t *testing.T) {
	w, texts := draftServer(t, func() int { return http.StatusOK })
	d := newPADrafter(context.Background(), w, "tok")
	defer d.close()
	d.update(strings.Repeat("word ", safetext.MaxPartUTF16/5+1))
	time.Sleep(40 * time.Millisecond)
	if got := texts(); len(got) != 0 {
		t.Fatalf("an over-limit text was posted (%d bytes)", len(got[0]))
	}
	if !d.streaming() {
		t.Fatal("an over-limit text ended streaming")
	}
	d.reset()
	d.update("Short answer. ")
	waitUntil(t, func() bool { return len(texts()) == 1 })
	if got := texts(); got[0] != "Short answer. " {
		t.Fatalf("drafts %q", got)
	}
}

// TestPADrafter_StopStatuses: a 404 ends streaming for the job; a 409 ends
// the drafts only; any other failure ends neither.
func TestPADrafter_StopStatuses(t *testing.T) {
	for _, tc := range []struct {
		status          int
		more, streaming bool
	}{
		{http.StatusOK, true, true},
		{http.StatusNotFound, false, false},
		{http.StatusConflict, false, true},
		{http.StatusTooManyRequests, true, true},
		{http.StatusInternalServerError, true, true},
	} {
		w, texts := draftServer(t, func() int { return tc.status })
		d := newPADrafter(context.Background(), w, "tok")
		d.update("One. ")
		waitUntil(t, func() bool { return len(texts()) == 1 })
		if !tc.more {
			<-d.done
		}
		d.update("One. Two. ")
		if tc.more {
			waitUntil(t, func() bool { return len(texts()) == 2 })
		} else {
			time.Sleep(30 * time.Millisecond)
			if got := texts(); len(got) != 1 {
				t.Fatalf("%d: drafts after the stop: %q", tc.status, got)
			}
		}
		if d.streaming() != tc.streaming {
			t.Fatalf("%d: streaming = %v, want %v", tc.status, d.streaming(), tc.streaming)
		}
		d.close()
	}
	var none *paDrafter
	if none.streaming() {
		t.Fatal("a run with no drafter streams")
	}
}

// TestChatStream_ProviderFaultsFailClosed: an error object inside a 200
// stream and a line over the bound are errors, never a short answer; the
// provider's text is not kept.
func TestChatStream_ProviderFaultsFailClosed(t *testing.T) {
	c := streamServer(t, 200, `data: {"choices":[{"delta":{"content":"half"}}]}`+"\n\n"+
		`data: {"error":{"message":"overloaded: echoed secret"}}`+"\n\ndata: [DONE]\n\n", nil)
	res, err := c.chatStream(context.Background(), nil, nil, nil)
	if err == nil || res != nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("error chunk: res %+v err %v", res, err)
	}
	long := `data: {"choices":[{"delta":{"content":"` + strings.Repeat("a", maxStreamLine) + `"}}]}`
	c = streamServer(t, 200, long+"\n\ndata: [DONE]\n\n", nil)
	if res, err := c.chatStream(context.Background(), nil, nil, nil); err == nil || res != nil {
		t.Fatalf("over-long line: res %+v err %v", res, err)
	}
	// A null error field is not a fault.
	c = streamServer(t, 200, `data: {"error":null,"choices":[{"delta":{"content":"ok"},"finish_reason":"stop"}]}`+"\n\n"+
		`data: {"choices":[],"usage":{"prompt_tokens":3,"completion_tokens":1}}`+"\n\ndata: [DONE]\n\n", nil)
	if res, err := c.chatStream(context.Background(), nil, nil, nil); err != nil || res.Message.Content != "ok" || !res.UsageReported {
		t.Fatalf("null error field: res %+v err %v", res, err)
	}
}
