package pa

// streaming_e2e_test.go runs a streamed job end to end (#1431): the real
// worker and its real OpenAI client against a scripted provider that
// answers in server-sent events, and the real run loop over HTTP, on
// SQLite and on Postgres. The streamed run is compared with the same run
// with the flag off.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/agentworker"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// sseProvider answers every chat call with answer: as server-sent events,
// word by word, when the request asks for a stream, and as one JSON body
// otherwise. It records which kind each request was.
type sseProvider struct {
	answer string
	mu     sync.Mutex
	stream []bool
}

func (p *sseProvider) calls() []bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]bool(nil), p.stream...)
}

func (p *sseProvider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var req struct {
		Stream bool `json:"stream"`
	}
	_ = json.Unmarshal(body, &req)
	p.mu.Lock()
	p.stream = append(p.stream, req.Stream)
	p.mu.Unlock()
	const usage = `{"prompt_tokens":20000,"completion_tokens":1000}`
	if !req.Stream {
		msg, _ := json.Marshal(p.answer)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"choices":[{"message":{"role":"assistant","content":%s},"finish_reason":"stop"}],"usage":%s}`, msg, usage)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	fl, _ := w.(http.Flusher)
	for _, word := range strings.SplitAfter(p.answer, " ") {
		delta, _ := json.Marshal(word)
		fmt.Fprintf(w, "data: {\"choices\":[{\"delta\":{\"content\":%s}}]}\n\n", delta)
		if fl != nil {
			fl.Flush()
		}
		time.Sleep(15 * time.Millisecond)
	}
	fmt.Fprintf(w, "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n")
	fmt.Fprintf(w, "data: {\"choices\":[],\"usage\":%s}\n\ndata: [DONE]\n\n", usage)
}

type e2eStreamResult struct {
	sent      []string
	drafts    []string
	typing    int
	streamed  []bool
	fragments int
	outbox    int
	job       string
	usage     string
	cost      float64
	reported  *float64
}

func runStreamE2E(t *testing.T, store *db.Store, flag string) e2eStreamResult {
	t.Helper()
	const question = "what is on https://example.org/a ?"
	rec, typing := &draftRecorder{}, &typingRecorder{}
	h := newRunLoopHarnessOn(t, store, withStreaming(rec, typing, newStreamFlag(flag)))
	h.loop.limiter.minInterval = 0
	h.consent(aliceID)
	h.text(aliceID, question)
	prov := &sseProvider{answer: "It is https://example.org/a and not https://evil.example/x at all, " +
		"so open the first link only. That is everything I found for you today."}
	psrv := httptest.NewServer(prov)
	t.Cleanup(psrv.Close)
	w := newE2EWorker(t, h, &agentworker.OpenAIClient{BaseURL: psrv.URL, APIKey: "test-key", Model: "test-model", HTTP: psrv.Client()})
	w.Streaming = true
	w.DraftInterval = time.Millisecond
	w.DraftDelta = 1
	c, err := w.Claim(context.Background())
	if err != nil || c == nil {
		t.Fatalf("claim = %v, %v", c, err)
	}
	out, err := w.Run(context.Background(), c)
	if err != nil || out != agentworker.PAReplied {
		t.Fatalf("run = %s, %v", out, err)
	}
	res := e2eStreamResult{sent: h.sentTo(aliceID), streamed: prov.calls()}
	// Whatever is sent after the reply was queued would show here.
	time.Sleep(50 * time.Millisecond)
	res.drafts, res.typing = rec.all(), typing.count(aliceID)
	res.fragments = h.fragments(aliceID)
	res.outbox = h.count(`SELECT count(*) FROM pa_outbox`)
	res.job, res.usage = h.jobStatus(c.JobID)
	res.cost, res.reported = e2eUsage(t, h, c.JobID)
	if h.loop.typing.active() != 0 {
		t.Fatal("presence still running after the reply")
	}
	return res
}

// TestStreamingE2E: a streamed job shows growing drafts and then sends
// exactly the message, stores exactly the rows and settles exactly the
// cost of the same job with the flag off.
func TestStreamingE2E(t *testing.T) {
	stores := map[string]func(*testing.T) *db.Store{"sqlite": newStore, "postgres": newPostgresStore}
	for name, open := range stores {
		t.Run(name, func(t *testing.T) {
			if name == "postgres" && os.Getenv("TEST_DATABASE_URL") == "" {
				t.Skip("TEST_DATABASE_URL not set")
			}
			// Each run has its own store, named after its subtest.
			var off, on e2eStreamResult
			t.Run("flag off", func(t *testing.T) { off = runStreamE2E(t, open(t), "false") })
			t.Run("flag on", func(t *testing.T) { on = runStreamE2E(t, open(t), "true") })
			if t.Failed() || len(off.sent) == 0 || len(on.sent) == 0 {
				t.Fatalf("runs did not finish: off %+v on %+v", off, on)
			}

			// Flag off: the model call is not streamed and nothing is drafted.
			if len(off.streamed) != 1 || off.streamed[0] || len(off.drafts) != 0 {
				t.Fatalf("flag off: streamed %v drafts %q", off.streamed, off.drafts)
			}
			if len(off.sent) != 1 || !strings.Contains(off.sent[0], "https://example.org/a") || strings.Contains(off.sent[0], "://evil") {
				t.Fatalf("flag off: sent %q", off.sent)
			}

			// Flag on: the call is streamed and drafts are shown.
			if len(on.streamed) != 1 || !on.streamed[0] {
				t.Fatalf("flag on: streamed %v", on.streamed)
			}
			if len(on.drafts) < 3 {
				t.Fatalf("flag on: drafts %q, want a growing answer", on.drafts)
			}
			final := on.sent[0]
			for i, d := range on.drafts {
				if !strings.HasPrefix(final, strings.TrimRight(d, " ")) {
					t.Fatalf("draft %d %q is not a prefix of the answer %q", i, d, final)
				}
				if strings.Contains(d, "://evil") || strings.Contains(d, "evil.example") {
					t.Fatalf("draft %d shows a link the principal did not type: %q", i, d)
				}
				if i > 0 && len(d) < len(on.drafts[i-1]) {
					t.Fatalf("draft %d is shorter than the one before: %q", i, on.drafts)
				}
			}
			if last := on.drafts[len(on.drafts)-1]; len(last) <= len(on.drafts[0]) {
				t.Fatalf("drafts did not grow: %q", on.drafts)
			}

			// The same outcome either way.
			if len(on.sent) != 1 || on.sent[0] != off.sent[0] {
				t.Fatalf("sent %q with streaming, %q without", on.sent, off.sent)
			}
			if on.fragments != off.fragments || on.outbox != off.outbox || on.outbox != 1 {
				t.Fatalf("stored: fragments %d outbox %d with streaming, %d and %d without", on.fragments, on.outbox, off.fragments, off.outbox)
			}
			if on.job != "done" || on.usage != "settled" || on.job != off.job || on.usage != off.usage {
				t.Fatalf("job %s usage %s with streaming, %s %s without", on.job, on.usage, off.job, off.usage)
			}
			if on.reported == nil || off.reported == nil || *on.reported != *off.reported || on.cost != off.cost ||
				*on.reported < 0.0209 || *on.reported > 0.0211 {
				t.Fatalf("settled %v (reported %v) with streaming, %v (%v) without; want 0.021", on.cost, on.reported, off.cost, off.reported)
			}
		})
	}
}
