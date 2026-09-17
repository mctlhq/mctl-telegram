package events

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

func sampleEvent() db.IncomingEvent {
	return db.IncomingEvent{
		EventID: "evt:v1:210408407:555:42", UserID: 1, Kind: db.EventKindPrivateMessage,
		ChatTGID: 555, SenderTGID: 555, MessageID: 42,
		Body: "the secret message text",
		Meta: `{"username":"anna_secret","display_name":"Anna Secret"}`,
	}
}

func TestBuildEnvelope_ReferencesOnly(t *testing.T) {
	env, err := BuildEnvelope(sampleEvent(), time.Date(2026, 9, 17, 8, 0, 0, 0, time.FixedZone("x", 3600)))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := env.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	for _, leaked := range []string{"secret", "Anna", "anna"} {
		if strings.Contains(raw, leaked) {
			t.Fatalf("envelope leaks %q: %s", leaked, raw)
		}
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"specversion": "mctl.events/v1", "id": "telegram:evt:v1:210408407:555:42",
		"type": "telegram.message.created", "source": "mctl-telegram",
		"occurred_at": "2026-09-17T07:00:00Z", "correlation_id": "telegram:evt:v1:210408407:555:42",
		"subject": map[string]any{"kind": "telegram.message", "account_id": "1", "chat_id": "555",
			"message_id": "42", "peer": "user:555"},
	}
	if fmt.Sprint(doc) != fmt.Sprint(want) {
		t.Fatalf("envelope = %v\nwant       %v", doc, want)
	}
}

func TestBuildEnvelope_KindsAndValidation(t *testing.T) {
	edit := sampleEvent()
	edit.Kind = db.EventKindMessageEdit
	if env, err := BuildEnvelope(edit, time.Now()); err != nil || env.Type != "telegram.message.edited" {
		t.Fatalf("edit: %+v %v", env, err)
	}
	for _, kind := range []string{db.EventKindOwnerOutgoing, db.EventKindSavedCommand} {
		if Publishable(kind) {
			t.Fatalf("%s must not be published", kind)
		}
		if row, ok, err := OutboxBuilder(DefaultStream)(db.IncomingEvent{Kind: kind}, time.Now()); ok || err != nil {
			t.Fatalf("builder for %s: row=%+v ok=%v err=%v", kind, row, ok, err)
		}
	}
	missing := sampleEvent()
	missing.MessageID = 0
	if _, err := BuildEnvelope(missing, time.Now()); err == nil {
		t.Fatal("event without a message id must not build")
	}
}

// --- relay -------------------------------------------------------------------

type fakeStore struct {
	mu        sync.Mutex
	rows      []db.OutboxRow
	published map[int64]time.Time
	failures  map[int64]string
	markErr   error
}

func (f *fakeStore) PendingOutbox(_ context.Context, limit int) ([]db.OutboxRow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []db.OutboxRow
	for _, r := range f.rows {
		if _, done := f.published[r.ID]; !done && len(out) < limit {
			out = append(out, r)
		}
	}
	return out, nil
}
func (f *fakeStore) MarkOutboxPublished(_ context.Context, id int64, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.markErr != nil {
		return f.markErr
	}
	f.published[id] = at
	return nil
}
func (f *fakeStore) MarkOutboxFailed(_ context.Context, id int64, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failures[id] = reason
	return nil
}
func (f *fakeStore) PurgePublishedOutbox(context.Context, time.Time) (int64, error) { return 0, nil }
func (f *fakeStore) OutboxBacklog(context.Context) (int64, error)                   { return 0, nil }

type fakePub struct {
	mu      sync.Mutex
	calls   [][]string
	failOn  string
	failErr error
}

func (p *fakePub) XAdd(stream string, maxLen int, fields ...string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failOn != "" && stream == p.failOn {
		return "", p.failErr
	}
	p.calls = append(p.calls, append([]string{stream}, fields...))
	return "1-0", nil
}
func (p *fakePub) Close() {}

func newFakes(n int) (*fakeStore, *fakePub) {
	st := &fakeStore{published: map[int64]time.Time{}, failures: map[int64]string{}}
	for i := 1; i <= n; i++ {
		st.rows = append(st.rows, db.OutboxRow{ID: int64(i), EventID: fmt.Sprintf("evt:v1:1:555:%d", i),
			Stream: DefaultStream, Envelope: fmt.Sprintf(`{"n":%d}`, i), CreatedAt: time.Now()})
	}
	return st, &fakePub{}
}

func TestRelay_PublishesInOrderAndAudits(t *testing.T) {
	st, pub := newFakes(3)
	r := NewRelay(st, pub, nil)
	if err := r.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	var events, audits []string
	for _, c := range pub.calls {
		switch c[0] {
		case DefaultStream:
			events = append(events, c[2])
		case AuditStream:
			audits = append(audits, strings.Join(c[1:], " "))
		}
	}
	if strings.Join(events, ",") != `{"n":1},{"n":2},{"n":3}` {
		t.Fatalf("published = %v", events)
	}
	if len(audits) != 3 || !strings.Contains(audits[0], "stage published") ||
		!strings.Contains(audits[0], "event_id telegram:evt:v1:1:555:1") {
		t.Fatalf("audit = %v", audits)
	}
	if len(st.published) != 3 || testutil.ToFloat64(r.published) != 3 {
		t.Fatalf("marked %d, counter %v", len(st.published), testutil.ToFloat64(r.published))
	}
}

func TestRelay_OutageStopsAtFirstFailureAndKeepsRows(t *testing.T) {
	st, pub := newFakes(3)
	pub.failOn, pub.failErr = DefaultStream, errors.New("connection refused")
	r := NewRelay(st, pub, nil)
	if err := r.Drain(context.Background()); err == nil {
		t.Fatal("drain during an outage must report the failure")
	}
	if len(st.failures) != 1 || len(st.published) != 0 || testutil.ToFloat64(r.failures) != 1 {
		t.Fatalf("failures=%v published=%v", st.failures, st.published)
	}
	pub.failOn = ""
	if err := r.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(st.published) != 3 {
		t.Fatalf("after recovery published %d, want 3", len(st.published))
	}
}

func TestRelay_AuditFailureDoesNotBlockDelivery(t *testing.T) {
	st, pub := newFakes(2)
	pub.failOn, pub.failErr = AuditStream, &ServerError{Msg: "NOPERM"}
	r := NewRelay(st, pub, nil)
	if err := r.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(st.published) != 2 {
		t.Fatalf("published %d, want 2", len(st.published))
	}
}

func TestRelay_UnmarkedPublishIsRetriedNotLost(t *testing.T) {
	st, pub := newFakes(1)
	st.markErr = errors.New("db gone")
	r := NewRelay(st, pub, nil)
	if err := r.Drain(context.Background()); err == nil {
		t.Fatal("want the mark failure reported")
	}
	st.markErr = nil
	if err := r.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Published twice with the same envelope: the consumer deduplicates by id.
	n := 0
	for _, c := range pub.calls {
		if c[0] == DefaultStream {
			n++
		}
	}
	if n != 2 || len(st.published) != 1 {
		t.Fatalf("xadd=%d marked=%d, want 2 and 1", n, len(st.published))
	}
}

// --- RESP client against an in-process server ---------------------------------

func fakeValkey(t *testing.T, handle func(args []string) string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					var n int
					fmt.Sscanf(line, "*%d", &n)
					args := make([]string, n)
					for i := range args {
						_, _ = r.ReadString('\n')
						v, _ := r.ReadString('\n')
						args[i] = strings.TrimSuffix(v, "\r\n")
					}
					_, _ = c.Write([]byte(handle(args)))
				}
			}(conn)
		}
	}()
	return "redis://telegram-producer@" + ln.Addr().String() + "/0"
}

func TestClient_AuthThenXAdd(t *testing.T) {
	var mu sync.Mutex
	var seen [][]string
	url := fakeValkey(t, func(args []string) string {
		mu.Lock()
		seen = append(seen, args)
		mu.Unlock()
		switch args[0] {
		case "AUTH":
			if len(args) == 3 && args[1] == "telegram-producer" && args[2] == "pw" {
				return "+OK\r\n"
			}
			return "-WRONGPASS invalid\r\n"
		case "XADD":
			return "$15\r\n1789626542319-0\r\n"
		}
		return "-ERR unknown\r\n"
	})
	c, err := NewClient(url, "pw", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	id, err := c.XAdd(DefaultStream, 10000, "envelope", `{"a":1}`)
	if err != nil || id != "1789626542319-0" {
		t.Fatalf("xadd = %q, %v", id, err)
	}
	mu.Lock()
	defer mu.Unlock()
	want := "XADD mctl:events:telegram MAXLEN ~ 10000 * envelope {\"a\":1}"
	if len(seen) != 2 || strings.Join(seen[1], " ") != want {
		t.Fatalf("commands = %v", seen)
	}
}

func TestClient_ServerErrorIsTypedAndPasswordNeverInURL(t *testing.T) {
	url := fakeValkey(t, func(args []string) string {
		if args[0] == "AUTH" {
			return "+OK\r\n"
		}
		return "-NOPERM No permissions to access a key\r\n"
	})
	c, _ := NewClient(url, "pw", time.Second)
	defer c.Close()
	_, err := c.XAdd("mctl:events:github", 10, "envelope", "{}")
	var se *ServerError
	if !errors.As(err, &se) || !strings.HasPrefix(se.Msg, "NOPERM") {
		t.Fatalf("err = %v, want NOPERM ServerError", err)
	}
	if _, err := NewClient("redis://u:secret@127.0.0.1:6379/0", "", 0); err == nil {
		t.Fatal("a password embedded in the URL must be refused")
	}
}

// TestClient_RealValkey runs only against a real server (VALKEY_TEST_URL).
func TestClient_RealValkey(t *testing.T) {
	url := os.Getenv("VALKEY_TEST_URL")
	if url == "" {
		t.Skip("VALKEY_TEST_URL not set")
	}
	c, err := NewClient(url, os.Getenv("VALKEY_TEST_PASSWORD"), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.XAdd("mctl:events:telegram", 100, "envelope", `{"probe":true}`); err != nil {
		t.Fatal(err)
	}
}
