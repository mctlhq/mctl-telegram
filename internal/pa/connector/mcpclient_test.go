package connector

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
)

// fakeServer is a minimal MCP Streamable HTTP server. The tests reach it
// with the httptest TLS client: egress refuses loopback by design, and is
// tested on its own in internal/pa/egress.
type fakeServer struct {
	mu    sync.Mutex
	sse   bool
	pages []string // tools/list result objects, chained by cursor
	// pageStatus forces the status of the tools/list request for page i.
	pageStatus map[int]int
	status     int // forced status for every request, 0 = normal
	bearers    []string
	sessions   []string
	methods    []string
	badID      bool
	// nullResult answers every request with "result": null.
	nullResult bool
	// noContentType sends the JSON body without a Content-Type.
	noContentType bool
	// notifyStatus forces the status of notifications (0 = 202).
	notifyStatus int
	deletes      []string // session ids of DELETE requests
	// onCall runs when tools/call arrives (under the lock).
	onCall func()
	// callResult replaces the tools/call result object when set.
	callResult string
	// calls records the params of every tools/call.
	calls []string
}

func (f *fakeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bearers = append(f.bearers, r.Header.Get("Authorization"))
	f.sessions = append(f.sessions, r.Header.Get("Mcp-Session-Id"))
	if r.Method == http.MethodDelete {
		f.deletes = append(f.deletes, r.Header.Get("Mcp-Session-Id"))
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if f.status != 0 {
		w.WriteHeader(f.status)
		return
	}
	body, _ := io.ReadAll(r.Body)
	var m struct {
		ID     *int64          `json:"id"`
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	f.methods = append(f.methods, m.Method)
	if m.ID == nil {
		if f.notifyStatus != 0 {
			w.WriteHeader(f.notifyStatus)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}
	var result string
	switch m.Method {
	case "initialize":
		w.Header().Set("Mcp-Session-Id", "sess-1")
		result = `{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"fake","version":"1"}}`
	case "tools/list":
		var p struct {
			Cursor string `json:"cursor"`
		}
		_ = json.Unmarshal(m.Params, &p)
		i := 0
		if p.Cursor != "" {
			_, _ = fmt.Sscanf(p.Cursor, "c%d", &i)
		}
		if st := f.pageStatus[i]; st != 0 {
			w.WriteHeader(st)
			return
		}
		result = f.pages[i]
	case "tools/call":
		if f.onCall != nil {
			f.onCall()
		}
		result = `{"content":[{"type":"text","text":"ok"}]}`
		if f.callResult != "" {
			result = f.callResult
		}
		f.calls = append(f.calls, string(m.Params))
	default:
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if f.nullResult {
		result = "null"
	}
	id := *m.ID
	if f.badID {
		id += 100
	}
	msg := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"result":%s}`, id, result)
	if f.sse {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprintf(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n")
		_, _ = fmt.Fprintf(w, "event: message\ndata: %s\n\n", msg)
		return
	}
	if f.noContentType {
		w.Header()["Content-Type"] = nil
	} else {
		w.Header().Set("Content-Type", "application/json")
	}
	_, _ = io.WriteString(w, msg)
}

func testEndpoint(t *testing.T, f *fakeServer) *Endpoint {
	t.Helper()
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	return &Endpoint{server: "tg", url: srv.URL, client: srv.Client()}
}

var tok = connection.NewSecret("fake-at-client-test")

func TestEndpoint_ListToolsPaginatesJSONAndSSE(t *testing.T) {
	for _, sse := range []bool{false, true} {
		t.Run(fmt.Sprintf("sse=%v", sse), func(t *testing.T) {
			f := &fakeServer{sse: sse, pages: []string{
				`{"tools":[{"name":"a"}],"nextCursor":"c1"}`,
				`{"tools":[{"name":"b"}]}`,
			}}
			pages, err := testEndpoint(t, f).ListTools(context.Background(), tok)
			if err != nil {
				t.Fatal(err)
			}
			if len(pages) != 2 || !strings.Contains(string(pages[1]), `"b"`) {
				t.Fatalf("pages %q", pages)
			}
			want := []string{"initialize", "notifications/initialized", "tools/list", "tools/list"}
			if len(f.deletes) != 1 || f.deletes[0] != "sess-1" {
				t.Fatalf("session not ended: %v", f.deletes)
			}
			if strings.Join(f.methods, ",") != strings.Join(want, ",") {
				t.Fatalf("methods %v", f.methods)
			}
			for i, b := range f.bearers {
				if b != "Bearer fake-at-client-test" {
					t.Fatalf("request %d bearer %q", i, b)
				}
				if i > 0 && f.sessions[i] != "sess-1" {
					t.Fatalf("request %d without the session id", i)
				}
			}
		})
	}
}

// A listing that keeps handing out cursors is a failed read, not a
// truncated list (I9).
func TestEndpoint_EndlessPaginationFails(t *testing.T) {
	pages := make([]string, maxListPages+1)
	for i := range pages {
		pages[i] = fmt.Sprintf(`{"tools":[],"nextCursor":"c%d"}`, i+1)
	}
	if _, err := testEndpoint(t, &fakeServer{pages: pages}).ListTools(context.Background(), tok); !errors.Is(err, ErrMCPProtocol) {
		t.Fatalf("err = %v", err)
	}
}

func TestEndpoint_Failures(t *testing.T) {
	cases := map[string]struct {
		f    *fakeServer
		want error
	}{
		"401":        {&fakeServer{status: http.StatusUnauthorized}, ErrMCPTokenRejected},
		"403":        {&fakeServer{status: http.StatusForbidden}, ErrMCPForbidden},
		"500":        {&fakeServer{status: http.StatusInternalServerError}, ErrMCPProtocol},
		"wrong id":   {&fakeServer{badID: true, pages: []string{`{"tools":[]}`}}, ErrMCPProtocol},
		"sse no msg": {&fakeServer{sse: true, badID: true, pages: []string{`{"tools":[]}`}}, ErrMCPProtocol},
		// A null result is a failed read, not an empty listing (I9).
		"null result": {&fakeServer{nullResult: true, pages: []string{`{"tools":[]}`}}, ErrMCPProtocol},
		// No content type: the body cannot be trusted to be either form.
		"no content type": {&fakeServer{noContentType: true, pages: []string{`{"tools":[]}`}}, ErrMCPProtocol},
		// The server refused notifications/initialized: no session.
		"notify refused": {&fakeServer{notifyStatus: http.StatusBadRequest, pages: []string{`{"tools":[]}`}}, ErrMCPProtocol},
		"notify 401":     {&fakeServer{notifyStatus: http.StatusUnauthorized, pages: []string{`{"tools":[]}`}}, ErrMCPTokenRejected},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			ep := testEndpoint(t, c.f)
			if _, err := ep.ListTools(context.Background(), tok); !errors.Is(err, c.want) {
				t.Fatalf("list err = %v, want %v", err, c.want)
			}
			if _, err := ep.CallTool(context.Background(), tok, "list_dialogs", json.RawMessage(`{}`)); !errors.Is(err, c.want) {
				t.Fatalf("call err = %v, want %v", err, c.want)
			}
		})
	}
	// A 401 (refresh and retry once) and a 403 (refused, never retried) are
	// told apart (#1318 slice C2b); both stay ErrMCPUnauthorized.
	if errors.Is(ErrMCPForbidden, ErrMCPTokenRejected) || errors.Is(ErrMCPTokenRejected, ErrMCPForbidden) ||
		!errors.Is(ErrMCPForbidden, ErrMCPUnauthorized) || !errors.Is(ErrMCPTokenRejected, ErrMCPUnauthorized) {
		t.Fatal("401 and 403 errors are not distinct kinds of ErrMCPUnauthorized")
	}
}

func TestEndpoint_CallTool(t *testing.T) {
	f := &fakeServer{}
	out, err := testEndpoint(t, f).CallTool(context.Background(), tok, "list_dialogs", json.RawMessage(`{"limit":5}`))
	if err != nil || !strings.Contains(string(out), `"ok"`) {
		t.Fatalf("out %q err %v", out, err)
	}
	if len(f.deletes) != 1 || f.deletes[0] != "sess-1" {
		t.Fatalf("session not ended: %v", f.deletes)
	}
	// The DELETE carries the connection's bearer like every request.
	if last := f.bearers[len(f.bearers)-1]; last != "Bearer fake-at-client-test" {
		t.Fatalf("delete bearer %q", last)
	}
}

// A call whose context was cancelled (fence, revoke, deadline) does not
// send the bearer again to end the session.
// TestS2D7_CallToolExactSendsTheBytes is S2-D7 at the wire: the server
// receives the approved canonical argument bytes byte for byte, where
// CallTool's json.Marshal would have escaped '<', '>' and '&' and so sent
// bytes that hash to something else.
func TestS2D7_CallToolExactSendsTheBytes(t *testing.T) {
	const args = `{"text":"<b>1 & 2</b> 5.0 5e0","to":"Carol"}`
	for _, sse := range []bool{false, true} {
		f := &fakeServer{sse: sse}
		out, err := testEndpoint(t, f).CallToolExact(context.Background(), tok, "send_message", []byte(args))
		if err != nil || !strings.Contains(string(out), `"ok"`) {
			t.Fatalf("out %q err %v", out, err)
		}
		if len(f.calls) != 1 {
			t.Fatalf("%d calls", len(f.calls))
		}
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal([]byte(f.calls[0]), &p); err != nil {
			t.Fatal(err)
		}
		if p.Name != "send_message" || string(p.Arguments) != args {
			t.Fatalf("server received %q for %q, want %q", p.Arguments, p.Name, args)
		}
		if got, want := sha256.Sum256(p.Arguments), sha256.Sum256([]byte(args)); got != want {
			t.Fatal("received arguments do not hash to the approved hash")
		}
	}
	// The marshalling path does change them: that is why it is not used.
	f := &fakeServer{}
	if _, err := testEndpoint(t, f).CallTool(context.Background(), tok, "send_message", json.RawMessage(args)); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(f.calls[0], "<b>") {
		t.Fatal("CallTool now sends bytes verbatim; the S2-D7 note in mcpclient.go is out of date")
	}
	// Anything but one bare JSON object is refused before a request.
	for _, bad := range []string{``, `[]`, `"x"`, ` {"a":1}`, `{"a":1} `, `{"a":1}{"b":2}`, `{"a":1},"x":{}`, `{"a":`} {
		f := &fakeServer{}
		if _, err := testEndpoint(t, f).CallToolExact(context.Background(), tok, "send_message", []byte(bad)); !errors.Is(err, ErrMCPProtocol) {
			t.Errorf("%q: err %v, want ErrMCPProtocol", bad, err)
		}
		if len(f.bearers) != 0 {
			t.Errorf("%q: %d requests made", bad, len(f.bearers))
		}
	}
}

func TestEndpoint_NoSessionCloseAfterCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := &fakeServer{onCall: cancel}
	_, _ = testEndpoint(t, f).CallTool(ctx, tok, "list_dialogs", json.RawMessage(`{}`))
	if len(f.deletes) != 0 {
		t.Fatalf("DELETE sent after cancel: %v", f.deletes)
	}
}

// A session whose notifications/initialized was refused is ended too.
func TestEndpoint_SessionEndedOnFailedOpen(t *testing.T) {
	f := &fakeServer{notifyStatus: http.StatusBadRequest}
	if _, err := testEndpoint(t, f).CallTool(context.Background(), tok, "list_dialogs", json.RawMessage(`{}`)); err == nil {
		t.Fatal("refused notification accepted")
	}
	if len(f.deletes) != 1 {
		t.Fatalf("session not ended: %v", f.deletes)
	}
}

// Errors never carry the bearer.
func TestEndpoint_ErrorsDoNotCarryTheToken(t *testing.T) {
	ep := &Endpoint{server: "tg", url: "https://127.0.0.1:1/", client: http.DefaultClient}
	_, err := ep.ListTools(context.Background(), tok)
	if err == nil || strings.Contains(err.Error(), "fake-at") {
		t.Fatalf("err = %v", err)
	}
}

func TestNewEndpoint_RefusesNonHTTPS(t *testing.T) {
	for _, u := range []string{"http://tg.example/mcp", "https://tg.example:8443/mcp", "https://user@tg.example/mcp", "tg.example/mcp", ""} {
		if _, err := NewEndpoint("tg", u); err == nil {
			t.Errorf("%q accepted", u)
		}
	}
	ep, err := NewEndpoint("tg", "https://tg.example/mcp")
	if err != nil || ep.Server() != "tg" || ep.client == nil {
		t.Fatalf("ep %v err %v", ep, err)
	}
}
