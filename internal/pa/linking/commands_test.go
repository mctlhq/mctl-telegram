package linking_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/pa"
	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/linking"
	"github.com/mctlhq/mctl-telegram/internal/pa/output"
	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
)

const cmdUser = 100001

type cmdLinks struct {
	startURL  string
	startErr  error
	handled   bool
	cbErr     error
	started   []connection.Server
	retired   []int64
	retireN   int
	retireErr error
}

func (l *cmdLinks) StartLink(_ context.Context, _ pa.Principal, s connection.Server) (string, error) {
	l.started = append(l.started, s)
	return l.startURL, l.startErr
}

func (l *cmdLinks) HandleCallback(context.Context, pa.VerifiedUpdate) (bool, error) {
	return l.handled, l.cbErr
}

func (l *cmdLinks) AbandonPending(_ context.Context, principal int64) (int, error) {
	l.retired = append(l.retired, principal)
	return l.retireN, l.retireErr
}

type cmdConns struct {
	conns       []connection.Connection
	listErr     error
	discErr     error
	remoteErr   error
	disconnects []string
}

func (c *cmdConns) List(context.Context, int64) ([]connection.Connection, error) {
	return c.conns, c.listErr
}

func (c *cmdConns) Disconnect(_ context.Context, _ int64, id string) (connection.DisconnectResult, error) {
	c.disconnects = append(c.disconnects, id)
	return connection.DisconnectResult{RemoteErr: c.remoteErr}, c.discErr
}

type cmdSender struct {
	mu     sync.Mutex
	texts  []string
	webApp []string
}

func (s *cmdSender) Send(_ context.Context, _ int64, text safetext.Text, _ output.Keyboard) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.texts = append(s.texts, text.String())
	return nil
}

func (s *cmdSender) SendWebApp(_ context.Context, _ int64, _ safetext.Text, _ safetext.Template, appURL string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.webApp = append(s.webApp, appURL)
	return nil
}

func (s *cmdSender) last() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.texts) == 0 {
		return ""
	}
	return s.texts[len(s.texts)-1]
}

func messageUpdate(t *testing.T) pa.VerifiedUpdate {
	t.Helper()
	body := fmt.Sprintf(`{"update_id":1,"message":{"message_id":1,"from":{"id":%d,"is_bot":false,"first_name":"Alice"},"chat":{"id":%d,"type":"private"},"text":"/connect"}}`, cmdUser, cmdUser)
	u, outcome := pa.Filter([]byte(body))
	if outcome != pa.OutcomeAccepted {
		t.Fatalf("filter: %s", outcome)
	}
	return u
}

func srv(t safetext.Template) string { return safetext.ServerText(t).String() }

func TestCommands_Connect(t *testing.T) {
	u := messageUpdate(t)
	for name, c := range map[string]struct {
		arg     string
		links   *cmdLinks
		want    string
		started bool
	}{
		"button sent":     {arg: "tg", links: &cmdLinks{startURL: "https://tg.example/pa/link/app?link=x"}, started: true},
		"no argument":     {arg: "", links: &cmdLinks{}, want: srv(safetext.TextConnectUsage)},
		"unknown server":  {arg: "nope", links: &cmdLinks{}, want: srv(safetext.TextConnectUsage)},
		"server disabled": {arg: "tg", links: &cmdLinks{startErr: linking.ErrServerDisabled}, want: srv(safetext.TextLinkingUnavailable), started: true},
		"start refused":   {arg: "tg", links: &cmdLinks{startErr: errors.New("too many")}, want: srv(safetext.TextConnectFailed), started: true},
	} {
		s := &cmdSender{}
		cmd := &linking.Commands{Links: c.links, Connections: &cmdConns{}, Sender: s}
		cmd.Run(context.Background(), u, pa.LinkAction{Command: pa.CommandConnect, Arg: c.arg})
		if got := s.last(); got != c.want {
			t.Errorf("%s: reply %q, want %q", name, got, c.want)
		}
		if (len(c.links.started) > 0) != c.started {
			t.Errorf("%s: StartLink called %v", name, c.links.started)
		}
		if c.want == "" && (len(s.webApp) != 1 || s.webApp[0] != c.links.startURL) {
			t.Errorf("%s: web_app %v", name, s.webApp)
		}
		if c.want != "" && len(s.webApp) != 0 {
			t.Errorf("%s: a button was sent on a refusal", name)
		}
	}
}

func TestCommands_Disconnect(t *testing.T) {
	u := messageUpdate(t)
	active := []connection.Connection{
		{ID: "c1", Server: connection.ServerTG, State: connection.StateActive},
		{ID: "c2", Server: connection.ServerTG, State: connection.StateRevoked},
		{ID: "c3", Server: connection.ServerAlice, State: connection.StateActive},
	}
	for name, c := range map[string]struct {
		conns *cmdConns
		want  string
		disc  []string
	}{
		"revoked":         {conns: &cmdConns{conns: active}, want: srv(safetext.TextDisconnected), disc: []string{"c1"}},
		"remote failed":   {conns: &cmdConns{conns: active, remoteErr: errors.New("down")}, want: srv(safetext.TextDisconnectedLocal), disc: []string{"c1"}},
		"none":            {conns: &cmdConns{conns: active[1:]}, want: srv(safetext.TextDisconnectNone)},
		"list unreadable": {conns: &cmdConns{conns: active, listErr: errors.New("disk")}, want: srv(safetext.TextDisconnectFailed)},
		"disconnect fail": {conns: &cmdConns{conns: active, discErr: errors.New("disk")}, want: srv(safetext.TextDisconnectFailed), disc: []string{"c1"}},
	} {
		s := &cmdSender{}
		cmd := &linking.Commands{Links: &cmdLinks{}, Connections: c.conns, Sender: s}
		cmd.Run(context.Background(), u, pa.LinkAction{Command: pa.CommandDisconnect, Arg: "tg"})
		if got := s.last(); got != c.want {
			t.Errorf("%s: reply %q, want %q", name, got, c.want)
		}
		if fmt.Sprint(c.conns.disconnects) != fmt.Sprint(c.disc) {
			t.Errorf("%s: disconnected %v, want %v", name, c.conns.disconnects, c.disc)
		}
	}
}

func TestCommands_List(t *testing.T) {
	u := messageUpdate(t)
	s := &cmdSender{}
	conns := &cmdConns{conns: []connection.Connection{
		{ID: "c1", Server: connection.ServerTG, State: connection.StateActive, AccountID: "telegram:100001"},
		{ID: "c2", Server: connection.ServerTG, State: connection.StateRevoked, AccountID: "telegram:9"},
	}}
	cmd := &linking.Commands{Links: &cmdLinks{}, Connections: conns, Sender: s}
	cmd.Run(context.Background(), u, pa.LinkAction{Command: pa.CommandConnections})
	if got, want := s.last(), "Your connections:\ntg (active): telegram:100001"; got != want {
		t.Fatalf("list %q, want %q", got, want)
	}
	// An expired connection is listed as it is, with the way back
	// (#1318 slice C2b).
	conns.conns[0].State = connection.StateExpired
	cmd.Run(context.Background(), u, pa.LinkAction{Command: pa.CommandConnections})
	if got, want := s.last(), "Your connections:\ntg (expired): telegram:100001 - send /connect tg to link it again"; got != want {
		t.Fatalf("expired list %q, want %q", got, want)
	}
	conns.conns = conns.conns[1:]
	cmd.Run(context.Background(), u, pa.LinkAction{Command: pa.CommandConnections})
	if got := s.last(); got != srv(safetext.TextConnectionsNone) {
		t.Fatalf("none: %q", got)
	}
	conns.listErr = errors.New("disk")
	cmd.Run(context.Background(), u, pa.LinkAction{Command: pa.CommandConnections})
	if got := s.last(); got != srv(safetext.TextConnectionsFailed) {
		t.Fatalf("unreadable: %q", got)
	}
}

func TestCommands_Button(t *testing.T) {
	for name, c := range map[string]struct {
		data  string
		links *cmdLinks
		want  string
	}{
		"confirmed":   {data: "pa:lc:x", links: &cmdLinks{handled: true}, want: srv(safetext.TextConnected)},
		"cancelled":   {data: "pa:lx:x", links: &cmdLinks{handled: true}, want: srv(safetext.TextConnectCancelled)},
		"not handled": {data: "pa:lc:x", links: &cmdLinks{}, want: srv(safetext.TextUnknownButton)},
		"disabled":    {data: "pa:lc:x", links: &cmdLinks{handled: true, cbErr: linking.ErrServerDisabled}, want: srv(safetext.TextLinkingUnavailable)},
		"refused":     {data: "pa:lc:x", links: &cmdLinks{handled: true, cbErr: linking.ErrRefused}, want: srv(safetext.TextConnectButtonGone)},
	} {
		s := &cmdSender{}
		cmd := &linking.Commands{Links: c.links, Connections: &cmdConns{}, Sender: s}
		cmd.Run(context.Background(), callbackUpdate(t, cmdUser, c.data), pa.LinkAction{Button: true})
		if got := s.last(); got != c.want {
			t.Errorf("%s: reply %q, want %q", name, got, c.want)
		}
	}
}

// Retire fails the principal's unfinished links and answers nothing: the
// command that recorded it already did. A failure is logged, not sent.
func TestCommands_Retire(t *testing.T) {
	for name, links := range map[string]*cmdLinks{
		"retired": {retireN: 1},
		"failed":  {retireErr: errors.New("store down")},
	} {
		s := &cmdSender{}
		cmd := &linking.Commands{Links: links, Connections: &cmdConns{}, Sender: s}
		cmd.Run(context.Background(), messageUpdate(t), pa.LinkAction{Retire: true})
		if len(links.retired) != 1 || links.retired[0] != cmdUser {
			t.Errorf("%s: AbandonPending calls %v, want [%d]", name, links.retired, cmdUser)
		}
		if s.last() != "" || len(s.webApp) != 0 || len(links.started) != 0 {
			t.Errorf("%s: retire sent %q or started a link", name, s.last())
		}
	}
}

// AfterCommit runs nothing when the handler recorded nothing. That it runs
// a recorded action is TestPATools_ConnectDispatchDisconnect (cmd/server).
func TestCommands_AfterCommit(t *testing.T) {
	u := messageUpdate(t)
	s := &cmdSender{}
	links := &cmdLinks{startURL: "https://tg.example/pa/link/app?link=x"}
	cmd := &linking.Commands{Links: links, Connections: &cmdConns{}, Sender: s}
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	cmd.AfterCommit(pa.WithPostCommit(context.Background()), u)
	cmd.Wait()
	// Most updates carry no linking action: nothing runs and nothing is
	// logged for them.
	if len(links.started) != 0 || len(s.webApp) != 0 || s.last() != "" || logs.Len() != 0 {
		t.Fatal("AfterCommit ran without a recorded action")
	}
}

// The conversation layer routes a confirm card press to the linking flow by
// prefix (pa.LinkButtonPrefixes); every button the card carries must match
// one, or its press is consumed as an unknown pa_callbacks button.
func TestConfirmCardButtonsAreLinkButtons(t *testing.T) {
	card := linking.ConfirmCard(connection.ServerTG, "telegram:100001", strings.Repeat("A", 43))
	if len(card.Buttons) != len(pa.LinkButtonPrefixes) {
		t.Fatalf("%d buttons, %d prefixes", len(card.Buttons), len(pa.LinkButtonPrefixes))
	}
	for i, b := range card.Buttons {
		if !strings.HasPrefix(b.Data, pa.LinkButtonPrefixes[i]) {
			t.Errorf("button %q does not start with %q", b.Data, pa.LinkButtonPrefixes[i])
		}
	}
}
