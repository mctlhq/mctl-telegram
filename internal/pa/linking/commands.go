package linking

// commands.go runs the PA bot's account-linking commands and confirm card
// buttons after the update's commit (#1318 slice C2). The conversation
// layer admits them inside the update's transaction (consent, rate window)
// and records a pa.LinkAction; nothing here runs inside that transaction,
// because StartLink, Disconnect and the confirm button take the principal
// lock the transaction holds (internal/pa/postcommit.go).

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa"
	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
)

// CommandTimeout bounds one linking action, a remote revocation included.
const CommandTimeout = 30 * time.Second

// Links is the linking flow half of Commands (*Service).
type Links interface {
	StartLink(ctx context.Context, principal pa.Principal, server connection.Server) (string, error)
	HandleCallback(ctx context.Context, u pa.VerifiedUpdate) (bool, error)
	AbandonPending(ctx context.Context, principal int64) (int, error)
}

var _ Links = (*Service)(nil)

// Connections is the connection manager half of Commands
// (*connection.Manager).
type Connections interface {
	List(ctx context.Context, principal int64) ([]connection.Connection, error)
	Disconnect(ctx context.Context, principal int64, id string) (connection.DisconnectResult, error)
}

var _ Connections = (*connection.Manager)(nil)

// Commands runs pa.LinkActions after their update committed.
type Commands struct {
	Links       Links
	Connections Connections
	Sender      BotSender

	wg sync.WaitGroup
}

// AfterCommit runs the action the update's handler recorded in ctx, if any,
// in the background: the webhook's AfterCommit must not block. It is only
// called once the update's transaction committed.
func (c *Commands) AfterCommit(ctx context.Context, u pa.VerifiedUpdate) {
	a, ok := pa.PostCommitAction(ctx)
	if !ok {
		return
	}
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), CommandTimeout)
		defer cancel()
		c.Run(actx, u, a)
	}()
}

// Wait waits for the actions AfterCommit started.
func (c *Commands) Wait() { c.wg.Wait() }

// Run performs one action and answers the principal. Every failure is
// answered with a fixed text and logged without content; none is retried.
func (c *Commands) Run(ctx context.Context, u pa.VerifiedUpdate, a pa.LinkAction) {
	p := u.Principal()
	if p.IsZero() {
		return
	}
	var text safetext.Text
	switch {
	case a.Retire:
		c.retire(ctx, u, p)
		return
	case a.Button:
		text = c.button(ctx, u)
	case a.Command == pa.CommandConnect:
		refusal := c.connect(ctx, p, a.Arg)
		if refusal == (safetext.Template{}) {
			return
		}
		text = safetext.ServerText(refusal)
	case a.Command == pa.CommandDisconnect:
		text = safetext.ServerText(c.disconnect(ctx, p, a.Arg))
	case a.Command == pa.CommandConnections:
		text = c.list(ctx, p)
	default:
		slog.Warn("pa linking: unknown post-commit action", "update_id", u.UpdateID())
		return
	}
	if err := c.send(ctx, p.TelegramID(), text); err != nil {
		slog.Warn("pa linking: reply not sent", "update_id", u.UpdateID(), "err", err)
	}
}

// retire fails the principal's unfinished links (LinkAction.Retire). It
// answers nothing: /forget or /consent withdraw already did.
func (c *Commands) retire(ctx context.Context, u pa.VerifiedUpdate, p pa.Principal) {
	if c.Links == nil {
		return
	}
	n, err := c.Links.AbandonPending(ctx, p.TelegramID())
	if err != nil {
		slog.Warn("pa linking: unfinished links not all retired; the sweep fails the rest", "update_id", u.UpdateID(), "retired", n, "err", err)
	}
}

func (c *Commands) send(ctx context.Context, chat int64, text safetext.Text) error {
	if c.Sender == nil {
		return fmt.Errorf("%w: no sender", ErrConfig)
	}
	return c.Sender.Send(ctx, chat, text, nil)
}

// commandServer reads a command argument as a catalog server.
func commandServer(arg string) (connection.Server, bool) {
	s := connection.Server(arg)
	return s, arg != "" && s.Valid()
}

// connect starts the link and sends the web_app button. It returns the
// zero Template when the button was sent, and the answer otherwise: a
// disabled server is "not available", anything else "could not start".
func (c *Commands) connect(ctx context.Context, p pa.Principal, arg string) safetext.Template {
	server, ok := commandServer(arg)
	if !ok {
		return safetext.TextConnectUsage
	}
	if c.Links == nil {
		return safetext.TextConnectFailed
	}
	appURL, err := c.Links.StartLink(ctx, p, server)
	if errors.Is(err, ErrServerDisabled) {
		return safetext.TextLinkingUnavailable
	}
	if err != nil {
		slog.Warn("pa linking: /connect refused", "server", string(server), "err", err)
		return safetext.TextConnectFailed
	}
	if err := (BotMessenger{Sender: c.Sender}).SendConnectButton(ctx, p.TelegramID(), appURL); err != nil {
		// The link token is unusable without its button; it expires and
		// the sweep fails the pending connection.
		slog.Warn("pa linking: connect button not sent", "server", string(server), "err", err)
		return safetext.TextConnectFailed
	}
	return safetext.Template{}
}

// disconnect revokes every connection of the principal on the server that
// is not already revoked or failed: locally first, then at the server
// (Manager.Disconnect, threat model T2).
func (c *Commands) disconnect(ctx context.Context, p pa.Principal, arg string) safetext.Template {
	server, ok := commandServer(arg)
	if !ok {
		return safetext.TextConnectUsage
	}
	if c.Connections == nil {
		return safetext.TextDisconnectFailed
	}
	conns, err := c.Connections.List(ctx, p.TelegramID())
	if err != nil {
		// A failed read is not "no connection" (I9).
		slog.Warn("pa linking: /disconnect list failed", "err", err)
		return safetext.TextDisconnectFailed
	}
	found, remoteFailed := false, false
	for _, conn := range conns {
		if conn.Server != server || conn.State == connection.StateRevoked || conn.State == connection.StateFailed {
			continue
		}
		found = true
		res, err := c.Connections.Disconnect(ctx, p.TelegramID(), conn.ID)
		if err != nil {
			slog.Warn("pa linking: /disconnect failed", "server", string(server), "err", err)
			return safetext.TextDisconnectFailed
		}
		if res.RemoteErr != nil {
			slog.Warn("pa linking: remote revocation failed", "server", string(server), "err", res.RemoteErr)
			remoteFailed = true
		}
	}
	switch {
	case !found:
		return safetext.TextDisconnectNone
	case remoteFailed:
		return safetext.TextDisconnectedLocal
	}
	return safetext.TextDisconnected
}

// list renders the principal's connections: server, state and the stable
// account id the server reported, never a token. The account id is the
// server's text, so it is rendered as untrusted (T14).
func (c *Commands) list(ctx context.Context, p pa.Principal) safetext.Text {
	if c.Connections == nil {
		return safetext.ServerText(safetext.TextConnectionsFailed)
	}
	conns, err := c.Connections.List(ctx, p.TelegramID())
	if err != nil {
		slog.Warn("pa linking: /connections list failed", "err", err)
		return safetext.ServerText(safetext.TextConnectionsFailed)
	}
	var lines []string
	for _, conn := range conns {
		if conn.State == connection.StateRevoked || conn.State == connection.StateFailed {
			continue
		}
		line := string(conn.Server) + " (" + string(conn.State) + ")"
		if conn.AccountID != "" {
			line += ": " + conn.AccountID
		}
		lines = append(lines, line)
	}
	if len(lines) == 0 {
		return safetext.ServerText(safetext.TextConnectionsNone)
	}
	sort.Strings(lines)
	text, err := safetext.Render("Your connections:\n"+strings.Join(lines, "\n"), safetext.UserText{})
	if err != nil {
		slog.Warn("pa linking: /connections not renderable", "err", err)
		return safetext.ServerText(safetext.TextConnectionsFailed)
	}
	return text
}

// button runs a confirm card press.
func (c *Commands) button(ctx context.Context, u pa.VerifiedUpdate) safetext.Text {
	if c.Links == nil {
		return safetext.ServerText(safetext.TextConnectButtonGone)
	}
	handled, err := c.Links.HandleCallback(ctx, u)
	switch {
	case !handled:
		return safetext.ServerText(safetext.TextUnknownButton)
	case errors.Is(err, ErrServerDisabled):
		return safetext.ServerText(safetext.TextLinkingUnavailable)
	case err != nil:
		slog.Warn("pa linking: confirm button refused", "update_id", u.UpdateID(), "err", err)
		return safetext.ServerText(safetext.TextConnectButtonGone)
	case strings.HasPrefix(u.CallbackData(), confirmPrefix):
		return safetext.ServerText(safetext.TextConnected)
	}
	return safetext.ServerText(safetext.TextConnectCancelled)
}
