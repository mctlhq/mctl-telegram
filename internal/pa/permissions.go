// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pa

// permissions.go is the /permissions command (#1320 slice P2-S10, threat
// model T7 "Standing permissions"): the only place a standing permission
// is granted or revoked by hand.
//
//   - The command is recognised in user-provenance text only (userCommand)
//     and is handled whole by the server: it is never stored as a fragment
//     and never reaches the model.
//   - Its update only admits it (consent, rate window). The screen is built
//     after the commit (PermissionCommands), because checking a grant reads
//     the principal's devices from the server.
//   - A grant screen shows the tool, device ids, value ceiling and expiry
//     and has one button. The button's callback is a pa_callbacks row of
//     the principal the screen was sent to, and its action carries the
//     whole grant, so pressing it creates exactly what was shown.
//     permissionButton, which handles that press, is the only caller of
//     InsertPAPermission (TestS2A8_GrantInsertHasOneCaller).
//
// Nothing here is reachable in a deployed service yet: no production
// wiring sets ConversationsConfig.Permissions or builds PermissionCommands,
// so /permissions is answered "not available". With them wired, a grant is
// still refused while PA_WRITES_ENABLED is off; listing and revoking work.
// A permission is consulted at dispatch by connector.Cards and the write
// executor (connector/lower.go, P2-S11), which no deployed wiring builds
// either.

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/convo"
	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
	"github.com/mctlhq/mctl-telegram/internal/pa/output"
	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
	"github.com/mctlhq/mctl-telegram/internal/pa/permissions"
)

// CommandPermissions lists, grants and revokes standing permissions.
const CommandPermissions = "/permissions"

// The verbs of /permissions.
const (
	permissionVerbGrant  = "grant"
	permissionVerbRevoke = "revoke"
)

// The fixed answers of /permissions.
const (
	// ReplyPermissionsUnavailable: standing permissions are not offered
	// (not wired, or writes are off).
	ReplyPermissionsUnavailable Reply = "permissions_unavailable"
	ReplyPermissionGranted      Reply = "permission_granted"
	ReplyPermissionRevoked      Reply = "permission_revoked"
	// ReplyPermissionRefused: the grant button was pressed and the grant
	// was refused; nothing changed.
	ReplyPermissionRefused Reply = "permission_refused"
)

// PermissionGrants is the permission table as a pressed /permissions
// button uses it (*db.Store), inside the update's transaction. A press can
// create one permission or revoke one, for the principal who pressed.
type PermissionGrants interface {
	InsertPAPermission(ctx context.Context, tx *sql.Tx, p permissions.Permission, now time.Time) error
	RevokePAPermission(ctx context.Context, tx *sql.Tx, principal int64, id string, now time.Time) error
}

// PermissionConnections reads the connection a grant names, in the
// update's transaction, for its write scope (*db.Store; #1320 slice
// P2-S14c). It is a read: a press still changes the permission table
// through PermissionGrants only.
type PermissionConnections interface {
	LockPAConnection(ctx context.Context, tx *sql.Tx, principal int64, id string) (connection.Connection, error)
}

// WritesSwitch reads PA_WRITES_ENABLED. An error means it could not be
// read, which is treated as off.
type WritesSwitch func() (bool, error)

// PermissionsConfig is what the conversation layer needs for /permissions.
type PermissionsConfig struct {
	Grants PermissionGrants
	// Policy is checked again when the grant button is pressed.
	Policy permissions.ToolPolicy
	Writes WritesSwitch
	// Connections is required: a grant is refused unless its connection
	// can be read and holds the tool's write scope.
	Connections PermissionConnections
	// Scopes names the scope each write tool needs; nil is the compiled
	// table (connection.DefaultWriteScopes). A standing permission is
	// granted only on a connection that holds its tool's scope.
	Scopes *connection.WriteScopes
}

func (p *PermissionsConfig) scopes() connection.WriteScopes {
	if p.Scopes != nil {
		return *p.Scopes
	}
	return connection.DefaultWriteScopes()
}

func (p *PermissionsConfig) valid() bool {
	return p.Grants != nil && p.Policy != nil && p.Writes != nil && p.Connections != nil
}

// writesOn reports whether writes are on; unreadable is off.
func writesOn(w WritesSwitch) bool {
	if w == nil {
		return false
	}
	on, err := w()
	return err == nil && on
}

// PermissionAction is a /permissions command admitted by its update and
// run after the commit. Args are the words after the command, as typed.
type PermissionAction struct {
	Args []string
}

// maxPermissionArgs bounds what of a command is carried past the commit:
// the verb, a tool, a device list and a value, and one word more so that a
// command with too many words is still seen to have too many.
const maxPermissionArgs = 5

// handlePermissionsCommand admits /permissions in the update's
// transaction: consent first, as for any message; the rate window has
// already counted it. Without the wiring the answer is fixed.
func (c *Conversations) handlePermissionsCommand(ctx context.Context, tx *sql.Tx, u VerifiedUpdate) error {
	if c.permissions == nil {
		return c.reply(ctx, tx, u, ReplyPermissionsUnavailable, "")
	}
	_, err := c.requireConsent(ctx, tx, u.Principal())
	if errors.Is(err, ErrConsentRequired) {
		return c.prompt(ctx, tx, u)
	}
	if err != nil {
		return err
	}
	args := commandArgs(u.Fragments())
	if len(args) > maxPermissionArgs {
		args = args[:maxPermissionArgs]
	}
	// With writes on, the list and a grant need the consent to actions:
	// the principal is shown its text here, and nothing else happens.
	// Revoking only removes authority and is never held back by it.
	if writesOn(c.permissions.Writes) && !(len(args) > 0 && strings.ToLower(args[0]) == permissionVerbRevoke) {
		err := RequireActionConsent(ctx, tx, c.store, u.Principal().TelegramID())
		if errors.Is(err, ErrActionConsentRequired) {
			return c.promptActions(ctx, tx, u)
		}
		if err != nil {
			return err
		}
	}
	return setPostCommitPermission(ctx, PermissionAction{Args: args})
}

// commandArgs returns the words after the command of a command message,
// as typed. It reads the same fragment userCommand does, and nothing
// unless that fragment is user text.
func commandArgs(frags []convo.Fragment) []string {
	for _, f := range frags {
		if f.Kind() != convo.KindText {
			continue
		}
		text, prov := f.Text()
		if prov != convo.ProvenanceUser {
			return nil
		}
		fields := strings.Fields(text)
		if len(fields) < 2 {
			return nil
		}
		return fields[1:]
	}
	return nil
}

// permissionButton handles a pressed Grant or Revoke whose callback id was
// just consumed for the principal who pressed: ConsumePACallback is keyed
// by (principal, id), so the press of anyone but the principal the screen
// was sent to never gets here (T4). The permission belongs to that
// principal, whatever the action says.
//
// A grant is checked again here, in the update's transaction: consent, the
// writes switch, the tool against the pin, and (inside the insert statement) the
// connection, its state and its authority revision. The device read was
// made when the screen was built, at most permissions.ScreenTTL ago.
func (c *Conversations) permissionButton(ctx context.Context, tx *sql.Tx, u VerifiedUpdate, action string) error {
	principal, now := u.Principal().TelegramID(), c.now()
	if id, ok := permissions.ParseRevokeAction(action); ok {
		err := c.permissions.Grants.RevokePAPermission(ctx, tx, principal, id, now)
		if err != nil && !errors.Is(err, permissions.ErrNotFound) {
			return err
		}
		// Already revoked (a revision change, an earlier press) reads the
		// same: the permission is not in force.
		return c.reply(ctx, tx, u, ReplyPermissionRevoked, "")
	}
	prop, ok := permissions.ParseGrantAction(action)
	if !ok {
		return c.reply(ctx, tx, u, ReplyUnknownButton, "")
	}
	// Consent may have been withdrawn since the screen was sent: the
	// command required it, and so does the press. Unreadable consent fails
	// the update, which rolls the consume back.
	_, err := c.requireConsent(ctx, tx, u.Principal())
	if errors.Is(err, ErrConsentRequired) {
		return c.prompt(ctx, tx, u)
	}
	if err != nil {
		return err
	}
	if !writesOn(c.permissions.Writes) {
		return c.reply(ctx, tx, u, ReplyPermissionsUnavailable, "")
	}
	// The consent to actions, read now: the screen may be older than its
	// withdrawal or than a change of its text. Without it nothing is
	// granted and the principal is shown the text.
	err = RequireActionConsent(ctx, tx, c.store, principal)
	if errors.Is(err, ErrActionConsentRequired) {
		return c.promptActions(ctx, tx, u)
	}
	if err != nil {
		return err
	}
	// The connection must hold the tool's write scope, as its token
	// response reported it. A connection that cannot be read fails the
	// update; one that is gone or holds no such scope grants nothing.
	conn, err := c.permissions.Connections.LockPAConnection(ctx, tx, principal, prop.ConnectionID)
	if err != nil && !errors.Is(err, connection.ErrNotFound) {
		return err
	}
	if err != nil || conn.Principal != principal || string(conn.Server) != prop.Server ||
		!c.permissions.scopes().Holds(conn, prop.Tool) {
		slog.Warn("pa permissions: grant refused at confirmation", "reason", "write_scope")
		return c.reply(ctx, tx, u, ReplyPermissionRefused, "")
	}
	if err := permissions.CheckTool(c.permissions.Policy, prop.Server, prop.Tool); err != nil {
		slog.Warn("pa permissions: grant refused at confirmation", "reason", string(permissions.ReasonOf(err)))
		return c.reply(ctx, tx, u, ReplyPermissionRefused, "")
	}
	err = c.permissions.Grants.InsertPAPermission(ctx, tx, permissions.Permission{
		Principal: principal, ID: newOpaqueID(),
		ConnectionID: prop.ConnectionID, AuthorityRevision: prop.AuthorityRevision,
		Server: prop.Server, Tool: prop.Tool, DeviceIDs: prop.DeviceIDs, Ceiling: prop.Ceiling,
		ExpiresAt: time.UnixMilli(prop.ExpiresAtMS),
	}, now)
	if errors.Is(err, permissions.ErrRefused) {
		slog.Warn("pa permissions: grant refused at confirmation", "reason", string(permissions.ReasonOf(err)))
		return c.reply(ctx, tx, u, ReplyPermissionRefused, "")
	}
	if err != nil {
		// Unreadable or unwritable: the update fails, the consume rolls
		// back with it and Telegram redelivers the press.
		return err
	}
	return c.reply(ctx, tx, u, ReplyPermissionGranted, "")
}

// setPostCommitPermission records a for after the commit.
func setPostCommitPermission(ctx context.Context, a PermissionAction) error {
	s, ok := ctx.Value(postCommitKey{}).(*postCommitSlot)
	if !ok || s == nil {
		return ErrNoPostCommit
	}
	s.permission = &a
	return nil
}

// PostCommitPermission returns the /permissions command the update's
// handler admitted, if any. Only AfterCommit calls it, after the commit.
func PostCommitPermission(ctx context.Context) (PermissionAction, bool) {
	s, ok := ctx.Value(postCommitKey{}).(*postCommitSlot)
	if !ok || s == nil || s.permission == nil {
		return PermissionAction{}, false
	}
	return *s.permission, true
}

// PermissionScreenButton is the one button of a /permissions screen.
type PermissionScreenButton struct {
	Label safetext.Template
	// Verb is the screen the button belongs to.
	Verb string
}

// permissionScreenButtons is every button a /permissions screen can have:
// Grant on a grant screen, Revoke on a revoke screen. The list has no
// button.
var permissionScreenButtons = []PermissionScreenButton{
	{Label: safetext.LabelPermissionGrant, Verb: permissionVerbGrant},
	{Label: safetext.LabelPermissionRevoke, Verb: permissionVerbRevoke},
}

// PermissionScreenButtons returns the buttons of the /permissions screens.
func PermissionScreenButtons() []PermissionScreenButton {
	return append([]PermissionScreenButton(nil), permissionScreenButtons...)
}

// permissionKeyboard is the keyboard of the verb's screen: its one button,
// carrying callbackID.
func permissionKeyboard(verb, callbackID string) (output.Keyboard, bool) {
	if callbackID == "" || len(callbackID) > jobs.MaxOutboxButton {
		return nil, false
	}
	for _, b := range permissionScreenButtons {
		if b.Verb == verb {
			return output.Keyboard{{{Label: b.Label, Data: callbackID}}}, true
		}
	}
	return nil, false
}

// PermissionStore is what the screens read and write (*db.Store).
type PermissionStore interface {
	ListActivePAPermissions(ctx context.Context, principal int64, now time.Time) ([]permissions.Permission, error)
	ActivePAConnectionRefs(ctx context.Context, principal int64) ([]permissions.ConnectionRef, error)
	IssuePAPermissionCallback(ctx context.Context, principal int64, id, action string, expiresAt time.Time) error
}

// PermissionSender sends a screen (*output.Sender).
type PermissionSender interface {
	Send(ctx context.Context, chatID int64, text safetext.Text, kb output.Keyboard) error
}

// PermissionCommandTimeout bounds one /permissions action, the device
// read included.
const PermissionCommandTimeout = 30 * time.Second

// PermissionCommands builds and sends the /permissions screens after
// their update committed. It never creates or revokes a permission: it
// can only issue the callback whose press does (permissionButton).
type PermissionCommands struct {
	Store     PermissionStore
	Validator *permissions.Validator
	Sender    PermissionSender
	Writes    WritesSwitch
	// Scopes is PermissionsConfig.Scopes: nil is the compiled table.
	Scopes *connection.WriteScopes
	// Now defaults to time.Now.
	Now func() time.Time

	wg sync.WaitGroup
}

// AfterCommit runs the /permissions command the update's handler admitted
// in ctx, if any, in the background. Like the linking commands, a crash
// between the commit and the screen loses the screen only: nothing was
// granted, and the principal sends the command again.
func (c *PermissionCommands) AfterCommit(ctx context.Context, u VerifiedUpdate) {
	a, ok := PostCommitPermission(ctx)
	if !ok {
		return
	}
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), PermissionCommandTimeout)
		defer cancel()
		c.Run(actx, u, a)
	}()
}

// Wait waits for the actions AfterCommit started.
func (c *PermissionCommands) Wait() { c.wg.Wait() }

func (c *PermissionCommands) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Run performs one action and answers the principal. Every failure is
// answered with a fixed text and logged without content.
func (c *PermissionCommands) Run(ctx context.Context, u VerifiedUpdate, a PermissionAction) {
	p := u.Principal()
	if p.IsZero() || c.Sender == nil {
		return
	}
	var (
		text safetext.Text
		kb   output.Keyboard
	)
	verb := ""
	if len(a.Args) > 0 {
		verb = strings.ToLower(a.Args[0])
	}
	switch {
	case c.Store == nil:
		text = safetext.ServerText(safetext.TextPermissionsFailed)
	case verb == permissionVerbGrant:
		text, kb = c.grantScreen(ctx, p.TelegramID(), a.Args[1:])
	case verb == permissionVerbRevoke:
		text, kb = c.revokeScreen(ctx, p.TelegramID(), a.Args[1:])
	case verb == "":
		text = c.list(ctx, p.TelegramID())
	default:
		text = safetext.ServerText(safetext.TextPermissionsUsage)
	}
	if err := c.Sender.Send(ctx, p.TelegramID(), text, kb); err != nil {
		slog.Warn("pa permissions: screen not sent", "update_id", u.UpdateID(), "err", err)
	}
}

func permissionView(p permissions.Permission, withID bool) safetext.PermissionView {
	v := safetext.PermissionView{Tool: p.Tool, Devices: p.DeviceIDs, Ceiling: p.Ceiling, ExpiresAt: p.ExpiresAt}
	if withID {
		v.ID = p.ID
	}
	return v
}

// list renders the principal's active permissions. A failed read is
// answered as a failure, never as "you have none" (I9).
func (c *PermissionCommands) list(ctx context.Context, principal int64) safetext.Text {
	perms, err := c.Store.ListActivePAPermissions(ctx, principal, c.now())
	if err != nil {
		slog.Warn("pa permissions: list failed", "err", err)
		return safetext.ServerText(safetext.TextPermissionsFailed)
	}
	if len(perms) == 0 {
		return safetext.ServerText(safetext.TextPermissionsNone)
	}
	views := make([]safetext.PermissionView, 0, len(perms))
	for _, p := range perms {
		views = append(views, permissionView(p, true))
	}
	text, err := safetext.PermissionList(safetext.TextPermissionsList, views, safetext.TextPermissionsUsage)
	if err != nil {
		slog.Warn("pa permissions: list not renderable", "err", err)
		return safetext.ServerText(safetext.TextPermissionsFailed)
	}
	return text
}

// parseGrantArgs reads "<tool> <id>[,<id>...] [<highest value>]".
func parseGrantArgs(args []string) (tool string, devices []string, ceiling int64, ok bool) {
	if len(args) < 2 || len(args) > 3 {
		return "", nil, 0, false
	}
	devices, err := permissions.CanonicalDevices(strings.Split(args[1], ","))
	if err != nil {
		return "", nil, 0, false
	}
	ceiling = permissions.NoCeiling
	if len(args) == 3 {
		n, err := strconv.ParseInt(args[2], 10, 64)
		if err != nil || n < 0 || n > permissions.MaxCeiling {
			return "", nil, 0, false
		}
		ceiling = n
	}
	return args[0], devices, ceiling, true
}

// grantScreen checks the requested grant and, when it may be granted,
// issues its confirmation callback and returns the screen showing exactly
// what the callback will create. Any refusal returns a fixed text and no
// button.
func (c *PermissionCommands) grantScreen(ctx context.Context, principal int64, args []string) (safetext.Text, output.Keyboard) {
	refused := safetext.ServerText(safetext.TextPermissionRefused)
	if !writesOn(c.Writes) || c.Validator == nil {
		return safetext.ServerText(safetext.TextPermissionsUnavailable), nil
	}
	tool, devices, ceiling, ok := parseGrantArgs(args)
	if !ok {
		return safetext.ServerText(safetext.TextPermissionsUsage), nil
	}
	conns, err := c.Store.ActivePAConnectionRefs(ctx, principal)
	if err != nil {
		slog.Warn("pa permissions: connections unreadable", "err", err)
		return safetext.ServerText(safetext.TextPermissionsFailed), nil
	}
	// The connection is the principal's one active connection to the
	// server that pins the tool. None, or more than one, refuses.
	var on []permissions.ConnectionRef
	for _, cn := range conns {
		if c.Validator.Policy == nil {
			break
		}
		if _, _, pinned := c.Validator.Policy.PinnedTool(cn.Server, tool); pinned {
			on = append(on, cn)
		}
	}
	if len(on) != 1 {
		slog.Warn("pa permissions: grant refused", "reason", string(permissions.ReasonUnknownTool))
		return refused, nil
	}
	now := c.now()
	prop := permissions.Proposal{
		ConnectionID: on[0].ID, AuthorityRevision: on[0].AuthorityRevision, Server: on[0].Server,
		Tool: tool, DeviceIDs: devices, Ceiling: ceiling,
		ExpiresAtMS: now.Add(permissions.DefaultTTL).UnixMilli(),
	}
	if err := c.Validator.Check(ctx, principal, prop, now); err != nil {
		slog.Warn("pa permissions: grant refused", "reason", string(permissions.ReasonOf(err)))
		return refused, nil
	}
	// The grant is one this build would give. A connection made for
	// reading, or one whose grant the service narrowed, holds no write
	// scope: the principal is told to connect the service again, and no
	// button is issued.
	scopes := connection.DefaultWriteScopes()
	if c.Scopes != nil {
		scopes = *c.Scopes
	}
	if !scopes.Holds(connection.Connection{
		Server: connection.Server(on[0].Server), GrantedScope: on[0].GrantedScope, RequestedScope: on[0].RequestedScope,
	}, tool) {
		slog.Warn("pa permissions: grant refused", "reason", "write_scope")
		return safetext.ServerText(safetext.TextWriteScopeNeeded), nil
	}
	text, err := safetext.PermissionScreen(safetext.TextPermissionGrantHead, safetext.PermissionView{
		Tool: prop.Tool, Devices: prop.DeviceIDs, Ceiling: prop.Ceiling, ExpiresAt: time.UnixMilli(prop.ExpiresAtMS),
	}, safetext.TextPermissionGrantFoot)
	if err != nil {
		slog.Warn("pa permissions: grant screen not renderable", "err", err)
		return refused, nil
	}
	action, err := permissions.GrantAction(prop)
	if err != nil {
		return refused, nil
	}
	return c.withButton(ctx, principal, permissionVerbGrant, action, text)
}

// revokeScreen shows one of the principal's active permissions with its
// Revoke button. Revoking only removes authority, so it works with writes
// off.
func (c *PermissionCommands) revokeScreen(ctx context.Context, principal int64, args []string) (safetext.Text, output.Keyboard) {
	if len(args) != 1 || !permissions.ValidID(args[0]) {
		return safetext.ServerText(safetext.TextPermissionsUsage), nil
	}
	perms, err := c.Store.ListActivePAPermissions(ctx, principal, c.now())
	if err != nil {
		slog.Warn("pa permissions: list failed", "err", err)
		return safetext.ServerText(safetext.TextPermissionsFailed), nil
	}
	for _, p := range perms {
		if p.ID != args[0] {
			continue
		}
		text, err := safetext.PermissionScreen(safetext.TextPermissionRevokeHead,
			permissionView(p, true), safetext.TextPermissionRevokeFoot)
		if err != nil {
			slog.Warn("pa permissions: revoke screen not renderable", "err", err)
			return safetext.ServerText(safetext.TextPermissionsFailed), nil
		}
		action, err := permissions.RevokeAction(p.ID)
		if err != nil {
			return safetext.ServerText(safetext.TextPermissionsFailed), nil
		}
		return c.withButton(ctx, principal, permissionVerbRevoke, action, text)
	}
	return safetext.ServerText(safetext.TextPermissionGone), nil
}

// withButton issues the screen's callback for principal and returns the
// screen with its button. A callback that could not be stored sends no
// screen: a button that resolves to nothing is not shown.
func (c *PermissionCommands) withButton(ctx context.Context, principal int64, verb, action string, text safetext.Text) (safetext.Text, output.Keyboard) {
	id := newOpaqueID()
	kb, ok := permissionKeyboard(verb, id)
	if !ok {
		return safetext.ServerText(safetext.TextPermissionsFailed), nil
	}
	if err := c.Store.IssuePAPermissionCallback(ctx, principal, id, action, c.now().Add(permissions.ScreenTTL)); err != nil {
		slog.Warn("pa permissions: callback not stored", "err", err)
		return safetext.ServerText(safetext.TextPermissionsFailed), nil
	}
	return text, kb
}
