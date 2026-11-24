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

package pa_test

// permissions_cmd_test.go drives /permissions through the real webhook,
// the real callback table and the real permission store (#1320 slice
// P2-S10). Threat model rows: S2-A8, S2-A9 (the store half is in
// internal/db), the /permissions half of S2-A10.

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/http"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/pa"
	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/connector"
	"github.com/mctlhq/mctl-telegram/internal/pa/convo"
	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
	"github.com/mctlhq/mctl-telegram/internal/pa/permissions"
)

const permTool = "alice_set_volume"

// permPin is a pin whose alice server has one lowerable write. Every
// other tool is one a standing permission may never cover; several are
// marked lowerable on purpose, so that the refusal is shown not to rest on
// the pin's word.
func permPin() *catalog.Pin {
	w := func(c catalog.Class, l catalog.Lowerable) catalog.PinnedTool {
		return catalog.PinnedTool{Tier: catalog.TierApprove, Class: c, Lowerable: l}
	}
	return &catalog.Pin{Servers: map[string]catalog.ServerPin{
		"alice": {Tools: map[string]catalog.PinnedTool{
			permTool:                 w(catalog.ClassWrite, catalog.LowerableYes),
			"alice_media_control":    w(catalog.ClassWrite, catalog.LowerableNever),
			"alice_say_phrase":       w(catalog.ClassDisclosure, catalog.LowerableYes),
			"alice_send_command":     w(catalog.ClassDisclosure, catalog.LowerableNever),
			"alice_control_room":     w(catalog.ClassWrite, catalog.LowerableYes),
			"alice_trigger_scenario": w(catalog.ClassWrite, catalog.LowerableYes),
			"alice_list_devices":     {Tier: catalog.TierAuto, Class: catalog.ClassRead, Lowerable: catalog.LowerableYes},
		}},
		"tg": cardPin().Servers["tg"],
	}}
}

// fakeDevices is the fresh device read of a grant.
type fakeDevices struct {
	devices atomic.Pointer[[]permissions.Device]
	fail    atomic.Bool
	reads   atomic.Int32
}

func (f *fakeDevices) ReadDevices(_ context.Context, _ int64, _ string) ([]permissions.Device, error) {
	f.reads.Add(1)
	if f.fail.Load() {
		return nil, errors.New("injected device read failure")
	}
	return *f.devices.Load(), nil
}

func (f *fakeDevices) set(ids ...string) {
	ds := make([]permissions.Device, 0, len(ids))
	for _, id := range ids {
		ds = append(ds, permissions.Device{ID: id, Type: "devices.types.media_device.speaker"})
	}
	f.devices.Store(&ds)
}

// allowRule stands in for the device-type rules (permissions.Rules), which
// have tests of their own.
type allowRule struct{ err atomic.Pointer[error] }

func (r *allowRule) CheckGrant(string, []permissions.Device, int64) error {
	if e := r.err.Load(); e != nil {
		return *e
	}
	return nil
}

// swapPolicy is a ToolPolicy that can change between screen and press.
type swapPolicy struct{ pin atomic.Pointer[catalog.Pin] }

func (s *swapPolicy) PinnedTool(server, tool string) (catalog.Class, catalog.Lowerable, bool) {
	return permissions.PinPolicy{Pin: s.pin.Load()}.PinnedTool(server, tool)
}

type permEnv struct {
	*cardEnv
	home, bobHome connection.Connection
	devices       *fakeDevices
	rule          *allowRule
	policy        *swapPolicy
	writes        atomic.Bool
	writesErr     atomic.Bool
	cmds          *pa.PermissionCommands
	validator     *permissions.Validator
}

// newPermEnv is a card env where Alice and Bob each also have an active
// alice connection, writes are on, and /permissions is wired as no
// production wiring wires it yet.
func newPermEnv(t *testing.T, s *db.Store) *permEnv {
	t.Helper()
	e := &permEnv{cardEnv: newCardEnv(t, s), devices: &fakeDevices{}, rule: &allowRule{}, policy: &swapPolicy{}}
	e.home = e.activeAlice(alice, "acct-alice-home")
	e.bobHome = e.activeAlice(bob, "acct-bob-home")
	e.devices.set("dev-1", "dev-2", "dev-3")
	e.policy.pin.Store(permPin())
	e.writes.Store(true)
	writes := func() (bool, error) {
		if e.writesErr.Load() {
			return false, errors.New("injected flag error")
		}
		return e.writes.Load(), nil
	}
	e.validator = &permissions.Validator{Policy: e.policy, Devices: e.devices, Rule: e.rule}
	e.cmds = &pa.PermissionCommands{Store: s, Validator: e.validator, Writes: writes, Now: e.h.Now}
	e.h.EnablePermissions(&pa.PermissionsConfig{Grants: s, Policy: e.policy, Writes: writes}, e.cmds)
	return e
}

// say sends text as user and returns the messages the bot then sent them.
func (e *permEnv) say(user int64, text string) []pa.SentCard {
	e.t.Helper()
	before := len(e.h.MessagesTo(user))
	if code := e.h.TextStatus(user, text); code != http.StatusOK {
		e.t.Fatalf("%q: %d", text, code)
	}
	return e.h.MessagesTo(user)[before:]
}

// one is say expecting exactly one message.
func (e *permEnv) one(user int64, text string) pa.SentCard {
	e.t.Helper()
	msgs := e.say(user, text)
	if len(msgs) != 1 {
		e.t.Fatalf("%q: %d messages: %+v", text, len(msgs), msgs)
	}
	return msgs[0]
}

// button returns the single button of a screen: its label and callback id.
func (e *permEnv) button(m pa.SentCard, label safetext.Template) string {
	e.t.Helper()
	if len(m.Buttons) != 1 || len(m.Buttons[0]) != 1 || m.Buttons[0][0][0] != label.String() || m.Buttons[0][0][1] == "" {
		e.t.Fatalf("screen %q has the keyboard %+v, want one %q button", m.Text, m.Buttons, label.String())
	}
	return m.Buttons[0][0][1]
}

// refused asserts the answer to text is the fixed template and offers no
// button.
func (e *permEnv) refused(user int64, text string, want safetext.Template) {
	e.t.Helper()
	m := e.one(user, text)
	if m.Text != want.String() || len(m.Buttons) != 0 {
		e.t.Errorf("%q: answered %q with %+v, want %q and no button", text, m.Text, m.Buttons, want.String())
	}
}

type permRow struct {
	principal                   int64
	id, conn, server, tool, dev string
	rev, ceiling                int64
	created, expires, revoked   int64
}

func (e *permEnv) rows() []permRow {
	e.t.Helper()
	rows, err := e.store.DB.Query(`SELECT principal, id, connection_id, server, tool, device_ids, authority_revision,
		ceiling, created_at_ms, expires_at_ms, revoked_at_ms FROM pa_permissions ORDER BY created_at_ms, id`)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []permRow
	for rows.Next() {
		var r permRow
		if err := rows.Scan(&r.principal, &r.id, &r.conn, &r.server, &r.tool, &r.dev, &r.rev, &r.ceiling,
			&r.created, &r.expires, &r.revoked); err != nil {
			e.t.Fatal(err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		e.t.Fatal(err)
	}
	return out
}

func (e *permEnv) permCallbacks() int {
	return e.h.Count(`SELECT COUNT(*) FROM pa_callbacks WHERE action LIKE 'permission%'`)
}

// nothingGranted asserts no permission exists and no screen is waiting.
func (e *permEnv) nothingGranted(step string) {
	e.t.Helper()
	if rows := e.rows(); len(rows) != 0 {
		e.t.Fatalf("%s: permission rows %+v", step, rows)
	}
	if n := e.permCallbacks(); n != 0 {
		e.t.Fatalf("%s: %d /permissions callbacks", step, n)
	}
}

// spacedEnv is a permEnv whose refused moves the clock past the rate
// window first.
type spacedEnv struct{ *permEnv }

func (e *spacedEnv) refused(user int64, text string, want safetext.Template) {
	e.t.Helper()
	e.h.Advance(jobs.DefaultRateWindow)
	e.permEnv.refused(user, text, want)
}

const grantCmd = "/permissions grant " + permTool + " dev-2,dev-1 5"

// TestPermissions_GrantListRevoke is the whole life of a standing
// permission: a screen that shows exactly what will be stored, a button
// only the principal can press, one row, a listing, a revoke.
func TestPermissions_GrantListRevoke(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newPermEnv(t, s)
		e.refused(alice, "/permissions", safetext.TextPermissionsNone)

		screen := e.one(alice, grantCmd)
		expiry := e.h.Now().Add(permissions.MaxTTL)
		for _, want := range []string{
			safetext.TextPermissionGrantHead.String(),
			safetext.TextPermissionTool.String() + " " + permTool + "\n",
			safetext.TextPermissionDevices.String() + " dev-1, dev-2\n",
			safetext.TextPermissionCeiling.String() + " 5\n",
			safetext.TextPermissionExpires.String() + " " + expiry.UTC().Format("2006-01-02 15:04"),
			safetext.TextPermissionGrantFoot.String(),
		} {
			if !strings.Contains(screen.Text, want) {
				t.Errorf("the grant screen lacks %q:\n%s", want, screen.Text)
			}
		}
		grant := e.button(screen, safetext.LabelPermissionGrant)
		if rows := e.rows(); len(rows) != 0 {
			t.Fatalf("a permission exists before the confirmation: %+v", rows)
		}
		if e.devices.reads.Load() != 1 {
			t.Fatalf("%d device reads for one grant screen", e.devices.reads.Load())
		}

		// Bob presses Alice's button: nothing, and the button still works
		// for Alice afterwards (T4).
		if r := e.press(bob, grant); r != pa.ReplyUnknownButton {
			t.Fatalf("bob's press answered %q", r)
		}
		if rows := e.rows(); len(rows) != 0 {
			t.Fatalf("bob's press granted: %+v", rows)
		}
		if r := e.press(alice, grant); r != pa.ReplyPermissionGranted {
			t.Fatalf("alice's press answered %q", r)
		}
		rows := e.rows()
		if len(rows) != 1 {
			t.Fatalf("rows %+v", rows)
		}
		got := rows[0]
		want := permRow{principal: alice, id: got.id, conn: e.home.ID, server: "alice", tool: permTool,
			dev: `["dev-1","dev-2"]`, rev: e.home.AuthorityRevision, ceiling: 5,
			created: e.h.Now().UnixMilli(), expires: expiry.UnixMilli()}
		if got != want || !permissions.ValidID(got.id) {
			t.Fatalf("stored %+v, want %+v", got, want)
		}
		// The button worked once.
		if r := e.press(alice, grant); r != pa.ReplyUnknownButton {
			t.Fatalf("second press answered %q", r)
		}
		if len(e.rows()) != 1 {
			t.Fatal("a second press granted again")
		}

		list := e.one(alice, "/permissions")
		if len(list.Buttons) != 0 || !strings.Contains(list.Text, safetext.TextPermissionID.String()+" "+got.id) ||
			!strings.Contains(list.Text, permTool) || !strings.Contains(list.Text, "dev-1, dev-2") {
			t.Fatalf("list: %q %+v", list.Text, list.Buttons)
		}
		// Bob sees none of it and cannot open a revoke screen for it.
		e.refused(bob, "/permissions", safetext.TextPermissionsNone)
		e.refused(bob, "/permissions revoke "+got.id, safetext.TextPermissionGone)

		rscreen := e.one(alice, "/permissions revoke "+got.id)
		if !strings.Contains(rscreen.Text, safetext.TextPermissionRevokeHead.String()) || !strings.Contains(rscreen.Text, got.id) {
			t.Fatalf("revoke screen: %q", rscreen.Text)
		}
		revoke := e.button(rscreen, safetext.LabelPermissionRevoke)
		if r := e.press(bob, revoke); r != pa.ReplyUnknownButton {
			t.Fatalf("bob's revoke press answered %q", r)
		}
		if e.rows()[0].revoked != 0 {
			t.Fatal("bob revoked alice's permission")
		}
		if r := e.press(alice, revoke); r != pa.ReplyPermissionRevoked {
			t.Fatalf("revoke press answered %q", r)
		}
		if e.rows()[0].revoked == 0 {
			t.Fatal("the permission is not revoked")
		}
		e.refused(alice, "/permissions", safetext.TextPermissionsNone)
		e.refused(alice, "/permissions revoke "+got.id, safetext.TextPermissionGone)

		// The command and its screens never reached the model: no fragment
		// holds them and no run was queued for them.
		if n := e.h.Count(`SELECT COUNT(*) FROM pa_jobs WHERE principal = $1`, alice); n != 1 {
			t.Fatalf("%d jobs, want the env's one", n)
		}
	})
}

// TestPermissions_GrantRefusals: every grant the threat model forbids is
// refused before a screen exists: no button, no callback, no row.
func TestPermissions_GrantRefusals(t *testing.T) {
	env := newPermEnv(t, sqliteStore(t))
	// Each command gets a rate window of its own; no screen is pending
	// here, so moving the clock expires nothing the test relies on.
	e := &spacedEnv{env}
	usage, refused := safetext.TextPermissionsUsage, safetext.TextPermissionRefused
	for _, tc := range []struct {
		cmd  string
		want safetext.Template
	}{
		{"/permissions grant alice_say_phrase dev-1", refused},       // disclosure
		{"/permissions grant alice_send_command dev-1", refused},     // disclosure
		{"/permissions grant alice_control_room dev-1", refused},     // never lowerable, whatever the pin says
		{"/permissions grant alice_trigger_scenario dev-1", refused}, // never lowerable, whatever the pin says
		{"/permissions grant alice_media_control dev-1", refused},    // the pin says never
		{"/permissions grant alice_list_devices dev-1", refused},     // a read
		{"/permissions grant alice_no_such_tool dev-1", refused},
		{"/permissions grant " + writeTool + " dev-1", refused}, // tg write, never lowerable
		{"/permissions grant " + permTool + " dev-9", refused},  // not in the fresh read
		{"/permissions grant " + permTool + " dev-1,dev-9 5", refused},
		{"/permissions grant " + permTool, usage},
		{"/permissions grant " + permTool + " dev-1 5 extra", usage},
		{"/permissions grant " + permTool + " dev-1 1001", usage},
		{"/permissions grant " + permTool + " dev-1 -1", usage},
		{"/permissions grant " + permTool + " dev-1 many", usage},
		{"/permissions grant " + permTool + " dev.1", usage},
		{"/permissions grant " + permTool + " d1,d2,d3,d4,d5,d6,d7,d8,d9,d10,d11", usage},
		{"/permissions revoke", usage},
		{"/permissions revoke not/an/id", usage},
		{"/permissions always", usage},
	} {
		e.refused(alice, tc.cmd, tc.want)
		e.nothingGranted(tc.cmd)
	}

	// The fresh device read: a failure and a malformed list refuse; they
	// are never "nothing to object to".
	e.devices.fail.Store(true)
	e.refused(alice, grantCmd, refused)
	e.devices.fail.Store(false)
	e.devices.set("dev-1", "dev-1", "dev-2")
	e.refused(alice, grantCmd, refused)
	e.devices.set("dev-1", "", "dev-2")
	e.refused(alice, grantCmd, refused)
	e.devices.set()
	e.refused(alice, grantCmd, refused)
	e.devices.set("dev-1", "dev-2")
	e.nothingGranted("device reads")

	// The tool-specific rule: none refuses (the default), and so does one
	// that objects.
	e.validator.Rule = nil
	e.refused(alice, grantCmd, refused)
	e.validator.Rule = e.rule
	objection := errors.New("not a speaker")
	e.rule.err.Store(&objection)
	e.refused(alice, grantCmd, refused)
	e.rule.err.Store(nil)
	e.nothingGranted("rules")

	// Fixture: the same command is offered once nothing objects.
	e.h.Advance(jobs.DefaultRateWindow)
	e.button(e.one(alice, grantCmd), safetext.LabelPermissionGrant)
}

// TestPermissions_InertWithoutWiringOrWrites: without the wiring the
// command is answered "not available"; with it and PA_WRITES_ENABLED off
// (or unreadable) no grant is offered or confirmed, while listing and
// revoking, which only remove authority, still work.
func TestPermissions_InertWithoutWiringOrWrites(t *testing.T) {
	e := newPermEnv(t, sqliteStore(t))
	screen := e.one(alice, grantCmd)
	grant := e.button(screen, safetext.LabelPermissionGrant)
	if r := e.press(alice, grant); r != pa.ReplyPermissionGranted {
		t.Fatalf("grant: %q", r)
	}
	id := e.rows()[0].id
	pending := e.button(e.one(alice, "/permissions grant "+permTool+" dev-3"), safetext.LabelPermissionGrant)

	for name, off := range map[string]func(bool){
		"writes off":        func(on bool) { e.writes.Store(!on) },
		"writes unreadable": func(on bool) { e.writesErr.Store(on) },
	} {
		off(true)
		e.refused(alice, grantCmd, safetext.TextPermissionsUnavailable)
		if n := e.permCallbacks(); n != 1 {
			t.Fatalf("%s: %d callbacks, want the pending one", name, n)
		}
		if list := e.one(alice, "/permissions"); !strings.Contains(list.Text, id) {
			t.Fatalf("%s: list %q", name, list.Text)
		}
		off(false)
	}
	// A screen shown while writes were on is not confirmed once they are
	// off.
	e.writes.Store(false)
	if r := e.press(alice, pending); r != pa.ReplyPermissionsUnavailable {
		t.Fatalf("press with writes off answered %q", r)
	}
	if len(e.rows()) != 1 {
		t.Fatal("a grant was confirmed with writes off")
	}
	revoke := e.button(e.one(alice, "/permissions revoke "+id), safetext.LabelPermissionRevoke)
	if r := e.press(alice, revoke); r != pa.ReplyPermissionRevoked {
		t.Fatalf("revoke with writes off answered %q", r)
	}
	e.writes.Store(true)

	// Not wired, as in every deployed service today.
	issued := e.button(e.one(alice, grantCmd), safetext.LabelPermissionGrant)
	e.h.EnablePermissions(nil, nil)
	fragments := e.h.Count(`SELECT COUNT(*) FROM pa_fragments WHERE principal = $1`, alice)
	before := len(e.h.Replies(alice))
	if code := e.h.TextStatus(alice, grantCmd); code != http.StatusOK {
		t.Fatalf("command: %d", code)
	}
	if r := e.h.Replies(alice)[before:]; !slices.Equal(r, []pa.Reply{pa.ReplyPermissionsUnavailable}) {
		t.Fatalf("unwired command answered %v", r)
	}
	if n := e.h.Count(`SELECT COUNT(*) FROM pa_fragments WHERE principal = $1`, alice); n != fragments {
		t.Fatal("the command was stored for the model")
	}
	if r := e.press(alice, issued); r != pa.ReplyUnknownButton {
		t.Fatalf("unwired press answered %q", r)
	}
	for _, r := range e.rows() {
		if r.revoked == 0 {
			t.Fatalf("a permission in force: %+v", r)
		}
	}
}

// TestPermissions_ConfirmationRechecks: what the press checks again, in
// its own transaction, after the screen was shown.
func TestPermissions_ConfirmationRechecks(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newPermEnv(t, s)
		ctx := context.Background()

		// The policy changed.
		grant := e.button(e.one(alice, grantCmd), safetext.LabelPermissionGrant)
		never := permPin()
		tool := never.Servers["alice"].Tools[permTool]
		tool.Lowerable = catalog.LowerableNever
		never.Servers["alice"].Tools[permTool] = tool
		e.policy.pin.Store(never)
		if r := e.press(alice, grant); r != pa.ReplyPermissionRefused {
			t.Fatalf("press after the tool stopped being lowerable answered %q", r)
		}
		e.policy.pin.Store(permPin())
		e.nothingGranted("policy changed")

		// Consent was withdrawn after the screen was sent. /consent
		// withdraw erases the principal's callbacks, so the button is
		// gone; a consent that ended any other way (the row alone changed)
		// makes the press ask for consent again. Neither grants.
		grant = e.button(e.one(alice, grantCmd), safetext.LabelPermissionGrant)
		e.h.Text(alice, "/consent withdraw")
		if r := e.press(alice, grant); r != pa.ReplyUnknownButton {
			t.Fatalf("press after /consent withdraw answered %q", r)
		}
		e.h.Consent(alice)
		grant = e.button(e.one(alice, grantCmd), safetext.LabelPermissionGrant)
		if _, err := s.DB.Exec(`UPDATE pa_consents SET state = $1 WHERE principal = $2`, string(convo.ConsentWithdrawn), alice); err != nil {
			t.Fatal(err)
		}
		if r := e.press(alice, grant); r != pa.ReplyConsentPrompt {
			t.Fatalf("press without consent answered %q", r)
		}
		if rows := e.rows(); len(rows) != 0 {
			t.Fatalf("granted without consent: %+v", rows)
		}
		e.h.Consent(alice)

		// The button expired.
		grant = e.button(e.one(alice, grantCmd), safetext.LabelPermissionGrant)
		e.h.Advance(permissions.ScreenTTL + time.Second)
		if r := e.press(alice, grant); r != pa.ReplyUnknownButton {
			t.Fatalf("press on an expired screen answered %q", r)
		}
		if rows := e.rows(); len(rows) != 0 {
			t.Fatalf("an expired screen granted: %+v", rows)
		}

		// The connection's revision moved between screen and press.
		grant = e.button(e.one(alice, grantCmd), safetext.LabelPermissionGrant)
		if _, err := s.TransitionPAConnection(ctx, alice, e.home.ID, connection.Transition{
			From: connection.StateActive, To: connection.StateExpired, ExpectRevision: e.home.AuthorityRevision,
			Reason: "invalid_grant"}); err != nil {
			t.Fatal(err)
		}
		if r := e.press(alice, grant); r != pa.ReplyPermissionRefused {
			t.Fatalf("press after a revision change answered %q", r)
		}
		if rows := e.rows(); len(rows) != 0 {
			t.Fatalf("granted on a changed connection: %+v", rows)
		}
		// And with no active connection to the tool's server, no screen.
		e.refused(alice, grantCmd, safetext.TextPermissionRefused)
	})
}

// TestS2A9_RevisionChangeRevokesAGrantedPermission is S2-A9 end to end: a
// permission granted through /permissions is revoked by /disconnect's
// store call, in its transaction, and the listing shows none.
func TestS2A9_RevisionChangeRevokesAGrantedPermission(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newPermEnv(t, s)
		ctx := context.Background()
		if r := e.press(alice, e.button(e.one(alice, grantCmd), safetext.LabelPermissionGrant)); r != pa.ReplyPermissionGranted {
			t.Fatalf("grant: %q", r)
		}
		lookup := func(rev int64) int {
			got, err := s.LookupPAPermissions(ctx, alice, e.home.ID, rev, "alice", permTool, e.h.Now())
			if err != nil {
				t.Fatal(err)
			}
			return len(got)
		}
		if lookup(e.home.AuthorityRevision) != 1 {
			t.Fatal("the granted permission is not found")
		}
		if _, _, _, err := s.RevokePAConnection(ctx, alice, e.home.ID, "user_disconnect"); err != nil {
			t.Fatal(err)
		}
		if rows := e.rows(); len(rows) != 1 || rows[0].revoked == 0 {
			t.Fatalf("after the disconnect: %+v", rows)
		}
		if lookup(e.home.AuthorityRevision) != 0 || lookup(e.home.AuthorityRevision+1) != 0 {
			t.Fatal("a permission is found after the revision changed")
		}
		e.refused(alice, "/permissions", safetext.TextPermissionsNone)
	})
}

// jobRoutes are the routes a job token (or the pool token) reaches.
func jobRoutes() []string { return append(pa.JobRoutes(), connector.RouteTool) }

// TestS2A8_NoJobRouteGrantsAPermission drives every route a job token
// reaches with payloads that ask for a standing permission, and delivers
// the command as text that is not the principal's own. The table stays
// empty and no grant screen is issued. The last step shows the same env
// does grant through /permissions, so the emptiness is not a dead fixture.
func TestS2A8_NoJobRouteGrantsAPermission(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newPermEnv(t, s)
		grantJSON := `{"tool":"` + permTool + `","device_ids":["dev-1"],"ceiling":5,"always":true}`
		bodies := []string{
			`{"always":true}`,
			`{"grant":` + grantJSON + `}`,
			`{"permission":` + grantJSON + `,"context_tokens":10}`,
			`{"context_tokens":10,"always":true}`,
			`{"text":"` + grantCmd + `","always":true}`,
			`{"server":"alice","tool":"permissions_grant","arguments":` + grantJSON + `}`,
			`{"server":"alice","tool":"/permissions","arguments":{"grant":"` + permTool + ` dev-1"}}`,
			`{"server":"alice","tool":"alice_grant_permission","arguments":` + grantJSON + `}`,
			`{"server":"alice","tool":"` + permTool + `","arguments":{"device_id":"dev-1","volume":5,"always":true}}`,
			`{"server":"alice","tool":"` + permTool + `","arguments":{"device_id":"dev-1","volume":5},"always":true}`,
			`{"server":"tg","tool":"` + writeTool + `","arguments":{"to":"Carol","text":"hi","always":true,"remember":true}}`,
			`{"server":"tg","tool":"get_messages","arguments":{"permission_grant":` + grantJSON + `}}`,
			`{"server":"permissions","tool":"grant","arguments":` + grantJSON + `}`,
		}
		routes := jobRoutes()
		if !slices.Contains(routes, pa.RouteReply) || len(routes) != 4 {
			t.Fatalf("routes %v", routes)
		}
		// The reply route ends the job, so it goes last.
		slices.SortStableFunc(routes, func(a, b string) int {
			return strings.Compare(strconv.FormatBool(a == pa.RouteReply), strconv.FormatBool(b == pa.RouteReply))
		})
		for _, tok := range []string{e.token, e.h.PoolToken()} {
			for _, route := range routes {
				for _, body := range bodies {
					if route == connector.RouteTool {
						e.call(tok, body)
					} else {
						e.h.PostJobRoute(route, tok, body)
					}
					e.nothingGranted(route + " " + body)
				}
			}
		}
		// The model's final answer is the command: it is sent as text, not
		// run. The job of the env was ended by a hostile reply above or is
		// ended here.
		e.h.PostJobRoute(pa.RouteReply, e.token, `{"text":"`+grantCmd+`"}`)
		e.nothingGranted("assistant reply")
		// Text that is not the principal's own: forwarded to the bot.
		for _, text := range []string{grantCmd, "/permissions", "/permissions revoke prm_1"} {
			if code := e.h.ForwardStatus(alice, text); code != http.StatusOK {
				t.Fatalf("forward: %d", code)
			}
			e.nothingGranted("forwarded " + text)
		}
		for _, m := range e.h.MessagesTo(alice) {
			for _, row := range m.Buttons {
				for _, b := range row {
					if b[0] == safetext.LabelPermissionGrant.String() || b[0] == safetext.LabelPermissionRevoke.String() {
						t.Fatalf("a /permissions button was sent: %q", m.Text)
					}
				}
			}
		}
		// Approving a card grants nothing either (S2-A10).
		// Fixture: the principal's own command does issue a screen and its
		// press does create the row.
		grant := e.button(e.one(alice, grantCmd), safetext.LabelPermissionGrant)
		if e.permCallbacks() != 1 {
			t.Fatal("fixture: the screen issued no callback")
		}
		if r := e.press(alice, grant); r != pa.ReplyPermissionGranted || len(e.rows()) != 1 {
			t.Fatalf("fixture: grant answered %q, rows %+v", r, e.rows())
		}
	})
}

// TestS2A10_ApprovingACardGrantsNoPermission: a card's Approve and Cancel
// reach the approval ledger only; with /permissions wired next to them, a
// pressed card leaves the permission table and its callbacks empty.
func TestS2A10_ApprovingACardGrantsNoPermission(t *testing.T) {
	e := newPermEnv(t, sqliteStore(t))
	e.manyCardsPerRun()
	first := e.emit(`{"to":"Carol","text":"hi"}`)
	if r := e.press(alice, first.approve); r == pa.ReplyUnknownButton {
		t.Fatalf("approve answered %q", r)
	}
	// emit reads the newest approval by its creation time.
	e.h.Advance(time.Second)
	second := e.emit(`{"to":"Carol","text":"again"}`)
	e.press(alice, second.cancel)
	if e.handed() != 1 {
		t.Fatalf("%d approvals handed over, want 1", e.handed())
	}
	e.nothingGranted("approved and cancelled cards")
	for _, m := range e.sentCards(alice) {
		for _, b := range m.Buttons[0] {
			if b[0] != safetext.LabelApprove.String() && b[0] != safetext.LabelCancel.String() {
				t.Fatalf("a card carries the button %q", b[0])
			}
		}
	}
	// A /permissions press never reaches the approval ledger.
	approvals := e.h.Count(`SELECT COUNT(*) FROM pa_approvals`)
	if r := e.press(alice, e.button(e.one(alice, grantCmd), safetext.LabelPermissionGrant)); r != pa.ReplyPermissionGranted {
		t.Fatalf("grant: %q", r)
	}
	if n := e.h.Count(`SELECT COUNT(*) FROM pa_approvals`); n != approvals || e.handed() != 1 {
		t.Fatal("a /permissions press touched the approval ledger")
	}
}

// repoGoFiles parses every non-test Go file of the module's internal and
// cmd trees.
func repoGoFiles(t *testing.T) (*token.FileSet, map[string]*ast.File) {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	files := map[string]*ast.File{}
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			files[filepath.ToSlash(rel)] = f
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(files) < 50 {
		t.Fatalf("only %d files parsed: wrong root %s", len(files), root)
	}
	return fset, files
}

// useSite is one mention of a name: the file and the function around it.
type useSite struct{ file, fn string }

func (u useSite) String() string { return u.file + ":" + u.fn }

// mentions returns, per name, where an identifier with that name appears
// (declarations, interface methods, calls, method values) and where a
// string literal matching one of the SQL fragments appears.
func mentions(t *testing.T, names, sql []string) (idents, literals map[string][]useSite) {
	t.Helper()
	_, files := repoGoFiles(t)
	idents, literals = map[string][]useSite{}, map[string][]useSite{}
	squash := func(s string) string { return strings.Join(strings.Fields(strings.ToLower(s)), " ") }
	for name, f := range files {
		for _, decl := range f.Decls {
			fn := "(package)"
			if fd, ok := decl.(*ast.FuncDecl); ok {
				fn = fd.Name.Name
			}
			ast.Inspect(decl, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.Ident:
					if slices.Contains(names, x.Name) {
						idents[x.Name] = append(idents[x.Name], useSite{name, fn})
					}
				case *ast.BasicLit:
					if x.Kind != token.STRING {
						return true
					}
					for _, frag := range sql {
						if strings.Contains(squash(x.Value), frag) {
							literals[frag] = append(literals[frag], useSite{name, fn})
						}
					}
				}
				return true
			})
		}
	}
	for _, m := range []map[string][]useSite{idents, literals} {
		for k := range m {
			slices.SortFunc(m[k], func(a, b useSite) int { return strings.Compare(a.String(), b.String()) })
		}
	}
	return idents, literals
}

// TestS2A8_GrantInsertHasOneCaller is the static half of S2-A8 and of the
// "single writer" of S2-A10: across the service's source, the statement
// that creates a standing permission is in one function, that function has
// one caller, the handler of a pressed /permissions button, and that
// handler is reached from the webhook's callback path only. Nothing that
// serves /api/pa/v1/jobs/* is on that path, and the routes under that
// prefix are exactly the ones TestS2A8_NoJobRouteGrantsAPermission drives.
func TestS2A8_GrantInsertHasOneCaller(t *testing.T) {
	const (
		dbFile  = "internal/db/pa_permissions.go"
		cmdFile = "internal/pa/permissions.go"
	)
	idents, literals := mentions(t,
		[]string{"InsertPAPermission", "permissionButton", "IssuePAPermissionCallback", "RevokePAPermission",
			"revokePAPermissionsOfConnTx", "revokePAPermissionsOfPrincipalTx", "PermissionGrants", "Grants"},
		[]string{"insert into pa_permissions", "update pa_permissions", "delete from pa_permissions", "pa_permissions"})
	site := func(file, fn string) useSite { return useSite{file, fn} }
	check := func(what string, got, want []useSite) {
		t.Helper()
		slices.SortFunc(want, func(a, b useSite) int { return strings.Compare(a.String(), b.String()) })
		if !slices.Equal(got, want) {
			t.Errorf("%s appears at %v, want exactly %v", what, got, want)
		}
	}
	// The insert: its declaration, the interface method the button
	// handler calls it through, and that one call.
	check("InsertPAPermission", idents["InsertPAPermission"], []useSite{
		site(dbFile, "InsertPAPermission"), site(cmdFile, "(package)"), site(cmdFile, "permissionButton"),
	})
	check("INSERT INTO pa_permissions", literals["insert into pa_permissions"], []useSite{site(dbFile, "InsertPAPermission")})
	// The button handler: its declaration and one call, from the webhook's
	// callback handler.
	check("permissionButton", idents["permissionButton"], []useSite{
		site("internal/pa/conversation.go", "handleCallback"), site(cmdFile, "permissionButton"),
	})
	// The store behind the handler is reached through the Grants field
	// only, and only the handler reads it.
	check("PermissionGrants", idents["PermissionGrants"], []useSite{site(cmdFile, "(package)"), site(cmdFile, "(package)")})
	for _, u := range idents["Grants"] {
		// buildPAWrites sets the field once, in the one constructor of the
		// write path (P2-S14); it never calls through it.
		if u != site(cmdFile, "(package)") && u != site(cmdFile, "permissionButton") && u != site(cmdFile, "valid") &&
			u != site("cmd/server/pa_writes.go", "buildPAWrites") {
			t.Errorf("the permission store is used at %v", u)
		}
	}
	// The screen's callback has one issuer, the post-commit command.
	check("IssuePAPermissionCallback", idents["IssuePAPermissionCallback"], []useSite{
		site(dbFile, "IssuePAPermissionCallback"), site(cmdFile, "(package)"), site(cmdFile, "withButton"),
	})
	// Revoking: by the button, and by every revision change.
	check("RevokePAPermission", idents["RevokePAPermission"], []useSite{
		site(dbFile, "RevokePAPermission"), site(cmdFile, "(package)"), site(cmdFile, "permissionButton"),
	})
	check("revokePAPermissionsOfConnTx", idents["revokePAPermissionsOfConnTx"], []useSite{
		site("internal/db/pa_connections.go", "RevokePAConnectionAt"), site("internal/db/pa_connections.go", "revokePAConnOnce"),
		site("internal/db/pa_connections.go", "transitionPAConnTx"), site(dbFile, "revokePAPermissionsOfConnTx"),
	})
	// And for a whole principal: consent withdrawal, /forget, an admin
	// disable (#1320 slice P2-S12).
	check("revokePAPermissionsOfPrincipalTx", idents["revokePAPermissionsOfPrincipalTx"], []useSite{
		site("internal/db/pa_convo.go", "ForgetPAConversations"), site("internal/db/pa_principal_disable.go", "SetPAPrincipalDisabled"),
		site(dbFile, "revokePAPermissionsOfPrincipalTx"),
	})
	check("UPDATE pa_permissions", literals["update pa_permissions"], []useSite{
		site(dbFile, "RevokePAPermission"), site(dbFile, "revokePAPermissionsOfConnTx"),
		site(dbFile, "revokePAPermissionsOfPrincipalTx"),
	})
	check("DELETE FROM pa_permissions", literals["delete from pa_permissions"], []useSite{site("internal/db/pa_account.go", "(package)")})
	// No other file names the table in SQL at all.
	for _, u := range literals["pa_permissions"] {
		if u.file != dbFile && u.file != "internal/db/pa_account.go" {
			t.Errorf("the table is named in %v", u)
		}
	}

	// The job routes: every string under the prefix in the source is one
	// of the routes the dynamic test drives.
	_, files := repoGoFiles(t)
	var found []string
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				if s, err := strconv.Unquote(lit.Value); err == nil && strings.HasPrefix(s, "/api/pa/v1/jobs") {
					found = append(found, s)
				}
			}
			return true
		})
	}
	slices.Sort(found)
	want := jobRoutes()
	slices.Sort(want)
	if !slices.Equal(slices.Compact(found), want) {
		t.Errorf("routes under /api/pa/v1/jobs in the source: %v, driven by the test: %v", found, want)
	}

	// What a press can do to the table, and what the screens can.
	methods := func(v any) []string {
		typ := reflect.TypeOf(v).Elem()
		var out []string
		for i := range typ.NumMethod() {
			out = append(out, typ.Method(i).Name)
		}
		return out
	}
	if got := methods((*pa.PermissionGrants)(nil)); !slices.Equal(got, []string{"InsertPAPermission", "RevokePAPermission"}) {
		t.Errorf("a press can call %v", got)
	}
	if got := methods((*pa.PermissionStore)(nil)); !slices.Equal(got, []string{"ActivePAConnectionRefs", "IssuePAPermissionCallback", "ListActivePAPermissions"}) {
		t.Errorf("the screens can call %v", got)
	}
}

// TestS2A10_PermissionScreensRouteToTheirOwnCallbacks: the /permissions
// half of S2-A10. Every screen has at most one button; Grant resolves to a
// grant action and Revoke to a revoke action of the principal the screen
// was sent to, and neither is an approval card's action. No text of an
// approval card and no other message of the bot carries either button.
func TestS2A10_PermissionScreensRouteToTheirOwnCallbacks(t *testing.T) {
	want := []pa.PermissionScreenButton{
		{Label: safetext.LabelPermissionGrant, Verb: "grant"},
		{Label: safetext.LabelPermissionRevoke, Verb: "revoke"},
	}
	if got := pa.PermissionScreenButtons(); !slices.Equal(got, want) {
		t.Fatalf("/permissions buttons %+v, want exactly Grant and Revoke", got)
	}
	for _, b := range want {
		kb, ok := pa.PermissionKeyboard(b.Verb, "cb-1")
		if !ok || len(kb) != 1 || len(kb[0]) != 1 || kb[0][0].Label != b.Label || kb[0][0].Data != "cb-1" {
			t.Errorf("%s keyboard %+v (ok %v), want its one button", b.Verb, kb, ok)
		}
		for _, c := range pa.ApprovalCardButtons() {
			if c.Label == b.Label || c.Label.String() == b.Label.String() {
				t.Errorf("an approval card carries the %s label", b.Verb)
			}
		}
	}
	for _, verb := range []string{"", "list", "approve", "always", "Grant"} {
		if kb, ok := pa.PermissionKeyboard(verb, "cb-1"); ok || kb != nil {
			t.Errorf("verb %q builds the keyboard %+v", verb, kb)
		}
	}
	if kb, ok := pa.PermissionKeyboard("grant", ""); ok || kb != nil {
		t.Error("a keyboard without a callback id")
	}
	if kb, ok := pa.PermissionKeyboard("grant", strings.Repeat("a", 65)); ok || kb != nil {
		t.Error("a keyboard with an oversized callback id")
	}
	for _, tp := range safetext.CardTemplates() {
		for _, own := range []safetext.Template{safetext.LabelPermissionGrant, safetext.LabelPermissionRevoke,
			safetext.TextPermissionGrantHead, safetext.TextPermissionGranted} {
			if tp == own {
				t.Errorf("an approval card uses the /permissions text %q", own.String())
			}
		}
	}

	// End to end: what each screen's button resolves to.
	e := newPermEnv(t, sqliteStore(t))
	action := func(id string) string {
		t.Helper()
		var a string
		var p int64
		if err := e.store.DB.QueryRow(`SELECT principal, action FROM pa_callbacks WHERE id = $1`, id).Scan(&p, &a); err != nil {
			t.Fatal(err)
		}
		if p != alice {
			t.Fatalf("the callback belongs to %d", p)
		}
		return a
	}
	grant := e.button(e.one(alice, grantCmd), safetext.LabelPermissionGrant)
	prop, ok := permissions.ParseGrantAction(action(grant))
	if !ok || prop.Tool != permTool || fmt.Sprint(prop.DeviceIDs) != "[dev-1 dev-2]" || prop.Ceiling != 5 ||
		prop.ConnectionID != e.home.ID || prop.AuthorityRevision != e.home.AuthorityRevision {
		t.Fatalf("the Grant button resolves to %q", action(grant))
	}
	if _, isRevoke := permissions.ParseRevokeAction(action(grant)); isRevoke {
		t.Fatal("a grant action reads as a revoke")
	}
	if r := e.press(alice, grant); r != pa.ReplyPermissionGranted {
		t.Fatalf("grant: %q", r)
	}
	id := e.rows()[0].id
	revoke := e.button(e.one(alice, "/permissions revoke "+id), safetext.LabelPermissionRevoke)
	if got, ok := permissions.ParseRevokeAction(action(revoke)); !ok || got != id {
		t.Fatalf("the Revoke button resolves to %q", action(revoke))
	}
	if _, isGrant := permissions.ParseGrantAction(action(revoke)); isGrant {
		t.Fatal("a revoke action reads as a grant")
	}
	// The list and every fixed answer carry no button at all.
	for _, m := range e.h.MessagesTo(alice) {
		if len(m.Buttons) == 0 {
			continue
		}
		label := m.Buttons[0][0][0]
		isScreen := strings.Contains(m.Text, safetext.TextPermissionGrantHead.String()) || strings.Contains(m.Text, safetext.TextPermissionRevokeHead.String())
		if isScreen != (label == safetext.LabelPermissionGrant.String() || label == safetext.LabelPermissionRevoke.String()) {
			t.Errorf("message %q carries %+v", m.Text, m.Buttons)
		}
	}
}
