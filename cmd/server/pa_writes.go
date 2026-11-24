package main

// pa_writes.go is the one place the Personal Assistant's write path is
// built (#1320 slice P2-S14, #1323): the Phase 2 pin, the approval card
// emitter, the write executor, the approval buttons, /permissions and the
// dispatch of an approved call after its update committed.
//
// buildPAWrites builds all of it when PA_WRITES_ENABLED reads true at
// startup, and nothing of it otherwise. internal/pa's
// TestNoRuntimePhase2Use allows the Phase 2 constructors in that one
// function only, and requires its flag check to stand before the first of
// them. With the flag false, unset or unreadable the server is what it
// was before this slice: the Phase 1 pin, read tools, no card path, and
// /permissions answered "not available".
//
// The flag read here decides what exists. Every switch is read again on
// each request (connector.EnvFlags), so a built write path is cut at once
// by PA_EXTERNAL_TOOLS_ENABLED, PA_SERVER_<NAME>_ENABLED or
// PA_WRITES_ENABLED turning off: the claim offers no write tool
// (paTools.toolResolver), the tool route refuses the call (the gate in
// connector.Cards.Emit) and an Approve tap dispatches nothing
// (connector.WriteExecutor). PA_ENABLED is read at startup only: turning
// it off is a restart, after which none of this is built.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/config"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/pa"
	"github.com/mctlhq/mctl-telegram/internal/pa/approval"
	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/connector"
	"github.com/mctlhq/mctl-telegram/internal/pa/permissions"
)

// paWriteTools are the approve-tier tools the write path can offer a model,
// per server. Whether a principal's connection gets one of them in a claim
// is not decided here: that is the action gate's answer (paWriteGate).
//
// The list is explicit, not "every approve-tier tool of the pin": a tool
// belongs here once a call of it can end in a card. buildPAWrites refuses
// to start when a listed tool of an enabled server is not an approve-tier
// tool of the Phase 2 pin or has no card path (connector.Cards.CardPath),
// so a missing reader is a refused start and not a tool that fails on
// every call. Not listed today, and so never offered:
// alice_trigger_scenario (no scenario reader), alice_control_device and
// alice_control_room (no card).
//
// A variable only so the wiring tests can list a tool that must refuse the
// start; nothing else assigns it.
var paWriteTools = map[connection.Server][]string{
	connection.ServerAlice: {
		"alice_media_control", "alice_play_music", "alice_say_phrase", "alice_send_command",
		"alice_set_light", "alice_set_volume",
	},
}

// paWriteGate decides, inside the claim transaction, which of a
// connection's write tools the principal may be offered: it holds the
// consent to actions and the connection's grant holds the scope each tool
// needs. tools and the answer are bare tool names. When it withholds every
// tool it may name why, as one of the pa.ActionsHint values; any other
// reason is dropped. A failed read is an error, never an empty answer.
//
// The consent and scope checks are not this file's: the gate is the seam
// the consent slice (P2-S14c, pa.ActionGate) plugs into.
type paWriteGate interface {
	Offer(ctx context.Context, tx *sql.Tx, principal int64, connectionID string, tools []string) (offered []string, withheld string, err error)
}

// newPAWriteGate builds the action gate of a write path. No gate is wired
// yet, and without one the write path offers no tool to anyone: every
// card, tap and dispatch is built and reachable by no claim. A variable so
// the wiring tests can put a gate in.
var newPAWriteGate = func(store *db.Store, writes func() (bool, error)) paWriteGate { return nil }

// paApprovedDispatchTimeout bounds the dispatch of one approved call after
// its update committed: the executor's own call deadline and the writes
// that record the outcome.
const paApprovedDispatchTimeout = connector.DefaultCallTimeout + 30*time.Second

// paWrites is the built write path. A nil *paWrites is the write path not
// built: every method on it does nothing and offers nothing.
type paWrites struct {
	cards    *connector.Cards
	executor *connector.WriteExecutor
	// approvals and permissions go to the conversations, commands to the
	// webhook's AfterCommit.
	approvals   pa.ApprovalCallbacks
	permissions *pa.PermissionsConfig
	commands    *pa.PermissionCommands
	// approveTools is what the run loop may sign into a claim next to the
	// pinned reads: every offered tool as "server/tool".
	approveTools map[string]catalog.ModelTool
	// tools are the write tools of each enabled server.
	tools map[connection.Server][]string
	// gate says which of them a connection gets; nil offers none.
	gate paWriteGate
	// hints holds, per principal, why the last claim built for them was
	// offered no write tool (a pa.ActionsHint value), from the resolver in
	// the claim transaction to the claim's response in the same request.
	hints sync.Map
	// deliver sends what a dispatch queued for the principal
	// (pa.RunLoop.DeliverAfter); set by bind, once the run loop exists.
	deliver func(ctx context.Context, principal int64)
	wg      sync.WaitGroup
}

// paWritesEnabled reads PA_WRITES_ENABLED for the startup decision, with
// the dispatch path's own reader: missing, empty and "false" are off,
// "true" is on, and anything else is unreadable, which is off with the
// error.
func paWritesEnabled(flags func() (connector.Flags, error)) (bool, error) {
	f, err := flags()
	if err != nil {
		// PA_EXTERNAL_TOOLS_ENABLED is unreadable and nothing more was
		// read: the writes switch is unknown, so off.
		return false, err
	}
	if f.WritesErr != nil {
		return false, f.WritesErr
	}
	return f.Writes, nil
}

// buildPAWrites builds the write path over the tools runtime pt, or
// returns nil, nil when PA_WRITES_ENABLED is not true: unset, false or
// unreadable. Unreadable is logged as an error and never on. With the
// flag on, a prerequisite that is missing refuses startup: the approval
// sealer's key, the Phase 2 pin, an endpoint that cannot send approved
// bytes, or a listed tool without a card path. The one case that is not a
// refusal is no enabled server with a write tool at all: nothing is built,
// as with the flag off, and the log says so.
//
// The approval sealer is keyed by ENCRYPTION_KEY, the master key the
// conversation sealer already uses, under its own HKDF label
// ("mctl-pa-approval-args/v1", internal/pa/approval): no new secret.
func buildPAWrites(cfg *config.Config, pt *paTools, store *db.Store, sender paBotSender, allowed pa.PrincipalAllowlist, m connector.Metrics) (*paWrites, error) {
	if pt == nil {
		slog.Info("pa writes off", "reason", "no PA server is enabled")
		return nil, nil
	}
	on, err := paWritesEnabled(pt.flags)
	switch {
	case err != nil:
		slog.Error("pa writes off: the switch is unreadable", "env", connector.WritesFlagEnv, "err", err)
	case !on:
		slog.Info("pa writes off", "reason", connector.WritesFlagEnv+" not true")
	}
	if !on {
		return nil, nil
	}

	pin, err := catalog.LoadPinPhase2()
	if err != nil {
		return nil, fmt.Errorf("pa writes: Phase 2 pin: %w", err)
	}
	sealer, err := approval.NewSealer(cfg.EncryptionKey)
	if err != nil {
		return nil, errors.New("pa writes: ENCRYPTION_KEY does not key the approval sealer")
	}
	fresh, err := connector.NewPinFresh(pin, pt.endpoints)
	if err != nil {
		return nil, fmt.Errorf("pa writes: %w", err)
	}
	w := &paWrites{
		approvals:    store,
		approveTools: map[string]catalog.ModelTool{}, tools: map[connection.Server][]string{},
	}
	endpoints := map[string]connector.WriteEndpoint{}
	speakers := map[string]connector.SpeakerReader{}
	lights := map[string]connector.LightReader{}
	devices := map[string]connector.DeviceLister{}
	var grantDevices permissions.DeviceReader
	for _, server := range pt.servers {
		listed := paWriteTools[server]
		if len(listed) == 0 {
			continue
		}
		name := string(server)
		ep, ok := pt.endpoints[name].(connector.WriteEndpoint)
		if !ok {
			return nil, fmt.Errorf("pa writes: the %s endpoint cannot send approved arguments", name)
		}
		endpoints[name] = ep
		if server == connection.ServerAlice {
			// One reader of the structured device listing: the card reads
			// the speaker or the light through it, the executor reads the
			// device again before it sends, and a grant reads the devices
			// it lists.
			r, err := connector.NewAliceDevices(pin, pt.endpoints[name])
			if err != nil {
				return nil, fmt.Errorf("pa writes: %w", err)
			}
			speakers[name], lights[name], devices[name] = r, r, r
			g, err := connector.NewGrantDevices(r, pt.manager)
			if err != nil {
				return nil, fmt.Errorf("pa writes: %w", err)
			}
			grantDevices = g
		}
		w.tools[server] = slices.Sorted(slices.Values(listed))
	}
	if len(w.tools) == 0 {
		// A server switch that is off must not stop the service: with no
		// enabled server that has a write tool there is nothing to build,
		// and the write path stays as absent as with the flag off.
		slog.Warn("pa writes off: no enabled server has a write tool", "env", connector.WritesFlagEnv)
		return nil, nil
	}
	w.executor, err = connector.NewWriteExecutor(connector.WriteConfig{
		Store: store, Connections: pt.manager, Endpoints: endpoints, Executor: pt.executor,
		Sealer: sealer, Flags: pt.flags, Allowed: allowed.Allowed, Fresh: fresh, Metrics: m,
		Devices: devices,
	})
	if err != nil {
		return nil, fmt.Errorf("pa writes: %w", err)
	}
	// Scenarios stays nil until a reader of scenario steps exists: every
	// call of alice_trigger_scenario is refused, and paWriteTools does not
	// list it.
	w.cards, err = connector.NewCards(connector.CardConfig{
		Store: store, Sealer: sealer, Pin: pin, Fresh: fresh, Speakers: speakers, Lights: lights,
		Permissions: store, Lowered: w.executor,
		Deliver: func(ctx context.Context, principal int64) { w.deliverTo(ctx, principal) },
	})
	if err != nil {
		return nil, fmt.Errorf("pa writes: %w", err)
	}
	for server, listed := range w.tools {
		for _, tool := range listed {
			name := string(server) + "/" + tool
			if !w.cards.CardPath(string(server), tool) {
				return nil, fmt.Errorf("pa writes: %s is offered but has no approval card path", name)
			}
			mt, err := pin.ModelTool(string(server), tool)
			if err != nil {
				return nil, fmt.Errorf("pa writes: %s: %w", name, err)
			}
			w.approveTools[name] = mt
		}
	}
	policy := permissions.PinPolicy{Pin: pin}
	writes := func() (bool, error) { return paWritesEnabled(pt.flags) }
	w.permissions = &pa.PermissionsConfig{Grants: store, Policy: policy, Writes: writes}
	// A grant reads the devices it lists through grantDevices. It is nil
	// only when no enabled server has such a reader; the Validator then
	// refuses every grant devices_unread (S2-D5), which is fail closed.
	w.commands = &pa.PermissionCommands{
		Store: store, Sender: sender, Writes: writes,
		Validator: &permissions.Validator{Policy: policy, Devices: grantDevices, Rule: permissions.Rules{}},
	}
	w.gate = newPAWriteGate(store, writes)
	offered := slices.Sorted(maps.Keys(w.approveTools))
	slog.Info("pa writes on", "env", connector.WritesFlagEnv, "tools", strings.Join(offered, ","), "gate", w.gate != nil)
	if w.gate == nil {
		slog.Warn("pa writes: no action gate is wired, so no write tool is offered to any run")
	}
	return w, nil
}

// bind gives the write path the run loop's delivery, which exists only
// after the loop was built on the write path's cards.
func (w *paWrites) bind(deliver func(ctx context.Context, principal int64)) {
	if w != nil {
		w.deliver = deliver
	}
}

func (w *paWrites) deliverTo(ctx context.Context, principal int64) {
	if w != nil && w.deliver != nil {
		w.deliver(ctx, principal)
	}
}

// offered returns the write tools of c a claim for principal may sign, as
// "server/tool", and, when it returns none, why the gate withheld them.
// None unless the switches read now say writes are on for that server,
// and then only what the action gate offers: no gate, no tool. f is the
// claim's one read of the switches. An error is a failed read of the
// gate, which is never "none".
func (w *paWrites) offered(ctx context.Context, tx *sql.Tx, f connector.Flags, principal int64, c connection.Connection) ([]string, string, error) {
	if w == nil || !f.ExternalTools || !f.Writes || f.WritesErr != nil ||
		!f.Servers[string(c.Server)] || f.ServerErrs[string(c.Server)] != nil {
		return nil, "", nil
	}
	listed := w.tools[c.Server]
	if w.gate == nil || len(listed) == 0 {
		return nil, "", nil
	}
	got, withheld, err := w.gate.Offer(ctx, tx, principal, c.ID, slices.Clone(listed))
	if err != nil {
		return nil, "", err
	}
	var out []string
	for _, tool := range got {
		// The gate narrows the list; it cannot add to it.
		if slices.Contains(listed, tool) {
			out = append(out, string(c.Server)+"/"+tool)
		}
	}
	if len(out) > 0 {
		return out, "", nil
	}
	return nil, withheld, nil
}

// note records why the claim being built for principal has no write tool
// ("" when it has one or nothing was said), replacing what an earlier
// claim left.
func (w *paWrites) note(principal int64, withheld string) {
	if w == nil {
		return
	}
	if withheld == "" {
		w.hints.Delete(principal)
		return
	}
	w.hints.Store(principal, withheld)
}

// hint is pa.RunLoopConfig.ActionsHint: what note recorded for the claim
// just built for principal, taken once.
func (w *paWrites) hint(principal int64) string {
	if w == nil {
		return ""
	}
	v, _ := w.hints.LoadAndDelete(principal)
	s, _ := v.(string)
	return s
}

// afterCommit is the write path's part of the webhook's AfterCommit: an
// approval this update's Approve tap marked approved is dispatched now,
// outside the update's transaction and off the webhook's request, and an
// admitted /permissions command is run. The dispatch is exactly once by
// the approval ledger, not by this call: a second tap finds no pending
// approval and reaches here with nothing to dispatch.
func (w *paWrites) afterCommit(ctx context.Context, u pa.VerifiedUpdate) {
	if w == nil {
		return
	}
	if id, ok := pa.PostCommitApproval(ctx); ok {
		principal := u.Principal().TelegramID()
		w.wg.Add(1)
		go func() {
			defer w.wg.Done()
			dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), paApprovedDispatchTimeout)
			defer cancel()
			out, err := w.executor.DispatchApproved(dctx, principal, id)
			if err != nil {
				slog.Warn("pa writes: approved call not dispatched", "err", err)
			} else {
				slog.Info("pa writes: approved call handled", "status", string(out.Status), "reason", out.Reason)
			}
			// The executor queued the outcome's notice; send it now.
			w.deliverTo(dctx, principal)
		}()
	}
	w.commands.AfterCommit(ctx, u)
}

// wait waits for the dispatches and /permissions actions afterCommit
// started.
func (w *paWrites) wait() {
	if w == nil {
		return
	}
	w.wg.Wait()
	w.commands.Wait()
}
