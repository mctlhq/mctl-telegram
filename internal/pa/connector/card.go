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

package connector

// card.go emits approval cards (#1320 slice P2-S5, threat model T2, T5, T7,
// T10, T14). When the worker calls an approve-tier tool, the tool route
// makes no downstream call. One transaction writes the pending approval
// with the call's arguments sealed into it, the callbacks of its Approve
// and Cancel buttons, and the outbox row of the card; the worker is told
// the call waits for the principal. The call itself is made later, by
// WriteExecutor.DispatchApproved, and only after the principal pressed
// Approve.
//
// Nothing here runs in a deployed service: no production wiring builds
// Cards (TestNoRuntimePhase2Use fails on any non-test call of NewCards),
// the run loop admits no approve-tier tool, and Emit refuses every call
// while PA_WRITES_ENABLED is off.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa"
	"github.com/mctlhq/mctl-telegram/internal/pa/approval"
	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/gate"
	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
)

// MaxCardArgsBytes bounds the canonical arguments a card shows (threat
// model T10). A call with more is refused, never shown cut: the principal
// approves what they can read.
const MaxCardArgsBytes = 4 << 10

// StatusApprovalPending is the tool route's answer to a call that now
// waits for the principal: nothing was called, a card was sent.
const StatusApprovalPending = "approval_pending"

// approvalPendingOutput is what the worker's model reads as the result of
// such a call. It is server text and is not recorded as conversation
// state: it holds nothing external.
const approvalPendingOutput = "Not done yet. The user was sent a card with this exact action and must approve it in Telegram. " +
	"Do not repeat this call. Tell the user that the action waits for their approval."

// Reasons of a card that was not emitted.
const (
	// ReasonCardTooLarge: the arguments are over MaxCardArgsBytes or the
	// card would not fit one message.
	ReasonCardTooLarge = "card_too_large"
	// ReasonCardUnshowable: the arguments hold a character a card cannot
	// show exactly (safetext.ErrCardUnshowable).
	ReasonCardUnshowable = "card_unshowable"
	// ReasonNoCard: the gate decided something a card cannot serve.
	ReasonNoCard = "no_card"
)

// CardStore is what Cards persists through (*db.Store).
type CardStore interface {
	// BeginPAWrite opens the transaction under the principal's lock.
	BeginPAWrite(ctx context.Context, principal int64, budget bool) (*sql.Tx, error)
	PAPrincipalDisabled(ctx context.Context, tx *sql.Tx, principal int64) (bool, error)
	PAConversationTaintIn(ctx context.Context, tx *sql.Tx, principal int64, conversationID string) (bool, error)
	CreatePAApproval(ctx context.Context, tx *sql.Tx, a approval.Approval) error
	CreatePACallback(ctx context.Context, tx *sql.Tx, principal int64, id, action string, expiresAt time.Time) error
	EnqueuePAOutbox(ctx context.Context, tx *sql.Tx, item jobs.OutboxItem, now time.Time) error
	// PAApprovalForCard and ReadPAConversationTaint serve the deliverer.
	PAApprovalForCard(ctx context.Context, principal int64, approveCallbackID string) (approval.Approval, error)
	ReadPAConversationTaint(ctx context.Context, principal int64, conversationID string) (bool, error)
}

// CardConfig wires Cards. Store, Sealer and Pin are required; without
// Fresh every card is refused (ReasonNoWritePath).
type CardConfig struct {
	Store  CardStore
	Sealer *approval.Sealer
	// Pin names the approve-tier tools. It is the pin the write path runs
	// on; production loads none with such a tool yet (P2-S14).
	Pin *catalog.Pin
	// Fresh reads the tool's definition as the server lists it now; the
	// approval binds those hashes (T7).
	Fresh FreshSurface
	// Speakers reads a server's speakers for the card of a disclosure
	// (disclosure.go), by server name. A disclosure on a server without a
	// reader is refused (ReasonNoWritePath).
	Speakers map[string]SpeakerReader
	// Lights reads a server's lights for the card of a write to a light
	// (device_write.go), by server name, as Speakers does for a speaker.
	Lights map[string]LightReader
	// Scenarios reads the steps of a server's scenario for the card of a
	// scenario call (scenario.go), by server name. A scenario call on a
	// server without a reader is refused (ReasonNoWritePath): that is
	// every server today.
	Scenarios map[string]ScenarioSteps
	Now       func() time.Time
	// Deliver is called after a card committed, to send it without
	// waiting for the next outbox pass (pa.RunLoop.DeliverAfter). Optional.
	Deliver func(ctx context.Context, principal int64)
}

// Cards emits approval cards and builds them for the deliverer.
type Cards struct {
	cfg CardConfig
}

var _ pa.CardRenderer = (*Cards)(nil)

// NewCards builds the card emitter.
func NewCards(cfg CardConfig) (*Cards, error) {
	if cfg.Store == nil || cfg.Sealer == nil || cfg.Pin == nil {
		return nil, errors.New("pa connector: cards need a store, a sealer and a pin")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Cards{cfg: cfg}, nil
}

// approveTool returns the pin entry of server/tool when the tool runs only
// after an approval.
func (c *Cards) approveTool(server, tool string) (catalog.PinnedTool, bool) {
	sp, ok := c.cfg.Pin.Servers[server]
	if !ok {
		return catalog.PinnedTool{}, false
	}
	t, ok := sp.Tools[tool]
	return t, ok && t.Tier == catalog.TierApprove
}

// Covers reports whether a call of server/tool takes the card path.
func (c *Cards) Covers(server, tool string) bool {
	_, ok := c.approveTool(server, tool)
	return ok
}

// CardRequest is one admitted call of an approve-tier tool.
type CardRequest struct {
	Policy            pa.Policy
	JobID             int64
	ConnectionID      string
	AuthorityRevision int64
	Server            string
	Tool              string
	Args              json.RawMessage
	// Token is the connection's access token, for the fresh tools/list.
	Token connection.Secret
	Flags Flags
}

// cardToolName is how a card names the tool: the catalog's own names, never
// a description the server supplied.
func cardToolName(server, tool string) string { return tool + " (" + server + ")" }

// Emit writes the approval, its two callbacks and the card for req in one
// transaction and makes no downstream tool call. It returns nil when the
// card is committed and the refusal otherwise. A refused call left no
// approval, callback or card behind; a disclosure refused for text over
// the cap leaves the principal's notice of it (offerSplit).
func (c *Cards) Emit(ctx context.Context, req CardRequest) *refusal {
	principal := req.Policy.Principal().TelegramID()
	pinned, ok := c.approveTool(req.Server, req.Tool)
	if !ok {
		return &refusal{ReasonNoWritePath, http.StatusForbidden}
	}
	in := gate.Input{
		Writes: req.Flags.Writes, WritesErr: req.Flags.WritesErr,
		Tool: req.Tool, Class: pinned.Class, Lowerable: pinned.Lowerable,
	}
	// Before anything is read or listed: with writes off, or a tool that
	// is no write, there is nothing to ask. The inputs not read yet are
	// given their unsafe values, which decide "card" at most.
	early := in
	early.Tainted = true
	if d := gate.Decide(early); d.Outcome != gate.OutcomeCard {
		return gateRefusal(d, nil)
	}

	canonical, err := catalog.CanonicalArgs(req.Args)
	if err != nil {
		return &refusal{ReasonBadRequest, http.StatusBadRequest}
	}
	if err := pinned.CheckDeclaredArgs(canonical); err != nil {
		return &refusal{ReasonBadRequest, http.StatusBadRequest}
	}
	// A disclosure has checks of its own (disclosure.go), ahead of the
	// size limits: text over the cap is told apart from a card too large.
	var disclosure *disclosureCall
	if pinned.Class == catalog.ClassDisclosure {
		call, ref := precheckDisclosure(req.Tool, pinned, canonical)
		if ref != nil {
			if ref.reason == ReasonTextTooLong {
				c.offerSplit(ctx, principal, req.JobID)
			}
			return ref
		}
		disclosure = &call
	}
	// A scenario call needs a reader of its steps before anything else is
	// read (scenario.go, S2-D6).
	_, isScenario := scenarioTools[req.Tool]
	scenario := ""
	// A write to one device has checks of its own too (device_write.go).
	// Every other Phase 2 write has no card here: it is never shown as a
	// plain card, which could not say what it does.
	var write *deviceWriteCall
	if isScenario {
		name, ref := c.precheckScenario(req.Server, req.Tool, canonical)
		if ref != nil {
			return ref
		}
		scenario = name
	} else if _, ok := deviceWriteTools[req.Tool]; ok && pinned.Class == catalog.ClassWrite {
		call, ref := precheckDeviceWrite(req.Tool, pinned, canonical)
		if ref != nil {
			return ref
		}
		write = &call
	} else if pinned.Class == catalog.ClassWrite && catalog.Phase2Tool(req.Tool) {
		return &refusal{ReasonNoWritePath, http.StatusForbidden}
	}
	if len(canonical) > MaxCardArgsBytes {
		return &refusal{ReasonCardTooLarge, http.StatusRequestEntityTooLarge}
	}
	// The largest card these arguments can get, so that an approval is
	// never written for a card that cannot be shown.
	if _, err := safetext.Card(cardToolName(req.Server, req.Tool), string(canonical), true); err != nil {
		return cardTextRefusal(err)
	}

	if c.cfg.Fresh == nil {
		return &refusal{ReasonNoWritePath, http.StatusForbidden}
	}
	fresh, err := c.cfg.Fresh.FreshTool(ctx, FreshRequest{
		Principal: principal, ConnectionID: req.ConnectionID, AuthorityRevision: req.AuthorityRevision,
		Server: req.Server, Tool: req.Tool, Token: req.Token,
	})
	if err != nil {
		reason := PinRefusalReason(err)
		code := http.StatusForbidden
		if reason == ReasonInternal || reason == ReasonServerUnavailable || reason == ReasonListingStale {
			code = http.StatusServiceUnavailable
		}
		return &refusal{reason, code}
	}
	if fresh.Tier != catalog.TierApprove || fresh.Class != pinned.Class {
		return &refusal{ReasonToolChanged, http.StatusForbidden}
	}

	// The target of a disclosure is read now, after the definition: the
	// card shows the speaker the server lists for this connection.
	var detail []byte
	if disclosure != nil {
		shown, sealed, ref := c.disclosureTarget(ctx, req, *disclosure)
		if ref != nil {
			return ref
		}
		if _, err := safetext.DisclosureCard(cardToolName(req.Server, req.Tool), string(canonical), shown, true); err != nil {
			return cardTextRefusal(err)
		}
		detail = sealed
	}
	if write != nil {
		shown, sealed, ref := c.deviceWriteTarget(ctx, req, *write)
		if ref != nil {
			return ref
		}
		if _, err := safetext.DeviceWriteCard(cardToolName(req.Server, req.Tool), string(canonical), shown, true); err != nil {
			return cardTextRefusal(err)
		}
		detail = sealed
	}
	// The steps of a scenario are read now too: the card lists them, or
	// there is no card.
	if isScenario {
		shown, sealed, ref := c.scenarioTarget(ctx, req, scenario)
		if ref != nil {
			return ref
		}
		if _, err := safetext.ScenarioCard(cardToolName(req.Server, req.Tool), string(canonical), shown, true); err != nil {
			return cardTextRefusal(err)
		}
		detail = sealed
	}

	// The hash is of all of the arguments, the device id among them: an
	// approval is for one text to one device (S2-D2).
	sum := sha256.Sum256(canonical)
	now := c.cfg.Now()
	a, err := approval.New(approval.Binding{
		Principal: principal, ConnectionID: req.ConnectionID, AuthorityRevision: req.AuthorityRevision,
		Server: req.Server, Tool: req.Tool, Class: pinned.Class,
		SchemaSHA: fresh.SchemaSHA, DescriptionSHA: fresh.DescriptionSHA, AnnotationSHA: fresh.AnnotationSHA,
		ArgsSHA:        hex.EncodeToString(sum[:]),
		ConversationID: req.Policy.ConversationID(), JobID: req.JobID,
	}, now)
	switch {
	case err != nil:
	case detail != nil:
		a, err = c.cfg.Sealer.SealWithDetail(a, canonical, detail)
	default:
		a, err = c.cfg.Sealer.Seal(a, canonical)
	}
	if err != nil {
		slog.Warn("pa card: approval not built", "err", err)
		return &refusal{ReasonInternal, http.StatusInternalServerError}
	}

	tx, err := c.cfg.Store.BeginPAWrite(ctx, principal, false)
	if err != nil {
		return &refusal{ReasonStateUnreadable, http.StatusServiceUnavailable}
	}
	defer func() { _ = tx.Rollback() }()
	in.PrincipalDisabled, in.PrincipalErr = c.cfg.Store.PAPrincipalDisabled(ctx, tx, principal)
	in.Tainted, in.TaintErr = c.cfg.Store.PAConversationTaintIn(ctx, tx, principal, a.ConversationID)
	// No standing permission is read: none exists yet (P2-S10), so the
	// gate cannot lower and every admitted call gets a card.
	if d := gate.Decide(in); d.Outcome != gate.OutcomeCard {
		return gateRefusal(d, in.PrincipalErr)
	}
	// One transaction: an approval without its card, or a card without
	// its approval, never commits.
	if err := c.cfg.Store.CreatePAApproval(ctx, tx, a); err != nil {
		if errors.Is(err, approval.ErrBinding) {
			return &refusal{ReasonConnectionUnbound, http.StatusForbidden}
		}
		return c.storeFailed("approval", err)
	}
	if err := c.cfg.Store.CreatePACallback(ctx, tx, principal, a.ApproveCallbackID, pa.ActionApprovalApprove, a.ExpiresAt); err != nil {
		return c.storeFailed("approve callback", err)
	}
	if err := c.cfg.Store.CreatePACallback(ctx, tx, principal, a.CancelCallbackID, pa.ActionApprovalCancel, a.ExpiresAt); err != nil {
		return c.storeFailed("cancel callback", err)
	}
	if err := c.cfg.Store.EnqueuePAOutbox(ctx, tx, jobs.OutboxItem{
		Principal: principal, Kind: jobs.OutboxApprovalCard, Button: a.ApproveCallbackID,
	}, now); err != nil {
		return c.storeFailed("card", err)
	}
	if err := tx.Commit(); err != nil {
		return c.storeFailed("commit", err)
	}
	if c.cfg.Deliver != nil {
		c.cfg.Deliver(ctx, principal)
	}
	return nil
}

// offerSplit queues the notice that a text for a speaker was over the cap
// (S2-D3): the one refusal of a disclosure the principal is told about by
// the server, once per job. Nothing else is written for the call. A notice
// that cannot be queued changes nothing about the refusal.
func (c *Cards) offerSplit(ctx context.Context, principal, jobID int64) {
	tx, err := c.cfg.Store.BeginPAWrite(ctx, principal, false)
	if err != nil {
		slog.Warn("pa card: split offer not queued", "step", "begin", "err_type", errorKind(err))
		return
	}
	defer func() { _ = tx.Rollback() }()
	if err := c.cfg.Store.EnqueuePAOutbox(ctx, tx, jobs.OutboxItem{
		Principal: principal, JobID: jobID, Kind: jobs.OutboxDisclosureTooLong,
	}, c.cfg.Now()); err != nil {
		slog.Warn("pa card: split offer not queued", "step", "enqueue", "err_type", errorKind(err))
		return
	}
	if err := tx.Commit(); err != nil {
		slog.Warn("pa card: split offer not queued", "step", "commit", "err_type", errorKind(err))
		return
	}
	if c.cfg.Deliver != nil {
		c.cfg.Deliver(ctx, principal)
	}
}

func (c *Cards) storeFailed(step string, err error) *refusal {
	// The step only: a store error may quote a row.
	slog.Warn("pa card: not written", "step", step, "err_type", errorKind(err))
	return &refusal{ReasonInternal, http.StatusInternalServerError}
}

// errorKind names an error without its text.
func errorKind(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return "context"
	case errors.Is(err, jobs.ErrOutboxUpdateReused):
		return "outbox_conflict"
	case errors.Is(err, approval.ErrUnreadable):
		return "approval_unreadable"
	}
	return "store"
}

// gateRefusal turns a gate decision that is not a card into a refusal.
func gateRefusal(d gate.Decision, principalErr error) *refusal {
	switch {
	case d.Outcome == gate.OutcomeNever && d.Reason == gate.ReasonWritesOff:
		return &refusal{ReasonWritesOff, http.StatusForbidden}
	case d.Outcome == gate.OutcomeNever && d.Reason == gate.ReasonPrincipalDisabled && principalErr != nil:
		// Could not read the disable: refused, and not called disabled.
		return &refusal{ReasonStateUnreadable, http.StatusServiceUnavailable}
	case d.Outcome == gate.OutcomeNever && d.Reason == gate.ReasonPrincipalDisabled:
		return &refusal{ReasonPrincipalDisabled, http.StatusForbidden}
	}
	// "Not a write", or a lowered call: this path serves neither.
	return &refusal{ReasonNoCard, http.StatusForbidden}
}

func cardTextRefusal(err error) *refusal {
	switch {
	case errors.Is(err, safetext.ErrTooLong):
		return &refusal{ReasonCardTooLarge, http.StatusRequestEntityTooLarge}
	case errors.Is(err, safetext.ErrCardUnshowable):
		return &refusal{ReasonCardUnshowable, http.StatusUnprocessableEntity}
	}
	return &refusal{ReasonInternal, http.StatusInternalServerError}
}

// RenderApprovalCard implements pa.CardRenderer. The card is built from
// the approval row when it is sent: its arguments are opened from the
// sealed bytes the executor will send (S2-D7), and its two buttons carry
// the row's own callback ids. The read is under the principal, so a row id
// that names another principal's card builds nothing.
func (c *Cards) RenderApprovalCard(ctx context.Context, principal int64, approveCallbackID string) (pa.ApprovalCard, error) {
	a, err := c.cfg.Store.PAApprovalForCard(ctx, principal, approveCallbackID)
	switch {
	case errors.Is(err, approval.ErrNotFound):
		return pa.ApprovalCard{}, pa.ErrCardGone
	case err != nil:
		return pa.ApprovalCard{}, errors.Join(pa.ErrCardUnreadable, err)
	}
	if a.Principal != principal || a.ApproveCallbackID != approveCallbackID {
		return pa.ApprovalCard{}, pa.ErrCardGone
	}
	if a.Status != approval.StatusPending || len(a.SealedArgs) == 0 {
		return pa.ApprovalCard{}, pa.ErrCardGone
	}
	args, detail, err := c.cfg.Sealer.OpenWithDetail(a)
	if err != nil {
		return pa.ApprovalCard{}, err
	}
	// Unreadable taint is shown as external content, never as none (I9).
	tainted, terr := c.cfg.Store.ReadPAConversationTaint(ctx, principal, a.ConversationID)
	var text safetext.Text
	if _, isScenario := scenarioTools[a.Tool]; isScenario {
		// A scenario's card lists its steps or is not built: it is never
		// shown as a plain card.
		var sc safetext.Scenario
		if sc, err = scenarioOf(a.Tool, args, detail); err == nil {
			text, err = safetext.ScenarioCard(cardToolName(a.Server, a.Tool), string(args), sc, tainted || terr != nil)
		}
	} else if a.Class == catalog.ClassDisclosure {
		// A disclosure has its own card or none: without the speaker
		// that was read for it, it is never shown as a plain card.
		var d safetext.Disclosure
		if d, err = disclosureOf(a.Tool, args, detail); err == nil {
			text, err = safetext.DisclosureCard(cardToolName(a.Server, a.Tool), string(args), d, tainted || terr != nil)
		}
	} else if _, ok := deviceWriteTools[a.Tool]; ok || catalog.Phase2Tool(a.Tool) {
		// A Phase 2 write has its own card or none, like a disclosure.
		pinned, pinnedOK := c.approveTool(a.Server, a.Tool)
		if !ok || !pinnedOK || a.Class != catalog.ClassWrite {
			return pa.ApprovalCard{}, errors.New("pa card: no card for this write")
		}
		var w safetext.DeviceWrite
		if w, err = deviceWriteOf(a.Tool, pinned, args, detail); err == nil {
			text, err = safetext.DeviceWriteCard(cardToolName(a.Server, a.Tool), string(args), w, tainted || terr != nil)
		}
	} else {
		text, err = safetext.Card(cardToolName(a.Server, a.Tool), string(args), tainted || terr != nil)
	}
	if err != nil {
		return pa.ApprovalCard{}, err
	}
	return pa.ApprovalCard{Text: text, Approve: a.ApproveCallbackID, Cancel: a.CancelCallbackID, ExpiresAt: a.ExpiresAt}, nil
}
