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

// card.go is the bot's half of an approval card (#1320 slice P2-S5, threat
// model T7): the card's keyboard, the two callback actions behind it, and
// what the webhook does when one is pressed. The card itself is written by
// connector.Cards, in one transaction with its approval and its callbacks.
//
// Nothing here is reachable in a deployed service yet: no production
// wiring sets ConversationsConfig.Approvals or RunLoopConfig.Cards, no
// card is emitted while PA_WRITES_ENABLED is off, and the run loop admits
// no approve-tier tool (TestRunLoopToolSetIsPhase1Reads).

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/approval"
	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
	"github.com/mctlhq/mctl-telegram/internal/pa/output"
	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
)

// The pa_callbacks actions of an approval card's two buttons. The action
// names no approval: the pressed id is looked up in the approval ledger
// under the principal who pressed it (LookupPAApprovalByCallback), so a
// button resolves only for the principal the card was sent to (T4, S2-X5).
const (
	ActionApprovalApprove = "approval_approve"
	ActionApprovalCancel  = "approval_cancel"
)

// The answers to an approval card's buttons.
const (
	ReplyApprovalCancelled   Reply = "approval_cancelled"
	ReplyApprovalAlreadyDone Reply = "approval_already_done"
	ReplyApprovalExpired     Reply = "approval_expired"
)

// CardButton is one button of an approval card: a registry label and the
// callback action its press resolves to.
type CardButton struct {
	Label  safetext.Template
	Action string
}

// approvalCardButtons is every button an approval card has, in order. A
// card offers Approve and Cancel and nothing else: no button grants a
// standing permission (threat model T7, S2-A10). The card's keyboard is
// built from this list and from nothing else.
var approvalCardButtons = []CardButton{
	{Label: safetext.LabelApprove, Action: ActionApprovalApprove},
	{Label: safetext.LabelCancel, Action: ActionApprovalCancel},
}

// ApprovalCardButtons returns the buttons of an approval card.
func ApprovalCardButtons() []CardButton {
	return append([]CardButton(nil), approvalCardButtons...)
}

// ApprovalCard is a card ready to send: its text and the opaque callback
// ids of its buttons, both read from the approval row.
type ApprovalCard struct {
	Text safetext.Text
	// Approve and Cancel are the callback ids, each at most 64 bytes.
	Approve string
	Cancel  string
	// ExpiresAt is when the approval, and both buttons, stop working.
	ExpiresAt time.Time
}

// Errors of a CardRenderer.
var (
	// ErrCardGone: the approval is not pending any more (approved,
	// cancelled, expired, refused, forgotten), or was never this
	// principal's. The card is not sent.
	ErrCardGone = errors.New("pa: approval card has nothing to ask")
	// ErrCardUnreadable: the approval could not be read. That says
	// nothing about it; the card stays due.
	ErrCardUnreadable = errors.New("pa: approval card unreadable")
)

// CardRenderer builds the card of the pending approval whose Approve
// callback id is approveCallbackID, for principal only
// (*connector.Cards). It returns ErrCardGone or ErrCardUnreadable as
// above; any other error is a card that can never be built.
type CardRenderer interface {
	RenderApprovalCard(ctx context.Context, principal int64, approveCallbackID string) (ApprovalCard, error)
}

// cardMinLife is how long a card's buttons must still work when it is
// sent. A card held back longer (flood waits, an outage) is dropped: the
// approval expires unanswered and the principal asks again.
const cardMinLife = time.Minute

// approvalCardKeyboard is the keyboard of c: one row, one button per
// approvalCardButtons entry, carrying that action's callback id.
func approvalCardKeyboard(c ApprovalCard) (output.Keyboard, bool) {
	row := make([]output.Button, 0, len(approvalCardButtons))
	for _, b := range approvalCardButtons {
		var data string
		switch b.Action {
		case ActionApprovalApprove:
			data = c.Approve
		case ActionApprovalCancel:
			data = c.Cancel
		}
		if data == "" || len(data) > jobs.MaxOutboxButton {
			return nil, false
		}
		row = append(row, output.Button{Label: b.Label, Data: data})
	}
	if c.Approve == c.Cancel {
		return nil, false
	}
	return output.Keyboard{row}, true
}

// ApprovalCallbacks is the approval ledger as the webhook uses it
// (*db.Store). Every call is keyed by the principal who pressed.
type ApprovalCallbacks interface {
	LookupPAApprovalByCallback(ctx context.Context, tx *sql.Tx, principal int64, callbackID string) (approval.Approval, error)
	ApprovePAApproval(ctx context.Context, tx *sql.Tx, principal int64, id string, now time.Time) (approval.Approval, error)
	CancelPAApproval(ctx context.Context, tx *sql.Tx, principal int64, id string, now time.Time) (approval.Approval, error)
}

// approvalButton handles a pressed Approve or Cancel whose callback id was
// just consumed for the principal. Approve marks the approval approved in
// this transaction and leaves the dispatch to AfterCommit
// (PostCommitApproval): no call is made before the approval is durable,
// and none inside the webhook's transaction (T2). Cancel ends the
// approval and erases its arguments.
func (c *Conversations) approvalButton(ctx context.Context, tx *sql.Tx, u VerifiedUpdate, action string) error {
	principal, data, now := u.Principal().TelegramID(), u.CallbackData(), c.now()
	a, err := c.approvals.LookupPAApprovalByCallback(ctx, tx, principal, data)
	if errors.Is(err, approval.ErrNotFound) {
		// The callback outlived its approval (/forget, the sweep).
		return c.reply(ctx, tx, u, ReplyUnknownButton, "")
	}
	if err != nil {
		return err
	}
	// The stored action must be the one of the id pressed: an Approve id
	// never cancels and a Cancel id never approves.
	if (action == ActionApprovalApprove) != (data == a.ApproveCallbackID) ||
		(action == ActionApprovalCancel) != (data == a.CancelCallbackID) {
		return c.reply(ctx, tx, u, ReplyUnknownButton, "")
	}
	if action == ActionApprovalCancel {
		if _, err := c.approvals.CancelPAApproval(ctx, tx, principal, a.ID, now); err != nil {
			return c.approvalEnded(ctx, tx, u, err)
		}
		return c.reply(ctx, tx, u, ReplyApprovalCancelled, "")
	}
	if _, err := c.approvals.ApprovePAApproval(ctx, tx, principal, a.ID, now); err != nil {
		return c.approvalEnded(ctx, tx, u, err)
	}
	// The executor reports the outcome with its own notice; the press
	// itself is answered by AnswerCallbackAfter.
	return setPostCommitApproval(ctx, a.ID)
}

// approvalEnded answers a press the ledger refused because the approval
// had already ended. Anything else (an unreadable ledger) fails the update:
// the consume rolls back with it and Telegram redelivers the press.
func (c *Conversations) approvalEnded(ctx context.Context, tx *sql.Tx, u VerifiedUpdate, err error) error {
	switch {
	case errors.Is(err, approval.ErrAlreadyApproved), errors.Is(err, approval.ErrConsumed):
		return c.reply(ctx, tx, u, ReplyApprovalAlreadyDone, "")
	case errors.Is(err, approval.ErrCancelled):
		return c.reply(ctx, tx, u, ReplyApprovalCancelled, "")
	case errors.Is(err, approval.ErrExpired), errors.Is(err, approval.ErrRefused):
		return c.reply(ctx, tx, u, ReplyApprovalExpired, "")
	case errors.Is(err, approval.ErrNotFound):
		return c.reply(ctx, tx, u, ReplyUnknownButton, "")
	}
	return err
}

// spentButton answers a callback id that no longer resolves. When it was a
// button of one of this principal's approval cards, the answer comes from
// the approval row, which outlives its callbacks: a second tap on Approve
// reads "already approved", not "unknown button" (T7, S2-A7). The lookup
// is under the principal who pressed, so another principal's id, a guessed
// one and one that never existed all read as unknown and change nothing
// (S2-X5).
func (c *Conversations) spentButton(ctx context.Context, tx *sql.Tx, u VerifiedUpdate) error {
	if c.approvals == nil {
		return c.reply(ctx, tx, u, ReplyUnknownButton, "")
	}
	a, err := c.approvals.LookupPAApprovalByCallback(ctx, tx, u.Principal().TelegramID(), u.CallbackData())
	if errors.Is(err, approval.ErrNotFound) {
		return c.reply(ctx, tx, u, ReplyUnknownButton, "")
	}
	if err != nil {
		// Unreadable is not "unknown": the update fails and is retried.
		return err
	}
	switch a.Status {
	case approval.StatusApproved, approval.StatusDispatching, approval.StatusDone:
		return c.reply(ctx, tx, u, ReplyApprovalAlreadyDone, "")
	case approval.StatusCancelled:
		return c.reply(ctx, tx, u, ReplyApprovalCancelled, "")
	case approval.StatusExpired, approval.StatusRefused:
		return c.reply(ctx, tx, u, ReplyApprovalExpired, "")
	case approval.StatusPending:
		if !a.ExpiresAt.After(c.now()) {
			// Past its five minutes and not yet swept.
			return c.reply(ctx, tx, u, ReplyApprovalExpired, "")
		}
	}
	// Pending with a live expiry and no callback: nothing explains it, so
	// it is not explained.
	return c.reply(ctx, tx, u, ReplyUnknownButton, "")
}
