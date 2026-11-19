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

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

// AuditToolPrefix starts the tool_name of every PA row in audit_logs, so PA
// rows are distinguishable from the hosted MCP surface's own rows and are
// kept out of public tool-call counts.
const AuditToolPrefix = "pa:"

// AuditCallPath is the call_path of every PA row.
const AuditCallPath = "pa"

// auditRecordVersion opens the digest record stored in peer_redacted.
const auditRecordVersion = "pa/v1"

// AuditStore is the part of *db.Store the sink uses: the existing ADR 0003
// hash-chained insert and the read-only Telegram id lookup. No PA-specific
// table is involved.
type AuditStore interface {
	UserIDByTelegramID(ctx context.Context, tgID int64) (int64, error)
	LogToolCallChecked(ctx context.Context, c db.ToolCall) error
}

// StoreSink appends PA entries to the per-user audit chain of ADR 0003
// (audit_logs, hashAuditEntry). Each entry becomes one row:
//
//   - user_id: the users.id of the principal's Telegram id. A principal
//     without a users row, or one whose lookup fails, cannot be audited, so
//     the append fails and the call is refused (I9);
//   - tool_name: "pa:<server>/<tool>";
//   - peer_redacted: the digest record built by FormatRecord, which is
//     hashed into entry_hash like every other row's peer;
//   - status: the entry's status;
//   - call_path: "pa";
//   - error: empty. Error text could carry server or argument content.
type StoreSink struct {
	Store AuditStore
}

// ErrUnrecordable is returned for an entry the sink refuses to write, such
// as one with an identifier outside the safe alphabet.
var ErrUnrecordable = errors.New("pa connector: entry cannot be recorded")

// Append implements Sink.
func (s StoreSink) Append(ctx context.Context, e Entry) error {
	if s.Store == nil {
		return fmt.Errorf("%w: no store", ErrUnrecordable)
	}
	if e.Principal <= 0 {
		return fmt.Errorf("%w: no principal", ErrUnrecordable)
	}
	record, err := FormatRecord(e)
	if err != nil {
		return err
	}
	userID, err := s.Store.UserIDByTelegramID(ctx, e.Principal)
	if err != nil {
		return fmt.Errorf("pa audit: resolve principal: %w", err)
	}
	if userID <= 0 {
		return fmt.Errorf("%w: principal has no user row", ErrUnrecordable)
	}
	return s.Store.LogToolCallChecked(ctx, db.ToolCall{
		UserID:       userID,
		Tool:         AuditToolPrefix + e.Server + "/" + e.Tool,
		PeerRedacted: record,
		Status:       string(e.Status),
		CallPath:     AuditCallPath,
	})
}

// safeToken is the alphabet of every identifier written into the record.
// Anything else is refused rather than escaped: identifiers come from the
// server's own tables, so a value outside it is a bug, not data to keep.
var safeToken = regexp.MustCompile(`^[A-Za-z0-9_.:/-]{1,128}$`)

func recordToken(field, v string, required bool) (string, error) {
	if v == "" {
		if required {
			return "", fmt.Errorf("%w: %s is empty", ErrUnrecordable, field)
		}
		return "-", nil
	}
	if !safeToken.MatchString(v) {
		return "", fmt.Errorf("%w: %s has unsafe characters", ErrUnrecordable, field)
	}
	return v, nil
}

// FormatRecord renders the digest record of one entry: space-separated
// key=value pairs in a fixed order, identifiers and digests only. Absent
// optional values are "-".
func FormatRecord(e Entry) (string, error) {
	fields := []struct {
		key, val string
		required bool
	}{
		{"call", e.CallID, true},
		{"phase", string(e.Phase), true},
		{"principal", strconv.FormatInt(e.Principal, 10), true},
		{"server", e.Server, true},
		{"tool", e.Tool, true},
		{"conn", e.ConnectionID, true},
		{"rev", strconv.FormatInt(e.AuthorityRevision, 10), true},
		{"args", e.ArgsSHA256, true},
		{"tier", string(e.Tier), false},
		{"class", string(e.Class), false},
		{"taint", string(e.Taint), true},
		{"approval", e.ApprovalID, false},
		{"approver", e.Approver, false},
		{"status", string(e.Status), true},
		{"result", e.ResultSHA256, false},
		{"cost", strconv.FormatInt(e.Cost, 10), true},
		{"reason", e.Reason, false},
	}
	var b strings.Builder
	b.WriteString(auditRecordVersion)
	for _, f := range fields {
		v, err := recordToken(f.key, f.val, f.required)
		if err != nil {
			return "", err
		}
		b.WriteByte(' ')
		b.WriteString(f.key)
		b.WriteByte('=')
		b.WriteString(v)
	}
	// Only a refusals_suppressed summary carries a count; every other
	// record keeps its pa/v1 shape byte for byte.
	if e.Suppressed > 0 {
		b.WriteString(" suppressed=")
		b.WriteString(strconv.FormatInt(e.Suppressed, 10))
	}
	return b.String(), nil
}
