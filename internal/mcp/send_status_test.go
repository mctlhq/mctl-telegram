package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// callSendStatus invokes the get_my_send_status handler with the given identity.
func callSendStatus(t *testing.T, srv *Server, id *auth.Identity) *mcplib.CallToolResult {
	t.Helper()
	_, handler := srv.toolGetMySendStatus()
	ctx := context.Background()
	if id != nil {
		ctx = auth.With(ctx, id)
	}
	res, err := handler(ctx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{
		Name: "get_my_send_status",
	}})
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	return res
}

func parseSendStatus(t *testing.T, res *mcplib.CallToolResult) map[string]any {
	t.Helper()
	if res.IsError {
		t.Fatalf("expected success result, got tool error: %s", contentText(res))
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(contentText(res)), &out); err != nil {
		t.Fatalf("result is not JSON: %v (%s)", err, contentText(res))
	}
	return out
}

// seedHostedAccount inserts a non-revoked hosted account with the given
// send_enabled value and returns the user id.
func seedHostedAccount(t *testing.T, store *db.Store, tgID int64, sendEnabled bool) int64 {
	t.Helper()
	ctx := context.Background()
	uid, err := store.EnsureUserByTelegramID(ctx, tgID, "seed", "Seed User")
	if err != nil {
		t.Fatalf("EnsureUserByTelegramID: %v", err)
	}
	if _, err := store.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, session_encrypted, send_enabled, mode) VALUES($1, $2, $3, 'hosted')`,
		uid, []byte("blob"), sendEnabled,
	); err != nil {
		t.Fatalf("seed hosted account: %v", err)
	}
	return uid
}

// The whole point of the tool: the blocking reason it reports must be the same
// string send_message would have put in dry_reason. If the two ever diverge,
// the status is worse than useless — it sends the caller to fix the wrong
// thing. This is why the handler calls evaluateSendGate rather than restating
// the rules.
func TestGetMySendStatus_ReasonMatchesSendMessageDryReason(t *testing.T) {
	store := newToolsTestStore(t)
	uid := seedHostedAccount(t, store, 4242, false)
	srv := &Server{AllowSend: true, Store: store}
	id := &auth.Identity{UserID: uid, Scopes: []string{"telegram:messages:send"}}

	status := parseSendStatus(t, callSendStatus(t, srv, id))
	preview := parseSendResult(t, callSend(t, srv, id, map[string]any{"peer": "@x", "text": "hi"}))

	if status["can_send"] != false {
		t.Fatalf("can_send = %v, want false", status["can_send"])
	}
	if preview["sent"] != false {
		t.Fatalf("precondition: send_message sent = %v, want false", preview["sent"])
	}
	if status["reason"] != preview["dry_reason"] {
		t.Errorf("reason = %q, send_message dry_reason = %q — the status must not\ndisagree with the behaviour it describes",
			status["reason"], preview["dry_reason"])
	}
}

// The three gate conditions are reported separately, because "reason" names
// only the first one that failed and a caller needs to know which of them is
// theirs to fix. Here the account flag is the only thing missing.
func TestGetMySendStatus_ReportsEachConditionSeparately(t *testing.T) {
	store := newToolsTestStore(t)
	uid := seedHostedAccount(t, store, 4343, false)
	srv := &Server{AllowSend: true, Store: store}
	id := &auth.Identity{UserID: uid, Scopes: []string{"telegram:messages:send"}}

	out := parseSendStatus(t, callSendStatus(t, srv, id))
	for field, want := range map[string]bool{
		"can_send":          false,
		"server_allow_send": true,
		"has_send_scope":    true,
		"send_enabled":      false,
		"connected":         true,
	} {
		if out[field] != want {
			t.Errorf("%s = %v, want %v", field, out[field], want)
		}
	}
}

// A blocked scope must be visible as a scope problem, not misreported as an
// account-flag problem — the remedy differs (reconnect vs. flip a flag).
func TestGetMySendStatus_MissingScopeIsDistinctFromDisabledAccount(t *testing.T) {
	store := newToolsTestStore(t)
	uid := seedHostedAccount(t, store, 4444, true)
	srv := &Server{AllowSend: true, Store: store}
	id := &auth.Identity{UserID: uid, Scopes: []string{"telegram:messages:read"}}

	out := parseSendStatus(t, callSendStatus(t, srv, id))
	if out["has_send_scope"] != false {
		t.Errorf("has_send_scope = %v, want false", out["has_send_scope"])
	}
	if out["send_enabled"] != true {
		t.Errorf("send_enabled = %v, want true — the account flag is on; the scope is what is missing", out["send_enabled"])
	}
}

// When every condition holds, the tool says so and offers no reason.
func TestGetMySendStatus_OpenGate(t *testing.T) {
	store := newToolsTestStore(t)
	uid := seedHostedAccount(t, store, 4545, true)
	srv := &Server{AllowSend: true, Store: store}
	id := &auth.Identity{UserID: uid, Scopes: []string{"telegram:messages:send"}}

	out := parseSendStatus(t, callSendStatus(t, srv, id))
	if out["can_send"] != true {
		t.Fatalf("can_send = %v, want true", out["can_send"])
	}
	if r, ok := out["reason"]; ok && r != "" {
		t.Errorf("reason = %q, want empty when the gate is open", r)
	}
}

// A store that cannot be read must produce an error, not a confident
// "send_enabled: false". Flattening the failure would send the caller to turn
// on a flag that may already be on.
func TestGetMySendStatus_StoreFailureIsReportedNotFlattened(t *testing.T) {
	store := newToolsTestStore(t)
	uid := seedHostedAccount(t, store, 4646, true)
	if err := store.DB.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}
	srv := &Server{AllowSend: true, Store: store}
	id := &auth.Identity{UserID: uid, Scopes: []string{"telegram:messages:send"}}

	res := callSendStatus(t, srv, id)
	if !res.IsError {
		t.Fatalf("expected a tool error when the account row cannot be read, got: %s", contentText(res))
	}
}

func TestGetMySendStatus_RequiresAuthentication(t *testing.T) {
	srv := &Server{AllowSend: true, Store: newToolsTestStore(t)}
	if res := callSendStatus(t, srv, nil); !res.IsError {
		t.Fatalf("expected an error without an identity, got: %s", contentText(res))
	}
}

// The reviewer/demo identity is forced to preview-only ahead of every other
// check. The status must say so — and must still report the account flag
// truthfully, since a true send_enabled next to can_send=false is not a
// contradiction here: a different condition is what blocks the send.
func TestGetMySendStatus_DemoReviewerIsPreviewOnly(t *testing.T) {
	store := newToolsTestStore(t)
	uid := seedHostedAccount(t, store, 4848, true)
	srv := &Server{AllowSend: true, Store: store, DemoReviewerTGID: 4848}
	id := &auth.Identity{UserID: uid, TelegramID: 4848, Scopes: []string{"telegram:messages:send"}}

	out := parseSendStatus(t, callSendStatus(t, srv, id))
	if out["can_send"] != false {
		t.Errorf("can_send = %v, want false for the reviewer identity", out["can_send"])
	}
	if r, _ := out["reason"].(string); !strings.Contains(r, "preview-only") {
		t.Errorf("reason = %q, want the reviewer preview-only reason", r)
	}
	if out["send_enabled"] != true {
		t.Errorf("send_enabled = %v, want true — the flag is on; the reviewer rule is what blocks", out["send_enabled"])
	}
}

// Without a store the tool must say it could not verify the account flag,
// rather than reporting a confident "not enabled".
func TestGetMySendStatus_NoStoreSaysSoInsteadOfGuessing(t *testing.T) {
	srv := &Server{AllowSend: true}
	id := &auth.Identity{UserID: 1, Scopes: []string{"telegram:messages:send"}}

	out := parseSendStatus(t, callSendStatus(t, srv, id))
	if out["can_send"] != false {
		t.Errorf("can_send = %v, want false", out["can_send"])
	}
	if r, _ := out["reason"].(string); !strings.Contains(r, "store unavailable") {
		t.Errorf("reason = %q, want it to name the unavailable store", r)
	}
}

// An identity that has never linked a Telegram account is a normal case, not a
// failure: GetActiveAccount reports Connected=false for it. The tool must
// answer with the status, not with an error.
func TestGetMySendStatus_NoAccountYetIsAnswered(t *testing.T) {
	store := newToolsTestStore(t)
	uid, err := store.EnsureUserByTelegramID(context.Background(), 4949, "nobody", "No Account")
	if err != nil {
		t.Fatalf("EnsureUserByTelegramID: %v", err)
	}
	srv := &Server{AllowSend: true, Store: store}
	id := &auth.Identity{UserID: uid, Scopes: []string{"telegram:messages:send"}}

	out := parseSendStatus(t, callSendStatus(t, srv, id))
	if out["connected"] != false {
		t.Errorf("connected = %v, want false", out["connected"])
	}
	if out["can_send"] != false {
		t.Errorf("can_send = %v, want false", out["can_send"])
	}
}

// When an identity-level condition already settles the verdict, an unreadable
// account row must not suppress the answer — send_message would still report
// the real reason, and a status that returned an infrastructure error instead
// would diverge from it. The account fields are then omitted rather than
// reported as false, since "off" and "unknown" are different answers.
func TestGetMySendStatus_SettledVerdictSurvivesAnUnreadableAccountRow(t *testing.T) {
	store := newToolsTestStore(t)
	uid := seedHostedAccount(t, store, 5050, true)
	if err := store.DB.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}
	srv := &Server{AllowSend: true, Store: store}
	id := &auth.Identity{UserID: uid, Scopes: []string{"telegram:messages:read"}} // no send scope

	out := parseSendStatus(t, callSendStatus(t, srv, id))
	if out["can_send"] != false {
		t.Fatalf("can_send = %v, want false", out["can_send"])
	}
	if r, _ := out["reason"].(string); !strings.Contains(r, "telegram:messages:send scope") {
		t.Errorf("reason = %q, want the missing-scope reason rather than a database error", r)
	}
	if _, present := out["send_enabled"]; present {
		t.Errorf("send_enabled present (%v) despite an unreadable row — absent means unknown, false would be a claim", out["send_enabled"])
	}
	if _, present := out["connected"]; present {
		t.Errorf("connected present (%v) despite an unreadable row", out["connected"])
	}
}
