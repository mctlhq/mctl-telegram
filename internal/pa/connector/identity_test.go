package connector

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
)

// Alice's synthetic Telegram id.
const aliceTG = 100001

// S1-L13 production half: the tg account source calls get_my_identity with
// the new token and returns its structured telegram_id.
func TestS1L13_IdentityAccountsReadsTelegramID(t *testing.T) {
	f := &fakeServer{callResult: `{"content":[{"type":"text","text":"{}"}],"structuredContent":{"telegram_id":100001,"username":"alice","display_name":"Alice"}}`}
	src := IdentityAccounts{Endpoints: map[connection.Server]MCPEndpoint{connection.ServerTG: testEndpoint(t, f)}}
	acct, err := src.Account(context.Background(), connection.ServerTG, tok)
	if err != nil {
		t.Fatalf("Account: %v", err)
	}
	if acct.TelegramID != aliceTG || acct.ID != "telegram:100001" || acct.DisplayName != "Alice" {
		t.Fatalf("account = %+v", acct)
	}
	if len(f.calls) != 1 || !strings.Contains(f.calls[0], `"name":"get_my_identity"`) {
		t.Fatalf("tools/call params = %v", f.calls)
	}
	for _, b := range f.bearers {
		if b != "Bearer "+tok.Reveal() {
			t.Errorf("request with bearer %q, want the new token only", b)
		}
	}
}

// Anything but a successful result with a positive integer telegram_id
// is an error, never an account (I9).
func TestIdentityAccounts_FailsClosed(t *testing.T) {
	bad := map[string]string{
		"error result":       `{"isError":true,"content":[{"type":"text","text":"x"}],"structuredContent":{"telegram_id":100001}}`,
		"no structured":      `{"content":[{"type":"text","text":"{\"telegram_id\":100001}"}]}`,
		"null structured":    `{"structuredContent":null}`,
		"no telegram_id":     `{"structuredContent":{"username":"alice"}}`,
		"zero":               `{"structuredContent":{"telegram_id":0}}`,
		"negative":           `{"structuredContent":{"telegram_id":-100001}}`,
		"fraction":           `{"structuredContent":{"telegram_id":100001.5}}`,
		"string":             `{"structuredContent":{"telegram_id":"100001"}}`,
		"overflow":           `{"structuredContent":{"telegram_id":99999999999999999999}}`,
		"structured not obj": `{"structuredContent":[100001]}`,
		"result not object":  `[1]`,
	}
	for name, res := range bad {
		f := &fakeServer{callResult: res}
		src := IdentityAccounts{Endpoints: map[connection.Server]MCPEndpoint{connection.ServerTG: testEndpoint(t, f)}}
		if acct, err := src.Account(context.Background(), connection.ServerTG, tok); err == nil {
			t.Errorf("%s: account %+v, want an error", name, acct)
		}
	}
	// A transport refusal is an error too.
	f := &fakeServer{status: 401}
	src := IdentityAccounts{Endpoints: map[connection.Server]MCPEndpoint{connection.ServerTG: testEndpoint(t, f)}}
	if _, err := src.Account(context.Background(), connection.ServerTG, tok); !errors.Is(err, ErrMCPUnauthorized) {
		t.Errorf("401: %v", err)
	}
}

// alice has no account source, and an unconfigured or empty call is
// refused before anything is sent.
func TestIdentityAccounts_UnsupportedAndUnconfigured(t *testing.T) {
	f := &fakeServer{}
	ep := testEndpoint(t, f)
	src := IdentityAccounts{Endpoints: map[connection.Server]MCPEndpoint{connection.ServerTG: ep, connection.ServerAlice: ep}}
	if _, err := src.Account(context.Background(), connection.ServerAlice, tok); !errors.Is(err, ErrAccountSourceUnsupported) {
		t.Errorf("alice: %v", err)
	}
	// A missing tg endpoint is a configuration fault, never reported as
	// "tg is unsupported".
	if _, err := (IdentityAccounts{}).Account(context.Background(), connection.ServerTG, tok); !errors.Is(err, ErrAccountSourceConfig) || errors.Is(err, ErrAccountSourceUnsupported) {
		t.Errorf("no endpoint: %v", err)
	}
	// An endpoint wired under tg that serves another server is the same
	// fault: the identity call must never go to the wrong server.
	other := &Endpoint{server: "alice", url: ep.url, client: ep.client}
	wrong := IdentityAccounts{Endpoints: map[connection.Server]MCPEndpoint{connection.ServerTG: other}}
	if _, err := wrong.Account(context.Background(), connection.ServerTG, tok); !errors.Is(err, ErrAccountSourceConfig) {
		t.Errorf("endpoint for another server: %v", err)
	}
	if _, err := src.Account(context.Background(), connection.ServerTG, connection.Secret{}); err == nil {
		t.Error("empty token accepted")
	}
	if len(f.methods) != 0 {
		t.Fatalf("requests sent: %v", f.methods)
	}
}
