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

// identity.go is the production linking.AccountSource (#1318 slice C1).
// For tg it calls get_my_identity on the server's MCP endpoint with the
// access token that was just issued, and nothing else, so the linking flow
// can bind the account to the principal before storing anything (threat
// model T1 step 6, S1-L13). For alice it calls alice_get_my_identity the
// same way and takes the account id that mctl-alice shows on its account
// page; alice accounts are not Telegram identities, so that id is only
// shown on the confirm card and stored, never compared with the principal
// (S1-L14). A server with no identity source is an error, never an empty
// account.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"

	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/linking"
)

// identityTool is tg's self-identity tool.
const identityTool = "get_my_identity"

// aliceIdentityTool is mctl-alice's self-identity tool. It returns one
// field, the stable account id, and reads nothing from Yandex.
const aliceIdentityTool = "alice_get_my_identity"

// aliceAccountID is what an alice account id may look like: the ids
// mctl-alice issues are digits, hex, or letters with "_" and "-". The id is
// printed on the confirm card as plain text, so nothing that could read as
// a link, markup or a second line is accepted.
var aliceAccountID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

var (
	// ErrAccountSourceUnsupported: the server has no account source.
	ErrAccountSourceUnsupported = errors.New("pa connector: no account source for this server")
	// ErrAccountSourceConfig: the server has an account source, but it is
	// not configured (no MCP endpoint). A wiring fault, not a property of
	// the server.
	ErrAccountSourceConfig = errors.New("pa connector: account source not configured")
)

// IdentityAccounts implements linking.AccountSource over the catalog
// servers' MCP endpoints.
type IdentityAccounts struct {
	// Endpoints maps a server to its MCP endpoint.
	Endpoints map[connection.Server]MCPEndpoint
}

var _ linking.AccountSource = IdentityAccounts{}

// Account implements linking.AccountSource. The answer must be a
// successful tools/call result whose structuredContent carries the id: a
// positive integer telegram_id for tg, a well-formed account_id for alice.
// Anything else (an error result, a missing or malformed id, a malformed
// body) is an error, never a zero account.
func (s IdentityAccounts) Account(ctx context.Context, server connection.Server, accessToken connection.Secret) (linking.Account, error) {
	var tool string
	switch server {
	case connection.ServerTG:
		tool = identityTool
	case connection.ServerAlice:
		tool = aliceIdentityTool
	default:
		return linking.Account{}, fmt.Errorf("%w (%s)", ErrAccountSourceUnsupported, server)
	}
	ep := s.Endpoints[server]
	if ep == nil || ep.Server() != string(server) {
		return linking.Account{}, fmt.Errorf("%w: no MCP endpoint for %s", ErrAccountSourceConfig, server)
	}
	if accessToken.Empty() {
		return linking.Account{}, errors.New("pa connector: no access token for the identity call")
	}
	raw, err := ep.CallTool(ctx, accessToken, tool, json.RawMessage(`{}`))
	if err != nil {
		return linking.Account{}, fmt.Errorf("pa connector: %s: %w", tool, err)
	}
	if server == connection.ServerAlice {
		return parseAliceIdentity(raw)
	}
	return parseIdentity(raw)
}

// parseAliceIdentity reads an alice_get_my_identity tools/call result. The
// structured content must be an object whose account_id is a JSON string
// of the accepted form; the value is never echoed in an error.
func parseAliceIdentity(raw []byte) (linking.Account, error) {
	var res struct {
		IsError    *bool           `json:"isError"`
		Structured json.RawMessage `json:"structuredContent"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return linking.Account{}, fmt.Errorf("%w: %s result", ErrMCPProtocol, aliceIdentityTool)
	}
	if res.IsError != nil && *res.IsError {
		return linking.Account{}, fmt.Errorf("%w: %s returned an error result", ErrMCPProtocol, aliceIdentityTool)
	}
	var id struct {
		// Raw, so that only a JSON string is accepted: a number is not
		// turned into its digits.
		AccountID json.RawMessage `json:"account_id"`
	}
	if s := bytes.TrimSpace(res.Structured); len(s) == 0 || s[0] != '{' || json.Unmarshal(s, &id) != nil {
		return linking.Account{}, fmt.Errorf("%w: %s has no structured account_id", ErrMCPProtocol, aliceIdentityTool)
	}
	var account string
	if a := bytes.TrimSpace(id.AccountID); len(a) == 0 || a[0] != '"' || json.Unmarshal(a, &account) != nil {
		return linking.Account{}, fmt.Errorf("%w: %s has no structured account_id", ErrMCPProtocol, aliceIdentityTool)
	}
	if !aliceAccountID.MatchString(account) {
		return linking.Account{}, fmt.Errorf("%w: %s account_id is not a well-formed id", ErrMCPProtocol, aliceIdentityTool)
	}
	return linking.Account{ID: account}, nil
}

// parseIdentity reads a get_my_identity tools/call result.
func parseIdentity(raw []byte) (linking.Account, error) {
	var res struct {
		IsError    *bool           `json:"isError"`
		Structured json.RawMessage `json:"structuredContent"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return linking.Account{}, fmt.Errorf("%w: %s result", ErrMCPProtocol, identityTool)
	}
	if res.IsError != nil && *res.IsError {
		return linking.Account{}, fmt.Errorf("%w: %s returned an error result", ErrMCPProtocol, identityTool)
	}
	var id struct {
		// Raw, so that only a JSON integer literal is accepted: a quoted
		// string, a fraction or an exponent is refused by ParseInt.
		TelegramID  json.RawMessage `json:"telegram_id"`
		DisplayName string          `json:"display_name"`
	}
	if s := bytes.TrimSpace(res.Structured); len(s) == 0 || s[0] != '{' || json.Unmarshal(s, &id) != nil || len(id.TelegramID) == 0 {
		return linking.Account{}, fmt.Errorf("%w: %s has no structured telegram_id", ErrMCPProtocol, identityTool)
	}
	tg, err := strconv.ParseInt(string(id.TelegramID), 10, 64)
	if err != nil || tg <= 0 {
		return linking.Account{}, fmt.Errorf("%w: %s telegram_id is not a positive integer", ErrMCPProtocol, identityTool)
	}
	return linking.Account{
		ID:          "telegram:" + strconv.FormatInt(tg, 10),
		TelegramID:  tg,
		DisplayName: id.DisplayName,
	}, nil
}
