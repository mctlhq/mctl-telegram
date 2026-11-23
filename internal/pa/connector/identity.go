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
// model T1 step 6, S1-L13). alice has no pinned identity source yet and
// stays off; asking for it is an error, never an empty account.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/linking"
)

// identityTool is tg's self-identity tool.
const identityTool = "get_my_identity"

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
	// Endpoints maps a server to its MCP endpoint. Only tg is used.
	Endpoints map[connection.Server]MCPEndpoint
}

var _ linking.AccountSource = IdentityAccounts{}

// Account implements linking.AccountSource. For tg the answer must be a
// successful tools/call result whose structuredContent carries a positive
// integer telegram_id; anything else (an error result, a missing or
// non-integer id, a malformed body) is an error, never a zero account.
func (s IdentityAccounts) Account(ctx context.Context, server connection.Server, accessToken connection.Secret) (linking.Account, error) {
	if server != connection.ServerTG {
		return linking.Account{}, fmt.Errorf("%w (%s)", ErrAccountSourceUnsupported, server)
	}
	ep := s.Endpoints[server]
	if ep == nil || ep.Server() != string(server) {
		return linking.Account{}, fmt.Errorf("%w: no MCP endpoint for %s", ErrAccountSourceConfig, server)
	}
	if accessToken.Empty() {
		return linking.Account{}, errors.New("pa connector: no access token for the identity call")
	}
	raw, err := ep.CallTool(ctx, accessToken, identityTool, json.RawMessage(`{}`))
	if err != nil {
		return linking.Account{}, fmt.Errorf("pa connector: %s: %w", identityTool, err)
	}
	return parseIdentity(raw)
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
