package connection

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// The write scopes (#1320 slice P2-S14c; owner decision 2026-11-21: writes
// use a separate alice connection with iot:control and iot:view, and the
// quasar scope is not used).
//
// A connection made while PA_WRITES_ENABLED is on asks for the read set
// plus the server's write scopes (WriteRequestScope). What it then holds is
// what the token response reported (Connection.GrantedScope), never what it
// asked for. A write tool is offered, shown on a card, granted a standing
// permission or sent only on a connection whose granted scope holds the
// tool's scope (WriteScopes.Holds).
//
// These tables are server configuration: compiled in, checked when the
// process starts (CheckScopeConfig) and never read from a model's or a
// user's text.

// writeScopes is what a write connection asks for on top of allowedScopes.
// A server without an entry has no write scope: its connections are never
// asked for one and none of its tools is a write this build can send.
var writeScopes = map[Server][]string{
	ServerAlice: {"iot:control"},
}

// writeToolScopes names, per server, the scope each write tool needs. The
// alice names and scopes are the ones the server enforces (mctl-alice
// TOOL_SCOPES). alice_send_command and alice_say_phrase need the quasar
// scope, which is not used, so they are not here and no connection ever
// holds them.
var writeToolScopes = map[Server]map[string]string{
	ServerAlice: {
		"alice_control_device":   "iot:control",
		"alice_control_room":     "iot:control",
		"alice_media_control":    "iot:control",
		"alice_play_music":       "iot:control",
		"alice_set_light":        "iot:control",
		"alice_set_volume":       "iot:control",
		"alice_trigger_scenario": "iot:control",
	},
}

// ErrScopeConfig reports scope tables this build must not start with.
var ErrScopeConfig = errors.New("pa connection: invalid scope configuration")

// WriteRequestScope is the canonical scope a write connection to server
// asks for: its read set and its write scopes. ok is false for a server
// that has no write scope.
func WriteRequestScope(server Server) (string, bool) {
	extra, has := writeScopes[server]
	read, ok := AllowedScopes(server)
	if !has || !ok || len(extra) == 0 {
		return "", false
	}
	all := slices.Concat(read, extra)
	slices.Sort(all)
	return strings.Join(slices.Compact(all), " "), true
}

// RequestScope is the canonical scope a new connection to server asks for:
// WriteRequestScope when writes is set and the server has one, else the
// read set.
func RequestScope(server Server, writes bool) (string, bool) {
	if writes {
		if s, ok := WriteRequestScope(server); ok {
			return s, true
		}
	}
	return CanonicalScope(server)
}

// ScopeAccepted reports whether c's granted scope is one this build
// accepts for its server: the read set, or the write set when that is what
// c asked for. Anything else, an unparseable or empty value included, is
// not; a connection that fails this is used for nothing.
func ScopeAccepted(c Connection) bool {
	read, ok := CanonicalScope(c.Server)
	if !ok || c.GrantedScope == "" {
		return false
	}
	if c.GrantedScope == read {
		return true
	}
	wide, ok := WriteRequestScope(c.Server)
	return ok && c.RequestedScope == wide && c.GrantedScope == wide
}

// WriteScopes says which scope each write tool needs. The zero value knows
// no tool and holds nothing.
type WriteScopes struct {
	tools map[Server]map[string]string
}

// DefaultWriteScopes is the compiled table (writeToolScopes).
func DefaultWriteScopes() WriteScopes {
	out := map[Server]map[string]string{}
	for server, tools := range writeToolScopes {
		out[server] = map[string]string{}
		for tool, scope := range tools {
			out[server][tool] = scope
		}
	}
	return WriteScopes{tools: out}
}

// NewWriteScopes builds a table from tools (server, tool, scope). It
// refuses an unknown server, an empty tool name and a scope that is not one
// well-formed scope token. Tests of the write path on a server that has no
// write scope use it; production uses DefaultWriteScopes.
func NewWriteScopes(tools map[Server]map[string]string) (WriteScopes, error) {
	out := map[Server]map[string]string{}
	for server, byTool := range tools {
		if !server.Valid() {
			return WriteScopes{}, fmt.Errorf("%w: unknown server", ErrScopeConfig)
		}
		out[server] = map[string]string{}
		for tool, scope := range byTool {
			if tool == "" || !scopeToken(scope) {
				return WriteScopes{}, fmt.Errorf("%w: tool or scope", ErrScopeConfig)
			}
			out[server][tool] = scope
		}
	}
	return WriteScopes{tools: out}, nil
}

// Needs returns the scope tool needs on server; ok is false for a tool the
// table does not know, which is then a write nothing holds.
func (w WriteScopes) Needs(server Server, tool string) (string, bool) {
	scope, ok := w.tools[server][tool]
	return scope, ok && scope != ""
}

// Holds reports whether c holds the scope tool needs: the table knows the
// tool, c's granted scope is one this build accepts (ScopeAccepted), parses
// strictly and contains that scope. Every other case is false: an unknown
// tool, a view-only connection, a granted scope that cannot be read.
func (w WriteScopes) Holds(c Connection, tool string) bool {
	need, ok := w.Needs(c.Server, tool)
	if !ok || !ScopeAccepted(c) {
		return false
	}
	got, err := parseScope(c.GrantedScope)
	if err != nil {
		return false
	}
	return slices.Contains(got, need)
}

// HoldsAny reports whether c holds the scope of at least one tool the table
// names for its server: whether c is a connection writes can use at all.
func (w WriteScopes) HoldsAny(c Connection) bool {
	for tool := range w.tools[c.Server] {
		if w.Holds(c, tool) {
			return true
		}
	}
	return false
}

// Tools returns the write tools the table names for server, sorted.
func (w WriteScopes) Tools(server Server) []string {
	out := make([]string, 0, len(w.tools[server]))
	for tool := range w.tools[server] {
		out = append(out, tool)
	}
	slices.Sort(out)
	return out
}

func scopeToken(s string) bool {
	got, err := parseScope(s)
	return err == nil && len(got) == 1
}

// CheckScopeConfig checks the compiled scope tables, once, when the
// process starts: every scope is one well-formed token, a write scope is
// not also a read scope, every write tool names a write scope of its own
// server, and every write scope is needed by some tool. A build that fails
// it must not serve the PA.
func CheckScopeConfig() error {
	for server, read := range allowedScopes {
		if !server.Valid() || len(read) == 0 {
			return fmt.Errorf("%w: read scopes of %q", ErrScopeConfig, server)
		}
		for _, s := range read {
			if !scopeToken(s) {
				return fmt.Errorf("%w: read scope of %q", ErrScopeConfig, server)
			}
		}
	}
	for server, extra := range writeScopes {
		read, ok := allowedScopes[server]
		if !ok || len(extra) == 0 {
			return fmt.Errorf("%w: write scopes of %q", ErrScopeConfig, server)
		}
		used := map[string]bool{}
		for _, scope := range writeToolScopes[server] {
			used[scope] = true
		}
		for _, s := range extra {
			if !scopeToken(s) || slices.Contains(read, s) || !used[s] {
				return fmt.Errorf("%w: write scope of %q", ErrScopeConfig, server)
			}
		}
	}
	for server, tools := range writeToolScopes {
		for tool, scope := range tools {
			if tool == "" || !slices.Contains(writeScopes[server], scope) {
				return fmt.Errorf("%w: write tool of %q", ErrScopeConfig, server)
			}
		}
	}
	return nil
}
