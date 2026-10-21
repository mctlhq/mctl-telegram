package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/toolprofile"
)

// Restricted tool profiles (docs/design/core-profiles.md). The OAuth server
// stamps the profile bound to a client into its access token; this file
// applies it on top of toolScopes:
//
//   - toolAllowed requires both the scope check and the profile, so
//     tools/list and tools/call (through mcpserver.WithToolFilter) only ever
//     see the intersection;
//   - scopeToolFilter shows a profiled caller each tool's schema with the
//     profile's argument rules applied;
//   - profileArgGuard enforces those rules on tools/call, because a filter
//     changes only what is listed.
//
// A refusal by the profile is audited as ReasonProfileDenied, distinct from
// ReasonScopeDenied, so the two policies can be told apart afterwards.

// profileOf reports the profile restricting id. restricted is false when the
// credential carries no profile, which keeps the scope surface unchanged.
// A profile name this build does not know (a token minted by a newer
// release, read by an older one after a rollback) is restricted with ok
// false: such a caller is allowed nothing, never everything.
func profileOf(id *auth.Identity) (p toolprofile.Profile, restricted, ok bool) {
	if id == nil || id.Profile == "" {
		return toolprofile.Profile{}, false, true
	}
	p, ok = toolprofile.Lookup(id.Profile)
	return p, true, ok
}

// profileAllows reports whether id's profile, if any, lets it see and call
// the named tool. A caller without a profile is allowed everything except
// the profile-only tools (toolprofile.ProfileOnly). It says nothing about
// scopes; toolAllowed combines both.
func profileAllows(id *auth.Identity, name string) bool {
	p, restricted, ok := profileOf(id)
	if !restricted {
		return !toolprofile.ProfileOnly(name)
	}
	if !ok {
		return false
	}
	_, listed := p.Tools[name]
	return listed
}

// profileDeniedMessage is the refusal text for a tool the caller's scopes
// allow but its profile hides. It names the profile, never the client.
func profileDeniedMessage(id *auth.Identity, name string) string {
	if id == nil {
		return fmt.Sprintf("tool %s is not available", name)
	}
	if id.Profile == "" {
		return fmt.Sprintf("tool %s is not available: it is offered only to connections with a tool profile that lists it", name)
	}
	if _, _, ok := profileOf(id); !ok {
		return fmt.Sprintf("tool %s is not available: this connection's tool profile %q is not recognised by the server", name, id.Profile)
	}
	return fmt.Sprintf("tool %s is not available under this connection's tool profile %q", name, id.Profile)
}

// applyProfileSchema returns t as a profiled caller is shown it: required
// arguments marked required, forbidden arguments removed, the limit bound
// stated, and one line at the top of the description that says so. t itself
// is never modified, so the unfiltered surface (descriptor snapshot, portal
// allowlist) is unaffected. A zero Rule returns t unchanged.
func applyProfileSchema(t mcplib.Tool, profile string, r toolprofile.Rule) mcplib.Tool {
	if len(r.Required) == 0 && len(r.Forbidden) == 0 && r.LimitMax == 0 && r.LimitDefault == 0 {
		return t
	}
	out := t
	out.InputSchema.Properties = maps.Clone(t.InputSchema.Properties)
	out.InputSchema.Required = slices.Clone(t.InputSchema.Required)
	for _, a := range r.Forbidden {
		delete(out.InputSchema.Properties, a)
		out.InputSchema.Required = slices.DeleteFunc(out.InputSchema.Required, func(s string) bool { return s == a })
	}
	for _, a := range r.Required {
		if !slices.Contains(out.InputSchema.Required, a) {
			out.InputSchema.Required = append(out.InputSchema.Required, a)
		}
	}
	if r.LimitMax > 0 || r.LimitDefault > 0 {
		if prop, ok := out.InputSchema.Properties["limit"].(map[string]any); ok {
			prop = maps.Clone(prop)
			prop["description"] = limitText(prop["description"], r)
			if r.LimitMax > 0 {
				prop["maximum"] = r.LimitMax
			}
			if r.LimitDefault > 0 {
				prop["default"] = r.LimitDefault
			}
			out.InputSchema.Properties["limit"] = prop
		}
	}
	out.Description = profileNote(profile, r) + "\n\n" + t.Description
	return out
}

// limitPhrase states the profile's limit bound, e.g. "default 20, max 50".
func limitPhrase(r toolprofile.Rule) string {
	switch {
	case r.LimitDefault > 0 && r.LimitMax > 0:
		return fmt.Sprintf("default %d, max %d", r.LimitDefault, r.LimitMax)
	case r.LimitMax > 0:
		return fmt.Sprintf("max %d", r.LimitMax)
	default:
		return fmt.Sprintf("default %d", r.LimitDefault)
	}
}

// limitText rewrites a limit property's description for the profile. The
// tool's own noun ("Max messages to return", "Maximum number of results")
// is kept and its parenthesised default/max, if any, replaced.
func limitText(orig any, r toolprofile.Rule) string {
	noun, _ := orig.(string)
	if i := strings.Index(noun, "("); i >= 0 {
		noun = noun[:i]
	}
	noun = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(noun), "."))
	if noun == "" {
		noun = "Max results to return"
	}
	return fmt.Sprintf("%s (%s).", noun, limitPhrase(r))
}

// profileNote is the line a profiled caller reads first. The tool's own
// description below it still describes the unrestricted tool, so this line
// is what overrides it.
func profileNote(profile string, r toolprofile.Rule) string {
	var parts []string
	if len(r.Required) > 0 {
		parts = append(parts, strings.Join(r.Required, ", ")+" required")
	}
	if r.LimitMax > 0 || r.LimitDefault > 0 {
		parts = append(parts, "limit "+limitPhrase(r))
	}
	for _, a := range r.Forbidden {
		parts = append(parts, a+" unavailable")
	}
	return fmt.Sprintf("Restricted by this connection's tool profile %q: %s. This overrides the description below.", profile, strings.Join(parts, "; "))
}

// profileArgGuard is the tools/call half of the profile: it refuses a call
// whose arguments break the caller's profile rule for the tool, and fills
// in the profile's default limit. It runs inside recordToolCall, so a
// refusal is recorded like any handler refusal, with ReasonProfileDenied.
// A caller without a profile passes through untouched.
func (s *Server) profileArgGuard(next mcpserver.ToolHandlerFunc) mcpserver.ToolHandlerFunc {
	return func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		id := auth.From(ctx)
		p, restricted, ok := profileOf(id)
		if !restricted {
			return next(ctx, req)
		}
		name := req.Params.Name
		rule, listed := p.Tools[name]
		if !ok || !listed {
			// The filter already refuses these before any handler; this is
			// the belt to its braces.
			hintReason(ctx, ReasonProfileDenied)
			return mcplib.NewToolResultError(profileDeniedMessage(id, name)), nil
		}
		args, err := checkProfileArgs(req.GetArguments(), rule)
		if err != nil {
			hintReason(ctx, ReasonProfileDenied)
			return mcplib.NewToolResultError(fmt.Sprintf("%s: %v (tool profile %q)", name, err, id.Profile)), nil
		}
		req.Params.Arguments = args
		return next(ctx, req)
	}
}

// checkProfileArgs applies r to a tools/call argument map. It returns a copy
// with the profile's default limit filled in, or an error naming the broken
// rule. The input map is never modified.
func checkProfileArgs(in map[string]any, r toolprofile.Rule) (map[string]any, error) {
	args := maps.Clone(in)
	if args == nil {
		args = map[string]any{}
	}
	for _, a := range r.Required {
		v, ok := args[a].(string)
		if !ok || strings.TrimSpace(v) == "" {
			return nil, fmt.Errorf("%s is required", a)
		}
	}
	for _, a := range r.Forbidden {
		if v, set := args[a]; set && !isZeroArg(v) {
			return nil, fmt.Errorf("%s is not available", a)
		}
	}
	if r.LimitMax == 0 && r.LimitDefault == 0 {
		return args, nil
	}
	raw, set := args["limit"]
	if !set || raw == nil {
		if r.LimitDefault > 0 {
			args["limit"] = float64(r.LimitDefault)
		}
		return args, nil
	}
	n, ok := numberArg(raw)
	if !ok {
		// The handlers fall back to their own (larger) default for a value
		// they cannot read, so an unreadable limit is refused here rather
		// than passed through.
		return nil, fmt.Errorf("limit must be a number")
	}
	if n < 1 {
		// The handlers read a limit below 1 as "use my own default"
		// (clampLimit), which is larger than the profile's and may exceed
		// its max. Under a profile it means the profile's default instead,
		// and without one it is refused.
		if r.LimitDefault > 0 {
			args["limit"] = float64(r.LimitDefault)
			return args, nil
		}
		return nil, fmt.Errorf("limit must be at least 1")
	}
	if r.LimitMax > 0 && n > float64(r.LimitMax) {
		return nil, fmt.Errorf("limit %v exceeds the maximum of %d", raw, r.LimitMax)
	}
	return args, nil
}

// numberArg reads a JSON number the way intArg does, and also a
// json.Number, reporting whether the value was numeric at all.
func numberArg(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}

// isZeroArg reports whether a forbidden argument was sent with its "off"
// value: false, null, 0 or "". fetch_media=false is what a careful client
// sends and must not be refused.
func isZeroArg(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case bool:
		return !x
	case string:
		return x == ""
	case float64:
		return x == 0
	case int:
		return x == 0
	case int64:
		return x == 0
	}
	return false
}
