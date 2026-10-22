package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	mcplib "github.com/mark3labs/mcp-go/mcp"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/productupdate"
	"github.com/mctlhq/mctl-telegram/internal/toolprofile"
)

// DescriptorSurface is the configuration docs/tool-descriptors.json
// enumerates: every tool, with the MCP Apps tools and links, so a tool that
// only exists behind a flag is still part of the release evidence.
var DescriptorSurface = productupdate.Surface{AppsEnabled: true, ToolFilter: "all"}

// ToolDescriptors snapshots the descriptor of every tool newMCPServer
// registers, as tools/list serves it (issue-440). It needs no database and no
// network: it is the same enumeration portal_allowlist_test.go relies on.
func ToolDescriptors() (productupdate.Snapshot, error) {
	return (&Server{
		ToolFilter:  DescriptorSurface.ToolFilter,
		AppsEnabled: DescriptorSurface.AppsEnabled,
	}).descriptors()
}

// descriptors enumerates this server's own configuration and labels the
// snapshot with that configuration, so the label cannot disagree with what
// was enumerated. Tests call it directly to prove the snapshot does not
// depend on fields such as Version.
func (s *Server) descriptors() (productupdate.Snapshot, error) {
	registered := s.newMCPServer().ListTools()
	descriptors := make(map[string][]byte, len(registered))
	for name, tool := range registered {
		raw, err := json.Marshal(tool.Tool)
		if err != nil {
			return productupdate.Snapshot{}, fmt.Errorf("marshal tool %s: %w", name, err)
		}
		descriptors[name] = raw
	}
	// One spelling per surface: toolPassesFilter treats "" as "all", and so
	// does the config default, so the label does too.
	filter := s.ToolFilter
	if filter == "" {
		filter = "all"
	}
	return productupdate.NewSnapshot(
		productupdate.Surface{AppsEnabled: s.AppsEnabled, ToolFilter: filter}, descriptors)
}

// ProfileDescriptorsFile is where the snapshot of one tool profile's surface
// is committed, next to the full docs/tool-descriptors.json.
func ProfileDescriptorsFile(profile string) string {
	return "docs/tool-descriptors." + profile + ".json"
}

// ProfileToolDescriptors snapshots the surface a caller bound to the named
// tool profile is shown by tools/list: the full registry passed through the
// same scopeToolFilter a request runs, for an identity carrying the profile
// and every scope any tool needs. So the snapshot is the profile's view, not
// a narrower view some scope set happens to give.
func ProfileToolDescriptors(profile string) (productupdate.Snapshot, error) {
	if _, ok := toolprofile.Lookup(profile); !ok {
		return productupdate.Snapshot{}, fmt.Errorf("unknown tool profile %q", profile)
	}
	s := &Server{ToolFilter: DescriptorSurface.ToolFilter, AppsEnabled: DescriptorSurface.AppsEnabled}
	registered := s.newMCPServer().ListTools()
	tools := make([]mcplib.Tool, 0, len(registered))
	for _, st := range registered {
		tools = append(tools, st.Tool)
	}
	id := &auth.Identity{UserID: 1, Profile: profile, Scopes: everyToolScope()}
	listed := scopeToolFilter(auth.With(context.Background(), id), tools)
	descriptors := make(map[string][]byte, len(listed))
	for _, t := range listed {
		raw, err := json.Marshal(t)
		if err != nil {
			return productupdate.Snapshot{}, fmt.Errorf("marshal tool %s: %w", t.Name, err)
		}
		descriptors[t.Name] = raw
	}
	return productupdate.NewSnapshot(productupdate.Surface{
		AppsEnabled: DescriptorSurface.AppsEnabled,
		ToolFilter:  DescriptorSurface.ToolFilter,
		Profile:     profile,
	}, descriptors)
}

// everyToolScope is the union of the scopes toolScopes names.
func everyToolScope() []string {
	var all []string
	for _, scopes := range toolScopes {
		for _, sc := range scopes {
			if !slices.Contains(all, sc) {
				all = append(all, sc)
			}
		}
	}
	slices.Sort(all)
	return all
}
