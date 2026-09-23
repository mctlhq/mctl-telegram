package mcp

import (
	"encoding/json"
	"fmt"

	"github.com/mctlhq/mctl-telegram/internal/productupdate"
)

// DescriptorSurface is the configuration docs/tool-descriptors.json
// enumerates: every tool, with the MCP Apps tools and links, so a tool that
// only exists behind a flag is still part of the release evidence.
var DescriptorSurface = productupdate.Surface{AppsEnabled: true, ToolFilter: "all"}

// ToolDescriptors snapshots the descriptor of every tool newMCPServer
// registers, as tools/list serves it (issue-440). It needs no database and no
// network: it is the same enumeration portal_allowlist_test.go relies on.
func ToolDescriptors() (productupdate.Snapshot, error) {
	return (&Server{ToolFilter: "", AppsEnabled: DescriptorSurface.AppsEnabled}).descriptorsForTest()
}

// descriptorsForTest enumerates this server's own configuration; tests use it
// to prove the snapshot does not depend on fields such as Version.
func (s *Server) descriptorsForTest() (productupdate.Snapshot, error) {
	registered := s.newMCPServer().ListTools()
	descriptors := make(map[string][]byte, len(registered))
	for name, tool := range registered {
		raw, err := json.Marshal(tool.Tool)
		if err != nil {
			return productupdate.Snapshot{}, fmt.Errorf("marshal tool %s: %w", name, err)
		}
		descriptors[name] = raw
	}
	return productupdate.NewSnapshot(DescriptorSurface, descriptors)
}
