package agentworker

import (
	"encoding/json"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

// jsonResult and the arg helpers below duplicate internal/mcp's private
// copies rather than importing them — this codebase's established
// convention (see internal/agentapi/json.go's writeJSONError comment) is
// that each HTTP/tool-facing package owns its own copy of these tiny
// helpers so they can drift independently without an extra cross-import.
func jsonResult(v any) (*mcplib.CallToolResult, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return mcplib.NewToolResultError("encode: " + err.Error()), nil
	}
	res := mcplib.NewToolResultText(string(b))
	res.StructuredContent = v
	return res, nil
}

func stringArg(args map[string]any, key, def string) string {
	if v, ok := args[key].(string); ok && v != "" {
		return v
	}
	return def
}

func intArg(args map[string]any, key string, def int) int {
	switch v := args[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	}
	return def
}
