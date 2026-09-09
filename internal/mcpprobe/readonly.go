package mcpprobe

import (
	"encoding/json"
	"errors"
)

// errToolNotListed and errToolNotReadOnly are the two ways the guard refuses.
var (
	errToolNotListed   = errors.New("tool is not present in tools/list")
	errToolNotReadOnly = errors.New("tool is not annotated read-only")
)

// toolsListResult is the slice of tools/list this package reads. Everything
// else the server returned — schemas, descriptions, titles — is left
// unparsed, so it cannot reach a report even by accident.
type toolsListResult struct {
	Tools []struct {
		Name        string `json:"name"`
		Annotations *struct {
			ReadOnlyHint *bool `json:"readOnlyHint"`
		} `json:"annotations"`
	} `json:"tools"`
}

// parseTools reduces a tools/list result to names and read-only annotations.
func parseTools(raw json.RawMessage) ([]ToolInfo, error) {
	if len(raw) == 0 {
		return nil, errMalformedBody
	}
	var parsed toolsListResult
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, errMalformedBody
	}
	out := make([]ToolInfo, 0, len(parsed.Tools))
	for _, t := range parsed.Tools {
		info := ToolInfo{Name: t.Name}
		if t.Annotations != nil && t.Annotations.ReadOnlyHint != nil {
			info.ReadOnly = boolPtr(*t.Annotations.ReadOnlyHint)
		}
		out = append(out, info)
	}
	return out, nil
}

// selectReadOnlyTool decides whether the probe may invoke want.
//
// The guard is structural rather than a list of known-safe names: the only
// thing that authorizes a call is the server's own read-only annotation for
// that tool in that deployment. A tool the server did not annotate is
// treated as not read-only, because an absent annotation is not a promise.
func selectReadOnlyTool(tools []ToolInfo, want string) (ToolInfo, error) {
	for _, t := range tools {
		if t.Name != want {
			continue
		}
		if t.ReadOnly == nil || !*t.ReadOnly {
			return t, errToolNotReadOnly
		}
		return t, nil
	}
	return ToolInfo{Name: want}, errToolNotListed
}
