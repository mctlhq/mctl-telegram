// Package assistants holds the catalog of installable Telegram assistants
// and the JSON Schemas that define their format (docs/assistants/spec.md).
// Each assistant lives in its own directory as assistant.yaml.
package assistants

import "embed"

// Schemas holds schemas/assistant.schema.json and
// schemas/assistant-install.schema.json.
//
//go:embed schemas/*.json
var Schemas embed.FS
