// Package mctltelegram exists to embed the assistant catalog together with
// the files its definitions point at. A definition's instructions.path may
// leave the assistants/ tree (the recruiter agent's points at
// deploy/agent-worker/system-prompt.txt, which the Mac mini worker's
// self-update also reads), and go:embed can only reach files below the
// embedding package, so the embedding package is the module root.
package mctltelegram

import "embed"

// Catalog holds assistants/ and every instructions file a definition
// references, at their repository paths. internal/assistant.LoadCatalog
// reads it.
//
//go:embed assistants deploy/agent-worker/system-prompt.txt
var Catalog embed.FS
