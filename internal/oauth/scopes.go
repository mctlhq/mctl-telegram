package oauth

// DCRNegotiableScopes is the scope set advertised to Dynamic Client
// Registration clients (ChatGPT/codex, claude.ai) via both RFC 8414
// authorization-server metadata and RFC 9728 protected-resource metadata.
// Intentionally excludes:
//   - "admin:users": implicit-privileged, granted by ResolveScopes based on
//     TG_LOGIN_ADMINS membership, never negotiable via DCR.
//   - "mctl": never actually granted by ResolveScopes anywhere in this
//     codebase; it leaked into the hand-built protected-resource JSON only,
//     causing DCR clients (observed live: codex) to request a scope the
//     authorization server silently drops.
//
// If you add a new telegram:*:read-shaped scope here, also add it to
// internal/workertoken's allowedReadOnlyScopes — that admin-mint allowlist
// is intentionally not derived from this list (this one still contains
// write scopes), so the two can drift silently if only one is updated.
var DCRNegotiableScopes = []string{
	"telegram:dialogs:read",
	"telegram:messages:read",
	"telegram:messages:send",
	"telegram:messages:pin",
}
