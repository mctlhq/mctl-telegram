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
//
// account:manage (issue-483) is the odd one out: it is not a telegram:*
// scope at all, and it is DELIBERATELY never added to
// internal/workertoken's allowedReadOnlyScopes or allowedLocalBridgeScopes
// -- the two allowlists that bound everything a worker or device credential
// can ever be minted with. It gates the owner-only consent/revocation tools
// (set_send_consent, revoke_local_bridge_device): a session negotiates it
// like any other DCR scope, but no worker token and no self-service device
// credential ever carries it, so a stolen device credential can never
// re-grant itself send consent or revoke its owner's other devices. See
// internal/workertoken/tokenhandler.go's allowlist comments for the other
// half of this contract.
var DCRNegotiableScopes = []string{
	"telegram:dialogs:read",
	"telegram:messages:read",
	"telegram:messages:send",
	"telegram:messages:pin",
	"account:manage",
}
