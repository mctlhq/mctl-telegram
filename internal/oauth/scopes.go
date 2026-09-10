package oauth

import "strings"

// DCRNegotiableScopes is the scope set advertised to Dynamic Client
// Registration clients (ChatGPT/codex, claude.ai) via both RFC 8414
// authorization-server metadata and RFC 9728 protected-resource metadata.
// Intentionally excludes:
//   - "admin:users": implicit-privileged, granted by ResolveScopes based on
//     TG_LOGIN_ADMINS membership, never negotiable via DCR.
//   - "admin:users:read": same, for TG_LOGIN_LOOKUP_ADMINS membership. It is
//     the read-only subset of admin:users, accepted only by
//     list_telegram_identities and get_user_audit_log.
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

// narrowGrant bounds an identity's entitled scopes to what the client asked
// for. It is the authorization_code half of the least-privilege rule that
// boundRefreshGrant already enforces on refresh: a grant may be narrower than
// what the identity could hold, never wider.
//
// Before this existed, the token endpoint minted ResolveScopes' full set and
// logged the requested scope for diagnostics only. Measured on 2026-09-10
// (#607): a client that asked for telegram:dialogs:read and
// telegram:messages:read received send, pin and account:manage as well,
// for a client-tier principal as much as for an admin. A gateway whose whole
// purpose is to present a narrower surface than the upstream was then
// holding a token that could send.
//
// Two deliberate asymmetries:
//
//   - An empty request keeps today's behaviour and grants the full entitled
//     set. RFC 6749 §3.3 lets the server apply a default when scope is
//     omitted, and existing clients that never send scope must keep working.
//   - Scopes outside DCRNegotiableScopes are not negotiable and so are not
//     subject to the request: admin:users and admin:users:read are granted
//     by membership, cannot be asked for, and stay. The portal-side
//     allowlist is the fence for those; this function is the fence for the
//     five scopes a client can actually name.
//
// A requested scope the identity is not entitled to is dropped silently, as
// it always was; the caller logs requested-vs-granted for the operator.
func narrowGrant(entitled []string, requested string) []string {
	fields := strings.Fields(requested)
	if len(fields) == 0 {
		return entitled
	}
	asked := make(map[string]struct{}, len(fields))
	for _, s := range fields {
		asked[s] = struct{}{}
	}
	negotiable := make(map[string]struct{}, len(DCRNegotiableScopes))
	for _, s := range DCRNegotiableScopes {
		negotiable[s] = struct{}{}
	}
	out := make([]string, 0, len(entitled))
	for _, s := range entitled {
		if _, isNegotiable := negotiable[s]; !isNegotiable {
			out = append(out, s)
			continue
		}
		if _, ok := asked[s]; ok {
			out = append(out, s)
		}
	}
	return out
}
