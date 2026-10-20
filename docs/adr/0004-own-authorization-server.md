# 0004. Its own OAuth 2.1 authorization server, brokering Telegram sign-in

Status: Accepted

## Context

MCP clients (ChatGPT, Claude, Cursor, agent platforms) authenticate with
OAuth: they discover an authorization server, register or identify
themselves, and send the user through a browser sign-in. The identity that
matters here is the user's Telegram account, and Telegram offers an OpenID
Connect provider for it.

Early versions borrowed tokens from `api.mctl.ai` through a shared HMAC
secret (`AUTH_MODE=shared-hmac`). That coupled two services through one
secret, and `api.mctl.ai` has no notion of a Telegram user id.

## Decision

- mctl-telegram is its own issuer (`internal/oauth/server.go`). To MCP
  clients it is an OAuth 2.1 authorization server; to Telegram it is an
  OpenID Connect relying party. `/oauth/authorize` sends the browser to
  `oauth.telegram.org`, the callback validates the returned `id_token`
  against Telegram's keys, and the service issues its own tokens
  (`internal/auth/telegramoidc`, `internal/auth/localjwt`; 0.16.0).
- Authorization code with PKCE `S256` only; any other method is refused.
- Clients register through Dynamic Client Registration (RFC 7591). The
  redirect hosts a registration may claim are on an allowlist
  (`OAUTH_ALLOWED_IMPLICIT_HOSTS`); custom URL schemes are never accepted.
- Discovery per RFC 8414 and RFC 9728 (`/.well-known/oauth-protected-resource`,
  0.46.0, #345), revocation per RFC 7009 (0.52.0).
- Refresh tokens are opaque, stored hashed, and rotated on every use.
  Presenting an already-rotated token revokes its whole family (0.15.0, #51).
- Client ID Metadata Documents (CIMD) next to DCR (0.81.0, #773): a
  platform's `client_id` is an https URL on its own domain, and its redirect
  URIs come from the document at that URL. Only allowlisted hosts are
  fetched, and `private_key_jwt` client authentication is supported. The
  resolver was ported from mctl-api, which runs the same contract.
- The shared-HMAC modes remain for compatibility, behind explicit
  configuration (`AUTH_MODE`, `AUTH_ALLOW_SHARED_HMAC_LEGACY`).

## Consequences

- The token carries the Telegram user id directly. There is no mapping
  table to another identity system, and nothing outside this service can
  mint a token for it.
- The service owns a security-critical component: an authorization server
  with its own registration, rotation and revocation rules. That is more
  code to get right, and the reason `SECURITY.md` documents its invariants.
- Pending authorizations and registrations are held in memory, which is
  one reason the service runs as a single replica
  ([0005](0005-session-pool-and-sticky-routing.md)).
- Access tokens are not individually revocable within their lifetime
  (default one hour); revocation acts on refresh tokens.
- CIMD lets a platform vouch for its own callbacks instead of the operator
  maintaining a host list per platform, which is what an agent platform
  integrating many users needs.

## Alternatives

- **Keep borrowing tokens from api.mctl.ai.** Rejected for the coupling and
  the missing Telegram identity.
- **A general identity provider (for example ZITADEL) in front.** Would
  add a second sign-in for the user and a mapping from that identity to a
  Telegram account, for no gain: Telegram already is the identity.
