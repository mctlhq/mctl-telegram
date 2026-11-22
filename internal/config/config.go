package config

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/canaryguard"
	"github.com/mctlhq/mctl-telegram/internal/oauth/cimd"
	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
	"github.com/mctlhq/mctl-telegram/internal/toolprofile"
)

// maxOAUTHAccessTokenTTL is the ceiling on OAUTH_ACCESS_TOKEN_TTL. 24h is
// already far longer than an access token needs to live given that clients
// renew silently with the refresh_token grant; it is set here only to leave
// room for a deployment that wants a whole working day without a renewal,
// not because any value near it is a good idea. Refresh tokens are the
// long-lived half of the pair and are bounded separately by
// OAUTH_REFRESH_TOKEN_TTL.
const maxOAUTHAccessTokenTTL = 24 * time.Hour

// The three issue #705 media knobs share their defaults between the envInt*
// call that resolves them and the clamp branch that falls back to the same
// value on a negative (or, for BULK_MEDIA_BYTE_CAP, zero) input; hoisted here
// so the literal is not repeated. A typo therefore always lands on the bounded
// default, never on an unbounded meaning: only an explicit 0 opts out of
// MEDIA_TEXT_INLINE_CAP_BYTES or MEDIA_MAX_CONCURRENT.
const (
	defaultBulkMediaByteCap        = 8388608
	defaultMediaTextInlineCapBytes = 1048576
	defaultMediaMaxConcurrent      = 2
)

// MinHumanInputPollInterval is the floor for HUMAN_INPUT_POLL_INTERVAL.
const MinHumanInputPollInterval = 10 * time.Second

type Config struct {
	Addr          string
	PublicBaseURL string
	MCPPath       string
	// AllowedOrigins is the Origin-header allowlist for the /mcp endpoint
	// (DNS-rebinding protection). Requests with no Origin header are always
	// allowed — server-to-server MCP clients (claude.ai, MCP Inspector, curl)
	// send none, and an over-strict check would break them. A present Origin
	// must match one of these entries (scheme://host[:port]) or the request is
	// rejected with 403. Set via ALLOWED_ORIGINS (comma-separated); defaults to
	// the PUBLIC_BASE_URL origin.
	AllowedOrigins []string
	AuthMode       string
	AuthRequired   bool
	OperatorLogin  string
	// Environment names the deployment tier this process is running in
	// (e.g. "production"). Sourced from ENV, empty otherwise. Not consumed
	// by any subsystem here — it feeds cmd/server's boot guard
	// (checkBootGuard in cmd/server/bootguard.go), which fails closed: any
	// value it does not recognize case-insensitively as a local development
	// tier (see localEnvNames there) makes an insecure-auth or
	// missing-encryption-key boot fatal regardless of the configured listen
	// address.
	Environment    string
	DatabaseURL    string
	OAUTHJWTSecret string // HS256 signing key; see OAUTH_JWT_SIGNING_KEY
	// OAUTHJWTSecretDedicated is true when OAUTHJWTSecret is mctl-telegram's
	// own OAUTH_JWT_SIGNING_KEY in local-jwt mode, not a secret another
	// service also holds (shared-hmac's OAUTH_JWT_SECRET or its legacy
	// fallback). The PA requires it (#1349 review).
	OAUTHJWTSecretDedicated bool
	OAUTHJWTAudience        string // expected `aud` claim; empty disables the check
	OAUTHJWTAudReq          bool   // when true, tokens without aud are rejected
	// WorkerTokenRevocationCacheTTL bounds how long a worker-token jti
	// denylist check may serve a stale in-memory snapshot before refreshing
	// from worker_token_revocations. <=0 falls back to
	// localjwt.DefaultRevocationCacheTTL (10s); any value above
	// localjwt.MaxRevocationCacheTTL (15s) is clamped down to it there — a
	// revocation nobody can rely on within a known window is not a
	// containment control. Set via WORKER_TOKEN_REVOCATION_CACHE_TTL.
	WorkerTokenRevocationCacheTTL time.Duration
	TGAPIID                       int
	TGAPIHash                     string
	// TGTestDC points every MTProto client at Telegram's test datacenters
	// (TG_TEST_DC, issue #854). cmd/server refuses it unless ENV names a
	// local or test tier explicitly, and every process checks the store's DC
	// stamp before opening a session.
	TGTestDC           bool
	EncryptionKey      []byte
	AllowSend          bool
	IdleClientTimeout  time.Duration
	RateLimitPerUser   int
	AuditRetentionDays int
	LogLevel           string
	// Telegram-native OAuth (local-jwt mode):
	TelegramLoginBotToken string // bot token used to send the daily new-client digest
	// TelegramLoginBotUsername is the login bot's @username (no "@"), used to
	// build the https://t.me/<username>?start=onboarding link. Optional; an
	// invalid value is ignored with a warning.
	TelegramLoginBotUsername string
	TGLoginAdmins            []int64 // allowlist of Telegram ids granted platform-admins scopes
	TGLoginClients           []int64 // allowlist of Telegram ids granted telegram:* scopes (no admin:users)
	TGLoginLookupAdmins      []int64 // allowlist of Telegram ids granted admin:users:read only — the two read-only admin lookups; deliberately not the flat admin:users, which also gates every admin write tool. See oauth.Config.LookupAdminTelegramIDs
	// Telegram OpenID Connect (Relying Party — replaces the legacy widget):
	TelegramOIDCClientID     string   // OIDC client id = the login bot's numeric id; not secret
	TelegramOIDCClientSecret string   // OIDC client secret from BotFather; sourced from Vault
	TelegramOIDCIssuerURL    string   // OIDC issuer; default https://oauth.telegram.org
	TelegramOIDCRedirectURL  string   // OIDC callback URL; empty → derived from PublicBaseURL
	TelegramOIDCSigningAlgs  []string // accepted id_token signing algs; empty → RS256
	// TelegramOIDCBotAccessEnabled is the per-environment rollout flag
	// (TELEGRAM_OIDC_BOT_ACCESS_ENABLED, default off) for requesting the
	// telegram:bot_access scope at OIDC sign-in.
	TelegramOIDCBotAccessEnabled bool
	OAUTHCodeTTL                 time.Duration
	OAUTHAccessTokenTTL          time.Duration
	OAUTHRefreshTokenTTL         time.Duration // absolute lifetime of an issued refresh token
	OAUTHAllowImplicitClient     bool          // accept unregistered client_ids; default false (explicit opt-in)
	// OAUTHCIMDAccept makes /oauth/authorize and /oauth/token resolve an
	// https URL client_id as an OAuth Client ID Metadata Document
	// (OAUTH_CIMD_ACCEPT, default false). It does not advertise CIMD in the
	// authorization server metadata; that is OAUTHCIMDAdvertise.
	OAUTHCIMDAccept bool
	// OAUTHCIMDAdvertise announces CIMD and private_key_jwt in discovery
	// (OAUTH_CIMD_ADVERTISE, default false; requires OAUTH_CIMD_ACCEPT). A
	// client that prefers CIMD switches to it as soon as it is advertised and
	// gets a 400 with no DCR fallback if its host is off the allowlist, so
	// turn it on only once the allowlist covers every CIMD client in use
	// (mctl-telegram#773).
	OAUTHCIMDAdvertise bool
	// OAUTHCIMDAllowedHosts is the mandatory host allowlist for CIMD
	// client_ids (OAUTH_CIMD_ALLOWED_HOSTS): exact host names or ".suffix"
	// entries. Required and non-empty when OAUTHCIMDAccept is true.
	OAUTHCIMDAllowedHosts []string
	// AllowSharedHMACLegacy opts in to AUTH_MODE=shared-hmac-legacy. The
	// alias is gated off by default: it is the audit-2026-08 leftover that
	// still treated a shared api.mctl.ai secret as a first-class mode.
	AllowSharedHMACLegacy bool
	// OAUTHRegisterRatePerMin caps unauthenticated POST /oauth/register
	// attempts per client-IP key. Zero in Load falls through to the oauth
	// server default (10).
	OAUTHRegisterRatePerMin int
	// OAUTHAllowedImplicitHosts is the redirect_uri hostname allowlist applied
	// both to unregistered client_ids and to every redirect_uri supplied at
	// RFC 7591 dynamic registration. Entries may include a path prefix
	// ("host/path-prefix") to restrict multi-tenant redirect hosts to specific
	// namespaces. Empty ⇒ the built-in default in internal/oauth (claude.ai,
	// claude.com, chatgpt.com, localhost, 127.0.0.1) applies, so an unset
	// variable changes nothing.
	//
	// Configurable because onboarding a new MCP client (an AI assistant with
	// its own hosted callback domain) is otherwise a code change and a
	// release for what is a deployment-level trust decision.
	OAUTHAllowedImplicitHosts []string
	// OAUTHPreregisteredClients are OAuth clients seeded at startup with an
	// exact redirect_uri set, parsed from OAUTH_PREREGISTERED_CLIENTS (a JSON
	// array of {"client_id","redirect_uris",["client_name"]}). They are the
	// path for a party that cannot use RFC 7591 dynamic registration and whose
	// callback host must not join the implicit allowlist: an enterprise MCP
	// gateway, for instance, is registered once with its exact callback and
	// nothing else about redirect acceptance changes. Unset ⇒ nothing is
	// seeded and behaviour is identical to before the variable existed.
	//
	// The records carry no secret: the authorization server is public-client
	// + PKCE only and this variable does not widen that contract.
	OAUTHPreregisteredClients []PreregisteredClient
	// OAUTHDCRRedirectURIs is the exact-match redirect URI allowlist for RFC
	// 7591 dynamic registration, parsed from OAUTH_DCR_REDIRECT_URIS
	// (comma-separated). A registration whose redirect_uris are ALL on this
	// list is accepted without consulting OAUTHAllowedImplicitHosts; one that
	// mixes a listed URI with anything else is refused. It is how the
	// Cloudflare MCP portal runs this server in automatic (DCR) mode
	// (mctlhq/.github#137) without its callback hosts joining the implicit
	// allowlist, which also governs every unregistered client_id. Matching is
	// byte for byte: no prefix, wildcard or host semantics. Unset ⇒ empty ⇒
	// /oauth/register behaves exactly as before. Entries are validated at
	// startup (https or loopback http, a host, no userinfo, no fragment) and a
	// bad entry aborts the boot. See internal/oauth Config.DCRRedirectURIs.
	OAUTHDCRRedirectURIs []string
	AutoApproveClients   bool // open registration: every widget login auto-gets the client tier
	DigestHourUTC        int  // UTC hour (0-23) for the daily new-client digest; default 9
	// DigestFormat is how the daily digest is sent: "html" (default) or
	// "plain" (the pre-0.135 behaviour, the switch back if the HTML digest
	// misbehaves). Anything else aborts the boot.
	DigestFormat string
	// DigestWeekday makes the digest weekly: "" (default) keeps the daily
	// digest; a weekday name (mon..sun, full names accepted) sends it once a
	// week on that day at DigestHourUTC, covering the last 7 days. Anything
	// else aborts the boot.
	DigestWeekday string
	// DigestRecipients is who receives the digest. Unset falls back to
	// TGLoginAdmins (the pre-existing behaviour). It deliberately does not
	// grant any scope: being listed here only means "gets the message".
	DigestRecipients []int64
	// BotReceiverEnabled turns on the inbound login-bot update receiver
	// (issue-619). Default OFF, and deliberately so: getUpdates allows exactly
	// one consumer per bot token, so enabling it in two environments that
	// share a token would make them fight (409 Conflict) and starve each
	// other. An explicit opt-in makes claiming the token a decision rather
	// than a side effect of deploying.
	BotReceiverEnabled bool
	// BotStartBridgeToken authenticates the bot-start bridge (issue-679):
	// mctl-agent owns the login bot's webhook and forwards a client's /start
	// to POST /internal/bot-start-observations with this bearer token. Empty
	// (the default) leaves the route unmounted; set but shorter than
	// bot.MinBridgeTokenLen fails startup. In production this, not
	// BotReceiverEnabled, is how /start reaches this service: getUpdates
	// cannot run against a bot whose webhook is set.
	BotStartBridgeToken string
	// Safe client broadcasts (issue-439). BroadcastOperators is the
	// allow-list of Telegram ids who may prepare, approve and cancel a
	// broadcast; empty (the default) turns the whole workflow off,
	// delivery worker included. The remaining knobs tune delivery through
	// the login bot: messages per second across all campaigns, rows per
	// worker pass, attempts per recipient on transient failures, the
	// per-campaign audience cap and how long a preview stays approvable.
	BroadcastOperators      []int64
	BroadcastRatePerSec     float64
	BroadcastBatchSize      int
	BroadcastMaxAttempts    int
	BroadcastRecipientLimit int
	BroadcastApprovalTTL    time.Duration
	// ProductUpdateFeedDir is the directory the product-update feed
	// (issue-683) is loaded from at server start: reviewed
	// docs/product-updates/<id>.yaml entries, the same feed the release gate
	// validates. Defaults to docs/product-updates (productupdate.FeedDir,
	// repeated as a literal so config imports no domain package) so local
	// dev and tests need no configuration; the runtime image sets it to the
	// path the feed was copied to (see Dockerfile). Set via
	// PRODUCT_UPDATE_FEED_DIR.
	ProductUpdateFeedDir string
	// Observability:
	// MetricsAllowCIDR restricts /metrics to requests whose remote IP falls
	// within the given CIDR (e.g. "10.0.0.0/8"). When empty the endpoint is
	// open without authentication — suitable for Kubernetes PodMonitor scrape
	// patterns where network policy provides the access control.
	MetricsAllowCIDR string // METRICS_ALLOW_CIDR, optional
	// PublicStatsRefresh is how often the landing page's usage numbers are
	// recounted from the database (PUBLIC_STATS_REFRESH, default 5m). 0 or a
	// negative value disables the sampler, GET /api/stats answers 503 and
	// the landing page renders without the strip.
	PublicStatsRefresh time.Duration // PUBLIC_STATS_REFRESH, default 5m
	// TelegramMaxSessions caps the number of concurrently live MTProto client
	// pool entries. 0 means no cap (default). Set via TELEGRAM_MAX_SESSIONS.
	TelegramMaxSessions int // TELEGRAM_MAX_SESSIONS, 0 = no cap
	// TGAPIRatePerSec is the api_id-wide MTProto RPC ceiling shared across every
	// live client (the pool plus the short-lived login client), expressed in
	// requests per second. All sessions authenticate under one TG_API_ID, so a
	// burst across many user accounts can get the *app credentials* flood-banned
	// even though each account's own per-account budget is fine. This bounds the
	// aggregate. 0 (default) disables the limiter — non-breaking. Set via
	// TG_API_RATE_PER_SEC.
	TGAPIRatePerSec float64
	// TGAPIRateBurst is the token-bucket burst size for the api_id-wide limiter.
	// Ignored when TGAPIRatePerSec <= 0. 0 falls back to ceil(TGAPIRatePerSec)
	// (at least 1). Set via TG_API_RATE_BURST.
	TGAPIRateBurst int
	// DBMaxOpenConns caps the Postgres connection pool. 0 means keep the
	// prior default of 10. Set via DB_MAX_OPEN_CONNS.
	DBMaxOpenConns int
	// DBMaxIdleConns sets the Postgres idle connection count. 0 means keep
	// the prior default of 2. Set via DB_MAX_IDLE_CONNS.
	DBMaxIdleConns int
	// ReplicaID identifies this pod for observability. Sourced from
	// REPLICA_ID env var; falls back to POD_NAME; falls back to "unknown".
	ReplicaID string
	// DemoVideoURL is the walkthrough video shown on the public /demo page
	// (for the ChatGPT App Directory review). Empty → the page renders a
	// "coming soon" placeholder. Accepts a YouTube/Loom share URL or a direct
	// .mp4/.webm URL; see internal/web.classifyDemoVideo. Set via
	// DEMO_VIDEO_URL.
	DemoVideoURL string
	// EnableAccessQREnabled turns on the web QR login in the enable_access
	// flow (#901). Off by default; with it off the QR routes answer 404.
	EnableAccessQREnabled bool // ENABLE_ACCESS_QR_ENABLED
	// TelegramAppName is the Telegram API app's name, which Telegram shows
	// when it asks the user to confirm a QR login. The QR page names it so
	// the user can tell a genuine prompt from a phishing one. Optional.
	TelegramAppName string // TELEGRAM_APP_NAME
	// CanaryTelegramIDs is CANARY_TELEGRAM_IDS: the Telegram accounts the
	// monitoring canary runs as. Disconnect, delete, revoke_telegram_session
	// and set_telegram_access tier "none" on a listed account need an
	// explicit confirmation (internal/canaryguard). Empty by default; a
	// malformed value is a startup error, because a typo would leave the
	// canary unguarded.
	CanaryTelegramIDs canaryguard.Set
	// K8sSA* admit one in-cluster workload (the canary) to /mcp with its
	// projected ServiceAccount token instead of a minted worker token
	// (internal/auth/k8ssa). Off unless MCP_K8S_SA_SUBJECT is set. The
	// Telegram id must be on CANARY_TELEGRAM_IDS, so this path can only ever
	// act as a guarded probe account, and its scopes are read-only in code.
	K8sSASubject    string // MCP_K8S_SA_SUBJECT, system:serviceaccount:<ns>:<name>
	K8sSAAudience   string // MCP_K8S_SA_AUDIENCE, dedicated token audience
	K8sSAIssuer     string // MCP_K8S_SA_ISSUER, default the in-cluster issuer
	K8sSATelegramID int64  // MCP_K8S_SA_TELEGRAM_ID
	// Reviewer/demo auth-mode for the ChatGPT App Directory review. When
	// DemoReviewerEnabled is true the /oauth/authorize page offers a
	// password-gated "reviewer access" path that authenticates as a single
	// pre-provisioned demo Telegram identity, bypassing the live Telegram
	// OIDC login (no phone/SMS). The demo account is expected to be a
	// throwaway with a pre-seeded MTProto session. Its writes are refused
	// except to DemoReviewerWritePeers (internal/mcp/reviewer.go). Off by
	// default; enabled only during review and disabled again after approval.
	// See internal/oauth.
	DemoReviewerEnabled  bool   // DEMO_REVIEWER_ENABLED
	DemoReviewerUsername string // DEMO_REVIEWER_USERNAME
	DemoReviewerPassword string // DEMO_REVIEWER_PASSWORD; compared in constant time, never logged
	DemoReviewerTGID     int64  // DEMO_REVIEWER_TG_ID; numeric Telegram id of the demo account
	// DemoReviewerWritePeers is DEMO_REVIEWER_WRITE_PEERS: the test chats the
	// reviewer identity may really write to, as a comma-separated list of
	// "user:<id>", "chat:<id>" or "channel:<id>" (canonical form, positive
	// ids). Only send_message and send_reply honour it; every other write
	// stays refused for the reviewer (internal/mcp/reviewer.go). It fails
	// closed: empty or unset means the reviewer can write nowhere. A
	// malformed value is a startup error while reviewer mode is on, and is
	// dropped (deny) while it is off, so a leftover value cannot block a
	// deployment that does not use it.
	DemoReviewerWritePeers []string

	// SessionTTLExemptTGIDs lists Telegram ids whose MTProto session is not
	// subject to the 90-day absolute TTL or the 30-day idle TTL — long-lived
	// operator and service identities that must never require an interactive
	// phone+SMS reconnect, even if left unused for a month or more.
	// SESSION_TTL_EXEMPT_TG_IDS, comma-separated.
	SessionTTLExemptTGIDs []int64
	// ToolFilter restricts which MCP tools are registered at startup.
	// "all" (default) registers every tool; "read-only" registers only tools
	// annotated with ReadOnlyHint=true. Set via MCP_TOOL_FILTER.
	ToolFilter string // MCP_TOOL_FILTER
	// ClientProfiles binds OAuth clients to restricted tool profiles
	// (docs/design/core-profiles.md), from MCP_CLIENT_PROFILES: a JSON array
	// of {"client_id","profile"} and {"redirect_uri","profile"} records,
	// each matched exactly. A client_id record may also carry a
	// "scope_ceiling" list, with or without a profile: the allowlist of
	// scopes that client's tokens may carry (#1326). Empty (the default)
	// restricts no client. A malformed table, an unknown profile or a
	// malformed ceiling aborts startup (toolprofile.ParseBindings; a
	// ceiling naming a scope the server never grants is refused by
	// oauth.New).
	ClientProfiles toolprofile.Bindings
	// MediaDownloadMaxBytes caps get_media downloads. 0 means no cap (use with
	// care). Default 20 MiB. Set via MEDIA_DOWNLOAD_MAX_BYTES.
	MediaDownloadMaxBytes int64 // MEDIA_DOWNLOAD_MAX_BYTES
	// MediaUploadMaxBytes caps send_media uploads (both the file_url fetch and
	// the file_base64 decode). 0 means no cap (use with care). Default 20 MiB,
	// independently configurable from MediaDownloadMaxBytes since upload and
	// download are different trust/cost boundaries. Set via
	// MEDIA_UPLOAD_MAX_BYTES.
	MediaUploadMaxBytes int64 // MEDIA_UPLOAD_MAX_BYTES
	// BulkMediaByteCap (issue #705) bounds the total raw bytes
	// get_messages/get_unread_messages fetch_media=true may pull across all
	// items in one call, independent of MediaDownloadMaxBytes. Default 8 MiB.
	// Set via BULK_MEDIA_BYTE_CAP.
	BulkMediaByteCap int64 // BULK_MEDIA_BYTE_CAP
	// MediaTextInlineCapBytes (issue #705) is the total base64 length above
	// which a media-bearing tool result omits the bytes from the text content
	// block (keeping them in structuredContent only) and substitutes a
	// placeholder instead. Default 1 MiB; 0 means always inline (restores the
	// pre-#705 dual-encoded behavior, at the pre-#705 memory cost) and must be
	// set explicitly — a negative value is normalised to the 1 MiB default
	// rather than to 0, so a config typo cannot silently re-arm the pre-#705
	// memory cost. Set via MEDIA_TEXT_INLINE_CAP_BYTES.
	MediaTextInlineCapBytes int64 // MEDIA_TEXT_INLINE_CAP_BYTES
	// MediaMaxConcurrent (issue #705) bounds how many media operations
	// (a fetchMediaInline call, a get_media download) may be in flight at
	// once. Default 2; 0 means unlimited (no admission gate — documented as
	// unsafe). A negative value falls back to the default of 2 rather than to
	// 0, so a config typo cannot silently disarm the gate. Set via
	// MEDIA_MAX_CONCURRENT.
	MediaMaxConcurrent int // MEDIA_MAX_CONCURRENT
	// AgentRetentionDays bounds how long the communication agent's stored
	// message content (incoming_events, conversation_messages) is kept before
	// the retention sweeper deletes it. Unlike audit rows this is third-party
	// message content, so the default is deliberately short. 0 keeps rows
	// forever. Set via AGENT_RETENTION_DAYS.
	AgentRetentionDays int // AGENT_RETENTION_DAYS, default 30
	// AgentLeadRetentionDays is how long a job lead is kept after its last
	// update. Separate from AgentRetentionDays because a lead outlives the
	// messages it came from. 0 keeps leads until account deletion.
	AgentLeadRetentionDays int // AGENT_LEAD_RETENTION_DAYS, default 90

	// AgentJobVisibility is how long a claimed (processing) agent job may sit
	// before the sweeper assumes the worker died and requeues it. Must exceed
	// the worst-case model round-trip for one job. Set via AGENT_JOB_VISIBILITY.
	AgentJobVisibility time.Duration // AGENT_JOB_VISIBILITY, default 5m
	// AgentAllowLegacyCompletion temporarily accepts completion requests from
	// pre-result-linkage workers during a controlled rollout. It must return
	// to false after old workers are drained.
	AgentAllowLegacyCompletion bool // AGENT_ALLOW_LEGACY_COMPLETION, default false
	// AgentApprovalTTL is how long an agent action waits in pending_approval
	// before expiring. Set via AGENT_APPROVAL_TTL.
	AgentApprovalTTL time.Duration // AGENT_APPROVAL_TTL, default 24h
	// AgentEnabled gates whether the agent-facing HTTP surface (/api/agent/v1,
	// POST /api/agent/token) is mounted at all. Off by default like every other
	// communication-agent PR — the underlying tables/queue/listener can be
	// present in a deployment without exposing the surface an external worker
	// talks to. Set via AGENT_ENABLED.
	AgentEnabled bool
	// AgentKillSwitch is the global, env-only kill switch the policy engine
	// checks on every evaluated action. Deliberately not a DB row (like
	// AgentProfile.AutopilotPaused) so an operator can cut the agent off by
	// redeploying config even if the database is unreachable or compromised.
	// Set via AGENT_KILL_SWITCH.
	AgentKillSwitch bool
	// AppsEnabled gates the MCP Apps (SEP-1865) prototype surface: the
	// "io.modelcontextprotocol/ui" extension capability, resource capability,
	// the internal/mcpui triage App resource, and the _meta.ui link on its
	// backing tools. Off by default, mirroring AgentEnabled — the flag exists
	// so the App can be built and deployed without exposing it, and a
	// deployment can drop back to the current tools-only surface by unsetting
	// it, with no redeploy of this repository required beyond the env change.
	// Set via MCP_APPS_ENABLED.
	AppsEnabled bool
	// BroadcastContentEnabled lets the content tools return broadcast
	// channel posts, with the channel's official sponsored messages attached
	// (Telegram API terms §3.3). On by default. Turning it off restores the
	// issue #851 refusal for every content read, hosted and Local Bridge,
	// with no release: a deployment flips it in gitops if Telegram objects
	// to how channel posts or their ads reach the AI.
	// Set via BROADCAST_CONTENT_ENABLED; see broadcastContentFromEnv.
	BroadcastContentEnabled bool

	// EventsValkeyURL enables publishing reference-only mctl.events/v1
	// envelopes for incoming messages to platform Valkey Streams
	// (redis://<acl-user>@host:port/db, no password in the URL). Empty
	// disables the event outbox entirely. EventsValkeyPassword is the ACL
	// user's password; EventsStream is the stream that user may XADD to.
	EventsValkeyURL      string
	EventsValkeyPassword string
	EventsStream         string
	// EventsOperatorRouting (EVENTS_OPERATOR_ROUTING, default false) stops
	// publishing a telegram.message.* envelope at ingest for an event the
	// agent job queue took, and publishes one only when the job ends in a
	// deny, require_approval or worker failure, so the operator stream
	// carries just the messages the conversation worker did not handle.
	// A job no worker claims within AgentUnclaimedRouteAfter is moved to
	// routed and forwarded with routing_reason=worker_unclaimed; worst-case
	// latency is that threshold plus one agent-jobs sweep interval (1m).
	EventsOperatorRouting bool
	// AgentTurnQuiet (AGENT_TURN_QUIET, default 0 = coalescing off) is the
	// quiet window of a conversation turn: a burst of messages closer
	// together than this becomes one agent job. AgentTurnMaxWait,
	// AgentTurnMaxMsgs and AgentTurnMaxBytes bound a turn; they are only
	// validated when coalescing is on.
	AgentTurnQuiet    time.Duration // AGENT_TURN_QUIET, default 0
	AgentTurnMaxWait  time.Duration // AGENT_TURN_MAX_WAIT, default 15s
	AgentTurnMaxMsgs  int           // AGENT_TURN_MAX_MSGS, default 10
	AgentTurnMaxBytes int           // AGENT_TURN_MAX_BYTES, default 16384
	// AgentUnclaimedRouteAfter (AGENT_UNCLAIMED_ROUTE_AFTER, default 5m) is
	// how long a never-claimed job may stay pending before it is routed to
	// the operator. Only used while EventsOperatorRouting is on.
	AgentUnclaimedRouteAfter time.Duration
	// AgentProfilePath is the deprecated mounted-YAML migration source. At
	// startup it is imported into the target tenant's encrypted DB profile
	// only when that document is still missing; it is never consulted on
	// runtime reads and never overwrites an admin-managed document.
	AgentProfilePath string
	// AgentProfileOwnerTGID is the Telegram id of the account
	// receiving the legacy AgentProfilePath import. Required whenever that
	// path is set; ignored otherwise. Runtime lookup is by authenticated
	// internal user_id, not this process-wide value.
	AgentProfileOwnerTGID int64
	// AgentTestCrashAfterReserve is a TEST-ONLY fault-injection switch. When
	// true, the executor hard-exits the process immediately after
	// ReserveAgentActionSend persists send_random_id and CASes an action to
	// `executing`, but before the Telegram RPC fires — deterministically
	// reproducing the crash-mid-send scenario the random_id/RecoverStuck
	// design exists for, so the retry-with-the-same-random_id drill (see
	// docs/plans/communication-agent.md's Rollout gates) can be run live
	// on demand instead of relying solely on unit tests. Must never be true
	// outside a deliberate drill window — every real send on the pod is hit
	// by this, not just a chosen one. Set via AGENT_TEST_CRASH_AFTER_RESERVE.
	AgentTestCrashAfterReserve bool

	// WorkContextEnabled gates the issue-443 work-context surface adapter:
	// the outbound mctl-api client and the /mctl work|link subcommands. Off
	// by default like every other agent-adjacent surface — with it false,
	// no workctx.Client is constructed, no outbound request is ever made,
	// and /mctl work|link fall through to the pre-#443 unknown-command
	// reply. Set via WORK_CONTEXT_ENABLED.
	WorkContextEnabled bool
	// MCTLAPIBaseURL is the mctl-api root the workctx client talks to. Set
	// via MCTL_API_BASE_URL, default https://api.mctl.ai.
	MCTLAPIBaseURL string
	// MCTLSurfaceTelegramToken is the bearer credential for the
	// surface:telegram principal — never MCTL_API_TOKEN or an mctl-agent
	// credential. Bare os.Getenv, matching the TG_API_HASH secret pattern:
	// no default, and registered in internal/audit/redact.go's
	// sensitiveKeys so it can never reach a log line. Set via
	// MCTL_SURFACE_TELEGRAM_TOKEN.
	MCTLSurfaceTelegramToken string
	// AssistantRegistryEnabled makes assistant installs fetch their
	// definition from the mctl-api registry (MCTL_API_BASE_URL, as the
	// surface:telegram principal with MCTL_SURFACE_TELEGRAM_TOKEN), store it
	// as a database snapshot with the install, refresh every pinned
	// version's lifecycle every 5 minutes, and stop claims for a disabled or
	// unknown one (#1020). Off by default: installs then use the embedded
	// catalog and no registry call is made. Set via
	// ASSISTANT_REGISTRY_ENABLED.
	AssistantRegistryEnabled bool
	// AssistantForksEnabled lets accounts create, change and install
	// private forks of catalog assistants (#1043,
	// docs/assistants/adr-forks.md). Off by default; turning it off also
	// stops the jobs of every account that runs a fork. Deleting a fork
	// stays possible. Set via ASSISTANT_FORKS_ENABLED.
	AssistantForksEnabled bool
	// AssistantForkEvalEnabled is the P4.3 S2 switch for fork eval runs
	// (docs/assistants/adr-forks.md). Off by default; nothing reads it yet
	// beyond the startup log. Set via ASSISTANT_FORK_EVAL_ENABLED.
	AssistantForkEvalEnabled bool
	// ManagedRuntimeEnabled lets an account choose runtime "managed" for its
	// assistant (ADR 0008). Off by default: switching to managed is then
	// refused. Set via MANAGED_RUNTIME_ENABLED. On, Load requires
	// AUTH_MODE=local-jwt with a dedicated OAUTH_JWT_SIGNING_KEY (#1351).
	ManagedRuntimeEnabled bool
	// ManagedRuntimeMaxAccounts caps how many accounts may be managed at
	// once; 0 means none may become managed. Set via
	// MANAGED_RUNTIME_MAX_ACCOUNTS.
	ManagedRuntimeMaxAccounts int
	// ManagedMaxInflightPerAccount is parsed only in this slice. Set via
	// MANAGED_MAX_INFLIGHT_PER_ACCOUNT.
	ManagedMaxInflightPerAccount int
	// Managed spend caps (ADR 0008 section 5), in USD. MaxJobCostUSD is the
	// amount reserved per claimed job (MANAGED_MAX_JOB_COST_USD); the others
	// are the UTC-calendar-day and month caps per account and the global day
	// cap (MANAGED_BUDGET_USD_PER_ACCOUNT_DAY, _PER_ACCOUNT_MONTH,
	// MANAGED_BUDGET_USD_GLOBAL_DAY). A zero value means the budget is not
	// wired (a Config built by hand, not by Load).
	ManagedMaxJobCostUSD            float64
	ManagedBudgetUSDPerAccountDay   float64
	ManagedBudgetUSDPerAccountMonth float64
	// ManagedClaimNotAfter (MANAGED_CLAIM_NOT_AFTER, RFC 3339, optional) ends
	// managed claims at that instant, so a time-boxed run stops spending without
	// depending on anyone being there to stop it. Zero means no cutoff. It
	// ends PA claims too (PABudget; owner decision 2026-11-19).
	ManagedClaimNotAfter      time.Time
	ManagedBudgetUSDGlobalDay float64
	// WorkItemTenant is the single configured mctl-api tenant every
	// Telegram-originated work item belongs to (see requirements.md's Open
	// questions — this repository's own "tenant" concept is a different
	// thing). Set via MCTL_WORK_ITEM_TENANT.
	WorkItemTenant string
	// HumanInputEnabled gates the issue-571 human-input (agent clarification)
	// Telegram adapter: the poller, the delivery rows and the /mctl input
	// command. Requires WorkContextEnabled (it reuses the same relay client).
	// Off by default; with it false no human-input client call, poller or
	// command exists. Set via HUMAN_INPUT_ENABLED.
	HumanInputEnabled bool
	// HumanInputPollInterval is how often the poller lists pending requests
	// per enrolled actor. Default 30s, minimum 10s. Set via
	// HUMAN_INPUT_POLL_INTERVAL.
	HumanInputPollInterval time.Duration
	// PAEnabled is the Personal Assistant master kill switch (issue #1313,
	// threat model T11). Fail-closed: unset, empty or unparseable means off,
	// and with it off no PA route is registered, no PA bot token is read and
	// nothing PA-related starts. Set via PA_ENABLED.
	PAEnabled bool
	// PABotToken is the dedicated PA Bot API token (PA_BOT_TOKEN). It has no
	// default, is read only when PAEnabled is true, and must belong to a
	// different bot than TELEGRAM_LOGIN_BOT_TOKEN: the PA bot is its own
	// trust boundary (ADR 0011).
	PABotToken string
	// PAWebhookSecret is the secret_token Telegram echoes in
	// X-Telegram-Bot-Api-Secret-Token on every webhook delivery
	// (PA_WEBHOOK_SECRET). No default; read only when PAEnabled is true.
	PAWebhookSecret string
	// PAWebhookURL is the public URL the webhook is registered at
	// (PA_WEBHOOK_URL): https, path /pa/bot/webhook, no userinfo, query or
	// fragment. Required when PAEnabled; the getWebhookInfo monitor alerts
	// when Telegram reports any other URL (T4). Read only when PAEnabled.
	PAWebhookURL string
	// PAAllowedPrincipals is the preview allowlist (PA_ALLOWED_PRINCIPALS,
	// config_pa_allowlist.go): the only Telegram user ids the PA serves.
	// Read only when PAEnabled; empty allows nobody.
	PAAllowedPrincipals []int64
	// PAConversationTTL is the PA conversation lifetime, anchored at
	// creation (PA_CONVERSATION_TTL, default 24h, at most 24h because the
	// consent text promises it). Read only when PAEnabled is true; an
	// unparseable or out-of-range value refuses to start.
	PAConversationTTL time.Duration
	// PA run-loop limits (issue #1313 slice d1; owner decisions
	// 2026-11-18). Read only when PAEnabled is true; an unparseable or
	// non-positive value refuses to start instead of falling back to a
	// default, because a limit that silently reverted is not a limit.
	//   PA_RATE_MESSAGES per PA_RATE_WINDOW per principal (20 per 1h; the
	//   window counts consent prompts and commands too);
	//   PA_MAX_CONTEXT_TOKENS (32000);
	//   PA_BUDGET_USD_JOB / _DAY / _MONTH (0.25 / 2 / 20), the per-run
	//   reservation and the per-principal caps. The platform-wide daily cap
	//   is MANAGED_BUDGET_USD_GLOBAL_DAY, shared with the managed runtime;
	//   PA_MIN_TURN_COST_USD (0.005), the settlement floor per model turn.
	// Active jobs per principal (1) and tool calls per run (8) are fixed.
	PARateMessages     int
	PARateWindow       time.Duration
	PAMaxContextTokens int
	PABudgetUSDJob     float64
	PABudgetUSDDay     float64
	PABudgetUSDMonth   float64
	PAMinTurnUSD       float64
}

// PALimits is the PA run loop's per-principal limits: the rate window and
// context bound from PA_RATE_* and PA_MAX_CONTEXT_TOKENS, and the fixed
// per-run tool-call cap.
func (c *Config) PALimits() jobs.Limits {
	return jobs.Limits{
		RateMessages: c.PARateMessages, RateWindow: c.PARateWindow,
		MaxToolCalls: jobs.DefaultMaxToolCalls, MaxContextTokens: c.PAMaxContextTokens,
	}
}

// PABudget is the PA run loop's budget: the PA caps, the global day shared
// with the managed runtime, and MANAGED_CLAIM_NOT_AFTER, which ends PA
// claims as it ends managed ones.
func (c *Config) PABudget() jobs.Budget {
	return jobs.Budget{
		PerJobUSD: c.PABudgetUSDJob, PrincipalDayUSD: c.PABudgetUSDDay, PrincipalMonthUSD: c.PABudgetUSDMonth,
		GlobalDayUSD: c.ManagedBudgetUSDGlobalDay, MinTurnUSD: c.PAMinTurnUSD, ClaimNotAfter: c.ManagedClaimNotAfter,
	}
}

// MinPAWebhookSecretLen is the shortest PA_WEBHOOK_SECRET Load accepts.
// Telegram allows 1-256 characters; anything short enough to guess is
// refused at boot rather than accepted on the public webhook.
const MinPAWebhookSecretLen = 32

// paBotTokenFormat is the shape of a Bot API token: numeric bot id, a colon,
// and a secret half of at least 30 URL-safe characters.
var paBotTokenFormat = regexp.MustCompile(`^[0-9]+:[A-Za-z0-9_-]{30,}$`)

// paWebhookSecretChars is Telegram's documented secret_token alphabet.
var paWebhookSecretChars = regexp.MustCompile(`^[A-Za-z0-9_-]{1,256}$`)

// ValidPAWebhookSecret reports whether s is a PA_WEBHOOK_SECRET Load
// accepts: MinPAWebhookSecretLen to 256 characters of Telegram's
// secret_token alphabet. pa.SetWebhook checks the same rule.
func ValidPAWebhookSecret(s string) bool {
	return len(s) >= MinPAWebhookSecretLen && paWebhookSecretChars.MatchString(s)
}

// loadPA reads the PA settings. With PA_ENABLED off it reads nothing else, so
// a stray PA_BOT_TOKEN in an environment that has not enabled the PA cannot
// be picked up by anything. Errors never contain the token or the secret.
func loadPA(c *Config) error {
	c.PAEnabled = envBool("PA_ENABLED", false)
	if !c.PAEnabled {
		return nil
	}
	c.PABotToken = os.Getenv("PA_BOT_TOKEN")
	c.PAWebhookSecret = os.Getenv("PA_WEBHOOK_SECRET")
	paID, ok := BotIDFromToken(c.PABotToken)
	if !ok || !paBotTokenFormat.MatchString(c.PABotToken) {
		return errors.New("PA_ENABLED=true requires PA_BOT_TOKEN to be a Bot API token")
	}
	if loginID, ok := BotIDFromToken(c.TelegramLoginBotToken); ok && loginID == paID {
		return errors.New("PA_BOT_TOKEN must belong to a different bot than TELEGRAM_LOGIN_BOT_TOKEN")
	}
	if !ValidPAWebhookSecret(c.PAWebhookSecret) {
		return fmt.Errorf("PA_ENABLED=true requires PA_WEBHOOK_SECRET of %d-256 characters from [A-Za-z0-9_-]", MinPAWebhookSecretLen)
	}
	c.PAWebhookURL = os.Getenv("PA_WEBHOOK_URL")
	if err := validatePAWebhookURL(c.PAWebhookURL); err != nil {
		return fmt.Errorf("PA_ENABLED=true requires PA_WEBHOOK_URL: %w", err)
	}
	c.PAConversationTTL = 24 * time.Hour
	if v := os.Getenv("PA_CONVERSATION_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < time.Minute || d > 24*time.Hour {
			return errors.New("PA_CONVERSATION_TTL must be a duration between 1m and 24h")
		}
		c.PAConversationTTL = d
	}
	if err := loadPAAllowlist(c); err != nil {
		return err
	}
	return loadPALimits(c)
}

func loadPALimits(c *Config) error {
	c.PARateMessages, c.PARateWindow = jobs.DefaultRateMessages, jobs.DefaultRateWindow
	c.PAMaxContextTokens = jobs.DefaultMaxContextTokens
	c.PABudgetUSDJob, c.PABudgetUSDDay, c.PABudgetUSDMonth = jobs.DefaultBudgetJobUSD, jobs.DefaultBudgetDayUSD, jobs.DefaultBudgetMonthUSD
	c.PAMinTurnUSD = jobs.DefaultMinTurnUSD
	for _, iv := range []struct {
		key string
		dst *int
	}{{"PA_RATE_MESSAGES", &c.PARateMessages}, {"PA_MAX_CONTEXT_TOKENS", &c.PAMaxContextTokens}} {
		if v := os.Getenv(iv.key); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 {
				return fmt.Errorf("%s must be a positive integer", iv.key)
			}
			*iv.dst = n
		}
	}
	if v := os.Getenv("PA_RATE_WINDOW"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < time.Minute || d > 24*time.Hour {
			return errors.New("PA_RATE_WINDOW must be a duration between 1m and 24h")
		}
		c.PARateWindow = d
	}
	for _, fv := range []struct {
		key string
		dst *float64
	}{{"PA_BUDGET_USD_JOB", &c.PABudgetUSDJob}, {"PA_BUDGET_USD_DAY", &c.PABudgetUSDDay}, {"PA_BUDGET_USD_MONTH", &c.PABudgetUSDMonth},
		{"PA_MIN_TURN_COST_USD", &c.PAMinTurnUSD}} {
		if v := os.Getenv(fv.key); v != "" {
			f, err := strconv.ParseFloat(v, 64)
			if err != nil || !(f > 0) || math.IsInf(f, 0) {
				return fmt.Errorf("%s must be a positive number", fv.key)
			}
			*fv.dst = f
		}
	}
	if c.PABudgetUSDJob > c.PABudgetUSDDay || c.PABudgetUSDDay > c.PABudgetUSDMonth {
		return errors.New("PA budgets must satisfy PA_BUDGET_USD_JOB <= PA_BUDGET_USD_DAY <= PA_BUDGET_USD_MONTH")
	}
	// The global day window is MANAGED_BUDGET_USD_GLOBAL_DAY, shared with
	// the managed runtime; a PA job dearer than it would be held forever.
	if c.PABudgetUSDJob > c.ManagedBudgetUSDGlobalDay {
		return errors.New("PA_BUDGET_USD_JOB must not exceed MANAGED_BUDGET_USD_GLOBAL_DAY")
	}
	// The floor of a run at its turn cap (one turn per tool call plus the
	// answer) must fit the reservation it is settled against.
	if c.PAMinTurnUSD*float64(jobs.DefaultMaxToolCalls+1) > c.PABudgetUSDJob+1e-9 {
		return fmt.Errorf("PA_MIN_TURN_COST_USD x %d turns must not exceed PA_BUDGET_USD_JOB", jobs.DefaultMaxToolCalls+1)
	}
	return nil
}

func Load() (*Config, error) {
	authMode := envOr("AUTH_MODE", "local-dev")
	c := &Config{
		Addr:                            envOr("ADDR", ":8080"),
		PublicBaseURL:                   envOr("PUBLIC_BASE_URL", "http://localhost:8080"),
		MCPPath:                         envOr("MCP_PATH", "/mcp"),
		AuthMode:                        authMode,
		AuthRequired:                    envBool("AUTH_REQUIRED", false),
		OperatorLogin:                   envOr("OPERATOR_GITHUB_LOGIN", "operator"),
		Environment:                     envOr("ENV", ""),
		DatabaseURL:                     envOr("DATABASE_URL", "file:mctl-telegram.db?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"),
		OAUTHJWTSecret:                  jwtSigningKey(authMode),
		OAUTHJWTSecretDedicated:         strings.EqualFold(authMode, "local-jwt") && os.Getenv("OAUTH_JWT_SIGNING_KEY") != "",
		OAUTHJWTAudience:                os.Getenv("OAUTH_JWT_AUDIENCE"),
		OAUTHJWTAudReq:                  envBool("OAUTH_JWT_AUDIENCE_REQUIRED", false),
		WorkerTokenRevocationCacheTTL:   envDuration("WORKER_TOKEN_REVOCATION_CACHE_TTL", 10*time.Second),
		TGAPIHash:                       os.Getenv("TG_API_HASH"),
		TGTestDC:                        TestDCFromEnv(),
		AllowSend:                       envBool("ALLOW_SEND", false),
		IdleClientTimeout:               envDuration("IDLE_CLIENT_TIMEOUT", 10*time.Minute),
		RateLimitPerUser:                envInt("RATE_LIMIT_PER_USER", 30),
		AuditRetentionDays:              envInt("AUDIT_RETENTION_DAYS", 90),
		AgentRetentionDays:              envInt("AGENT_RETENTION_DAYS", 30),
		AgentLeadRetentionDays:          envInt("AGENT_LEAD_RETENTION_DAYS", 90),
		AgentJobVisibility:              envDuration("AGENT_JOB_VISIBILITY", 5*time.Minute),
		AgentAllowLegacyCompletion:      envBool("AGENT_ALLOW_LEGACY_COMPLETION", false),
		AgentApprovalTTL:                envDuration("AGENT_APPROVAL_TTL", 24*time.Hour),
		AgentEnabled:                    envBool("AGENT_ENABLED", false),
		AgentKillSwitch:                 envBool("AGENT_KILL_SWITCH", false),
		AppsEnabled:                     envBool("MCP_APPS_ENABLED", false),
		BroadcastContentEnabled:         broadcastContentFromEnv(),
		EventsValkeyURL:                 os.Getenv("EVENTS_VALKEY_URL"),
		EventsValkeyPassword:            os.Getenv("EVENTS_VALKEY_PASSWORD"),
		EventsStream:                    envOr("EVENTS_STREAM", "mctl:events:telegram"),
		EventsOperatorRouting:           envBool("EVENTS_OPERATOR_ROUTING", false),
		AgentTurnQuiet:                  envDuration("AGENT_TURN_QUIET", 0),
		AgentTurnMaxWait:                envDuration("AGENT_TURN_MAX_WAIT", 15*time.Second),
		AgentTurnMaxMsgs:                envInt("AGENT_TURN_MAX_MSGS", 10),
		AgentTurnMaxBytes:               envInt("AGENT_TURN_MAX_BYTES", 16384),
		AgentUnclaimedRouteAfter:        envDuration("AGENT_UNCLAIMED_ROUTE_AFTER", 5*time.Minute),
		AgentProfilePath:                os.Getenv("AGENT_PROFILE_PATH"),
		AgentProfileOwnerTGID:           envInt64("AGENT_PROFILE_OWNER_TG_ID", 0),
		AgentTestCrashAfterReserve:      envBool("AGENT_TEST_CRASH_AFTER_RESERVE", false),
		LogLevel:                        envOr("LOG_LEVEL", "info"),
		TelegramLoginBotToken:           os.Getenv("TELEGRAM_LOGIN_BOT_TOKEN"),
		TelegramLoginBotUsername:        loginBotUsernameFromEnv(),
		TelegramOIDCClientID:            os.Getenv("TELEGRAM_OIDC_CLIENT_ID"),
		TelegramOIDCBotAccessEnabled:    envBool("TELEGRAM_OIDC_BOT_ACCESS_ENABLED", false),
		TelegramOIDCClientSecret:        os.Getenv("TELEGRAM_OIDC_CLIENT_SECRET"),
		TelegramOIDCIssuerURL:           envOr("TELEGRAM_OIDC_ISSUER", "https://oauth.telegram.org"),
		TelegramOIDCRedirectURL:         os.Getenv("TELEGRAM_OIDC_REDIRECT_URL"),
		OAUTHCodeTTL:                    envDuration("OAUTH_CODE_TTL", 10*time.Minute),
		OAUTHAccessTokenTTL:             envDuration("OAUTH_ACCESS_TOKEN_TTL", 1*time.Hour),
		OAUTHRefreshTokenTTL:            envDuration("OAUTH_REFRESH_TOKEN_TTL", 720*time.Hour),
		OAUTHAllowImplicitClient:        envBool("OAUTH_ALLOW_IMPLICIT_CLIENT", false),
		OAUTHCIMDAccept:                 envBool("OAUTH_CIMD_ACCEPT", false),
		OAUTHCIMDAdvertise:              envBool("OAUTH_CIMD_ADVERTISE", false),
		AllowSharedHMACLegacy:           envBool("AUTH_ALLOW_SHARED_HMAC_LEGACY", false),
		OAUTHRegisterRatePerMin:         envInt("OAUTH_REGISTER_RATE_PER_MIN", 10),
		AutoApproveClients:              envBool("AUTO_APPROVE_CLIENTS", false),
		DigestHourUTC:                   envInt("DIGEST_HOUR_UTC", 9),
		DigestFormat:                    strings.ToLower(strings.TrimSpace(envOr("DIGEST_FORMAT", "html"))),
		DigestWeekday:                   strings.ToLower(strings.TrimSpace(os.Getenv("DIGEST_WEEKDAY"))),
		BotReceiverEnabled:              envBool("BOT_RECEIVER_ENABLED", false),
		BotStartBridgeToken:             strings.TrimSpace(os.Getenv("BOT_START_BRIDGE_TOKEN")),
		BroadcastRatePerSec:             envFloat("BROADCAST_RATE_PER_SEC", 10),
		BroadcastBatchSize:              envInt("BROADCAST_BATCH_SIZE", 20),
		BroadcastMaxAttempts:            envInt("BROADCAST_MAX_ATTEMPTS", 5),
		BroadcastRecipientLimit:         envInt("BROADCAST_RECIPIENT_LIMIT", 1000),
		BroadcastApprovalTTL:            envDuration("BROADCAST_APPROVAL_TTL", 30*time.Minute),
		WorkContextEnabled:              envBool("WORK_CONTEXT_ENABLED", false),
		AssistantRegistryEnabled:        envBool("ASSISTANT_REGISTRY_ENABLED", false),
		AssistantForksEnabled:           envBool("ASSISTANT_FORKS_ENABLED", false),
		AssistantForkEvalEnabled:        envBool("ASSISTANT_FORK_EVAL_ENABLED", false),
		ManagedRuntimeEnabled:           envBool("MANAGED_RUNTIME_ENABLED", false),
		ManagedRuntimeMaxAccounts:       envInt("MANAGED_RUNTIME_MAX_ACCOUNTS", 1),
		ManagedMaxInflightPerAccount:    envInt("MANAGED_MAX_INFLIGHT_PER_ACCOUNT", 1),
		ManagedMaxJobCostUSD:            envFloat("MANAGED_MAX_JOB_COST_USD", 0.50),
		ManagedBudgetUSDPerAccountDay:   envFloat("MANAGED_BUDGET_USD_PER_ACCOUNT_DAY", 1.00),
		ManagedBudgetUSDPerAccountMonth: envFloat("MANAGED_BUDGET_USD_PER_ACCOUNT_MONTH", 15.00),
		ManagedBudgetUSDGlobalDay:       envFloat("MANAGED_BUDGET_USD_GLOBAL_DAY", 20.00),
		MCTLAPIBaseURL:                  envOr("MCTL_API_BASE_URL", "https://api.mctl.ai"),
		MCTLSurfaceTelegramToken:        os.Getenv("MCTL_SURFACE_TELEGRAM_TOKEN"),
		WorkItemTenant:                  os.Getenv("MCTL_WORK_ITEM_TENANT"),
		HumanInputEnabled:               envBool("HUMAN_INPUT_ENABLED", false),
		HumanInputPollInterval:          envDuration("HUMAN_INPUT_POLL_INTERVAL", 30*time.Second),
		ProductUpdateFeedDir:            envOr("PRODUCT_UPDATE_FEED_DIR", "docs/product-updates"),
	}
	c.MetricsAllowCIDR = os.Getenv("METRICS_ALLOW_CIDR")
	c.PublicStatsRefresh = envDuration("PUBLIC_STATS_REFRESH", 5*time.Minute)
	c.TelegramMaxSessions = envInt("TELEGRAM_MAX_SESSIONS", 0)
	c.TGAPIRatePerSec = envFloat("TG_API_RATE_PER_SEC", 0)
	c.TGAPIRateBurst = envInt("TG_API_RATE_BURST", 0)
	c.DBMaxOpenConns = envInt("DB_MAX_OPEN_CONNS", 0)
	c.DBMaxIdleConns = envInt("DB_MAX_IDLE_CONNS", 0)
	c.ReplicaID = envOr("REPLICA_ID", envOr("POD_NAME", "unknown"))
	c.DemoVideoURL = envOr("DEMO_VIDEO_URL", "")
	if _, _, err := ParseDigestWeekday(c.DigestWeekday); err != nil {
		return nil, err
	}
	if raw := strings.TrimSpace(os.Getenv("DIGEST_RECIPIENTS")); raw != "" {
		ids, err := parseStrictInt64CSV(raw)
		if err != nil {
			return nil, fmt.Errorf("DIGEST_RECIPIENTS: %w", err)
		}
		c.DigestRecipients = ids
	}
	if c.DigestFormat != "html" && c.DigestFormat != "plain" {
		return nil, fmt.Errorf("DIGEST_FORMAT must be html or plain, got %q", c.DigestFormat)
	}
	c.EnableAccessQREnabled = envBool("ENABLE_ACCESS_QR_ENABLED", false)
	c.TelegramAppName = strings.TrimSpace(os.Getenv("TELEGRAM_APP_NAME"))
	canaryIDs, err := canaryguard.Parse(os.Getenv("CANARY_TELEGRAM_IDS"))
	if err != nil {
		return nil, fmt.Errorf("CANARY_TELEGRAM_IDS: %w", err)
	}
	c.CanaryTelegramIDs = canaryIDs
	if err := loadK8sSA(c); err != nil {
		return nil, err
	}
	c.DemoReviewerEnabled = envBool("DEMO_REVIEWER_ENABLED", false)
	c.DemoReviewerUsername = os.Getenv("DEMO_REVIEWER_USERNAME")
	c.DemoReviewerPassword = os.Getenv("DEMO_REVIEWER_PASSWORD")
	if v := os.Getenv("DEMO_REVIEWER_TG_ID"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("DEMO_REVIEWER_TG_ID must be integer: %w", err)
		}
		c.DemoReviewerTGID = n
	}
	if c.DemoReviewerEnabled {
		if c.DemoReviewerUsername == "" || c.DemoReviewerPassword == "" || c.DemoReviewerTGID == 0 {
			return nil, fmt.Errorf("DEMO_REVIEWER_ENABLED requires DEMO_REVIEWER_USERNAME, DEMO_REVIEWER_PASSWORD and DEMO_REVIEWER_TG_ID")
		}
	}
	if peers, err := parseReviewerWritePeers(os.Getenv("DEMO_REVIEWER_WRITE_PEERS")); err != nil {
		if c.DemoReviewerEnabled {
			return nil, fmt.Errorf("DEMO_REVIEWER_WRITE_PEERS: %w", err)
		}
	} else if c.DemoReviewerEnabled {
		c.DemoReviewerWritePeers = peers
	}
	// AgentProfileOwnerTGID's doc comment documents it as required whenever
	// AgentProfilePath is set — a missing or malformed value silently
	// defaulted to 0, so the profile loaded successfully at startup but
	// handleRecruiterProfile then returned 403 for every account (owner ID
	// zero is explicitly forbidden there), leaving a seemingly enabled
	// endpoint permanently unusable with no loud failure anywhere. Fail
	// closed here instead, matching this function's existing DemoReviewer
	// validation immediately above.
	if c.AgentProfilePath != "" && c.AgentProfileOwnerTGID <= 0 {
		return nil, fmt.Errorf("AGENT_PROFILE_OWNER_TG_ID must be set to a positive Telegram id when AGENT_PROFILE_PATH is set")
	}
	if c.AgentTurnQuiet < 0 {
		return nil, fmt.Errorf("AGENT_TURN_QUIET must not be negative")
	}
	if c.AgentTurnQuiet > 0 {
		if c.AgentTurnMaxWait <= 0 || c.AgentTurnMaxMsgs <= 0 || c.AgentTurnMaxBytes <= 0 {
			return nil, fmt.Errorf("AGENT_TURN_MAX_WAIT, AGENT_TURN_MAX_MSGS and AGENT_TURN_MAX_BYTES must be > 0 when AGENT_TURN_QUIET is set")
		}
		if c.AgentUnclaimedRouteAfter <= c.AgentTurnMaxWait {
			return nil, fmt.Errorf("AGENT_UNCLAIMED_ROUTE_AFTER must be greater than AGENT_TURN_MAX_WAIT when AGENT_TURN_QUIET is set")
		}
	}
	if c.EventsOperatorRouting && c.AgentUnclaimedRouteAfter <= 0 {
		return nil, fmt.Errorf("AGENT_UNCLAIMED_ROUTE_AFTER must be > 0 when EVENTS_OPERATOR_ROUTING is on")
	}
	// Mirrors the DemoReviewer validation immediately above: an adapter
	// enabled with no way to authenticate to mctl-api, or no tenant to file
	// work items under, would either fail every call at runtime or (worse)
	// silently misfile work — refuse to start rather than degrade quietly.
	if c.WorkContextEnabled {
		if c.MCTLSurfaceTelegramToken == "" || c.WorkItemTenant == "" {
			return nil, fmt.Errorf("WORK_CONTEXT_ENABLED requires MCTL_SURFACE_TELEGRAM_TOKEN and MCTL_WORK_ITEM_TENANT")
		}
	}
	if c.ManagedRuntimeMaxAccounts < 0 {
		return nil, fmt.Errorf("MANAGED_RUNTIME_MAX_ACCOUNTS must not be negative")
	}
	if c.ManagedMaxInflightPerAccount < 1 {
		return nil, fmt.Errorf("MANAGED_MAX_INFLIGHT_PER_ACCOUNT must be at least 1")
	}
	for _, b := range []struct {
		name string
		v    float64
	}{
		{"MANAGED_MAX_JOB_COST_USD", c.ManagedMaxJobCostUSD},
		{"MANAGED_BUDGET_USD_PER_ACCOUNT_DAY", c.ManagedBudgetUSDPerAccountDay},
		{"MANAGED_BUDGET_USD_PER_ACCOUNT_MONTH", c.ManagedBudgetUSDPerAccountMonth},
		{"MANAGED_BUDGET_USD_GLOBAL_DAY", c.ManagedBudgetUSDGlobalDay},
	} {
		if !(b.v > 0) || math.IsInf(b.v, 0) {
			return nil, fmt.Errorf("%s must be greater than 0", b.name)
		}
	}
	if v := strings.TrimSpace(os.Getenv("MANAGED_CLAIM_NOT_AFTER")); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return nil, fmt.Errorf("MANAGED_CLAIM_NOT_AFTER must be RFC 3339: %w", err)
		}
		c.ManagedClaimNotAfter = t.UTC()
	}
	for name, capUSD := range map[string]float64{
		"MANAGED_BUDGET_USD_PER_ACCOUNT_DAY":   c.ManagedBudgetUSDPerAccountDay,
		"MANAGED_BUDGET_USD_PER_ACCOUNT_MONTH": c.ManagedBudgetUSDPerAccountMonth,
		"MANAGED_BUDGET_USD_GLOBAL_DAY":        c.ManagedBudgetUSDGlobalDay,
	} {
		if c.ManagedMaxJobCostUSD > capUSD {
			return nil, fmt.Errorf("MANAGED_MAX_JOB_COST_USD must not exceed %s", name)
		}
	}
	if c.AssistantRegistryEnabled && c.MCTLSurfaceTelegramToken == "" {
		return nil, fmt.Errorf("ASSISTANT_REGISTRY_ENABLED requires MCTL_SURFACE_TELEGRAM_TOKEN")
	}
	if c.HumanInputEnabled {
		if !c.WorkContextEnabled {
			return nil, fmt.Errorf("HUMAN_INPUT_ENABLED requires WORK_CONTEXT_ENABLED=true")
		}
		if c.HumanInputPollInterval < MinHumanInputPollInterval {
			return nil, fmt.Errorf("HUMAN_INPUT_POLL_INTERVAL must be at least %s, got %s", MinHumanInputPollInterval, c.HumanInputPollInterval)
		}
	}
	if err := loadPA(c); err != nil {
		return nil, err
	}
	c.ToolFilter = envOr("MCP_TOOL_FILTER", "all")
	if c.OAUTHCIMDAdvertise && !c.OAUTHCIMDAccept {
		return nil, fmt.Errorf("OAUTH_CIMD_ADVERTISE=true requires OAUTH_CIMD_ACCEPT=true: advertising documents the server would refuse leaves CIMD clients with no DCR fallback")
	}
	if c.OAUTHCIMDAccept {
		hosts, err := cimd.ParseAllowedHosts(os.Getenv("OAUTH_CIMD_ALLOWED_HOSTS"))
		if err != nil {
			return nil, err
		}
		c.OAUTHCIMDAllowedHosts = hosts
	}
	if c.ToolFilter != "all" && c.ToolFilter != "read-only" {
		return nil, fmt.Errorf("MCP_TOOL_FILTER must be \"all\" or \"read-only\", got %q", c.ToolFilter)
	}
	// MCPPath must be an absolute path below the origin. A root value would
	// shadow the landing page and the root MCP alias: cmd/server/main.go
	// mounts the MCP handler at cfg.MCPPath and registers GET, POST and
	// DELETE on "/" separately, so "/" collapses them onto one route. A value
	// without a leading slash ("mcp") is just as unusable: chi's Mount panics
	// on a pattern that does not begin with '/', and main.go concatenates
	// MCPPath onto "/.well-known/oauth-protected-resource", which would yield
	// ".../oauth-protected-resourcemcp". Reject both at load rather than
	// silently normalising — matching the fail-closed posture above for
	// MCP_TOOL_FILTER and (below) ENCRYPTION_KEY.
	if !strings.HasPrefix(c.MCPPath, "/") || strings.Trim(c.MCPPath, "/") == "" {
		return nil, fmt.Errorf("MCP_PATH must be an absolute path below the origin (e.g. /mcp), got %q: "+
			"a root path would shadow the landing page and the root MCP alias, and a path "+
			"without a leading slash cannot be mounted", c.MCPPath)
	}
	// An access token is the credential an attacker gets to keep when one
	// leaks, and its TTL is the only thing bounding how long they keep it.
	// This variable had no ceiling, so a deployment could — and did — set
	// 8760h: tg-preview minted admin-scoped tokens valid for a year, one
	// escaped into chat logs and on-disk client configs, and nothing about
	// the config looked wrong because nothing checked it. Reject rather than
	// clamp, matching the fail-closed validation above: silently shortening
	// a lifetime an operator deliberately asked for would hide the mistake
	// instead of correcting it. Long-lived credentials have a separate,
	// bounded path (POST /api/agent/token, capped at maxAgentTokenTTL).
	if c.OAUTHAccessTokenTTL > maxOAUTHAccessTokenTTL {
		return nil, fmt.Errorf("OAUTH_ACCESS_TOKEN_TTL must not exceed %v, got %v — "+
			"clients renew silently with the refresh_token grant, so a long access "+
			"token buys nothing and only widens the window on a leak", maxOAUTHAccessTokenTTL, c.OAUTHAccessTokenTTL)
	}
	if c.OAUTHAccessTokenTTL <= 0 {
		return nil, fmt.Errorf("OAUTH_ACCESS_TOKEN_TTL must be positive, got %v", c.OAUTHAccessTokenTTL)
	}
	c.MediaDownloadMaxBytes = int64(envInt("MEDIA_DOWNLOAD_MAX_BYTES", 20971520))
	c.MediaUploadMaxBytes = int64(envInt("MEDIA_UPLOAD_MAX_BYTES", 20971520))
	c.BulkMediaByteCap = envInt64("BULK_MEDIA_BYTE_CAP", defaultBulkMediaByteCap)
	if c.BulkMediaByteCap <= 0 {
		slog.Warn("BULK_MEDIA_BYTE_CAP must be positive; falling back to the 8388608-byte default "+
			"(unlike MEDIA_DOWNLOAD_MAX_BYTES/MEDIA_TEXT_INLINE_CAP_BYTES, 0 here would silently skip every bulk media item instead of uncapping)",
			"bulk_media_byte_cap", c.BulkMediaByteCap)
		c.BulkMediaByteCap = defaultBulkMediaByteCap
	}
	c.MediaTextInlineCapBytes = envInt64("MEDIA_TEXT_INLINE_CAP_BYTES", defaultMediaTextInlineCapBytes)
	if c.MediaTextInlineCapBytes < 0 {
		slog.Warn("MEDIA_TEXT_INLINE_CAP_BYTES is negative; falling back to the 1048576-byte default "+
			"(set it to exactly 0 to explicitly opt into always inlining media base64 in the text block)",
			"media_text_inline_cap_bytes", c.MediaTextInlineCapBytes)
		c.MediaTextInlineCapBytes = defaultMediaTextInlineCapBytes
	}
	c.MediaMaxConcurrent = envInt("MEDIA_MAX_CONCURRENT", defaultMediaMaxConcurrent)
	if c.MediaMaxConcurrent < 0 {
		slog.Warn("MEDIA_MAX_CONCURRENT is negative; falling back to the default of 2 "+
			"(set it to exactly 0 to explicitly disable the media admission gate)",
			"media_max_concurrent", c.MediaMaxConcurrent)
		c.MediaMaxConcurrent = defaultMediaMaxConcurrent
	}
	c.OAUTHAllowedImplicitHosts = parseStringCSV(os.Getenv("OAUTH_ALLOWED_IMPLICIT_HOSTS"))
	preregistered, err := parsePreregisteredClients(os.Getenv("OAUTH_PREREGISTERED_CLIENTS"))
	if err != nil {
		return nil, fmt.Errorf("OAUTH_PREREGISTERED_CLIENTS: %w", err)
	}
	c.OAUTHPreregisteredClients = preregistered
	if c.OAUTHCIMDAccept {
		// With CIMD on, a URL-shaped client_id is resolved as a metadata
		// document before any registration is consulted, so a pre-registered
		// client of that shape would silently stop working.
		for _, pc := range preregistered {
			if cimd.IsCIMDURL(pc.ClientID) {
				return nil, fmt.Errorf("OAUTH_PREREGISTERED_CLIENTS: client_id %q is URL-shaped and would be resolved as a CIMD document while OAUTH_CIMD_ACCEPT is on; give it a non-URL client_id", pc.ClientID)
			}
		}
	}
	c.OAUTHDCRRedirectURIs = parseStringCSV(os.Getenv("OAUTH_DCR_REDIRECT_URIS"))
	profiles, err := toolprofile.ParseBindings(os.Getenv("MCP_CLIENT_PROFILES"))
	if err != nil {
		return nil, fmt.Errorf("MCP_CLIENT_PROFILES: %w", err)
	}
	c.ClientProfiles = *profiles
	c.AllowedOrigins = parseStringCSV(os.Getenv("ALLOWED_ORIGINS"))
	if len(c.AllowedOrigins) == 0 {
		if origin := originOf(c.PublicBaseURL); origin != "" {
			c.AllowedOrigins = []string{origin}
		} else {
			slog.Warn("ALLOWED_ORIGINS is empty and PUBLIC_BASE_URL has no parseable origin; "+
				"the /mcp Origin guard is disabled (all origins allowed)",
				"public_base_url", c.PublicBaseURL)
		}
	}
	c.TGLoginAdmins = parseInt64CSV(os.Getenv("TG_LOGIN_ADMINS"))
	c.SessionTTLExemptTGIDs = parseInt64CSV(os.Getenv("SESSION_TTL_EXEMPT_TG_IDS"))
	c.TGLoginClients = parseInt64CSV(os.Getenv("TG_LOGIN_CLIENTS"))
	c.TGLoginLookupAdmins = parseInt64CSV(os.Getenv("TG_LOGIN_LOOKUP_ADMINS"))
	c.BroadcastOperators = parseInt64CSV(os.Getenv("BROADCAST_OPERATORS"))
	c.TelegramOIDCSigningAlgs = parseStringCSV(os.Getenv("TELEGRAM_OIDC_SIGNING_ALGS"))

	if v := os.Getenv("TG_API_ID"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("TG_API_ID must be integer: %w", err)
		}
		c.TGAPIID = n
	}

	if v := os.Getenv("ENCRYPTION_KEY"); v != "" {
		if len(v) != 64 {
			return nil, fmt.Errorf("ENCRYPTION_KEY must be 64 hex chars (32 bytes), got %d chars", len(v))
		}
		decoded, err := hexDecode(v)
		if err != nil {
			return nil, fmt.Errorf("ENCRYPTION_KEY hex decode: %w", err)
		}
		c.EncryptionKey = decoded
	}
	if err := validatePAWiring(c); err != nil {
		return nil, err
	}
	if err := validateManagedRuntimeKey(c); err != nil {
		return nil, err
	}

	return c, nil
}

// validateManagedRuntimeKey refuses MANAGED_RUNTIME_ENABLED=true unless the
// key that signs and verifies its tokens is mctl-telegram's own (issue
// #1351). The managed runtime trusts two credentials: the claim-only
// agent-pool token, which claims jobs across every managed account, and the
// agent-job tokens a pool claim mints for those accounts. Both are signed with
// OAUTHJWTSecret. In shared-hmac that is api.mctl.ai's shared
// OAUTH_JWT_SECRET, and in local-jwt without OAUTH_JWT_SIGNING_KEY it is the
// legacy OAUTH_JWT_SECRET, historically that same shared value: either way a
// holder of the other service's secret could mint a pool token. The same rule
// as validatePAWiring; names the variables, never a value. With the managed
// runtime off nothing changes.
//
// OAUTHJWTSecretDedicated records where the key came from, not what it is,
// so a dedicated OAUTH_JWT_SIGNING_KEY that merely repeats the value of
// OAUTH_JWT_SECRET (the shared secret, copied over in a migration) is
// refused too. The comparison is constant-time and nothing is printed.
func validateManagedRuntimeKey(c *Config) error {
	if !c.ManagedRuntimeEnabled {
		return nil
	}
	if c.OAUTHJWTSecret == "" || !c.OAUTHJWTSecretDedicated {
		return errors.New("MANAGED_RUNTIME_ENABLED=true requires AUTH_MODE=local-jwt with OAUTH_JWT_SIGNING_KEY set: it signs the agent-pool and managed agent-job tokens, and no other service may hold that key (OAUTH_JWT_SECRET is not accepted)")
	}
	if legacy := os.Getenv("OAUTH_JWT_SECRET"); legacy != "" &&
		subtle.ConstantTimeCompare([]byte(legacy), []byte(c.OAUTHJWTSecret)) == 1 {
		return errors.New("MANAGED_RUNTIME_ENABLED=true requires OAUTH_JWT_SIGNING_KEY to differ from OAUTH_JWT_SECRET: an equal value is the shared secret under another name")
	}
	return nil
}

// validatePAWiring refuses an enabled PA without the two server secrets its
// run loop is built from (#1343): ENCRYPTION_KEY keys the conversation-state
// sealer (its own HKDF info keeps it apart from the session keys) and the
// OAuth signing key signs and verifies the pool and pa-job tokens. It runs
// after both are parsed, and names the variable, never its value. With the
// PA off neither is required by this check.
func validatePAWiring(c *Config) error {
	if !c.PAEnabled {
		return nil
	}
	if len(c.EncryptionKey) != 32 {
		return errors.New("PA_ENABLED=true requires ENCRYPTION_KEY (64 hex chars): it keys the PA conversation state")
	}
	// The PA's pool and pa-job tokens unlock principals' conversations, so
	// they must be signed with a key only this service holds: the dedicated
	// OAUTH_JWT_SIGNING_KEY in local-jwt mode. shared-hmac signs with
	// api.mctl.ai's shared secret, and local-jwt's legacy OAUTH_JWT_SECRET
	// fallback was historically that same secret.
	if c.OAUTHJWTSecret == "" || !c.OAUTHJWTSecretDedicated {
		return errors.New("PA_ENABLED=true requires AUTH_MODE=local-jwt with OAUTH_JWT_SIGNING_KEY set: it signs the PA worker and job tokens, and no other service may hold that key")
	}
	return nil
}

// jwtSigningKey resolves the HS256 key for OAuth/MCP JWTs, honouring AUTH_MODE.
//
// In local-jwt mode mctl-telegram signs its own tokens: the dedicated
// OAUTH_JWT_SIGNING_KEY is preferred, sourced from mctl-telegram's own Vault
// path. The legacy OAUTH_JWT_SECRET stays as a fallback for one transition
// window — historically it was wired to api.mctl.ai's shared secret, so a
// rotation in mctl-api would silently invalidate every mctl-telegram token.
//
// In shared-hmac(-legacy) mode the service VERIFIES tokens signed by
// api.mctl.ai, so the correct key is that service's shared OAUTH_JWT_SECRET —
// never the dedicated key. Preferring OAUTH_JWT_SIGNING_KEY there would break
// all authentication with "invalid JWT signature"; we use OAUTH_JWT_SECRET and
// warn loudly if a dedicated key was set by mistake (e.g. a partial rollout).
func jwtSigningKey(authMode string) string {
	dedicated := os.Getenv("OAUTH_JWT_SIGNING_KEY")
	legacy := os.Getenv("OAUTH_JWT_SECRET")
	switch strings.ToLower(authMode) {
	case "shared-hmac", "shared-hmac-legacy":
		if dedicated != "" {
			slog.Warn("OAUTH_JWT_SIGNING_KEY is set but AUTH_MODE is shared-hmac; " +
				"that mode verifies tokens signed by api.mctl.ai — using OAUTH_JWT_SECRET instead")
		}
		return legacy
	default:
		if dedicated != "" {
			return dedicated
		}
		if legacy != "" {
			slog.Warn("OAUTH_JWT_SECRET is deprecated; set OAUTH_JWT_SIGNING_KEY instead " +
				"(a dedicated mctl-telegram signing key, not the shared mctl-api secret)")
			return legacy
		}
		return ""
	}
}

func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

// TestDCFromEnv reads TG_TEST_DC the way every binary must (issue #854):
// cmd/server and cmd/login through Load, the Local Bridge directly. An
// unrecognised value is production, the safe reading for a flag whose wrong
// value revokes sessions.
func TestDCFromEnv() bool {
	return envBool("TG_TEST_DC", false)
}

// LocalTiers are the ENV values that explicitly name a developer machine or a
// test tier. cmd/server's boot guard builds its list from this one (adding
// the empty string), so the two cannot drift. TG_TEST_DC accepts only these:
// the production deployment leaves ENV unset, so an empty value proves
// nothing about the tier.
var LocalTiers = []string{"local", "local-dev", "localdev", "dev", "development", "test", "ci"}

// CheckTestDC refuses TG_TEST_DC=true unless ENV names a local or test tier
// explicitly, compared case-insensitively. Every process that writes or opens
// stored sessions calls it before opening the store: cmd/server and
// cmd/login, whose store may be the production database. A test-DC process
// on that store would revoke every session it touched (cmd/server), or stamp
// a still-empty production store test so production refuses to boot
// (cmd/login). The store's DC stamp (db.Store.EnsureDCMode) is the second,
// independent check.
func CheckTestDC(cfg *Config) error {
	if !cfg.TGTestDC {
		return nil
	}
	env := strings.TrimSpace(cfg.Environment)
	for _, name := range LocalTiers {
		if strings.EqualFold(env, name) {
			return nil
		}
	}
	return fmt.Errorf("refusing to start: TG_TEST_DC=true needs ENV set to a local or test tier (%s), got ENV=%q",
		strings.Join(LocalTiers, ", "), cfg.Environment)
}

// broadcastContentFromEnv reads BROADCAST_CONTENT_ENABLED. Unset or empty
// means on. A value envBool does not recognise ("off", "disabled", a typo)
// means off: this is a kill switch, so an operator who set it to anything
// other than a true value meant to turn the content off.
func broadcastContentFromEnv() bool {
	v, ok := os.LookupEnv("BROADCAST_CONTENT_ENABLED")
	if !ok || v == "" {
		return true
	}
	switch v {
	case "1", "true", "TRUE", "True", "yes":
		return true
	}
	return false
}

func envBool(key string, def bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok {
		return def
	}
	switch v {
	case "1", "true", "TRUE", "True", "yes":
		return true
	case "0", "false", "FALSE", "False", "no":
		return false
	default:
		return def
	}
}

func envInt(key string, def int) int {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func envInt64(key string, def int64) int64 {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return def
	}
	return n
}

func envFloat(key string, def float64) float64 {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return def
	}
	return f
}

func envDuration(key string, def time.Duration) time.Duration {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

func hexDecode(s string) ([]byte, error) {
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		hi, err := hexNib(s[i*2])
		if err != nil {
			return nil, err
		}
		lo, err := hexNib(s[i*2+1])
		if err != nil {
			return nil, err
		}
		out[i] = hi<<4 | lo
	}
	return out, nil
}

// parseInt64CSV splits a comma-separated list of integer ids, ignoring
// whitespace, empty entries, and non-numeric values (with a slog warning).
// Used for TG_LOGIN_ADMINS.
func parseInt64CSV(s string) []int64 {
	if s == "" {
		return nil
	}
	parts := []int64{}
	for _, raw := range splitTrim(s) {
		if raw == "" {
			continue
		}
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			continue
		}
		parts = append(parts, n)
	}
	return parts
}

// originOf returns the scheme://host[:port] origin of a base URL, matching the
// shape of a browser Origin header. Returns "" if rawURL has no scheme/host.
func originOf(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// parseStringCSV splits a comma-separated list, trimming whitespace and
// dropping empty entries. Used for TELEGRAM_OIDC_SIGNING_ALGS and ALLOWED_ORIGINS.
func parseStringCSV(s string) []string {
	if s == "" {
		return nil
	}
	out := []string{}
	for _, raw := range splitTrim(s) {
		if raw != "" {
			out = append(out, raw)
		}
	}
	return out
}

// splitTrim is strings.Split + TrimSpace per element. Kept private — the
// stdlib strings.Split is fine but the trim removes accidental newlines and
// blanks that K8s configmap multiline values often introduce.
func splitTrim(s string) []string {
	out := []string{}
	cur := []byte{}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ',' || c == '\n' {
			out = append(out, trimASCII(string(cur)))
			cur = cur[:0]
			continue
		}
		cur = append(cur, c)
	}
	if len(cur) > 0 {
		out = append(out, trimASCII(string(cur)))
	}
	return out
}

func trimASCII(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t' || s[0] == '\r') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

func hexNib(b byte) (byte, error) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', nil
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, nil
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, nil
	}
	return 0, fmt.Errorf("invalid hex char %q", b)
}

// PreregisteredClient is one static OAuth client record from
// OAUTH_PREREGISTERED_CLIENTS. RedirectURIs are matched byte-for-byte by
// the authorization server; there is no host allowlist, prefix or wildcard
// semantics for these records, so an operator pastes the callback exactly as
// the counterpart displays it.
type PreregisteredClient struct {
	ClientID     string   `json:"client_id"`
	ClientName   string   `json:"client_name,omitempty"`
	RedirectURIs []string `json:"redirect_uris"`
}

// parsePreregisteredClients decodes the OAUTH_PREREGISTERED_CLIENTS JSON
// array. It fails closed: a value that is present but malformed aborts
// startup rather than silently seeding nothing, because the operator who set
// the variable is relying on the client existing. Unknown keys are rejected
// so that a record carrying a field this contract does not support (a secret,
// say) is caught at boot instead of being ignored.
func parsePreregisteredClients(raw string) ([]PreregisteredClient, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	var out []PreregisteredClient
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if dec.More() {
		return nil, errors.New("trailing data after the JSON array")
	}
	seen := make(map[string]struct{}, len(out))
	for i := range out {
		rec := &out[i]
		rec.ClientID = strings.TrimSpace(rec.ClientID)
		if rec.ClientID == "" {
			return nil, fmt.Errorf("record %d: client_id is required", i)
		}
		if _, dup := seen[rec.ClientID]; dup {
			return nil, fmt.Errorf("record %d: duplicate client_id %q", i, rec.ClientID)
		}
		seen[rec.ClientID] = struct{}{}
		if len(rec.RedirectURIs) == 0 {
			return nil, fmt.Errorf("record %d (%s): redirect_uris must list at least one URI", i, rec.ClientID)
		}
		for j, u := range rec.RedirectURIs {
			u = strings.TrimSpace(u)
			if u == "" {
				return nil, fmt.Errorf("record %d (%s): redirect_uris[%d] is empty", i, rec.ClientID, j)
			}
			rec.RedirectURIs[j] = u
		}
	}
	return out, nil
}

var loginBotUsernameRE = regexp.MustCompile(`^[A-Za-z0-9_]{2,29}[Bb][Oo][Tt]$`)

// ValidLoginBotUsername reports whether s is a valid Telegram bot username:
// 5-32 characters of [A-Za-z0-9_], ending in "bot" (case-insensitive).
func ValidLoginBotUsername(s string) bool {
	return loginBotUsernameRE.MatchString(s)
}

// loginBotUsernameFromEnv reads TELEGRAM_LOGIN_BOT_USERNAME. Unset yields "";
// an invalid value is ignored with one warning rather than failing startup.
func loginBotUsernameFromEnv() string {
	v := strings.TrimPrefix(strings.TrimSpace(os.Getenv("TELEGRAM_LOGIN_BOT_USERNAME")), "@")
	if v == "" {
		return ""
	}
	if !ValidLoginBotUsername(v) {
		slog.Warn("TELEGRAM_LOGIN_BOT_USERNAME is not a valid Telegram bot username; ignoring it")
		return ""
	}
	return v
}

// parseReviewerWritePeers parses DEMO_REVIEWER_WRITE_PEERS. Blank is an empty
// list. Every entry must be "user:<id>", "chat:<id>" or "channel:<id>" with a
// positive decimal id written canonically (no sign, no leading zeros, no
// spaces inside the entry), so an entry names exactly one peer in one
// spelling. At send time internal/mcp's canonicalPeerRef normalises
// equivalent spellings of the requested id (user:+7001 is user:7001) before
// comparing, which widens the accepted spelling but never the set of ids,
// because telegram.ResolvePeer parses the id the same way. An empty
// entry ("a,,b", a trailing comma) is an error too: a list that does
// not say what it means is refused, not guessed.
func parseReviewerWritePeers(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var out []string
	for _, part := range strings.Split(raw, ",") {
		entry := strings.TrimSpace(part)
		kind, num, ok := strings.Cut(entry, ":")
		switch kind {
		case "user", "chat", "channel":
		default:
			ok = false
		}
		n, err := strconv.ParseInt(num, 10, 64)
		if !ok || err != nil || n <= 0 || strconv.FormatInt(n, 10) != num {
			return nil, fmt.Errorf("entry %q is not user:<id>, chat:<id> or channel:<id> with a positive id", entry)
		}
		out = append(out, entry)
	}
	return out, nil
}

// BotIDFromToken returns the numeric bot id (the digits before the first
// colon) of a Telegram bot token, or false when it is missing or not decimal.
func BotIDFromToken(token string) (string, bool) {
	id, _, found := strings.Cut(token, ":")
	if !found || id == "" {
		return "", false
	}
	for _, r := range id {
		if r < '0' || r > '9' {
			return "", false
		}
	}
	return id, true
}

// LoginBotMatchesOIDCClient reports whether the login bot token belongs to the
// same bot as the OIDC client id. When it does not, reason is one of
// bot_token_unset, bot_token_malformed or bot_id_mismatch. The reason never
// contains the token.
func (c *Config) LoginBotMatchesOIDCClient() (bool, string) {
	if c.TelegramLoginBotToken == "" {
		return false, "bot_token_unset"
	}
	id, ok := BotIDFromToken(c.TelegramLoginBotToken)
	if !ok {
		return false, "bot_token_malformed"
	}
	if id != strings.TrimSpace(c.TelegramOIDCClientID) {
		return false, "bot_id_mismatch"
	}
	return true, ""
}

// ParseDigestWeekday maps DIGEST_WEEKDAY to a weekday. ok is false for the
// empty value (daily digest). A name that is not a weekday is an error, never
// a silent fall back to daily.
func ParseDigestWeekday(v string) (day time.Weekday, ok bool, err error) {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return 0, false, nil
	}
	for d := time.Sunday; d <= time.Saturday; d++ {
		name := strings.ToLower(d.String())
		if v == name || v == name[:3] {
			return d, true, nil
		}
	}
	return 0, false, fmt.Errorf("DIGEST_WEEKDAY must be empty or a weekday (mon..sun), got %q", v)
}

// parseStrictInt64CSV parses a comma-separated list of Telegram ids and
// rejects any malformed entry, so a typo stops startup instead of silently
// dropping a recipient.
func parseStrictInt64CSV(s string) ([]int64, error) {
	var out []int64
	for _, raw := range splitTrim(s) {
		if raw == "" {
			continue
		}
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("invalid Telegram id %q", raw)
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil, errors.New("no Telegram ids in the list")
	}
	return out, nil
}

// defaultK8sSAIssuer is the service-account token issuer of a cluster that
// keeps the Kubernetes default (--service-account-issuer).
const defaultK8sSAIssuer = "https://kubernetes.default.svc.cluster.local"

// loadK8sSA reads MCP_K8S_SA_*. Setting any of them without the subject, or
// the subject without the rest, is a startup error rather than a silently
// disabled probe path.
func loadK8sSA(c *Config) error {
	c.K8sSASubject = strings.TrimSpace(os.Getenv("MCP_K8S_SA_SUBJECT"))
	c.K8sSAAudience = strings.TrimSpace(os.Getenv("MCP_K8S_SA_AUDIENCE"))
	c.K8sSAIssuer = strings.TrimSpace(os.Getenv("MCP_K8S_SA_ISSUER"))
	rawID := strings.TrimSpace(os.Getenv("MCP_K8S_SA_TELEGRAM_ID"))
	if c.K8sSASubject == "" {
		if c.K8sSAAudience != "" || c.K8sSAIssuer != "" || rawID != "" {
			return errors.New("MCP_K8S_SA_AUDIENCE/ISSUER/TELEGRAM_ID are set but MCP_K8S_SA_SUBJECT is not")
		}
		return nil
	}
	if c.K8sSAIssuer == "" {
		c.K8sSAIssuer = defaultK8sSAIssuer
	}
	if c.K8sSAAudience == "" {
		return errors.New("MCP_K8S_SA_AUDIENCE is required with MCP_K8S_SA_SUBJECT")
	}
	if c.K8sSAAudience == c.K8sSAIssuer || strings.Contains(c.K8sSAAudience, "kubernetes.default.svc") {
		return fmt.Errorf("MCP_K8S_SA_AUDIENCE %q looks like the API server's own audience; use a dedicated one", c.K8sSAAudience)
	}
	id, err := strconv.ParseInt(rawID, 10, 64)
	if err != nil || id <= 0 {
		return fmt.Errorf("MCP_K8S_SA_TELEGRAM_ID must be a positive integer, got %q", rawID)
	}
	if !c.CanaryTelegramIDs.Contains(id) {
		return fmt.Errorf("MCP_K8S_SA_TELEGRAM_ID %d must be listed in CANARY_TELEGRAM_IDS", id)
	}
	c.K8sSATelegramID = id
	return nil
}

// PAWebhookPath is pa.WebhookPath. config does not import internal/pa
// (internal/pa imports config for ValidPAWebhookSecret);
// pa.TestWebhookPathMatchesConfig keeps the two equal.
const PAWebhookPath = "/pa/bot/webhook"

// validatePAWebhookURL accepts an absolute https URL with a host, the PA
// webhook path, and no userinfo, query or fragment. The value is never
// echoed in the error.
func validatePAWebhookURL(raw string) error {
	if raw == "" {
		return errors.New("not set")
	}
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		return errors.New("not a url")
	case u.Scheme != "https":
		return errors.New("must be https")
	case u.Hostname() == "":
		return errors.New("no host")
	case u.User != nil:
		return errors.New("userinfo is not allowed")
	case u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(raw, "?#"):
		return errors.New("query and fragment are not allowed")
	case u.Path != PAWebhookPath:
		return errors.New("path must be " + PAWebhookPath)
	}
	return nil
}
