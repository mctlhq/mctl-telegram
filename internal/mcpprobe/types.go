package mcpprobe

import "time"

// Mode selects which mctl-telegram MCP protocol era a run probes. The two
// modes are separate code paths with separate results; there is no implicit
// fallback from one to the other (requirements.md acceptance criterion B).
type Mode string

const (
	// ModeModern probes the stateless protocol core (>= 2026-07-28).
	ModeModern Mode = "modern"
	// ModeLegacy probes the pre-2026-07-28 initialize/session lifecycle.
	ModeLegacy Mode = "legacy"
)

// EvidenceSource labels which row of the three-row compatibility matrix
// (design.md section 3) a Report belongs to.
type EvidenceSource string

const (
	// EvidenceInProcessCurrentMain is CI/in-process httptest evidence around
	// the real handler wiring. This is the only row this package's own tests
	// generate; it must never be mislabeled as live evidence.
	EvidenceInProcessCurrentMain EvidenceSource = "in-process-current-main"
	// EvidenceDirectDeployed is an operator run against a preview or
	// tg.mctl.ai deployment.
	EvidenceDirectDeployed EvidenceSource = "direct-deployed"
	// EvidenceCloudflarePortal is an operator run through the configured
	// Cloudflare Portal.
	EvidenceCloudflarePortal EvidenceSource = "cloudflare-portal"
)

// PendingOperator is the sentinel recorded in Report.Pending for a row that
// requires a bounded operator run this package cannot perform unattended
// (direct-deployed, cloudflare-portal) and that has not been run yet.
const PendingOperator = "PENDING-OPERATOR"

// Defaults for the values an operator may otherwise leave unconfigured.
const (
	// DefaultModernProtocolVersion is the modern protocol version probed
	// when Config.ProtocolVersion is empty and Config.Mode is ModeModern.
	DefaultModernProtocolVersion = "2026-07-28"
	// DefaultLegacyProtocolVersion is the legacy protocol version probed
	// when Config.ProtocolVersion is empty and Config.Mode is ModeLegacy.
	DefaultLegacyProtocolVersion = "2024-11-05"
	// DefaultReadOnlyTool is the tools/call target used when
	// Config.ReadOnlyTool is empty. It must carry readOnlyHint=true; the
	// probe refuses to call it otherwise (see readOnlyGuard).
	DefaultReadOnlyTool = "get_my_send_status"
	// DefaultMCPPath is the MCP endpoint path used when Config.MCPPath is
	// empty, matching mctl-telegram's own default (MCP_PATH env var).
	DefaultMCPPath = "/mcp"
	// defaultClientName/defaultClientVersion identify this probe in the
	// modern per-request _meta clientInfo and the legacy initialize
	// clientInfo. Self-reported and unverified, matching every other MCP
	// client's clientInfo.
	defaultClientName    = "mctl-telegram-mcpprobe"
	defaultClientVersion = "dev"
)

// Report is the structurally redacted output of one probe Run. See the
// package doc for the redaction guarantee this type embodies.
type Report struct {
	// EvidenceSource labels which row of the compatibility matrix this
	// report is. Required.
	EvidenceSource EvidenceSource `json:"evidence_source"`
	// Label is an operator-supplied, human-readable description of the
	// target (e.g. "tg.mctl.ai direct", "cloudflare portal preview"). It
	// must never itself be or contain a secret; callers are responsible for
	// that, exactly as they are for BuildRef.
	Label string `json:"label,omitempty"`
	// Timestamp is when the report was generated, UTC.
	Timestamp time.Time `json:"timestamp"`
	// BuildRef identifies the code under test (e.g. a git SHA or image tag),
	// when known.
	BuildRef string `json:"build_ref,omitempty"`

	// Modern holds the modern-mode observations, when this report probed
	// ModeModern.
	Modern *ModernResult `json:"modern,omitempty"`
	// Legacy holds the legacy-mode observations, when this report probed
	// ModeLegacy.
	Legacy *LegacyResult `json:"legacy,omitempty"`
	// OAuth holds the OAuth metadata / 401-challenge observations. Present
	// regardless of Mode: OAuth surface is protocol-mode-independent.
	OAuth *OAuthResult `json:"oauth,omitempty"`

	// Pending is set to PendingOperator, instead of populating Modern/
	// Legacy/OAuth, for a row this run did not execute (bounded operator
	// evidence not yet collected). See NewPendingReport.
	Pending string `json:"pending,omitempty"`
}

// NewPendingReport builds a Report for a row that requires a bounded
// operator run this package has not performed yet (design.md section 3:
// direct-deployed and cloudflare-portal rows may be PENDING-OPERATOR).
func NewPendingReport(evidence EvidenceSource, mode Mode, label string) *Report {
	return &Report{
		EvidenceSource: evidence,
		Label:          label,
		Timestamp:      time.Now().UTC(),
		Pending:        PendingOperator,
	}
}

// ToolSummary is the redacted subset of one tools/list entry: enough to
// prove the read-only guard's decision, never the tool's input schema or any
// server-side description text that might carry deployment-specific detail.
type ToolSummary struct {
	Name         string `json:"name"`
	ReadOnlyHint *bool  `json:"read_only_hint,omitempty"`
}

// NegativeCase records one deliberate protocol-error probe: a call this
// package expects the server to reject, and whether it did.
type NegativeCase struct {
	// Name identifies the negative scenario, e.g. "initialize is a removed
	// method" or "missing Mcp-Method header".
	Name string `json:"name"`
	// HTTPStatus is the HTTP status the server returned.
	HTTPStatus int `json:"http_status"`
	// JSONRPCErrorCode is the JSON-RPC error code returned, 0 when the
	// response carried no error object.
	JSONRPCErrorCode int `json:"jsonrpc_error_code,omitempty"`
	// Rejected is true when the response matched the expected rejection
	// shape for this scenario (the specific code checked is scenario
	// dependent; see modern.go).
	Rejected bool `json:"rejected"`
}

// DiscoverObservation records one server/discover call.
type DiscoverObservation struct {
	HTTPStatus        int      `json:"http_status"`
	JSONRPCErrorCode  int      `json:"jsonrpc_error_code,omitempty"`
	SupportedVersions []string `json:"supported_versions,omitempty"`
	ServerName        string   `json:"server_name,omitempty"`
	ServerVersion     string   `json:"server_version,omitempty"`
	// SessionIDPresent/SessionIDLength record whether the response carried
	// Mcp-Session-Id and how long it was -- never the value. The expected
	// modern behavior is SessionIDPresent=false; this is an observation, not
	// an assertion (requirements.md acceptance criterion A).
	SessionIDPresent bool `json:"session_id_present"`
	SessionIDLength  int  `json:"session_id_length,omitempty"`
}

// ToolsListObservation records one modern tools/list call.
type ToolsListObservation struct {
	HTTPStatus       int           `json:"http_status"`
	JSONRPCErrorCode int           `json:"jsonrpc_error_code,omitempty"`
	ToolCount        int           `json:"tool_count"`
	Tools            []ToolSummary `json:"tools,omitempty"`
	SessionIDPresent bool          `json:"session_id_present"`
	SessionIDLength  int           `json:"session_id_length,omitempty"`
}

// ToolCallObservation records the one guarded tools/call this package will
// ever issue, or the refusal when the guard did not clear it.
type ToolCallObservation struct {
	ToolName string `json:"tool_name"`
	// Attempted is false when the read-only guard refused the call; see
	// RefusalReason.
	Attempted        bool   `json:"attempted"`
	RefusalReason    string `json:"refusal_reason,omitempty"`
	HTTPStatus       int    `json:"http_status,omitempty"`
	IsError          bool   `json:"is_error,omitempty"`
	JSONRPCErrorCode int    `json:"jsonrpc_error_code,omitempty"`
	SessionIDPresent bool   `json:"session_id_present"`
	SessionIDLength  int    `json:"session_id_length,omitempty"`
}

// ModernResult is the full set of modern-mode (>= 2026-07-28) observations.
type ModernResult struct {
	ProtocolVersion string `json:"protocol_version"`

	Discover  *DiscoverObservation  `json:"discover,omitempty"`
	ToolsList *ToolsListObservation `json:"tools_list,omitempty"`
	ToolCall  *ToolCallObservation  `json:"tool_call,omitempty"`

	// InitializeRemovedMethod is the negative test required by
	// requirements.md acceptance criterion A: `initialize` must never be
	// used to bootstrap a modern request, only probed as an expected
	// removed-method rejection.
	InitializeRemovedMethod *NegativeCase `json:"initialize_removed_method,omitempty"`
	// HeaderNegativeTests are the missing/mismatched Mcp-Method / Mcp-Name /
	// Mcp-Protocol-Version cases (tasks.md task 4).
	HeaderNegativeTests []NegativeCase `json:"header_negative_tests,omitempty"`
}

// LegacyInitializeObservation records the legacy initialize handshake.
type LegacyInitializeObservation struct {
	HTTPStatus                int    `json:"http_status"`
	NegotiatedProtocolVersion string `json:"negotiated_protocol_version,omitempty"`
	SessionIDMinted           bool   `json:"session_id_minted"`
	SessionIDLength           int    `json:"session_id_length,omitempty"`
}

// LegacyCallObservation records one legacy tools/list or tools/call made
// with the session id from LegacyInitializeObservation.
type LegacyCallObservation struct {
	Attempted        bool   `json:"attempted"`
	RefusalReason    string `json:"refusal_reason,omitempty"`
	HTTPStatus       int    `json:"http_status,omitempty"`
	IsError          bool   `json:"is_error,omitempty"`
	JSONRPCErrorCode int    `json:"jsonrpc_error_code,omitempty"`
	ToolCount        int    `json:"tool_count,omitempty"`
	// SessionIDRequired records whether the same call made WITHOUT the
	// session id was refused -- the evidence for "session id required",
	// distinct from merely "minted".
	SessionIDRequired bool `json:"session_id_required"`
}

// LegacyResult is the full set of legacy-mode observations. Legacy and
// modern results are never combined into one session_required boolean
// without this mode label (requirements.md acceptance criterion B).
type LegacyResult struct {
	ProtocolVersion string `json:"protocol_version"`

	Initialize *LegacyInitializeObservation `json:"initialize,omitempty"`
	ToolsList  *LegacyCallObservation       `json:"tools_list,omitempty"`
	ToolCall   *LegacyCallObservation       `json:"tool_call,omitempty"`
}

// Challenge401 classifies an unauthenticated 401 response's WWW-Authenticate
// challenge, without ever recording the bearer token that was absent.
type Challenge401 struct {
	HTTPStatus               int  `json:"http_status"`
	HasWWWAuthenticateHeader bool `json:"has_www_authenticate_header"`
	HasResourceMetadataParam bool `json:"has_resource_metadata_param"`
	WWWAuthenticateIsBearer  bool `json:"www_authenticate_is_bearer"`
}

// OAuthResult is the OAuth metadata / 401-challenge probe (requirements.md
// acceptance criterion E and F's public-client compatibility gate).
type OAuthResult struct {
	ProtectedResourceHTTPStatus   int      `json:"protected_resource_http_status,omitempty"`
	AuthorizationServerHTTPStatus int      `json:"authorization_server_http_status,omitempty"`
	Issuer                        string   `json:"issuer,omitempty"`
	TokenEndpointAuthMethods      []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	// PublicClientPKCECompatible is true when token_endpoint_auth_methods
	// includes "none" -- the contract requirements.md acceptance criterion E
	// requires the spike to verify explicitly.
	PublicClientPKCECompatible bool `json:"public_client_pkce_compatible"`

	Unauthenticated401 *Challenge401 `json:"unauthenticated_401,omitempty"`

	// AuthenticatedProbeSkipped is true when no bearer token was configured:
	// OAuth metadata and the unauthenticated challenge check still ran (see
	// Unauthenticated401 above), but any bearer-gated cell was skipped
	// rather than attempted (requirements.md acceptance criterion C).
	AuthenticatedProbeSkipped bool `json:"authenticated_probe_skipped"`
}
