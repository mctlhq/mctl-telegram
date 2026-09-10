package mcpprobe

import (
	"log/slog"
	"time"
)

// ReportSchema versions the on-disk/on-issue shape of a Report so a consumer
// can tell an old artifact from a new one.
const ReportSchema = "mctl-mcpprobe/1"

// Outcome is the verdict of a step or of a whole run. The set is closed on
// purpose: a run that could not be measured says PENDING or SKIPPED rather
// than borrowing the colour of a result it did not obtain.
type Outcome string

const (
	// OutcomePass means the step behaved as the protocol requires.
	OutcomePass Outcome = "PASS"
	// OutcomeFail means the step was measured and did not.
	OutcomeFail Outcome = "FAIL"
	// OutcomeSkipped means the step was deliberately not attempted, e.g. a
	// tool call whose target is not annotated read-only.
	OutcomeSkipped Outcome = "SKIPPED"
	// OutcomePending means the evidence requires an operator with credentials
	// or configuration this run did not have.
	OutcomePending Outcome = "PENDING-OPERATOR"
	// OutcomeBlocked means a prerequisite is known to be unsatisfiable, so
	// the step will not become measurable by retrying it.
	OutcomeBlocked Outcome = "BLOCKED"
)

// Reason is a closed vocabulary explaining an outcome. It is an enum rather
// than free text because the alternative — echoing the server's error
// message — is how a chat title, a peer identifier or a token fragment ends
// up in a report that gets pasted into a public issue.
type Reason string

const (
	ReasonNone                 Reason = ""
	ReasonTransport            Reason = "transport-error"
	ReasonHTTPStatus           Reason = "unexpected-http-status"
	ReasonMalformedBody        Reason = "malformed-body"
	ReasonJSONRPCError         Reason = "jsonrpc-error"
	ReasonMethodNotFound       Reason = "method-not-found"
	ReasonHeaderMismatch       Reason = "header-mismatch"
	ReasonUnexpectedSuccess    Reason = "unexpected-success"
	ReasonToolNotListed        Reason = "tool-not-listed"
	ReasonToolNotReadOnly      Reason = "tool-not-read-only"
	ReasonToolReportedError    Reason = "tool-reported-error"
	ReasonNoSessionID          Reason = "no-session-id"
	ReasonPrerequisiteFailed   Reason = "prerequisite-failed"
	ReasonNotApplicable        Reason = "not-applicable"
	ReasonOperatorRunRequired  Reason = "operator-run-required"
	ReasonUnauthenticatedProbe Reason = "unauthenticated-probe"
)

// Report is the whole result of a run.
//
// Every field below is a label, a number, a boolean or a closed enum. There
// is deliberately no field typed json.RawMessage, map[string]any, any or
// []byte anywhere in this type or its children: a value the server chose —
// a tool result, an error message, a session identifier — has nowhere to go.
// That is what makes the redaction guarantee structural. A change that adds
// such a field will be caught by the reflection guard in report_test.go.
type Report struct {
	Schema          string       `json:"schema"`
	Timestamp       time.Time    `json:"timestamp"`
	GitRef          string       `json:"git_ref,omitempty"`
	Source          Source       `json:"source"`
	Mode            Mode         `json:"mode"`
	ProtocolVersion string       `json:"protocol_version"`
	TargetHost      string       `json:"target_host"`
	Summary         Outcome      `json:"summary"`
	Server          ServerInfo   `json:"server"`
	Tools           []ToolInfo   `json:"tools,omitempty"`
	Session         SessionInfo  `json:"session"`
	Steps           []Step       `json:"steps"`
	Negatives       []Step       `json:"negatives,omitempty"`
	OAuth           *OAuthReport `json:"oauth,omitempty"`
}

// ServerInfo is the identity a server volunteered about itself.
type ServerInfo struct {
	Name              string   `json:"name,omitempty"`
	Version           string   `json:"version,omitempty"`
	SupportedVersions []string `json:"supported_versions,omitempty"`
}

// ToolInfo is one entry of tools/list, reduced to what a compatibility
// decision needs. ReadOnly is a pointer so "the server said false" and "the
// server said nothing" stay distinguishable — the difference decides whether
// the probe is allowed to call it.
type ToolInfo struct {
	Name     string `json:"name"`
	ReadOnly *bool  `json:"read_only,omitempty"`
}

// SessionInfo records what happened to Mcp-Session-Id. The identifier itself
// is never stored; its presence and length are enough to tell a minted
// session from an absent one.
type SessionInfo struct {
	HeaderPresent bool `json:"header_present"`
	IDLength      int  `json:"id_length"`
	// Required reports whether a later request is refused when the header is
	// absent entirely.
	Required *bool `json:"required,omitempty"`
	// ForeignAccepted reports whether a well-formed identifier the server
	// never issued is accepted. Together with Required it separates the two
	// questions a router in front of the server actually has: whether the
	// header must be carried through at all, and whether a given request has
	// to reach the same process that issued it. A server that requires the
	// header but accepts any well-formed value needs the first and not the
	// second.
	ForeignAccepted *bool `json:"foreign_accepted,omitempty"`
}

// Step is one probed interaction.
type Step struct {
	Label      string  `json:"label"`
	Method     string  `json:"method,omitempty"`
	Tool       string  `json:"tool,omitempty"`
	HTTPStatus int     `json:"http_status,omitempty"`
	JSONRPCode *int    `json:"jsonrpc_code,omitempty"`
	IsError    *bool   `json:"is_error,omitempty"`
	Outcome    Outcome `json:"outcome"`
	Reason     Reason  `json:"reason,omitempty"`
}

// OAuthReport is the authorization surface as an unauthenticated caller sees
// it. It records which token endpoint authentication methods the server
// advertises without naming any of them in this package's source, so a guard
// test can assert the probe introduces no credential handling of its own.
type OAuthReport struct {
	ProtectedResource     MetadataProbe   `json:"protected_resource"`
	ProtectedResourcePath MetadataProbe   `json:"protected_resource_path_variant"`
	AuthorizationServer   AuthServerProbe `json:"authorization_server"`
	Unauthenticated       ChallengeProbe  `json:"unauthenticated"`
}

// MetadataProbe is one metadata document fetch.
type MetadataProbe struct {
	HTTPStatus               int     `json:"http_status"`
	ResourcePresent          bool    `json:"resource_present"`
	AuthorizationServerCount int     `json:"authorization_servers_count"`
	ScopesCount              int     `json:"scopes_count"`
	Outcome                  Outcome `json:"outcome"`
	Reason                   Reason  `json:"reason,omitempty"`
}

// AuthServerProbe is the authorization-server metadata document.
//
// TokenEndpointAuthMethods echoes the advertised list verbatim because that
// is the fact an operator needs; SupportsNone and SecretRequired classify it
// structurally so callers need not string-match on credential vocabulary.
type AuthServerProbe struct {
	HTTPStatus               int      `json:"http_status"`
	Issuer                   string   `json:"issuer,omitempty"`
	AuthorizationEndpoint    bool     `json:"authorization_endpoint_present"`
	TokenEndpoint            bool     `json:"token_endpoint_present"`
	RegistrationEndpoint     bool     `json:"registration_endpoint_present"`
	TokenEndpointAuthMethods []string `json:"token_endpoint_auth_methods,omitempty"`
	SupportsPublicClient     bool     `json:"supports_public_client"`
	RequiresClientCredential bool     `json:"requires_client_credential"`
	PKCES256                 bool     `json:"pkce_s256"`
	Outcome                  Outcome  `json:"outcome"`
	Reason                   Reason   `json:"reason,omitempty"`
}

// ChallengeProbe is the response to a deliberately unauthenticated request.
type ChallengeProbe struct {
	HTTPStatus              int     `json:"http_status"`
	BearerScheme            bool    `json:"bearer_scheme"`
	Realm                   string  `json:"realm,omitempty"`
	ResourceMetadataPresent bool    `json:"resource_metadata_present"`
	ResourceMetadataMatches bool    `json:"resource_metadata_matches_path_variant"`
	ErrorCode               string  `json:"error,omitempty"`
	Outcome                 Outcome `json:"outcome"`
	Reason                  Reason  `json:"reason,omitempty"`
}

// LogValue mirrors the whitelist above for structured logging, so a report
// logged at any level carries the same bounded set of fields as one written
// to a file. Without it slog would reflect over the struct and the guarantee
// would depend on the type staying frozen.
func (r *Report) LogValue() slog.Value {
	if r == nil {
		return slog.Value{}
	}
	return slog.GroupValue(
		slog.String("schema", r.Schema),
		slog.Time("timestamp", r.Timestamp),
		slog.String("source", string(r.Source)),
		slog.String("mode", string(r.Mode)),
		slog.String("protocol_version", r.ProtocolVersion),
		slog.String("target_host", r.TargetHost),
		slog.String("summary", string(r.Summary)),
		slog.String("server_name", r.Server.Name),
		slog.String("server_version", r.Server.Version),
		slog.Int("tool_count", len(r.Tools)),
		slog.Bool("session_header_present", r.Session.HeaderPresent),
		slog.Int("session_id_length", r.Session.IDLength),
		slog.Int("step_count", len(r.Steps)),
		slog.Int("negative_count", len(r.Negatives)),
	)
}

// addStep appends a step and returns it, so callers can read back the
// outcome they just recorded.
func (r *Report) addStep(s Step) Step {
	r.Steps = append(r.Steps, s)
	return s
}

func (r *Report) addNegative(s Step) {
	r.Negatives = append(r.Negatives, s)
}

// mandatorySteps lists the step labels a mode must actually produce for a
// run to be eligible for PASS. Aggregation is fail-closed against this list:
// a cell that never executed is not evidence of anything, and a report that
// silently omitted it must not be able to claim the same verdict as one that
// ran it and passed.
func mandatorySteps(mode Mode) []string {
	switch mode {
	case ModeModern:
		return []string{"discover", "tools_list", "tools_call_readonly"}
	case ModeLegacy:
		return []string{"initialize", "tools_list", "tools_call_readonly"}
	}
	return nil
}

// mandatoryNegatives lists the negative probes a modern run must produce.
// Enforcement of the modern binding is the point of the modern row; a run
// that skipped these measured tolerance, not conformance.
func mandatoryNegatives(mode Mode) []string {
	if mode != ModeModern {
		return nil
	}
	return []string{
		"modern_initialize_removed",
		"missing_protocol_version_header",
		"missing_method_header",
		"mismatched_method_header",
		"missing_name_header",
		"mismatched_name_header",
	}
}

// outcomeRank orders verdicts from strongest to weakest claim. finalize
// carries up the weakest one present, so a single measured failure fails the
// run and a single unexecuted cell keeps it out of PASS.
var outcomeRank = map[Outcome]int{
	OutcomePass:    0,
	OutcomeSkipped: 1,
	OutcomePending: 2,
	OutcomeBlocked: 3,
	OutcomeFail:    4,
}

// finalize computes the run verdict, fail-closed.
//
// PASS requires two things, not one: every mandatory cell for this mode is
// present in the report, and nothing recorded anything weaker than PASS. A
// missing mandatory cell yields PENDING-OPERATOR — the honest statement that
// the measurement was not taken — rather than borrowing the colour of the
// cells that did run.
func (r *Report) finalize() {
	worst := OutcomePass
	consider := func(o Outcome) {
		// An outcome the enum does not name — the zero value above all —
		// counts as a failure, because a map miss would otherwise return
		// PASS's rank and an outcome nobody set would aggregate exactly like
		// a pass. It is normalised to OutcomeFail rather than carried up as
		// itself: Summary must stay inside the closed set the type
		// documents, and ranking the unnamed value above FAIL would let one
		// forgotten field outrank a real measured failure and report it as
		// "nothing was measured" — the inverse of the distinction the exit
		// codes exist to make.
		if _, named := outcomeRank[o]; !named {
			o = OutcomeFail
		}
		if outcomeRank[o] > outcomeRank[worst] {
			worst = o
		}
	}

	present := make(map[string]Outcome, len(r.Steps)+len(r.Negatives))
	for _, s := range r.Steps {
		present[s.Label] = s.Outcome
		consider(s.Outcome)
	}
	for _, s := range r.Negatives {
		present[s.Label] = s.Outcome
		consider(s.Outcome)
	}
	if r.OAuth != nil {
		consider(r.OAuth.ProtectedResource.Outcome)
		consider(r.OAuth.ProtectedResourcePath.Outcome)
		consider(r.OAuth.AuthorizationServer.Outcome)
		consider(r.OAuth.Unauthenticated.Outcome)
	}

	for _, label := range mandatorySteps(r.Mode) {
		if _, ok := present[label]; !ok {
			consider(OutcomePending)
		}
	}
	for _, label := range mandatoryNegatives(r.Mode) {
		if _, ok := present[label]; !ok {
			consider(OutcomePending)
		}
	}

	r.Summary = worst
}

// stepOutcome returns the recorded outcome for a label, or "" when the step
// is absent.
func stepOutcome(r *Report, label string) Outcome {
	for _, s := range r.Steps {
		if s.Label == label {
			return s.Outcome
		}
	}
	return ""
}

// boolPtr is a local helper; the report uses pointers wherever "unset" and
// "false" mean different things.
func boolPtr(b bool) *bool { return &b }

func intPtr(i int) *int { return &i }
