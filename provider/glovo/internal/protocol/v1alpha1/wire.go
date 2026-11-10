// Package v1alpha1 is the provider side of the mctl-api command bridge wire.
// The schemas under schema/ are byte copies of mctl-api internal/bridge/schema
// (v1alpha1) and mctl-agents docs/contracts/bridge/v1alpha2 and are never
// edited here. The one v1alpha2 command this provider understands is
// place_order_fake; its answer is the unchanged v1alpha1 result.
package v1alpha1

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed schema/command.schema.json schema/result.schema.json schema/PROVENANCE schema/v1alpha2/*.json schema/v1alpha2/PROVENANCE schema/v1alpha2/SHA256SUMS
var schemaFS embed.FS

// Wire versions.
const (
	Version      = "bridge.mctl.ai/v1alpha1"
	VersionV2    = "bridge.mctl.ai/v1alpha2"
	ClaimVersion = Version
	ClaimV2      = "bridge.mctl.ai/claim/v1alpha2"
)

// Command kinds.
const (
	KindQuote       = "quote"
	KindPlaceOrder  = "place_order_fake"
	KindCancelOrder = "cancel_order_fake"
	KindReadStatus  = "read_status"
)

// Result enums (result.schema.json).
const (
	OutcomeSucceeded       = "succeeded"
	OutcomeFailedRetryable = "failed_retryable"
	OutcomeFailedTerminal  = "failed_terminal"
	OutcomeCancelled       = "cancelled"
	OutcomeApprovalRefused = "approval_refused"

	EffectNone    = "none"
	EffectApplied = "applied"
	EffectUnknown = "unknown"

	ErrNone                = "none"
	ErrApprovalRefused     = "approval_refused"
	ErrProviderUnavailable = "provider_unavailable"
	ErrProviderRejected    = "provider_rejected"
	ErrInternal            = "internal"
)

// MaxClaimCommands is the claim batch ceiling of the bridge.
const MaxClaimCommands = 10

// ErrInvalid is returned for a document the schemas or the strict decoder refuse.
var ErrInvalid = errors.New("v1alpha1: invalid document")

// Payload is the v1alpha1 command payload.
type Payload struct {
	ItemCodes     []string `json:"item_codes,omitempty"`
	QuantityTotal *int     `json:"quantity_total,omitempty"`
	Note          string   `json:"note,omitempty"`
}

// BasketLine is one line of the v1alpha2 approval basket.
type BasketLine struct {
	ItemCode       string `json:"item_code"`
	Quantity       int    `json:"quantity"`
	UnitPriceMinor int    `json:"unit_price_minor"`
}

// Basket is the v1alpha2 approval basket (the payload of place_order_fake).
type Basket struct {
	V                string       `json:"v"`
	StoreRef         string       `json:"store_ref"`
	Currency         string       `json:"currency"`
	Lines            []BasketLine `json:"lines"`
	SubtotalMinor    int          `json:"subtotal_minor"`
	DeliveryFeeMinor int          `json:"delivery_fee_minor"`
	ServiceFeeMinor  int          `json:"service_fee_minor"`
	DiscountMinor    int          `json:"discount_minor"`
	TotalMinor       int          `json:"total_minor"`
}

// Command is a parsed, schema-valid bridge command. Basket is set only for a
// v1alpha2 place_order_fake; Payload only for v1alpha1.
type Command struct {
	SchemaVersion   string
	CommandID       string
	ExecutionID     string
	WorkItemID      string
	Kind            string
	Attempt         int
	TenantRef       string
	PrincipalRef    string
	OrderRef        string
	ConnectionRef   string
	ApprovalRef     string
	IntentHash      string
	Issuer          string
	Audience        string
	Nonce           string
	IssuedAt        string
	ExpiresAt       string
	TTLSeconds      int
	LeaseToken      string
	CancelRequested bool
	Payload         Payload
	Basket          *Basket
}

// Mutating reports whether the kind needs a write permit.
func (c Command) Mutating() bool { return Mutating(c.Kind) }

// Mutating reports whether a kind is a write.
func Mutating(kind string) bool { return kind == KindPlaceOrder || kind == KindCancelOrder }

// wireCommand mirrors the closed property list shared by both versions.
type wireCommand struct {
	SchemaVersion   string          `json:"schema_version"`
	CommandID       string          `json:"command_id"`
	ExecutionID     string          `json:"execution_id"`
	WorkItemID      string          `json:"work_item_id"`
	Kind            string          `json:"kind"`
	Attempt         int             `json:"attempt"`
	TenantRef       string          `json:"tenant_ref"`
	PrincipalRef    string          `json:"principal_ref"`
	OrderRef        string          `json:"order_ref"`
	ConnectionRef   string          `json:"connection_ref"`
	ApprovalRef     string          `json:"approval_ref"`
	IntentHash      string          `json:"intent_hash"`
	Issuer          string          `json:"issuer"`
	Audience        string          `json:"audience"`
	Nonce           string          `json:"nonce"`
	IssuedAt        string          `json:"issued_at"`
	ExpiresAt       string          `json:"expires_at"`
	TTLSeconds      int             `json:"ttl_seconds"`
	LeaseToken      string          `json:"lease_token"`
	CancelRequested bool            `json:"cancel_requested"`
	Payload         json.RawMessage `json:"payload"`
}

// Envelope is the best-effort identity of a document that failed validation.
// A field is filled only when it individually matches its schema pattern.
type Envelope struct {
	CommandID   string
	ExecutionID string
	LeaseToken  string
	Attempt     int
}

// Complete reports whether a terminal result can be addressed to the command.
func (e Envelope) Complete() bool {
	return e.CommandID != "" && e.ExecutionID != "" && e.LeaseToken != "" && e.Attempt > 0
}

// Result is the provider's answer. It has exactly the 12 properties of
// result.schema.json.
type Result struct {
	SchemaVersion  string `json:"schema_version"`
	CommandID      string `json:"command_id"`
	ExecutionID    string `json:"execution_id"`
	LeaseToken     string `json:"lease_token"`
	Attempt        int    `json:"attempt"`
	WorkerIdentity string `json:"worker_identity"`
	Outcome        string `json:"outcome"`
	ProviderEffect string `json:"provider_effect"`
	ResultRef      string `json:"result_ref,omitempty"`
	ErrorCode      string `json:"error_code,omitempty"`
	ErrorDetail    string `json:"error_detail,omitempty"`
	CompletedAt    string `json:"completed_at"`
}

// ClaimResponse is the strict claim body.
type ClaimResponse struct {
	SchemaVersion string
	Commands      []json.RawMessage
}

type schemas struct {
	command, commandV2, result *jsonschema.Schema
}

var (
	schemaOnce sync.Once
	schemaVal  schemas
	schemaErr  error
)

const (
	urlCommand   = "https://mctl.ai/schemas/bridge/v1alpha1/command.schema.json"
	urlResult    = "https://mctl.ai/schemas/bridge/v1alpha1/result.schema.json"
	urlCommandV2 = "https://mctl.ai/schemas/bridge/v1alpha2/command-place-order-fake.schema.json"
	urlBasketV2  = "https://mctl.ai/schemas/bridge/v1alpha2/approval-basket.schema.json"
)

func compile() (schemas, error) {
	schemaOnce.Do(func() {
		c := jsonschema.NewCompiler()
		c.AssertFormat()
		for url, file := range map[string]string{
			urlCommand:   "schema/command.schema.json",
			urlResult:    "schema/result.schema.json",
			urlCommandV2: "schema/v1alpha2/command-place-order-fake.schema.json",
			urlBasketV2:  "schema/v1alpha2/approval-basket.schema.json",
		} {
			raw, err := schemaFS.ReadFile(file)
			if err != nil {
				schemaErr = fmt.Errorf("read %s: %w", file, err)
				return
			}
			doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
			if err != nil {
				schemaErr = fmt.Errorf("parse %s: %w", file, err)
				return
			}
			if err := c.AddResource(url, doc); err != nil {
				schemaErr = fmt.Errorf("add %s: %w", file, err)
				return
			}
		}
		for _, p := range []struct {
			dst *(*jsonschema.Schema)
			url string
		}{{&schemaVal.command, urlCommand}, {&schemaVal.result, urlResult}, {&schemaVal.commandV2, urlCommandV2}} {
			s, err := c.Compile(p.url)
			if err != nil {
				schemaErr = fmt.Errorf("compile %s: %w", p.url, err)
				return
			}
			*p.dst = s
		}
	})
	return schemaVal, schemaErr
}

// SchemaFile returns an embedded schema-directory file (tests and PROVENANCE checks).
func SchemaFile(name string) ([]byte, error) { return schemaFS.ReadFile("schema/" + name) }

func validate(s *jsonschema.Schema, raw []byte) error {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("%w: not json", ErrInvalid)
	}
	if err := s.Validate(doc); err != nil {
		return fmt.Errorf("%w: schema", ErrInvalid)
	}
	return nil
}

func strictDecode(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: decode", ErrInvalid)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing data", ErrInvalid)
	}
	return nil
}

var (
	reCommandID = regexp.MustCompile(`^cmd_[A-Za-z0-9]{26}$`)
	reExecID    = regexp.MustCompile(`^we_[A-Za-z0-9]{16,40}$`)
	reLease     = regexp.MustCompile(`^lt_[A-Za-z0-9_-]{16,64}$`)
)

func envelopeOf(raw []byte) Envelope {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return Envelope{}
	}
	str := func(k string, re *regexp.Regexp) string {
		if s, ok := m[k].(string); ok && re.MatchString(s) {
			return s
		}
		return ""
	}
	e := Envelope{CommandID: str("command_id", reCommandID), ExecutionID: str("execution_id", reExecID), LeaseToken: str("lease_token", reLease)}
	if f, ok := m["attempt"].(float64); ok && f >= 1 && f <= 100 && f == float64(int(f)) {
		e.Attempt = int(f)
	}
	return e
}

// ParseCommand validates raw against the schema its schema_version selects,
// then strict-decodes it. v1alpha2 is accepted only for place_order_fake; any
// other combination is ErrInvalid. On failure the Envelope is best effort.
func ParseCommand(raw json.RawMessage) (Command, Envelope, error) {
	s, err := compile()
	if err != nil {
		return Command{}, Envelope{}, fmt.Errorf("schemas unavailable: %w", err)
	}
	fail := func(err error) (Command, Envelope, error) { return Command{}, envelopeOf(raw), err }
	var head struct {
		SchemaVersion string `json:"schema_version"`
		Kind          string `json:"kind"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return fail(fmt.Errorf("%w: not an object", ErrInvalid))
	}
	var sch *jsonschema.Schema
	switch head.SchemaVersion {
	case Version:
		sch = s.command
	case VersionV2:
		if head.Kind != KindPlaceOrder {
			return fail(fmt.Errorf("%w: v1alpha2 supports place_order_fake only", ErrInvalid))
		}
		sch = s.commandV2
	default:
		return fail(fmt.Errorf("%w: unknown schema_version", ErrInvalid))
	}
	if err := validate(sch, raw); err != nil {
		return fail(err)
	}
	var w wireCommand
	if err := strictDecode(raw, &w); err != nil {
		return fail(err)
	}
	c := Command{
		SchemaVersion: w.SchemaVersion, CommandID: w.CommandID, ExecutionID: w.ExecutionID, WorkItemID: w.WorkItemID,
		Kind: w.Kind, Attempt: w.Attempt, TenantRef: w.TenantRef, PrincipalRef: w.PrincipalRef, OrderRef: w.OrderRef,
		ConnectionRef: w.ConnectionRef, ApprovalRef: w.ApprovalRef, IntentHash: w.IntentHash, Issuer: w.Issuer,
		Audience: w.Audience, Nonce: w.Nonce, IssuedAt: w.IssuedAt, ExpiresAt: w.ExpiresAt, TTLSeconds: w.TTLSeconds,
		LeaseToken: w.LeaseToken, CancelRequested: w.CancelRequested,
	}
	if w.SchemaVersion == VersionV2 {
		var b Basket
		if err := strictDecode(w.Payload, &b); err != nil {
			return fail(err)
		}
		c.Basket = &b
	} else if err := strictDecode(w.Payload, &c.Payload); err != nil {
		return fail(err)
	}
	return c, Envelope{}, nil
}

// EncodeResult marshals r and validates the bytes against result.schema.json,
// so an extra field or a bad enum can never leave the process.
func EncodeResult(r Result) ([]byte, error) {
	s, err := compile()
	if err != nil {
		return nil, fmt.Errorf("schemas unavailable: %w", err)
	}
	b, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("marshal result: %w", err)
	}
	if err := validate(s.result, b); err != nil {
		return nil, err
	}
	return b, nil
}

// ValidateResult validates an arbitrary result document (used by the fake bridge).
func ValidateResult(raw []byte) error {
	s, err := compile()
	if err != nil {
		return err
	}
	return validate(s.result, raw)
}

// ParseClaimResponse strictly decodes a claim body: exactly
// {"schema_version","commands"}, no trailing data, commands a present array of
// at most MaxClaimCommands, and a known envelope version.
func ParseClaimResponse(body []byte) (ClaimResponse, error) {
	var w struct {
		SchemaVersion string          `json:"schema_version"`
		Commands      json.RawMessage `json:"commands"`
	}
	if err := strictDecode(body, &w); err != nil {
		return ClaimResponse{}, err
	}
	if w.SchemaVersion != ClaimVersion && w.SchemaVersion != ClaimV2 {
		return ClaimResponse{}, fmt.Errorf("%w: unknown claim schema_version", ErrInvalid)
	}
	if !strings.HasPrefix(strings.TrimSpace(string(w.Commands)), "[") {
		return ClaimResponse{}, fmt.Errorf("%w: commands is not an array", ErrInvalid)
	}
	var cmds []json.RawMessage
	if err := json.Unmarshal(w.Commands, &cmds); err != nil {
		return ClaimResponse{}, fmt.Errorf("%w: commands", ErrInvalid)
	}
	if len(cmds) > MaxClaimCommands {
		return ClaimResponse{}, fmt.Errorf("%w: too many commands", ErrInvalid)
	}
	return ClaimResponse{SchemaVersion: w.SchemaVersion, Commands: cmds}, nil
}
