// Package v1alpha1 is the versioned control-to-provider request contract.
// The wire format is expected to be replaced when mctl-agents#1043 lands; the
// package is the single place that would change. Requests carry opaque
// identifiers only.
package v1alpha1

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// Version is the only accepted protocol version.
const Version = "v1alpha1"

const (
	PrefixExecution  = "we_"
	PrefixConnection = "gcn_"
	PrefixApproval   = "aar_"
)

// ErrInvalid wraps every decode and validation failure. Messages carry field
// names only, never values.
var ErrInvalid = errors.New("v1alpha1: invalid request")

// ProviderRequest is the opaque identity and intent of one provider call.
type ProviderRequest struct {
	Version         string `json:"version"`
	ExecutionRef    string `json:"execution_ref"`
	TenantRef       string `json:"tenant_ref"`
	OwnerRef        string `json:"owner_ref"`
	ConnectionRef   string `json:"connection_ref"`
	InstallRef      string `json:"install_ref"`
	InstallRevision int64  `json:"install_revision"`
	OrderRef        string `json:"order_ref"`
	IntentHash      string `json:"intent_hash"`
	ApprovalRef     string `json:"approval_ref,omitempty"`
}

// ProviderResult is the structured outcome of a provider call.
type ProviderResult struct {
	Version     string `json:"version"`
	Code        string `json:"code,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Total       int    `json:"total,omitempty"`
	Applied     bool   `json:"applied,omitempty"`
	Deduped     bool   `json:"deduped,omitempty"`
}

// forbiddenKeys must never appear as a JSON key at any depth.
var forbiddenKeys = map[string]bool{
	"namespace": true, "workflow_id": true, "run_id": true, "task_queue": true,
	"role": true, "url": true, "endpoint": true, "cookie": true, "session": true,
	"token": true, "password": true,
}

var (
	opaqueRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$`)
	hashRe   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Decode strictly decodes and validates a request.
func Decode(data []byte) (ProviderRequest, error) {
	var raw any
	if err := json.Unmarshal(data, &raw); err != nil {
		return ProviderRequest{}, fmt.Errorf("%w: malformed json", ErrInvalid)
	}
	if k := findForbidden(raw); k != "" {
		return ProviderRequest{}, fmt.Errorf("%w: forbidden field %q", ErrInvalid, k)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var req ProviderRequest
	if err := dec.Decode(&req); err != nil {
		return ProviderRequest{}, fmt.Errorf("%w: unknown or mistyped field", ErrInvalid)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return ProviderRequest{}, fmt.Errorf("%w: trailing data", ErrInvalid)
	}
	if err := req.Validate(); err != nil {
		return ProviderRequest{}, err
	}
	return req, nil
}

func findForbidden(v any) string {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			if forbiddenKeys[strings.ToLower(k)] {
				return strings.ToLower(k)
			}
			if f := findForbidden(child); f != "" {
				return f
			}
		}
	case []any:
		for _, child := range t {
			if f := findForbidden(child); f != "" {
				return f
			}
		}
	}
	return ""
}

// Validate checks version, ref prefixes and formats. ApprovalRef is optional
// here and required by the mutation boundary.
func (r ProviderRequest) Validate() error {
	if r.Version != Version {
		return fmt.Errorf("%w: version", ErrInvalid)
	}
	checks := []struct {
		field, val, prefix string
	}{
		{"execution_ref", r.ExecutionRef, PrefixExecution},
		{"tenant_ref", r.TenantRef, ""},
		{"owner_ref", r.OwnerRef, ""},
		{"connection_ref", r.ConnectionRef, PrefixConnection},
		{"install_ref", r.InstallRef, ""},
		{"order_ref", r.OrderRef, ""},
	}
	for _, c := range checks {
		if !validRef(c.val, c.prefix) {
			return fmt.Errorf("%w: %s", ErrInvalid, c.field)
		}
	}
	if r.ApprovalRef != "" && !validRef(r.ApprovalRef, PrefixApproval) {
		return fmt.Errorf("%w: approval_ref", ErrInvalid)
	}
	if r.InstallRevision < 1 {
		return fmt.Errorf("%w: install_revision", ErrInvalid)
	}
	if !hashRe.MatchString(r.IntentHash) {
		return fmt.Errorf("%w: intent_hash", ErrInvalid)
	}
	return nil
}

// RequireApproval additionally demands a well-formed aar_ ref.
func (r ProviderRequest) RequireApproval() error {
	if r.ApprovalRef == "" {
		return fmt.Errorf("%w: approval_ref", ErrInvalid)
	}
	return r.Validate()
}

func validRef(v, prefix string) bool {
	if !strings.HasPrefix(v, prefix) || !opaqueRe.MatchString(v) {
		return false
	}
	return len(v) > len(prefix)
}
