// Package bridge defines the provider worker's only view of the control
// plane: live scope resolution and single-use approval consumption. No
// production implementation exists in this slice (blocked on
// mctl-agents#1043, mctl-api#953/#954); only bridge/fake, for tests.
package bridge

import (
	"context"
	"errors"
	"time"

	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/protocol/v1alpha1"
)

// Refusal codes. The first group comes from ADR 0010; the rest are local to
// the provider boundary.
const (
	CodeNotAuthorized     = "not_authorized"
	CodeNotFound          = "not_found"
	CodeStaleInstall      = "stale_install"
	CodeConnectionRevoked = "connection_revoked"
	CodeConnectionExpired = "connection_expired"
	CodeApprovalInvalid   = "approval_invalid"
	CodeApprovalExpired   = "approval_expired"
	CodeApprovalReplayed  = "approval_replayed"
	CodeIntentMismatch    = "intent_mismatch"
	CodeBridgeUnavailable = "bridge_unavailable"
	CodeProviderDisabled  = "provider_disabled"
	CodeProviderUnavail   = "provider_unavailable"
	CodeTenantBusy        = "tenant_busy"
	CodeInvalidRequest    = "invalid_request"
	CodeWriteUnverified   = "write_unverified"
	CodeWriteFailed       = "write_failed"
	CodeNeedsInput        = "needs_input"
)

// Refusal is a typed, non-retryable refusal. It carries a code only.
type Refusal struct{ Code string }

func (r *Refusal) Error() string { return "refused: " + r.Code }

// Refuse builds a Refusal.
func Refuse(code string) error { return &Refusal{Code: code} }

// CodeOf returns the refusal code of err, or "" if err is not a Refusal.
func CodeOf(err error) string {
	var r *Refusal
	if errors.As(err, &r) {
		return r.Code
	}
	return ""
}

// Scope is the live, authoritative state resolved by the control plane.
type Scope struct {
	TenantRef       string
	OwnerRef        string
	InstallRef      string
	InstallRevision int64
	ConnectionRef   string
}

// ControlBridge is implemented by the control plane side.
type ControlBridge interface {
	// ResolveScope resolves live tenant, owner, install revision and
	// connection state for the request, or returns a *Refusal.
	ResolveScope(ctx context.Context, req v1alpha1.ProviderRequest) (Scope, error)
	// ConsumeApproval consumes the single-use aar_ receipt for the request
	// and basket fingerprint, or returns a *Refusal.
	ConsumeApproval(ctx context.Context, req v1alpha1.ProviderRequest, basketFingerprint string) error
}

// DefaultTimeout bounds one bridge call.
const DefaultTimeout = 5 * time.Second

type failClosed struct {
	next    ControlBridge
	timeout time.Duration
}

// FailClosed wraps b so that timeouts, transport errors and malformed or
// partial answers become a bridge_unavailable Refusal, never an allow.
func FailClosed(b ControlBridge, timeout time.Duration) ControlBridge {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &failClosed{next: b, timeout: timeout}
}

func (f *failClosed) ResolveScope(ctx context.Context, req v1alpha1.ProviderRequest) (Scope, error) {
	ctx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()
	sc, err := f.next.ResolveScope(ctx, req)
	if err != nil {
		if code := CodeOf(err); code != "" {
			return Scope{}, Refuse(code)
		}
		return Scope{}, Refuse(CodeBridgeUnavailable)
	}
	// An allow must restate exactly the identity that was asked about.
	if sc.TenantRef != req.TenantRef || sc.OwnerRef != req.OwnerRef || sc.InstallRef != req.InstallRef ||
		sc.InstallRevision != req.InstallRevision || sc.ConnectionRef != req.ConnectionRef {
		return Scope{}, Refuse(CodeBridgeUnavailable)
	}
	return sc, nil
}

func (f *failClosed) ConsumeApproval(ctx context.Context, req v1alpha1.ProviderRequest, fp string) error {
	ctx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()
	if err := f.next.ConsumeApproval(ctx, req, fp); err != nil {
		if code := CodeOf(err); code != "" {
			return Refuse(code)
		}
		return Refuse(CodeBridgeUnavailable)
	}
	return nil
}
