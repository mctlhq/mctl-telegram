// Package bridgeclient is the provider's only control-plane I/O: an HTTP
// client for the mctl-api command bridge (claim, write-permit, result).
package bridgeclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// CredentialSetting is the only name an error may carry for the credential.
const CredentialSetting = "MCTL_BRIDGE_CREDENTIAL_FILE"

const maxCredentialBytes = 4096

// Secret holds the bearer credential. Every formatting path is redacted.
type Secret struct{ v string }

func (Secret) String() string               { return "[redacted]" }
func (Secret) GoString() string             { return "[redacted]" }
func (Secret) LogValue() slog.Value         { return slog.StringValue("[redacted]") }
func (Secret) MarshalJSON() ([]byte, error) { return json.Marshal("[redacted]") }
func (Secret) MarshalText() ([]byte, error) { return []byte("[redacted]"), nil }

// Bearer returns the Authorization header value. It is for the transport only.
func (s Secret) bearer() string { return "Bearer " + s.v }

// CredentialSource yields the credential for one request.
type CredentialSource interface {
	Get() (Secret, error)
}

// FileCredential re-reads a file on every call, so rotation needs no restart.
type FileCredential struct{ Path string }

// ErrCredential is wrapped by every credential failure; messages name the
// setting only, never the path or the content.
var ErrCredential = errors.New(CredentialSetting + " is unreadable, empty or too large")

func (f FileCredential) Get() (Secret, error) {
	b, err := os.ReadFile(f.Path)
	if err != nil {
		return Secret{}, fmt.Errorf("%w", ErrCredential)
	}
	v := strings.TrimSpace(string(b))
	if v == "" || len(b) > maxCredentialBytes || strings.ContainsAny(v, "\r\n") {
		return Secret{}, fmt.Errorf("%w", ErrCredential)
	}
	return Secret{v: v}, nil
}
