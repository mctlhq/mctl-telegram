package linking

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/mctlhq/mctl-telegram/internal/pa/egress"
)

// ASMetadata is what the linking flow takes from a server's OAuth 2.0
// authorization server metadata (RFC 8414).
type ASMetadata struct {
	// Issuer is the metadata's issuer. ParseASMetadata only returns
	// metadata whose issuer is the one it was asked for (RFC 8414 3.3).
	Issuer string
	// IssParameterSupported is authorization_response_iss_parameter_supported
	// (RFC 9207 section 3): the server puts iss on every authorization
	// response. RequireIss is derived from it.
	IssParameterSupported bool
	// AuthorizationEndpoint, TokenEndpoint and RevocationEndpoint are the
	// endpoints the metadata names, or "" for one it leaves out. The
	// server wiring refuses to start when one differs from the configured
	// value (#1318 slice C2): the metadata is the server's own statement
	// of where its endpoints are.
	AuthorizationEndpoint string
	TokenEndpoint         string
	RevocationEndpoint    string
}

// ErrASMetadata is authorization server metadata that could not be fetched
// or read. It never means "the server does not send iss".
var ErrASMetadata = errors.New("pa linking: authorization server metadata unusable")

// issParameterField is the RFC 9207 metadata parameter.
const issParameterField = "authorization_response_iss_parameter_supported"

// ParseASMetadata reads an RFC 8414 metadata document for issuer. It fails
// closed (#1338): a body that is not a JSON object, an issuer that is
// missing or not issuer, and an iss parameter field that is present but not
// a JSON boolean are all ErrASMetadata, never IssParameterSupported=false.
// Only the field's absence means false, as RFC 9207 section 3 defines.
func ParseASMetadata(body []byte, issuer string) (ASMetadata, error) {
	if issuer == "" {
		return ASMetadata{}, fmt.Errorf("%w: no issuer to check against", ErrASMetadata)
	}
	var doc map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&doc); err != nil || doc == nil {
		return ASMetadata{}, fmt.Errorf("%w: not a JSON object", ErrASMetadata)
	}
	// Token, not More: More reports false before a stray closing bracket.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return ASMetadata{}, fmt.Errorf("%w: trailing data after the JSON object", ErrASMetadata)
	}
	var got string
	if raw, ok := doc["issuer"]; !ok || json.Unmarshal(raw, &got) != nil || got != issuer {
		return ASMetadata{}, fmt.Errorf("%w: issuer is not the pinned issuer", ErrASMetadata)
	}
	md := ASMetadata{Issuer: got}
	for field, dst := range map[string]*string{
		"authorization_endpoint": &md.AuthorizationEndpoint,
		"token_endpoint":         &md.TokenEndpoint,
		"revocation_endpoint":    &md.RevocationEndpoint,
	} {
		raw, ok := doc[field]
		if !ok {
			continue
		}
		// Present but not a string is unreadable, never absent.
		if json.Unmarshal(raw, dst) != nil || *dst == "" {
			return ASMetadata{}, fmt.Errorf("%w: %s is not a non-empty string", ErrASMetadata, field)
		}
	}
	if raw, ok := doc[issParameterField]; ok {
		raw = bytes.TrimSpace(raw)
		switch string(raw) {
		case "true":
			md.IssParameterSupported = true
		case "false":
		default:
			return ASMetadata{}, fmt.Errorf("%w: %s is not a boolean", ErrASMetadata, issParameterField)
		}
	}
	return md, nil
}

// MetadataURL is issuer's RFC 8414 metadata URL: the well-known path goes
// between the host and the issuer's path (RFC 8414 3.1).
func MetadataURL(issuer string) (string, error) {
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("%w: issuer must be an https URL without query or fragment", ErrASMetadata)
	}
	u.Path = "/.well-known/oauth-authorization-server" + strings.TrimSuffix(u.Path, "/")
	u.RawPath = ""
	return u.String(), nil
}

// FetchASMetadata fetches and parses issuer's metadata with client, the
// server's egress client (internal/pa/egress). Anything but a 2xx answer
// with a document ParseASMetadata accepts is ErrASMetadata: a server whose
// metadata cannot be read is not a server that never sends iss.
func FetchASMetadata(ctx context.Context, client *http.Client, issuer string) (ASMetadata, error) {
	if client == nil {
		return ASMetadata{}, fmt.Errorf("%w: no egress client", ErrConfig)
	}
	mdURL, err := MetadataURL(issuer)
	if err != nil {
		return ASMetadata{}, err
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, mdURL, nil)
	if err != nil {
		return ASMetadata{}, fmt.Errorf("%w: request: %v", ErrASMetadata, err)
	}
	r.Header.Set("Accept", "application/json")
	resp, err := client.Do(r)
	if err != nil {
		return ASMetadata{}, fmt.Errorf("%w: %v", ErrASMetadata, err)
	}
	body, err := egress.ReadBody(resp)
	if err != nil {
		return ASMetadata{}, fmt.Errorf("%w: body: %v", ErrASMetadata, err)
	}
	if resp.StatusCode/100 != 2 {
		return ASMetadata{}, fmt.Errorf("%w: HTTP %d", ErrASMetadata, resp.StatusCode)
	}
	return ParseASMetadata(body, issuer)
}
