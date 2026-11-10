package bridgeclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/protocol/v1alpha1"
)

// APIError is a non-2xx bridge answer. Code is empty when the body carried no
// parseable code (a rate limiter, a 401 {"error"} body, a proxy page). The body
// itself is never kept.
type APIError struct {
	Status     int
	Code       string
	RetryAfter time.Duration
}

func (e *APIError) Error() string {
	return fmt.Sprintf("bridge answered status %d code %q", e.Status, e.Code)
}

// Permit is the single-use write permit answer.
type Permit struct {
	CommandID string `json:"command_id"`
	FenceRef  string `json:"fence_ref"`
	IssuedAt  string `json:"issued_at"`
}

// SubmitAck is the result answer.
type SubmitAck struct {
	CommandID    string `json:"command_id"`
	Status       string `json:"status"`
	EffectState  string `json:"effect_state"`
	ResultDigest string `json:"result_digest"`
	Replayed     bool   `json:"replayed"`
}

// ErrMalformed marks a 2xx body the client refuses to interpret.
var ErrMalformed = errors.New("bridgeclient: malformed response")

// Client talks to one mctl-api origin.
type Client struct {
	base *url.URL
	hc   *http.Client
	cred CredentialSource
}

// New builds a client for origin. hc is optional (tests); nil uses NewHTTPClient.
func New(origin *url.URL, cred CredentialSource, hc *http.Client) *Client {
	if hc == nil {
		hc = NewHTTPClient(origin)
	}
	return &Client{base: origin, hc: hc, cred: cred}
}

func (c *Client) do(ctx context.Context, path string, body []byte) ([]byte, error) {
	u := *c.base
	// path is already escaped (the command id goes through url.PathEscape), so
	// keep Path as its decoded form and RawPath as the wire form; assigning the
	// escaped string to Path alone would double-escape every %.
	if dec, derr := url.PathUnescape(path); derr == nil {
		u.Path, u.RawPath = dec, path
	} else {
		u.Path = path
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	secret, err := c.cred.Get() // re-read per request
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", secret.bearer())
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		// Never wrap the transport error text: it can echo the URL.
		if errors.Is(err, ErrOrigin) {
			return nil, ErrOrigin
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("bridgeclient: transport error")
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes))
	if err != nil {
		return nil, errors.New("bridgeclient: transport error reading body")
	}
	if len(b) >= MaxBodyBytes {
		return nil, fmt.Errorf("%w: body at the size cap", ErrMalformed)
	}
	if resp.StatusCode/100 != 2 {
		ae := &APIError{Status: resp.StatusCode}
		var e struct {
			Code string `json:"code"`
		}
		if json.Unmarshal(b, &e) == nil && validCode(e.Code) {
			ae.Code = e.Code
		}
		if s := resp.Header.Get("Retry-After"); s != "" {
			if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n >= 0 && n <= 3600 {
				ae.RetryAfter = time.Duration(n) * time.Second
			}
		}
		return nil, ae
	}
	return b, nil
}

func validCode(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if r != '_' && (r < 'a' || r > 'z') {
			return false
		}
	}
	return true
}

// Claim leases up to max due commands. The returned raw commands are
// unparsed; Version is the claim envelope version.
func (c *Client) Claim(ctx context.Context, max int) (v1alpha1.ClaimResponse, error) {
	body, _ := json.Marshal(map[string]int{"max": max})
	b, err := c.do(ctx, routePrefix+"claim", body)
	if err != nil {
		return v1alpha1.ClaimResponse{}, err
	}
	resp, err := v1alpha1.ParseClaimResponse(b)
	if err != nil {
		return v1alpha1.ClaimResponse{}, fmt.Errorf("%w: claim body", ErrMalformed)
	}
	return resp, nil
}

// WritePermit asks for the single-use permit of one leased mutating command.
func (c *Client) WritePermit(ctx context.Context, commandID, leaseToken string) (Permit, error) {
	body, _ := json.Marshal(map[string]string{"lease_token": leaseToken})
	b, err := c.do(ctx, routePrefix+url.PathEscape(commandID)+"/write-permit", body)
	if err != nil {
		return Permit{}, err
	}
	var p Permit
	if err := decodeStrict(b, &p); err != nil || p.CommandID != commandID {
		return Permit{}, fmt.Errorf("%w: permit body", ErrMalformed)
	}
	return p, nil
}

// SubmitResult posts one encoded result. Callers retry the same bytes.
func (c *Client) SubmitResult(ctx context.Context, commandID string, body []byte) (SubmitAck, error) {
	b, err := c.do(ctx, routePrefix+url.PathEscape(commandID)+"/result", body)
	if err != nil {
		return SubmitAck{}, err
	}
	var a SubmitAck
	if err := decodeStrict(b, &a); err != nil {
		return SubmitAck{}, fmt.Errorf("%w: result body", ErrMalformed)
	}
	return a, nil
}

func decodeStrict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data")
	}
	return nil
}
