package main

// activate.go implements the `activate` subcommand: the CLI side of
// self-service Local Bridge device activation (issue #482) and, once the
// browser-driven leg completes, the self-service device credential
// bootstrap (issue #483) that makes the daemon runnable with zero operator
// action (issue #484). It persists a local Ed25519 device identity, starts
// an activation against the server, prints the verification_uri and
// user_code (never a URL carrying either), polls until the browser-driven
// flow resolves to done or denied, and then walks the PoP nonce/sign/
// credential round trip that turns a bare activation into a connect-ready
// device credential.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// activateSleep and activateNow are package vars (not direct time.Sleep/
// time.Now calls) so tests can drive the poll loop without waiting on real
// wall-clock time, mirroring the enableLockWait-style testing seam used
// elsewhere in this repo.
//
// activateSleep takes a context because the poll interval is the longest the
// CLI is ever idle: with a bare time.Sleep, a Ctrl-C arriving just after a
// poll would sit unnoticed for the whole interval before anything looked at
// the context again.
var activateSleep = func(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
var activateNow = time.Now

type activateStartResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

type activatePollResponse struct {
	Status   string `json:"status"`
	Reason   string `json:"reason,omitempty"`
	DeviceID string `json:"device_id,omitempty"`
}

// errActivationDenied and errActivationTimedOut are sentinel errors
// runActivateFlow returns so the caller (runActivate) can choose the right
// exit code and message without string-matching.
var errActivationDenied = errors.New("activation denied")
var errActivationTimedOut = errors.New("activation timed out")

func runActivate(args []string) {
	fs := flag.NewFlagSet("activate", flag.ExitOnError)
	telegramID := fs.Int64("telegram-id", 0, "Your Telegram user id (numeric)")
	server := fs.String("server", "", "Override the server URL (default: from config.json)")
	label := fs.String("label", "", "Human-readable label for this device (default: hostname)")
	if err := fs.Parse(args); err != nil {
		die(err)
	}
	if *telegramID <= 0 {
		fmt.Fprintln(os.Stderr, "--telegram-id is required (your numeric Telegram user id)")
		os.Exit(2)
	}

	cfg, err := loadConfig()
	if err != nil {
		die(err)
	}
	srv := cfg.Server
	if *server != "" {
		srv = *server
	}
	if srv == "" {
		die(errors.New("no server configured -- pass --server or run `mctl-telegram-local connect --server <url> --token <t>` first"))
	}

	rec, priv, pub, err := loadOrCreateDeviceIdentity()
	if err != nil {
		die(err)
	}
	deviceLabel := *label
	if deviceLabel == "" {
		if h, herr := os.Hostname(); herr == nil {
			deviceLabel = h
		}
	}

	deviceID, err := runActivateFlow(context.Background(), os.Stdout, srv, *telegramID, rec.DeviceRegistrationKey, deviceLabel, pub)
	switch {
	case err == nil:
		fmt.Printf("\nDevice activated (device_id=%s).\n", deviceID)
		if bootErr := bootstrapDeviceCredential(context.Background(), srv, deviceID, priv, pub); bootErr != nil {
			fmt.Fprintln(os.Stderr, bootErr)
			os.Exit(1)
		}
		// Persist a --server override only now that the device is fully
		// activated against it, mirroring `connect`. `daemon` reads the
		// server from config.json and has no flag of its own, so without
		// this the documented first-time sequence (init, login, activate
		// --server, daemon) left the daemon with no server to dial.
		if *server != "" && cfg.Server != srv {
			cfg.Server = srv
			if err := saveConfig(cfg); err != nil {
				die(fmt.Errorf("persist server override: %w", err))
			}
		}
		fmt.Println("Device is fully activated and ready. Run `mctl-telegram-local daemon` next.")
	case errors.Is(err, errActivationDenied):
		fmt.Fprintf(os.Stderr, "Activation was not completed: %v\n", err)
		os.Exit(1)
	case errors.Is(err, errActivationTimedOut):
		fmt.Fprintln(os.Stderr, "Activation timed out. Run `mctl-telegram-local activate` again to get a fresh code.")
		os.Exit(1)
	default:
		die(err)
	}
}

// runActivateFlow starts an activation, prints the verification instructions
// to out, and polls until the browser leg resolves. It returns the
// server-generated device_id on success. errActivationDenied wraps the
// server's reason string; errActivationTimedOut is returned once the
// activation's own expires_in has elapsed.
//
// Never constructs or prints a URL that carries user_code or device_code —
// that would defeat the whole point of the short human-typed code (see
// design.md's "resolved open question" on verification_uri_complete).
func runActivateFlow(ctx context.Context, out io.Writer, server string, telegramID int64, deviceKey, deviceLabel string, pub ed25519.PublicKey) (deviceID string, err error) {
	start, err := activateStartRequest(ctx, server, telegramID, deviceKey, deviceLabel, pub)
	if err != nil {
		return "", fmt.Errorf("start activation: %w", err)
	}

	fmt.Fprintf(out, "\nOpen this page in a browser: %s\n", start.VerificationURI)
	fmt.Fprintf(out, "Enter this code when prompted: %s\n\n", start.UserCode)
	fmt.Fprintln(out, "Waiting for you to sign in with Telegram and approve this device...")

	interval := time.Duration(start.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	var deadline time.Time
	if start.ExpiresIn > 0 {
		deadline = activateNow().Add(time.Duration(start.ExpiresIn) * time.Second)
	}

	for {
		if !deadline.IsZero() && activateNow().After(deadline) {
			return "", errActivationTimedOut
		}
		if err := activateSleep(ctx, interval); err != nil {
			return "", err
		}
		poll, err := activatePollRequest(ctx, server, start.DeviceCode)
		if err != nil {
			// A failed poll says nothing about the activation, which lives on
			// the server and is still waiting for the browser leg. A dropped
			// connection, a DNS blip or the 15s client timeout used to kill
			// the CLI outright and strand a sign-in the user had already
			// half-completed. Keep polling; the deadline above is what ends
			// the flow, and ctx cancellation still stops it immediately.
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			fmt.Fprintf(out, "Still waiting (%v); retrying...\n", err)
			continue
		}
		switch poll.Status {
		case "pending":
			continue
		case "denied":
			reason := poll.Reason
			if reason == "" {
				reason = "no reason given"
			}
			return "", fmt.Errorf("%w: %s", errActivationDenied, reason)
		case "done":
			if poll.DeviceID == "" {
				return "", errors.New("server reported done but returned no device_id")
			}
			return poll.DeviceID, nil
		case "expired":
			return "", errActivationTimedOut
		default:
			return "", fmt.Errorf("server returned an unrecognized status %q", poll.Status)
		}
	}
}

func activateStartRequest(ctx context.Context, server string, telegramID int64, deviceKey, deviceLabel string, pub ed25519.PublicKey) (*activateStartResponse, error) {
	body, err := json.Marshal(map[string]any{
		"telegram_id":             telegramID,
		"device_registration_key": deviceKey,
		"device_label":            deviceLabel,
		"device_pubkey":           base64.StdEncoding.EncodeToString(pub),
	})
	if err != nil {
		return nil, err
	}
	reqURL := strings.TrimRight(server, "/") + "/api/local-bridge/activate/start"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	var out activateStartResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	if out.DeviceCode == "" || out.UserCode == "" || out.VerificationURI == "" {
		return nil, errors.New("server returned an incomplete start response")
	}
	return &out, nil
}

// activatePollRequest polls once. HTTP 400 -- the server's only non-200 shape
// for this endpoint, covering both "device_code is required" and "unknown or
// expired device_code" -- is translated to a synthetic {"status":"expired"}
// rather than propagated as a Go error, so the caller's switch in
// runActivateFlow has one place that decides what to do with every terminal
// outcome. Every OTHER non-200 is returned as an error: a 502 from an ingress
// mid-rollout says nothing about the activation, which the server still holds.
func activatePollRequest(ctx context.Context, server, deviceCode string) (*activatePollResponse, error) {
	body, err := json.Marshal(map[string]string{"device_code": deviceCode})
	if err != nil {
		return nil, err
	}
	reqURL := strings.TrimRight(server, "/") + "/api/local-bridge/activate/poll"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	// Only 400 is terminal. The poll handler answers 400 for both "device_code
	// is required" and "unknown or expired device_code", and nothing else it
	// can return means the activation is gone. Treating every non-200 as
	// "expired" threw the activation away on a 502 from the ingress during a
	// rollout, or on any transient 500 -- the user's browser leg was still
	// perfectly valid and the server still held the activation. Anything else
	// is reported as an error so the caller can wait it out.
	if resp.StatusCode == http.StatusBadRequest {
		return &activatePollResponse{Status: "expired", Reason: strings.TrimSpace(string(respBody))}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	var out activatePollResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	return &out, nil
}

// ----- post-activation device credential bootstrap (issue #483 self-service
// issuance, wired up by issue #484) -----

// devicePoPRequest is the body of both /credential and /refresh: the nonce
// obtained from /nonce, and an Ed25519 signature over
// device_id + "." + nonce, base64 (standard, padded) encoded. Mirrors
// internal/oauth/local_bridge_credential.go's devicePoPRequest exactly.
type devicePoPRequest struct {
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}

// deviceNonceResponse mirrors handleDeviceNonce's response shape.
type deviceNonceResponse struct {
	Nonce     string `json:"nonce"`
	ExpiresIn int    `json:"expires_in"`
}

// deviceCredentialResponse mirrors the shared response shape of
// /credential and /refresh (internal/oauth/local_bridge_credential.go's
// deviceCredentialResponse).
type deviceCredentialResponse struct {
	WorkerToken string `json:"worker_token"`
	ExpiresAt   string `json:"expires_at"`
	Jti         string `json:"jti"`
}

// fetchDeviceNonce calls the unauthenticated, device_id-scoped
// POST /api/local-bridge/devices/{device_id}/nonce.
func fetchDeviceNonce(ctx context.Context, server, deviceID string) (*deviceNonceResponse, error) {
	reqURL := strings.TrimRight(server, "/") + "/api/local-bridge/devices/" + url.PathEscape(deviceID) + "/nonce"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out deviceNonceResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	if out.Nonce == "" {
		return nil, errors.New("server returned an empty nonce")
	}
	return &out, nil
}

// signDevicePoP signs deviceID+"."+nonce with priv and base64 (standard)
// encodes the result, matching verifyDevicePoP's exact expected wire
// format (internal/oauth/local_bridge_credential.go).
func signDevicePoP(deviceID, nonce string, priv ed25519.PrivateKey) string {
	sig := ed25519.Sign(priv, []byte(deviceID+"."+nonce))
	return base64.StdEncoding.EncodeToString(sig)
}

// postDevicePoP POSTs {nonce, signature} to
// /api/local-bridge/devices/{device_id}/{path} (path is "credential" or
// "refresh") and returns the raw status code and body. Callers decide what
// a given status means: 200 succeeds, 409 has its own recovery meaning at
// /credential, and anything else is a hard failure whose body is worth
// reporting verbatim.
func postDevicePoP(ctx context.Context, server, deviceID, path, nonce, sig string) (status int, body []byte, err error) {
	reqBody, err := json.Marshal(devicePoPRequest{Nonce: nonce, Signature: sig})
	if err != nil {
		return 0, nil, err
	}
	reqURL := strings.TrimRight(server, "/") + "/api/local-bridge/devices/" + url.PathEscape(deviceID) + "/" + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(reqBody))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, _ = io.ReadAll(resp.Body)
	return resp.StatusCode, body, nil
}

// obtainDeviceCredentialViaPoP runs one full nonce -> sign -> POST round
// trip against either /credential (path="credential", first issuance) or
// /refresh (path="refresh", every later call). Returns the parsed
// credential on 200; on any other status returns the raw status/body so the
// caller can decide what it means (409 at /credential means "already
// claimed", handled by the caller; any other status is a hard failure).
func obtainDeviceCredentialViaPoP(ctx context.Context, server, deviceID, path string, priv ed25519.PrivateKey) (cred *deviceCredentialResponse, status int, body []byte, err error) {
	nr, err := fetchDeviceNonce(ctx, server, deviceID)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("fetch nonce: %w", err)
	}
	sig := signDevicePoP(deviceID, nr.Nonce, priv)
	status, body, err = postDevicePoP(ctx, server, deviceID, path, nr.Nonce, sig)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("POST %s: %w", path, err)
	}
	if status != http.StatusOK {
		return nil, status, body, nil
	}
	var out deviceCredentialResponse
	if jerr := json.Unmarshal(body, &out); jerr != nil || out.WorkerToken == "" || out.ExpiresAt == "" || out.Jti == "" {
		return nil, status, body, fmt.Errorf("server returned an incomplete or invalid credential response")
	}
	return &out, status, body, nil
}

// bootstrapDeviceCredential runs the post-activation credential bootstrap
// (design.md, "cmd/local activate", steps 4-6): nonce -> sign -> POST
// /credential. On 200 it merges the returned credential into the device
// record. On 409 (lineage already claimed) it checks whether the record
// already carries a usable credential for THIS device -- if so, the run is
// a no-op success ("already activated"); otherwise it is the half-claimed
// lineage case, and recovery goes through the /refresh PoP flow, which
// authenticates by possession alone and needs no existing credential. Any
// other failure -- including a failing repair refresh -- returns an error
// naming the device as already activated and the credential step as
// retryable, and never writes a partial/error body into the credential
// fields.
func bootstrapDeviceCredential(ctx context.Context, server, deviceID string, priv ed25519.PrivateKey, pub ed25519.PublicKey) error {
	cred, status, body, err := obtainDeviceCredentialViaPoP(ctx, server, deviceID, "credential", priv)
	if err != nil {
		return fmt.Errorf("device %s was activated, but the credential step failed and can be retried by running `mctl-telegram-local activate` again: %w", deviceID, err)
	}

	switch status {
	case http.StatusOK:
		if _, mErr := mergeDeviceCredential(pub, deviceID, cred.WorkerToken, cred.ExpiresAt, cred.Jti); mErr != nil {
			return fmt.Errorf("device %s was activated and issued a credential, but saving it locally failed and can be retried by running `mctl-telegram-local activate` again: %w", deviceID, mErr)
		}
		return nil

	case http.StatusConflict:
		// Lineage already claimed. Two causes look identical from here: a
		// prior run's credential really was issued and persisted usably (a
		// no-op re-run), or the server claimed the lineage and this machine
		// has nothing usable to show for it (a crash or network drop
		// between the claim and the write). See design.md's "two causes
		// that look identical".
		dir, derr := configDirPath()
		if derr != nil {
			return derr
		}
		var alreadyGood bool
		lockErr := withDeviceRecordLock(dir, deviceLockTimeout, func() error {
			rec, rerr := readDeviceRecord()
			if rerr != nil {
				return rerr
			}
			alreadyGood = rec.DeviceID == deviceID && deviceCredentialUsable(rec)
			return nil
		})
		if lockErr != nil {
			return lockErr
		}
		if alreadyGood {
			return nil
		}

		// Half-claimed lineage: recover via /refresh, which needs only
		// possession of the device key, not an existing credential.
		refreshCred, refreshStatus, refreshBody, refreshErr := obtainDeviceCredentialViaPoP(ctx, server, deviceID, "refresh", priv)
		if refreshErr != nil {
			return fmt.Errorf("device %s was activated, but recovering its credential via refresh failed and can be retried by running `mctl-telegram-local activate` again: %w", deviceID, refreshErr)
		}
		if refreshStatus != http.StatusOK || refreshCred == nil {
			return fmt.Errorf("device %s was activated, but its credential could not be recovered via refresh (server returned %d: %s) -- run `mctl-telegram-local activate` again to retry", deviceID, refreshStatus, strings.TrimSpace(string(refreshBody)))
		}
		if _, mErr := mergeDeviceCredential(pub, deviceID, refreshCred.WorkerToken, refreshCred.ExpiresAt, refreshCred.Jti); mErr != nil {
			return fmt.Errorf("device %s's credential was recovered via refresh, but saving it locally failed and can be retried by running `mctl-telegram-local activate` again: %w", deviceID, mErr)
		}
		return nil

	default:
		return fmt.Errorf("device %s was activated, but the credential step failed (server returned %d: %s) and can be retried by running `mctl-telegram-local activate` again", deviceID, status, strings.TrimSpace(string(body)))
	}
}
