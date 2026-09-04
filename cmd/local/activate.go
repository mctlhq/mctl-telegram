package main

// activate.go implements the `activate` subcommand: the CLI side of
// self-service Local Bridge device activation (issue #482). It persists a
// local device_registration_key, starts an activation against the server,
// prints the verification_uri and user_code (never a URL carrying either),
// and polls until the browser-driven flow resolves to done or denied.
//
// This command does not by itself make the daemon runnable: activation only
// gets the account into local mode with a registered device
// (send_enabled=false throughout). An operator (or a future self-service
// step, issue #483) still has to mint a bridge token before `connect`/
// `daemon` work.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// activateSleep and activateNow are package vars (not direct time.Sleep/
// time.Now calls) so tests can drive the poll loop without waiting on real
// wall-clock time, mirroring the enableLockWait-style testing seam used
// elsewhere in this repo.
var activateSleep = time.Sleep
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

	deviceKey, err := loadOrCreateDeviceKey()
	if err != nil {
		die(err)
	}
	deviceLabel := *label
	if deviceLabel == "" {
		if h, herr := os.Hostname(); herr == nil {
			deviceLabel = h
		}
	}

	deviceID, err := runActivateFlow(context.Background(), os.Stdout, srv, *telegramID, deviceKey, deviceLabel)
	switch {
	case err == nil:
		fmt.Printf("\nDevice activated (device_id=%s).\n", deviceID)
		fmt.Println("An operator still needs to issue this device a token (or, once available, a self-service credential step lands in a later release) before `connect`/`daemon` will work.")
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
func runActivateFlow(ctx context.Context, out io.Writer, server string, telegramID int64, deviceKey, deviceLabel string) (deviceID string, err error) {
	start, err := activateStartRequest(ctx, server, telegramID, deviceKey, deviceLabel)
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
		activateSleep(interval)
		poll, err := activatePollRequest(ctx, server, start.DeviceCode)
		if err != nil {
			return "", fmt.Errorf("poll activation: %w", err)
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

func activateStartRequest(ctx context.Context, server string, telegramID int64, deviceKey, deviceLabel string) (*activateStartResponse, error) {
	body, err := json.Marshal(map[string]any{
		"telegram_id":             telegramID,
		"device_registration_key": deviceKey,
		"device_label":            deviceLabel,
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

// activatePollRequest polls once. A non-200 HTTP status (the server's shape
// for "unknown or expired device_code") is translated to a synthetic
// {"status":"expired"} rather than propagated as a Go error, so the caller's
// switch in runActivateFlow has one place that decides what to do with
// every terminal outcome.
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
	if resp.StatusCode != http.StatusOK {
		return &activatePollResponse{Status: "expired", Reason: strings.TrimSpace(string(respBody))}, nil
	}
	var out activatePollResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	return &out, nil
}
