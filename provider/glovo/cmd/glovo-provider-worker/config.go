package main

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/bridgeclient"
)

const (
	defaultHealthAddr   = ":8081"
	defaultIdentity     = "provider:glovo"
	defaultClaimMax     = 4
	defaultPollInterval = 2 * time.Second
	minPollInterval     = 500 * time.Millisecond
	maxPollInterval     = 60 * time.Second
	defaultStopTimeout  = 25 * time.Second
	maxStopTimeout      = 28 * time.Second
)

var identityPattern = regexp.MustCompile(`^provider:[a-z0-9-]{1,32}$`)

// Config is the worker's environment configuration. The only control-plane
// endpoint is the mctl-api origin; there is no Temporal setting.
type Config struct {
	BaseURL        *url.URL
	CredentialFile string
	WorkerIdentity string
	ClaimMax       int
	PollInterval   time.Duration
	HealthAddr     string
	Disabled       bool
	StopTimeout    time.Duration
}

// getenv looks a name up in a KEY=VALUE slice.
func getenv(env []string, name string) (string, bool) {
	prefix := name + "="
	for _, kv := range env {
		if strings.HasPrefix(kv, prefix) {
			return kv[len(prefix):], true
		}
	}
	return "", false
}

func envOr(env []string, name, def string) string {
	if v, ok := getenv(env, name); ok && v != "" {
		return v
	}
	return def
}

// LoadConfig parses env. Errors carry setting names, never values.
func LoadConfig(env []string) (Config, error) {
	var temporal []string
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(strings.ToUpper(name), "TEMPORAL_") {
			temporal = append(temporal, name)
		}
	}
	if len(temporal) > 0 {
		sort.Strings(temporal)
		return Config{}, fmt.Errorf("this worker holds no Temporal credential; remove: %s", strings.Join(temporal, ","))
	}
	c := Config{
		CredentialFile: envOr(env, "MCTL_BRIDGE_CREDENTIAL_FILE", ""),
		WorkerIdentity: envOr(env, "BRIDGE_WORKER_IDENTITY", defaultIdentity),
		ClaimMax:       defaultClaimMax,
		PollInterval:   defaultPollInterval,
		HealthAddr:     envOr(env, "HEALTH_ADDR", defaultHealthAddr),
		StopTimeout:    defaultStopTimeout,
	}
	base := envOr(env, "MCTL_API_BASE_URL", "")
	if base == "" {
		return Config{}, errors.New("MCTL_API_BASE_URL is required")
	}
	u, err := bridgeclient.ParseOrigin(base)
	if err != nil {
		return Config{}, err
	}
	c.BaseURL = u
	if c.CredentialFile == "" {
		return Config{}, errors.New("MCTL_BRIDGE_CREDENTIAL_FILE is required")
	}
	if !identityPattern.MatchString(c.WorkerIdentity) {
		return Config{}, errors.New("BRIDGE_WORKER_IDENTITY must match ^provider:[a-z0-9-]{1,32}$")
	}
	if v, ok := getenv(env, "BRIDGE_CLAIM_MAX"); ok && v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 10 {
			return Config{}, errors.New("BRIDGE_CLAIM_MAX must be an integer in 1..10")
		}
		c.ClaimMax = n
	}
	if v, ok := getenv(env, "BRIDGE_POLL_INTERVAL"); ok && v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < minPollInterval || d > maxPollInterval {
			return Config{}, fmt.Errorf("BRIDGE_POLL_INTERVAL must be a duration in [%s, %s]", minPollInterval, maxPollInterval)
		}
		c.PollInterval = d
	}
	if v, ok := getenv(env, "GLOVO_PROVIDER_DISABLED"); ok && v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return Config{}, errors.New("GLOVO_PROVIDER_DISABLED must be a boolean")
		}
		c.Disabled = b
	}
	if v, ok := getenv(env, "WORKER_STOP_TIMEOUT"); ok && v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 || d > maxStopTimeout {
			return Config{}, fmt.Errorf("WORKER_STOP_TIMEOUT must be a duration in (0, %s]", maxStopTimeout)
		}
		c.StopTimeout = d
	}
	return c, nil
}
