package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
)

// Compiled constants: the worker polls exactly this namespace and queue and
// refuses to start for anything else (ADR 0009, ADR 0010).
const (
	providerNamespace = "mctl-assistants-provider-glovo"
	providerTaskQueue = "assistants-provider-glovo"

	defaultHealthAddr  = ":8081"
	defaultHostPort    = "localhost:7233"
	defaultStopTimeout = 25 * time.Second
	maxStopTimeout     = 28 * time.Second
)

// Config is the worker's environment configuration.
type Config struct {
	HostPort    string
	Namespace   string
	TaskQueue   string
	HealthAddr  string
	Disabled    bool
	StopTimeout time.Duration
	TLSCert     string
	TLSKey      string
	TLSCA       string
}

// getenv looks a name up in a KEY=VALUE slice.
func getenv(env []string, name string) (string, bool) {
	prefix := name + "="
	for _, kv := range env {
		if len(kv) >= len(prefix) && kv[:len(prefix)] == prefix {
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

// LoadConfig parses env. Errors never include values other than the
// namespace and queue names, which are not secrets.
func LoadConfig(env []string) (Config, error) {
	c := Config{
		HostPort:    envOr(env, "TEMPORAL_HOSTPORT", defaultHostPort),
		Namespace:   envOr(env, "TEMPORAL_NAMESPACE", providerNamespace),
		TaskQueue:   envOr(env, "TEMPORAL_TASK_QUEUE", providerTaskQueue),
		HealthAddr:  envOr(env, "HEALTH_ADDR", defaultHealthAddr),
		StopTimeout: defaultStopTimeout,
		TLSCert:     envOr(env, "TEMPORAL_TLS_CERT_FILE", ""),
		TLSKey:      envOr(env, "TEMPORAL_TLS_KEY_FILE", ""),
		TLSCA:       envOr(env, "TEMPORAL_TLS_CA_FILE", ""),
	}
	if c.Namespace != providerNamespace {
		return Config{}, fmt.Errorf("TEMPORAL_NAMESPACE must be %q, got %q", providerNamespace, c.Namespace)
	}
	if c.TaskQueue != providerTaskQueue {
		return Config{}, fmt.Errorf("TEMPORAL_TASK_QUEUE must be %q, got %q", providerTaskQueue, c.TaskQueue)
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
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return Config{}, errors.New("TEMPORAL_TLS_CERT_FILE and TEMPORAL_TLS_KEY_FILE must be set together")
	}
	return c, nil
}

// TLSConfig returns nil when no TLS file is configured.
func (c Config) TLSConfig() (*tls.Config, error) {
	if c.TLSCert == "" && c.TLSCA == "" {
		return nil, nil
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.TLSCert != "" {
		pair, err := tls.LoadX509KeyPair(c.TLSCert, c.TLSKey)
		if err != nil {
			return nil, fmt.Errorf("load client certificate: %w", err)
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	if c.TLSCA != "" {
		pem, err := os.ReadFile(c.TLSCA)
		if err != nil {
			return nil, fmt.Errorf("read ca file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("ca file contains no certificates")
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}
