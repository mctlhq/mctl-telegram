// Package config parses and validates the GLOVO_MCP_* environment of the
// Glovo MCP facade. No variable names a tenant: the tenant only ever comes
// from the caller's token and mctl-api.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ContractResource is the protected resource of the M0 contract; in non-dev
// mode GLOVO_MCP_RESOURCE must equal it.
const ContractResource = "https://glovo.mctl.ai/mcp"

// Config is the validated facade configuration.
type Config struct {
	Enabled             bool
	Dev                 bool
	Addr                string
	PublicBaseURL       string
	Resource            string
	Issuer              string
	JWKSURL             string
	AuthorizationServer string
	APIBaseURL          string
	APICredentialFile   string
	RatePerMin          int
	Burst               int
	MaxInflight         int
	MetricsAllowCIDR    string
	DrainTimeout        time.Duration
}

// Load reads the configuration through getenv. With the kill switch off
// (the default) nothing beyond syntax is required.
func Load(getenv func(string) string) (Config, error) {
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	boolVar := func(name string) bool {
		v := strings.TrimSpace(getenv(name))
		if v == "" {
			return false
		}
		b, err := strconv.ParseBool(v)
		if err != nil {
			fail("%s: not a boolean", name)
		}
		return b
	}
	intVar := func(name string, def int) int {
		v := strings.TrimSpace(getenv(name))
		if v == "" {
			return def
		}
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			fail("%s: must be a positive integer", name)
			return def
		}
		return n
	}

	c := Config{
		Enabled:           boolVar("GLOVO_MCP_ENABLED"),
		Dev:               boolVar("GLOVO_MCP_DEV"),
		Addr:              strings.TrimSpace(getenv("GLOVO_MCP_ADDR")),
		PublicBaseURL:     strings.TrimRight(strings.TrimSpace(getenv("GLOVO_MCP_PUBLIC_BASE_URL")), "/"),
		Resource:          strings.TrimSpace(getenv("GLOVO_MCP_RESOURCE")),
		Issuer:            strings.TrimSpace(getenv("GLOVO_MCP_ISSUER")),
		JWKSURL:           strings.TrimSpace(getenv("GLOVO_MCP_JWKS_URL")),
		APIBaseURL:        strings.TrimRight(strings.TrimSpace(getenv("GLOVO_MCP_API_BASE_URL")), "/"),
		APICredentialFile: strings.TrimSpace(getenv("GLOVO_MCP_API_CREDENTIAL_FILE")),
		RatePerMin:        intVar("GLOVO_MCP_RATE_PER_MIN", 30),
		Burst:             intVar("GLOVO_MCP_BURST", 10),
		MaxInflight:       intVar("GLOVO_MCP_MAX_INFLIGHT", 64),
		MetricsAllowCIDR:  strings.TrimSpace(getenv("GLOVO_MCP_METRICS_ALLOW_CIDR")),
		DrainTimeout:      20 * time.Second,
	}
	if c.Addr == "" {
		c.Addr = ":8080"
	}
	if c.MetricsAllowCIDR == "" {
		c.MetricsAllowCIDR = "127.0.0.1/32"
	}
	if _, _, err := net.ParseCIDR(c.MetricsAllowCIDR); err != nil {
		fail("GLOVO_MCP_METRICS_ALLOW_CIDR: not a CIDR")
	}
	if c.Resource == "" && c.PublicBaseURL != "" {
		c.Resource = c.PublicBaseURL + "/mcp"
	}
	c.AuthorizationServer = strings.TrimSpace(getenv("GLOVO_MCP_AUTHORIZATION_SERVER"))
	if c.AuthorizationServer == "" {
		c.AuthorizationServer = c.Issuer
	}

	if c.Enabled {
		urlVar := func(name, v string) {
			if v == "" {
				fail("%s: required when GLOVO_MCP_ENABLED=true", name)
				return
			}
			if err := checkURL(v, c.Dev); err != nil {
				fail("%s: %v", name, err)
			}
		}
		urlVar("GLOVO_MCP_PUBLIC_BASE_URL", c.PublicBaseURL)
		urlVar("GLOVO_MCP_ISSUER", c.Issuer)
		urlVar("GLOVO_MCP_JWKS_URL", c.JWKSURL)
		urlVar("GLOVO_MCP_API_BASE_URL", c.APIBaseURL)
		if c.AuthorizationServer != "" {
			urlVar("GLOVO_MCP_AUTHORIZATION_SERVER", c.AuthorizationServer)
		}
		if c.APICredentialFile == "" {
			fail("GLOVO_MCP_API_CREDENTIAL_FILE: required when GLOVO_MCP_ENABLED=true")
		}
		if c.Resource == "" {
			fail("GLOVO_MCP_RESOURCE: required when GLOVO_MCP_ENABLED=true")
		} else if !c.Dev && c.Resource != ContractResource {
			fail("GLOVO_MCP_RESOURCE: must equal %s outside GLOVO_MCP_DEV", ContractResource)
		}
	}
	if len(errs) > 0 {
		return Config{}, errors.Join(errs...)
	}
	return c, nil
}

// checkURL requires an absolute https URL without query or fragment; http is
// accepted only in dev mode on a loopback host.
func checkURL(raw string, dev bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return errors.New("not an absolute URL")
	}
	if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return errors.New("must not carry userinfo, query or fragment")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if dev && isLoopback(u.Hostname()) {
			return nil
		}
		return errors.New("http is allowed only with GLOVO_MCP_DEV=true on loopback")
	}
	return errors.New("scheme must be https")
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
