package config

import (
	"errors"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// PAAllowedPrincipalsEnv is the preview principal allowlist (owner decision
// on #1318, 2026-11-21): a comma-separated list of Telegram user ids,
// delivered from Vault through an ExternalSecret so no id appears in the
// public gitops repository.
const PAAllowedPrincipalsEnv = "PA_ALLOWED_PRINCIPALS"

// errPAAllowedPrincipals names the variable, never its value: the ids are
// personal data.
var errPAAllowedPrincipals = errors.New(PAAllowedPrincipalsEnv + " must be a comma-separated list of positive Telegram user ids")

// loadPAAllowlist reads PA_ALLOWED_PRINCIPALS (only called with PA_ENABLED
// on). Unset or empty allows nobody (fail closed): it leaves the list
// empty, it does not mean everyone. A malformed entry refuses startup.
func loadPAAllowlist(c *Config) error {
	ids, err := parsePAAllowedPrincipals(os.Getenv(PAAllowedPrincipalsEnv))
	if err != nil {
		return err
	}
	c.PAAllowedPrincipals = ids
	return nil
}

// paPrincipalID is one canonical id: decimal digits with no sign and no
// leading zero, so "+4242001" or "04242001" cannot pass for an id that
// review reads differently.
var paPrincipalID = regexp.MustCompile(`^[1-9][0-9]*$`)

// parsePAAllowedPrincipals parses the list. Surrounding whitespace is
// trimmed; an empty entry (",,", a trailing comma), a sign, a leading
// zero, a non-integer, zero or an id that overflows is an error.
// Duplicates are kept once.
func parsePAAllowedPrincipals(v string) ([]int64, error) {
	if strings.TrimSpace(v) == "" {
		return nil, nil
	}
	var out []int64
	seen := map[int64]bool{}
	for _, f := range strings.Split(v, ",") {
		f = strings.TrimSpace(f)
		if !paPrincipalID.MatchString(f) {
			return nil, errPAAllowedPrincipals
		}
		id, err := strconv.ParseInt(f, 10, 64)
		if err != nil || id <= 0 {
			return nil, errPAAllowedPrincipals
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out, nil
}
